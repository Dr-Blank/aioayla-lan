"""Session crypto round trips."""

import base64
import hashlib
import hmac
import json

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from aioayla_lan import SessionCrypto, SignatureError
from aioayla_lan.crypto import build_key, zero_pad, zero_unpad

KEY = "0123456789abcdef0123456789abcdef"


def _pair() -> tuple[SessionCrypto, SessionCrypto]:
    ours = SessionCrypto(KEY, "r1-device", 111, "r2-ours", 222)
    # The device derives the same keys with the directions swapped.
    device = SessionCrypto(KEY, "r2-ours", 222, "r1-device", 111)
    return ours, device


def _sha256_hmac(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def test_round_trip_keeps_cbc_chain() -> None:
    ours, device = _pair()
    for seq in range(5):
        doc = {"seq_no": seq, "data": {"name": "adjust_temperature", "value": 240}}
        assert ours.decrypt_and_validate(device.encrypt_and_sign(doc)) == doc
        assert device.decrypt_and_validate(ours.encrypt_and_sign(doc)) == doc


def test_bad_signature_rejected() -> None:
    ours, device = _pair()
    payload = device.encrypt_and_sign({"seq_no": 0})
    payload["sign"] = "AAAA" + payload["sign"][4:]
    with pytest.raises(SignatureError):
        ours.decrypt_and_validate(payload)


def test_build_key_known_answer() -> None:
    key, msg = b"lan-key", b"r1r2t1t20"
    expected = _sha256_hmac(key, _sha256_hmac(key, msg) + msg)
    assert build_key(key, msg) == expected
    assert len(expected) == 32


@pytest.mark.parametrize(
    ("length", "padded_length"),
    [
        pytest.param(0, 0, id="empty"),
        pytest.param(15, 16, id="one-short"),
        pytest.param(16, 16, id="exact-block"),
        pytest.param(17, 32, id="one-over"),
    ],
)
def test_zero_pad_round_trip(length: int, padded_length: int) -> None:
    data = b"x" * length
    padded = zero_pad(data)
    assert len(padded) == padded_length
    assert padded == data + b"\0" * (padded_length - length)
    assert zero_unpad(padded) == data


def test_encrypt_and_sign_known_answer() -> None:
    random_1, time_1, random_2, time_2 = "r1-device", 111, "r2-ours", 222
    key = KEY.encode()
    msg = b"r1-device" + b"r2-ours" + b"111" + b"222"
    sign_key = build_key(key, msg + b"0")
    crypto_key = build_key(key, msg + b"1")
    iv = build_key(key, msg + b"2")[:16]
    encryptor = Cipher(algorithms.AES(crypto_key), modes.CBC(iv)).encryptor()
    ours = SessionCrypto(KEY, random_1, time_1, random_2, time_2)

    for doc in ({"seq_no": 0, "data": {}}, {"seq_no": 1, "data": {"a": 1}}):
        text = json.dumps(doc).encode()
        assert ours.encrypt_and_sign(doc) == {
            "enc": base64.b64encode(encryptor.update(zero_pad(text))).decode(),
            "sign": base64.b64encode(_sha256_hmac(sign_key, text)).decode(),
        }


def test_device_mirror_decrypts_our_messages() -> None:
    ours = SessionCrypto(KEY, "r1", 1, "r2", 2)
    device = SessionCrypto(KEY, "r2", 2, "r1", 1)
    payload = ours.encrypt_and_sign({"hello": "device"})
    assert device.decrypt_and_validate(payload) == {"hello": "device"}


def test_same_side_cannot_decrypt_own_messages() -> None:
    ours = SessionCrypto(KEY, "r1", 1, "r2", 2)
    other = SessionCrypto(KEY, "r1", 1, "r2", 2)
    with pytest.raises(SignatureError):
        other.decrypt_and_validate(ours.encrypt_and_sign({"a": 1}))


def test_cbc_chain_across_many_messages_of_varied_length() -> None:
    ours, device = _pair()
    for seq in range(100):
        doc = {"seq_no": seq, "data": {"name": "p", "value": "v" * (seq % 37)}}
        assert device.decrypt_and_validate(ours.encrypt_and_sign(doc)) == doc
        assert ours.decrypt_and_validate(device.encrypt_and_sign(doc)) == doc


def test_out_of_order_message_fails_signature() -> None:
    ours, device = _pair()
    ours.encrypt_and_sign({"seq_no": 0, "data": {"name": "first"}})
    second = ours.encrypt_and_sign({"seq_no": 1, "data": {"name": "second"}})
    with pytest.raises(SignatureError):
        device.decrypt_and_validate(second)


def test_replayed_message_fails_signature() -> None:
    ours, device = _pair()
    first = ours.encrypt_and_sign({"seq_no": 0, "data": {"name": "first"}})
    assert device.decrypt_and_validate(first)["seq_no"] == 0
    with pytest.raises(SignatureError):
        device.decrypt_and_validate(first)


def test_wrong_lan_key_fails_signature() -> None:
    ours, _ = _pair()
    stranger = SessionCrypto("f" * 32, "r2-ours", 222, "r1-device", 111)
    with pytest.raises(SignatureError):
        stranger.decrypt_and_validate(ours.encrypt_and_sign({"seq_no": 0}))


@pytest.mark.parametrize(
    "tamper",
    [
        pytest.param({"enc": "AAAAA"}, id="enc-not-base64"),
        pytest.param({"sign": "AAAAA"}, id="sign-not-base64"),
        pytest.param({"enc": 123}, id="enc-not-string"),
        pytest.param({"sign": None}, id="sign-not-string"),
        pytest.param({"enc": ""}, id="enc-empty"),
        pytest.param(
            {"enc": base64.b64encode(b"x" * 15).decode()}, id="enc-partial-block"
        ),
    ],
)
def test_malformed_payload_rejected_without_breaking_chain(
    tamper: dict[str, object],
) -> None:
    ours, device = _pair()
    first = device.encrypt_and_sign({"seq_no": 0})
    with pytest.raises(SignatureError):
        ours.decrypt_and_validate(first | tamper)
    # The untampered payload still decrypts: the chain did not move.
    assert ours.decrypt_and_validate(first) == {"seq_no": 0}
