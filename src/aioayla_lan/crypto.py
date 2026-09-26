"""Ayla LAN mode session crypto.

msg_app = random_1 + random_2 + time_1 + time_2
msg_dev = random_2 + random_1 + time_2 + time_1
build(k, m) = HMAC(k, HMAC(k, m) + m)
sign_key = build(lanip_key, msg + b"0")
crypto_key = build(lanip_key, msg + b"1")
iv = build(lanip_key, msg + b"2")[:16]

AES-256-CBC with zero padding. CBC chaining carries across messages for the
whole session, so a cipher reset to the initial IV breaks every message after
the first. `sign` is an HMAC over the plaintext.
"""

import base64
import binascii
import hashlib
import hmac
import json
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .exceptions import SignatureError

_BLOCK = 16


def _hmac(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def build_key(lanip_key: bytes, msg: bytes) -> bytes:
    """Derive a session key the way the Ayla SDK does (double HMAC)."""
    return _hmac(lanip_key, _hmac(lanip_key, msg) + msg)


def zero_pad(data: bytes) -> bytes:
    """Pad to the AES block size with zero bytes, not PKCS#7."""
    return data + b"\0" * (-len(data) % _BLOCK)


def zero_unpad(data: bytes) -> bytes:
    """Strip zero padding."""
    return data.rstrip(b"\0")


class _Direction:
    """Keys and chaining state for one direction of a session."""

    def __init__(self, lanip_key: bytes, msg: bytes) -> None:
        self.sign_key = build_key(lanip_key, msg + b"0")
        self._crypto_key = build_key(lanip_key, msg + b"1")
        self._iv = build_key(lanip_key, msg + b"2")[:_BLOCK]
        self.encryptor = Cipher(
            algorithms.AES(self._crypto_key), modes.CBC(self._iv)
        ).encryptor()

    def decrypt(self, data: bytes) -> tuple[bytes, bytes]:
        """Decrypt without advancing the chain. Returns (plaintext, next IV).

        Equivalent to a session-long decryptor, but a payload that later fails
        its signature check cannot desync the chain.
        """
        if not data or len(data) % _BLOCK:
            raise SignatureError("ciphertext is not a whole number of blocks")
        decryptor = Cipher(
            algorithms.AES(self._crypto_key), modes.CBC(self._iv)
        ).decryptor()
        return decryptor.update(data), data[-_BLOCK:]

    def advance(self, iv: bytes) -> None:
        """Commit the chain state after a payload was accepted."""
        self._iv = iv


class SessionCrypto:
    """Encrypts what we send and decrypts what the device sends."""

    def __init__(
        self,
        lanip_key: str,
        random_1: str,
        time_1: int,
        random_2: str,
        time_2: int,
    ) -> None:
        key = lanip_key.encode()
        r1, r2 = random_1.encode(), random_2.encode()
        t1, t2 = str(time_1).encode(), str(time_2).encode()
        self._app = _Direction(key, r1 + r2 + t1 + t2)
        self._dev = _Direction(key, r2 + r1 + t2 + t1)

    def encrypt_and_sign(self, obj: Any) -> dict[str, str]:
        """Encrypt a JSON document for the device."""
        text = json.dumps(obj).encode()
        enc = self._app.encryptor.update(zero_pad(text))
        return {
            "enc": base64.b64encode(enc).decode(),
            "sign": base64.b64encode(_hmac(self._app.sign_key, text)).decode(),
        }

    def decrypt_and_validate(self, doc: dict[str, Any]) -> Any:
        """Decrypt a device payload, verifying its signature before parsing.

        Raises :exc:`SignatureError` for any payload that fails validation, leaving
        the session usable.
        """
        enc, sign = doc["enc"], doc["sign"]
        if not isinstance(enc, str) or not isinstance(sign, str):
            raise SignatureError("enc and sign must be strings")
        try:
            data, signature = base64.b64decode(enc), base64.b64decode(sign)
        except binascii.Error as err:
            raise SignatureError("invalid base64") from err
        padded, next_iv = self._dev.decrypt(data)
        text = zero_unpad(padded)
        if not hmac.compare_digest(_hmac(self._dev.sign_key, text), signature):
            raise SignatureError("signature mismatch")
        self._dev.advance(next_iv)
        return json.loads(text)
