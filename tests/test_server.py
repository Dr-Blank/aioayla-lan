"""AylaLanServer request routing."""

import asyncio
import json
from typing import Any
from unittest.mock import MagicMock

import pytest
from conftest import (
    DEVICE_HOST,
    KEY_ID,
    LAN_KEY,
    PRIME,
    device_side,
    key_exchange_request,
)

from aioayla_lan import (
    AylaLanDevice,
    AylaLanServer,
    Datapoint,
    LanKey,
    SessionCrypto,
    WriteRejectedError,
)


def _body(doc: Any) -> bytes:
    return json.dumps(doc).encode()


@pytest.fixture
def server(device: AylaLanDevice) -> AylaLanServer:
    server = AylaLanServer()
    server.add_device(device)
    return server


def _key_exchange(server: AylaLanServer) -> SessionCrypto:
    status, reply = server.handle(
        DEVICE_HOST,
        "POST",
        "key_exchange.json",
        _body({"key_exchange": key_exchange_request()}),
    )
    assert status == 200
    return device_side(reply)


def _fetch(server: AylaLanServer) -> tuple[int, Any]:
    return server.handle(DEVICE_HOST, "GET", "commands.json", b"")


def _drained(server: AylaLanServer) -> SessionCrypto:
    """Key exchange, then let the module collect the primed reads."""
    mirror = _key_exchange(server)
    for _ in PRIME:
        # Decrypted so the mirror's CBC chain keeps up.
        mirror.decrypt_and_validate(_fetch(server)[1])
    return mirror


@pytest.mark.parametrize(
    ("remote", "method", "path"),
    [
        pytest.param(None, "GET", "commands.json", id="no-remote"),
        pytest.param("192.0.2.99", "GET", "commands.json", id="unknown-get"),
        pytest.param("192.0.2.99", "POST", "key_exchange.json", id="unknown-post"),
    ],
)
def test_unknown_remote_forbidden(
    server: AylaLanServer, remote: str | None, method: str, path: str
) -> None:
    body = _body({"key_exchange": key_exchange_request()})
    assert server.handle(remote, method, path, body) == (403, {})


def test_get_other_path_not_found(server: AylaLanServer) -> None:
    _key_exchange(server)
    assert server.handle(DEVICE_HOST, "GET", "property/datapoint.json", b"") == (
        404,
        {},
    )


def test_get_commands_before_session(server: AylaLanServer) -> None:
    assert server.handle(DEVICE_HOST, "GET", "commands.json", b"") == (400, {})


def test_key_exchange_returns_unwrapped_reply(
    server: AylaLanServer, connection_changes: list[bool]
) -> None:
    status, reply = server.handle(
        DEVICE_HOST,
        "POST",
        "key_exchange.json",
        _body({"key_exchange": key_exchange_request()}),
    )
    assert status == 200
    assert set(reply) == {"random_2", "time_2"}
    assert connection_changes == [True]


def test_get_commands_after_session(server: AylaLanServer) -> None:
    mirror = _key_exchange(server)
    replies = [_fetch(server) for _ in range(len(PRIME) + 1)]
    # 206 while commands remain, so the module fetches again without a notify.
    assert [status for status, _ in replies] == [206] * (len(PRIME) - 1) + [200, 200]
    assert [mirror.decrypt_and_validate(p)["seq_no"] for _, p in replies] == list(
        range(len(PRIME) + 1)
    )


def test_get_commands_partial_while_write_queued(
    server: AylaLanServer, device: AylaLanDevice
) -> None:
    _drained(server)
    device.set_property("power", 1)
    device.set_property("mode", 1)
    assert [_fetch(server)[0] for _ in range(3)] == [206, 200, 200]


def test_key_exchange_ok_despite_primed_reads(
    server: AylaLanServer, device: AylaLanDevice
) -> None:
    _key_exchange(server)
    assert device.pending


@pytest.mark.parametrize(
    ("key_exchange", "status"),
    [
        pytest.param(
            key_exchange_request(key_id=KEY_ID + 1), 404, id="key-id-mismatch"
        ),
        pytest.param(key_exchange_request(ver=2), 400, id="unsupported-version"),
        pytest.param(
            {k: v for k, v in key_exchange_request().items() if k != "random_1"},
            400,
            id="missing-random",
        ),
        pytest.param(
            {k: v for k, v in key_exchange_request().items() if k != "key_id"},
            400,
            id="missing-key-id",
        ),
    ],
)
def test_key_exchange_rejected(
    server: AylaLanServer,
    connection_changes: list[bool],
    key_exchange: dict[str, Any],
    status: int,
) -> None:
    body = _body({"key_exchange": key_exchange})
    assert server.handle(DEVICE_HOST, "POST", "key_exchange.json", body) == (
        status,
        {},
    )
    assert connection_changes == []


def test_datapoint_fires_callback(
    server: AylaLanServer, datapoints: list[Datapoint]
) -> None:
    mirror = _drained(server)
    payload = mirror.encrypt_and_sign(
        {"seq_no": 0, "data": {"name": "power", "value": 1, "base_type": "boolean"}}
    )
    assert server.handle(
        DEVICE_HOST, "POST", "property/datapoint.json", _body(payload)
    ) == (200, {})
    assert datapoints == [Datapoint("power", 1, "boolean")]


DATAPOINT = {"name": "power", "value": 1}
ACK = {"id": "unknown1", "ack_status": 200, "ack_message": 0}


@pytest.mark.parametrize(
    ("path", "data"),
    [
        pytest.param("property/datapoint.json", DATAPOINT, id="datapoint"),
        pytest.param("property/datapoint/ack.json", ACK, id="ack"),
    ],
)
@pytest.mark.parametrize(
    ("fetches", "status"),
    [
        pytest.param(0, 206, id="queued"),
        pytest.param(len(PRIME) - 1, 206, id="one-left"),
        pytest.param(len(PRIME), 200, id="empty"),
    ],
)
def test_encrypted_post_status_follows_queue(
    server: AylaLanServer,
    path: str,
    data: dict[str, Any],
    fetches: int,
    status: int,
) -> None:
    mirror = _key_exchange(server)
    for _ in range(fetches):
        _fetch(server)
    payload = mirror.encrypt_and_sign({"seq_no": 0, "data": data})
    assert server.handle(DEVICE_HOST, "POST", path, _body(payload)) == (status, {})


@pytest.mark.parametrize(
    ("ack_status", "expected"),
    [
        pytest.param(200, type(None), id="accepted"),
        pytest.param(400, WriteRejectedError, id="rejected"),
    ],
)
async def test_write_acknowledged_through_server(
    server: AylaLanServer,
    device: AylaLanDevice,
    datapoints: list[Datapoint],
    ack_status: int,
    expected: type[object],
) -> None:
    mirror = _drained(server)
    write = asyncio.create_task(device.async_set_property("power", 1))
    await asyncio.sleep(0)

    status, payload = _fetch(server)
    assert status == 200
    command = mirror.decrypt_and_validate(payload)["data"]["properties"][0]
    ack = {"id": command["property"]["id"], "ack_status": ack_status, "ack_message": 0}
    body = _body(mirror.encrypt_and_sign({"seq_no": 0, "data": ack}))
    assert server.handle(DEVICE_HOST, "POST", "property/datapoint/ack.json", body) == (
        200,
        {},
    )

    (result,) = await asyncio.wait_for(asyncio.gather(write, return_exceptions=True), 1)
    assert type(result) is expected
    assert datapoints == []


def test_datapoint_bad_signature(
    server: AylaLanServer, datapoints: list[Datapoint]
) -> None:
    mirror = _key_exchange(server)
    payload = mirror.encrypt_and_sign({"seq_no": 0, "data": {"name": "power"}})
    payload["sign"] = "AAAA" + payload["sign"][4:]
    assert server.handle(
        DEVICE_HOST, "POST", "property/datapoint.json", _body(payload)
    ) == (400, {})
    assert datapoints == []


def test_datapoint_before_session(
    server: AylaLanServer, datapoints: list[Datapoint]
) -> None:
    body = _body({"enc": "AAAA", "sign": "AAAA"})
    assert server.handle(DEVICE_HOST, "POST", "property/datapoint.json", body) == (
        400,
        {},
    )
    assert datapoints == []


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(b"{not json", id="malformed-json"),
        pytest.param(b"\xff\xfe", id="not-utf8"),
        pytest.param(b"[1, 2]", id="list"),
        pytest.param(b'"key_exchange"', id="string"),
        pytest.param(b'{"enc": "AAAA"}', id="enc-without-sign"),
        pytest.param(b'{"enc": "!!!", "sign": "AAAA"}', id="enc-not-base64"),
    ],
)
def test_malformed_body_rejected(server: AylaLanServer, body: bytes) -> None:
    _key_exchange(server)
    assert server.handle(DEVICE_HOST, "POST", "property/datapoint.json", body) == (
        400,
        {},
    )


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b'{"other": 1}', id="unrecognised"),
    ],
)
def test_unrecognised_post_acknowledged(server: AylaLanServer, body: bytes) -> None:
    _key_exchange(server)
    # Plain 200 even with commands queued: only encrypted posts are partial.
    assert server.handle(DEVICE_HOST, "POST", "anything.json", body) == (200, {})


def test_non_dict_key_exchange_rejected(server: AylaLanServer) -> None:
    body = _body({"key_exchange": "nope"})
    assert server.handle(DEVICE_HOST, "POST", "key_exchange.json", body) == (400, {})


def test_non_string_enc_rejected(server: AylaLanServer) -> None:
    _key_exchange(server)
    body = _body({"enc": 123, "sign": "AAAA"})
    assert server.handle(DEVICE_HOST, "POST", "property/datapoint.json", body) == (
        400,
        {},
    )


def test_rejected_datapoint_does_not_break_session(
    server: AylaLanServer, datapoints: list[Datapoint]
) -> None:
    mirror = _key_exchange(server)
    forged = _body({"enc": "A" * 24, "sign": "AAAA"})
    assert server.handle(DEVICE_HOST, "POST", "property/datapoint.json", forged)[0] == (
        400
    )
    payload = mirror.encrypt_and_sign({"seq_no": 0, "data": {"name": "power"}})
    assert server.handle(
        DEVICE_HOST, "POST", "property/datapoint.json", _body(payload)
    ) == (206, {})
    assert datapoints == [Datapoint("power", None, None)]


def test_remove_device(server: AylaLanServer, device: AylaLanDevice) -> None:
    server.remove_device(device)
    assert server.handle(DEVICE_HOST, "GET", "commands.json", b"") == (403, {})


def test_remove_device_keeps_replacement(
    server: AylaLanServer, device: AylaLanDevice
) -> None:
    replacement = AylaLanDevice(
        MagicMock(),
        DEVICE_HOST,
        "OTHERDSN",
        LanKey(LAN_KEY, KEY_ID),
        "192.0.2.10",
        8123,
        lambda _: None,
    )
    server.add_device(replacement)
    server.remove_device(device)
    assert (
        server.handle(
            DEVICE_HOST,
            "POST",
            "key_exchange.json",
            _body({"key_exchange": key_exchange_request()}),
        )[0]
        == 200
    )
    assert replacement.connected
    assert not device.connected
