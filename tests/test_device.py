"""AylaLanDevice session handling, command queue and registration loop."""

import asyncio
import base64
import hashlib
import hmac
import itertools
import json
import logging
import re
from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine
from contextlib import AbstractContextManager, nullcontext
from enum import IntEnum
from typing import Any
from unittest.mock import MagicMock, patch

import aiohttp
import pytest
from conftest import (
    CALLBACK_HOST,
    CALLBACK_PORT,
    DEVICE_HOST,
    DSN,
    KEY_ID,
    LAN_KEY,
    PRIME,
    device_side,
    key_exchange_request,
)

from aioayla_lan import (
    LAN_URI,
    AylaLanDevice,
    CallbackRejectedError,
    CannotConnectError,
    Datapoint,
    InvalidKeyError,
    KeyIdMismatchError,
    LanKey,
    NoCallbackError,
    NoSessionError,
    SessionCrypto,
    SignatureError,
    WriteExpiredError,
    WriteRejectedError,
    WriteUnacknowledgedError,
)
from aioayla_lan.crypto import zero_pad
from aioayla_lan.device import (
    REJECTED_KEY_EXCHANGES,
    RETRY_INTERVAL,
    SESSION_TIMEOUT,
    STALLED_SESSIONS,
    WRITE_TTL,
)

START = 1000.0


def _read(name: str, cmd_id: int) -> dict[str, Any]:
    return {
        "cmds": [
            {
                "cmd": {
                    "method": "GET",
                    "resource": f"property.json?name={name}",
                    "uri": f"{LAN_URI}/property/datapoint.json",
                    "data": "",
                    "cmd_id": cmd_id,
                }
            }
        ]
    }


def _commands(device: AylaLanDevice, mirror: SessionCrypto) -> dict[str, Any]:
    body: dict[str, Any] = mirror.decrypt_and_validate(device.handle_commands())
    return body


def _written(device: AylaLanDevice, mirror: SessionCrypto) -> dict[str, Any]:
    prop: dict[str, Any] = _commands(device, mirror)["data"]["properties"][0][
        "property"
    ]
    return prop


def _ack(mirror: SessionCrypto, write_id: object, status: object = 200) -> Any:
    return mirror.encrypt_and_sign(
        {"seq_no": 0, "data": {"id": write_id, "ack_status": status, "ack_message": 0}}
    )


def _plain_device(http: MagicMock, datapoints: list[Datapoint]) -> AylaLanDevice:
    return AylaLanDevice(
        http,
        DEVICE_HOST,
        DSN,
        LanKey(LAN_KEY, KEY_ID),
        CALLBACK_HOST,
        CALLBACK_PORT,
        datapoints.append,
    )


class _Clock:
    """Stand-in for the `time` module as the device sees it."""

    def __init__(self) -> None:
        self.now = START

    def monotonic(self) -> float:
        return self.now

    def monotonic_ns(self) -> int:
        return int(self.now * 1e9)


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    """Freeze the device's monotonic clock; the event loop keeps real time."""
    clock = _Clock()
    monkeypatch.setattr("aioayla_lan.device.time", clock)
    return clock


def test_key_exchange_reply_is_unwrapped(device: AylaLanDevice) -> None:
    reply = device.handle_key_exchange(key_exchange_request())
    assert set(reply) == {"random_2", "time_2"}
    assert isinstance(reply["random_2"], str)
    assert len(reply["random_2"]) == 16
    assert isinstance(reply["time_2"], int)
    assert device.connected
    # Only the module fetching or posting proves it can reach us.
    assert device.last_seen is None


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"ver": 2}, id="ver-2"),
        pytest.param({"ver": None}, id="ver-missing"),
        pytest.param({"proto": 2}, id="proto-2"),
        pytest.param({"sec": 1}, id="sec-truthy"),
        pytest.param({"sec": {"cert": "x"}}, id="sec-dict"),
    ],
)
def test_key_exchange_rejects_unsupported(
    device: AylaLanDevice,
    connection_changes: list[bool],
    overrides: dict[str, Any],
) -> None:
    with pytest.raises(ValueError, match="unsupported key exchange"):
        device.handle_key_exchange(key_exchange_request(**overrides))
    assert not device.connected
    assert connection_changes == []


@pytest.mark.parametrize(
    "sec", [pytest.param(0, id="zero"), pytest.param(None, id="none")]
)
def test_key_exchange_accepts_falsy_sec(device: AylaLanDevice, sec: int | None) -> None:
    device.handle_key_exchange(key_exchange_request(sec=sec))
    assert device.connected


def test_key_exchange_rejects_key_id_mismatch(
    device: AylaLanDevice, connection_changes: list[bool]
) -> None:
    with pytest.raises(KeyIdMismatchError):
        device.handle_key_exchange(key_exchange_request(key_id=KEY_ID + 1))
    assert not device.connected
    assert connection_changes == []


@pytest.mark.parametrize(
    ("key_id", "expected"),
    [
        pytest.param(KEY_ID, KEY_ID, id="supplied"),
        pytest.param(None, None, id="unknown"),
    ],
)
def test_key_id_property(
    http: MagicMock,
    datapoints: list[Datapoint],
    key_id: int | None,
    expected: int | None,
) -> None:
    device = AylaLanDevice(
        http,
        DEVICE_HOST,
        DSN,
        LanKey(LAN_KEY, key_id),
        CALLBACK_HOST,
        CALLBACK_PORT,
        datapoints.append,
    )
    assert device.key_id == expected


def test_key_exchange_learns_key_id(
    http: MagicMock, datapoints: list[Datapoint]
) -> None:
    device = AylaLanDevice(
        http,
        DEVICE_HOST,
        DSN,
        LanKey(LAN_KEY),
        CALLBACK_HOST,
        CALLBACK_PORT,
        datapoints.append,
    )
    mirror = device_side(device.handle_key_exchange(key_exchange_request()))
    assert device.key_id == KEY_ID
    device.handle_datapoint(
        mirror.encrypt_and_sign({"seq_no": 0, "data": {"name": "power", "value": 1}})
    )
    assert datapoints == [Datapoint("power", 1)]

    with pytest.raises(KeyIdMismatchError):
        device.handle_key_exchange(key_exchange_request(key_id=KEY_ID + 1))
    assert device.key_id == KEY_ID


def test_key_exchange_primes_reads_and_reports_connected(
    device: AylaLanDevice, connection_changes: list[bool]
) -> None:
    assert not device.pending
    mirror = device_side(device.handle_key_exchange(key_exchange_request()))
    assert connection_changes == [True]
    assert device.pending
    assert [_commands(device, mirror)["data"] for _ in PRIME] == [
        _read(name, cmd_id) for cmd_id, name in enumerate(PRIME, start=1)
    ]
    assert not device.pending


def test_rekey_resets_sequence_and_reads(
    device: AylaLanDevice, mirror: SessionCrypto
) -> None:
    device.request_properties(["extra"])
    for _ in range(2):
        _commands(device, mirror)

    second = device_side(device.handle_key_exchange(key_exchange_request()))

    body = _commands(device, second)
    assert body["seq_no"] == 0
    assert body["data"]["cmds"][0]["cmd"]["resource"] == "property.json?name=power"
    _commands(device, second)
    assert not device.pending


@pytest.mark.parametrize(
    "call",
    [
        pytest.param(lambda d: d.handle_commands(), id="commands"),
        pytest.param(
            lambda d: d.handle_datapoint({"enc": "", "sign": ""}), id="datapoint"
        ),
    ],
)
def test_handlers_require_session(
    device: AylaLanDevice, call: Callable[[AylaLanDevice], object]
) -> None:
    with pytest.raises(NoSessionError):
        call(device)


def test_writes_served_before_reads(
    device: AylaLanDevice, mirror: SessionCrypto
) -> None:
    device.request_properties(["fan_speed"])
    device.set_property("power", 1)
    device.set_property("mode", "cool", base_type="string")

    writes = [_written(device, mirror) for _ in range(2)]
    for write in writes:
        del write["id"]
    assert writes == [
        {"base_type": "integer", "name": "power", "value": 1},
        {"base_type": "string", "name": "mode", "value": "cool"},
    ]
    assert [
        _commands(device, mirror)["data"]["cmds"][0]["cmd"]["resource"]
        for _ in range(3)
    ] == [f"property.json?name={name}" for name in (*PRIME, "fan_speed")]


def test_write_ids_are_random_tokens(
    device: AylaLanDevice, mirror: SessionCrypto
) -> None:
    device.set_property("power", 1)
    device.set_property("mode", 0)
    ids = [_written(device, mirror)["id"] for _ in range(2)]
    assert all(len(i) == 8 and i.isalnum() for i in ids)
    assert ids[0] != ids[1]


def test_empty_queue_returns_encrypted_empty_command(
    device: AylaLanDevice, mirror: SessionCrypto
) -> None:
    for _ in PRIME:
        _commands(device, mirror)
    payload = device.handle_commands()
    assert set(payload) == {"enc", "sign"}
    assert mirror.decrypt_and_validate(payload) == {
        "seq_no": len(PRIME),
        "data": {},
    }


def test_seq_no_increments(device: AylaLanDevice, mirror: SessionCrypto) -> None:
    assert [_commands(device, mirror)["seq_no"] for _ in range(5)] == [0, 1, 2, 3, 4]


def test_write_to_queued_name_replaces_it_and_moves_to_end(
    device: AylaLanDevice, mirror: SessionCrypto
) -> None:
    device.set_property("power", 1)
    device.set_property("mode", "cool", base_type="string")
    device.set_property("power", 0)

    writes = [_written(device, mirror) for _ in range(2)]
    assert [(w["name"], w["value"]) for w in writes] == [("mode", "cool"), ("power", 0)]
    assert _commands(device, mirror)["data"] == _read(PRIME[0], 1)


def test_write_to_collected_name_is_queued_again(
    device: AylaLanDevice, mirror: SessionCrypto
) -> None:
    device.set_property("power", 1)
    first = _written(device, mirror)
    device.set_property("power", 0)
    second = _written(device, mirror)
    assert (first["value"], second["value"]) == (1, 0)
    assert first["id"] != second["id"]


def test_repeated_read_is_asked_once(
    device: AylaLanDevice, mirror: SessionCrypto
) -> None:
    device.request_properties(["fan_speed", PRIME[0], "fan_speed"])
    device.request_properties(["fan_speed"])

    assert [_commands(device, mirror)["data"] for _ in range(3)] == [
        _read(name, cmd_id)
        for cmd_id, name in enumerate((*PRIME, "fan_speed"), start=1)
    ]
    assert not device.pending


def test_read_cmd_id_assigned_at_collection(
    device: AylaLanDevice, mirror: SessionCrypto
) -> None:
    device.request_properties(["fan_speed"])
    # The re-key drops the queued reads before they are collected.
    second = device_side(device.handle_key_exchange(key_exchange_request()))
    device.set_property("power", 1)

    assert "properties" in _commands(device, second)["data"]
    assert [_commands(device, second)["data"] for _ in PRIME] == [
        _read(name, cmd_id) for cmd_id, name in enumerate(PRIME, start=1)
    ]


def test_pending_since_tracks_busy_queue(clock: _Clock, device: AylaLanDevice) -> None:
    assert device.pending_since is None
    mirror = device_side(device.handle_key_exchange(key_exchange_request()))
    assert device.pending_since == START

    clock.now += 5
    device.set_property("power", 1)
    assert device.pending_since == START
    for _ in range(1 + len(PRIME)):
        _commands(device, mirror)
    assert device.pending_since is None

    clock.now += 5
    device.request_properties(["fan_speed"])
    assert device.pending_since == START + 10


@pytest.mark.parametrize(
    ("queue", "expected"),
    [
        pytest.param(
            lambda d: d.request_properties(["fan_speed"]), START + 5, id="reads-only"
        ),
        pytest.param(lambda d: d.set_property("power", 1), START, id="write"),
    ],
)
def test_key_exchange_restarts_pending_since_unless_writes_wait(
    clock: _Clock,
    device: AylaLanDevice,
    queue: Callable[[AylaLanDevice], None],
    expected: float,
) -> None:
    device.handle_key_exchange(key_exchange_request())
    queue(device)
    clock.now += 5
    device.handle_key_exchange(key_exchange_request())
    assert device.pending_since == expected


@pytest.mark.parametrize(
    "action",
    [
        pytest.param(
            lambda d: d.handle_key_exchange(key_exchange_request()),
            id="key-exchange-without-prime",
        ),
        pytest.param(lambda d: d.request_properties([]), id="no-reads"),
    ],
)
def test_nothing_queued_does_not_wake(
    http: MagicMock,
    datapoints: list[Datapoint],
    action: Callable[[AylaLanDevice], object],
) -> None:
    device = _plain_device(http, datapoints)
    action(device)
    assert not device.pending
    assert device.pending_since is None
    assert not device._wake.is_set()


def _undecodable_datapoint(device: AylaLanDevice, mirror: SessionCrypto) -> None:
    device.handle_datapoint(_sign_raw(mirror, b'{"seq_no":0 "data":{}}'))


@pytest.mark.parametrize(
    "contact",
    [
        pytest.param(_commands, id="commands"),
        pytest.param(
            lambda d, m: d.handle_datapoint(
                m.encrypt_and_sign({"seq_no": 0, "data": {"name": "power"}})
            ),
            id="datapoint",
        ),
        pytest.param(_undecodable_datapoint, id="undecodable-datapoint"),
    ],
)
def test_contact_updates_last_seen(
    clock: _Clock,
    device: AylaLanDevice,
    mirror: SessionCrypto,
    contact: Callable[[AylaLanDevice, SessionCrypto], object],
) -> None:
    assert device.last_seen is None
    clock.now += 5
    contact(device, mirror)
    assert device.last_seen == START + 5


@pytest.mark.parametrize(
    ("age", "served"),
    [
        pytest.param(WRITE_TTL, "properties", id="at-ttl"),
        pytest.param(WRITE_TTL + 1, "cmds", id="past-ttl"),
    ],
)
def test_stale_write_dropped_at_collection(
    clock: _Clock,
    device: AylaLanDevice,
    mirror: SessionCrypto,
    age: float,
    served: str,
) -> None:
    device.set_property("power", 1)
    clock.now += age
    assert set(_commands(device, mirror)["data"]) == {served}


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        pytest.param(
            {"name": "power", "value": 1, "base_type": "boolean"},
            Datapoint("power", 1, "boolean"),
            id="full",
        ),
        pytest.param(
            {"name": "display_temperature", "value": 23.5},
            Datapoint("display_temperature", 23.5, None),
            id="no-base-type",
        ),
    ],
)
def test_handle_datapoint_reports_value(
    device: AylaLanDevice,
    mirror: SessionCrypto,
    datapoints: list[Datapoint],
    data: dict[str, Any],
    expected: Datapoint,
) -> None:
    device.handle_datapoint(mirror.encrypt_and_sign({"seq_no": 0, "data": data}))
    assert datapoints == [expected]


@pytest.mark.parametrize(
    "update",
    [
        pytest.param({"seq_no": 0, "data": {"value": 1}}, id="data-without-name"),
        pytest.param({"seq_no": 0, "data": {}}, id="empty-data"),
        pytest.param({"seq_no": 0}, id="no-data"),
        pytest.param({"seq_no": 0, "data": "power"}, id="data-not-an-object"),
        pytest.param([{"name": "power"}], id="not-an-object"),
    ],
)
def test_handle_datapoint_ignores_update_without_name(
    device: AylaLanDevice,
    mirror: SessionCrypto,
    datapoints: list[Datapoint],
    update: object,
) -> None:
    device.handle_datapoint(mirror.encrypt_and_sign(update))
    assert datapoints == []


def test_handle_datapoint_logs_undecodable_payload(
    device: AylaLanDevice,
    mirror: SessionCrypto,
    datapoints: list[Datapoint],
    caplog: pytest.LogCaptureFixture,
) -> None:
    text = '{"seq_no":1 "data":{}}'
    with patch.object(json, "dumps", return_value=text):
        payload = mirror.encrypt_and_sign(None)
    caplog.set_level(logging.DEBUG, logger="aioayla_lan")

    device.handle_datapoint(payload)

    assert datapoints == []
    # Only the plaintext is logged, never the payload or session material.
    assert caplog.messages == [f"{DSN}: undecodable payload: {text!r}"]


def _sign_raw(mirror: SessionCrypto, text: bytes) -> dict[str, str]:
    """Encrypt and sign plaintext that `json.dumps` cannot produce."""
    direction = mirror._app
    return {
        "enc": base64.b64encode(direction.encryptor.update(zero_pad(text))).decode(),
        "sign": base64.b64encode(
            hmac.new(direction.sign_key, text, hashlib.sha256).digest()
        ).decode(),
    }


def test_handle_datapoint_logs_non_utf8_payload(
    device: AylaLanDevice,
    mirror: SessionCrypto,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # A Latin-1 degree sign, as firmware might put in a free-text property.
    text = b'{"seq_no":0,"data":{"name":"device_name","value":"20\xb0C"}}'
    payload = _sign_raw(mirror, text)
    caplog.set_level(logging.DEBUG, logger="aioayla_lan")

    device.handle_datapoint(payload)

    assert caplog.messages == [f"{DSN}: undecodable payload: {text!r}"]


async def _queue_async_write(
    device: AylaLanDevice, name: str = "power", value: Any = 1
) -> asyncio.Task[None]:
    task = asyncio.create_task(device.async_set_property(name, value))
    await asyncio.sleep(0)
    return task


def _refused(status: object) -> AbstractContextManager[object]:
    """Expect an explicit refusal, never mistaken for a missing ack."""
    return pytest.raises(
        WriteRejectedError,
        match=f"ack_status {status}",
        check=lambda err: not isinstance(err, WriteUnacknowledgedError),
    )


@pytest.mark.parametrize(
    ("status", "expectation"),
    [
        pytest.param(200, nullcontext(), id="200"),
        pytest.param(204, nullcontext(), id="204"),
        pytest.param(400, _refused(400), id="400"),
        pytest.param(500, _refused(500), id="500"),
        pytest.param("200", _refused("200"), id="not-int"),
    ],
)
async def test_async_set_property_settled_by_ack(
    device: AylaLanDevice,
    mirror: SessionCrypto,
    datapoints: list[Datapoint],
    caplog: pytest.LogCaptureFixture,
    status: object,
    expectation: AbstractContextManager[object],
) -> None:
    caplog.set_level(logging.DEBUG, logger="aioayla_lan")
    write = await _queue_async_write(device)
    write_id = _written(device, mirror)["id"]
    await asyncio.sleep(0)
    assert not write.done()

    device.handle_datapoint(_ack(mirror, write_id, status))

    with expectation:
        await asyncio.wait_for(write, 1)
    assert datapoints == []
    assert caplog.messages == [
        f"{DSN}: sending power = 1 (id {write_id}, seq 0)",
        f"{DSN}: ack {status} for power (id {write_id})",
    ]


class _Mode(IntEnum):
    FAN = 5


def test_write_logs_enum_as_plain_value(
    device: AylaLanDevice, mirror: SessionCrypto, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="aioayla_lan")
    device.set_property("mode", _Mode.FAN)

    write_id = _written(device, mirror)["id"]

    assert caplog.messages == [f"{DSN}: sending mode = 5 (id {write_id}, seq 0)"]


def test_commands_log_cmd_id_and_seq(
    device: AylaLanDevice, mirror: SessionCrypto, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="aioayla_lan")
    device.set_property("power", 1)

    write_id = _written(device, mirror)["id"]
    for _ in PRIME:
        _commands(device, mirror)

    # The write takes seq 0 but no cmd_id, so the two counters differ.
    assert caplog.messages == [
        f"{DSN}: sending power = 1 (id {write_id}, seq 0)",
        f"{DSN}: sending read of power (cmd_id 1, seq 1)",
        f"{DSN}: sending read of mode (cmd_id 2, seq 2)",
    ]


async def test_async_set_property_unacknowledged_without_ack(
    device: AylaLanDevice,
    mirror: SessionCrypto,
    datapoints: list[Datapoint],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="aioayla_lan")
    monkeypatch.setattr("aioayla_lan.device.ACK_TIMEOUT", 0.01)
    write = await _queue_async_write(device)
    write_id = _written(device, mirror)["id"]

    # Callers that only handle WriteRejectedError still catch a missing ack.
    with pytest.raises(
        WriteRejectedError, match=f"^{DSN}: power was not acknowledged$"
    ) as exc_info:
        await asyncio.wait_for(write, 1)
    assert type(exc_info.value) is WriteUnacknowledgedError
    # A late ack finds nothing to settle.
    device.handle_datapoint(_ack(mirror, write_id))

    assert datapoints == []
    late = {"id": write_id, "ack_status": 200, "ack_message": 0}
    assert caplog.messages == [
        f"{DSN}: sending power = 1 (id {write_id}, seq 0)",
        f"{DSN}: no ack for power (id {write_id}) within 0.01 s",
        f"{DSN}: ack for no pending write: {late}",
    ]


@pytest.mark.parametrize(
    "collect",
    [
        pytest.param(lambda device, mirror: None, id="queued"),
        pytest.param(_written, id="collected"),
    ],
)
async def test_cancelled_caller_leaves_no_timer(
    device: AylaLanDevice,
    mirror: SessionCrypto,
    collect: Callable[[AylaLanDevice, SessionCrypto], object],
) -> None:
    write = await _queue_async_write(device)
    collect(device, mirror)
    armed = [*device._writes.values(), *device._unacked.values()]
    assert armed[0].timer is not None

    write.cancel()
    await asyncio.sleep(0)

    assert armed[0].timer is None
    assert device._unacked == {}


@pytest.mark.parametrize(
    "name",
    [
        pytest.param("power", id="same-name"),
        pytest.param("mode", id="other-name"),
    ],
)
async def test_cancelled_caller_leaves_other_callers_armed(
    device: AylaLanDevice, mirror: SessionCrypto, name: str
) -> None:
    first = await _queue_async_write(device, "power", 1)
    second = await _queue_async_write(device, name, 0)

    second.cancel()
    await asyncio.sleep(0)

    assert second.cancelled()
    assert device._writes["power"].timer is not None
    device.handle_datapoint(_ack(mirror, _written(device, mirror)["id"]))
    await asyncio.wait_for(first, 1)


@pytest.mark.parametrize(
    ("queue", "pending_since"),
    [
        pytest.param(lambda d: None, None, id="nothing-else"),
        pytest.param(
            lambda d: d.request_properties(["fan_speed"]), START, id="reads-wait"
        ),
    ],
)
async def test_expired_write_clears_pending_since_unless_reads_wait(
    clock: _Clock,
    http: MagicMock,
    datapoints: list[Datapoint],
    monkeypatch: pytest.MonkeyPatch,
    queue: Callable[[AylaLanDevice], None],
    pending_since: float | None,
) -> None:
    """An expired write must not leave the queue looking stuck, nor hide reads."""
    monkeypatch.setattr("aioayla_lan.device.WRITE_TTL", 0.01)
    device = _plain_device(http, datapoints)
    write = await _queue_async_write(device)
    queue(device)

    with pytest.raises(WriteExpiredError):
        await asyncio.wait_for(write, 1)

    assert device.pending_since == pending_since
    assert device.pending is (pending_since is not None)


async def test_async_set_property_expired_at_collection(
    clock: _Clock, device: AylaLanDevice, mirror: SessionCrypto
) -> None:
    write = await _queue_async_write(device)
    clock.now += WRITE_TTL + 1

    assert _commands(device, mirror)["data"] == _read(PRIME[0], 1)
    with pytest.raises(WriteExpiredError, match="power was not collected"):
        await asyncio.wait_for(write, 1)


async def test_async_set_property_expires_when_never_collected(
    device: AylaLanDevice, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("aioayla_lan.device.WRITE_TTL", 0.01)
    monkeypatch.setattr("aioayla_lan.device.ACK_TIMEOUT", 0.01)
    with pytest.raises(WriteExpiredError, match="power was not collected"):
        await device.async_set_property("power", 1)


@pytest.mark.parametrize(
    "ack_id",
    [
        pytest.param("unknown1", id="unknown"),
        pytest.param(12345, id="not-a-string"),
        pytest.param(None, id="missing"),
    ],
)
async def test_ack_with_unknown_id_ignored(
    device: AylaLanDevice,
    mirror: SessionCrypto,
    datapoints: list[Datapoint],
    caplog: pytest.LogCaptureFixture,
    ack_id: object,
) -> None:
    write = await _queue_async_write(device)
    write_id = _written(device, mirror)["id"]
    caplog.set_level(logging.DEBUG, logger="aioayla_lan")

    device.handle_datapoint(_ack(mirror, ack_id, 500))
    await asyncio.sleep(0)
    assert not write.done()
    unmatched = {"id": ack_id, "ack_status": 500, "ack_message": 0}
    assert caplog.messages == [f"{DSN}: ack for no pending write: {unmatched}"]

    device.handle_datapoint(_ack(mirror, write_id))
    await asyncio.wait_for(write, 1)
    assert datapoints == []


def test_ack_for_fire_and_forget_write_ignored(
    device: AylaLanDevice, mirror: SessionCrypto, datapoints: list[Datapoint]
) -> None:
    device.set_property("power", 1)
    device.handle_datapoint(_ack(mirror, _written(device, mirror)["id"], 500))
    assert datapoints == []


async def test_ack_carrying_a_name_is_not_a_datapoint(
    device: AylaLanDevice, mirror: SessionCrypto, datapoints: list[Datapoint]
) -> None:
    write = await _queue_async_write(device)
    ack = {"id": _written(device, mirror)["id"], "ack_status": 200, "ack_message": 0}
    device.handle_datapoint(
        mirror.encrypt_and_sign({"seq_no": 0, "data": ack | {"name": "power"}})
    )
    await asyncio.wait_for(write, 1)
    assert datapoints == []


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        pytest.param(200, type(None), id="accepted"),
        pytest.param(500, WriteRejectedError, id="rejected"),
    ],
)
async def test_coalesced_writes_settled_by_one_ack(
    device: AylaLanDevice,
    mirror: SessionCrypto,
    status: int,
    expected: type[object],
) -> None:
    first = await _queue_async_write(device, "power", 1)
    device.set_property("mode", 2)
    device.set_property("power", 2)
    second = await _queue_async_write(device, "power", 0)

    writes = [_written(device, mirror) for _ in range(2)]
    assert [(w["name"], w["value"]) for w in writes] == [("mode", 2), ("power", 0)]
    device.handle_datapoint(_ack(mirror, writes[1]["id"], status))

    results = await asyncio.wait_for(
        asyncio.gather(first, second, return_exceptions=True), 1
    )
    assert [type(result) for result in results] == [expected, expected]


async def test_superseded_caller_learns_fate_of_late_replacement(
    device: AylaLanDevice, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("aioayla_lan.device.WRITE_TTL", 0.1)
    monkeypatch.setattr("aioayla_lan.device.ACK_TIMEOUT", 0.05)
    first = asyncio.create_task(device.async_set_property("power", 1))
    await asyncio.sleep(0.08)
    second = asyncio.create_task(device.async_set_property("power", 0))
    # Past the first caller's deadline, well within the replacement's TTL.
    await asyncio.sleep(0.08)
    mirror = device_side(device.handle_key_exchange(key_exchange_request()))
    device.handle_datapoint(_ack(mirror, _written(device, mirror)["id"]))

    results = await asyncio.wait_for(
        asyncio.gather(first, second, return_exceptions=True), 1
    )
    assert list(results) == [None, None]


class _Registration:
    """One recorded `local_reg.json` request."""

    def __init__(self, method: str, url: str, kwargs: dict[str, Any]) -> None:
        self.method = method
        self.url = url
        self.params = kwargs["params"]
        self.json = kwargs["json"]
        self.timeout = kwargs["timeout"]
        self.at = asyncio.get_running_loop().time()

    @property
    def notify(self) -> int:
        notify: int = self.json["local_reg"]["notify"]
        return notify


class _FakeResponse:
    def __init__(self, error: aiohttp.ClientResponseError | None) -> None:
        self._error = error
        self.status = 200 if error is None else error.status

    def raise_for_status(self) -> None:
        if self._error is not None:
            raise self._error


class _FakeRequest:
    def __init__(self, http: "_FakeHttp", call: _Registration) -> None:
        self._http = http
        self._call = call

    async def __aenter__(self) -> _FakeResponse:
        await self._http.calls.put(self._call)
        if self._http.errors:
            error = self._http.errors.pop(0)
        else:
            error = self._http.failing.get(self._call.method)
        # Only an HTTP error comes with a response; anything else has none.
        if error is None or isinstance(error, aiohttp.ClientResponseError):
            return _FakeResponse(error)
        raise error

    async def __aexit__(self, *exc: object) -> None:
        return None


class _FakeHttp:
    """Registration endpoint that hands each request to the test in lockstep."""

    def __init__(self) -> None:
        self.calls: asyncio.Queue[_Registration] = asyncio.Queue(maxsize=1)
        self.errors: list[BaseException | None] = []
        # Raised for every request of that method once `errors` runs out.
        self.failing: dict[str, BaseException] = {}

    def request(self, method: str, url: str, **kwargs: Any) -> _FakeRequest:
        return _FakeRequest(self, _Registration(method, url, kwargs))

    async def next_call(self) -> _Registration:
        return await asyncio.wait_for(self.calls.get(), 1)

    async def calls_until(self, method: str) -> list[_Registration]:
        calls = [await self.next_call()]
        while calls[-1].method != method:
            calls.append(await self.next_call())
        return calls


@pytest.fixture
def fake_http() -> _FakeHttp:
    return _FakeHttp()


@pytest.fixture
async def runner(
    fake_http: _FakeHttp,
    datapoints: list[Datapoint],
    connection_changes: list[bool],
) -> AsyncIterator[Callable[[], AylaLanDevice]]:
    device = AylaLanDevice(
        fake_http,  # type: ignore[arg-type]
        DEVICE_HOST,
        DSN,
        LanKey(LAN_KEY, KEY_ID),
        CALLBACK_HOST,
        CALLBACK_PORT,
        datapoints.append,
        connection_changes.append,
    )
    task: asyncio.Task[None] | None = None

    def start() -> AylaLanDevice:
        nonlocal task
        task = asyncio.create_task(device.run())
        return device

    yield start
    assert task is not None
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_run_first_registration_is_post_then_put(
    runner: Callable[[], AylaLanDevice], fake_http: _FakeHttp
) -> None:
    device = runner()
    first = await fake_http.next_call()
    device.set_property("power", 1)
    second = await fake_http.next_call()

    assert (first.method, second.method) == ("POST", "PUT")
    for call in (first, second):
        assert call.url == f"http://{DEVICE_HOST}/local_reg.json"
        assert call.params == {"dsn": DSN}
        assert isinstance(call.timeout, aiohttp.ClientTimeout)
    assert first.json == {
        "local_reg": {
            "ip": CALLBACK_HOST,
            "port": CALLBACK_PORT,
            "uri": "/local_lan",
            "notify": 0,
        }
    }
    assert second.notify == 1


async def test_run_heartbeat_reregisters_without_work(
    runner: Callable[[], AylaLanDevice],
    fake_http: _FakeHttp,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("aioayla_lan.device.HEARTBEAT_INTERVAL", 0.01)
    runner()
    calls = [await fake_http.next_call() for _ in range(3)]
    assert [(c.method, c.notify) for c in calls] == [
        ("POST", 0),
        ("PUT", 0),
        ("PUT", 0),
    ]


TRANSIENT_ERRORS = [
    pytest.param(aiohttp.ClientConnectionError("refused"), id="client-error"),
    pytest.param(TimeoutError(), id="timeout"),
]
# Slack for timer resolution when comparing loop timestamps.
SLACK = 0.02


async def test_run_follows_module_through_queue_without_reregistering(
    runner: Callable[[], AylaLanDevice],
    fake_http: _FakeHttp,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("aioayla_lan.device.NOTIFY_TIMEOUT", 0.2)
    device = runner()
    await fake_http.next_call()
    mirror = device_side(device.handle_key_exchange(key_exchange_request()))
    names = [f"prop_{i}" for i in range(6)]
    for name in names:
        device.set_property(name, 1)

    notify = await fake_http.next_call()
    assert (notify.method, notify.notify) == ("PUT", 1)
    # Spread over longer than NOTIFY_TIMEOUT: each fetch restarts the timer.
    for _ in names:
        await asyncio.sleep(0.05)
        _commands(device, mirror)
    assert not device.pending

    await asyncio.sleep(0.25)
    assert fake_http.calls.empty()


async def test_run_notifies_again_when_module_stalls(
    runner: Callable[[], AylaLanDevice],
    fake_http: _FakeHttp,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="aioayla_lan")
    monkeypatch.setattr("aioayla_lan.device.NOTIFY_TIMEOUT", 0.05)
    device = runner()
    await fake_http.next_call()
    mirror = device_side(device.handle_key_exchange(key_exchange_request()))
    device.set_property("power", 1)
    device.set_property("mode", 1)

    notify = await fake_http.next_call()
    _commands(device, mirror)
    renotify = await fake_http.next_call()

    assert [(c.method, c.notify) for c in (notify, renotify)] == [("PUT", 1)] * 2
    assert renotify.at - notify.at >= 0.05 - SLACK
    assert device.pending
    assert f"{DSN}: notified, but the queue was not collected" in caplog.messages


async def test_run_registers_afresh_when_notifies_go_unanswered(
    runner: Callable[[], AylaLanDevice],
    fake_http: _FakeHttp,
    connection_changes: list[bool],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A module that accepts notifies but stops dialling back is re-registered."""
    monkeypatch.setattr("aioayla_lan.device.NOTIFY_TIMEOUT", 0.02)
    monkeypatch.setattr("aioayla_lan.device.SESSION_TIMEOUT", 0.1)
    device = runner()
    await fake_http.next_call()
    mirror = device_side(device.handle_key_exchange(key_exchange_request()))
    _commands(device, mirror)
    contact = asyncio.get_running_loop().time()
    device.set_property("power", 1)

    # Bounded: without the fix the PUTs never stop.
    calls = [await fake_http.next_call() for _ in range(20)]
    *ignored, fresh = calls[: [c.method for c in calls].index("POST") + 1]

    assert {(c.method, c.notify) for c in ignored} == {("PUT", 1)}
    assert len(ignored) >= 2
    assert fresh.at - contact >= 0.1 - SLACK
    assert fresh.notify == 1
    # The session stands until the module replaces it with a key exchange.
    assert device.connected
    assert connection_changes == [True]


async def test_run_fresh_session_gets_full_timeout(
    runner: Callable[[], AylaLanDevice],
    fake_http: _FakeHttp,
    connection_changes: list[bool],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A module that re-keys but never fetches is not re-keyed every notify."""
    monkeypatch.setattr("aioayla_lan.device.NOTIFY_TIMEOUT", 0.02)
    monkeypatch.setattr("aioayla_lan.device.SESSION_TIMEOUT", 0.1)
    loop = asyncio.get_running_loop()
    device = runner()
    await fake_http.next_call()
    mirror = device_side(device.handle_key_exchange(key_exchange_request()))
    _commands(device, mirror)
    # Last heard from longer ago than SESSION_TIMEOUT when it keys again.
    await asyncio.sleep(0.15)
    device.handle_key_exchange(key_exchange_request())
    keyed = loop.time()
    device.request_properties(["power"])

    *ignored, fresh = await fake_http.calls_until("POST")

    assert {(c.method, c.notify) for c in ignored} == {("PUT", 1)}
    assert len(ignored) >= 2
    assert fresh.at - keyed >= 0.1 - SLACK
    assert connection_changes == [True, True]


@pytest.mark.parametrize(
    ("stalled", "rekey_after"),
    [
        pytest.param(0, 30.0, id="0"),
        pytest.param(1, 30.0, id="1"),
        pytest.param(2, 30.0, id="2"),
        pytest.param(3, 60.0, id="3"),
        pytest.param(4, 120.0, id="4"),
        pytest.param(5, 120.0, id="5-capped"),
    ],
)
def test_rekey_after_backs_off(
    device: AylaLanDevice, stalled: int, rekey_after: float
) -> None:
    device._stalled_sessions = stalled
    assert device._rekey_after() == rekey_after


async def test_run_stalled_sessions_back_off(
    runner: Callable[[], AylaLanDevice],
    fake_http: _FakeHttp,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A module that re-keys on every registration but never fetches."""
    caplog.set_level(logging.DEBUG, logger="aioayla_lan")
    monkeypatch.setattr("aioayla_lan.device.NOTIFY_TIMEOUT", 0.01)
    monkeypatch.setattr("aioayla_lan.device.SESSION_TIMEOUT", 0.1)
    monkeypatch.setattr("aioayla_lan.device.MAX_REKEY_INTERVAL", 0.4)
    loop = asyncio.get_running_loop()
    device = runner()
    await fake_http.next_call()
    mirror = device_side(device.handle_key_exchange(key_exchange_request()))
    _commands(device, mirror)
    keyed = loop.time()
    # Reads only: a queued write re-keys sooner than the back-off.
    device.request_properties(["power"])

    gaps: list[float] = []
    for _ in range(6):
        *_, fresh = await fake_http.calls_until("POST")
        gaps.append(fresh.at - keyed)
        device.handle_key_exchange(key_exchange_request())
        keyed = loop.time()
        # A key exchange drops queued reads.
        device.request_properties(["power"])

    expected = [0.1, 0.1, 0.1, 0.2, 0.4, 0.4]
    assert all(gap >= rekey - SLACK for gap, rekey in zip(gaps, expected, strict=True))
    # Below the next step: no back-off too early, none past the cap.
    assert all(gap < rekey + 0.1 for gap, rekey in zip(gaps, expected, strict=True))
    assert [m for m in caplog.messages if "stalled" in m] == [
        f"{DSN}: session stalled ({count} in a row), keying a new one"
        for count in range(1, 7)
    ]


async def test_run_first_session_rekeyed_when_never_heard_from(
    runner: Callable[[], AylaLanDevice],
    fake_http: _FakeHttp,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A module that keys but never fetches or pushes is not notified forever."""
    monkeypatch.setattr("aioayla_lan.device.NOTIFY_TIMEOUT", 0.02)
    monkeypatch.setattr("aioayla_lan.device.SESSION_TIMEOUT", 0.1)
    device = runner()
    await fake_http.next_call()
    device.handle_key_exchange(key_exchange_request())
    keyed = asyncio.get_running_loop().time()
    device.request_properties(["power"])

    # Bounded: a session never heard from would otherwise get PUTs forever.
    calls = [await fake_http.next_call() for _ in range(20)]
    *ignored, fresh = calls[: [c.method for c in calls].index("POST") + 1]

    assert {(c.method, c.notify) for c in ignored} == {("PUT", 1)}
    assert len(ignored) >= 2
    assert fresh.at - keyed >= 0.1 - SLACK
    assert device.last_seen is None


async def test_run_write_rekeys_despite_back_off(
    runner: Callable[[], AylaLanDevice],
    fake_http: _FakeHttp,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A write is not held back past its TTL by a backed-off re-key."""
    caplog.set_level(logging.DEBUG, logger="aioayla_lan")
    monkeypatch.setattr("aioayla_lan.device.NOTIFY_TIMEOUT", 0.02)
    monkeypatch.setattr("aioayla_lan.device.SESSION_TIMEOUT", 0.1)
    device = runner()
    await fake_http.next_call()
    device.handle_key_exchange(key_exchange_request())
    keyed = asyncio.get_running_loop().time()
    # Backed off to twice SESSION_TIMEOUT.
    device._stalled_sessions = STALLED_SESSIONS
    device.set_property("power", 1)

    *ignored, fresh = await fake_http.calls_until("POST")

    assert {(c.method, c.notify) for c in ignored} == {("PUT", 1)}
    assert 0.1 - SLACK <= fresh.at - keyed < 0.2
    assert fresh.notify == 1
    assert [m for m in caplog.messages if "stalled" in m] == [
        f"{DSN}: session stalled, keying a new one for a write"
    ]
    assert device._stalled_sessions == STALLED_SESSIONS


async def test_run_write_rekey_waits_for_session_timeout(
    runner: Callable[[], AylaLanDevice],
    fake_http: _FakeHttp,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A write re-keys a stalled session at most once per SESSION_TIMEOUT."""
    caplog.set_level(logging.DEBUG, logger="aioayla_lan")
    monkeypatch.setattr("aioayla_lan.device.NOTIFY_TIMEOUT", 0.02)
    # Far beyond the notifies collected below, so none may re-key.
    monkeypatch.setattr("aioayla_lan.device.SESSION_TIMEOUT", 1.0)
    device = runner()
    await fake_http.next_call()
    device.handle_key_exchange(key_exchange_request())
    device._stalled_sessions = STALLED_SESSIONS
    device.set_property("power", 1)

    calls = [await fake_http.next_call() for _ in range(4)]

    assert {(c.method, c.notify) for c in calls} == {("PUT", 1)}
    assert [m for m in caplog.messages if "stalled" in m] == []
    assert device._stalled_sessions == STALLED_SESSIONS


async def test_run_stale_write_stops_rekeying(
    runner: Callable[[], AylaLanDevice],
    fake_http: _FakeHttp,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A fire-and-forget write past its TTL no longer overrides the back-off."""
    caplog.set_level(logging.DEBUG, logger="aioayla_lan")
    monkeypatch.setattr("aioayla_lan.device.NOTIFY_TIMEOUT", 0.02)
    monkeypatch.setattr("aioayla_lan.device.SESSION_TIMEOUT", 0.1)
    monkeypatch.setattr("aioayla_lan.device.WRITE_TTL", 0.15)
    loop = asyncio.get_running_loop()
    device = runner()
    await fake_http.next_call()
    device.handle_key_exchange(key_exchange_request())
    # Backed off to twice SESSION_TIMEOUT.
    device._stalled_sessions = STALLED_SESSIONS
    device.set_property("power", 1)
    # Keeps notifying once the write is gone, so the back-off still runs.
    device.request_properties(["mode"])

    await fake_http.calls_until("POST")
    device.handle_key_exchange(key_exchange_request())
    keyed = loop.time()
    device.request_properties(["mode"])
    *_, fresh = await fake_http.calls_until("POST")

    assert fresh.at - keyed >= 0.2 - SLACK
    assert [m for m in caplog.messages if "stalled" in m or "stale" in m] == [
        f"{DSN}: session stalled, keying a new one for a write",
        f"{DSN}: dropping stale write of power",
        f"{DSN}: session stalled ({STALLED_SESSIONS + 1} in a row), keying a new one",
    ]


async def test_run_write_without_stalled_sessions_waits_for_silence(
    runner: Callable[[], AylaLanDevice],
    fake_http: _FakeHttp,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With no stalled session yet, a write follows the normal silence rule."""
    monkeypatch.setattr("aioayla_lan.device.NOTIFY_TIMEOUT", 0.02)
    monkeypatch.setattr("aioayla_lan.device.SESSION_TIMEOUT", 0.1)
    loop = asyncio.get_running_loop()
    device = runner()
    await fake_http.next_call()
    mirror = device_side(device.handle_key_exchange(key_exchange_request()))
    keyed = loop.time()
    device.set_property("power", 1)

    async def module() -> None:
        # Pushing keeps it heard from, but it never fetches the write.
        for seq_no in itertools.count():
            await asyncio.sleep(0.02)
            device.handle_datapoint(
                mirror.encrypt_and_sign(
                    {"seq_no": seq_no, "data": {"name": "power", "value": 0}}
                )
            )

    pushing = asyncio.create_task(module())
    try:
        calls = [await fake_http.next_call() for _ in range(15)]
    finally:
        pushing.cancel()

    # Well past SESSION_TIMEOUT since the key exchange, yet no re-key.
    assert calls[-1].at - keyed >= 0.1 + 2 * SLACK
    assert {(c.method, c.notify) for c in calls} == {("PUT", 1)}
    assert device._stalled_sessions == 0


async def test_run_drained_queue_resets_stalled_sessions(
    runner: Callable[[], AylaLanDevice], fake_http: _FakeHttp
) -> None:
    device = runner()
    await fake_http.next_call()
    mirror = device_side(device.handle_key_exchange(key_exchange_request()))
    device._stalled_sessions = STALLED_SESSIONS
    device.set_property("power", 1)

    assert (await fake_http.next_call()).notify == 1
    _commands(device, mirror)
    # Let the run loop see the queue drain.
    await asyncio.sleep(0.01)

    assert device._stalled_sessions == 0
    assert device._rekey_after() == SESSION_TIMEOUT


async def test_run_busy_module_is_not_registered_afresh(
    runner: Callable[[], AylaLanDevice],
    fake_http: _FakeHttp,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A module pushing values without fetching commands is left to finish."""
    monkeypatch.setattr("aioayla_lan.device.NOTIFY_TIMEOUT", 0.02)
    monkeypatch.setattr("aioayla_lan.device.SESSION_TIMEOUT", 0.1)
    device = runner()
    await fake_http.next_call()
    mirror = device_side(device.handle_key_exchange(key_exchange_request()))
    device.set_property("power", 1)

    async def module() -> None:
        # Like a catalogue push: steady datapoints, no command fetches.
        for seq_no in itertools.count():
            await asyncio.sleep(0.02)
            device.handle_datapoint(
                mirror.encrypt_and_sign(
                    {"seq_no": seq_no, "data": {"name": "power", "value": 0}}
                )
            )

    pushing = asyncio.create_task(module())
    try:
        calls = [await fake_http.next_call() for _ in range(10)]
    finally:
        pushing.cancel()

    assert calls[-1].at - calls[0].at >= 0.1
    assert {(c.method, c.notify) for c in calls} == {("PUT", 1)}


async def test_run_heartbeat_during_long_drain(
    runner: Callable[[], AylaLanDevice],
    fake_http: _FakeHttp,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("aioayla_lan.device.HEARTBEAT_INTERVAL", 0.2)
    monkeypatch.setattr("aioayla_lan.device.NOTIFY_TIMEOUT", 0.1)
    device = runner()
    await fake_http.next_call()
    mirror = device_side(device.handle_key_exchange(key_exchange_request()))
    for i in range(50):
        device.set_property(f"prop_{i}", i)
    notify = await fake_http.next_call()

    fetched: list[float] = []

    async def module() -> None:
        # Fetches far more often than NOTIFY_TIMEOUT, so the drain never stalls.
        while True:
            await asyncio.sleep(0.02)
            _commands(device, mirror)
            fetched.append(asyncio.get_running_loop().time())

    fetching = asyncio.create_task(module())
    try:
        beat = await fake_http.next_call()
    finally:
        fetching.cancel()

    assert (beat.method, beat.notify) == ("PUT", 1)
    assert beat.at - notify.at >= 0.2 - SLACK
    assert len(fetched) >= 3
    assert device.pending


@pytest.mark.parametrize("status", [404, 500])
async def test_run_put_http_error_registers_afresh(
    runner: Callable[[], AylaLanDevice],
    fake_http: _FakeHttp,
    connection_changes: list[bool],
    status: int,
) -> None:
    device = runner()
    await fake_http.next_call()
    device.handle_key_exchange(key_exchange_request())
    fake_http.errors.append(_http_error(status))
    device.set_property("power", 1)

    failed = await fake_http.next_call()
    retry = await fake_http.next_call()

    assert [(c.method, c.notify) for c in (failed, retry)] == [("PUT", 1), ("POST", 1)]
    assert retry.at - failed.at < RETRY_INTERVAL
    assert device.connected
    assert connection_changes == [True]


@pytest.mark.parametrize("error", TRANSIENT_ERRORS)
async def test_run_transient_failure_keeps_session(
    runner: Callable[[], AylaLanDevice],
    fake_http: _FakeHttp,
    connection_changes: list[bool],
    monkeypatch: pytest.MonkeyPatch,
    error: BaseException,
) -> None:
    monkeypatch.setattr("aioayla_lan.device.RETRY_INTERVAL", 0.05)
    device = runner()
    await fake_http.next_call()
    device.handle_key_exchange(key_exchange_request())
    fake_http.errors.append(error)
    device.set_property("power", 1)

    failed = await fake_http.next_call()
    retry = await fake_http.next_call()

    assert [(c.method, c.notify) for c in (failed, retry)] == [("PUT", 1)] * 2
    assert retry.at - failed.at >= 0.05 - SLACK
    assert device.connected
    assert connection_changes == [True]


@pytest.mark.parametrize("error", TRANSIENT_ERRORS)
async def test_run_datapoint_extends_session(
    runner: Callable[[], AylaLanDevice],
    fake_http: _FakeHttp,
    connection_changes: list[bool],
    monkeypatch: pytest.MonkeyPatch,
    error: BaseException,
) -> None:
    monkeypatch.setattr("aioayla_lan.device.SESSION_TIMEOUT", 0.1)
    monkeypatch.setattr("aioayla_lan.device.RETRY_INTERVAL", 0.01)
    device = runner()
    await fake_http.next_call()
    mirror = device_side(device.handle_key_exchange(key_exchange_request()))
    # The registration alone is older than SESSION_TIMEOUT by now.
    await asyncio.sleep(0.15)
    device.handle_datapoint(
        mirror.encrypt_and_sign({"seq_no": 0, "data": {"name": "power", "value": 1}})
    )
    fake_http.errors.append(error)
    device.set_property("power", 1)

    calls = [await fake_http.next_call() for _ in range(2)]

    assert [(c.method, c.notify) for c in calls] == [("PUT", 1)] * 2
    assert device.connected
    assert connection_changes == [True]


@pytest.mark.parametrize("error", TRANSIENT_ERRORS)
async def test_run_drops_session_after_session_timeout(
    runner: Callable[[], AylaLanDevice],
    fake_http: _FakeHttp,
    connection_changes: list[bool],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    error: BaseException,
) -> None:
    caplog.set_level(logging.DEBUG, logger="aioayla_lan")
    monkeypatch.setattr("aioayla_lan.device.HEARTBEAT_INTERVAL", 0.3)
    monkeypatch.setattr("aioayla_lan.device.SESSION_TIMEOUT", 0.1)
    monkeypatch.setattr("aioayla_lan.device.RETRY_INTERVAL", 0.01)
    device = runner()
    registered = await fake_http.next_call()
    device.handle_key_exchange(key_exchange_request())
    fake_http.failing["PUT"] = error
    device.set_property("power", 1)

    *retries, fresh = await fake_http.calls_until("POST")

    assert {(c.method, c.notify) for c in retries} == {("PUT", 1)}
    assert len(retries) >= 2
    assert retries[-1].at - registered.at >= 0.1 - SLACK
    # Retry pace only while the session may be alive, heartbeat pace after.
    assert fresh.at - retries[-1].at >= 0.3 - SLACK
    assert fresh.notify == 1
    assert not device.connected
    assert connection_changes == [True, False]
    assert re.search(rf"{DSN}: session lost, silent for \d+ s", caplog.text)


async def test_run_registration_logs_status(
    runner: Callable[[], AylaLanDevice],
    fake_http: _FakeHttp,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="aioayla_lan")
    fake_http.errors.extend([None, _http_error(500)])
    device = runner()
    await fake_http.next_call()
    device.set_property("power", 1)
    await fake_http.next_call()
    # The fresh registration proves the failed PUT was handled, and so logged.
    await fake_http.next_call()

    assert [m for m in caplog.messages if "local_reg" in m] == [
        f"{DSN}: POST local_reg notify=0: 200",
        f"{DSN}: PUT local_reg notify=1: 500",
        f"{DSN}: POST local_reg notify=1: 200",
    ]


@pytest.mark.parametrize(
    ("error", "logged"),
    [
        pytest.param(
            aiohttp.ClientConnectionError("refused"),
            "ClientConnectionError('refused')",
            id="client-error",
        ),
        # str() of a bare TimeoutError is blank.
        pytest.param(TimeoutError(), "TimeoutError()", id="timeout"),
    ],
)
async def test_run_registration_failure_logged(
    runner: Callable[[], AylaLanDevice],
    fake_http: _FakeHttp,
    caplog: pytest.LogCaptureFixture,
    error: BaseException,
    logged: str,
) -> None:
    caplog.set_level(logging.DEBUG, logger="aioayla_lan")
    fake_http.errors.append(error)
    device = runner()
    await fake_http.next_call()
    device.set_property("power", 1)
    # The retry proves the failure was handled, and so logged.
    await fake_http.next_call()

    # A transport error has no response, so no status line.
    assert caplog.messages == [
        f"{DSN}: registration failed: {logged}",
        f"{DSN}: POST local_reg notify=1: 200",
    ]


async def test_run_failure_without_session_does_not_report(
    runner: Callable[[], AylaLanDevice],
    fake_http: _FakeHttp,
    connection_changes: list[bool],
) -> None:
    fake_http.errors.append(aiohttp.ClientConnectionError("refused"))
    device = runner()
    assert (await fake_http.next_call()).method == "POST"
    device.set_property("power", 1)
    assert (await fake_http.next_call()).method == "POST"
    assert connection_changes == []


@pytest.mark.parametrize("error", TRANSIENT_ERRORS)
async def test_run_failure_before_key_exchange_keeps_registration(
    runner: Callable[[], AylaLanDevice],
    fake_http: _FakeHttp,
    connection_changes: list[bool],
    monkeypatch: pytest.MonkeyPatch,
    error: BaseException,
) -> None:
    """A fresh registration outlives one lost heartbeat, even with no session yet."""
    monkeypatch.setattr("aioayla_lan.device.HEARTBEAT_INTERVAL", 0.1)
    device = runner()
    await fake_http.next_call()
    fake_http.errors.append(error)
    device.set_property("power", 1)

    failed = await fake_http.next_call()
    retry = await fake_http.next_call()

    assert [(c.method, c.notify) for c in (failed, retry)] == [("PUT", 1)] * 2
    assert retry.at - failed.at >= 0.1 - SLACK
    assert connection_changes == []


async def test_run_drops_session_without_connection_callback(
    fake_http: _FakeHttp, datapoints: list[Datapoint], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("aioayla_lan.device.HEARTBEAT_INTERVAL", 0.1)
    monkeypatch.setattr("aioayla_lan.device.SESSION_TIMEOUT", 0.05)
    monkeypatch.setattr("aioayla_lan.device.RETRY_INTERVAL", 0.01)
    device = _plain_device(fake_http, datapoints)  # type: ignore[arg-type]
    task = asyncio.create_task(device.run())
    await fake_http.next_call()
    device.handle_key_exchange(key_exchange_request())
    fake_http.failing["PUT"] = aiohttp.ClientConnectionError("refused")
    device.set_property("power", 1)

    await fake_http.calls_until("POST")

    assert not device.connected
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


WRONG_LAN_KEY = "f" * 32
VERIFY_TIMEOUT = 0.05


def _verifier(
    fake_http: _FakeHttp, datapoints: list[Datapoint], lan_key: LanKey
) -> AylaLanDevice:
    return AylaLanDevice(
        fake_http,  # type: ignore[arg-type]
        DEVICE_HOST,
        DSN,
        lan_key,
        CALLBACK_HOST,
        CALLBACK_PORT,
        datapoints.append,
    )


@pytest.mark.parametrize(
    "key_id",
    [pytest.param(KEY_ID, id="supplied"), pytest.param(None, id="learned")],
)
async def test_verify_returns_key_id_once_datapoint_authenticates(
    fake_http: _FakeHttp,
    datapoints: list[Datapoint],
    key_id: int | None,
) -> None:
    device = _verifier(fake_http, datapoints, LanKey(LAN_KEY, key_id))
    verify = asyncio.create_task(device.verify(1))

    register = await fake_http.next_call()
    assert (register.method, register.notify) == ("POST", 1)
    assert register.params == {"dsn": DSN}
    mirror = device_side(device.handle_key_exchange(key_exchange_request()))
    assert not verify.done()
    device.handle_datapoint(
        mirror.encrypt_and_sign({"seq_no": 0, "data": {"name": "power", "value": 1}})
    )

    assert await verify == KEY_ID
    assert device.key_id == KEY_ID
    assert datapoints == [Datapoint("power", 1)]
    assert asyncio.all_tasks() == {asyncio.current_task()}


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(aiohttp.ClientConnectionError("refused"), id="client-error"),
        pytest.param(TimeoutError(), id="timeout"),
    ],
)
async def test_verify_cannot_connect(
    fake_http: _FakeHttp, datapoints: list[Datapoint], error: BaseException
) -> None:
    fake_http.errors.append(error)
    device = _verifier(fake_http, datapoints, LanKey(LAN_KEY, KEY_ID))
    with pytest.raises(CannotConnectError):
        await device.verify(VERIFY_TIMEOUT)
    assert fake_http.calls.qsize() == 1
    assert asyncio.all_tasks() == {asyncio.current_task()}


async def test_verify_no_callback(
    fake_http: _FakeHttp, datapoints: list[Datapoint]
) -> None:
    device = _verifier(fake_http, datapoints, LanKey(LAN_KEY, KEY_ID))
    with pytest.raises(NoCallbackError):
        await device.verify(VERIFY_TIMEOUT)
    assert (await fake_http.next_call()).method == "POST"
    assert asyncio.all_tasks() == {asyncio.current_task()}


async def test_verify_invalid_key_without_datapoint(
    fake_http: _FakeHttp, datapoints: list[Datapoint]
) -> None:
    device = _verifier(fake_http, datapoints, LanKey(LAN_KEY, KEY_ID))
    verify = asyncio.create_task(device.verify(VERIFY_TIMEOUT))
    await fake_http.next_call()
    device.handle_key_exchange(key_exchange_request())

    with pytest.raises(InvalidKeyError):
        await verify
    assert asyncio.all_tasks() == {asyncio.current_task()}


async def test_verify_invalid_key_when_datapoint_fails_hmac(
    fake_http: _FakeHttp, datapoints: list[Datapoint]
) -> None:
    device = _verifier(fake_http, datapoints, LanKey(WRONG_LAN_KEY))
    verify = asyncio.create_task(device.verify(VERIFY_TIMEOUT))
    await fake_http.next_call()
    mirror = device_side(device.handle_key_exchange(key_exchange_request()))
    with pytest.raises(SignatureError):
        device.handle_datapoint(
            mirror.encrypt_and_sign({"seq_no": 0, "data": {"name": "power"}})
        )

    with pytest.raises(InvalidKeyError):
        await verify
    assert device.key_id == KEY_ID


@pytest.mark.parametrize(
    "plaintext",
    [
        pytest.param(b'{"seq_no":28,"data":{}', id="bad-json"),
        pytest.param(
            b'{"seq_no":0,"data":{"name":"device_name","value":"20\xb0C"}}',
            id="non-utf8",
        ),
    ],
)
async def test_verify_accepts_key_when_datapoint_is_undecodable(
    fake_http: _FakeHttp, datapoints: list[Datapoint], plaintext: bytes
) -> None:
    device = _verifier(fake_http, datapoints, LanKey(LAN_KEY, KEY_ID))
    verify = asyncio.create_task(device.verify(VERIFY_TIMEOUT))
    await fake_http.next_call()
    mirror = device_side(device.handle_key_exchange(key_exchange_request()))
    device.handle_datapoint(_sign_raw(mirror, plaintext))
    # Further exchanges must not read as a rejected key either.
    for _ in range(REJECTED_KEY_EXCHANGES):
        device.handle_key_exchange(key_exchange_request())

    # The signature proves the key even when the firmware's JSON is broken.
    assert await verify == KEY_ID
    assert datapoints == []
    assert datapoints == []


def _http_error(status: int) -> aiohttp.ClientResponseError:
    return aiohttp.ClientResponseError(MagicMock(), (), status=status)


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        pytest.param(403, CallbackRejectedError, id="403-callback-rejected"),
        pytest.param(404, CannotConnectError, id="404-cannot-connect"),
        pytest.param(500, CannotConnectError, id="500-cannot-connect"),
    ],
)
@pytest.mark.parametrize(
    "call",
    [
        pytest.param(lambda d: d.register(), id="register"),
        pytest.param(lambda d: d.verify(VERIFY_TIMEOUT), id="verify"),
    ],
)
async def test_registration_http_error(
    fake_http: _FakeHttp,
    datapoints: list[Datapoint],
    status: int,
    expected: type[Exception],
    call: Callable[[AylaLanDevice], Awaitable[object]],
) -> None:
    error = _http_error(status)
    fake_http.errors.append(error)
    device = _verifier(fake_http, datapoints, LanKey(LAN_KEY, KEY_ID))

    with pytest.raises(expected) as exc_info:
        await call(device)

    assert type(exc_info.value) is expected
    assert exc_info.value.__cause__ is error
    register = await fake_http.next_call()
    assert (register.method, register.notify) == ("POST", 1)
    assert fake_http.calls.empty()
    assert asyncio.all_tasks() == {asyncio.current_task()}


async def test_callback_rejected_is_no_callback(
    fake_http: _FakeHttp, datapoints: list[Datapoint]
) -> None:
    fake_http.errors.append(_http_error(403))
    device = _verifier(fake_http, datapoints, LanKey(LAN_KEY, KEY_ID))
    # Callers that only handle NoCallbackError still catch a refused callback.
    with pytest.raises(NoCallbackError, match=CALLBACK_HOST):
        await device.register()


async def _registered(
    fake_http: _FakeHttp, datapoints: list[Datapoint]
) -> AylaLanDevice:
    device = _verifier(fake_http, datapoints, LanKey(LAN_KEY, KEY_ID))
    await device.register()
    assert (await fake_http.next_call()).method == "POST"
    return device


def _no_session(device: AylaLanDevice) -> None:
    return None


def _one_exchange(device: AylaLanDevice) -> None:
    device.handle_key_exchange(key_exchange_request())


def _reject_key(device: AylaLanDevice) -> None:
    for _ in range(REJECTED_KEY_EXCHANGES):
        device.handle_key_exchange(key_exchange_request())


def _authenticate(device: AylaLanDevice) -> None:
    mirror = device_side(device.handle_key_exchange(key_exchange_request()))
    device.handle_datapoint(
        mirror.encrypt_and_sign({"seq_no": 0, "data": {"name": "power", "value": 1}})
    )


def _qualname(task: asyncio.Task[Any]) -> str:
    coro = task.get_coro()
    assert coro is not None
    return coro.__qualname__


@pytest.fixture
def created_tasks(monkeypatch: pytest.MonkeyPatch) -> list[asyncio.Task[Any]]:
    """Record every task created through `asyncio.create_task`."""
    created: list[asyncio.Task[Any]] = []
    create_task = asyncio.create_task

    def spy(coro: Coroutine[Any, Any, Any]) -> asyncio.Task[Any]:
        task = create_task(coro)
        created.append(task)
        return task

    monkeypatch.setattr(asyncio, "create_task", spy)
    return created


async def test_register_resets_stalled_sessions(
    fake_http: _FakeHttp, datapoints: list[Datapoint]
) -> None:
    device = await _registered(fake_http, datapoints)
    device._stalled_sessions = STALLED_SESSIONS + 1

    await device.register()
    assert (await fake_http.next_call()).method == "POST"

    assert device._stalled_sessions == 0
    assert device._rekey_after() == SESSION_TIMEOUT


async def test_wait_verified_rejects_key_without_waiting_for_timeout(
    fake_http: _FakeHttp, datapoints: list[Datapoint]
) -> None:
    device = await _registered(fake_http, datapoints)
    loop = asyncio.get_running_loop()
    start = loop.time()
    wait = asyncio.create_task(device.wait_verified(5))
    await asyncio.sleep(0.01)

    for _ in range(REJECTED_KEY_EXCHANGES - 1):
        device.handle_key_exchange(key_exchange_request())
    await asyncio.sleep(0.01)
    assert not wait.done()

    device.handle_key_exchange(key_exchange_request())
    with pytest.raises(InvalidKeyError):
        await asyncio.wait_for(wait, 1)
    assert loop.time() - start < 1
    assert asyncio.all_tasks() == {asyncio.current_task()}


async def test_wait_verified_authenticated_before_rejection_threshold(
    fake_http: _FakeHttp, datapoints: list[Datapoint]
) -> None:
    device = await _registered(fake_http, datapoints)
    wait = asyncio.create_task(device.wait_verified(5))
    await asyncio.sleep(0.01)

    for _ in range(REJECTED_KEY_EXCHANGES - 2):
        device.handle_key_exchange(key_exchange_request())
    _authenticate(device)
    # The module re-keying after a validated payload is not a rejection.
    device.handle_key_exchange(key_exchange_request())

    assert await asyncio.wait_for(wait, 1) == KEY_ID
    assert not device._key_rejected.is_set()
    assert datapoints == [Datapoint("power", 1)]


@pytest.mark.parametrize(
    "session",
    [
        pytest.param(_reject_key, id="after-key-rejected"),
        pytest.param(_authenticate, id="after-authenticated"),
    ],
)
async def test_register_resets_verification_state(
    fake_http: _FakeHttp,
    datapoints: list[Datapoint],
    session: Callable[[AylaLanDevice], None],
) -> None:
    device = await _registered(fake_http, datapoints)
    session(device)

    await device.register()
    assert (await fake_http.next_call()).method == "POST"

    # Stale state would return the key id or raise InvalidKeyError instead.
    with pytest.raises(NoCallbackError):
        await device.wait_verified(VERIFY_TIMEOUT)


@pytest.mark.parametrize(
    ("session", "timeout", "expectation"),
    [
        pytest.param(_authenticate, 5, nullcontext(), id="authenticated"),
        pytest.param(_reject_key, 5, pytest.raises(InvalidKeyError), id="key-rejected"),
        pytest.param(
            _no_session,
            VERIFY_TIMEOUT,
            pytest.raises(NoCallbackError),
            id="timeout-no-callback",
        ),
        pytest.param(
            _one_exchange,
            VERIFY_TIMEOUT,
            pytest.raises(InvalidKeyError),
            id="timeout-invalid-key",
        ),
    ],
)
async def test_wait_verified_cancels_its_tasks(
    fake_http: _FakeHttp,
    datapoints: list[Datapoint],
    created_tasks: list[asyncio.Task[Any]],
    session: Callable[[AylaLanDevice], None],
    timeout: float,
    expectation: AbstractContextManager[object],
) -> None:
    device = await _registered(fake_http, datapoints)
    wait = asyncio.get_running_loop().create_task(device.wait_verified(timeout))
    await asyncio.sleep(0.01)
    session(device)

    with expectation:
        await asyncio.wait_for(wait, 1)

    runner, *waiters = created_tasks
    assert _qualname(runner) == "AylaLanDevice._run"
    assert runner.cancelled()
    assert [_qualname(w) for w in waiters] == ["Event.wait"] * 2
    assert all(w.done() for w in waiters)
    assert (await fake_http.next_call()).method == "PUT"
    assert fake_http.calls.empty()
    assert asyncio.all_tasks() == {asyncio.current_task()}


@pytest.mark.parametrize(
    ("session", "timeout", "expectation", "outcome"),
    [
        pytest.param(
            _authenticate,
            5,
            nullcontext(),
            "authenticated=True, key exchanges=1",
            id="authenticated",
        ),
        pytest.param(
            _no_session,
            VERIFY_TIMEOUT,
            pytest.raises(NoCallbackError),
            "authenticated=False, key exchanges=0",
            id="no-callback",
        ),
        pytest.param(
            _one_exchange,
            VERIFY_TIMEOUT,
            pytest.raises(InvalidKeyError),
            "authenticated=False, key exchanges=1",
            id="invalid-key",
        ),
    ],
)
async def test_wait_verified_logs_outcome(
    clock: _Clock,
    fake_http: _FakeHttp,
    datapoints: list[Datapoint],
    caplog: pytest.LogCaptureFixture,
    session: Callable[[AylaLanDevice], None],
    timeout: float,
    expectation: AbstractContextManager[object],
    outcome: str,
) -> None:
    caplog.set_level(logging.DEBUG, logger="aioayla_lan")
    device = await _registered(fake_http, datapoints)
    wait = asyncio.create_task(device.wait_verified(timeout))
    await asyncio.sleep(0.01)
    session(device)
    clock.now += 2

    with expectation:
        await asyncio.wait_for(wait, 1)

    assert caplog.messages[0] == (
        f"{DSN}: registering at {DEVICE_HOST}, callback {CALLBACK_HOST}:{CALLBACK_PORT}"
    )
    assert caplog.messages[-1] == f"{DSN}: verify ended after 2.0 s: {outcome}"


async def test_wait_verified_right_after_starting_run_does_not_double_it(
    runner: Callable[[], AylaLanDevice],
    fake_http: _FakeHttp,
    created_tasks: list[asyncio.Task[Any]],
) -> None:
    # The probe scripts start run() and await wait_verified() in one go.
    device = runner()
    wait = asyncio.get_running_loop().create_task(device.wait_verified(1))
    assert (await fake_http.next_call()).method == "POST"
    _authenticate(device)

    assert await asyncio.wait_for(wait, 1) == KEY_ID
    assert [_qualname(t) for t in created_tasks] == [
        "AylaLanDevice.run",
        "Event.wait",
        "Event.wait",
    ]
    assert fake_http.calls.empty()


async def test_wait_verified_leaves_registering_to_running_loop(
    runner: Callable[[], AylaLanDevice],
    fake_http: _FakeHttp,
    created_tasks: list[asyncio.Task[Any]],
) -> None:
    device = runner()
    assert (await fake_http.next_call()).method == "POST"
    wait = asyncio.get_running_loop().create_task(device.wait_verified(1))
    await asyncio.sleep(0.01)
    _authenticate(device)

    assert await asyncio.wait_for(wait, 1) == KEY_ID
    assert [_qualname(t) for t in created_tasks] == [
        "AylaLanDevice.run",
        "Event.wait",
        "Event.wait",
    ]
    assert not created_tasks[0].done()
    assert fake_http.calls.empty()
