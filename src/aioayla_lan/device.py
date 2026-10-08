"""One Ayla module in LAN mode: registration, session and command queue.

The module is the HTTP client. We register with it (`local_reg.json`), it dials
back to the address we advertise and POSTs `key_exchange.json`, then fetches
`commands.json` whenever `notify` is raised and POSTs `datapoint.json` with
property values, including unsolicited changes made by other controllers.
Answering any of its requests with 206 Partial Content makes it fetch
`commands.json` again straight away, so a queue drains in one notify.
"""

import asyncio
import json
import logging
import secrets
import string
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

import aiohttp

from .crypto import SessionCrypto
from .exceptions import (
    AylaLanError,
    CallbackRejectedError,
    CannotConnectError,
    InvalidKeyError,
    KeyIdMismatchError,
    NoCallbackError,
    NoSessionError,
    WriteError,
    WriteExpiredError,
    WriteRejectedError,
    WriteUnacknowledgedError,
)
from .models import Datapoint, LanKey

_LOGGER = logging.getLogger(__name__)

HEARTBEAT_INTERVAL = 10.0
"""Seconds between registrations.

A third of the module's keep_alive (30 s), as the Ayla SDK does.
"""
REGISTER_TIMEOUT = 6.0
VERIFY_TIMEOUT = 30.0
SESSION_TIMEOUT = 30.0
"""Silence after which the session is gone.

The module forgets a registration it has not heard from in keep_alive.
"""
RETRY_INTERVAL = 2.0
"""Pace of heartbeat retries while the session may still be alive."""
NOTIFY_TIMEOUT = 3.0
"""Wait for a notified module to fetch before notifying again.

A notified module fetches within a second, so silence means it went quiet.
"""
ACK_TIMEOUT = 10.0
"""Wait for a collected write to be acked, as long as the Ayla SDK waits.

A settled module acks about a second after collecting a write; one busy after
a reboot can take longer, and a property without acks enabled is never acked.
"""
WRITE_TTL = 30.0
"""Age at which an uncollected write is dropped rather than applied late."""
REJECTED_KEY_EXCHANGES = 3
"""Unauthenticated key exchanges before the key counts as rejected.

A module that cannot validate our replies re-keys on every registration.
"""
LAN_URI = "/local_lan"
_ALPHABET = string.ascii_letters + string.digits


def _random_token(length: int) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


async def fetch_dsn(session: aiohttp.ClientSession, host: str) -> str:
    """Read the DSN a module reports on the LAN, without a key.

    Raises :exc:`CannotConnectError` when nothing answers and :exc:`AylaLanError` when
    the reply is not an Ayla module's.
    """
    try:
        async with session.get(
            f"http://{host}/regtoken.json",
            timeout=aiohttp.ClientTimeout(total=REGISTER_TIMEOUT),
        ) as resp:
            resp.raise_for_status()
            reply = await resp.json(content_type=None)
    except (aiohttp.ClientError, TimeoutError) as err:
        raise CannotConnectError(err) from err
    except ValueError as err:
        raise AylaLanError(f"{host} is not an Ayla module") from err
    if not isinstance(reply, dict) or not isinstance(
        dsn := reply.get("host_symname"), str
    ):
        raise AylaLanError(f"{host} reported no DSN")
    return dsn


@dataclass
class _Write:
    name: str
    value: Any
    base_type: str
    queued_at: float
    id: str = field(default_factory=lambda: _random_token(8))
    futures: list[asyncio.Future[None]] = field(default_factory=list)
    # Expiry while queued, then the ack deadline once collected.
    timer: asyncio.TimerHandle | None = None

    def command(self) -> dict[str, Any]:
        return {
            "properties": [
                {
                    "property": {
                        "base_type": self.base_type,
                        "name": self.name,
                        "value": self.value,
                        "id": self.id,
                    }
                }
            ]
        }

    def settle(self, error: WriteError | None = None) -> None:
        if self.timer:
            self.timer.cancel()
            self.timer = None
        for future in self.futures:
            if future.done():
                continue
            if error is None:
                future.set_result(None)
            else:
                future.set_exception(error)
        self.futures.clear()


class AylaLanDevice:
    """Local session with one Ayla module.

    Handlers are synchronous and must run on one event loop, in arrival order:
    the session cipher is stateful.
    """

    def __init__(
        self,
        session: aiohttp.ClientSession,
        host: str,
        dsn: str,
        lan_key: LanKey,
        callback_host: str,
        callback_port: int,
        on_datapoint: Callable[[Datapoint], None],
        on_connection_change: Callable[[bool], None] | None = None,
        prime_properties: Iterable[str] = (),
    ) -> None:
        """Initialise; call :meth:`run` to start registering."""
        self._http = session
        self.host = host
        self.dsn = dsn
        self._lan_key = lan_key
        self._key_id = lan_key.key_id
        self._callback_host = callback_host
        self._callback_port = callback_port
        self._on_datapoint = on_datapoint
        self._on_connection_change = on_connection_change
        self._prime = tuple(prime_properties)

        self._crypto: SessionCrypto | None = None
        self._cmd_seq = 0
        self._cmd_id = 1
        # By name, in the order they go out: a newer write to a name replaces
        # the queued one and a repeated read is asked once.
        self._writes: dict[str, _Write] = {}
        self._reads: dict[str, None] = {}
        self._unacked: dict[str, _Write] = {}
        self._pending_since: float | None = None
        self._wake = asyncio.Event()
        self._collected = asyncio.Event()
        self._running = False
        self._registered_at = 0.0
        self._key_exchanges = 0
        self._key_rejected = asyncio.Event()
        self._authenticated = asyncio.Event()
        self.last_seen: float | None = None

    @property
    def connected(self) -> bool:
        """Whether a key exchange has completed."""
        return self._crypto is not None

    @property
    def key_id(self) -> int | None:
        """The LAN key id, learned from the device when not supplied."""
        return self._key_id

    @property
    def pending(self) -> bool:
        """Whether commands are waiting for the device to collect them."""
        return bool(self._writes or self._reads)

    @property
    def pending_since(self) -> float | None:
        """When the queue last went from empty to busy, on the monotonic clock."""
        return self._pending_since

    def set_property(self, name: str, value: Any, base_type: str = "integer") -> None:
        """Queue a property write. Writes go out before any queued reads."""
        self._queue_write(name, value, base_type)

    async def async_set_property(
        self, name: str, value: Any, base_type: str = "integer"
    ) -> None:
        """Write a property and wait until the device acknowledges it.

        Raises :exc:`WriteExpiredError` when the device does not collect the
        write within :data:`WRITE_TTL`, :exc:`WriteRejectedError` when it
        refuses the write and :exc:`WriteUnacknowledgedError` when it sends no
        ack within :data:`ACK_TIMEOUT`, which does not prove the write failed.
        A newer write to the same name before collection replaces this one; the
        caller then learns the newer write's fate.
        """
        future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        write = self._queue_write(name, value, base_type)
        write.futures.append(future)
        if write.timer is None:
            self._arm_expiry(write)
        future.add_done_callback(self._forget_cancelled)
        await future

    def _forget_cancelled(self, future: asyncio.Future[None]) -> None:
        # A cancelled caller, e.g. on unload, must not leave timers armed.
        if not future.cancelled():
            return
        for write in (*self._writes.values(), *self._unacked.values()):
            if future not in write.futures:
                continue
            write.futures.remove(future)
            if not write.futures and write.timer:
                write.timer.cancel()
                write.timer = None
                self._unacked.pop(write.id, None)
            return

    def _queue_write(self, name: str, value: Any, base_type: str) -> _Write:
        write = _Write(name, value, base_type, time.monotonic())
        if (superseded := self._writes.pop(name, None)) is not None:
            # Its callers learn the fate of the value that replaced theirs.
            write.futures = superseded.futures
            if superseded.timer:
                superseded.timer.cancel()
        self._writes[name] = write
        if write.futures:
            self._arm_expiry(write)
        self._queued()
        return write

    def _arm_expiry(self, write: _Write) -> None:
        write.timer = asyncio.get_running_loop().call_later(
            WRITE_TTL, self._expire_write, write
        )

    def _expire_write(self, write: _Write) -> None:
        write.timer = None
        if self._writes.get(write.name) is write:
            del self._writes[write.name]
            if not self.pending:
                self._pending_since = None
        write.settle(WriteExpiredError(f"{self.dsn}: {write.name} was not collected"))

    def request_properties(self, names: Iterable[str]) -> None:
        """Queue property reads; values arrive through `on_datapoint`."""
        self._reads.update(dict.fromkeys(names))
        self._queued()

    def _queued(self) -> None:
        if not self.pending:
            return
        if self._pending_since is None:
            self._pending_since = time.monotonic()
        self._wake.set()

    def handle_key_exchange(self, key_exchange: dict[str, Any]) -> dict[str, Any]:
        """Start a new session. Returns the unwrapped reply."""
        if not isinstance(key_exchange, dict):
            raise TypeError("key_exchange is not an object")
        if (
            key_exchange.get("ver") != 1
            or key_exchange.get("proto") != 1
            or key_exchange.get("sec")
        ):
            raise ValueError(f"unsupported key exchange: {key_exchange}")
        self._key_exchanges += 1
        if (
            self._key_exchanges >= REJECTED_KEY_EXCHANGES
            and not self._authenticated.is_set()
        ):
            self._key_rejected.set()
        if not isinstance(key_exchange["key_id"], int):
            raise TypeError("key_id is not an integer")
        if self._key_id is None:
            self._key_id = key_exchange["key_id"]
        elif key_exchange["key_id"] != self._key_id:
            raise KeyIdMismatchError(
                f"device key_id {key_exchange['key_id']}, ours {self._key_id}"
            )
        if not isinstance(key_exchange["random_1"], str):
            raise TypeError("random_1 is not a string")
        random_2 = _random_token(16)
        time_2 = time.monotonic_ns() % 2**40
        self._crypto = SessionCrypto(
            self._lan_key.key,
            key_exchange["random_1"],
            key_exchange["time_1"],
            random_2,
            time_2,
        )
        self._cmd_seq = 0
        self._reads.clear()
        if not self.pending:
            self._pending_since = None
        self.request_properties(self._prime)
        _LOGGER.debug("%s: session established", self.dsn)
        if self._on_connection_change:
            self._on_connection_change(True)
        # Wrapped in {"key_exchange": ...} the device silently retries forever.
        return {"random_2": random_2, "time_2": time_2}

    def handle_commands(self) -> dict[str, str]:
        """Hand the device its next command, encrypted even when empty."""
        if self._crypto is None:
            raise NoSessionError
        self._expire_writes()
        if self._writes:
            write = self._writes.pop(next(iter(self._writes)))
            data = write.command()
            _LOGGER.debug(
                "%s: sending %s = %s (id %s)",
                self.dsn,
                write.name,
                write.value,
                write.id,
            )
            if write.timer:
                write.timer.cancel()
            if write.futures:
                self._unacked[write.id] = write
                write.timer = asyncio.get_running_loop().call_later(
                    ACK_TIMEOUT, self._ack_timed_out, write.id
                )
        elif self._reads:
            name = next(iter(self._reads))
            del self._reads[name]
            data = self._read_command(name)
        else:
            data = {}
        if not self.pending:
            self._pending_since = None
        body = {"seq_no": self._cmd_seq, "data": data}
        self._cmd_seq += 1
        self._touch()
        self._collected.set()
        return self._crypto.encrypt_and_sign(body)

    def _read_command(self, name: str) -> dict[str, Any]:
        cmd_id, self._cmd_id = self._cmd_id, self._cmd_id + 1
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

    def _expire_writes(self) -> None:
        now = time.monotonic()
        for name, write in list(self._writes.items()):
            if now - write.queued_at > WRITE_TTL:
                _LOGGER.debug("%s: dropping stale write of %s", self.dsn, name)
                del self._writes[name]
                write.settle(WriteExpiredError(f"{self.dsn}: {name} was not collected"))

    def _ack_timed_out(self, write_id: str) -> None:
        if (write := self._unacked.pop(write_id, None)) is not None:
            write.timer = None
            _LOGGER.debug(
                "%s: no ack for %s (id %s) within %s s",
                self.dsn,
                write.name,
                write_id,
                ACK_TIMEOUT,
            )
            write.settle(
                WriteUnacknowledgedError(
                    f"{self.dsn}: {write.name} was not acknowledged"
                )
            )

    def handle_datapoint(self, doc: dict[str, Any]) -> None:
        """Decrypt a pushed property value and report it."""
        if self._crypto is None:
            raise NoSessionError
        try:
            update = self._crypto.decrypt_and_validate(doc)
        # Signed by the module, so the key is right and only firmware quirks land
        # here. Skipped, not refused: a refusal makes the module re-key and resend.
        except json.JSONDecodeError as err:
            self._contact()
            _LOGGER.debug("%s: undecodable payload: %r", self.dsn, err.doc)
            return
        except UnicodeDecodeError as err:
            self._contact()
            _LOGGER.debug("%s: undecodable payload: %r", self.dsn, err.object)
            return
        self._contact()
        data = update.get("data") if isinstance(update, dict) else None
        if isinstance(data, dict) and "ack_status" in data:
            self._handle_ack(data)
            return
        if not isinstance(data, dict) or "name" not in data:
            _LOGGER.debug("%s: ignoring update without a name: %s", self.dsn, update)
            return
        self._on_datapoint(
            Datapoint(data["name"], data.get("value"), data.get("base_type"))
        )

    def _handle_ack(self, ack: dict[str, Any]) -> None:
        # Posted to datapoint/ack.json with the id we gave the write.
        write_id = ack.get("id")
        if not isinstance(write_id, str) or (
            (write := self._unacked.pop(write_id, None)) is None
        ):
            # Late, or a shape we do not know: logged to learn which.
            _LOGGER.debug("%s: ack for no pending write: %s", self.dsn, ack)
            return
        status = ack["ack_status"]
        _LOGGER.debug(
            "%s: ack %s for %s (id %s)", self.dsn, status, write.name, write_id
        )
        if isinstance(status, int) and 200 <= status < 300:
            write.settle()
        else:
            write.settle(
                WriteRejectedError(f"{self.dsn}: {write.name} ack_status {status}")
            )

    def _touch(self) -> None:
        self.last_seen = time.monotonic()

    def _contact(self) -> None:
        self._authenticated.set()
        self._touch()

    def _drop_session(self) -> None:
        if self._crypto is None:
            return
        self._crypto = None
        _LOGGER.debug(
            "%s: session lost, silent for %.0f s", self.dsn, self._silent_for()
        )
        if self._on_connection_change:
            self._on_connection_change(False)

    async def register(self) -> None:
        """Register once, asking the module to dial back now.

        Raises :exc:`CallbackRejectedError` when the module refuses the callback
        address, which it does for addresses outside its own subnet, and
        :exc:`CannotConnectError` for any other failure. Follow with
        :meth:`wait_verified`. Takes the module's LAN session from any other client.
        """
        self._key_exchanges = 0
        self._key_rejected.clear()
        self._authenticated.clear()
        _LOGGER.debug(
            "%s: registering at %s, callback %s:%s",
            self.dsn,
            self.host,
            self._callback_host,
            self._callback_port,
        )
        try:
            await self._register(True, 1)
        except aiohttp.ClientResponseError as err:
            if err.status == 403:
                raise CallbackRejectedError(
                    f"{self.dsn}: callback address {self._callback_host} refused"
                ) from err
            raise CannotConnectError(err) from err
        except (aiohttp.ClientError, TimeoutError) as err:
            raise CannotConnectError(err) from err

    async def wait_verified(self, timeout: float = VERIFY_TIMEOUT) -> int:
        """Keep registering until the LAN key authenticates a pushed value.

        Pass `prime_properties`, so the module has a value to push. Registers
        itself unless :meth:`run` is already doing so. Returns the device's key id.
        Raises :exc:`NoCallbackError` when the module never dials back and
        :exc:`InvalidKeyError` when it does but no payload validates.
        """
        # Let a just-created run() task start, so it is not doubled.
        await asyncio.sleep(0)
        started = time.monotonic()
        runner = None if self._running else asyncio.create_task(self._run(False))
        waiters = [
            asyncio.create_task(self._authenticated.wait()),
            asyncio.create_task(self._key_rejected.wait()),
        ]
        try:
            await asyncio.wait(
                waiters, timeout=timeout, return_when=asyncio.FIRST_COMPLETED
            )
        finally:
            tasks = [*waiters] if runner is None else [runner, *waiters]
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        _LOGGER.debug(
            "%s: verify ended after %.1f s: authenticated=%s, key exchanges=%d",
            self.dsn,
            time.monotonic() - started,
            self._authenticated.is_set(),
            self._key_exchanges,
        )
        if not self._authenticated.is_set():
            if self._key_exchanges:
                raise InvalidKeyError(f"{self.dsn}: no payload validated")
            raise NoCallbackError(f"{self.dsn}: no key exchange")
        assert self._key_id is not None
        return self._key_id

    async def verify(self, timeout: float = VERIFY_TIMEOUT) -> int:
        """Register, then wait until the LAN key authenticates a pushed value."""
        await self.register()
        return await self.wait_verified(timeout)

    async def run(self) -> None:
        """Register with the module and keep the registration alive. Never returns.

        `notify=1` asks the module to fetch `commands.json`. It is raised as soon
        as work is queued rather than on the next heartbeat, otherwise a write
        can wait a full device-side cycle (~90 s). The server's 206 replies then
        keep the module fetching until the queue is empty.
        """
        await self._run(first=True)

    async def _run(self, first: bool) -> None:
        owner = not self._running
        self._running = True
        try:
            while True:
                first = await self._cycle(first)
        finally:
            if owner:
                self._running = False

    async def _cycle(self, first: bool) -> bool:
        """Register once and wait for the next reason to. Returns the next `first`."""
        notify = 1 if self.pending else 0
        self._wake.clear()
        # Cleared first: the module may fetch before the PUT returns.
        self._collected.clear()
        heartbeat_at = time.monotonic() + HEARTBEAT_INTERVAL
        try:
            await self._register(first, notify)
        except (aiohttp.ClientError, TimeoutError) as err:
            _LOGGER.debug("%s: registration failed: %r", self.dsn, err)
            if isinstance(err, aiohttp.ClientResponseError) and not first:
                # The module forgot us: register afresh straight away.
                return True
            if time.monotonic() - self._last_contact() > SESSION_TIMEOUT:
                self._drop_session()
                first = True
            elif self.connected:
                # One lost heartbeat does not end the session.
                await asyncio.sleep(RETRY_INTERVAL)
                return first
        else:
            first = False
            self._registered_at = time.monotonic()
            if notify and not await self._drained(heartbeat_at):
                # A module can accept every notify yet never dial back; only
                # registering afresh makes it key-exchange again.
                _LOGGER.debug("%s: notified, but the queue was not collected", self.dsn)
                return self.connected and self._silent_for() > SESSION_TIMEOUT
            # Anything queued while draining has been served already.
            if not self.pending:
                self._wake.clear()
        try:
            await asyncio.wait_for(
                self._wake.wait(), max(0.0, heartbeat_at - time.monotonic())
            )
        except TimeoutError:
            pass
        return first

    async def _drained(self, deadline: float) -> bool:
        """Follow the module through the queue; False if it goes quiet first."""
        while self.pending:
            timeout = min(NOTIFY_TIMEOUT, deadline - time.monotonic())
            try:
                await asyncio.wait_for(self._collected.wait(), max(0.0, timeout))
            except TimeoutError:
                return False
            self._collected.clear()
        return True

    def _last_contact(self) -> float:
        return max(self._registered_at, self.last_seen or 0.0)

    def _silent_for(self) -> float:
        # Registrations do not count: a mute module still accepts them.
        return time.monotonic() - (self.last_seen or self._registered_at)

    async def _register(self, first: bool, notify: int) -> None:
        body = {
            "local_reg": {
                "ip": self._callback_host,
                "notify": notify,
                "port": self._callback_port,
                "uri": LAN_URI,
            }
        }
        async with self._http.request(
            "POST" if first else "PUT",
            f"http://{self.host}/local_reg.json",
            params={"dsn": self.dsn},
            json=body,
            timeout=aiohttp.ClientTimeout(total=REGISTER_TIMEOUT),
        ) as resp:
            resp.raise_for_status()
