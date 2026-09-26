"""fetch_dsn reads a module's DSN from regtoken.json without a key."""

import json
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock

import aiohttp
import pytest
from conftest import DEVICE_HOST, DSN

from aioayla_lan import AylaLanError, CannotConnectError, fetch_dsn

REGTOKEN_URL = f"http://{DEVICE_HOST}/regtoken.json"
REGTOKEN = json.dumps(
    {
        "regtoken": "000000",
        "registered": 1,
        "registration_type": "Same-LAN",
        "host_symname": DSN,
    }
)


@dataclass
class _Reply:
    status: int = 200
    body: str = REGTOKEN
    exception: BaseException | None = None


class _FakeResponse:
    def __init__(self, reply: _Reply) -> None:
        self.status = reply.status
        self._body = reply.body

    def raise_for_status(self) -> None:
        if self.status >= 400:
            raise aiohttp.ClientResponseError(
                MagicMock(), (), status=self.status, message="error"
            )

    async def json(self, *, content_type: str | None = "application/json") -> Any:
        assert content_type is None
        return json.loads(self._body)


class _FakeRequest:
    def __init__(self, reply: _Reply) -> None:
        self._reply = reply

    async def __aenter__(self) -> _FakeResponse:
        if self._reply.exception is not None:
            raise self._reply.exception
        return _FakeResponse(self._reply)

    async def __aexit__(self, *exc: object) -> None:
        return None


@dataclass
class _FakeHttp:
    """Serves one canned GET reply and records every call."""

    reply: _Reply = field(default_factory=_Reply)
    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    def get(self, url: str, **kwargs: Any) -> _FakeRequest:
        self.calls.append((url, kwargs))
        return _FakeRequest(self.reply)


@pytest.fixture
def http() -> _FakeHttp:
    return _FakeHttp()


async def test_fetch_dsn_returns_host_symname(http: _FakeHttp) -> None:
    assert await fetch_dsn(http, DEVICE_HOST) == DSN  # type: ignore[arg-type]
    ((url, kwargs),) = http.calls
    assert url == REGTOKEN_URL
    assert isinstance(kwargs["timeout"], aiohttp.ClientTimeout)


@pytest.mark.parametrize(
    "reply",
    [
        pytest.param(
            _Reply(exception=aiohttp.ClientConnectionError("refused")),
            id="client-error",
        ),
        pytest.param(_Reply(exception=TimeoutError()), id="timeout"),
        pytest.param(_Reply(status=404, body="not found"), id="http-404"),
    ],
)
async def test_fetch_dsn_cannot_connect(http: _FakeHttp, reply: _Reply) -> None:
    http.reply = reply
    with pytest.raises(CannotConnectError):
        await fetch_dsn(http, DEVICE_HOST)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("body", "match"),
    [
        pytest.param("<html>router</html>", "not an Ayla module", id="not-json"),
        pytest.param("", "not an Ayla module", id="empty"),
        pytest.param(
            json.dumps({"regtoken": "000000"}), "reported no DSN", id="no-symname"
        ),
        pytest.param(
            json.dumps({"host_symname": 1}), "reported no DSN", id="symname-not-str"
        ),
        pytest.param(json.dumps({"host_symname": None}), "reported no DSN", id="null"),
        pytest.param(json.dumps([DSN]), "reported no DSN", id="not-object"),
    ],
)
async def test_fetch_dsn_not_an_ayla_module(
    http: _FakeHttp, body: str, match: str
) -> None:
    http.reply = _Reply(body=body)
    with pytest.raises(AylaLanError, match=match) as exc_info:
        await fetch_dsn(http, DEVICE_HOST)  # type: ignore[arg-type]
    assert type(exc_info.value) is AylaLanError
