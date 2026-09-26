"""AylaCloud sign-in, device listing and LAN key fetch."""

from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock

import aiohttp
import pytest

from aioayla_lan import (
    REGIONS,
    AylaCloud,
    CloudAuthError,
    CloudDevice,
    CloudError,
    LanKey,
)

USER_HOST, ADS_HOST = REGIONS["us"]
SIGN_IN_URL = f"https://{USER_HOST}/users/sign_in.json"
DEVICES_URL = f"https://{ADS_HOST}/apiv1/devices.json"
DSN = "AC000W000000001"
LAN_URL = f"https://{ADS_HOST}/apiv1/dsns/{DSN}/lan.json"
TOKEN = "token-abc"


@dataclass
class _Reply:
    status: int = 200
    payload: Any = None
    exception: BaseException | None = None


@dataclass
class _Call:
    method: str
    url: str
    kwargs: dict[str, Any]


class _FakeResponse:
    def __init__(self, reply: _Reply) -> None:
        self.status = reply.status
        self._payload = reply.payload

    def raise_for_status(self) -> None:
        if self.status >= 400:
            raise aiohttp.ClientResponseError(
                MagicMock(), (), status=self.status, message="error"
            )

    async def json(self) -> Any:
        return self._payload


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
    """Serves canned replies keyed by (method, url) and records every call."""

    replies: dict[tuple[str, str], _Reply] = field(default_factory=dict)
    calls: list[_Call] = field(default_factory=list)

    def _request(self, method: str, url: str, kwargs: dict[str, Any]) -> _FakeRequest:
        self.calls.append(_Call(method, url, kwargs))
        return _FakeRequest(self.replies[(method, url)])

    def post(self, url: str, **kwargs: Any) -> _FakeRequest:
        return self._request("POST", url, kwargs)

    def get(self, url: str, **kwargs: Any) -> _FakeRequest:
        return self._request("GET", url, kwargs)


@pytest.fixture
def http() -> _FakeHttp:
    return _FakeHttp()


@pytest.fixture
def cloud(http: _FakeHttp) -> AylaCloud:
    return AylaCloud(http, "app-id", "app-secret")  # type: ignore[arg-type]


@pytest.fixture
async def signed_in(cloud: AylaCloud, http: _FakeHttp) -> AylaCloud:
    http.replies[("POST", SIGN_IN_URL)] = _Reply(payload={"access_token": TOKEN})
    await cloud.sign_in("user@example.com", "hunter2")
    return cloud


async def test_sign_in_sends_credentials_and_stores_token(
    signed_in: AylaCloud, http: _FakeHttp
) -> None:
    http.replies[("GET", DEVICES_URL)] = _Reply(payload=[])
    await signed_in.list_devices()

    sign_in, get = http.calls
    assert sign_in.kwargs["json"] == {
        "user": {
            "email": "user@example.com",
            "password": "hunter2",
            "application": {"app_id": "app-id", "app_secret": "app-secret"},
        }
    }
    assert get.kwargs["headers"] == {"Authorization": f"auth_token {TOKEN}"}


@pytest.mark.parametrize(
    "region",
    [pytest.param(region, id=region) for region in REGIONS],
)
async def test_region_selects_hosts(http: _FakeHttp, region: str) -> None:
    user_host, ads_host = REGIONS[region]
    sign_in_url = f"https://{user_host}/users/sign_in.json"
    devices_url = f"https://{ads_host}/apiv1/devices.json"
    http.replies[("POST", sign_in_url)] = _Reply(payload={"access_token": TOKEN})
    http.replies[("GET", devices_url)] = _Reply(payload=[])
    cloud = AylaCloud(http, "id", "secret", region)  # type: ignore[arg-type]

    await cloud.sign_in("a", "b")
    await cloud.list_devices()

    assert [call.url for call in http.calls] == [sign_in_url, devices_url]


@pytest.mark.parametrize(
    "status",
    [pytest.param(s, id=str(s)) for s in (401, 403, 404)],
)
async def test_sign_in_rejected(cloud: AylaCloud, http: _FakeHttp, status: int) -> None:
    http.replies[("POST", SIGN_IN_URL)] = _Reply(status=status)
    with pytest.raises(CloudAuthError, match=str(status)):
        await cloud.sign_in("user@example.com", "wrong")
    with pytest.raises(CloudError, match="not signed in"):
        await cloud.list_devices()


@pytest.mark.parametrize(
    "reply",
    [
        pytest.param(_Reply(status=500), id="server-error"),
        pytest.param(
            _Reply(exception=aiohttp.ClientConnectionError("down")), id="connection"
        ),
    ],
)
async def test_sign_in_failure(
    cloud: AylaCloud, http: _FakeHttp, reply: _Reply
) -> None:
    http.replies[("POST", SIGN_IN_URL)] = reply
    with pytest.raises(CloudError) as excinfo:
        await cloud.sign_in("user@example.com", "hunter2")
    assert not isinstance(excinfo.value, CloudAuthError)


async def test_list_devices(signed_in: AylaCloud, http: _FakeHttp) -> None:
    http.replies[("GET", DEVICES_URL)] = _Reply(
        payload=[
            {
                "device": {
                    "dsn": DSN,
                    "product_name": "Living room",
                    "lan_ip": "192.0.2.50",
                    "lan_enabled": True,
                }
            },
            {"device": {"dsn": "AC000W000000002"}},
            {"not_a_device": {}},
            {"device": None},
        ]
    )
    assert await signed_in.list_devices() == [
        CloudDevice(DSN, "Living room", "192.0.2.50", True),
        CloudDevice("AC000W000000002", None, None, False),
    ]


async def test_get_lan_key(signed_in: AylaCloud, http: _FakeHttp) -> None:
    http.replies[("GET", LAN_URL)] = _Reply(
        payload={"lanip": {"lanip_key": "secret-key", "lanip_key_id": 42}}
    )
    lan_key = await signed_in.get_lan_key(DSN)
    assert lan_key == LanKey(key="secret-key", key_id=42)
    assert "secret-key" not in repr(lan_key)


@pytest.mark.parametrize(
    "reply",
    [
        pytest.param(_Reply(status=401), id="unauthorized"),
        pytest.param(_Reply(status=500), id="server-error"),
        pytest.param(
            _Reply(exception=aiohttp.ClientConnectionError("down")), id="connection"
        ),
    ],
)
async def test_get_failure_raises_cloud_error(
    signed_in: AylaCloud, http: _FakeHttp, reply: _Reply
) -> None:
    http.replies[("GET", LAN_URL)] = reply
    with pytest.raises(CloudError):
        await signed_in.get_lan_key(DSN)


async def test_get_timeout_raises_cloud_error(
    signed_in: AylaCloud, http: _FakeHttp
) -> None:
    http.replies[("GET", LAN_URL)] = _Reply(exception=TimeoutError())
    with pytest.raises(CloudError):
        await signed_in.get_lan_key(DSN)


async def test_get_before_sign_in(cloud: AylaCloud, http: _FakeHttp) -> None:
    with pytest.raises(CloudError, match="not signed in"):
        await cloud._get("/apiv1/devices.json")
    with pytest.raises(CloudError, match="not signed in"):
        await cloud.get_lan_key(DSN)
    assert http.calls == []
