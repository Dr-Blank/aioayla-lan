"""One-time fetch of a device's LAN key from the Ayla cloud.

The app ID and secret identify the vendor's mobile app and are supplied by the
caller. After this, local control needs no internet.
"""

from dataclasses import dataclass
from typing import Any

import aiohttp

from .exceptions import CloudAuthError, CloudError
from .models import LanKey

REGIONS: dict[str, tuple[str, str]] = {
    "us": ("user-field.aylanetworks.com", "ads-field.aylanetworks.com"),
    "eu": ("user-field-eu.aylanetworks.com", "ads-eu.aylanetworks.com"),
    "cn": ("user-field.ayla.com.cn", "ads-field.ayla.com.cn"),
}
_TIMEOUT = aiohttp.ClientTimeout(total=20)


@dataclass(frozen=True)
class CloudDevice:
    """A device listed on the account."""

    dsn: str
    product_name: str | None
    lan_ip: str | None
    lan_enabled: bool


class AylaCloud:
    """Minimal Ayla cloud client: sign in, list devices, fetch LAN keys."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        app_id: str,
        app_secret: str,
        region: str = "us",
    ) -> None:
        """Initialise for one region."""
        self._http = session
        self._app_id = app_id
        self._app_secret = app_secret
        self._user_host, self._ads_host = REGIONS[region]
        self._token: str | None = None

    async def sign_in(self, email: str, password: str) -> None:
        """Sign in. Raises :exc:`CloudAuthError` on bad credentials."""
        payload = {
            "user": {
                "email": email,
                "password": password,
                "application": {
                    "app_id": self._app_id,
                    "app_secret": self._app_secret,
                },
            }
        }
        try:
            async with self._http.post(
                f"https://{self._user_host}/users/sign_in.json",
                json=payload,
                timeout=_TIMEOUT,
            ) as resp:
                if resp.status in (401, 403, 404):
                    raise CloudAuthError(f"sign-in rejected: HTTP {resp.status}")
                resp.raise_for_status()
                auth = await resp.json()
        except (aiohttp.ClientError, TimeoutError) as err:
            raise CloudError(err) from err
        if not isinstance(auth, dict) or not isinstance(
            token := auth.get("access_token"), str
        ):
            raise CloudError("sign-in reply has no access token")
        self._token = token

    async def _get(self, path: str) -> Any:
        if self._token is None:
            raise CloudError("not signed in")
        try:
            async with self._http.get(
                f"https://{self._ads_host}{path}",
                headers={"Authorization": f"auth_token {self._token}"},
                timeout=_TIMEOUT,
            ) as resp:
                resp.raise_for_status()
                return await resp.json()
        except (aiohttp.ClientError, TimeoutError) as err:
            raise CloudError(err) from err

    async def list_devices(self) -> list[CloudDevice]:
        """List devices on the account."""
        return [
            CloudDevice(
                dsn=dev["dsn"],
                product_name=dev.get("product_name"),
                lan_ip=dev.get("lan_ip"),
                lan_enabled=bool(dev.get("lan_enabled")),
            )
            for entry in await self._get("/apiv1/devices.json")
            if (dev := entry.get("device"))
        ]

    async def get_lan_key(self, dsn: str) -> LanKey:
        """Fetch the LAN key for one device."""
        reply = await self._get(f"/apiv1/dsns/{dsn}/lan.json")
        try:
            lan = reply["lanip"]
            return LanKey(key=lan["lanip_key"], key_id=lan["lanip_key_id"])
        except (KeyError, TypeError) as err:
            raise CloudError(f"no LAN key for {dsn}") from err
