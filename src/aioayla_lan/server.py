"""Framework-agnostic handling of the callback endpoints the module dials.

Host these under `/local_lan/` on any HTTP server and pass each request to
:meth:`AylaLanServer.handle`. The endpoints cannot be authenticated with a token, so
requests are only accepted from the IP of a registered device, and every
encrypted payload is HMAC-checked before it is parsed.

Replies are 206 Partial Content while the device has commands queued, which
makes the module fetch `commands.json` again without another notify.
"""

import ipaddress
import json
import logging
from typing import Any

from .device import AylaLanDevice
from .exceptions import AylaLanError

_LOGGER = logging.getLogger(__name__)


def _normalize_ip(address: str) -> str:
    """Canonical form, so IPv4-mapped IPv6 peers match their IPv4 device."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return address
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return str(ip.ipv4_mapped)
    return str(ip)


def _more(device: AylaLanDevice) -> int:
    return 206 if device.pending else 200


class AylaLanServer:
    """Routes callback requests to the device that sent them."""

    def __init__(self) -> None:
        """Initialise with no devices."""
        self._devices: dict[str, AylaLanDevice] = {}

    def add_device(self, device: AylaLanDevice) -> None:
        """Accept callbacks from :attr:`device.host <AylaLanDevice.host>`."""
        self._devices[_normalize_ip(device.host)] = device

    def remove_device(self, device: AylaLanDevice) -> None:
        """Stop accepting callbacks from :attr:`device.host <AylaLanDevice.host>`."""
        host = _normalize_ip(device.host)
        if self._devices.get(host) is device:
            del self._devices[host]

    def handle(
        self, remote: str | None, method: str, path: str, body: bytes
    ) -> tuple[int, Any]:
        """Handle one request. Returns (HTTP status, JSON-serialisable body).

        Reply with the status as given: 206 is what keeps the module fetching.

        `path` is relative to `/local_lan/`, for example `commands.json`.
        """
        if (
            remote is None
            or (device := self._devices.get(_normalize_ip(remote))) is None
        ):
            _LOGGER.debug("rejecting callback from unknown address %s", remote)
            return 403, {}

        if method == "GET":
            if not path.endswith("commands.json"):
                return 404, {}
            try:
                reply = device.handle_commands()
            except AylaLanError:
                return 400, {}
            return _more(device), reply

        try:
            doc = json.loads(body) if body else {}
        except ValueError:
            return 400, {}
        if not isinstance(doc, dict):
            return 400, {}

        try:
            if "key_exchange" in doc:
                return 200, device.handle_key_exchange(doc["key_exchange"])
            if "enc" in doc:
                device.handle_datapoint(doc)
                return _more(device), {}
        except AylaLanError as err:
            _LOGGER.warning("%s: %s on %s", device.dsn, type(err).__name__, path)
            return (404 if "key_exchange" in doc else 400), {}
        except (KeyError, TypeError, ValueError) as err:
            _LOGGER.debug("%s: malformed %s: %s", device.dsn, path, err)
            return 400, {}
        return 200, {}
