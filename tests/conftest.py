"""Shared fixtures for aioayla_lan tests."""

from typing import Any
from unittest.mock import MagicMock

import pytest

from aioayla_lan import AylaLanDevice, Datapoint, LanKey, SessionCrypto

LAN_KEY = "0123456789abcdef0123456789abcdef"
KEY_ID = 7
DEVICE_HOST = "192.0.2.50"
DSN = "AC000W000000001"
CALLBACK_HOST = "192.0.2.10"
CALLBACK_PORT = 8123
PRIME = ("power", "mode")
RANDOM_1 = "devrandom0123456"
TIME_1 = 123456789


def key_exchange_request(**overrides: Any) -> dict[str, Any]:
    """Build the inner key_exchange document a device sends."""
    return {
        "ver": 1,
        "proto": 1,
        "random_1": RANDOM_1,
        "time_1": TIME_1,
        "key_id": KEY_ID,
    } | overrides


def device_side(reply: dict[str, Any]) -> SessionCrypto:
    """Mirror crypto as the device derives it from our key exchange reply."""
    return SessionCrypto(LAN_KEY, reply["random_2"], reply["time_2"], RANDOM_1, TIME_1)


@pytest.fixture
def datapoints() -> list[Datapoint]:
    """Datapoints reported by the device."""
    return []


@pytest.fixture
def connection_changes() -> list[bool]:
    """Connection state changes reported by the device."""
    return []


@pytest.fixture
def http() -> MagicMock:
    """HTTP session stand-in for tests that never register."""
    return MagicMock()


@pytest.fixture
def device(
    http: MagicMock,
    datapoints: list[Datapoint],
    connection_changes: list[bool],
) -> AylaLanDevice:
    """A device with no session yet."""
    return AylaLanDevice(
        http,
        DEVICE_HOST,
        DSN,
        LanKey(LAN_KEY, KEY_ID),
        CALLBACK_HOST,
        CALLBACK_PORT,
        datapoints.append,
        connection_changes.append,
        prime_properties=PRIME,
    )


@pytest.fixture
def mirror(device: AylaLanDevice) -> SessionCrypto:
    """Complete a key exchange and return the device-side crypto."""
    return device_side(device.handle_key_exchange(key_exchange_request()))
