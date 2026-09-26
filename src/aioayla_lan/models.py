"""Data models."""

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class LanKey:
    """Per-device LAN key, fetched once from the cloud.

    :attr:`key` grants full local control of the device. Never log it. A
    :attr:`key_id` of None accepts whichever id the device offers.
    """

    key: str = field(repr=False)
    key_id: int | None = None


@dataclass(frozen=True)
class Datapoint:
    """One property value reported by the device, uninterpreted."""

    name: str
    value: Any
    base_type: str | None = None
