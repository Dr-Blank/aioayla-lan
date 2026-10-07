"""Exceptions raised by aioayla_lan."""


class AylaLanError(Exception):
    """Base class for all aioayla_lan errors."""


class SignatureError(AylaLanError):
    """A payload failed HMAC validation."""


class NoSessionError(AylaLanError):
    """An encrypted payload arrived before a key exchange."""


class KeyIdMismatchError(AylaLanError):
    """The device offered a LAN key other than the one we hold."""


class CannotConnectError(AylaLanError):
    """The device did not answer on the LAN."""


class NoCallbackError(AylaLanError):
    """The device accepted registration but never dialled back."""


class CallbackRejectedError(NoCallbackError):
    """The device refused to dial the callback address, e.g. another subnet."""


class InvalidKeyError(AylaLanError):
    """The device dialled back but the LAN key did not authenticate it."""


class WriteError(AylaLanError):
    """A property write was not confirmed by the device."""


class WriteExpiredError(WriteError):
    """The device did not collect a queued write in time, so it was dropped."""


class WriteRejectedError(WriteError):
    """The device collected a write and refused it.

    Also the base of :exc:`WriteUnacknowledgedError`, so catching this covers a
    missing ack too.
    """


class WriteUnacknowledgedError(WriteRejectedError):
    """The device collected a write but sent no ack in time.

    Not proof the write failed: modules only ack properties the cloud marks
    ack-enabled, and a busy module can ack late. Firmware also drops unknown
    names and out-of-range values without a word. Read the property back.
    """


class CloudAuthError(AylaLanError):
    """Cloud sign-in was rejected."""


class CloudError(AylaLanError):
    """Any other failure talking to the Ayla cloud."""
