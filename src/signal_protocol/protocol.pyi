# Typing stub for signal_protocol.protocol module
# Direct class definitions instead of type aliases

from ._signal_protocol.protocol import (
    CiphertextMessage as _CiphertextMessageImpl,
    PreKeySignalMessage as _PreKeySignalMessageImpl,
    SignalMessage as _SignalMessageImpl,
    SenderKeyDistributionMessage as _SenderKeyDistributionMessageImpl,
)

class CiphertextMessage(_CiphertextMessageImpl):
    """Base class for encrypted messages."""

    def message_type(self) -> int: ...
    def serialize(self) -> bytes: ...

class PreKeySignalMessage(_PreKeySignalMessageImpl):
    """Message containing a pre-key Signal message."""

    @staticmethod
    def try_from(data: bytes) -> 'PreKeySignalMessage': ...

class SignalMessage(_SignalMessageImpl):
    """Regular Signal message (non-prekey)."""

    @staticmethod
    def try_from(data: bytes) -> 'SignalMessage': ...

class SenderKeyDistributionMessage(_SenderKeyDistributionMessageImpl):
    """Message for distributing sender keys in group messaging."""

    @staticmethod
    def try_from(data: bytes) -> 'SenderKeyDistributionMessage': ...
    def serialized(self) -> bytes: ...

__all__ = [
    "CiphertextMessage",
    "PreKeySignalMessage",
    "SignalMessage",
    "SenderKeyDistributionMessage",
]
