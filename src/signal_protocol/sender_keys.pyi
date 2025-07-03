# Typing stub for signal_protocol.sender_keys module
# Direct class definitions instead of type aliases

from ._signal_protocol.sender_keys import (
    SenderKeyName as _SenderKeyNameImpl,
    SenderKeyRecord as _SenderKeyRecordImpl,
)

from .address import ProtocolAddress

class SenderKeyName(_SenderKeyNameImpl):
    """Identifier for a sender key in group messaging."""

    def __init__(self, group_id: str, sender: ProtocolAddress) -> None: ...
    def group_id(self) -> str: ...
    def sender(self) -> ProtocolAddress: ...

class SenderKeyRecord(_SenderKeyRecordImpl):
    """Record containing sender key information for group messaging."""

    @staticmethod
    def new_empty() -> 'SenderKeyRecord': ...
    def is_empty(self) -> bool: ...
    def serialize(self) -> bytes: ...
    @staticmethod
    def deserialize(data: bytes) -> 'SenderKeyRecord': ...

__all__ = ["SenderKeyName", "SenderKeyRecord"]
