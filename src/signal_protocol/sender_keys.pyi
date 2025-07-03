# Typing stub for signal_protocol.sender_keys module
from ._signal_protocol import sender_keys as _sender_keys_impl
from ._signal_protocol import (
    SenderKeyName as _SenderKeyNameType,
    SenderKeyRecord as _SenderKeyRecordType,
)

SenderKeyName: type[_SenderKeyNameType] = _sender_keys_impl.SenderKeyName
SenderKeyRecord: type[_SenderKeyRecordType] = _sender_keys_impl.SenderKeyRecord

__all__ = ["SenderKeyName", "SenderKeyRecord"]
