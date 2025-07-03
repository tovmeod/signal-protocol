# Typing stub for signal_protocol.state module
from ._signal_protocol import state as _state_impl
from ._signal_protocol import (
    SessionRecord as _SessionRecordType,
    PreKeyRecord as _PreKeyRecordType,
    SignedPreKeyRecord as _SignedPreKeyRecordType,
    PreKeyBundle as _PreKeyBundleType,
)

SessionRecord: type[_SessionRecordType] = _state_impl.SessionRecord
PreKeyRecord: type[_PreKeyRecordType] = _state_impl.PreKeyRecord
SignedPreKeyRecord: type[_SignedPreKeyRecordType] = _state_impl.SignedPreKeyRecord
PreKeyBundle: type[_PreKeyBundleType] = _state_impl.PreKeyBundle

__all__ = [
    "SessionRecord",
    "PreKeyRecord",
    "SignedPreKeyRecord",
    "PreKeyBundle",
]
