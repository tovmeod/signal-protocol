# Typing stub for signal_protocol.protocol module
from ._signal_protocol import protocol as _protocol_impl
from ._signal_protocol import (
    CiphertextMessage as _CiphertextMessageType,
    PreKeySignalMessage as _PreKeySignalMessageType,
    SignalMessage as _SignalMessageType,
    SenderKeyDistributionMessage as _SenderKeyDistributionMessageType,
)

CiphertextMessage: type[_CiphertextMessageType] = _protocol_impl.CiphertextMessage
PreKeySignalMessage: type[_PreKeySignalMessageType] = _protocol_impl.PreKeySignalMessage
SignalMessage: type[_SignalMessageType] = _protocol_impl.SignalMessage
SenderKeyDistributionMessage: type[_SenderKeyDistributionMessageType] = _protocol_impl.SenderKeyDistributionMessage

__all__ = [
    "CiphertextMessage",
    "PreKeySignalMessage",
    "SignalMessage",
    "SenderKeyDistributionMessage",
]
