# Typing stub for signal_protocol.ratchet module
from ._signal_protocol import ratchet as _ratchet_impl
from ._signal_protocol import BobSignalProtocolParameters as _BobSignalProtocolParametersType

BobSignalProtocolParameters: type[_BobSignalProtocolParametersType] = _ratchet_impl.BobSignalProtocolParameters

__all__ = ["BobSignalProtocolParameters"]
