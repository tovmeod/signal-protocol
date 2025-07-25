# Typing stub for signal_protocol.ratchet module
# Direct class definition instead of type alias

from ._signal_protocol.ratchet import BobSignalProtocolParameters as _BobSignalProtocolParametersImpl

class BobSignalProtocolParameters(_BobSignalProtocolParametersImpl):
    """Parameters for Bob's side of the Signal Protocol handshake."""
    ...

__all__ = ["BobSignalProtocolParameters"]
