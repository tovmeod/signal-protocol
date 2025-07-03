# Typing stub for signal_protocol.error module
# Direct class definition instead of type alias

from ._signal_protocol.error import SignalProtocolException as _SignalProtocolExceptionImpl

class SignalProtocolException(Exception, _SignalProtocolExceptionImpl):
    """Base exception for Signal Protocol errors."""
    ...

__all__ = ["SignalProtocolException"]
