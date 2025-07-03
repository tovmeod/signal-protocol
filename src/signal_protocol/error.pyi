# Typing stub for signal_protocol.error module
# Re-export from the native _signal_protocol extension's error submodule

from ._signal_protocol import error as _error_impl
from ._signal_protocol import SignalProtocolException as _SignalProtocolExceptionType

# Explicitly re-export SignalProtocolException
SignalProtocolException: type[_SignalProtocolExceptionType] = _error_impl.SignalProtocolException

__all__ = ["SignalProtocolException"]
