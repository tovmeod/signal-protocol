# Typing stub for signal_protocol.address module
# Re-export from the native _signal_protocol extension's address submodule

from ._signal_protocol import address as _address_impl
from ._signal_protocol import ProtocolAddress as _ProtocolAddressType

# Explicitly re-export ProtocolAddress for clarity and direct import
ProtocolAddress: type[_ProtocolAddressType] = _address_impl.ProtocolAddress

__all__ = ["ProtocolAddress"]
