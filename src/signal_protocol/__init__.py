import sys

# Import the compiled Rust extension module directly
from . import _signal_protocol

# Re-export all submodules and make them available in sys.modules
# so that "from signal_protocol.submodule import Foo" works.
_submodules = {
    "address": _signal_protocol.address,
    "curve": _signal_protocol.curve,
    "error": _signal_protocol.error,
    "fingerprint": _signal_protocol.fingerprint,
    "group_cipher": _signal_protocol.group_cipher,
    "identity_key": _signal_protocol.identity_key,
    "protocol": _signal_protocol.protocol,
    "ratchet": _signal_protocol.ratchet,
    "sealed_sender": _signal_protocol.sealed_sender,
    "sender_keys": _signal_protocol.sender_keys,
    "session_cipher": _signal_protocol.session_cipher,
    "session": _signal_protocol.session,
    "state": _signal_protocol.state,
    "storage": _signal_protocol.storage,
}

for name, module in _submodules.items():
    globals()[name] = module
    sys.modules[f"signal_protocol.{name}"] = module

# Export everything
__all__ = [
    'address',
    'curve',
    'error',
    'fingerprint',
    'group_cipher',
    'identity_key',
    'protocol',
    'ratchet',
    'sealed_sender',
    'sender_keys',
    'session_cipher',
    'session',
    'state',
    'storage',
]
