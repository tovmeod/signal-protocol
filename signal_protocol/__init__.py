# Import the compiled Rust extension module directly
from . import _signal_protocol
import sys

# List of all submodules/attributes to be lazily loaded from _signal_protocol
_LAZY_LOAD_ATTRIBUTES = [
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

__all__ = _LAZY_LOAD_ATTRIBUTES

def __getattr__(name: str):
    if name in _LAZY_LOAD_ATTRIBUTES:
        # Get the attribute from the Rust extension module
        module = getattr(_signal_protocol, name)
        # Cache it on the current module (signal_protocol) for future accesses
        setattr(sys.modules[__name__], name, module)
        return module
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

# To ensure IDEs and static analyzers can still "see" the attributes,
# especially if they don't execute __getattr__ during analysis.
# This block is optional and might not be necessary depending on tooling.
if typing.TYPE_CHECKING:
    from ._signal_protocol import address
    from ._signal_protocol import curve
    from ._signal_protocol import error
    from ._signal_protocol import fingerprint
    from ._signal_protocol import group_cipher
    from ._signal_protocol import identity_key
    from ._signal_protocol import protocol
    from ._signal_protocol import ratchet
    from ._signal_protocol import sealed_sender
    from ._signal_protocol import sender_keys
    from ._signal_protocol import session_cipher
    from ._signal_protocol import session
    from ._signal_protocol import state
    from ._signal_protocol import storage
    import typing
