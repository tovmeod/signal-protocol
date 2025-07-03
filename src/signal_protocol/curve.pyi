# Typing stub for signal_protocol.curve module
# Re-export from the native _signal_protocol extension's curve submodule

from ._signal_protocol import curve as _curve_impl
from ._signal_protocol import (
    KeyPair as _KeyPairType,
    PublicKey as _PublicKeyType,
    PrivateKey as _PrivateKeyType,
    generate_keypair as _generate_keypair_func, # Assuming this is how top-level funcs are accessed if needed directly
    verify_signature as _verify_signature_func,   # Or they are methods on _curve_impl
)

# Classes
KeyPair: type[_KeyPairType] = _curve_impl.KeyPair
PublicKey: type[_PublicKeyType] = _curve_impl.PublicKey
PrivateKey: type[_PrivateKeyType] = _curve_impl.PrivateKey

# Functions - assuming they are attributes of the curve submodule object
generate_keypair = _curve_impl.generate_keypair
verify_signature = _curve_impl.verify_signature


__all__ = [
    "KeyPair",
    "PublicKey",
    "PrivateKey",
    "generate_keypair",
    "verify_signature",
]
