# Typing stub for signal_protocol.identity_key module
from ._signal_protocol import identity_key as _identity_key_impl
from ._signal_protocol import (
    IdentityKey as _IdentityKeyType,
    IdentityKeyPair as _IdentityKeyPairType,
)

IdentityKey: type[_IdentityKeyType] = _identity_key_impl.IdentityKey
IdentityKeyPair: type[_IdentityKeyPairType] = _identity_key_impl.IdentityKeyPair

__all__ = ["IdentityKey", "IdentityKeyPair"]
