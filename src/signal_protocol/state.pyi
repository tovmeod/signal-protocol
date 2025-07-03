# Typing stub for signal_protocol.state module
# Direct class definitions instead of type aliases

from ._signal_protocol.state import (
    SessionRecord as _SessionRecordImpl,
    PreKeyRecord as _PreKeyRecordImpl,
    SignedPreKeyRecord as _SignedPreKeyRecordImpl,
    PreKeyBundle as _PreKeyBundleImpl,
)

from .curve import KeyPair, PublicKey
from .identity_key import IdentityKey

class SessionRecord(_SessionRecordImpl):
    """Record containing session state information."""

    @staticmethod
    def new_fresh() -> 'SessionRecord': ...
    def serialize(self) -> bytes: ...
    @staticmethod
    def deserialize(data: bytes) -> 'SessionRecord': ...
    def session_version(self) -> int: ...
    def alice_base_key(self) -> bytes: ...

class PreKeyRecord(_PreKeyRecordImpl):
    """Record containing pre-key information."""

    def __init__(self, id: int, key_pair: KeyPair) -> None: ...
    def serialize(self) -> bytes: ...
    @staticmethod
    def deserialize(data: bytes) -> 'PreKeyRecord': ...

class SignedPreKeyRecord(_SignedPreKeyRecordImpl):
    """Record containing signed pre-key information."""

    def __init__(self, id: int, timestamp: int, key_pair: KeyPair, signature: bytes) -> None: ...
    def serialize(self) -> bytes: ...
    @staticmethod
    def deserialize(data: bytes) -> 'SignedPreKeyRecord': ...

class PreKeyBundle(_PreKeyBundleImpl):
    """Bundle containing pre-key information for session initialization."""

    def __init__(
        self,
        registration_id: int,
        device_id: int,
        prekey_id: int,
        prekey: PublicKey,
        signed_prekey_id: int,
        signed_prekey: PublicKey,
        signed_prekey_signature: bytes,
        identity_key: IdentityKey,
    ) -> None: ...

__all__ = [
    "SessionRecord",
    "PreKeyRecord",
    "SignedPreKeyRecord",
    "PreKeyBundle",
]
