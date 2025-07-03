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
        pre_key_id: Optional[int],
        pre_key_public: Optional[PublicKey],
        signed_pre_key_id: int,
        signed_pre_key_public: PublicKey,
        signed_pre_key_signature: bytes,
        identity_key: IdentityKey,
    ) -> None:
        """
        Create a new PreKeyBundle.

        Args:
            registration_id: Registration ID of the remote client
            device_id: Device ID of the remote client
            pre_key_id: ID of the one-time pre-key (None if no pre-key available)
            pre_key_public: Public component of one-time pre-key (None if no pre-key available)
            signed_pre_key_id: ID of the signed pre-key
            signed_pre_key_public: Public component of signed pre-key
            signed_pre_key_signature: Signature of the signed pre-key
            identity_key: Identity key of the remote client
        """
        ...

    def registration_id(self) -> int: ...
    def device_id(self) -> int: ...
    def pre_key_id(self) -> Optional[int]: ...
    def pre_key_public(self) -> Optional[PublicKey]: ...
    def signed_pre_key_id(self) -> int: ...
    def signed_pre_key_public(self) -> PublicKey: ...
    def signed_pre_key_signature(self) -> bytes: ...
    def identity_key(self) -> IdentityKey: ...
