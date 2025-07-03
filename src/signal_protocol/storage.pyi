# Typing stub for signal_protocol.storage module
from typing import Optional

# Import directly from native extension submodules
from ._signal_protocol.storage import (
    PersistentStorageBase as _PersistentStorageBaseImpl,
    InMemSignalProtocolStore as _InMemSignalProtocolStoreImpl,
)

# Import required types from other modules
from .address import ProtocolAddress
from .identity_key import IdentityKey, IdentityKeyPair
from .state import SessionRecord, PreKeyRecord, SignedPreKeyRecord
from .sender_keys import SenderKeyName, SenderKeyRecord

class PersistentStorageBase(_PersistentStorageBaseImpl):
    """Base class for persistent storage implementations."""

    def __init__(self) -> None: ...

    # Identity store methods
    def save_identity(self, address: ProtocolAddress, identity_key: IdentityKey) -> bool: ...
    def get_identity(self, address: ProtocolAddress) -> Optional[IdentityKey]: ...

    # Session store methods
    def store_session(self, address: ProtocolAddress, session_record: SessionRecord) -> None: ...
    def load_session(self, address: ProtocolAddress) -> Optional[SessionRecord]: ...
    def contains_session(self, address: ProtocolAddress) -> bool:
        """
        Check if session exists for the given address.

        This is a lightweight operation that can be optimized by subclasses
        to avoid loading the full session data. The default implementation
        uses load_session internally.

        Args:
            address: The protocol address to check

        Returns:
            True if session exists, False otherwise
        """
        ...

    # PreKey store methods
    def get_pre_key(self, pre_key_id: int) -> PreKeyRecord: ...
    def save_pre_key(self, pre_key_id: int, pre_key_record: PreKeyRecord) -> None: ...
    def remove_pre_key(self, pre_key_id: int) -> None: ...

    # Signed PreKey store methods
    def get_signed_pre_key(self, signed_pre_key_id: int) -> SignedPreKeyRecord: ...
    def save_signed_pre_key(self, signed_pre_key_id: int, signed_pre_key_record: SignedPreKeyRecord) -> None: ...

    # Sender key store methods
    def store_sender_key(self, sender_key_name: SenderKeyName, sender_key_record: SenderKeyRecord) -> None: ...
    def load_sender_key(self, sender_key_name: SenderKeyName) -> Optional[SenderKeyRecord]: ...

class InMemSignalProtocolStore(_InMemSignalProtocolStoreImpl):
    """In-memory implementation of Signal Protocol storage."""

    def __init__(
        self,
        key_pair: IdentityKeyPair,
        registration_id: int,
        persistent_storage: Optional[PersistentStorageBase] = None
    ) -> None: ...

    # Identity store methods
    def get_identity_key_pair(self) -> IdentityKeyPair: ...
    def get_local_registration_id(self) -> int: ...
    def save_identity(self, address: ProtocolAddress, identity: IdentityKey) -> bool: ...
    def get_identity(self, address: ProtocolAddress) -> Optional[IdentityKey]: ...

    # Session store methods
    def load_session(self, address: ProtocolAddress) -> Optional[SessionRecord]: ...
    def store_session(self, address: ProtocolAddress, record: SessionRecord) -> None: ...
    def contains_session(self, address: ProtocolAddress) -> bool:
        """
        Check if a session exists for the given address.

        This is a lightweight operation that first checks the in-memory cache,
        then falls back to persistent storage if available. Does not load
        session data as a side effect.

        Args:
            address: The protocol address to check

        Returns:
            True if session exists in cache or persistent storage, False otherwise
        """
        ...

    # PreKey store methods
    def get_pre_key(self, id: int) -> PreKeyRecord: ...
    def save_pre_key(self, id: int, record: PreKeyRecord) -> None: ...
    def remove_pre_key(self, id: int) -> None: ...

    # Signed PreKey store methods
    def get_signed_pre_key(self, id: int) -> SignedPreKeyRecord: ...
    def save_signed_pre_key(self, id: int, record: SignedPreKeyRecord) -> None: ...

    # Sender key store methods
    def store_sender_key(self, sender_key_name: SenderKeyName, record: SenderKeyRecord) -> None: ...
    def load_sender_key(self, sender_key_name: SenderKeyName) -> Optional[SenderKeyRecord]: ...

__all__ = ["PersistentStorageBase", "InMemSignalProtocolStore"]
