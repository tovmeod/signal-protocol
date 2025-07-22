# Typing stub for signal_protocol.storage module
from typing import Optional

# Import directly from native extension submodules
from ._signal_protocol.storage import (
    InMemSignalProtocolStore as _InMemSignalProtocolStoreImpl,
    init_logging as _init_logging,
)

# Import required types from other modules
from .address import ProtocolAddress
from .identity_key import IdentityKey, IdentityKeyPair
from .state import SessionRecord, PreKeyRecord, SignedPreKeyRecord
from .sender_keys import SenderKeyName, SenderKeyRecord

class InMemSignalProtocolStore(_InMemSignalProtocolStoreImpl):
    """In-memory Signal Protocol store with optional database persistence.
    
    This is the main storage implementation that combines fast in-memory caching
    with optional database persistence. It implements all Signal Protocol storage
    traits (sessions, prekeys, identity keys, sender keys).
    
    Architecture:
        - **Cache + Backing Store**: Fast in-memory cache with database persistence
        - **Automatic Fallback**: If not found in cache, loads from database
        - **Write-Through**: All writes go to both cache and database
        - **Database Support**: SQLite and PostgreSQL via connection strings
    
    Usage Examples:
        Basic (cache-only):
            store = InMemSignalProtocolStore(identity_key_pair, registration_id)
        
        With SQLite persistence:
            store = InMemSignalProtocolStore(
                identity_key_pair, 
                registration_id,
                connection_string="sqlite://signal.db",
                device_jid="alice@example.com"
            )
            await store.migrate()  # Create database tables
        
        With PostgreSQL:
            store = InMemSignalProtocolStore(
                identity_key_pair,
                registration_id, 
                connection_string="postgresql://user:pass@localhost/signal",
                device_jid="alice@example.com"
            )
            await store.migrate()
    """

    def __init__(
        self,
        key_pair: IdentityKeyPair,
        registration_id: int,
        connection_string: Optional[str] = None,
        device_jid: Optional[str] = None
    ) -> None:
        """
        Create a Signal Protocol store with optional database persistence.
        
        Args:
            key_pair: Identity key pair for this device
            registration_id: Registration ID for this device  
            connection_string: Optional database URL (e.g., "sqlite://signal.db")
            device_jid: Optional unique device identifier (required if connection_string is provided)
            
        Raises:
            ValueError: If only one of connection_string/device_jid is provided
            RuntimeError: If database connection fails
        
        Examples:
            # In-memory only
            store = InMemSignalProtocolStore(identity_key_pair, 123)
            
            # With SQLite persistence  
            store = InMemSignalProtocolStore(
                identity_key_pair,
                123,
                connection_string="sqlite://signal.db",
                device_jid="alice@example.com"
            )
            await store.migrate()  # Set up database tables
            
        Note:
            Both connection_string and device_jid must be provided together,
            or both omitted for cache-only operation.
        """
        ...
    
    async def migrate(self) -> None:
        """
        Run database migrations to create required tables.
        
        Only available when persistence is enabled. Call this after creating
        a store with with_persistence() to set up the database schema.
        
        Raises:
            RuntimeError: If persistence is not enabled
        
        Example:
            store = InMemSignalProtocolStore(
                identity_key_pair, registration_id, 
                connection_string="sqlite://signal.db", 
                device_jid="alice@example.com"
            )
            await store.migrate()  # Creates tables
        """
        ...
    
    def device_jid(self) -> str:
        """
        Get the device JID for this store.
        
        Returns:
            Device identifier string
            
        Raises:
            RuntimeError: If persistence is not enabled
        """
        ...

    # Identity store methods
    def get_identity_key_pair(self) -> IdentityKeyPair: ...
    def get_local_registration_id(self) -> int: ...

    # Session store methods - Cache + backing store implementation
    def load_session(self, address: ProtocolAddress) -> Optional[SessionRecord]:
        """
        Load session for the given address.
        
        Uses cache + backing store: checks cache first, falls back to database
        if persistence is enabled, and updates cache with loaded data.
        """
        ...
    
    def store_session(self, address: ProtocolAddress, session_record: SessionRecord) -> None:
        """
        Store session for the given address.
        
        Uses cache + backing store: stores to both cache and database
        (if persistence is enabled).
        """
        ...
    
    def contains_session(self, address: ProtocolAddress) -> bool:
        """
        Check if session exists for the given address.
        
        This is an optimized operation that checks cache first, then database
        if persistence is enabled. Faster than load_session for existence checks.
        """
        ...
    
    def delete_session(self, recipient_name: str, recipient_device_id: int) -> bool:
        """
        Delete a specific session.
        
        Args:
            recipient_name: The recipient name
            recipient_device_id: The recipient device ID
            
        Returns:
            True if session existed and was deleted, False if it didn't exist
            
        Note:
            Only available when persistence is enabled.
        """
        ...
    
    def delete_all_sessions_for_user(self, recipient_name: str) -> int:
        """
        Delete all sessions for a specific user (all device IDs).
        
        Args:
            recipient_name: The recipient name to delete sessions for
            
        Returns:
            Number of sessions deleted
            
        Note:
            Only available when persistence is enabled.
        """
        ...

    # Identity store methods - Cache + backing store implementation
    def get_identity(self, address: ProtocolAddress) -> Optional[IdentityKey]:
        """
        Get identity key for the given address.
        
        Uses cache + backing store: checks cache first, falls back to database
        if persistence is enabled.
        """
        ...
    
    def save_identity(self, address: ProtocolAddress, identity_key: IdentityKey) -> bool:
        """
        Save identity key for the given address.
        
        Uses cache + backing store: stores to both cache and database
        (if persistence is enabled).
        
        Returns:
            True if this is a new identity or if the identity changed
        """
        ...

    # PreKey store methods - Cache + backing store implementation  
    def get_pre_key(self, pre_key_id: int) -> PreKeyRecord:
        """
        Load prekey by ID.
        
        Uses cache + backing store pattern.
        """
        ...
    
    def save_pre_key(self, pre_key_id: int, pre_key_record: PreKeyRecord) -> None:
        """
        Store prekey.
        
        Uses cache + backing store pattern.
        """
        ...
    
    def remove_pre_key(self, pre_key_id: int) -> None:
        """
        Remove prekey by ID.
        
        Uses cache + backing store pattern.
        """
        ...
    
    # Signed PreKey store methods - Cache + backing store implementation
    def get_signed_pre_key(self, signed_pre_key_id: int) -> SignedPreKeyRecord:
        """
        Load signed prekey by ID.
        
        Uses cache + backing store pattern.
        """
        ...
    
    def save_signed_pre_key(self, signed_pre_key_id: int, signed_pre_key_record: SignedPreKeyRecord) -> None:
        """
        Store signed prekey.
        
        Uses cache + backing store pattern.
        """
        ...
    
    # Sender key store methods - Cache + backing store implementation
    def store_sender_key(self, sender_key_name: SenderKeyName, sender_key_record: SenderKeyRecord) -> None:
        """
        Store sender key.
        
        Uses cache + backing store pattern.
        """
        ...
    
    def load_sender_key(self, sender_key_name: SenderKeyName) -> Optional[SenderKeyRecord]:
        """
        Load sender key.
        
        Uses cache + backing store pattern.
        """
        ...

    # Resource management
    def close(self) -> None:
        """
        Close the store and clean up resources.
        
        This method closes database connections and cleans up resources.
        After calling this method, the store should not be used for database operations.
        
        Examples:
            # Basic usage
            store = InMemSignalProtocolStore(key_pair, reg_id, "sqlite://db.sqlite", "user@example.com")
            try:
                # Use store...
                pass
            finally:
                store.close()
                
            # Context manager pattern
            store = InMemSignalProtocolStore(key_pair, reg_id, "sqlite://db.sqlite", "user@example.com")
            store.close()  # Safe to call multiple times
        """
        ...


def init_logging() -> None:
    """Initialize logging for the signal-protocol library.

    This function sets up env_logger to handle log output.
    Call this once at the start of your application to see debug and error messages.

    Environment variables:
    - RUST_LOG=debug : Show all debug messages
    - RUST_LOG=signal_protocol=debug : Show only signal-protocol debug messages
    - RUST_LOG=error : Show only error messages
    """
    ...

__all__ = ["InMemSignalProtocolStore", "init_logging"]
