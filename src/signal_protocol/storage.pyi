# Typing stub for signal_protocol.storage module
from typing import Optional, List, Tuple

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

    # Convenient session deletion wrapper methods

    async def delete_session_by_address(self, address: str) -> bool:
        """
        Delete a session by address string (convenient wrapper).
        
        This method provides a convenient way to delete sessions using an address string,
        automatically parsing the recipient name and device ID from the address format.
        
        Args:
            address: Address string in format "recipient_name:device_id" or just "recipient_name"
                    If no colon is found or device_id is invalid, device_id defaults to 0
            
        Returns:
            True if a session was found and deleted, False if no session was found
            
        Raises:
            RuntimeError: If persistence is not enabled
            
        Note:
            Only available when persistence is enabled.
            This is an async method and must be awaited.
            
        Example:
            store = InMemSignalProtocolStore(
                identity_key_pair, 
                registration_id,
                connection_string="sqlite://signal.db",
                device_jid="alice@example.com"
            )
            
            # Delete session with explicit device ID
            was_deleted = await store.delete_session_by_address("1234567890:1")
            
            # Delete session with default device ID (0)
            was_deleted = await store.delete_session_by_address("user@example.com")
            
            # Handles parsing errors gracefully
            was_deleted = await store.delete_session_by_address("invalid:format:extra")
        """
        ...

    async def delete_all_sessions_by_phone(self, phone: str) -> int:
        """
        Delete all sessions for a phone number (convenient wrapper).
        
        This method deletes all sessions where the recipient name starts with the
        specified phone number followed by a colon, matching the typical Signal
        Protocol address format for phone numbers.
        
        Args:
            phone: Phone number string to match against session recipient names
            
        Returns:
            Number of sessions deleted
            
        Raises:
            RuntimeError: If persistence is not enabled
            
        Note:
            Only available when persistence is enabled.
            This is an async method and must be awaited.
            
        Example:
            store = InMemSignalProtocolStore(
                identity_key_pair, 
                registration_id,
                connection_string="sqlite://signal.db",
                device_jid="alice@example.com"
            )
            
            # Delete all sessions for phone number "1234567890"
            # This will delete sessions for recipients like:
            # - "1234567890:1"
            # - "1234567890:2" 
            # - "1234567890:device_id"
            deleted_count = await store.delete_all_sessions_by_phone("1234567890")
            print(f"Deleted {deleted_count} sessions")
            
        Warning:
            This operation cannot be undone. All session data for the specified
            phone number will be permanently deleted.
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
    
    async def mark_pre_key_uploaded(self, pre_key_id: int) -> bool:
        """
        Mark a pre-key as uploaded.
        
        Sets the uploaded flag to True for the specified pre-key in the database.
        This is useful for tracking which pre-keys have been uploaded to the server.
        
        Args:
            pre_key_id: ID of the pre-key to mark as uploaded
            
        Returns:
            True if the pre-key was found and marked as uploaded, False if not found
            
        Raises:
            RuntimeError: If persistence is not enabled
            
        Note:
            Only available when persistence is enabled.
            This is an async method and must be awaited.
            
        Example:
            store = InMemSignalProtocolStore(
                identity_key_pair, 
                registration_id,
                connection_string="sqlite://signal.db",
                device_jid="alice@example.com"
            )
            
            # Save a pre-key
            pre_key_record = PreKeyRecord(123, key_pair)
            store.save_pre_key(123, pre_key_record)
            
            # Mark it as uploaded to the server (async)
            was_found = await store.mark_pre_key_uploaded(123)
            assert was_found == True
            
            # Batch operations with asyncio.gather
            import asyncio
            pre_key_ids = [100, 101, 102, 103, 104]
            results = await asyncio.gather(*[
                store.mark_pre_key_uploaded(key_id) 
                for key_id in pre_key_ids
            ])
        """
        ...

    async def delete_all_identities(self, phone: str) -> int:
        """
        Delete all identity keys for recipients whose names start with the given phone number.
        
        This helper function deletes all identity keys where the recipient name starts with
        the specified phone number followed by a colon (e.g., "1234567890:").
        
        Args:
            phone: Phone number string to match against recipient names
            
        Returns:
            Number of identity keys deleted
            
        Raises:
            RuntimeError: If persistence is not enabled
            
        Note:
            Only available when persistence is enabled.
            This is an async method and must be awaited.
            
        Example:
            store = InMemSignalProtocolStore(
                identity_key_pair, 
                registration_id,
                connection_string="sqlite://signal.db",
                device_jid="alice@example.com"
            )
            
            # Delete all identity keys for phone number "1234567890"
            # This will delete identities for recipients like:
            # - "1234567890:1" 
            # - "1234567890:2"
            # - "1234567890:device_id"
            deleted_count = await store.delete_all_identities("1234567890")
            print(f"Deleted {deleted_count} identity keys")
            
        Warning:
            This operation cannot be undone. Use with caution as it will remove
            all trust relationships for the specified phone number.
        """
        ...

    async def delete_identity(self, address: str) -> bool:
        """
        Delete a specific identity key for a given address.
        
        This method deletes the identity key for a specific recipient address.
        The address should be in the format "recipient_name:device_id".
        
        Args:
            address: Address string in format "recipient_name:device_id"
            
        Returns:
            True if an identity was found and deleted, False if no identity was found
            
        Raises:
            ValueError: If the address format is invalid
            RuntimeError: If persistence is not enabled
            
        Note:
            Only available when persistence is enabled.
            This is an async method and must be awaited.
            
        Example:
            store = InMemSignalProtocolStore(
                identity_key_pair, 
                registration_id,
                connection_string="sqlite://signal.db",
                device_jid="alice@example.com"
            )
            
            # Delete identity for a specific recipient and device
            was_deleted = await store.delete_identity("1234567890:1")
            if was_deleted:
                print("Identity deleted successfully")
            else:
                print("No identity found for that address")
                
            # Examples of valid address formats:
            await store.delete_identity("phone:123:1")       # Phone with colon
            await store.delete_identity("user@domain.com:2") # Email-like recipient
            await store.delete_identity("simple_user:1")     # Simple name
            
        Warning:
            This operation cannot be undone. The identity will need to be 
            re-established through the normal Signal Protocol handshake.
        """
        ...

    # Pre-key helper methods for advanced key management

    async def get_next_pre_key_id(self) -> int:
        """
        Get the next available pre-key ID.
        
        Returns the next sequential pre-key ID based on existing keys in the database.
        If no pre-keys exist, returns 1.
        
        Returns:
            The next available pre-key ID
            
        Raises:
            RuntimeError: If persistence is not enabled
            
        Note:
            Only available when persistence is enabled.
            This is an async method and must be awaited.
            
        Example:
            store = InMemSignalProtocolStore(
                identity_key_pair, 
                registration_id,
                connection_string="sqlite://signal.db",
                device_jid="alice@example.com"
            )
            
            next_id = await store.get_next_pre_key_id()
            print(f"Next pre-key ID: {next_id}")
        """
        ...

    async def get_non_uploaded_pre_keys(self, limit: Optional[int] = None) -> List[Tuple[int, bytes]]:
        """
        Get existing non-uploaded pre-keys, ordered by key_id.
        
        Returns pre-keys that have been generated but not yet marked as uploaded
        to the server. This is useful for batch uploading operations.
        
        Args:
            limit: Optional maximum number of pre-keys to return
            
        Returns:
            List of tuples (key_id, serialized_pre_key_record)
            
        Raises:
            RuntimeError: If persistence is not enabled
            
        Note:
            Only available when persistence is enabled.
            This is an async method and must be awaited.
            
        Example:
            store = InMemSignalProtocolStore(
                identity_key_pair, 
                registration_id,
                connection_string="sqlite://signal.db",
                device_jid="alice@example.com"
            )
            
            # Get all non-uploaded pre-keys
            all_keys = await store.get_non_uploaded_pre_keys()
            print(f"Found {len(all_keys)} non-uploaded pre-keys")
            
            # Get only first 10 non-uploaded pre-keys
            some_keys = await store.get_non_uploaded_pre_keys(limit=10)
            
            # Process each key
            for key_id, serialized_data in all_keys:
                # Use the serialized_data to reconstruct PreKeyRecord if needed
                print(f"Pre-key {key_id}: {len(serialized_data)} bytes")
        """
        ...

    async def mark_pre_keys_as_uploaded_up_to(self, up_to_id: int) -> int:
        """
        Mark pre-keys as uploaded up to the given ID (inclusive).
        
        This bulk operation marks all pre-keys with IDs less than or equal to
        the specified ID as uploaded. Useful after successful batch uploads.
        
        Args:
            up_to_id: Mark all pre-keys with ID <= this value as uploaded
            
        Returns:
            Number of pre-keys that were marked as uploaded
            
        Raises:
            RuntimeError: If persistence is not enabled
            
        Note:
            Only available when persistence is enabled.
            This is an async method and must be awaited.
            
        Example:
            store = InMemSignalProtocolStore(
                identity_key_pair, 
                registration_id,
                connection_string="sqlite://signal.db",
                device_jid="alice@example.com"
            )
            
            # After successfully uploading pre-keys 1-100 to server
            updated_count = await store.mark_pre_keys_as_uploaded_up_to(100)
            print(f"Marked {updated_count} pre-keys as uploaded")
        """
        ...

    async def uploaded_prekey_count(self) -> int:
        """
        Get the count of uploaded pre-keys.
        
        Returns the total number of pre-keys that have been marked as uploaded
        to the server. Useful for monitoring and quota management.
        
        Returns:
            Number of pre-keys marked as uploaded
            
        Raises:
            RuntimeError: If persistence is not enabled
            
        Note:
            Only available when persistence is enabled.
            This is an async method and must be awaited.
            
        Example:
            store = InMemSignalProtocolStore(
                identity_key_pair, 
                registration_id,
                connection_string="sqlite://signal.db",
                device_jid="alice@example.com"
            )
            
            uploaded_count = await store.uploaded_prekey_count()
            print(f"Currently have {uploaded_count} uploaded pre-keys")
        """
        ...

    async def generate_and_save_pre_key(self, key_id: int, mark_uploaded: bool = False) -> bytes:
        """
        Generate and save a pre-key with the given ID.
        
        Creates a new pre-key with the specified ID and saves it to the database.
        If a pre-key with this ID already exists, returns the existing key.
        
        Args:
            key_id: The ID for the new pre-key
            mark_uploaded: Whether to mark the pre-key as uploaded immediately
            
        Returns:
            Serialized PreKeyRecord data
            
        Raises:
            RuntimeError: If persistence is not enabled
            
        Note:
            Only available when persistence is enabled.
            This is an async method and must be awaited.
            
        Example:
            store = InMemSignalProtocolStore(
                identity_key_pair, 
                registration_id,
                connection_string="sqlite://signal.db",
                device_jid="alice@example.com"
            )
            
            # Generate a new pre-key for uploading
            key_data = await store.generate_and_save_pre_key(42, mark_uploaded=False)
            print(f"Generated pre-key 42: {len(key_data)} bytes")
            
            # Generate a pre-key and mark it as already uploaded
            uploaded_key = await store.generate_and_save_pre_key(43, mark_uploaded=True)
            
            # If key already exists, returns existing data
            same_key = await store.generate_and_save_pre_key(42, mark_uploaded=False)
            assert key_data == same_key
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
