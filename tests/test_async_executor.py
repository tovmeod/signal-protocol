"""
Test async executor functionality and backward compatibility.
"""
import pytest
import asyncio
from signal_protocol import storage, identity_key, address, state, PersistentStorageBase


class SyncOnlyStorage(PersistentStorageBase):
    """Storage that only implements sync methods."""
    
    def __init__(self):
        super().__init__()
        self.identities = {}
        self.sessions = {}
        self.pre_keys = {}
        self.signed_pre_keys = {}
        self.sender_keys = {}
    
    def save_identity(self, addr, identity_key):
        """Sync implementation."""
        key = f"{addr.name()}:{addr.device_id()}"
        self.identities[key] = identity_key
        return True
    
    def get_identity(self, addr):
        """Sync implementation."""
        key = f"{addr.name()}:{addr.device_id()}"
        return self.identities.get(key, None)
    
    def store_session(self, addr, session_record):
        """Sync implementation."""
        key = f"{addr.name()}:{addr.device_id()}"
        self.sessions[key] = session_record
    
    def load_session(self, addr):
        """Sync implementation."""
        key = f"{addr.name()}:{addr.device_id()}"
        return self.sessions.get(key, None)
    
    def contains_session(self, addr):
        """Sync implementation."""
        key = f"{addr.name()}:{addr.device_id()}"
        return key in self.sessions


class AsyncOnlyStorage(PersistentStorageBase):
    """Storage that only implements async methods."""
    
    def __init__(self):
        super().__init__()
        self.identities = {}
        self.sessions = {}
        self.pre_keys = {}
        self.signed_pre_keys = {}
        self.sender_keys = {}
    
    async def save_identity(self, addr, identity_key):
        """Async implementation."""
        await asyncio.sleep(0.001)  # Simulate async work
        key = f"{addr.name()}:{addr.device_id()}"
        self.identities[key] = identity_key
        return True
    
    async def get_identity(self, addr):
        """Async implementation."""
        await asyncio.sleep(0.001)  # Simulate async work
        key = f"{addr.name()}:{addr.device_id()}"
        return self.identities.get(key, None)
    
    async def store_session(self, addr, session_record):
        """Async implementation."""
        await asyncio.sleep(0.001)  # Simulate async work
        key = f"{addr.name()}:{addr.device_id()}"
        self.sessions[key] = session_record
    
    async def load_session(self, addr):
        """Async implementation."""
        await asyncio.sleep(0.001)  # Simulate async work
        key = f"{addr.name()}:{addr.device_id()}"
        return self.sessions.get(key, None)
    
    async def contains_session(self, addr):
        """Async implementation."""
        await asyncio.sleep(0.001)  # Simulate async work
        key = f"{addr.name()}:{addr.device_id()}"
        return key in self.sessions


def test_sync_only_storage_backward_compatibility():
    """Test that sync-only storage works without creating async executor."""
    # Create sync-only storage
    sync_storage = SyncOnlyStorage()
    
    # Initially, no executor should be running
    assert sync_storage._async_executor is None
    
    # Create store with sync storage
    identity_key_pair = identity_key.IdentityKeyPair.generate()
    store = storage.InMemSignalProtocolStore(identity_key_pair, 123, sync_storage)
    
    # Use the store
    addr = address.ProtocolAddress("test_user", 1)
    session_record = state.SessionRecord.new_fresh()
    
    # These should work without starting async executor
    store.store_session(addr, session_record)
    assert store.contains_session(addr)
    loaded_session = store.load_session(addr)
    assert loaded_session is not None
    
    # Verify no async executor was started (sync storage shouldn't have one)
    assert sync_storage._async_executor is None
    
    # Clean up
    sync_storage.close()


def test_async_storage_creates_executor():
    """Test that async storage creates and uses executor."""
    # Create async storage
    async_storage = AsyncOnlyStorage()
    
    # Executor should be created when async method is called
    assert async_storage._async_executor is None  # Not created yet
    
    # Create store with async storage
    identity_key_pair = identity_key.IdentityKeyPair.generate()
    store = storage.InMemSignalProtocolStore(identity_key_pair, 123, async_storage)
    
    # Use the store - this should trigger async executor creation
    addr = address.ProtocolAddress("test_user", 1)
    session_record = state.SessionRecord.new_fresh()
    
    # These should work and start async executor
    store.store_session(addr, session_record)
    
    # Verify async executor was created after operations
    assert async_storage._async_executor is not None
    assert async_storage._async_executor.is_set()
    
    # Continue testing async functionality
    assert store.contains_session(addr)
    loaded_session = store.load_session(addr)
    assert loaded_session is not None
    
    # Clean up
    async_storage.close()


def test_mixed_sync_async_context():
    """Test that async storage works in both sync and async contexts."""
    async_storage = AsyncOnlyStorage()
    
    # Create store with async storage
    identity_key_pair = identity_key.IdentityKeyPair.generate()
    store = storage.InMemSignalProtocolStore(identity_key_pair, 123, async_storage)
    
    # Test in sync context
    addr = address.ProtocolAddress("test_user", 1)
    session_record = state.SessionRecord.new_fresh()
    
    store.store_session(addr, session_record)
    assert store.contains_session(addr)
    
    # Test in async context
    async def async_test():
        addr2 = address.ProtocolAddress("test_user2", 1)
        session_record2 = state.SessionRecord.new_fresh()
        
        store.store_session(addr2, session_record2)
        assert store.contains_session(addr2)
        return True
    
    # Run async test
    result = asyncio.run(async_test())
    assert result
    
    # Clean up
    async_storage.close()


def test_executor_cleanup():
    """Test that executor can be properly shut down."""
    # Start with async storage to trigger executor
    async_storage = AsyncOnlyStorage()
    identity_key_pair = identity_key.IdentityKeyPair.generate()
    store = storage.InMemSignalProtocolStore(identity_key_pair, 123, async_storage)
    
    # Use the store to trigger executor creation
    addr = address.ProtocolAddress("test_user", 1)
    session_record = state.SessionRecord.new_fresh()
    store.store_session(addr, session_record)
    
    # Verify executor is running
    assert async_storage._async_executor is not None
    assert async_storage._async_executor.is_set()
    
    # Clean up
    async_storage.close()
    
    # Verify executor is shut down
    assert async_storage._shutdown_event.is_set()


@pytest.mark.asyncio
async def test_async_context_handling():
    """Test that async methods work correctly in async context."""
    async_storage = AsyncOnlyStorage()
    identity_key_pair = identity_key.IdentityKeyPair.generate()
    store = storage.InMemSignalProtocolStore(identity_key_pair, 123, async_storage)
    
    # This should work in async context
    addr = address.ProtocolAddress("test_user", 1)
    session_record = state.SessionRecord.new_fresh()
    
    store.store_session(addr, session_record)
    assert store.contains_session(addr)
    loaded_session = store.load_session(addr)
    assert loaded_session is not None
    
    # Clean up
    async_storage.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])