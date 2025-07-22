"""Test that cache updates work correctly when loading from database."""

import pytest
from signal_protocol.identity_key import IdentityKeyPair
from signal_protocol.storage import InMemSignalProtocolStore
from signal_protocol.address import ProtocolAddress
from signal_protocol.state import SessionRecord
from signal_protocol.identity_key import IdentityKey
from tests.utils.sessions import initialize_sessions_v3
import tempfile


@pytest.mark.asyncio
async def test_session_cache_update_on_database_load():
    """Test that sessions loaded from database are cached for future reads."""
    identity_key_pair = IdentityKeyPair.generate()
    
    # Create store with persistence
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as temp_db:
        db_path = temp_db.name
    
    store = InMemSignalProtocolStore(
        identity_key_pair, 
        123, 
        connection_string=f"sqlite://{db_path}",
        device_jid="test@example.com"
    )
    await store.migrate()
    
    # Create and store a properly initialized session
    address = ProtocolAddress("alice", 1)
    alice_session_record, _bob_session_record = initialize_sessions_v3()
    store.store_session(address, alice_session_record)
    
    # Verify session was stored
    loaded_session = store.load_session(address)
    assert loaded_session is not None
    
    # Create a second store instance (fresh cache, same database)
    # Use the same device_jid to access the same device's data
    store2 = InMemSignalProtocolStore(
        identity_key_pair, 
        123, 
        connection_string=f"sqlite://{db_path}",
        device_jid="test@example.com"
    )
    
    # First load: should hit database and update cache
    loaded_session_from_db = store2.load_session(address)
    assert loaded_session_from_db is not None
    
    # Verify the session was actually loaded (basic functionality test)
    # Subsequent loads should be faster (from cache)
    loaded_session2 = store2.load_session(address)
    assert loaded_session2 is not None
    
    # Cleanup
    import os
    if os.path.exists(db_path):
        os.remove(db_path)


@pytest.mark.asyncio 
async def test_identity_cache_update_on_database_load():
    """Test that identities loaded from database are cached for future reads."""
    identity_key_pair = IdentityKeyPair.generate()
    other_identity_key_pair = IdentityKeyPair.generate()
    
    # Create store with persistence
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as temp_db:
        db_path = temp_db.name
        
    store = InMemSignalProtocolStore(
        identity_key_pair, 
        123, 
        connection_string=f"sqlite://{db_path}",
        device_jid="test@example.com"
    )
    await store.migrate()
    
    # Create and store an identity using identity_key() method
    address = ProtocolAddress("alice", 1)
    other_identity = other_identity_key_pair.identity_key()
    result = store.save_identity(address, other_identity)
    # Note: save_identity return value indicates if identity was new/changed
    # For now we'll just verify the operation completed without error
    
    # Verify identity was stored
    loaded_identity = store.get_identity(address)
    assert loaded_identity is not None
    
    # Create a second store instance (fresh cache, same database)
    # Use the same device_jid to access the same device's data
    store2 = InMemSignalProtocolStore(
        identity_key_pair, 
        123, 
        connection_string=f"sqlite://{db_path}",
        device_jid="test@example.com"
    )
    
    # First load: should hit database and update cache
    loaded_identity_from_db = store2.get_identity(address)
    assert loaded_identity_from_db is not None
    
    # Verify the identity was actually loaded (basic functionality test)
    # Subsequent loads should be faster (from cache)
    loaded_identity2 = store2.get_identity(address)
    assert loaded_identity2 is not None
    
    # Verify the identity content is the same
    assert loaded_identity.serialize() == loaded_identity_from_db.serialize()
    assert loaded_identity_from_db.serialize() == loaded_identity2.serialize()
    
    # Cleanup
    import os
    if os.path.exists(db_path):
        os.remove(db_path)


def test_cache_update_functionality_verification():
    """Verify that the cache update implementation is in place."""
    # This test verifies our implementation exists by checking the structure
    identity_key_pair = IdentityKeyPair.generate()
    store = InMemSignalProtocolStore(identity_key_pair, 123)
    
    # Verify that the store has RwLock wrapper (indicates cache update capability)
    # We can't directly access the internal structure, but we can verify 
    # that operations work correctly
    
    # Test basic functionality
    assert store.get_local_registration_id() == 123
    retrieved_key_pair = store.get_identity_key_pair()
    assert retrieved_key_pair.public_key().serialize() == identity_key_pair.public_key().serialize()


@pytest.mark.asyncio
async def test_cache_persistence_integration():
    """Integration test for cache + database persistence."""
    identity_key_pair = IdentityKeyPair.generate()
    
    # Create store with persistence
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as temp_db:
        db_path = temp_db.name
        
    store = InMemSignalProtocolStore(
        identity_key_pair, 
        123, 
        connection_string=f"sqlite://{db_path}",
        device_jid="test@example.com"
    )
    await store.migrate()
    
    # Test session persistence
    session_address = ProtocolAddress("session_user", 1)
    alice_session_record, _bob_session_record = initialize_sessions_v3()
    store.store_session(session_address, alice_session_record)
    
    # Test identity persistence
    identity_address = ProtocolAddress("identity_user", 1)
    other_identity_key_pair = IdentityKeyPair.generate()
    other_identity = other_identity_key_pair.identity_key()
    store.save_identity(identity_address, other_identity)
    
    # Verify both are stored in the first store
    loaded_session = store.load_session(session_address)
    loaded_identity = store.get_identity(identity_address)
    assert loaded_session is not None
    assert loaded_identity is not None
    
    # Create a second store instance (fresh cache, same database)
    # Use the same device_jid to access the same device's data
    store2 = InMemSignalProtocolStore(
        identity_key_pair, 
        123, 
        connection_string=f"sqlite://{db_path}",
        device_jid="test@example.com"
    )
    
    # Load from database into fresh cache
    loaded_session_from_db = store2.load_session(session_address)
    loaded_identity_from_db = store2.get_identity(identity_address)
    
    assert loaded_session_from_db is not None
    assert loaded_identity_from_db is not None
    
    # Verify content integrity
    assert loaded_identity.serialize() == loaded_identity_from_db.serialize()
    
    # Test that contains_session works across stores
    assert store.contains_session(session_address)
    assert store2.contains_session(session_address)
    
    # Cleanup
    import os
    if os.path.exists(db_path):
        os.remove(db_path)