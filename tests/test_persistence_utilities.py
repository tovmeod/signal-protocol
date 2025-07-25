"""
Tests for PersistenceManager utility methods exposed through InMemSignalProtocolStore.
"""
import tempfile
import pytest
import signal_protocol


@pytest.mark.asyncio
async def test_persistence_utility_methods():
    """Test the database utility methods exposed through InMemSignalProtocolStore"""
    identity_key_pair = signal_protocol.identity_key.IdentityKeyPair.generate()
    registration_id = 12345
    device_jid = "test_device@example.com"
    
    # Use temporary database file
    with tempfile.NamedTemporaryFile(suffix='.db') as temp_db:
        connection_string = f"sqlite://{temp_db.name}"
        
        # Create store with database persistence
        store = signal_protocol.InMemSignalProtocolStore(
            identity_key_pair,
            registration_id,
            connection_string=connection_string,
            device_jid=device_jid
        )
        
        # Test device_jid method
        retrieved_jid = store.device_jid()
        assert retrieved_jid == device_jid
        
        # Test migrate method  
        await store.migrate()
        
        # Test contains_session method
        test_address = signal_protocol.address.ProtocolAddress("test_user", 1)
        has_session = store.contains_session(test_address)
        assert has_session == False  # No session should exist initially
        
        # Test delete_session method (should return False since no session exists)
        deleted = await store.delete_session("test_user", 1)
        assert not deleted  # Should be False since no session exists to delete
        
        # Test delete_all_sessions_for_user method (should return 0 since no sessions exist)
        deleted_count = await store.delete_all_sessions_for_user("test_user")
        assert deleted_count == 0


def test_utility_methods_without_persistence():
    """Test that utility methods fail gracefully when persistence is not enabled"""
    identity_key_pair = signal_protocol.identity_key.IdentityKeyPair.generate()
    registration_id = 12345
    
    # Create basic store (no persistence)
    store = signal_protocol.InMemSignalProtocolStore(
        identity_key_pair, 
        registration_id
    )
    
    # All persistence methods should raise RuntimeError
    with pytest.raises(RuntimeError, match="only available when persistence is enabled"):
        store.device_jid()
        
    test_address = signal_protocol.address.ProtocolAddress("test_user", 1)
    
    # These async methods should also fail but need to be called with pytest-asyncio
    # For now, we just test the sync method


@pytest.mark.asyncio 
async def test_utility_methods_without_persistence_async():
    """Test that async utility methods fail gracefully when persistence is not enabled"""
    identity_key_pair = signal_protocol.identity_key.IdentityKeyPair.generate()
    registration_id = 12345
    
    # Create basic store (no persistence)
    store = signal_protocol.InMemSignalProtocolStore(
        identity_key_pair, 
        registration_id
    )
    
    test_address = signal_protocol.address.ProtocolAddress("test_user", 1)
    
    with pytest.raises(RuntimeError, match="only available when persistence is enabled"):
        await store.migrate()
    
    assert not store.contains_session(test_address)
        
    with pytest.raises(RuntimeError, match="only available when persistence is enabled"):
        await store.delete_session("test_user", 1)
        
    with pytest.raises(RuntimeError, match="only available when persistence is enabled"):
        await store.delete_all_sessions_for_user("test_user")