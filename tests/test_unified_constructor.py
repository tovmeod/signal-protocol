"""Test the unified constructor API for InMemSignalProtocolStore."""

import pytest
import tempfile
from signal_protocol.identity_key import IdentityKeyPair
from signal_protocol.storage import InMemSignalProtocolStore


def test_basic_constructor():
    """Test the basic constructor without persistence."""
    identity_key_pair = IdentityKeyPair.generate()
    
    store = InMemSignalProtocolStore(identity_key_pair, 123)
    
    # Verify basic functionality
    assert store.get_local_registration_id() == 123
    retrieved_key_pair = store.get_identity_key_pair()
    assert retrieved_key_pair.public_key().serialize() == identity_key_pair.public_key().serialize()


def test_constructor_with_persistence(temp_db_path):
    """Test the constructor with database persistence using optional parameters."""
    # NOTE: Using temp file instead of sqlite::memory: due to migration issues
    identity_key_pair = IdentityKeyPair.generate()
    
    store = InMemSignalProtocolStore(
        identity_key_pair, 
        123,
        connection_string=f"sqlite://{temp_db_path}",
        device_jid="test@example.com"
    )
    
    # Verify basic functionality
    assert store.get_local_registration_id() == 123
    retrieved_key_pair = store.get_identity_key_pair()
    assert retrieved_key_pair.public_key().serialize() == identity_key_pair.public_key().serialize()
    
    # Verify persistence functionality
    assert store.device_jid() == "test@example.com"


def test_constructor_with_file_database():
    """Test the constructor with file-based SQLite database."""
    identity_key_pair = IdentityKeyPair.generate()
    
    with tempfile.NamedTemporaryFile(suffix='.db') as temp_db:
        store = InMemSignalProtocolStore(
            identity_key_pair, 
            124,
            connection_string=f"sqlite://{temp_db.name}",
            device_jid="test2@example.com"
        )
        
        assert store.device_jid() == "test2@example.com"
        assert store.get_local_registration_id() == 124


def test_constructor_parameter_validation(temp_db_path):
    """Test that constructor validates persistence parameters correctly."""
    identity_key_pair = IdentityKeyPair.generate()
    
    # Should now succeed if only connection_string is provided (for pairing scenarios)
    store_with_conn_only = InMemSignalProtocolStore(
        identity_key_pair, 
        123,
        connection_string=f"sqlite://{temp_db_path}"
    )
    assert store_with_conn_only.get_local_registration_id() == 123
    
    # Should fail if only device_jid is provided (connection string is required for persistence)
    with pytest.raises(ValueError, match="Connection string is required when device_jid is provided"):
        InMemSignalProtocolStore(
            identity_key_pair, 
            123,
            device_jid="test@example.com"
        )


def test_constructor_backward_compatibility(temp_db_path):
    """Test that the constructor maintains backward compatibility."""
    identity_key_pair = IdentityKeyPair.generate()
    
    # Old way (positional arguments only) should still work
    store = InMemSignalProtocolStore(identity_key_pair, 123)
    assert store.get_local_registration_id() == 123
    
    # New way with persistence should work
    store_with_persistence = InMemSignalProtocolStore(
        identity_key_pair, 
        124,
        connection_string=f"sqlite://{temp_db_path}",
        device_jid="test@example.com"
    )
    assert store_with_persistence.get_local_registration_id() == 124
    assert store_with_persistence.device_jid() == "test@example.com"


def test_no_with_persistence_method():
    """Test that the with_persistence method no longer exists."""
    # This tests that we successfully eliminated the with_persistence method
    with pytest.raises(AttributeError):
        InMemSignalProtocolStore.with_persistence
        
    # Also test that it's not available as an instance method
    identity_key_pair = IdentityKeyPair.generate()
    store = InMemSignalProtocolStore(identity_key_pair, 123)
    with pytest.raises(AttributeError):
        store.with_persistence


@pytest.mark.asyncio
async def test_migration_still_async(temp_db_path):
    """Test that migration is still async (that's fine)."""
    identity_key_pair = IdentityKeyPair.generate()
    
    store = InMemSignalProtocolStore(
        identity_key_pair, 
        123,
        connection_string=f"sqlite://{temp_db_path}",
        device_jid="test@example.com"
    )
    
    # Migration should still be async
    await store.migrate()  # This should work without issues


def test_constructor_is_synchronous(temp_db_path):
    """Test that the constructor itself is synchronous and doesn't require await."""
    identity_key_pair = IdentityKeyPair.generate()
    
    # Both basic and persistence constructors should be synchronous
    store1 = InMemSignalProtocolStore(identity_key_pair, 123)
    store2 = InMemSignalProtocolStore(
        identity_key_pair, 
        124,
        connection_string=f"sqlite://{temp_db_path}",
        device_jid="test@example.com"
    )
    
    # These should be actual objects, not coroutines
    assert hasattr(store1, 'get_local_registration_id')
    assert hasattr(store2, 'get_local_registration_id')
    assert hasattr(store2, 'device_jid')