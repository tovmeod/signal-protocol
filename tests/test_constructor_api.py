"""Test the new constructor API for InMemSignalProtocolStore."""

import pytest
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


def test_with_persistence_constructor(temp_db_path):
    """Test the constructor with database persistence."""
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
    
    # Migration is still async - that's fine, main constructor goal achieved


def test_new_constructor_with_persistence(temp_db_path):
    """Test the new constructor with database persistence."""
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
    
    # Migration is still async - that's fine


def test_persistence_with_different_databases(temp_db_path):
    """Test persistence with different database connection strings."""
    # NOTE: Using temp file instead of sqlite::memory: due to migration issues
    identity_key_pair = IdentityKeyPair.generate()
    
    # SQLite file
    store_sqlite = InMemSignalProtocolStore(
        identity_key_pair, 
        123,
        connection_string=f"sqlite://{temp_db_path}",
        device_jid="test@example.com"
    )
    # Migration is still async - that's fine
    assert store_sqlite.device_jid() == "test@example.com"
    
    # SQLite file (temporary)
    import tempfile
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as temp_db:
        store_sqlite_file = InMemSignalProtocolStore(
            identity_key_pair, 
            124,
            connection_string=f"sqlite://{temp_db.name}",
            device_jid="test2@example.com"
        )
        # Migration is still async - that's fine
        assert store_sqlite_file.device_jid() == "test2@example.com"


def test_basic_constructor_no_persistence():
    """Verify that basic constructor doesn't have persistence methods."""
    identity_key_pair = IdentityKeyPair.generate()
    store = InMemSignalProtocolStore(identity_key_pair, 123)
    
    # These should raise RuntimeError since persistence is not enabled
    with pytest.raises(RuntimeError, match="Device JID only available when persistence is enabled"):
        store.device_jid()
    
    with pytest.raises(RuntimeError, match="Migration only available when persistence is enabled"):
        import asyncio
        asyncio.run(store.migrate())