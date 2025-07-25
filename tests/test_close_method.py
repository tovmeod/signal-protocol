"""Test the close() method functionality."""

import pytest
import tempfile
from signal_protocol.identity_key import IdentityKeyPair
from signal_protocol.storage import InMemSignalProtocolStore


def test_close_method_basic_store():
    """Test that close() method works on basic store (no persistence)."""
    key_pair = IdentityKeyPair.generate()
    store = InMemSignalProtocolStore(key_pair, 123)
    
    # Should not raise any errors
    store.close()
    
    # Should be able to call close multiple times
    store.close()


def test_close_method_persistent_store(temp_db_path):
    """Test that close() method works on persistent store."""
    key_pair = IdentityKeyPair.generate()
    store = InMemSignalProtocolStore(
        key_pair, 
        123, 
        connection_string=f"sqlite://{temp_db_path}",
        device_jid="test@example.com"
    )
    
    # Use the store for some operations first
    reg_id = store.get_local_registration_id()
    assert reg_id == 123
    
    # Should not raise any errors
    store.close()
    
    # Should be able to call close multiple times
    store.close()


def test_close_method_context_manager_pattern(temp_db_path):
    """Test that close() method works in context manager pattern."""
    key_pair = IdentityKeyPair.generate()
    
    store = InMemSignalProtocolStore(
        key_pair, 
        456, 
        connection_string=f"sqlite://{temp_db_path}",
        device_jid="context@example.com"
    )
    
    try:
        # Use the store
        reg_id = store.get_local_registration_id()
        assert reg_id == 456
        
        # Verify it has required attributes
        assert hasattr(store, 'close')
        assert callable(getattr(store, 'close'))
        
    finally:
        # Ensure cleanup
        store.close()


def test_close_method_exists():
    """Test that close() method exists and is callable."""
    key_pair = IdentityKeyPair.generate()
    store = InMemSignalProtocolStore(key_pair, 789)
    
    # Verify the method exists
    assert hasattr(store, 'close')
    assert callable(getattr(store, 'close'))
    
    # Call it
    store.close()