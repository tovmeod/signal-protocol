"""Test proper cleanup sequence for SQLite file release."""

import pytest
import tempfile
import os
import time
from signal_protocol.identity_key import IdentityKeyPair
from signal_protocol.storage import InMemSignalProtocolStore, shutdown_runtime


def test_cleanup_sequence_basic_store():
    """Test cleanup sequence for basic store (no persistence)."""
    key_pair = IdentityKeyPair.generate()
    store = InMemSignalProtocolStore(key_pair, 123)
    
    # Use the store
    reg_id = store.get_local_registration_id()
    assert reg_id == 123
    
    # Cleanup should work without issues
    store.close()
    shutdown_runtime()


@pytest.mark.asyncio
async def test_cleanup_sequence_with_sqlite_file_deletion():
    """Test that proper cleanup allows SQLite file deletion."""
    # Create a temporary SQLite file
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as temp_db:
        db_path = temp_db.name
    
    try:
        # Create store with persistence
        key_pair = IdentityKeyPair.generate()
        store = InMemSignalProtocolStore(
            key_pair, 
            123, 
            connection_string=f"sqlite://{db_path}",
            device_jid="test@example.com"
        )
        
        # Run migrations to create tables
        await store.migrate()
        
        # Use the store for some operations
        reg_id = store.get_local_registration_id()
        assert reg_id == 123
        
        # Proper cleanup sequence
        # Step 1: Close the store first
        store.close()
        
        # Step 2: Shutdown the global runtime
        shutdown_runtime()
        
        # Step 3: Small delay for file system
        time.sleep(0.2)
        
        # Step 4: Try to delete the file - this should succeed
        os.unlink(db_path)
        
        # If we get here, the file was successfully deleted
        assert True, "File deletion succeeded"
        
    except OSError as e:
        pytest.fail(f"Failed to delete SQLite file after proper cleanup: {e}")


@pytest.mark.asyncio
async def test_cleanup_prevents_file_locking_issues():
    """Test that WAL checkpoint and runtime shutdown prevent file locking."""
    # Create a temporary SQLite file
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as temp_db:
        db_path = temp_db.name
    
    try:
        # Create store with persistence
        key_pair = IdentityKeyPair.generate()
        store = InMemSignalProtocolStore(
            key_pair, 
            456, 
            connection_string=f"sqlite://{db_path}",
            device_jid="cleanup_test@example.com"
        )
        
        # Run migrations and do some operations that create WAL files
        await store.migrate()
        
        # Perform operations that might create WAL/SHM files
        reg_id = store.get_local_registration_id()
        assert reg_id == 456
        
        # The cleanup sequence should handle WAL files properly
        store.close()  # This should trigger WAL checkpoint
        shutdown_runtime()  # This should stop background threads
        
        # Small delay to allow file handles to be released
        time.sleep(0.1)
        
        # Check if WAL/SHM files exist and can be cleaned up
        wal_file = f"{db_path}-wal"
        shm_file = f"{db_path}-shm"
        
        # Try to delete auxiliary files if they exist
        for aux_file in [wal_file, shm_file]:
            if os.path.exists(aux_file):
                os.unlink(aux_file)  # Should not raise OSError
        
        # Delete main database file
        os.unlink(db_path)
        
        assert True, "All SQLite files deleted successfully"
        
    except OSError as e:
        pytest.fail(f"Failed to clean up SQLite files: {e}")


def test_shutdown_runtime_is_safe_to_call_multiple_times():
    """Test that shutdown_runtime() can be called multiple times without issues."""
    # Should not raise any exceptions
    shutdown_runtime()
    shutdown_runtime()
    shutdown_runtime()
    
    assert True, "Multiple shutdown_runtime() calls succeeded"


def test_store_operations_after_cleanup():
    """Test behavior when trying to use stores after runtime shutdown."""
    # Create a basic store
    key_pair = IdentityKeyPair.generate()
    store = InMemSignalProtocolStore(key_pair, 789)
    
    # Use it normally
    reg_id = store.get_local_registration_id()
    assert reg_id == 789
    
    # Clean shutdown
    store.close()
    shutdown_runtime()
    
    # Creating new stores might work (creates new runtime)
    # but we shouldn't rely on this behavior
    key_pair2 = IdentityKeyPair.generate()
    store2 = InMemSignalProtocolStore(key_pair2, 999)
    reg_id2 = store2.get_local_registration_id()
    assert reg_id2 == 999
    
    # Clean up the second store too
    store2.close()