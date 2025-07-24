"""Test the JID-optional store creation and update functionality for pairing scenarios."""

import pytest
import sqlite3
from signal_protocol.identity_key import IdentityKeyPair
from signal_protocol.storage import InMemSignalProtocolStore
from signal_protocol.address import ProtocolAddress
from signal_protocol.state import SessionRecord


async def test_create_store_without_jid(temp_db_path):
    """Test creating a store with persistence but without JID."""
    key_pair = IdentityKeyPair.generate()
    
    # Create store without JID (as would happen during pairing)
    store = InMemSignalProtocolStore(
        key_pair,
        123,
        connection_string=f"sqlite://{temp_db_path}"
        # No device_jid provided
    )
    
    # Should be able to use basic functionality
    address = ProtocolAddress("test_user", 1)
    session_record = SessionRecord.new_fresh()
    
    # Store session should work
    store.store_session(address, session_record)
    
    # Load session should work
    loaded_session = store.load_session(address)
    assert loaded_session is not None, "Should be able to store and load sessions"
    
    # Check that device was created in database without JID
    conn = sqlite3.connect(temp_db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT device_id, jid, registration_id FROM devices")
    devices = cursor.fetchall()
    conn.close()
    
    assert len(devices) == 1, "Should have created one device"
    device_id, jid, reg_id = devices[0]
    assert device_id > 0, "Should have valid device_id"
    assert jid is None, "JID should be NULL initially"
    assert reg_id == 123, "Registration ID should match"


async def test_update_jid_after_pairing(temp_db_path):
    """Test updating JID after pairing completes."""
    key_pair = IdentityKeyPair.generate()
    
    # Create store without JID
    store = InMemSignalProtocolStore(
        key_pair,
        123,
        connection_string=f"sqlite://{temp_db_path}"
    )
    
    # Update JID after "pairing" completes
    await store.update_jid("alice@example.com")
    
    # Check that JID was updated in database
    conn = sqlite3.connect(temp_db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT device_id, jid, registration_id FROM devices")
    devices = cursor.fetchall()
    conn.close()
    
    assert len(devices) == 1, "Should have one device"
    device_id, jid, reg_id = devices[0]
    assert device_id > 0, "Should have valid device_id"
    assert jid == "alice@example.com", "JID should be updated"
    assert reg_id == 123, "Registration ID should remain unchanged"


async def test_update_jid_multiple_times(temp_db_path):
    """Test that JID can be updated multiple times."""
    key_pair = IdentityKeyPair.generate()
    
    # Create store without JID
    store = InMemSignalProtocolStore(
        key_pair,
        123,
        connection_string=f"sqlite://{temp_db_path}"
    )
    
    # Update JID first time
    await store.update_jid("alice@example.com")
    
    # Update JID second time (re-pairing scenario)
    await store.update_jid("alice@different.com")
    
    # Check final state
    conn = sqlite3.connect(temp_db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT jid FROM devices")
    jids = cursor.fetchall()
    conn.close()
    
    assert len(jids) == 1, "Should have one device"
    assert jids[0][0] == "alice@different.com", "Should have latest JID"


async def test_update_jid_without_persistence():
    """Test that update_jid raises error without persistence."""
    key_pair = IdentityKeyPair.generate()
    
    # Create store without persistence
    store = InMemSignalProtocolStore(key_pair, 123)
    
    # Should raise RuntimeError since persistence is not enabled
    with pytest.raises(RuntimeError, match="JID update only available when persistence is enabled"):
        await store.update_jid("alice@example.com")


async def test_pairing_workflow_simulation(temp_db_path):
    """Test simulating a complete pairing workflow."""
    key_pair = IdentityKeyPair.generate()
    
    # Step 1: Create store during pairing (no JID yet)
    store = InMemSignalProtocolStore(
        key_pair,
        123,
        connection_string=f"sqlite://{temp_db_path}"
    )
    
    # Step 2: Do some basic operations during pairing
    # (e.g., storing temporary session data)
    temp_address = ProtocolAddress("pairing_server", 1)
    temp_session = SessionRecord.new_fresh()
    store.store_session(temp_address, temp_session)
    
    # Verify session was stored
    loaded_temp = store.load_session(temp_address)
    assert loaded_temp is not None, "Temporary session should be stored"
    
    # Step 3: Pairing succeeds, now we have the JID
    await store.update_jid("alice@example.com")
    
    # Step 4: Continue normal operations with persistent data
    user_address = ProtocolAddress("bob@example.com", 1)
    user_session = SessionRecord.new_fresh()
    store.store_session(user_address, user_session)
    
    # Verify both sessions exist
    loaded_temp_after = store.load_session(temp_address)
    loaded_user = store.load_session(user_address)
    
    assert loaded_temp_after is not None, "Temporary session should still exist"
    assert loaded_user is not None, "User session should exist"
    
    # Verify database state
    conn = sqlite3.connect(temp_db_path)
    cursor = conn.cursor()
    
    # Check device record
    cursor.execute("SELECT device_id, jid FROM devices")
    device = cursor.fetchone()
    assert device is not None, "Device should exist"
    assert device[1] == "alice@example.com", "JID should be set"
    
    # Check sessions exist
    device_id = device[0]
    cursor.execute("SELECT COUNT(*) FROM signal_sessions WHERE device_id = ?", (device_id,))
    session_count = cursor.fetchone()[0]
    
    conn.close()
    
    assert session_count == 2, "Should have both sessions in database"


async def test_store_with_jid_still_works(temp_db_path):
    """Test that the traditional way of creating stores with JID still works."""
    key_pair = IdentityKeyPair.generate()
    
    # Create store the traditional way (with JID)
    store = InMemSignalProtocolStore(
        key_pair,
        123,
        connection_string=f"sqlite://{temp_db_path}",
        device_jid="alice@example.com"
    )
    
    # Should work normally
    address = ProtocolAddress("test_user", 1)
    session_record = SessionRecord.new_fresh()
    
    store.store_session(address, session_record)
    loaded_session = store.load_session(address)
    assert loaded_session is not None, "Traditional store creation should still work"
    
    # Check database state
    conn = sqlite3.connect(temp_db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT jid FROM devices")
    jids = cursor.fetchall()
    conn.close()
    
    assert len(jids) == 1, "Should have one device"
    assert jids[0][0] == "alice@example.com", "JID should be set immediately"