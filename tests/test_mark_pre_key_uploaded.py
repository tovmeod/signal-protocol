"""Test the mark_pre_key_uploaded functionality."""

import pytest
import tempfile
import sqlite3
from signal_protocol.identity_key import IdentityKeyPair
from signal_protocol.storage import InMemSignalProtocolStore
from signal_protocol.curve import KeyPair
from signal_protocol.state import PreKeyRecord


async def test_mark_pre_key_uploaded_with_persistence(temp_db_path):
    """Test mark_pre_key_uploaded with persistent store."""
    key_pair = IdentityKeyPair.generate()
    store = InMemSignalProtocolStore(
        key_pair,
        123,
        connection_string=f"sqlite://{temp_db_path}",
        device_jid="test@example.com"
    )
    
    # Create and save a pre-key
    pre_key_pair = KeyPair.generate()
    pre_key_record = PreKeyRecord(456, pre_key_pair)
    store.save_pre_key(456, pre_key_record)
    
    # Mark it as uploaded
    was_found = await store.mark_pre_key_uploaded(456)
    assert was_found is True, "Pre-key should be found and marked as uploaded"
    
    # Verify in the database directly
    conn = sqlite3.connect(temp_db_path)
    cursor = conn.cursor()
    # First get the device_id for the JID
    cursor.execute("SELECT device_id FROM devices WHERE jid = ?", ("test@example.com",))
    device_id_result = cursor.fetchone()
    assert device_id_result is not None, "Device should exist in database"
    device_id = device_id_result[0]
    
    # Then check the pre-key using device_id
    cursor.execute(
        "SELECT uploaded FROM signal_pre_keys WHERE device_id = ? AND key_id = ?",
        (device_id, 456)
    )
    result = cursor.fetchone()
    conn.close()
    
    assert result is not None, "Pre-key should exist in database"
    assert result[0] == 1, "Pre-key should be marked as uploaded (TRUE/1)"


async def test_mark_pre_key_uploaded_nonexistent_key(temp_db_path):
    """Test mark_pre_key_uploaded with non-existent pre-key."""
    key_pair = IdentityKeyPair.generate()
    store = InMemSignalProtocolStore(
        key_pair,
        123,
        connection_string=f"sqlite://{temp_db_path}",
        device_jid="test@example.com"
    )
    
    # Try to mark a non-existent pre-key as uploaded
    was_found = await store.mark_pre_key_uploaded(999)
    assert was_found is False, "Non-existent pre-key should return False"


async def test_mark_pre_key_uploaded_without_persistence():
    """Test that mark_pre_key_uploaded raises error without persistence."""
    key_pair = IdentityKeyPair.generate()
    store = InMemSignalProtocolStore(key_pair, 123)
    
    # Should raise RuntimeError since persistence is not enabled
    with pytest.raises(RuntimeError, match="Pre-key upload marking only available when persistence is enabled"):
        await store.mark_pre_key_uploaded(456)


async def test_mark_pre_key_uploaded_multiple_calls(temp_db_path):
    """Test calling mark_pre_key_uploaded multiple times."""
    key_pair = IdentityKeyPair.generate()
    store = InMemSignalProtocolStore(
        key_pair,
        123,
        connection_string=f"sqlite://{temp_db_path}",
        device_jid="test@example.com"
    )
    
    # Create and save a pre-key
    pre_key_pair = KeyPair.generate()
    pre_key_record = PreKeyRecord(789, pre_key_pair)
    store.save_pre_key(789, pre_key_record)
    
    # Mark it as uploaded multiple times
    was_found1 = await store.mark_pre_key_uploaded(789)
    was_found2 = await store.mark_pre_key_uploaded(789)
    was_found3 = await store.mark_pre_key_uploaded(789)
    
    assert was_found1 is True, "First call should find and mark the pre-key"
    assert was_found2 is True, "Second call should still find the pre-key"
    assert was_found3 is True, "Third call should still find the pre-key"
    
    # Verify it's still marked as uploaded
    conn = sqlite3.connect(temp_db_path)
    cursor = conn.cursor()
    # First get the device_id for the JID
    cursor.execute("SELECT device_id FROM devices WHERE jid = ?", ("test@example.com",))
    device_id = cursor.fetchone()[0]
    
    cursor.execute(
        "SELECT uploaded FROM signal_pre_keys WHERE device_id = ? AND key_id = ?",
        (device_id, 789)
    )
    result = cursor.fetchone()
    conn.close()
    
    assert result is not None, "Pre-key should exist in database"
    assert result[0] == 1, "Pre-key should still be marked as uploaded"


async def test_mark_pre_key_uploaded_workflow(temp_db_path):
    """Test a complete workflow: save, verify not uploaded, mark uploaded, verify uploaded."""
    key_pair = IdentityKeyPair.generate()
    store = InMemSignalProtocolStore(
        key_pair,
        123,
        connection_string=f"sqlite://{temp_db_path}",
        device_jid="workflow@example.com"
    )
    
    # Create and save a pre-key
    pre_key_pair = KeyPair.generate()
    pre_key_record = PreKeyRecord(100, pre_key_pair)
    store.save_pre_key(100, pre_key_record)
    
    # Verify it starts as not uploaded (FALSE/0)
    conn = sqlite3.connect(temp_db_path)
    cursor = conn.cursor()
    # First get the device_id for the JID
    cursor.execute("SELECT device_id FROM devices WHERE jid = ?", ("workflow@example.com",))
    device_id = cursor.fetchone()[0]
    
    cursor.execute(
        "SELECT uploaded FROM signal_pre_keys WHERE device_id = ? AND key_id = ?",
        (device_id, 100)
    )
    result = cursor.fetchone()
    assert result is not None, "Pre-key should exist in database"
    assert result[0] == 0, "Pre-key should start as not uploaded (FALSE/0)"
    
    # Mark it as uploaded
    was_found = await store.mark_pre_key_uploaded(100)
    assert was_found is True, "Pre-key should be found and marked as uploaded"
    
    # Verify it's now uploaded (TRUE/1)
    cursor.execute(
        "SELECT uploaded FROM signal_pre_keys WHERE device_id = ? AND key_id = ?",
        (device_id, 100)
    )
    result = cursor.fetchone()
    conn.close()
    
    assert result is not None, "Pre-key should still exist in database"
    assert result[0] == 1, "Pre-key should now be marked as uploaded (TRUE/1)"


async def test_mark_pre_key_uploaded_multiple_keys_same_device(temp_db_path):
    """Test mark_pre_key_uploaded API behavior with multiple pre-keys for the same device."""
    key_pair = IdentityKeyPair.generate()
    store = InMemSignalProtocolStore(
        key_pair,
        123,
        connection_string=f"sqlite://{temp_db_path}",
        device_jid="alice@example.com"
    )
    
    # Create multiple pre-keys for the same device (common scenario)
    pre_key_ids = [100, 101, 102, 103, 104]
    
    for pre_key_id in pre_key_ids:
        pre_key_pair = KeyPair.generate()
        pre_key_record = PreKeyRecord(pre_key_id, pre_key_pair)
        store.save_pre_key(pre_key_id, pre_key_record)
    
    # Verify all pre-keys exist in database
    conn = sqlite3.connect(temp_db_path)
    cursor = conn.cursor()
    # First get the device_id for the JID
    cursor.execute("SELECT device_id FROM devices WHERE jid = ?", ("alice@example.com",))
    device_id = cursor.fetchone()[0]
    
    cursor.execute(
        "SELECT key_id FROM signal_pre_keys WHERE device_id = ? ORDER BY key_id",
        (device_id,)
    )
    existing_keys = [row[0] for row in cursor.fetchall()]
    conn.close()
    
    assert existing_keys == pre_key_ids, "All pre-keys should exist in database"
    
    # Test marking existing pre-keys as uploaded (should all return True)
    for key_id in pre_key_ids:
        was_found = await store.mark_pre_key_uploaded(key_id)
        assert was_found is True, f"Pre-key {key_id} should be found and marked as uploaded"
    
    # Test marking the same keys again (idempotent behavior)
    for key_id in pre_key_ids:
        was_found = await store.mark_pre_key_uploaded(key_id)
        assert was_found is True, f"Pre-key {key_id} should still be found (idempotent behavior)"
    
    # Test marking non-existent pre-keys (should return False)
    non_existent_keys = [999, 1000, 1001]
    for key_id in non_existent_keys:
        was_found = await store.mark_pre_key_uploaded(key_id)
        assert was_found is False, f"Non-existent pre-key {key_id} should return False"
    
    # Test mixed scenario: some existing, some non-existent
    mixed_keys = [102, 999, 104, 1001, 100]  # Mix of existing and non-existent
    expected_results = [True, False, True, False, True]  # Expected results
    
    for key_id, expected in zip(mixed_keys, expected_results):
        was_found = await store.mark_pre_key_uploaded(key_id)
        assert was_found == expected, f"Pre-key {key_id} should return {expected}"
    
    # Verify all our original pre-keys still exist after mixed operations
    conn = sqlite3.connect(temp_db_path)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT key_id FROM signal_pre_keys WHERE device_id = ? ORDER BY key_id",
        (device_id,)
    )
    final_keys = [row[0] for row in cursor.fetchall()]
    conn.close()
    
    assert final_keys == pre_key_ids, "Original pre-keys should still exist after operations"


async def test_mark_pre_key_uploaded_concurrent_operations(temp_db_path):
    """Test mark_pre_key_uploaded with concurrent async operations."""
    import asyncio
    
    key_pair = IdentityKeyPair.generate()
    store = InMemSignalProtocolStore(
        key_pair,
        123,
        connection_string=f"sqlite://{temp_db_path}",
        device_jid="concurrent@example.com"
    )
    
    # Create multiple pre-keys
    pre_key_ids = [200, 201, 202, 203, 204, 205, 206, 207, 208, 209]
    
    for pre_key_id in pre_key_ids:
        pre_key_pair = KeyPair.generate()
        pre_key_record = PreKeyRecord(pre_key_id, pre_key_pair)
        store.save_pre_key(pre_key_id, pre_key_record)
    
    # Test concurrent marking using asyncio.gather
    results = await asyncio.gather(*[
        store.mark_pre_key_uploaded(key_id) 
        for key_id in pre_key_ids
    ])
    
    # All should return True (found and marked)
    assert all(results), "All pre-keys should be found and marked as uploaded"
    assert len(results) == len(pre_key_ids), "Should get result for each pre-key"
    
    # Test concurrent marking of mixed existing/non-existent keys
    mixed_keys = pre_key_ids + [999, 1000, 1001]  # Mix existing with non-existent
    expected_mixed = [True] * len(pre_key_ids) + [False, False, False]
    
    mixed_results = await asyncio.gather(*[
        store.mark_pre_key_uploaded(key_id) 
        for key_id in mixed_keys
    ])
    
    assert mixed_results == expected_mixed, "Mixed concurrent operations should return correct results"
    
    # Test that we can handle errors gracefully in concurrent operations
    # (no errors expected here, but tests the pattern)
    try:
        concurrent_results = await asyncio.gather(*[
            store.mark_pre_key_uploaded(key_id) 
            for key_id in [200, 999, 202, 1001, 204]
        ], return_exceptions=True)
        
        # Should all be boolean results, no exceptions
        assert all(isinstance(result, bool) for result in concurrent_results), \
               "All concurrent results should be boolean values"
        assert concurrent_results == [True, False, True, False, True], \
               "Concurrent mixed operations should return expected pattern"
               
    except Exception as e:
        pytest.fail(f"Concurrent operations should not raise exceptions: {e}")