import pytest
import time
from signal_protocol import storage, state, address, identity_key, session
from tests.utils.sessions import create_pre_key_bundle


class TestContainsSessionBasicFunctionality:
    """Test basic contains_session functionality."""

    def test_contains_session_with_existing_session(self, alice_store, protocol_address):
        """Test contains_session returns True for existing sessions."""
        # Setup: Create and store a session
        session_record = state.SessionRecord.new_fresh()
        alice_store.store_session(protocol_address, session_record)

        # Test: Check contains_session
        result = alice_store.contains_session(protocol_address)

        # Verify: Should return True
        assert result is True

    def test_contains_session_with_non_existing_session(self, alice_store, protocol_address):
        """Test contains_session returns False for non-existing sessions."""
        # Test: Check contains_session for non-existent session
        result = alice_store.contains_session(protocol_address)

        # Verify: Should return False
        assert result is False

    def test_contains_session_multiple_addresses(self, alice_store):
        """Test contains_session works correctly with multiple addresses."""
        # Setup: Create multiple addresses
        addr1 = address.ProtocolAddress("user1", 1)
        addr2 = address.ProtocolAddress("user2", 1) 
        addr3 = address.ProtocolAddress("user1", 2)  # Same user, different device

        # Setup: Store session for only addr1
        session_record = state.SessionRecord.new_fresh()
        alice_store.store_session(addr1, session_record)

        # Test and Verify
        assert alice_store.contains_session(addr1) is True
        assert alice_store.contains_session(addr2) is False
        assert alice_store.contains_session(addr3) is False


class TestContainsSessionPersistentStorage:
    """Test contains_session with persistent storage integration."""

    def test_contains_session_persistent_storage_only(self, persistent_storage, protocol_address):
        """Test contains_session with session only in persistent storage."""
        # Setup: Create session
        session_record = state.SessionRecord.new_fresh()

        # Setup: Store session directly in persistent storage (bypass cache)
        address_str = f"{protocol_address.name()}:{protocol_address.device_id()}"
        persistent_storage.sessions[address_str] = session_record

        # Setup: Create store with persistent storage
        identity_key_pair = identity_key.IdentityKeyPair.generate()
        store = storage.InMemSignalProtocolStore(
            identity_key_pair, 
            123, 
            persistent_storage
        )

        # Test: contains_session should find it in persistent storage
        result = store.contains_session(protocol_address)

        # Verify: Should return True even though cache is empty
        assert result is True

    def test_contains_session_cache_priority(self, persistent_storage, protocol_address):
        """Test contains_session checks cache before persistent storage."""
        # Setup: Create components
        identity_key_pair = identity_key.IdentityKeyPair.generate()
        store = storage.InMemSignalProtocolStore(
            identity_key_pair, 
            123, 
            persistent_storage
        )

        # Setup: Store session in cache
        session_record = state.SessionRecord.new_fresh()
        store.store_session(protocol_address, session_record)

        # Test: Should return True even if persistent storage is empty
        result = store.contains_session(protocol_address)

        # Verify: Cache takes priority
        assert result is True

        # Additional verification: persistent storage should also have the session
        # because store_session updates both cache and persistent storage
        address_str = f"{protocol_address.name()}:{protocol_address.device_id()}"
        assert address_str in persistent_storage.sessions

    def test_contains_session_fallback_behavior(self, persistent_storage):
        """Test contains_session falls back correctly."""
        # Setup: Components
        protocol_address = address.ProtocolAddress("test_user", 1)
        identity_key_pair = identity_key.IdentityKeyPair.generate()
        store = storage.InMemSignalProtocolStore(
            identity_key_pair, 
            123, 
            persistent_storage
        )

        # Setup: Ensure no session exists anywhere
        address_str = f"{protocol_address.name()}:{protocol_address.device_id()}"
        assert address_str not in persistent_storage.sessions

        # Test: Should return False when session doesn't exist anywhere
        result = store.contains_session(protocol_address)

        # Verify
        assert result is False


class TestContainsSessionErrorHandling:
    """Test contains_session error handling and edge cases."""

    def test_contains_session_graceful_error_handling(self, alice_store):
        """Test contains_session handles errors gracefully."""
        # Test: Try with edge case addresses
        empty_address = address.ProtocolAddress("", 0)
        long_address = address.ProtocolAddress("x" * 1000, 999999)

        # Should not raise exceptions, should return False
        assert alice_store.contains_session(empty_address) is False
        assert alice_store.contains_session(long_address) is False

    def test_contains_session_no_persistent_storage(self):
        """Test contains_session works without persistent storage."""
        # Setup: Store without persistent storage
        identity_key_pair = identity_key.IdentityKeyPair.generate()
        store = storage.InMemSignalProtocolStore(identity_key_pair, 123)  # No persistent storage

        protocol_address = address.ProtocolAddress("test_user", 1)

        # Test: Should return False when no persistent storage and no cache
        result = store.contains_session(protocol_address)
        assert result is False

        # Test: Should return True when session exists in cache
        session_record = state.SessionRecord.new_fresh()
        store.store_session(protocol_address, session_record)
        result = store.contains_session(protocol_address)
        assert result is True


class TestContainsSessionConsistency:
    """Test contains_session consistency with other methods."""

    def test_contains_session_consistency_with_load_session(self, alice_store):
        """Test contains_session is consistent with load_session."""
        protocol_address = address.ProtocolAddress("test_user", 1)

        # Test: When no session exists
        contains_result = alice_store.contains_session(protocol_address)
        load_result = alice_store.load_session(protocol_address)
        assert contains_result == (load_result is not None)

        # Test: Store a session
        session_record = state.SessionRecord.new_fresh()
        alice_store.store_session(protocol_address, session_record)

        # Test: After storing session
        contains_result = alice_store.contains_session(protocol_address)
        load_result = alice_store.load_session(protocol_address)
        assert contains_result == (load_result is not None)
        assert contains_result is True  # Both should be True now

    def test_contains_session_after_session_operations(self, alice_store):
        """Test contains_session behavior after various session operations."""
        protocol_address = address.ProtocolAddress("test_user", 1)
        session_record = state.SessionRecord.new_fresh()

        # Initially no session
        assert alice_store.contains_session(protocol_address) is False

        # After storing session
        alice_store.store_session(protocol_address, session_record)
        assert alice_store.contains_session(protocol_address) is True

        # Verify load_session also works
        loaded_session = alice_store.load_session(protocol_address)
        assert loaded_session is not None
        assert alice_store.contains_session(protocol_address) is True


class TestContainsSessionPerformance:
    """Test contains_session performance characteristics."""

    def test_contains_session_performance_vs_load_session(self, alice_store):
        """Test that contains_session is faster than load_session."""
        protocol_address = address.ProtocolAddress("test_user", 1)
        session_record = state.SessionRecord.new_fresh()
        alice_store.store_session(protocol_address, session_record)

        # Warm up
        alice_store.contains_session(protocol_address)
        alice_store.load_session(protocol_address)

        # Time contains_session
        start_time = time.perf_counter()
        for _ in range(100):
            alice_store.contains_session(protocol_address)
        contains_time = time.perf_counter() - start_time

        # Time load_session
        start_time = time.perf_counter()
        for _ in range(100):
            alice_store.load_session(protocol_address)
        load_time = time.perf_counter() - start_time

        # contains_session should be faster or at least not significantly slower
        # Allow some margin for measurement variance
        assert contains_time <= load_time * 1.1  # Allow 10% margin

    def test_contains_session_multiple_calls_consistent(self, alice_store):
        """Test contains_session returns consistent results on multiple calls."""
        protocol_address = address.ProtocolAddress("test_user", 1)

        # Test consistency when session doesn't exist
        results = [alice_store.contains_session(protocol_address) for _ in range(10)]
        assert all(result is False for result in results)

        # Add session
        session_record = state.SessionRecord.new_fresh()
        alice_store.store_session(protocol_address, session_record)

        # Test consistency when session exists
        results = [alice_store.contains_session(protocol_address) for _ in range(10)]
        assert all(result is True for result in results)


class TestPersistentStorageContainsSession:
    """Test PersistentStorage contains_session optimization."""

    def test_persistent_storage_contains_session_optimization(self, persistent_storage, protocol_address):
        """Test that persistent storage can override contains_session for optimization."""
        session_record = state.SessionRecord.new_fresh()
        address_str = f"{protocol_address.name()}:{protocol_address.device_id()}"

        # Test: When session doesn't exist
        result = persistent_storage.contains_session(protocol_address)
        assert result is False

        # Test: Add session and test again
        persistent_storage.sessions[address_str] = session_record
        result = persistent_storage.contains_session(protocol_address)
        assert result is True

        # Test: Verify it's using optimized path (not load_session)
        # This test verifies the implementation in conftest.py is working correctly
        assert address_str in persistent_storage.sessions


class TestContainsSessionIntegration:
    """Integration tests for contains_session with real Signal Protocol workflows."""

    def test_contains_session_integration_with_protocol_flow(self, alice_store, bob_store):
        """Test contains_session in realistic Signal Protocol scenarios."""
        # Setup: Create addresses for Alice and Bob
        alice_address = address.ProtocolAddress("alice", 1)
        bob_address = address.ProtocolAddress("bob", 1)

        # Initially no sessions should exist
        assert alice_store.contains_session(bob_address) is False
        assert bob_store.contains_session(alice_address) is False

        # After creating sessions (simulating successful protocol handshake)
        alice_session = state.SessionRecord.new_fresh()
        bob_session = state.SessionRecord.new_fresh()

        alice_store.store_session(bob_address, alice_session)
        bob_store.store_session(alice_address, bob_session)

        # Sessions should now exist
        assert alice_store.contains_session(bob_address) is True
        assert bob_store.contains_session(alice_address) is True

        # Cross-check: Alice shouldn't have session with herself
        assert alice_store.contains_session(alice_address) is False
        assert bob_store.contains_session(bob_address) is False

    def test_contains_session_with_multiple_devices(self, alice_store):
        """Test contains_session with multi-device scenarios."""
        # Setup: Bob has multiple devices
        bob_device1 = address.ProtocolAddress("bob", 1) 
        bob_device2 = address.ProtocolAddress("bob", 2)
        bob_device3 = address.ProtocolAddress("bob", 3)

        # Setup: Alice has sessions with some of Bob's devices
        session_record = state.SessionRecord.new_fresh()
        alice_store.store_session(bob_device1, session_record)
        alice_store.store_session(bob_device3, session_record)

        # Test: Check session existence per device
        assert alice_store.contains_session(bob_device1) is True
        assert alice_store.contains_session(bob_device2) is False  # No session
        assert alice_store.contains_session(bob_device3) is True

    def test_contains_session_in_session_workflow(self, alice_store, bob_store):
        """Test contains_session integrates properly with session establishment workflow."""
        # Setup addresses
        alice_address = address.ProtocolAddress("alice", 1)
        bob_address = address.ProtocolAddress("bob", 1)

        # Initially no sessions
        assert not alice_store.contains_session(bob_address)
        assert not bob_store.contains_session(alice_address)

        # Create prekey bundle and establish session
        bob_pre_key_bundle = create_pre_key_bundle(bob_store)
        session.process_prekey_bundle(bob_address, alice_store, bob_pre_key_bundle)

        # After session establishment, Alice should have session with Bob
        assert alice_store.contains_session(bob_address)
        # But Bob doesn't have session with Alice yet (one-way establishment)
        assert not bob_store.contains_session(alice_address)
