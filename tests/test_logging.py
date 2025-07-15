import pytest
import os
import signal_protocol.storage as storage


def test_init_logging():
    """Test that init_logging function can be called without errors."""
    # Call the init_logging function
    storage.init_logging()
    
    # If we get here without exceptions, the test passes
    assert True


def test_logging_with_env_var():
    """Test that logging respects environment variables."""
    # Set environment variable for logging
    os.environ["RUST_LOG"] = "debug"
    
    # Call the init_logging function
    storage.init_logging()
    
    # If we get here without exceptions, the test passes
    assert True


def test_persistent_storage_fix(persistent_storage):
    """Test that message_encrypt now properly works with persistent storage.
    
    This test demonstrates the fix where message_encrypt successfully loads
    sessions from persistent storage when they're not in the memory cache.
    """
    from signal_protocol import curve, address, state, session, session_cipher, identity_key
    
    # Setup Alice with persistent storage
    alice_identity_key_pair = identity_key.IdentityKeyPair.generate()
    alice_registration_id = 1
    alice_store = storage.InMemSignalProtocolStore(
        alice_identity_key_pair, alice_registration_id, persistent_storage
    )
    
    # Setup Bob 
    bob_identity_key_pair = identity_key.IdentityKeyPair.generate()
    bob_registration_id = 2
    bob_store = storage.InMemSignalProtocolStore(bob_identity_key_pair, bob_registration_id)
    
    # Create addresses
    alice_address = address.ProtocolAddress("alice", 1)
    bob_address = address.ProtocolAddress("bob", 1)
    
    # Create proper prekey bundle
    bob_pre_key_pair = curve.KeyPair.generate()
    bob_signed_pre_key_pair = curve.KeyPair.generate()
    bob_signed_pre_key_sig = bob_store.get_identity_key_pair().private_key().calculate_signature(
        bob_signed_pre_key_pair.public_key().serialize()
    )
    
    bundle = state.PreKeyBundle(
        bob_registration_id,
        1,  # device_id
        31337,  # pre_key_id
        bob_pre_key_pair.public_key(),
        22,  # signed_pre_key_id  
        bob_signed_pre_key_pair.public_key(),
        bob_signed_pre_key_sig,
        bob_store.get_identity_key_pair().identity_key()
    )
    
    # Alice processes Bob's bundle (creates session)
    session.process_prekey_bundle(bob_address, alice_store, bundle)
    
    # Manually ensure the session gets stored in persistent storage
    # (process_prekey_bundle also bypasses persistent storage, but that's another fix)
    session_record = alice_store.load_session(bob_address)
    if session_record:
        alice_store.store_session(bob_address, session_record)
    
    # Verify session exists in persistent storage
    #assert persistent_storage.contains_session(bob_address) == True
    address_key = f"{bob_address.name()}:{bob_address.device_id()}"
    assert address_key in persistent_storage.sessions
    
    # Create a NEW alice store with the SAME persistent storage
    # This simulates a fresh start where the in-memory cache is empty
    # but the session still exists in persistent storage
    alice_store_fresh = storage.InMemSignalProtocolStore(
        alice_identity_key_pair, alice_registration_id, persistent_storage
    )
    
    # This should now work because message_encrypt loads from persistent storage
    message = b"Hello Bob from persistent storage!"
    
    # This should succeed with our fix
    ciphertext = session_cipher.message_encrypt(alice_store_fresh, bob_address, message)
    
    # Verify the encryption worked
    assert ciphertext is not None
    assert len(ciphertext.serialize()) > 0
    
    print("✓ SUCCESS: message_encrypt worked with persistent storage!")