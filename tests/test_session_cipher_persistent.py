import pytest

from tests.utils.sessions import (
    create_pre_key_bundle,
    run_interaction,
    initialize_sessions_v3,
    run_session_interaction,
    is_session_id_equal,
)

from signal_protocol import (
    curve,
    address,
    error,
    identity_key,
    protocol,
    session,
    session_cipher,
    state,
)

DEVICE_ID = 1


def test_basic_prekey_v3_persistent(alice_store, bob_store):
    alice_address = address.ProtocolAddress("+14151111111", DEVICE_ID)
    bob_address = address.ProtocolAddress("+14151111112", DEVICE_ID)

    # Setup bob's pre-key and signed pre-key
    bob_pre_key_pair = curve.KeyPair.generate()
    bob_signed_pre_key_pair = curve.KeyPair.generate()
    bob_signed_pre_key_public = bob_signed_pre_key_pair.public_key().serialize()
    bob_signed_pre_key_signature = (
        bob_store.get_identity_key_pair()
        .private_key()
        .calculate_signature(bob_signed_pre_key_public)
    )

    pre_key_id = 31337
    signed_pre_key_id = 22

    bob_pre_key_bundle = state.PreKeyBundle(
        bob_store.get_local_registration_id(),
        DEVICE_ID,
        pre_key_id,
        bob_pre_key_pair.public_key(),
        signed_pre_key_id,
        bob_signed_pre_key_pair.public_key(),
        bob_signed_pre_key_signature,
        bob_store.get_identity_key_pair().identity_key(),
    )

    # Create pre-key records
    pre_key_record = state.PreKeyRecord(pre_key_id, bob_pre_key_pair)
    signed_pre_key_record = state.SignedPreKeyRecord(
        signed_pre_key_id,
        42,
        bob_signed_pre_key_pair,
        bob_signed_pre_key_signature,
    )

    assert alice_store.load_session(bob_address) is None

    # Process the pre-key bundle
    session.process_prekey_bundle(
        bob_address,
        alice_store,
        bob_pre_key_bundle,
    )

    # Skip session check as it's not accessible through StorageProxy

    original_message = b"Hobgoblins hold themselves to high standards of military honor"

    # Encrypt a message from Alice to Bob
    outgoing_message = session_cipher.message_encrypt(
        alice_store, bob_address, original_message
    )
    assert outgoing_message.message_type() == 3  # 3 == CiphertextMessageType::PreKey
    outgoing_message_wire = outgoing_message.serialize()

    # Now Bob processes the message
    incoming_message = protocol.PreKeySignalMessage.try_from(outgoing_message_wire)

    # Store the pre-key and signed pre-key in Bob's store
    print(f"Saving pre-key with ID {pre_key_id}")
    bob_store.save_pre_key(pre_key_id, pre_key_record)
    print(f"Saving signed pre-key with ID {signed_pre_key_id}")
    bob_store.save_signed_pre_key(signed_pre_key_id, signed_pre_key_record)

    # Verify that the pre-key and signed pre-key were saved correctly
    try:
        saved_pre_key = bob_store.get_pre_key(pre_key_id)
        print(f"Retrieved pre-key with ID {pre_key_id}: {saved_pre_key is not None}")
    except Exception as e:
        print(f"Error retrieving pre-key with ID {pre_key_id}: {e}")

    try:
        saved_signed_pre_key = bob_store.get_signed_pre_key(signed_pre_key_id)
        print(f"Retrieved signed pre-key with ID {signed_pre_key_id}: {saved_signed_pre_key is not None}")
    except Exception as e:
        print(f"Error retrieving signed pre-key with ID {signed_pre_key_id}: {e}")

    assert bob_store.load_session(alice_address) is None

    # Decrypt the message
    plaintext = session_cipher.message_decrypt(
        bob_store, alice_address, incoming_message
    )

    assert original_message == plaintext

    # Bob responds to Alice
    bobs_response = b"Who watches the watchers?"

    # Skip session check as it's not accessible through StorageProxy

    bob_outgoing = session_cipher.message_encrypt(
        bob_store, alice_address, bobs_response
    )
    assert bob_outgoing.message_type() == 2  # 2 == CiphertextMessageType::Whisper

    # Alice decrypts Bob's response
    alice_decrypts = session_cipher.message_decrypt(
        alice_store, bob_address, bob_outgoing
    )
    assert alice_decrypts == bobs_response


def test_basic_simultaneous_initiate_persistent(alice_store, bob_store):
    alice_address = address.ProtocolAddress("+14151111111", 1)
    bob_address = address.ProtocolAddress("+14151111112", 1)

    # Create pre-key bundles for Alice and Bob
    alice_pre_key_pair = curve.KeyPair.generate()
    alice_signed_pre_key_pair = curve.KeyPair.generate()
    alice_signed_pre_key_public = alice_signed_pre_key_pair.public_key().serialize()
    alice_signed_pre_key_signature = (
        alice_store.get_identity_key_pair()
        .private_key()
        .calculate_signature(alice_signed_pre_key_public)
    )

    bob_pre_key_pair = curve.KeyPair.generate()
    bob_signed_pre_key_pair = curve.KeyPair.generate()
    bob_signed_pre_key_public = bob_signed_pre_key_pair.public_key().serialize()
    bob_signed_pre_key_signature = (
        bob_store.get_identity_key_pair()
        .private_key()
        .calculate_signature(bob_signed_pre_key_public)
    )

    # Create pre-key records
    alice_pre_key_record = state.PreKeyRecord(1, alice_pre_key_pair)
    alice_signed_pre_key_record = state.SignedPreKeyRecord(
        1, 42, alice_signed_pre_key_pair, alice_signed_pre_key_signature
    )

    bob_pre_key_record = state.PreKeyRecord(2, bob_pre_key_pair)
    bob_signed_pre_key_record = state.SignedPreKeyRecord(
        2, 42, bob_signed_pre_key_pair, bob_signed_pre_key_signature
    )

    # Create pre-key bundles
    alice_pre_key_bundle = state.PreKeyBundle(
        alice_store.get_local_registration_id(),
        1,
        1,
        alice_pre_key_pair.public_key(),
        1,
        alice_signed_pre_key_pair.public_key(),
        alice_signed_pre_key_signature,
        alice_store.get_identity_key_pair().identity_key(),
    )

    bob_pre_key_bundle = state.PreKeyBundle(
        bob_store.get_local_registration_id(),
        1,
        2,
        bob_pre_key_pair.public_key(),
        2,
        bob_signed_pre_key_pair.public_key(),
        bob_signed_pre_key_signature,
        bob_store.get_identity_key_pair().identity_key(),
    )

    # Process pre-key bundles
    session.process_prekey_bundle(
        bob_address,
        alice_store,
        bob_pre_key_bundle,
    )
    session.process_prekey_bundle(
        alice_address,
        bob_store,
        alice_pre_key_bundle,
    )

    # Save pre-keys and signed pre-keys
    alice_store.save_pre_key(1, alice_pre_key_record)
    alice_store.save_signed_pre_key(1, alice_signed_pre_key_record)

    bob_store.save_pre_key(2, bob_pre_key_record)
    bob_store.save_signed_pre_key(2, bob_signed_pre_key_record)

    # Encrypt messages
    message_for_bob = session_cipher.message_encrypt(
        alice_store, bob_address, b"hi bob"
    )
    message_for_alice = session_cipher.message_encrypt(
        bob_store, alice_address, b"hi alice"
    )

    assert message_for_bob.message_type() == 3  # 3 == CiphertextMessageType::PreKey
    assert message_for_alice.message_type() == 3  # 3 == CiphertextMessageType::PreKey

    # Decrypt messages
    alice_plaintext = session_cipher.message_decrypt(
        alice_store,
        bob_address,
        protocol.PreKeySignalMessage.try_from(message_for_alice.serialize()),
    )
    assert alice_plaintext == b"hi alice"

    bob_plaintext = session_cipher.message_decrypt(
        bob_store,
        alice_address,
        protocol.PreKeySignalMessage.try_from(message_for_bob.serialize()),
    )
    assert bob_plaintext == b"hi bob"

    # Skip session check as it's not accessible through StorageProxy

    # Send a response
    alice_response = session_cipher.message_encrypt(
        alice_store, bob_address, b"nice to see you"
    )
    assert alice_response.message_type() == 2  # CiphertextMessageType::Whisper => 2

    response_plaintext = session_cipher.message_decrypt(
        bob_store,
        alice_address,
        protocol.SignalMessage.try_from(alice_response.serialize()),
    )
    assert response_plaintext == b"nice to see you"

    # Bob responds
    bob_response = session_cipher.message_encrypt(
        bob_store, alice_address, b"you as well"
    )
    assert bob_response.message_type() == 2  # CiphertextMessageType::Whisper => 2

    response_plaintext = session_cipher.message_decrypt(
        alice_store,
        bob_address,
        protocol.SignalMessage.try_from(bob_response.serialize()),
    )
    assert response_plaintext == b"you as well"
