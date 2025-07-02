import pytest

from signal_protocol import address, curve, error, identity_key, sealed_sender, session, state

from tests.utils.sessions import create_pre_key_bundle


def test_sealed_sender_happy_persistent(alice_store, bob_store):
    alice_device_id = 2
    bob_device_id = 3

    alice_e164 = "alice_e164"
    bob_e164 = "bob_e164"
    alice_uuid = "alice_uuid"
    bob_uuid = "bob_uuid"

    alice_pubkey = alice_store.get_identity_key_pair().public_key()
    bob_uuid_address = address.ProtocolAddress(bob_uuid, bob_device_id)

    # Create pre-key bundle for Bob
    bob_pre_key_pair = curve.KeyPair.generate()
    bob_signed_pre_key_pair = curve.KeyPair.generate()
    bob_signed_pre_key_public = bob_signed_pre_key_pair.public_key().serialize()
    bob_signed_pre_key_signature = (
        bob_store.get_identity_key_pair()
        .private_key()
        .calculate_signature(bob_signed_pre_key_public)
    )

    # Create pre-key records
    pre_key_id = 1
    signed_pre_key_id = 2
    pre_key_record = state.PreKeyRecord(pre_key_id, bob_pre_key_pair)
    signed_pre_key_record = state.SignedPreKeyRecord(
        signed_pre_key_id,
        42,
        bob_signed_pre_key_pair,
        bob_signed_pre_key_signature,
    )

    # Create pre-key bundle
    bob_pre_key_bundle = state.PreKeyBundle(
        bob_store.get_local_registration_id(),
        bob_device_id,
        pre_key_id,
        bob_pre_key_pair.public_key(),
        signed_pre_key_id,
        bob_signed_pre_key_pair.public_key(),
        bob_signed_pre_key_signature,
        bob_store.get_identity_key_pair().identity_key(),
    )

    # Save pre-keys in Bob's store
    bob_store.save_pre_key(pre_key_id, pre_key_record)
    bob_store.save_signed_pre_key(signed_pre_key_id, signed_pre_key_record)

    # Process pre-key bundle
    session.process_prekey_bundle(
        bob_uuid_address,
        alice_store,
        bob_pre_key_bundle,
    )

    # Create certificates
    trust_root = curve.KeyPair.generate()
    server_key = curve.KeyPair.generate()
    server_cert = sealed_sender.ServerCertificate(
        1, server_key.public_key(), trust_root.private_key()
    )

    expiration = 1234567
    sender_cert = sealed_sender.SenderCertificate(
        alice_uuid,
        alice_e164,
        alice_pubkey,
        alice_device_id,
        expiration,
        server_cert,
        server_key.private_key(),
    )

    # Encrypt and decrypt message
    alice_plaintext = b"teehee"
    alice_ciphertext = sealed_sender.sealed_sender_encrypt(
        bob_uuid_address, sender_cert, alice_plaintext, alice_store
    )

    bob_plaintext = sealed_sender.sealed_sender_decrypt(
        alice_ciphertext,
        trust_root.public_key(),
        expiration - 1,
        bob_e164,
        bob_uuid,
        bob_device_id,
        bob_store,
    )

    assert bob_plaintext.message() == alice_plaintext
    assert bob_plaintext.sender_uuid() == alice_uuid
    assert bob_plaintext.sender_e164() == alice_e164
    assert bob_plaintext.device_id() == alice_device_id


def test_sealed_sender_expired_cert_persistent(alice_store, bob_store):
    alice_device_id = 2
    bob_device_id = 3

    alice_e164 = "alice_e164"
    bob_e164 = "bob_e164"
    alice_uuid = "alice_uuid"
    bob_uuid = "bob_uuid"

    alice_pubkey = alice_store.get_identity_key_pair().public_key()
    bob_uuid_address = address.ProtocolAddress(bob_uuid, bob_device_id)

    # Create pre-key bundle for Bob
    bob_pre_key_pair = curve.KeyPair.generate()
    bob_signed_pre_key_pair = curve.KeyPair.generate()
    bob_signed_pre_key_public = bob_signed_pre_key_pair.public_key().serialize()
    bob_signed_pre_key_signature = (
        bob_store.get_identity_key_pair()
        .private_key()
        .calculate_signature(bob_signed_pre_key_public)
    )

    # Create pre-key records
    pre_key_id = 3
    signed_pre_key_id = 4
    pre_key_record = state.PreKeyRecord(pre_key_id, bob_pre_key_pair)
    signed_pre_key_record = state.SignedPreKeyRecord(
        signed_pre_key_id,
        42,
        bob_signed_pre_key_pair,
        bob_signed_pre_key_signature,
    )

    # Create pre-key bundle
    bob_pre_key_bundle = state.PreKeyBundle(
        bob_store.get_local_registration_id(),
        bob_device_id,
        pre_key_id,
        bob_pre_key_pair.public_key(),
        signed_pre_key_id,
        bob_signed_pre_key_pair.public_key(),
        bob_signed_pre_key_signature,
        bob_store.get_identity_key_pair().identity_key(),
    )

    # Save pre-keys in Bob's store
    bob_store.save_pre_key(pre_key_id, pre_key_record)
    bob_store.save_signed_pre_key(signed_pre_key_id, signed_pre_key_record)

    # Process pre-key bundle
    session.process_prekey_bundle(
        bob_uuid_address,
        alice_store,
        bob_pre_key_bundle,
    )

    # Create certificates
    trust_root = curve.KeyPair.generate()
    server_key = curve.KeyPair.generate()
    server_cert = sealed_sender.ServerCertificate(
        1, server_key.public_key(), trust_root.private_key()
    )

    expiration = 1234567
    sender_cert = sealed_sender.SenderCertificate(
        alice_uuid,
        alice_e164,
        alice_pubkey,
        alice_device_id,
        expiration,
        server_cert,
        server_key.private_key(),
    )

    # Encrypt message
    alice_plaintext = b"teehee"
    alice_ciphertext = sealed_sender.sealed_sender_encrypt(
        bob_uuid_address, sender_cert, alice_plaintext, alice_store
    )

    # Attempt to decrypt with expired certificate
    with pytest.raises(error.SignalProtocolException, match="invalid sealed sender"):
        sealed_sender.sealed_sender_decrypt(
            alice_ciphertext,
            trust_root.public_key(),
            expiration + 1,
            bob_e164,
            bob_uuid,
            bob_device_id,
            bob_store,
        )


def test_sealed_sender_invalid_trust_root_persistent(alice_store, bob_store):
    alice_device_id = 2
    bob_device_id = 3

    alice_e164 = "alice_e164"
    bob_e164 = "bob_e164"
    alice_uuid = "alice_uuid"
    bob_uuid = "bob_uuid"

    alice_pubkey = alice_store.get_identity_key_pair().public_key()
    bob_uuid_address = address.ProtocolAddress(bob_uuid, bob_device_id)

    # Create pre-key bundle for Bob
    bob_pre_key_pair = curve.KeyPair.generate()
    bob_signed_pre_key_pair = curve.KeyPair.generate()
    bob_signed_pre_key_public = bob_signed_pre_key_pair.public_key().serialize()
    bob_signed_pre_key_signature = (
        bob_store.get_identity_key_pair()
        .private_key()
        .calculate_signature(bob_signed_pre_key_public)
    )

    # Create pre-key records
    pre_key_id = 5
    signed_pre_key_id = 6
    pre_key_record = state.PreKeyRecord(pre_key_id, bob_pre_key_pair)
    signed_pre_key_record = state.SignedPreKeyRecord(
        signed_pre_key_id,
        42,
        bob_signed_pre_key_pair,
        bob_signed_pre_key_signature,
    )

    # Create pre-key bundle
    bob_pre_key_bundle = state.PreKeyBundle(
        bob_store.get_local_registration_id(),
        bob_device_id,
        pre_key_id,
        bob_pre_key_pair.public_key(),
        signed_pre_key_id,
        bob_signed_pre_key_pair.public_key(),
        bob_signed_pre_key_signature,
        bob_store.get_identity_key_pair().identity_key(),
    )

    # Save pre-keys in Bob's store
    bob_store.save_pre_key(pre_key_id, pre_key_record)
    bob_store.save_signed_pre_key(signed_pre_key_id, signed_pre_key_record)

    # Process pre-key bundle
    session.process_prekey_bundle(
        bob_uuid_address,
        alice_store,
        bob_pre_key_bundle,
    )

    # Create certificates
    trust_root = curve.KeyPair.generate()
    server_key = curve.KeyPair.generate()
    server_cert = sealed_sender.ServerCertificate(
        1, server_key.public_key(), trust_root.private_key()
    )

    expiration = 1234567
    sender_cert = sealed_sender.SenderCertificate(
        alice_uuid,
        alice_e164,
        alice_pubkey,
        alice_device_id,
        expiration,
        server_cert,
        server_key.private_key(),
    )

    # Encrypt message
    alice_plaintext = b"teehee"
    alice_ciphertext = sealed_sender.sealed_sender_encrypt(
        bob_uuid_address, sender_cert, alice_plaintext, alice_store
    )

    # Attempt to decrypt with invalid trust root
    invalid_trust_root = curve.KeyPair.generate()

    with pytest.raises(error.SignalProtocolException, match="invalid sealed sender"):
        sealed_sender.sealed_sender_decrypt(
            alice_ciphertext,
            invalid_trust_root.public_key(),
            expiration - 1,
            bob_e164,
            bob_uuid,
            bob_device_id,
            bob_store,
        )
