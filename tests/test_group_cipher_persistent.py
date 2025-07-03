import pytest
import random
from signal_protocol import address, error, group_cipher, identity_key, sender_keys, protocol

DEVICE_ID = 1

def test_group_no_send_session_persistent(alice_store):
    sender_address = address.ProtocolAddress("+14159999111", DEVICE_ID)
    group_sender = sender_keys.SenderKeyName("pizza party", sender_address)

    with pytest.raises(error.SignalProtocolException, match="invalid send key id"):
        group_cipher.group_encrypt(alice_store, group_sender, "hello".encode("utf8"))


def test_group_basic_encrypt_decrypt_persistent(alice_store, bob_store):
    sender_address = address.ProtocolAddress("+14159999111", DEVICE_ID)
    group_sender = sender_keys.SenderKeyName("pizza party", sender_address)

    sent_distribution_message = group_cipher.create_sender_key_distribution_message(
        group_sender, alice_store
    )
    recv_distribution_message = protocol.SenderKeyDistributionMessage.try_from(
        sent_distribution_message.serialized()
    )

    alice_ciphertext = group_cipher.group_encrypt(alice_store, group_sender, "hello".encode("utf8"))

    group_cipher.process_sender_key_distribution_message(
        group_sender, recv_distribution_message, bob_store
    )

    bob_plaintext = group_cipher.group_decrypt(alice_ciphertext, bob_store, group_sender)

    assert bob_plaintext.decode("utf8") == "hello"


def test_group_no_recv_session_persistent(alice_store, bob_store):
    sender_address = address.ProtocolAddress("+14159999111", DEVICE_ID)
    group_sender = sender_keys.SenderKeyName("pizza party", sender_address)

    sent_distribution_message = group_cipher.create_sender_key_distribution_message(
        group_sender, alice_store
    )
    recv_distribution_message = protocol.SenderKeyDistributionMessage.try_from(
        sent_distribution_message.serialized()
    )

    alice_ciphertext = group_cipher.group_encrypt(alice_store, group_sender, "hello".encode("utf8"))

    with pytest.raises(error.SignalProtocolException, match="invalid send key id"):
        bob_plaintext = group_cipher.group_decrypt(alice_ciphertext, bob_store, group_sender)


def test_group_large_message_persistent(alice_store, bob_store):
    sender_address = address.ProtocolAddress("+14159999111", DEVICE_ID)
    group_sender = sender_keys.SenderKeyName("pizza party", sender_address)

    sent_distribution_message = group_cipher.create_sender_key_distribution_message(
        group_sender, alice_store
    )
    recv_distribution_message = protocol.SenderKeyDistributionMessage.try_from(
        sent_distribution_message.serialized()
    )

    large_message = bytes(1024)
    alice_ciphertext = group_cipher.group_encrypt(alice_store, group_sender, large_message)

    group_cipher.process_sender_key_distribution_message(
        group_sender, recv_distribution_message, bob_store
    )

    bob_plaintext = group_cipher.group_decrypt(alice_ciphertext, bob_store, group_sender)

    assert bob_plaintext == large_message


def test_group_basic_ratchet_persistent(alice_store, bob_store):
    sender_address = address.ProtocolAddress("+14159999111", DEVICE_ID)
    group_sender = sender_keys.SenderKeyName("pizza party", sender_address)

    sent_distribution_message = group_cipher.create_sender_key_distribution_message(
        group_sender, alice_store
    )
    recv_distribution_message = protocol.SenderKeyDistributionMessage.try_from(
        sent_distribution_message.serialized()
    )

    group_cipher.process_sender_key_distribution_message(
        group_sender, recv_distribution_message, bob_store
    )

    alice_ciphertext_1 = group_cipher.group_encrypt(
        alice_store, group_sender, "message 1".encode("utf8")
    )
    alice_ciphertext_2 = group_cipher.group_encrypt(
        alice_store, group_sender, "message 2".encode("utf8")
    )
    alice_ciphertext_3 = group_cipher.group_encrypt(
        alice_store, group_sender, "message 3".encode("utf8")
    )

    bob_plaintext1 = group_cipher.group_decrypt(alice_ciphertext_1, bob_store, group_sender)
    assert bob_plaintext1.decode("utf8") == "message 1"

    with pytest.raises(error.SignalProtocolException, match="message with old counter 1 / 0"):
        bob_plaintext1 = group_cipher.group_decrypt(alice_ciphertext_1, bob_store, group_sender)

    bob_plaintext2 = group_cipher.group_decrypt(alice_ciphertext_2, bob_store, group_sender)
    assert bob_plaintext2.decode("utf8") == "message 2"

    bob_plaintext3 = group_cipher.group_decrypt(alice_ciphertext_3, bob_store, group_sender)
    assert bob_plaintext3.decode("utf8") == "message 3"


def test_group_late_join_persistent(alice_store, bob_store):
    sender_address = address.ProtocolAddress("+14159999111", DEVICE_ID)
    group_sender = sender_keys.SenderKeyName("pizza party", sender_address)

    sent_distribution_message = group_cipher.create_sender_key_distribution_message(
        group_sender, alice_store
    )
    recv_distribution_message = protocol.SenderKeyDistributionMessage.try_from(
        sent_distribution_message.serialized()
    )

    for i in range(100):
        group_cipher.group_encrypt(alice_store, group_sender, f"message {i}/100".encode("utf8"))

    group_cipher.process_sender_key_distribution_message(
        group_sender, recv_distribution_message, bob_store
    )

    alice_ciphertext = group_cipher.group_encrypt(
        alice_store, group_sender, "welcome Bob!".encode("utf8")
    )

    bob_plaintext = group_cipher.group_decrypt(alice_ciphertext, bob_store, group_sender)
    assert bob_plaintext.decode("utf8") == "welcome Bob!"


def test_group_out_of_order_persistent(alice_store, bob_store):
    sender_address = address.ProtocolAddress("+14159999111", DEVICE_ID)
    group_sender = sender_keys.SenderKeyName("pizza party", sender_address)

    sent_distribution_message = group_cipher.create_sender_key_distribution_message(
        group_sender, alice_store
    )
    recv_distribution_message = protocol.SenderKeyDistributionMessage.try_from(
        sent_distribution_message.serialized()
    )
    group_cipher.process_sender_key_distribution_message(
        group_sender, recv_distribution_message, bob_store
    )

    ooo_ciphertexts = []
    for i in range(100):
        ooo_ciphertexts.append(
            group_cipher.group_encrypt(alice_store, group_sender, f"{i}".encode("utf8"))
        )
    random.shuffle(ooo_ciphertexts)

    plaintexts = []
    for ciphertext in ooo_ciphertexts:
        plaintexts.append(group_cipher.group_decrypt(ciphertext, bob_store, group_sender))
    plaintexts.sort(key=lambda x: int(x))

    for i, plaintext in enumerate(plaintexts):
        assert plaintext.decode("utf8") == f"{i}"


def test_group_too_far_in_the_future_persistent(alice_store, bob_store):
    sender_address = address.ProtocolAddress("+14159999111", DEVICE_ID)
    group_sender = sender_keys.SenderKeyName("pizza party", sender_address)

    sent_distribution_message = group_cipher.create_sender_key_distribution_message(
        group_sender, alice_store
    )
    recv_distribution_message = protocol.SenderKeyDistributionMessage.try_from(
        sent_distribution_message.serialized()
    )
    group_cipher.process_sender_key_distribution_message(
        group_sender, recv_distribution_message, bob_store
    )

    for i in range(2001):
        group_cipher.group_encrypt(alice_store, group_sender, f"this is message {i}".encode("utf8"))

    alice_ciphertext = group_cipher.group_encrypt(
        alice_store, group_sender, "hello????".encode("utf8")
    )

    with pytest.raises(
        error.SignalProtocolException, match="message from too far into the future"
    ):
        assert group_cipher.group_decrypt(alice_ciphertext, bob_store, group_sender)


def test_group_message_key_limit_persistent(alice_store, bob_store):
    sender_address = address.ProtocolAddress("+14159999111", DEVICE_ID)
    group_sender = sender_keys.SenderKeyName("pizza party", sender_address)

    sent_distribution_message = group_cipher.create_sender_key_distribution_message(
        group_sender, alice_store
    )
    recv_distribution_message = protocol.SenderKeyDistributionMessage.try_from(
        sent_distribution_message.serialized()
    )
    group_cipher.process_sender_key_distribution_message(
        group_sender, recv_distribution_message, bob_store
    )

    ciphertexts = []
    for i in range(2010):
        ciphertexts.append(
            group_cipher.group_encrypt(alice_store, group_sender, "too many msg".encode("utf8"))
        )

    assert (
        group_cipher.group_decrypt(ciphertexts[1000], bob_store, group_sender).decode("utf8")
        == "too many msg"
    )
    assert (
        group_cipher.group_decrypt(
            ciphertexts[len(ciphertexts) - 1], bob_store, group_sender
        ).decode("utf8")
        == "too many msg"
    )

    with pytest.raises(error.SignalProtocolException, match="message with old counter"):
        assert group_cipher.group_decrypt(ciphertexts[0], bob_store, group_sender).decode("utf8")