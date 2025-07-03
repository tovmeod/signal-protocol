import pytest
from signal_protocol import (
    storage,
    state,
    address,
    identity_key,
    curve,
    sender_keys,
)
from tests.conftest import PersistentStorage

# A spy class to track method calls on the persistent storage
class SpiedPersistentStorage(PersistentStorage):
    def __init__(self):
        super().__init__()
        self.call_log = []

    def save_identity(self, address, identity_key_obj):
        self.call_log.append(("save_identity", address, identity_key_obj))
        return super().save_identity(address, identity_key_obj)

    def get_identity(self, address):
        self.call_log.append(("get_identity", address))
        return super().get_identity(address)

    def store_session(self, address, session_record):
        self.call_log.append(("store_session", address, session_record))
        super().store_session(address, session_record)

    def load_session(self, address):
        self.call_log.append(("load_session", address))
        return super().load_session(address)

    def save_pre_key(self, pre_key_id, pre_key_record):
        self.call_log.append(("save_pre_key", pre_key_id, pre_key_record))
        super().save_pre_key(pre_key_id, pre_key_record)

    def get_pre_key(self, pre_key_id):
        self.call_log.append(("get_pre_key", pre_key_id))
        return super().get_pre_key(pre_key_id)

    def remove_pre_key(self, pre_key_id):
        self.call_log.append(("remove_pre_key", pre_key_id))
        super().remove_pre_key(pre_key_id)

    def save_signed_pre_key(self, signed_pre_key_id, signed_pre_key_record):
        self.call_log.append(("save_signed_pre_key", signed_pre_key_id, signed_pre_key_record))
        super().save_signed_pre_key(signed_pre_key_id, signed_pre_key_record)

    def get_signed_pre_key(self, signed_pre_key_id):
        self.call_log.append(("get_signed_pre_key", signed_pre_key_id))
        return super().get_signed_pre_key(signed_pre_key_id)

    def store_sender_key(self, sender_key_name, sender_key_record):
        self.call_log.append(("store_sender_key", sender_key_name, sender_key_record))
        super().store_sender_key(sender_key_name, sender_key_record)

    def load_sender_key(self, sender_key_name):
        self.call_log.append(("load_sender_key", sender_key_name))
        return super().load_sender_key(sender_key_name)

@pytest.fixture
def spied_persistent_storage():
    return SpiedPersistentStorage()

def test_storage_creation_with_persistent_storage(identity_key_pair, spied_persistent_storage):
    registration_id = 123
    store = storage.InMemSignalProtocolStore(
        identity_key_pair,
        registration_id,
        spied_persistent_storage
    )
    assert store is not None
    assert store.get_local_registration_id() == 123

def test_identity_key_proxy(identity_key_pair, spied_persistent_storage, protocol_address):
    registration_id = 123
    store1 = storage.InMemSignalProtocolStore(identity_key_pair, registration_id, spied_persistent_storage)

    # Test save_identity
    ik = identity_key.IdentityKey(identity_key.IdentityKeyPair.generate().public_key().serialize())
    store1.save_identity(protocol_address, ik)

    assert any(log[0] == "save_identity" and log[1].name() == protocol_address.name() and 
               log[1].device_id() == protocol_address.device_id() for log in spied_persistent_storage.call_log)

    # Create a new store to simulate cache miss
    store2 = storage.InMemSignalProtocolStore(identity_key_pair, registration_id, spied_persistent_storage)
    spied_persistent_storage.call_log.clear()

    # Test get_identity
    retrieved_ik = store2.get_identity(protocol_address)
    assert any(log[0] == "get_identity" and log[1].name() == protocol_address.name() and 
               log[1].device_id() == protocol_address.device_id() for log in spied_persistent_storage.call_log)
    assert retrieved_ik.serialize() == ik.serialize()

def test_session_proxy(identity_key_pair, spied_persistent_storage, protocol_address, session_record):
    registration_id = 123
    store1 = storage.InMemSignalProtocolStore(identity_key_pair, registration_id, spied_persistent_storage)

    # Test store_session
    store1.store_session(protocol_address, session_record)
    assert any(log[0] == "store_session" and log[1].name() == protocol_address.name() and 
               log[1].device_id() == protocol_address.device_id() for log in spied_persistent_storage.call_log)

    # Create a new store to simulate cache miss
    store2 = storage.InMemSignalProtocolStore(identity_key_pair, registration_id, spied_persistent_storage)
    spied_persistent_storage.call_log.clear()

    # Test load_session
    retrieved_session = store2.load_session(protocol_address)
    assert any(log[0] == "load_session" and log[1].name() == protocol_address.name() and 
               log[1].device_id() == protocol_address.device_id() for log in spied_persistent_storage.call_log)
    assert retrieved_session.serialize() == session_record.serialize()

def test_pre_key_proxy(identity_key_pair, spied_persistent_storage, pre_key_record):
    registration_id = 123
    store1 = storage.InMemSignalProtocolStore(identity_key_pair, registration_id, spied_persistent_storage)
    pre_key_id = 10

    # Test save_pre_key
    store1.save_pre_key(pre_key_id, pre_key_record)
    assert any(log[0] == "save_pre_key" and log[1] == pre_key_id for log in spied_persistent_storage.call_log)

    # Create a new store to simulate cache miss
    store2 = storage.InMemSignalProtocolStore(identity_key_pair, registration_id, spied_persistent_storage)
    spied_persistent_storage.call_log.clear()

    # Test get_pre_key
    retrieved_pre_key = store2.get_pre_key(pre_key_id)
    assert any(log[0] == "get_pre_key" and log[1] == pre_key_id for log in spied_persistent_storage.call_log)
    assert retrieved_pre_key.serialize() == pre_key_record.serialize()

    # Test remove_pre_key
    store2.remove_pre_key(pre_key_id)
    assert any(log[0] == "remove_pre_key" and log[1] == pre_key_id for log in spied_persistent_storage.call_log)
    with pytest.raises(KeyError):
        spied_persistent_storage.get_pre_key(pre_key_id)

def test_signed_pre_key_proxy(identity_key_pair, spied_persistent_storage, signed_pre_key_record):
    registration_id = 123
    store1 = storage.InMemSignalProtocolStore(identity_key_pair, registration_id, spied_persistent_storage)
    signed_pre_key_id = 33

    # Test save_signed_pre_key
    store1.save_signed_pre_key(signed_pre_key_id, signed_pre_key_record)
    assert any(log[0] == "save_signed_pre_key" and log[1] == signed_pre_key_id for log in spied_persistent_storage.call_log)

    # Create a new store to simulate cache miss
    store2 = storage.InMemSignalProtocolStore(identity_key_pair, registration_id, spied_persistent_storage)
    spied_persistent_storage.call_log.clear()

    # Test get_signed_pre_key
    retrieved_signed_pre_key = store2.get_signed_pre_key(signed_pre_key_id)
    assert any(log[0] == "get_signed_pre_key" and log[1] == signed_pre_key_id for log in spied_persistent_storage.call_log)
    assert retrieved_signed_pre_key.serialize() == signed_pre_key_record.serialize()

def test_sender_key_proxy(identity_key_pair, spied_persistent_storage, sender_key_name, sender_key_record):
    registration_id = 123
    store1 = storage.InMemSignalProtocolStore(identity_key_pair, registration_id, spied_persistent_storage)

    # Test store_sender_key
    store1.store_sender_key(sender_key_name, sender_key_record)
    assert any(log[0] == "store_sender_key" and log[1].group_id() == sender_key_name.group_id() and
               log[1].sender().name() == sender_key_name.sender().name() and
               log[1].sender().device_id() == sender_key_name.sender().device_id() 
               for log in spied_persistent_storage.call_log)

    # Create a new store to simulate cache miss
    store2 = storage.InMemSignalProtocolStore(identity_key_pair, registration_id, spied_persistent_storage)
    spied_persistent_storage.call_log.clear()

    # Test load_sender_key
    retrieved_sender_key = store2.load_sender_key(sender_key_name)
    assert any(log[0] == "load_sender_key" and log[1].group_id() == sender_key_name.group_id() and
               log[1].sender().name() == sender_key_name.sender().name() and
               log[1].sender().device_id() == sender_key_name.sender().device_id() 
               for log in spied_persistent_storage.call_log)
    assert retrieved_sender_key.serialize() == sender_key_record.serialize()
