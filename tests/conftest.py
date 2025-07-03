import pytest
from typing import Dict, Optional
from signal_protocol import storage, state, address, identity_key, curve, sender_keys

# Python-based persistent storage logic - now inherits from PersistentStorageBase
class PersistentStorage(storage.PersistentStorageBase):
    def __init__(self) -> None:
        self.identities: Dict[str, identity_key.IdentityKey] = {}
        self.sessions: Dict[str, state.SessionRecord] = {}
        self.pre_keys: Dict[int, state.PreKeyRecord] = {}
        self.signed_pre_keys: Dict[int, state.SignedPreKeyRecord] = {}
        self.sender_keys: Dict[str, sender_keys.SenderKeyRecord] = {}

    # Identity Store Methods
    def save_identity(self, address_name: str, identity_key: identity_key.IdentityKey) -> bool:
        """Save identity for the given address name"""
        self.identities[address_name] = identity_key
        return True

    def get_identity(self, address_name: str) -> Optional[identity_key.IdentityKey]:
        """Get identity for the given address name"""
        return self.identities.get(address_name, None)

    # Session Store Methods
    def store_session(self, address_name: str, session_record: state.SessionRecord) -> None:
        """Store session for the given address name"""
        self.sessions[address_name] = session_record

    def load_session(self, address_name: str) -> Optional[state.SessionRecord]:
        """Load session for the given address name"""
        return self.sessions.get(address_name, None)

    # PreKey Store Methods
    def get_pre_key(self, pre_key_id: int) -> state.PreKeyRecord:
        """Get prekey by ID - raises KeyError if not found"""
        if pre_key_id not in self.pre_keys:
            raise KeyError(f"PreKey with ID {pre_key_id} not found")
        return self.pre_keys[pre_key_id]

    def save_pre_key(self, pre_key_id: int, pre_key_record: state.PreKeyRecord) -> None:
        """Save prekey record with given ID"""
        self.pre_keys[pre_key_id] = pre_key_record

    def remove_pre_key(self, pre_key_id: int) -> None:
        """Remove prekey with given ID"""
        if pre_key_id in self.pre_keys:
            del self.pre_keys[pre_key_id]

    # Signed PreKey Store Methods
    def get_signed_pre_key(self, signed_pre_key_id: int) -> state.SignedPreKeyRecord:
        """Get signed prekey by ID - raises KeyError if not found"""
        if signed_pre_key_id not in self.signed_pre_keys:
            raise KeyError(f"SignedPreKey with ID {signed_pre_key_id} not found")
        return self.signed_pre_keys[signed_pre_key_id]

    def save_signed_pre_key(self, signed_pre_key_id: int, signed_pre_key_record: state.SignedPreKeyRecord) -> None:
        """Save signed prekey record with given ID"""
        self.signed_pre_keys[signed_pre_key_id] = signed_pre_key_record

    # Sender Key Store Methods
    def store_sender_key(self, sender_key_name: str, sender_key_record: sender_keys.SenderKeyRecord) -> None:
        """Store sender key record with given name"""
        self.sender_keys[sender_key_name] = sender_key_record

    def load_sender_key(self, sender_key_name: str) -> Optional[sender_keys.SenderKeyRecord]:
        """Load sender key by name"""
        return self.sender_keys.get(sender_key_name, None)

    # Utility methods for testing
    def clear_all(self) -> None:
        """Clear all stored data - useful for test cleanup"""
        self.identities.clear()
        self.sessions.clear()
        self.pre_keys.clear()
        self.signed_pre_keys.clear()
        self.sender_keys.clear()


@pytest.fixture
def persistent_storage() -> PersistentStorage:
    """Create a fresh PersistentStorage instance for each test"""
    return PersistentStorage()


@pytest.fixture
def identity_key_pair() -> identity_key.IdentityKeyPair:
    """Generate a random identity key pair for testing"""
    return identity_key.IdentityKeyPair.generate()


@pytest.fixture
def protocol_address() -> address.ProtocolAddress:
    """Create a test protocol address"""
    return address.ProtocolAddress("remote_user", 1)


@pytest.fixture
def session_record() -> state.SessionRecord:
    """Create a fresh session record for testing"""
    return state.SessionRecord.new_fresh()


@pytest.fixture
def pre_key_pair() -> curve.KeyPair:
    """Generate a random pre key pair for testing"""
    return curve.KeyPair.generate()


@pytest.fixture
def pre_key_record(pre_key_pair: curve.KeyPair) -> state.PreKeyRecord:
    """Create a pre key record for testing"""
    pre_key_id = 10
    return state.PreKeyRecord(pre_key_id, pre_key_pair)


@pytest.fixture
def signed_pre_key_record() -> state.SignedPreKeyRecord:
    """Create a signed pre key record for testing"""
    signed_pre_key_pair = curve.KeyPair.generate()
    signed_pre_key_id = 33
    timestamp = 42
    # Create a dummy signature (in real usage this would be properly signed)
    signature = b"dummy_signature_for_testing_purposes_only"
    return state.SignedPreKeyRecord(signed_pre_key_id, timestamp, signed_pre_key_pair, signature)


@pytest.fixture
def sender_key_name(protocol_address: address.ProtocolAddress) -> sender_keys.SenderKeyName:
    """Create a sender key name for testing"""
    return sender_keys.SenderKeyName("test_group", protocol_address)


@pytest.fixture
def sender_key_record() -> sender_keys.SenderKeyRecord:
    """Create a sender key record for testing"""
    return sender_keys.SenderKeyRecord.new_empty()


@pytest.fixture
def alice_store() -> storage.InMemSignalProtocolStore:
    """Create Alice's storage for testing"""
    alice_identity_key_pair = identity_key.IdentityKeyPair.generate()
    alice_registration_id = 1
    alice_persistent_storage = PersistentStorage()

    # Create a store with caching
    alice_store = storage.InMemSignalProtocolStore(
        alice_identity_key_pair,
        alice_registration_id,
        alice_persistent_storage
    )
    return alice_store


@pytest.fixture
def bob_store() -> storage.InMemSignalProtocolStore:
    """Create Bob's storage with caching for testing"""
    bob_identity_key_pair = identity_key.IdentityKeyPair.generate()
    bob_registration_id = 2
    bob_persistent_storage = PersistentStorage()

    # Create a store with caching
    bob_store = storage.InMemSignalProtocolStore(
        bob_identity_key_pair,
        bob_registration_id,
        bob_persistent_storage
    )
    return bob_store


@pytest.fixture
def proxy_instance(identity_key_pair: identity_key.IdentityKeyPair, persistent_storage: PersistentStorage) -> storage.InMemSignalProtocolStore:
    """Create a storage instance for general testing"""
    registration_id = 123

    return storage.InMemSignalProtocolStore(
        identity_key_pair,
        registration_id,
        persistent_storage
    )