import pytest
import tempfile
import os
from signal_protocol import storage, state, address, identity_key, curve, sender_keys

@pytest.fixture(autouse=True)
def init_signal_logging():
    """Initialize signal protocol logging for all tests"""
    storage.init_logging()

@pytest.fixture
def temp_db_path():
    """Create a temporary database file that is automatically cleaned up"""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=True) as temp_db:
        yield temp_db.name

# Basic store fixture (cache-only)
@pytest.fixture
def basic_store():
    """Create a basic InMemSignalProtocolStore without persistence (cache-only)"""
    alice_identity_key_pair = identity_key.IdentityKeyPair.generate()
    alice_registration_id = 1
    
    store = storage.InMemSignalProtocolStore(
        alice_identity_key_pair,
        alice_registration_id
    )
    
    yield store
    # No cleanup needed for basic store


# Async fixture for store with database persistence  
@pytest.fixture
async def alice_store_with_persistence():
    """Create Alice's store with database persistence (cache + backing store)"""
    import tempfile
    alice_identity_key_pair = identity_key.IdentityKeyPair.generate()
    alice_registration_id = 1
    device_jid = "alice@test.com"
    
    # Use temporary SQLite database
    with tempfile.NamedTemporaryFile(suffix='.db') as temp_db:
        connection_string = f"sqlite://{temp_db.name}"
        
        alice_store = storage.InMemSignalProtocolStore(
            alice_identity_key_pair,
            alice_registration_id,
            connection_string=connection_string,
            device_jid=device_jid
        )
        
        # Run migrations to create database tables
        await alice_store.migrate()
        
        yield alice_store
        # Database cleanup handled by temp file context manager

@pytest.fixture
def alice_store() -> storage.InMemSignalProtocolStore:
    """Create Alice's basic store (cache-only) for testing"""
    alice_identity_key_pair = identity_key.IdentityKeyPair.generate()
    alice_registration_id = 1

    # Create a basic store without persistence
    alice_store = storage.InMemSignalProtocolStore(
        alice_identity_key_pair,
        alice_registration_id
    )
    
    yield alice_store
    # No cleanup needed for basic store


@pytest.fixture
async def bob_store_with_persistence():
    """Create Bob's store with database persistence (cache + backing store)"""
    import tempfile
    bob_identity_key_pair = identity_key.IdentityKeyPair.generate()
    bob_registration_id = 2
    device_jid = "bob@test.com"
    
    # Use temporary SQLite database
    with tempfile.NamedTemporaryFile(suffix='.db') as temp_db:
        connection_string = f"sqlite://{temp_db.name}"
        
        bob_store = storage.InMemSignalProtocolStore(
            bob_identity_key_pair,
            bob_registration_id,
            connection_string=connection_string,
            device_jid=device_jid
        )
        
        # Run migrations to create database tables
        await bob_store.migrate()
        
        yield bob_store
        # Database cleanup handled by temp file context manager

@pytest.fixture
def bob_store() -> storage.InMemSignalProtocolStore:
    """Create Bob's basic store (cache-only) for testing"""
    bob_identity_key_pair = identity_key.IdentityKeyPair.generate()
    bob_registration_id = 2

    # Create a basic store without persistence
    bob_store = storage.InMemSignalProtocolStore(
        bob_identity_key_pair,
        bob_registration_id
    )
    
    yield bob_store
    # No cleanup needed for basic store


@pytest.fixture
def proxy_instance(identity_key_pair: identity_key.IdentityKeyPair) -> storage.InMemSignalProtocolStore:
    """Create a basic storage instance for general testing (cache-only)"""
    registration_id = 123

    store = storage.InMemSignalProtocolStore(
        identity_key_pair,
        registration_id
    )
    
    yield store
    # No cleanup needed for basic store


# Non-parametrized fixtures (these don't depend on storage type)
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