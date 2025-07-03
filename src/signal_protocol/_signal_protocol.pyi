"""
Type stubs for signal_protocol._signal_protocol

Signal Protocol implementation in Python via Rust bindings.
"""

from typing import Optional, Tuple, Union
import sys

if sys.version_info >= (3, 8):
    from typing import Literal
else:
    from typing_extensions import Literal

# Exception Classes
class SignalProtocolException(Exception):
    """Base exception for Signal Protocol errors."""
    ...

# Core Cryptographic Classes
class KeyPair:
    """A public/private key pair for cryptographic operations."""

    def __init__(self, public_key: PublicKey, private_key: PrivateKey) -> None: ...

    @staticmethod
    def generate() -> KeyPair:
        """Generate a new random key pair."""
        ...

    @staticmethod
    def from_public_and_private(public_key: bytes, private_key: bytes) -> KeyPair:
        """Create a key pair from raw public and private key bytes."""
        ...

    def public_key(self) -> PublicKey:
        """Get the public key component."""
        ...

    def private_key(self) -> PrivateKey:
        """Get the private key component."""
        ...

    def serialize(self) -> bytes:
        """Serialize the public key to bytes."""
        ...

    def calculate_signature(self, message: bytes) -> bytes:
        """Calculate a signature for the given message."""
        ...

    def calculate_agreement(self, their_key: PublicKey) -> bytes:
        """Calculate a shared secret with another public key."""
        ...

class PublicKey:
    """A public key for cryptographic operations."""

    @staticmethod
    def deserialize(key: bytes) -> PublicKey:
        """Deserialize a public key from bytes."""
        ...

    def serialize(self) -> bytes:
        """Serialize the public key to bytes."""
        ...

    def verify_signature(self, message: bytes, signature: bytes) -> bool:
        """Verify a signature against a message."""
        ...

    def __eq__(self, other: object) -> bool: ...
    def __ne__(self, other: object) -> bool: ...

class PrivateKey:
    """A private key for cryptographic operations."""

    @staticmethod
    def deserialize(key: bytes) -> PrivateKey:
        """Deserialize a private key from bytes."""
        ...

    def serialize(self) -> bytes:
        """Serialize the private key to bytes."""
        ...

    def calculate_signature(self, message: bytes) -> bytes:
        """Calculate a signature for the given message."""
        ...

    def calculate_agreement(self, their_key: PublicKey) -> bytes:
        """Calculate a shared secret with another public key."""
        ...

    def public_key(self) -> PublicKey:
        """Get the corresponding public key."""
        ...

# Address and Identity Classes
class ProtocolAddress:
    """An address identifying a Signal Protocol participant."""

    def __init__(self, name: str, device_id: int) -> None: ...
    def name(self) -> str: ...
    def device_id(self) -> int: ...
    def __str__(self) -> str: ...
    def __repr__(self) -> str: ...

class IdentityKey:
    """An identity key representing a user's long-term identity."""

    def __init__(self, public_key: bytes) -> None: ...
    def public_key(self) -> PublicKey: ...
    def serialize(self) -> bytes: ...
    def __eq__(self, other: object) -> bool: ...
    def __ne__(self, other: object) -> bool: ...

class IdentityKeyPair:
    """A pair containing both identity key and its private key."""

    def __init__(self, identity_key: IdentityKey, private_key: PrivateKey) -> None: ...

    @staticmethod
    def from_bytes(identity_key_pair_bytes: bytes) -> IdentityKeyPair: ...

    @staticmethod
    def generate() -> IdentityKeyPair:
        """Generate a new random identity key pair."""
        ...

    def identity_key(self) -> IdentityKey: ...
    def public_key(self) -> PublicKey: ...
    def private_key(self) -> PrivateKey: ...
    def serialize(self) -> bytes: ...

# State and Record Classes
class SessionRecord:
    """Record containing session state information."""

    @staticmethod
    def new_fresh() -> SessionRecord: ...
    def serialize(self) -> bytes: ...
    @staticmethod
    def deserialize(data: bytes) -> SessionRecord: ...
    def session_version(self) -> int: ...
    def alice_base_key(self) -> bytes: ...

class PreKeyRecord:
    """Record containing pre-key information."""

    def __init__(self, id: int, key_pair: KeyPair) -> None: ...
    def serialize(self) -> bytes: ...
    @staticmethod
    def deserialize(data: bytes) -> PreKeyRecord: ...

class SignedPreKeyRecord:
    """Record containing signed pre-key information."""

    def __init__(self, id: int, timestamp: int, key_pair: KeyPair, signature: bytes) -> None: ...
    def serialize(self) -> bytes: ...
    @staticmethod
    def deserialize(data: bytes) -> SignedPreKeyRecord: ...

class PreKeyBundle:
    """Bundle containing pre-key information for session initialization."""

    def __init__(
        self,
        registration_id: int,
        device_id: int,
        prekey_id: int,
        prekey: PublicKey,
        signed_prekey_id: int,
        signed_prekey: PublicKey,
        signed_prekey_signature: bytes,
        identity_key: IdentityKey,
    ) -> None: ...

# Sender Key Classes
class SenderKeyName:
    """Identifier for a sender key in group messaging."""

    def __init__(self, group_id: str, sender: ProtocolAddress) -> None: ...
    def group_id(self) -> str: ...
    def sender(self) -> ProtocolAddress: ...

class SenderKeyRecord:
    """Record containing sender key information for group messaging."""

    @staticmethod
    def new_empty() -> SenderKeyRecord: ...
    def is_empty(self) -> bool: ...
    def serialize(self) -> bytes: ...
    @staticmethod
    def deserialize(data: bytes) -> SenderKeyRecord: ...

# Protocol Message Classes
class CiphertextMessage:
    """Base class for encrypted messages."""

    def message_type(self) -> int: ...
    def serialize(self) -> bytes: ...

class PreKeySignalMessage:
    """Message containing a pre-key Signal message."""

    @staticmethod
    def try_from(data: bytes) -> PreKeySignalMessage: ...

class SignalMessage:
    """Regular Signal message (non-prekey)."""

    @staticmethod
    def try_from(data: bytes) -> SignalMessage: ...

class SenderKeyDistributionMessage:
    """Message for distributing sender keys in group messaging."""

    @staticmethod
    def try_from(data: bytes) -> SenderKeyDistributionMessage: ...
    def serialized(self) -> bytes: ...

# Sealed Sender Classes
class ServerCertificate:
    """Certificate for sealed sender server validation."""

    def __init__(self, key_id: int, server_key: PublicKey, trust_root: PrivateKey) -> None: ...
    def serialized(self) -> bytes: ...
    @staticmethod
    def deserialize(data: bytes) -> ServerCertificate: ...
    def validate(self, trust_root: PublicKey) -> bool: ...

class SenderCertificate:
    """Certificate for sealed sender validation."""

    def __init__(
        self,
        sender_uuid: str,
        sender_e164: str,
        sender_key: PublicKey,
        sender_device_id: int,
        expiration: int,
        server_certificate: ServerCertificate,
        server_key: PrivateKey,
    ) -> None: ...
    def serialized(self) -> bytes: ...
    @staticmethod
    def deserialize(data: bytes) -> SenderCertificate: ...
    def validate(self, trust_root: PublicKey, validation_time: int) -> bool: ...

class UnidentifiedSenderMessageContent:
    """Content of an unidentified sender message."""

    def message(self) -> bytes: ...
    def sender_uuid(self) -> str: ...
    def sender_e164(self) -> str: ...
    def device_id(self) -> int: ...

# Fingerprint Classes
class Fingerprint:
    """Security fingerprint for identity verification."""

    def __init__(
        self,
        version: int,
        iterations: int,
        local_id: bytes,
        local_key: IdentityKey,
        remote_id: bytes,
        remote_key: IdentityKey,
    ) -> None: ...

    def display_string(self) -> str: ...
    def compare(self, combined: bytes) -> bool: ...
    def serialize(self) -> bytes: ...
    def __str__(self) -> str: ...
    def __repr__(self) -> str: ...

# Ratchet Classes
class BobSignalProtocolParameters:
    """Parameters for Bob's side of the Signal Protocol handshake."""
    ...

# Storage Classes
class PersistentStorageBase:
    """Base class for persistent storage implementations."""

    def __init__(self) -> None: ...

    # Identity store methods
    def save_identity(self, address_name: str, identity_key: IdentityKey) -> bool: ...
    def get_identity(self, address_name: str) -> Optional[IdentityKey]: ...

    # Session store methods
    def store_session(self, address_name: str, session_record: SessionRecord) -> None: ...
    def load_session(self, address_name: str) -> Optional[SessionRecord]: ...

    # PreKey store methods
    def get_pre_key(self, pre_key_id: int) -> PreKeyRecord: ...
    def save_pre_key(self, pre_key_id: int, pre_key_record: PreKeyRecord) -> None: ...
    def remove_pre_key(self, pre_key_id: int) -> None: ...

    # Signed PreKey store methods
    def get_signed_pre_key(self, signed_pre_key_id: int) -> SignedPreKeyRecord: ...
    def save_signed_pre_key(self, signed_pre_key_id: int, signed_pre_key_record: SignedPreKeyRecord) -> None: ...

    # Sender key store methods
    def store_sender_key(self, sender_key_name: str, sender_key_record: SenderKeyRecord) -> None: ...
    def load_sender_key(self, sender_key_name: str) -> Optional[SenderKeyRecord]: ...

class InMemSignalProtocolStore:
    """In-memory implementation of Signal Protocol storage."""

    def __init__(
        self,
        key_pair: IdentityKeyPair,
        registration_id: int,
        persistent_storage: Optional[PersistentStorageBase] = None
    ) -> None: ...

    # Identity store methods
    def get_identity_key_pair(self) -> IdentityKeyPair: ...
    def get_local_registration_id(self) -> int: ...
    def save_identity(self, address: ProtocolAddress, identity: IdentityKey) -> bool: ...
    def get_identity(self, address: ProtocolAddress) -> Optional[IdentityKey]: ...

    # Session store methods
    def load_session(self, address: ProtocolAddress) -> Optional[SessionRecord]: ...
    def store_session(self, address: ProtocolAddress, record: SessionRecord) -> None: ...

    # PreKey store methods
    def get_pre_key(self, id: int) -> PreKeyRecord: ...
    def save_pre_key(self, id: int, record: PreKeyRecord) -> None: ...
    def remove_pre_key(self, id: int) -> None: ...

    # Signed PreKey store methods
    def get_signed_pre_key(self, id: int) -> SignedPreKeyRecord: ...
    def save_signed_pre_key(self, id: int, record: SignedPreKeyRecord) -> None: ...

    # Sender key store methods
    def store_sender_key(self, sender_key_name: SenderKeyName, record: SenderKeyRecord) -> None: ...
    def load_sender_key(self, sender_key_name: SenderKeyName) -> Optional[SenderKeyRecord]: ...

# Top-level functions
def generate_keypair() -> Tuple[bytes, bytes]:
    """Generate a new key pair and return as (public_key_bytes, private_key_bytes)."""
    ...

def verify_signature(public_key: PublicKey, message: bytes, signature: bytes) -> bool:
    """Verify a signature using a public key."""
    ...

# Session functions
def process_prekey_bundle(
    remote_address: ProtocolAddress,
    session_store: InMemSignalProtocolStore,
    prekey_bundle: PreKeyBundle,
) -> None:
    """Process a prekey bundle to establish a session."""
    ...

# Session cipher functions
def message_encrypt(
    store: InMemSignalProtocolStore,
    remote_address: ProtocolAddress,
    message: bytes,
) -> CiphertextMessage:
    """Encrypt a message using Signal Protocol."""
    ...

def message_decrypt(
    store: InMemSignalProtocolStore,
    remote_address: ProtocolAddress,
    message: Union[PreKeySignalMessage, SignalMessage],
) -> bytes:
    """Decrypt a message using Signal Protocol."""
    ...

# Group cipher functions
def group_encrypt(
    protocol_store: InMemSignalProtocolStore,
    sender_key_id: SenderKeyName,
    plaintext: bytes,
) -> bytes:
    """Encrypt a message for group delivery."""
    ...

def group_decrypt(
    skm_bytes: bytes,
    protocol_store: InMemSignalProtocolStore,
    sender_key_id: SenderKeyName,
) -> bytes:
    """Decrypt a group message."""
    ...

def process_sender_key_distribution_message(
    sender_key_name: SenderKeyName,
    skdm: SenderKeyDistributionMessage,
    protocol_store: InMemSignalProtocolStore,
) -> None:
    """Process a sender key distribution message."""
    ...

def create_sender_key_distribution_message(
    sender_key_name: SenderKeyName,
    protocol_store: InMemSignalProtocolStore,
) -> SenderKeyDistributionMessage:
    """Create a sender key distribution message."""
    ...

# Submodules with correct types
class AddressModule:
    ProtocolAddress: type[ProtocolAddress]

class CurveModule:
    KeyPair: type[KeyPair]
    PublicKey: type[PublicKey]
    PrivateKey: type[PrivateKey]
    generate_keypair: type[generate_keypair]
    verify_signature: type[verify_signature]

class ErrorModule:
    SignalProtocolException: type[SignalProtocolException]

class FingerprintModule:
    Fingerprint: type[Fingerprint]

class GroupCipherModule:
    group_encrypt: type[group_encrypt]
    group_decrypt: type[group_decrypt]
    process_sender_key_distribution_message: type[process_sender_key_distribution_message]
    create_sender_key_distribution_message: type[create_sender_key_distribution_message]

class IdentityKeyModule:
    IdentityKey: type[IdentityKey]
    IdentityKeyPair: type[IdentityKeyPair]

class ProtocolModule:
    CiphertextMessage: type[CiphertextMessage]
    PreKeySignalMessage: type[PreKeySignalMessage]
    SignalMessage: type[SignalMessage]
    SenderKeyDistributionMessage: type[SenderKeyDistributionMessage]

class RatchetModule:
    BobSignalProtocolParameters: type[BobSignalProtocolParameters]

class SealedSenderModule:
    ServerCertificate: type[ServerCertificate]
    SenderCertificate: type[SenderCertificate]
    UnidentifiedSenderMessageContent: type[UnidentifiedSenderMessageContent]

class SenderKeysModule:
    SenderKeyName: type[SenderKeyName]
    SenderKeyRecord: type[SenderKeyRecord]

class SessionModule:
    process_prekey_bundle: type[process_prekey_bundle]

class SessionCipherModule:
    message_encrypt: type[message_encrypt]
    message_decrypt: type[message_decrypt]

class StateModule:
    SessionRecord: type[SessionRecord]
    PreKeyRecord: type[PreKeyRecord]
    SignedPreKeyRecord: type[SignedPreKeyRecord]
    PreKeyBundle: type[PreKeyBundle]

class StorageModule:
    PersistentStorageBase: type[PersistentStorageBase]
    InMemSignalProtocolStore: type[InMemSignalProtocolStore]

# Submodules
address: AddressModule
curve: CurveModule
error: ErrorModule
fingerprint: FingerprintModule
group_cipher: GroupCipherModule
identity_key: IdentityKeyModule
protocol: ProtocolModule
ratchet: RatchetModule
sealed_sender: SealedSenderModule
sender_keys: SenderKeysModule
session: SessionModule
session_cipher: SessionCipherModule
state: StateModule
storage: StorageModule