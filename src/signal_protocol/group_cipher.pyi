# Typing stub for signal_protocol.group_cipher module
# Direct function definitions instead of direct imports

from ._signal_protocol.group_cipher import (
    group_encrypt as _group_encrypt,
    group_decrypt as _group_decrypt,
    process_sender_key_distribution_message as _process_sender_key_distribution_message,
    create_sender_key_distribution_message as _create_sender_key_distribution_message,
)

from .storage import InMemSignalProtocolStore
from .sender_keys import SenderKeyName
from .protocol import SenderKeyDistributionMessage

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

__all__ = [
    "group_encrypt",
    "group_decrypt",
    "process_sender_key_distribution_message",
    "create_sender_key_distribution_message",
]
