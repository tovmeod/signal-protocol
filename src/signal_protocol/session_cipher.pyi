# Typing stub for signal_protocol.session_cipher module
# Direct function definitions instead of direct imports
from typing import Union

from ._signal_protocol.session_cipher import (
    message_encrypt as _message_encrypt,
    message_decrypt as _message_decrypt,
    message_decrypt_prekey as _message_decrypt_prekey,
    message_decrypt_signal as _message_decrypt_signal,
)

from .address import ProtocolAddress
from .storage import InMemSignalProtocolStore
from .protocol import CiphertextMessage, PreKeySignalMessage, SignalMessage

def message_encrypt(
    protocol_store: InMemSignalProtocolStore,
    remote_address: ProtocolAddress,
    msg: bytes,
) -> CiphertextMessage:
    """Encrypt a message using Signal Protocol."""
    ...

def message_decrypt(
    protocol_store: InMemSignalProtocolStore,
    remote_address: ProtocolAddress,
    msg: CiphertextMessage,
) -> bytes:
    """Decrypt a message using Signal Protocol."""
    ...

def message_decrypt_prekey(
    protocol_store: InMemSignalProtocolStore,
    remote_address: ProtocolAddress,
    msg: PreKeySignalMessage,
) -> bytes:
    """Decrypt a PreKeySignalMessage using Signal Protocol."""
    ...

def message_decrypt_signal(
    protocol_store: InMemSignalProtocolStore,
    remote_address: ProtocolAddress,
    msg: SignalMessage,
) -> bytes:
    """Decrypt a SignalMessage using Signal Protocol."""
    ...

__all__ = ["message_encrypt", "message_decrypt", "message_decrypt_prekey", "message_decrypt_signal"]
