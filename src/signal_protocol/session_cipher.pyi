# Typing stub for signal_protocol.session_cipher module
# Direct function definitions instead of direct imports
from typing import Union

from ._signal_protocol.session_cipher import (
    message_encrypt as _message_encrypt,
    message_decrypt as _message_decrypt,
)

from .address import ProtocolAddress
from .storage import InMemSignalProtocolStore
from .protocol import CiphertextMessage, PreKeySignalMessage, SignalMessage

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

__all__ = ["message_encrypt", "message_decrypt"]
