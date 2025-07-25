# Typing stub for signal_protocol.protocol module
# Direct class definitions instead of type aliases

from typing import Optional
from ._signal_protocol.protocol import (
    CiphertextMessage as _CiphertextMessageImpl,
    PreKeySignalMessage as _PreKeySignalMessageImpl,
    SignalMessage as _SignalMessageImpl,
    SenderKeyMessage as _SenderKeyMessageImpl,
    SenderKeyDistributionMessage as _SenderKeyDistributionMessageImpl,
)
from .curve import PublicKey, PrivateKey
from .identity_key import IdentityKey

class CiphertextMessage(_CiphertextMessageImpl):
    """Base class for encrypted messages."""

    def message_type(self) -> int: ...
    def serialize(self) -> bytes: ...

class PreKeySignalMessage(_PreKeySignalMessageImpl):
    """Message containing a pre-key Signal message."""

    def __init__(
        self,
        message_version: int,
        registration_id: int,
        pre_key_id: Optional[int],
        signed_pre_key_id: int,
        base_key: PublicKey,
        identity_key: IdentityKey,
        message: 'SignalMessage',
    ) -> None: ...

    @staticmethod
    def try_from(data: bytes) -> 'PreKeySignalMessage': ...

    def serialized(self) -> bytes: ...
    def message_version(self) -> int: ...
    def registration_id(self) -> int: ...
    def pre_key_id(self) -> Optional[int]: ...
    def signed_pre_key_id(self) -> int: ...
    def base_key(self) -> PublicKey: ...
    def identity_key(self) -> IdentityKey: ...
    def message(self) -> 'SignalMessage': ...

class SignalMessage(_SignalMessageImpl):
    """Regular Signal message (non-prekey)."""

    def __init__(
        self,
        message_version: int,
        mac_key: bytes,
        sender_ratchet_key: PublicKey,
        counter: int,
        previous_counter: int,
        ciphertext: bytes,
        sender_identity_key: IdentityKey,
        receiver_identity_key: IdentityKey,
    ) -> None: ...

    @staticmethod
    def try_from(data: bytes) -> 'SignalMessage': ...

    def message_version(self) -> int: ...
    def sender_ratchet_key(self) -> PublicKey: ...
    def counter(self) -> int: ...
    def serialized(self) -> bytes: ...
    def body(self) -> bytes: ...
    def verify_mac(
        self,
        sender_identity_key: IdentityKey,
        receiver_identity_key: IdentityKey,
        mac_key: bytes,
    ) -> bool: ...

class SenderKeyMessage(_SenderKeyMessageImpl):
    """Message encrypted with a sender key for group messaging."""

    def __init__(
        self,
        key_id: int,
        iteration: int,
        ciphertext: bytes,
        signature_key: PrivateKey,
    ) -> None: ...

    @staticmethod
    def try_from(data: bytes) -> 'SenderKeyMessage': ...

    def serialized(self) -> bytes: ...
    def message_version(self) -> int: ...
    def key_id(self) -> int: ...
    def iteration(self) -> int: ...
    def ciphertext(self) -> bytes: ...
    def verify_signature(self, signature_key: PublicKey) -> bool: ...

class SenderKeyDistributionMessage(_SenderKeyDistributionMessageImpl):
    """Message for distributing sender keys in group messaging."""

    def __init__(
        self,
        id: int,
        iteration: int,
        chain_key: bytes,
        signing_key: PublicKey,
    ) -> None: ...

    @staticmethod
    def try_from(data: bytes) -> 'SenderKeyDistributionMessage': ...

    def serialized(self) -> bytes: ...
    def message_version(self) -> int: ...
    def id(self) -> int: ...
    def iteration(self) -> int: ...
    def chain_key(self) -> bytes: ...
    def signing_key(self) -> PublicKey: ...

__all__ = [
    "CiphertextMessage",
    "PreKeySignalMessage",
    "SignalMessage",
    "SenderKeyMessage",
    "SenderKeyDistributionMessage",
]
