# Typing stub for signal_protocol.sealed_sender module
# Direct class definitions instead of type aliases

from ._signal_protocol.sealed_sender import (
    ServerCertificate as _ServerCertificateImpl,
    SenderCertificate as _SenderCertificateImpl,
    UnidentifiedSenderMessageContent as _UnidentifiedSenderMessageContentImpl,
)

from .curve import PublicKey, PrivateKey

class ServerCertificate(_ServerCertificateImpl):
    """Certificate for sealed sender server validation."""

    def __init__(self, key_id: int, server_key: PublicKey, trust_root: PrivateKey) -> None: ...
    def serialized(self) -> bytes: ...
    @staticmethod
    def deserialize(data: bytes) -> 'ServerCertificate': ...
    def validate(self, trust_root: PublicKey) -> bool: ...

class SenderCertificate(_SenderCertificateImpl):
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
    def deserialize(data: bytes) -> 'SenderCertificate': ...
    def validate(self, trust_root: PublicKey, validation_time: int) -> bool: ...

class UnidentifiedSenderMessageContent(_UnidentifiedSenderMessageContentImpl):
    """Content of an unidentified sender message."""

    def message(self) -> bytes: ...
    def sender_uuid(self) -> str: ...
    def sender_e164(self) -> str: ...
    def device_id(self) -> int: ...

__all__ = [
    "ServerCertificate",
    "SenderCertificate",
    "UnidentifiedSenderMessageContent",
]
