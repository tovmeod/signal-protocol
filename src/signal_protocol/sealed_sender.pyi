# Typing stub for signal_protocol.sealed_sender module
from ._signal_protocol import sealed_sender as _sealed_sender_impl
from ._signal_protocol import (
    ServerCertificate as _ServerCertificateType,
    SenderCertificate as _SenderCertificateType,
    UnidentifiedSenderMessageContent as _UnidentifiedSenderMessageContentType,
)

ServerCertificate: type[_ServerCertificateType] = _sealed_sender_impl.ServerCertificate
SenderCertificate: type[_SenderCertificateType] = _sealed_sender_impl.SenderCertificate
UnidentifiedSenderMessageContent: type[_UnidentifiedSenderMessageContentType] = _sealed_sender_impl.UnidentifiedSenderMessageContent

__all__ = [
    "ServerCertificate",
    "SenderCertificate",
    "UnidentifiedSenderMessageContent",
]
