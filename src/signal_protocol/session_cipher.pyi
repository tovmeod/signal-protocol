# Typing stub for signal_protocol.session_cipher module
from ._signal_protocol import session_cipher as _session_cipher_impl

# Functions are directly attributes of the _session_cipher_impl object
message_encrypt = _session_cipher_impl.message_encrypt
message_decrypt = _session_cipher_impl.message_decrypt

__all__ = ["message_encrypt", "message_decrypt"]
