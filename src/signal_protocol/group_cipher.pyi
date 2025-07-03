# Typing stub for signal_protocol.group_cipher module
from ._signal_protocol import group_cipher as _group_cipher_impl
# Functions are directly attributes of the _group_cipher_impl object
# Type hints for these functions are already in _signal_protocol.pyi

group_encrypt = _group_cipher_impl.group_encrypt
group_decrypt = _group_cipher_impl.group_decrypt
process_sender_key_distribution_message = _group_cipher_impl.process_sender_key_distribution_message
create_sender_key_distribution_message = _group_cipher_impl.create_sender_key_distribution_message

__all__ = [
    "group_encrypt",
    "group_decrypt",
    "process_sender_key_distribution_message",
    "create_sender_key_distribution_message",
]
