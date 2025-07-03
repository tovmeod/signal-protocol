# Typing stub for signal_protocol.session module
from ._signal_protocol import session as _session_impl

# Functions are directly attributes of the _session_impl object
process_prekey_bundle = _session_impl.process_prekey_bundle

__all__ = ["process_prekey_bundle"]
