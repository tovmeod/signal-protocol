# Typing stub for signal_protocol.fingerprint module
from ._signal_protocol import fingerprint as _fingerprint_impl
from ._signal_protocol import Fingerprint as _FingerprintType

Fingerprint: type[_FingerprintType] = _fingerprint_impl.Fingerprint

__all__ = ["Fingerprint"]
