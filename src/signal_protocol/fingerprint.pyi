# Typing stub for signal_protocol.fingerprint module
# Direct class definition instead of type alias

from ._signal_protocol.fingerprint import Fingerprint as _FingerprintImpl

from .identity_key import IdentityKey

class Fingerprint(_FingerprintImpl):
    """Security fingerprint for identity verification."""

    def __init__(
        self,
        version: int,
        iterations: int,
        local_id: bytes,
        local_key: IdentityKey,
        remote_id: bytes,
        remote_key: IdentityKey,
    ) -> None: ...

    def display_string(self) -> str: ...
    def compare(self, combined: bytes) -> bool: ...
    def serialize(self) -> bytes: ...
    def __str__(self) -> str: ...
    def __repr__(self) -> str: ...

__all__ = ["Fingerprint"]
