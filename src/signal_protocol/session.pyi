# Typing stub for signal_protocol.session module
# Direct function definition instead of direct import

from ._signal_protocol.session import process_prekey_bundle as _process_prekey_bundle

from .address import ProtocolAddress
from .storage import InMemSignalProtocolStore
from .state import PreKeyBundle

def process_prekey_bundle(
    remote_address: ProtocolAddress,
    session_store: InMemSignalProtocolStore,
    prekey_bundle: PreKeyBundle,
) -> None:
    """Process a prekey bundle to establish a session."""
    ...

__all__ = ["process_prekey_bundle"]
