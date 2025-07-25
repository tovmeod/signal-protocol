# Typing stub for signal_protocol.session module
# Direct function definitions instead of direct imports

from typing import Optional
from ._signal_protocol.session import (
    process_prekey as _process_prekey,
    process_prekey_bundle as _process_prekey_bundle,
)

from .address import ProtocolAddress
from .protocol import PreKeySignalMessage
from .state import PreKeyBundle, SessionRecord
from .storage import InMemSignalProtocolStore

def process_prekey(
    message: PreKeySignalMessage,
    remote_address: ProtocolAddress,
    session_record: SessionRecord,
    protocol_store: InMemSignalProtocolStore,
) -> Optional[int]:
    """Process a prekey Signal message."""
    ...

def process_prekey_bundle(
    remote_address: ProtocolAddress,
    session_store: InMemSignalProtocolStore,
    prekey_bundle: PreKeyBundle,
) -> None:
    """Process a prekey bundle to establish a session."""
    ...

__all__ = ["process_prekey", "process_prekey_bundle"]
