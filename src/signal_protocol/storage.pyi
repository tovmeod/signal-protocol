# Typing stub for signal_protocol.storage module
from ._signal_protocol import storage as _storage_impl
from ._signal_protocol import (
    PersistentStorageBase as _PersistentStorageBaseType,
    InMemSignalProtocolStore as _InMemSignalProtocolStoreType,
)

PersistentStorageBase: type[_PersistentStorageBaseType] = _storage_impl.PersistentStorageBase
InMemSignalProtocolStore: type[_InMemSignalProtocolStoreType] = _storage_impl.InMemSignalProtocolStore

__all__ = ["PersistentStorageBase", "InMemSignalProtocolStore"]
