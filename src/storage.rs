use futures::executor::block_on;
use pyo3::prelude::*;

use crate::address::ProtocolAddress;
use crate::error::{Result, SignalProtocolError};
use crate::identity_key::{IdentityKey, IdentityKeyPair};
use crate::sender_keys::{SenderKeyName, SenderKeyRecord};
use crate::state::{PreKeyId, PreKeyRecord, SessionRecord, SignedPreKeyId, SignedPreKeyRecord};

// traits
use libsignal_protocol_rust::{
    IdentityKeyStore, PreKeyStore, SenderKeyStore, SessionStore, SignedPreKeyStore,
};

/// Base class for persistent storage that users can inherit from in Python
#[pyclass(subclass)]
pub struct PersistentStorageBase {
}

#[pymethods]
impl PersistentStorageBase {
    #[new]
    fn new() -> Self {
        Self {}
    }

    // Identity Store Methods
    fn save_identity(&self, _address: &ProtocolAddress, _identity_key: &IdentityKey) -> PyResult<bool> {
        Err(pyo3::exceptions::PyNotImplementedError::new_err(
            "save_identity must be implemented by subclass"
        ))
    }

    fn get_identity(&self, _address: &ProtocolAddress) -> PyResult<Option<IdentityKey>> {
        Err(pyo3::exceptions::PyNotImplementedError::new_err(
            "get_identity must be implemented by subclass"
        ))
    }

    // Session Store Methods
    fn store_session(&self, _address: &ProtocolAddress, _session_record: &SessionRecord) -> PyResult<()> {
        Err(pyo3::exceptions::PyNotImplementedError::new_err(
            "store_session must be implemented by subclass"
        ))
    }

    fn load_session(&self, _address: &ProtocolAddress) -> PyResult<Option<SessionRecord>> {
        Err(pyo3::exceptions::PyNotImplementedError::new_err(
            "load_session must be implemented by subclass"
        ))
    }

    fn contains_session(&self, address: &ProtocolAddress) -> PyResult<bool> {
        // Default implementation that uses load_session
        match self.load_session(address) {
            Ok(session) => Ok(session.is_some()),
            Err(_) => Ok(false) // Handle errors gracefully
        }
    }

    // PreKey Store Methods
    fn get_pre_key(&self, _pre_key_id: PreKeyId) -> PyResult<PreKeyRecord> {
        Err(pyo3::exceptions::PyNotImplementedError::new_err(
            "get_pre_key must be implemented by subclass"
        ))
    }

    fn save_pre_key(&self, _pre_key_id: PreKeyId, _pre_key_record: &PreKeyRecord) -> PyResult<()> {
        Err(pyo3::exceptions::PyNotImplementedError::new_err(
            "save_pre_key must be implemented by subclass"
        ))
    }

    fn remove_pre_key(&self, _pre_key_id: PreKeyId) -> PyResult<()> {
        Err(pyo3::exceptions::PyNotImplementedError::new_err(
            "remove_pre_key must be implemented by subclass"
        ))
    }

    // Signed PreKey Store Methods
    fn get_signed_pre_key(&self, _signed_pre_key_id: SignedPreKeyId) -> PyResult<SignedPreKeyRecord> {
        Err(pyo3::exceptions::PyNotImplementedError::new_err(
            "get_signed_pre_key must be implemented by subclass"
        ))
    }

    fn save_signed_pre_key(&self, _signed_pre_key_id: SignedPreKeyId, _signed_pre_key_record: &SignedPreKeyRecord) -> PyResult<()> {
        Err(pyo3::exceptions::PyNotImplementedError::new_err(
            "save_signed_pre_key must be implemented by subclass"
        ))
    }

    // Sender Key Store Methods
    fn store_sender_key(&self, _sender_key_name: &SenderKeyName, _sender_key_record: &SenderKeyRecord) -> PyResult<()> {
        Err(pyo3::exceptions::PyNotImplementedError::new_err(
            "store_sender_key must be implemented by subclass"
        ))
    }

    fn load_sender_key(&self, _sender_key_name: &SenderKeyName) -> PyResult<Option<SenderKeyRecord>> {
        Err(pyo3::exceptions::PyNotImplementedError::new_err(
            "load_sender_key must be implemented by subclass"
        ))
    }
}

// Custom Clone implementation for InMemSignalProtocolStore
#[pyclass]
pub struct InMemSignalProtocolStore {
    pub store: libsignal_protocol_rust::InMemSignalProtocolStore,
    py_storage: Option<Py<PersistentStorageBase>>,
}

impl Clone for InMemSignalProtocolStore {
    fn clone(&self) -> Self {
        let py_storage = if let Some(storage) = &self.py_storage {
            Python::with_gil(|py| Some(storage.clone_ref(py)))
        } else {
            None
        };

        Self {
            store: self.store.clone(),
            py_storage,
        }
    }
}

#[pymethods]
impl InMemSignalProtocolStore {
    #[new]
    #[pyo3(signature = (key_pair, registration_id, persistent_storage=None))]
    fn new(
        key_pair: &IdentityKeyPair,
        registration_id: u32,
        persistent_storage: Option<Py<PersistentStorageBase>>
    ) -> PyResult<InMemSignalProtocolStore> {
        match libsignal_protocol_rust::InMemSignalProtocolStore::new(key_pair.key, registration_id) {
            Ok(store) => Ok(Self { 
                store,
                py_storage: persistent_storage 
            }),
            Err(err) => Err(SignalProtocolError::new_err(err)),
        }
    }

    // Identity Store Methods
    fn get_identity_key_pair(&self) -> Result<IdentityKeyPair> {
        let key = block_on(self.store.identity_store.get_identity_key_pair(None))?;
        Ok(IdentityKeyPair { key })
    }

    fn get_local_registration_id(&self) -> Result<u32> {
        Ok(block_on(
            self.store.identity_store.get_local_registration_id(None),
        )?)
    }

    fn save_identity(&mut self, address: &ProtocolAddress, identity: &IdentityKey) -> Result<bool> {
        // Always save in cache
        let cached_result = block_on(self.store.identity_store.save_identity(
            &address.state,
            &identity.key,
            None,
        ))?;

        // Also save in persistent storage if available
        if let Some(ref py_storage) = self.py_storage {
            Python::with_gil(|py| {
                match py_storage.call_method1(py, "save_identity", (address.clone(), identity.clone())) {
                    Ok(_) => Ok(cached_result),
                    Err(err) => Err(SignalProtocolError::from(
                        libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                            format!("Python error: {}", err)
                        )
                    ).into())
                }
            })
        } else {
            Ok(cached_result)
        }
    }

    fn get_identity(&self, address: &ProtocolAddress) -> Result<Option<IdentityKey>> {
        // Try cache first
        let cached = block_on(self.store.identity_store.get_identity(&address.state, None))?;

        if cached.is_some() {
            return Ok(cached.map(|key| IdentityKey { key }));
        }

        // Fall back to persistent storage if available
        if let Some(ref py_storage) = self.py_storage {
            Python::with_gil(|py| {
                match py_storage.call_method1(py, "get_identity", (address.clone(),)) {
                    Ok(result) => {
                        match result.extract::<Option<IdentityKey>>(py) {
                            Ok(identity) => {
                                if let Some(identity) = &identity {
                                    let mut store = self.store.clone();
                                    let address_state = address.state.clone();
                                    let identity_key = identity.key.clone();
                                    block_on(store.identity_store.save_identity(&address_state, &identity_key, None))?;
                                }
                                Ok(identity)
                            },
                            Err(err) => Err(SignalProtocolError::from(
                                libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                                    format!("Python error: {}", err)
                                )
                            ).into())
                        }
                    },
                    Err(err) => Err(SignalProtocolError::from(
                        libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                            format!("Python error: {}", err)
                        )
                    ).into())
                }
            })
        } else {
            Ok(None)
        }
    }

    // Session Store Methods
    pub fn load_session(&self, address: &ProtocolAddress) -> Result<Option<SessionRecord>> {
        // Try cache first
        let cached = block_on(self.store.load_session(&address.state, None))?;

        if cached.is_some() {
            return Ok(cached.map(|state| SessionRecord { state }));
        }

        // Fall back to persistent storage if available
        if let Some(ref py_storage) = self.py_storage {
            Python::with_gil(|py| {
                match py_storage.call_method1(py, "load_session", (address.clone(),)) {
                    Ok(result) => {
                        match result.extract::<Option<SessionRecord>>(py) {
                            Ok(session) => {
                                if let Some(session) = &session {
                                    let mut store = self.store.clone();
                                    let address_state = address.state.clone();
                                    let session_state = session.state.clone();
                                    block_on(store.store_session(&address_state, &session_state, None))?;
                                }
                                Ok(session)
                            },
                            Err(err) => Err(SignalProtocolError::from(
                                libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                                    format!("Python error: {}", err)
                                )
                            ).into())
                        }
                    },
                    Err(err) => Err(SignalProtocolError::from(
                        libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                            format!("Python error: {}", err)
                        )
                    ).into())
                }
            })
        } else {
            Ok(None)
        }
    }

    fn store_session(&mut self, address: &ProtocolAddress, record: &SessionRecord) -> Result<()> {
        // Always store in cache
        block_on(
            self.store
                .store_session(&address.state, &record.state, None),
        )?;

        // Also store in persistent storage if available
        if let Some(ref py_storage) = self.py_storage {
            Python::with_gil(|py| {
                match py_storage.call_method1(py, "store_session", (address.clone(), record.clone())) {
                    Ok(_) => Ok(()),
                    Err(err) => Err(SignalProtocolError::from(
                        libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                            format!("Python error: {}", err)
                        )
                    ).into())
                }
            })
        } else {
            Ok(())
        }
    }

    /// Check if a session exists for the given address
    /// This is a lightweight operation that doesn't load session data
    fn contains_session(&self, address: &ProtocolAddress) -> Result<bool> {
        // Check if session exists in cache first (lightweight check)
        match block_on(self.store.load_session(&address.state, None)) {
            Ok(cached) => {
                if cached.is_some() {
                    return Ok(true);
                }
            },
            Err(_) => {
                // Cache errors should not propagate - just fall through to persistent storage
            }
        }

        // Fall back to persistent storage's contains_session (NOT load_session)
        if let Some(ref py_storage) = self.py_storage {
            Python::with_gil(|py| {
                match py_storage.call_method1(py, "contains_session", (address.clone(),)) {
                    Ok(result) => {
                        match result.extract::<bool>(py) {
                            Ok(exists) => Ok(exists),
                            Err(_) => Ok(false) // Handle extraction errors gracefully
                        }
                    },
                    Err(_) => Ok(false) // Handle Python call errors gracefully
                }
            })
        } else {
            Ok(false)
        }
    }

    // PreKey Store Methods
    fn get_pre_key(&self, id: PreKeyId) -> Result<PreKeyRecord> {
        // Try cache first
        match block_on(self.store.pre_key_store.get_pre_key(id, None)) {
            Ok(state) => Ok(PreKeyRecord { state }),
            Err(_) => {
                // If not in cache, try persistent storage
                if let Some(ref py_storage) = self.py_storage {
                    Python::with_gil(|py| {
                        match py_storage.call_method1(py, "get_pre_key", (id,)) {
                            Ok(result) => {
                                match result.extract::<PreKeyRecord>(py) {
                                    Ok(record) => {
                                        let mut store = self.store.clone();
                                        block_on(store.pre_key_store.save_pre_key(id, &record.state, None))?;
                                        Ok(record)
                                    },
                                    Err(err) => Err(SignalProtocolError::from(
                                        libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                                            format!("Python error: {}", err)
                                        )
                                    ).into())
                                }
                            },
                            Err(err) => Err(SignalProtocolError::from(
                                libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                                    format!("Python error: {}", err)
                                )
                            ).into())
                        }
                    })
                } else {
                    Err(SignalProtocolError::from(
                        libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                            format!("PreKey with ID {} not found", id)
                        )
                    ).into())
                }
            }
        }
    }

    fn save_pre_key(&mut self, id: PreKeyId, record: &PreKeyRecord) -> Result<()> {
        // Always save in cache
        block_on(
            self.store
                .pre_key_store
                .save_pre_key(id, &record.state, None),
        )?;

        // Also save in persistent storage if available
        if let Some(ref py_storage) = self.py_storage {
            Python::with_gil(|py| {
                match py_storage.call_method1(py, "save_pre_key", (id, record.clone())) {
                    Ok(_) => Ok(()),
                    Err(err) => Err(SignalProtocolError::from(
                        libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                            format!("Python error: {}", err)
                        )
                    ).into())
                }
            })
        } else {
            Ok(())
        }
    }

    fn remove_pre_key(&mut self, id: PreKeyId) -> Result<()> {
        // Remove from cache
        block_on(self.store.pre_key_store.remove_pre_key(id, None))?;

        // Also remove from persistent storage if available
        if let Some(ref py_storage) = self.py_storage {
            Python::with_gil(|py| {
                match py_storage.call_method1(py, "remove_pre_key", (id,)) {
                    Ok(_) => Ok(()),
                    Err(err) => Err(SignalProtocolError::from(
                        libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                            format!("Python error: {}", err)
                        )
                    ).into())
                }
            })
        } else {
            Ok(())
        }
    }

    // Signed PreKey Store Methods
    fn get_signed_pre_key(&self, id: SignedPreKeyId) -> Result<SignedPreKeyRecord> {
        // Try cache first
        match block_on(self.store.get_signed_pre_key(id, None)) {
            Ok(state) => Ok(SignedPreKeyRecord { state }),
            Err(_) => {
                // If not in cache, try persistent storage
                if let Some(ref py_storage) = self.py_storage {
                    Python::with_gil(|py| {
                        match py_storage.call_method1(py, "get_signed_pre_key", (id,)) {
                            Ok(result) => {
                                match result.extract::<SignedPreKeyRecord>(py) {
                                    Ok(record) => {
                                        let mut store = self.store.clone();
                                        block_on(store.save_signed_pre_key(id, &record.state, None))?;
                                        Ok(record)
                                    },
                                    Err(err) => Err(SignalProtocolError::from(
                                        libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                                            format!("Python error: {}", err)
                                        )
                                    ).into())
                                }
                            },
                            Err(err) => Err(SignalProtocolError::from(
                                libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                                    format!("Python error: {}", err)
                                )
                            ).into())
                        }
                    })
                } else {
                    Err(SignalProtocolError::from(
                        libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                            format!("SignedPreKey with ID {} not found", id)
                        )
                    ).into())
                }
            }
        }
    }

    fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<()> {
        // Always save in cache
        block_on(
            self.store
                .save_signed_pre_key(id, &record.state.to_owned(), None),
        )?;

        // Also save in persistent storage if available
        if let Some(ref py_storage) = self.py_storage {
            Python::with_gil(|py| {
                match py_storage.call_method1(py, "save_signed_pre_key", (id, record.clone())) {
                    Ok(_) => Ok(()),
                    Err(err) => Err(SignalProtocolError::from(
                        libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                            format!("Python error: {}", err)
                        )
                    ).into())
                }
            })
        } else {
            Ok(())
        }
    }

    // Sender Key Store Methods
    fn store_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        record: &SenderKeyRecord,
    ) -> Result<()> {
        // Always store in cache
        block_on(self.store.store_sender_key(
            &sender_key_name.state,
            &record.state,
            None,
        ))?;

        // Also store in persistent storage if available
        if let Some(ref py_storage) = self.py_storage {
            Python::with_gil(|py| {
                match py_storage.call_method1(py, "store_sender_key", (sender_key_name.clone(), record.clone())) {
                    Ok(_) => Ok(()),
                    Err(err) => Err(SignalProtocolError::from(
                        libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                            format!("Python error: {}", err)
                        )
                    ).into())
                }
            })
        } else {
            Ok(())
        }
    }


    fn load_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
    ) -> Result<Option<SenderKeyRecord>> {
        // Try cache first
        let cached = block_on(self.store.load_sender_key(&sender_key_name.state, None))?;

        if cached.is_some() {
            return Ok(cached.map(|state| SenderKeyRecord { state }));
        }

        // Fall back to persistent storage if available
        if let Some(ref py_storage) = self.py_storage {
            Python::with_gil(|py| {
                match py_storage.call_method1(py, "load_sender_key", (sender_key_name.clone(),)) {
                    Ok(result) => {
                        match result.extract::<Option<SenderKeyRecord>>(py) {
                            Ok(record) => {
                                if let Some(record) = &record {
                                    let mut store = self.store.clone();
                                    let sender_key_name_state = sender_key_name.state.clone();
                                    let record_state = record.state.clone();
                                    block_on(store.store_sender_key(&sender_key_name_state, &record_state, None))?;
                                }
                                Ok(record)
                            },
                            Err(err) => Err(SignalProtocolError::from(
                                libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                                    format!("Python error: {}", err)
                                )
                            ).into())
                        }
                    },
                    Err(err) => Err(SignalProtocolError::from(
                        libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                            format!("Python error: {}", err)
                        )
                    ).into())
                }
            })
        } else {
            Ok(None)
        }
    }
}

pub fn init_submodule(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PersistentStorageBase>()?;
    module.add_class::<InMemSignalProtocolStore>()?;
    Ok(())
}
