use futures::executor::block_on;
use pyo3::prelude::*;
use log::{debug, error};

use crate::address::ProtocolAddress;
use crate::error::{Result, SignalProtocolError};
use crate::identity_key::{IdentityKey, IdentityKeyPair};
use crate::sender_keys::{SenderKeyName, SenderKeyRecord};
use crate::state::{PreKeyId, PreKeyRecord, SessionRecord, SignedPreKeyId, SignedPreKeyRecord};

// traits
use libsignal_protocol_rust::{
    IdentityKeyStore, PreKeyStore, SenderKeyStore, SessionStore, SignedPreKeyStore,
};

/// Protocol interface for persistent storage that users can inherit from in Python
#[pyclass(subclass)]
pub struct PersistentStorageProtocol {
}

#[pymethods]
impl PersistentStorageProtocol {
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

    // Cleanup method
    fn close(&self) -> PyResult<()> {
        debug!("Closing PersistentStorageProtocol - base implementation does nothing");
        Ok(())
    }
}

// Custom Clone implementation for InMemSignalProtocolStore
#[pyclass]
pub struct InMemSignalProtocolStore {
    pub store: libsignal_protocol_rust::InMemSignalProtocolStore,
    py_storage: Option<Py<PersistentStorageProtocol>>,
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
        persistent_storage: Option<Py<PersistentStorageProtocol>>
    ) -> PyResult<InMemSignalProtocolStore> {
        debug!("Creating new InMemSignalProtocolStore with registration_id: {}", registration_id);
        if persistent_storage.is_some() {
            debug!("InMemSignalProtocolStore created with persistent storage backend");
        } else {
            debug!("InMemSignalProtocolStore created without persistent storage backend");
        }

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
        debug!("get_identity_key_pair called");
        let key = block_on(self.store.identity_store.get_identity_key_pair(None))?;
        Ok(IdentityKeyPair { key })
    }

    fn get_local_registration_id(&self) -> Result<u32> {
        debug!("get_local_registration_id called");
        Ok(block_on(
            self.store.identity_store.get_local_registration_id(None),
        )?)
    }

    fn save_identity(&mut self, address: &ProtocolAddress, identity: &IdentityKey) -> Result<bool> {
        // Use the trait implementation which handles both cache and persistent storage
        use libsignal_protocol_rust::IdentityKeyStore;
        match block_on(IdentityKeyStore::save_identity(self, &address.state, &identity.key, None)) {
            Ok(result) => Ok(result),
            Err(e) => Err(crate::error::SignalProtocolError::new(e)),
        }
    }

    fn get_identity(&self, address: &ProtocolAddress) -> Result<Option<IdentityKey>> {
        // First check cache
        let cached_result = block_on(self.store.identity_store.get_identity(
            &address.state,
            None,
        ));

        match cached_result {
            Ok(Some(identity)) => {
                // Found in cache
                Ok(Some(IdentityKey { key: identity }))
            },
            Ok(None) => {
                // Not in cache, check persistent storage if available
                if let Some(ref py_storage) = self.py_storage {
                    Python::with_gil(|py| {
                        let storage_obj = py_storage.bind(py);
                        match crate::pymethod_caller::call_get_identity(py, storage_obj, address) {
                            Ok(identity) => Ok(identity),
                            Err(err) => {
                                error!("Error calling persistent_storage.get_identity: {}", err);
                                Ok(None) // Return None on error instead of failing
                            }
                        }
                    })
                } else {
                    Ok(None)
                }
            },
            Err(err) => Err(SignalProtocolError::from(err).into())
        }
    }

    fn store_session(&mut self, address: &ProtocolAddress, record: &SessionRecord) -> Result<()> {
        // Always store in cache
        block_on(self.store.session_store.store_session(
            &address.state,
            &record.state,
            None,
        ))?;

        // Also store in persistent storage if available
        if let Some(ref py_storage) = self.py_storage {
            Python::with_gil(|py| {
                let storage_obj = py_storage.bind(py);
                match crate::pymethod_caller::call_store_session(py, storage_obj, address, record) {
                    Ok(_) => {
                        debug!("persistent_storage.store_session completed successfully");
                        Ok(())
                    },
                    Err(err) => {
                        error!("Error calling persistent_storage.store_session: {}", err);
                        Err(SignalProtocolError::from(
                            libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                                format!("Python error: {}", err)
                            )
                        ).into())
                    }
                }
            })
        } else {
            Ok(())
        }
    }

    /// Check if a session exists for the given address
    /// This is a lightweight operation that doesn't load session data
    /// todo: we can delete this, we don't need to implement this, it isn't on the trait
    fn contains_session(&self, address: &ProtocolAddress) -> Result<bool> {
        // First check cache
        let cached_result = block_on(self.store.session_store.load_session(
            &address.state,
            None,
        ));

        match cached_result {
            Ok(Some(_)) => {
                // Found in cache
                Ok(true)
            },
            Ok(None) => {
                // Not in cache, check persistent storage if available
                if let Some(ref py_storage) = self.py_storage {
                    Python::with_gil(|py| {
                        let storage_obj = py_storage.bind(py);
                        // We need to add a call_contains_session function
                        match crate::pymethod_caller::call_contains_session(py, storage_obj, address) {
                            Ok(contains) => Ok(contains),
                            Err(err) => {
                                error!("Error calling persistent_storage.contains_session: {}", err);
                                Ok(false) // Return false on error instead of failing
                            }
                        }
                    })
                } else {
                    Ok(false)
                }
            },
            Err(_) => Ok(false) // Return false on error
        }
    }

    pub fn load_session(&self, address: &ProtocolAddress) -> Result<Option<SessionRecord>> {
        // First check cache
        let cached_result = block_on(self.store.session_store.load_session(
            &address.state,
            None,
        ));

        match cached_result {
            Ok(Some(session)) => {
                // Found in cache
                Ok(Some(SessionRecord { state: session }))
            },
            Ok(None) => {
                // Not in cache, check persistent storage if available
                if let Some(ref py_storage) = self.py_storage {
                    Python::with_gil(|py| {
                        let storage_obj = py_storage.bind(py);
                        match crate::pymethod_caller::call_load_session(py, storage_obj, address) {
                            Ok(session) => Ok(session),
                            Err(err) => {
                                error!("Error calling persistent_storage.load_session: {}", err);
                                Ok(None) // Return None on error instead of failing
                            }
                        }
                    })
                } else {
                    Ok(None)
                }
            },
            Err(err) => Err(SignalProtocolError::from(err).into())
        }
    }

    fn save_pre_key(&mut self, id: PreKeyId, record: &PreKeyRecord) -> Result<()> {
        // Use the trait implementation which handles both cache and persistent storage
        use libsignal_protocol_rust::PreKeyStore;
        match block_on(PreKeyStore::save_pre_key(self, id, &record.state, None)) {
            Ok(()) => Ok(()),
            Err(e) => Err(crate::error::SignalProtocolError::new(e)),
        }
    }

    fn get_pre_key(&self, id: PreKeyId) -> Result<PreKeyRecord> {
        // First check cache
        let cached_result = block_on(self.store.pre_key_store.get_pre_key(id, None));

        match cached_result {
            Ok(pre_key) => {
                // Found in cache
                Ok(PreKeyRecord { state: pre_key })
            },
            Err(_) => {
                // Not in cache, check persistent storage if available
                if let Some(ref py_storage) = self.py_storage {
                    Python::with_gil(|py| {
                        let storage_obj = py_storage.bind(py);
                        match crate::pymethod_caller::call_get_pre_key(py, storage_obj, id) {
                            Ok(pre_key) => Ok(pre_key),
                            Err(err) => {
                                error!("Error calling persistent_storage.get_pre_key: {}", err);
                                Err(SignalProtocolError::from(
                                    libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                                        format!("PreKey {} not found", id)
                                    )
                                ).into())
                            }
                        }
                    })
                } else {
                    Err(SignalProtocolError::from(
                        libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                            format!("PreKey {} not found", id)
                        )
                    ).into())
                }
            }
        }
    }

    fn remove_pre_key(&mut self, id: PreKeyId) -> Result<()> {
        // Use the trait implementation which handles both cache and persistent storage
        use libsignal_protocol_rust::PreKeyStore;
        match block_on(PreKeyStore::remove_pre_key(self, id, None)) {
            Ok(()) => Ok(()),
            Err(e) => Err(crate::error::SignalProtocolError::new(e)),
        }
    }

    fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<()> {
        // Use the trait implementation which handles both cache and persistent storage
        use libsignal_protocol_rust::SignedPreKeyStore;
        match block_on(SignedPreKeyStore::save_signed_pre_key(self, id, &record.state, None)) {
            Ok(()) => Ok(()),
            Err(e) => Err(crate::error::SignalProtocolError::new(e)),
        }
    }

    fn get_signed_pre_key(&self, id: SignedPreKeyId) -> Result<SignedPreKeyRecord> {
        // First check cache
        let cached_result = block_on(self.store.signed_pre_key_store.get_signed_pre_key(id, None));

        match cached_result {
            Ok(signed_pre_key) => {
                // Found in cache
                Ok(SignedPreKeyRecord { state: signed_pre_key })
            },
            Err(_) => {
                // Not in cache, check persistent storage if available
                if let Some(ref py_storage) = self.py_storage {
                    Python::with_gil(|py| {
                        let storage_obj = py_storage.bind(py);
                        match crate::pymethod_caller::call_get_signed_pre_key(py, storage_obj, id) {
                            Ok(signed_pre_key) => Ok(signed_pre_key),
                            Err(err) => {
                                error!("Error calling persistent_storage.get_signed_pre_key: {}", err);
                                Err(SignalProtocolError::from(
                                    libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                                        format!("SignedPreKey {} not found", id)
                                    )
                                ).into())
                            }
                        }
                    })
                } else {
                    Err(SignalProtocolError::from(
                        libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                            format!("SignedPreKey {} not found", id)
                        )
                    ).into())
                }
            }
        }
    }

    fn store_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        record: &SenderKeyRecord,
    ) -> Result<()> {
        // Always store in cache
        block_on(self.store.sender_key_store.store_sender_key(
            &sender_key_name.state,
            &record.state,
            None,
        ))?;

        // Also store in persistent storage if available
        if let Some(ref py_storage) = self.py_storage {
            Python::with_gil(|py| {
                let storage_obj = py_storage.bind(py);
                match crate::pymethod_caller::call_store_sender_key(py, storage_obj, sender_key_name, record) {
                    Ok(_) => {
                        debug!("persistent_storage.store_sender_key completed successfully");
                        Ok(())
                    },
                    Err(err) => {
                        error!("Error calling persistent_storage.store_sender_key: {}", err);
                        Err(SignalProtocolError::from(
                            libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                                format!("Python error: {}", err)
                            )
                        ).into())
                    }
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
        // First check cache
        let cached_result = block_on(self.store.sender_key_store.load_sender_key(
            &sender_key_name.state,
            None,
        ));

        match cached_result {
            Ok(Some(sender_key)) => {
                // Found in cache
                Ok(Some(SenderKeyRecord { state: sender_key }))
            },
            Ok(None) => {
                // Not in cache, check persistent storage if available
                if let Some(ref py_storage) = self.py_storage {
                    Python::with_gil(|py| {
                        let storage_obj = py_storage.bind(py);
                        match crate::pymethod_caller::call_load_sender_key(py, storage_obj, sender_key_name) {
                            Ok(sender_key) => Ok(sender_key),
                            Err(err) => {
                                error!("Error calling persistent_storage.load_sender_key: {}", err);
                                Ok(None) // Return None on error instead of failing
                            }
                        }
                    })
                } else {
                    Ok(None)
                }
            },
            Err(err) => Err(SignalProtocolError::from(err).into())
        }
    }
}

// Implement the libsignal traits for our wrapper so that core functions can use it directly
#[async_trait::async_trait(?Send)]
impl libsignal_protocol_rust::SessionStore for InMemSignalProtocolStore {
    async fn load_session(
        &self,
        address: &libsignal_protocol_rust::ProtocolAddress,
        _ctx: libsignal_protocol_rust::Context,
    ) -> std::result::Result<Option<libsignal_protocol_rust::SessionRecord>, libsignal_protocol_rust::SignalProtocolError> {
        // First check cache using the underlying store directly (no blocking)
        let cached_result = self.store.session_store.load_session(address, None).await;
        
        match cached_result {
            Ok(Some(session)) => {
                // Found in cache
                Ok(Some(session))
            },
            Ok(None) => {
                // Not in cache, check persistent storage if available
                if let Some(ref py_storage) = self.py_storage {
                    let our_address = crate::address::ProtocolAddress { state: address.clone() };
                    match Python::with_gil(|py| {
                        let storage_obj = py_storage.bind(py);
                        crate::pymethod_caller::call_load_session(py, storage_obj, &our_address)
                    }) {
                        Ok(Some(session)) => {
                            // Found in persistent storage, return it
                            // Note: We can't update the cache here since load_session has &self, not &mut self
                            // The cache will be updated when store_session is called later
                            Ok(Some(session.state))
                        },
                        Ok(None) => Ok(None),
                        Err(err) => {
                            error!("Error calling persistent_storage.load_session: {}", err);
                            Ok(None) // Return None on error instead of failing
                        }
                    }
                } else {
                    Ok(None)
                }
            },
            Err(err) => Err(err)
        }
    }

    async fn store_session(
        &mut self,
        address: &libsignal_protocol_rust::ProtocolAddress,
        record: &libsignal_protocol_rust::SessionRecord,
        _ctx: libsignal_protocol_rust::Context,
    ) -> std::result::Result<(), libsignal_protocol_rust::SignalProtocolError> {
        // Always store in cache first
        self.store.session_store.store_session(address, record, None).await?;

        // Also store in persistent storage if available
        if let Some(ref py_storage) = self.py_storage {
            let our_address = crate::address::ProtocolAddress { state: address.clone() };
            let our_record = crate::state::SessionRecord { state: record.clone() };
            
            match Python::with_gil(|py| {
                let storage_obj = py_storage.bind(py);
                crate::pymethod_caller::call_store_session(py, storage_obj, &our_address, &our_record)
            }) {
                Ok(_) => {
                    debug!("persistent_storage.store_session completed successfully");
                    Ok(())
                },
                Err(err) => {
                    error!("Error calling persistent_storage.store_session: {}", err);
                    Err(libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                        format!("Python error: {}", err)
                    ))
                }
            }
        } else {
            Ok(())
        }
    }
}

#[async_trait::async_trait(?Send)]
impl libsignal_protocol_rust::IdentityKeyStore for InMemSignalProtocolStore {
    async fn get_identity_key_pair(&self, ctx: libsignal_protocol_rust::Context) -> std::result::Result<libsignal_protocol_rust::IdentityKeyPair, libsignal_protocol_rust::SignalProtocolError> {
        // Delegate to the underlying store for identity operations
        self.store.identity_store.get_identity_key_pair(ctx).await
    }

    async fn get_local_registration_id(&self, ctx: libsignal_protocol_rust::Context) -> std::result::Result<u32, libsignal_protocol_rust::SignalProtocolError> {
        // Delegate to the underlying store for identity operations  
        self.store.identity_store.get_local_registration_id(ctx).await
    }

    async fn save_identity(
        &mut self,
        address: &libsignal_protocol_rust::ProtocolAddress,
        identity: &libsignal_protocol_rust::IdentityKey,
        ctx: libsignal_protocol_rust::Context,
    ) -> std::result::Result<bool, libsignal_protocol_rust::SignalProtocolError> {
        // Always save in cache first
        let cached_result = self.store.identity_store.save_identity(address, identity, ctx).await?;

        // Also save in persistent storage if available
        if let Some(ref py_storage) = self.py_storage {
            let our_address = crate::address::ProtocolAddress { state: address.clone() };
            let our_identity = crate::identity_key::IdentityKey { key: *identity };
            
            match Python::with_gil(|py| {
                let storage_obj = py_storage.bind(py);
                crate::pymethod_caller::call_save_identity(py, storage_obj, &our_address, &our_identity)
            }) {
                Ok(_) => {
                    debug!("persistent_storage.save_identity completed successfully");
                    Ok(cached_result)
                },
                Err(err) => {
                    error!("Error calling persistent_storage.save_identity: {}", err);
                    Err(libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                        format!("Python error: {}", err)
                    ))
                }
            }
        } else {
            Ok(cached_result)
        }
    }

    async fn is_trusted_identity(
        &self,
        address: &libsignal_protocol_rust::ProtocolAddress,
        identity: &libsignal_protocol_rust::IdentityKey,
        direction: libsignal_protocol_rust::Direction,
        ctx: libsignal_protocol_rust::Context,
    ) -> std::result::Result<bool, libsignal_protocol_rust::SignalProtocolError> {
        // Delegate to the underlying store for trust decisions
        self.store.identity_store.is_trusted_identity(address, identity, direction, ctx).await
    }

    async fn get_identity(
        &self,
        address: &libsignal_protocol_rust::ProtocolAddress,
        ctx: libsignal_protocol_rust::Context,
    ) -> std::result::Result<Option<libsignal_protocol_rust::IdentityKey>, libsignal_protocol_rust::SignalProtocolError> {
        // First check cache
        let cached_result = self.store.identity_store.get_identity(address, ctx).await;

        match cached_result {
            Ok(Some(identity)) => {
                // Found in cache
                Ok(Some(identity))
            },
            Ok(None) => {
                // Not in cache, check persistent storage if available
                if let Some(ref py_storage) = self.py_storage {
                    let our_address = crate::address::ProtocolAddress { state: address.clone() };
                    match Python::with_gil(|py| {
                        let storage_obj = py_storage.bind(py);
                        crate::pymethod_caller::call_get_identity(py, storage_obj, &our_address)
                    }) {
                        Ok(Some(identity)) => Ok(Some(identity.key)),
                        Ok(None) => Ok(None),
                        Err(err) => {
                            error!("Error calling persistent_storage.get_identity: {}", err);
                            Ok(None) // Return None on error instead of failing
                        }
                    }
                } else {
                    Ok(None)
                }
            },
            Err(err) => Err(err)
        }
    }
}

#[async_trait::async_trait(?Send)]
impl libsignal_protocol_rust::PreKeyStore for InMemSignalProtocolStore {
    async fn get_pre_key(&self, id: PreKeyId, ctx: libsignal_protocol_rust::Context) -> std::result::Result<libsignal_protocol_rust::PreKeyRecord, libsignal_protocol_rust::SignalProtocolError> {
        // First check cache
        let cached_result = self.store.pre_key_store.get_pre_key(id, ctx).await;

        match cached_result {
            Ok(pre_key) => {
                // Found in cache
                Ok(pre_key)
            },
            Err(_) => {
                // Not in cache, check persistent storage if available
                if let Some(ref py_storage) = self.py_storage {
                    match Python::with_gil(|py| {
                        let storage_obj = py_storage.bind(py);
                        crate::pymethod_caller::call_get_pre_key(py, storage_obj, id)
                    }) {
                        Ok(pre_key) => Ok(pre_key.state),
                        Err(err) => {
                            error!("Error calling persistent_storage.get_pre_key: {}", err);
                            Err(libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                                format!("PreKey {} not found", id)
                            ))
                        }
                    }
                } else {
                    Err(libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                        format!("PreKey {} not found", id)
                    ))
                }
            }
        }
    }

    async fn save_pre_key(
        &mut self,
        id: PreKeyId,
        record: &libsignal_protocol_rust::PreKeyRecord,
        _ctx: libsignal_protocol_rust::Context,
    ) -> std::result::Result<(), libsignal_protocol_rust::SignalProtocolError> {
        // Always save in cache first
        self.store.pre_key_store.save_pre_key(id, record, None).await?;

        // Also save in persistent storage if available
        if let Some(ref py_storage) = self.py_storage {
            let our_record = crate::state::PreKeyRecord { state: record.clone() };
            
            match Python::with_gil(|py| {
                let storage_obj = py_storage.bind(py);
                crate::pymethod_caller::call_save_pre_key(py, storage_obj, id, &our_record)
            }) {
                Ok(_) => {
                    debug!("persistent_storage.save_pre_key completed successfully");
                    Ok(())
                },
                Err(err) => {
                    error!("Error calling persistent_storage.save_pre_key: {}", err);
                    Err(libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                        format!("Python error: {}", err)
                    ))
                }
            }
        } else {
            Ok(())
        }
    }

    async fn remove_pre_key(&mut self, id: PreKeyId, _ctx: libsignal_protocol_rust::Context) -> std::result::Result<(), libsignal_protocol_rust::SignalProtocolError> {
        // Always remove from cache first
        self.store.pre_key_store.remove_pre_key(id, None).await?;

        // Also remove from persistent storage if available
        if let Some(ref py_storage) = self.py_storage {
            match Python::with_gil(|py| {
                let storage_obj = py_storage.bind(py);
                crate::pymethod_caller::call_remove_pre_key(py, storage_obj, id)
            }) {
                Ok(_) => {
                    debug!("persistent_storage.remove_pre_key completed successfully");
                    Ok(())
                },
                Err(err) => {
                    error!("Error calling persistent_storage.remove_pre_key: {}", err);
                    Err(libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                        format!("Python error: {}", err)
                    ))
                }
            }
        } else {
            Ok(())
        }
    }
}

#[async_trait::async_trait(?Send)]
impl libsignal_protocol_rust::SignedPreKeyStore for InMemSignalProtocolStore {
    async fn get_signed_pre_key(
        &self,
        id: SignedPreKeyId,
        _ctx: libsignal_protocol_rust::Context,
    ) -> std::result::Result<libsignal_protocol_rust::SignedPreKeyRecord, libsignal_protocol_rust::SignalProtocolError> {
        // First check cache
        let cached_result = self.store.signed_pre_key_store.get_signed_pre_key(id, None).await;

        match cached_result {
            Ok(signed_pre_key) => {
                // Found in cache
                Ok(signed_pre_key)
            },
            Err(_) => {
                // Not in cache, check persistent storage if available
                if let Some(ref py_storage) = self.py_storage {
                    match Python::with_gil(|py| {
                        let storage_obj = py_storage.bind(py);
                        crate::pymethod_caller::call_get_signed_pre_key(py, storage_obj, id)
                    }) {
                        Ok(signed_pre_key) => Ok(signed_pre_key.state),
                        Err(err) => {
                            error!("Error calling persistent_storage.get_signed_pre_key: {}", err);
                            Err(libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                                format!("SignedPreKey {} not found", id)
                            ))
                        }
                    }
                } else {
                    Err(libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                        format!("SignedPreKey {} not found", id)
                    ))
                }
            }
        }
    }

    async fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &libsignal_protocol_rust::SignedPreKeyRecord,
        _ctx: libsignal_protocol_rust::Context,
    ) -> std::result::Result<(), libsignal_protocol_rust::SignalProtocolError> {
        // Always save in cache first
        self.store.signed_pre_key_store.save_signed_pre_key(id, record, None).await?;

        // Also save in persistent storage if available
        if let Some(ref py_storage) = self.py_storage {
            let our_record = crate::state::SignedPreKeyRecord { state: record.clone() };
            
            match Python::with_gil(|py| {
                let storage_obj = py_storage.bind(py);
                crate::pymethod_caller::call_save_signed_pre_key(py, storage_obj, id, &our_record)
            }) {
                Ok(_) => {
                    debug!("persistent_storage.save_signed_pre_key completed successfully");
                    Ok(())
                },
                Err(err) => {
                    error!("Error calling persistent_storage.save_signed_pre_key: {}", err);
                    Err(libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                        format!("Python error: {}", err)
                    ))
                }
            }
        } else {
            Ok(())
        }
    }
}

#[async_trait::async_trait(?Send)]
impl libsignal_protocol_rust::SenderKeyStore for InMemSignalProtocolStore {
    async fn store_sender_key(
        &mut self,
        sender_key_name: &libsignal_protocol_rust::SenderKeyName,
        record: &libsignal_protocol_rust::SenderKeyRecord,
        _ctx: libsignal_protocol_rust::Context,
    ) -> std::result::Result<(), libsignal_protocol_rust::SignalProtocolError> {
        // Always store in cache first
        self.store.sender_key_store.store_sender_key(sender_key_name, record, None).await?;

        // Also store in persistent storage if available
        if let Some(ref py_storage) = self.py_storage {
            let our_sender_key_name = crate::sender_keys::SenderKeyName { state: sender_key_name.clone() };
            let our_record = crate::sender_keys::SenderKeyRecord { state: record.clone() };
            
            match Python::with_gil(|py| {
                let storage_obj = py_storage.bind(py);
                crate::pymethod_caller::call_store_sender_key(py, storage_obj, &our_sender_key_name, &our_record)
            }) {
                Ok(_) => {
                    debug!("persistent_storage.store_sender_key completed successfully");
                    Ok(())
                },
                Err(err) => {
                    error!("Error calling persistent_storage.store_sender_key: {}", err);
                    Err(libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                        format!("Python error: {}", err)
                    ))
                }
            }
        } else {
            Ok(())
        }
    }

    async fn load_sender_key(
        &mut self,
        sender_key_name: &libsignal_protocol_rust::SenderKeyName,
        _ctx: libsignal_protocol_rust::Context,
    ) -> std::result::Result<Option<libsignal_protocol_rust::SenderKeyRecord>, libsignal_protocol_rust::SignalProtocolError> {
        // First check cache
        let cached_result = self.store.sender_key_store.load_sender_key(sender_key_name, None).await;

        match cached_result {
            Ok(Some(sender_key)) => {
                // Found in cache
                Ok(Some(sender_key))
            },
            Ok(None) => {
                // Not in cache, check persistent storage if available
                if let Some(ref py_storage) = self.py_storage {
                    let our_sender_key_name = crate::sender_keys::SenderKeyName { state: sender_key_name.clone() };
                    match Python::with_gil(|py| {
                        let storage_obj = py_storage.bind(py);
                        crate::pymethod_caller::call_load_sender_key(py, storage_obj, &our_sender_key_name)
                    }) {
                        Ok(Some(sender_key)) => {
                            // Found in persistent storage, return it
                            // Note: We can't update the cache here since load_sender_key has &mut self
                            // but we need to avoid double borrowing for the async call
                            Ok(Some(sender_key.state))
                        },
                        Ok(None) => Ok(None),
                        Err(err) => {
                            error!("Error calling persistent_storage.load_sender_key: {}", err);
                            Ok(None) // Return None on error instead of failing
                        }
                    }
                } else {
                    Ok(None)
                }
            },
            Err(err) => Err(err)
        }
    }
}

// Now we can implement ProtocolStore since all required traits are implemented
impl libsignal_protocol_rust::ProtocolStore for InMemSignalProtocolStore {}


/// Initialize logging for the signal-protocol library
///
/// This function sets up env_logger to handle log output.
/// Call this once at the start of your application to see debug and error messages.
///
/// Environment variables:
/// - RUST_LOG=debug : Show all debug messages
/// - RUST_LOG=signal_protocol=debug : Show only signal-protocol debug messages
/// - RUST_LOG=error : Show only error messages
#[pyfunction]
pub fn init_logging() -> PyResult<()> {
    // Configure env_logger with debug level if RUST_LOG is not set
    let result = env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Debug) // Default to debug level
        .try_init();

    // Silently ignore if logger is already initialized
    let _ = result;

    // Add a debug message to confirm logging is working
    debug!("signal-protocol logging initialized successfully");

    Ok(())
}



pub fn init_submodule(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PersistentStorageProtocol>()?;
    module.add_class::<InMemSignalProtocolStore>()?;
    module.add_function(wrap_pyfunction!(init_logging, module)?)?;
    Ok(())
}