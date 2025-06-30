use futures::executor::block_on;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

use crate::address::ProtocolAddress;
use crate::error::{Result, SignalProtocolError};
use crate::identity_key::{IdentityKey, IdentityKeyPair};
use crate::sender_keys::{SenderKeyName, SenderKeyRecord};
use crate::state::{PreKeyId, PreKeyRecord, SessionRecord, SignedPreKeyId, SignedPreKeyRecord};

// traits
use libsignal_protocol_rust::{
    IdentityKeyStore, PreKeyStore, SenderKeyStore, SessionStore, SignedPreKeyStore,
};

#[pyclass(subclass)]
#[derive(Clone)]
pub struct InMemSignalProtocolStore {
    pub store: libsignal_protocol_rust::InMemSignalProtocolStore,
}

#[pymethods]
impl InMemSignalProtocolStore {
    #[new]
    fn new(key_pair: &IdentityKeyPair, registration_id: u32) -> PyResult<InMemSignalProtocolStore> {
        match libsignal_protocol_rust::InMemSignalProtocolStore::new(key_pair.key, registration_id)
        {
            Ok(store) => Ok(Self { store }),
            Err(err) => Err(SignalProtocolError::new_err(err)),
        }
    }

    #[getter]
    fn get_sessions_internal_map(&self, py: Python) -> PyResult<PyObject> {
        // This assumes the internal store has a `sessions` field that is a HashMap
        // wrapped in an RwLock or Mutex. The exact access path might need adjustment
        // based on the actual structure of `libsignal_protocol_rust::InMemSignalProtocolStore`.
        let store_guard = self.store.session_store.read().unwrap(); // Assuming RwLock
        let sessions_map_rust = &store_guard.sessions;

        let py_dict = PyDict::new(py);
        for (address, record_bytes) in sessions_map_rust.iter() {
            // ProtocolAddress has __str__ through PyObjectProtocol
            let py_address_str = address.__str__()?;
            let py_record_bytes = PyBytes::new(py, record_bytes);
            py_dict.set_item(py_address_str, py_record_bytes)?;
        }
        Ok(py_dict.into())
    }
}

/// libsignal_protocol_rust::IdentityKeyStore
/// is_trusted_identity is not implemented (it requries traits::Direction as arg)
#[pymethods]
impl InMemSignalProtocolStore {
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
        Ok(block_on(self.store.identity_store.save_identity(
            &address.state,
            &identity.key,
            None,
        ))?)
    }

    fn get_identity(&self, address: &ProtocolAddress) -> Result<Option<IdentityKey>> {
        let key = block_on(self.store.identity_store.get_identity(&address.state, None))?;

        match key {
            Some(key) => Ok(Some(IdentityKey { key })),
            None => Ok(None),
        }
    }
}

/// libsignal_protocol_rust::SessionStore
#[pymethods]
impl InMemSignalProtocolStore {
    pub fn load_session(&self, address: &ProtocolAddress) -> Result<Option<SessionRecord>> {
        let session = block_on(self.store.load_session(&address.state, None))?;

        match session {
            None => Ok(None),
            Some(state) => Ok(Some(SessionRecord { state })),
        }
    }

    fn store_session(&mut self, address: &ProtocolAddress, record: &SessionRecord) -> Result<()> {
        block_on(
            self.store
                .store_session(&address.state, &record.state, None),
        )?;
        Ok(())
    }
}

/// libsignal_protocol_rust::PreKeyStore
#[pymethods]
impl InMemSignalProtocolStore {
    fn get_pre_key(&self, id: PreKeyId) -> Result<PreKeyRecord> {
        let state = block_on(self.store.pre_key_store.get_pre_key(id, None))?;
        Ok(PreKeyRecord { state })
    }

    fn save_pre_key(&mut self, id: PreKeyId, record: &PreKeyRecord) -> Result<()> {
        block_on(
            self.store
                .pre_key_store
                .save_pre_key(id, &record.state, None),
        )?;
        Ok(())
    }

    fn remove_pre_key(&mut self, id: PreKeyId) -> Result<()> {
        block_on(self.store.pre_key_store.remove_pre_key(id, None))?;
        Ok(())
    }
}

/// libsignal_protocol_rust::SignedPreKeyStore
#[pymethods]
impl InMemSignalProtocolStore {
    fn get_signed_pre_key(&self, id: SignedPreKeyId) -> Result<SignedPreKeyRecord> {
        let state = block_on(self.store.get_signed_pre_key(id, None))?;
        Ok(SignedPreKeyRecord { state })
    }

    fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<()> {
        block_on(
            self.store
                .save_signed_pre_key(id, &record.state.to_owned(), None),
        )?;
        Ok(())
    }
}

/// libsignal_protocol_rust::SenderKeyStore
#[pymethods]
impl InMemSignalProtocolStore {
    fn store_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        record: &SenderKeyRecord,
    ) -> Result<()> {
        Ok(block_on(self.store.store_sender_key(
            &sender_key_name.state,
            &record.state,
            None,
        ))?)
    }

    fn load_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
    ) -> Result<Option<SenderKeyRecord>> {
        match block_on(self.store.load_sender_key(&sender_key_name.state, None))? {
            Some(state) => Ok(Some(SenderKeyRecord { state })),
            None => Ok(None),
        }
    }
}

/// The storage traits are not exposed as part of the API (this is not supported by Pyo3)
///
/// Python classes for InMemSenderKeyStore, InMemSessionStore, InMemIdentityKeyStore, InMemPreKeyStore
/// or InMemSignedPreKeyStore are not exposed.
/// One will need to operate on the InMemSignalProtocolStore instead.
pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<InMemSignalProtocolStore>()?;
    Ok(())
}
