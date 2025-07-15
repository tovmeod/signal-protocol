#![allow(dead_code)]

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use futures::executor::block_on;
use rand::rngs::OsRng;

use crate::address::ProtocolAddress;
use crate::error::Result;
use crate::protocol::{CiphertextMessage, PreKeySignalMessage, SignalMessage};
use crate::storage::InMemSignalProtocolStore;

#[pyfunction]
pub fn message_encrypt(
    protocol_store: &mut InMemSignalProtocolStore,
    remote_address: &ProtocolAddress,
    msg: &[u8],
) -> Result<CiphertextMessage> {
    // Now use protocol_store directly, which will use our trait implementations
    // that handle persistent storage properly
    
    // We need to create separate trait object references to avoid double borrowing
    // This is safe because the async function won't execute concurrently
    let store_ptr = protocol_store as *mut InMemSignalProtocolStore;
    let session_store = unsafe { &mut *store_ptr } as &mut dyn libsignal_protocol_rust::SessionStore;
    let identity_store = unsafe { &mut *store_ptr } as &mut dyn libsignal_protocol_rust::IdentityKeyStore;
    
    let ciphertext = block_on(libsignal_protocol_rust::message_encrypt(
        msg,
        &remote_address.state,
        session_store, // <- This now uses our wrapper that handles persistent storage!
        identity_store, // <- Identity store wrapper
        None,
    ))?;
    Ok(CiphertextMessage::new(ciphertext))
}

#[pyfunction]
pub fn message_decrypt(
    py: Python<'_>,
    protocol_store: &mut InMemSignalProtocolStore,
    remote_address: &ProtocolAddress,
    msg: &CiphertextMessage,
) -> Result<PyObject> {
    let mut csprng = OsRng;
    let store_ptr = protocol_store as *mut InMemSignalProtocolStore;
    let session_store = unsafe { &mut *store_ptr } as &mut dyn libsignal_protocol_rust::SessionStore;
    let identity_store = unsafe { &mut *store_ptr } as &mut dyn libsignal_protocol_rust::IdentityKeyStore;
    let pre_key_store = unsafe { &mut *store_ptr } as &mut dyn libsignal_protocol_rust::PreKeyStore;
    let signed_pre_key_store = unsafe { &mut *store_ptr } as &mut dyn libsignal_protocol_rust::SignedPreKeyStore;
    let plaintext = block_on(libsignal_protocol_rust::message_decrypt(
        &msg.data,
        &remote_address.state,
        session_store,
        identity_store,
        pre_key_store,
        signed_pre_key_store,
        &mut csprng,
        None,
    ))?;
    Ok(PyBytes::new(py, &plaintext).into())
}

#[pyfunction]
pub fn message_decrypt_prekey(
    py: Python<'_>,
    protocol_store: &mut InMemSignalProtocolStore,
    remote_address: &ProtocolAddress,
    msg: &PreKeySignalMessage,
) -> Result<PyObject> {
    let mut csprng = OsRng;
    let store_ptr = protocol_store as *mut InMemSignalProtocolStore;
    let session_store = unsafe { &mut *store_ptr } as &mut dyn libsignal_protocol_rust::SessionStore;
    let identity_store = unsafe { &mut *store_ptr } as &mut dyn libsignal_protocol_rust::IdentityKeyStore;
    let pre_key_store = unsafe { &mut *store_ptr } as &mut dyn libsignal_protocol_rust::PreKeyStore;
    let signed_pre_key_store = unsafe { &mut *store_ptr } as &mut dyn libsignal_protocol_rust::SignedPreKeyStore;
    let plaintext = block_on(libsignal_protocol_rust::message_decrypt_prekey(
        &msg.data,
        &remote_address.state,
        session_store,
        identity_store,
        pre_key_store,
        signed_pre_key_store,
        &mut csprng,
        None,
    ))?;
    Ok(PyBytes::new(py, &plaintext).into())
}

#[pyfunction]
pub fn message_decrypt_signal(
    py: Python<'_>,
    protocol_store: &mut InMemSignalProtocolStore,
    remote_address: &ProtocolAddress,
    msg: &SignalMessage,
) -> Result<PyObject> {
    let mut csprng = OsRng;
    let store_ptr = protocol_store as *mut InMemSignalProtocolStore;
    let session_store = unsafe { &mut *store_ptr } as &mut dyn libsignal_protocol_rust::SessionStore;
    let identity_store = unsafe { &mut *store_ptr } as &mut dyn libsignal_protocol_rust::IdentityKeyStore;
    let plaintext = block_on(libsignal_protocol_rust::message_decrypt_signal(
        &msg.data,
        &remote_address.state,
        session_store,
        identity_store,
        &mut csprng,
        None,
    ))?;
    Ok(PyBytes::new(py, &plaintext).into())
}

pub fn init_submodule(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(message_encrypt, module)?)?;
    module.add_function(wrap_pyfunction!(message_decrypt, module)?)?;
    module.add_function(wrap_pyfunction!(message_decrypt_prekey, module)?)?;
    module.add_function(wrap_pyfunction!(message_decrypt_signal, module)?)?;
    Ok(())
}
