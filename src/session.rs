#![allow(dead_code)]

use pyo3::prelude::*;

use futures::executor::block_on;
use rand::rngs::OsRng;

use crate::address::ProtocolAddress;
use crate::error::Result;
use crate::protocol::PreKeySignalMessage;
use crate::state::{PreKeyBundle, PreKeyId, SessionRecord};
use crate::storage::InMemSignalProtocolStore;

#[pyfunction]
pub fn process_prekey(
    message: &PreKeySignalMessage,
    remote_address: &ProtocolAddress,
    session_record: &mut SessionRecord,
    protocol_store: &mut InMemSignalProtocolStore,
) -> Result<Option<PreKeyId>> {
    let store_ptr = protocol_store as *mut InMemSignalProtocolStore;
    let identity_store = unsafe { &mut *store_ptr } as &mut dyn libsignal_protocol_rust::IdentityKeyStore;
    let pre_key_store = unsafe { &mut *store_ptr } as &mut dyn libsignal_protocol_rust::PreKeyStore;
    let signed_pre_key_store = unsafe { &mut *store_ptr } as &mut dyn libsignal_protocol_rust::SignedPreKeyStore;

    let result = block_on(libsignal_protocol_rust::process_prekey(
        &message.data,
        &remote_address.state,
        &mut session_record.state,
        identity_store,
        pre_key_store,
        signed_pre_key_store,
        None,
    ))?;
    Ok(result)
}

#[pyfunction]
pub fn process_prekey_bundle(
    remote_address: ProtocolAddress,
    protocol_store: &mut InMemSignalProtocolStore,
    bundle: PreKeyBundle,
) -> Result<()> {
    let mut csprng = OsRng;
    let store_ptr = protocol_store as *mut InMemSignalProtocolStore;
    let session_store = unsafe { &mut *store_ptr } as &mut dyn libsignal_protocol_rust::SessionStore;
    let identity_store = unsafe { &mut *store_ptr } as &mut dyn libsignal_protocol_rust::IdentityKeyStore;

    block_on(libsignal_protocol_rust::process_prekey_bundle(
        &remote_address.state,
        session_store,
        identity_store,
        &bundle.state,
        &mut csprng,
        None,
    ))?;
    Ok(())
}

pub fn init_submodule(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(process_prekey, module)?)?;
    module.add_function(wrap_pyfunction!(process_prekey_bundle, module)?)?;
    Ok(())
}
