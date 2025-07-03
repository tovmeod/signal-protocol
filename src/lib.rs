use pyo3::prelude::*;
use pyo3::types::PyModule;
use pyo3::BoundObject;


mod address;
mod curve;
mod error;
mod fingerprint;
mod group_cipher;
mod identity_key;
mod protocol;
mod ratchet;
mod sealed_sender;
mod sender_keys;
mod session;
mod session_cipher;
mod state;
mod storage;

/// Signal Protocol in Python
///
/// This Rust extension provides Python bindings for the Rust crate
/// libsignal-protocol-rust.
///
/// Basic usage:
///
/// >>> pub, priv = signal_protocol.curve.generate_keypair()
///
/// We do not expose a Python submodule for HKDF (a module in the upstream crate).
#[pymodule]
fn _signal_protocol(py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    // Create and initialize submodules
    let address_module = PyModule::new(py, "address")?;
    address::init_submodule(&address_module.clone().into_bound())?;
    module.add("address", address_module)?;

    let curve_module = PyModule::new(py, "curve")?;
    curve::init_curve_submodule(&curve_module.clone().into_bound())?;
    module.add("curve", curve_module)?;

    let error_module = PyModule::new(py, "error")?;
    error::init_submodule(py, &error_module.clone().into_bound())?;
    module.add("error", error_module)?;

    let fingerprint_module = PyModule::new(py, "fingerprint")?;
    fingerprint::init_submodule(&fingerprint_module.clone().into_bound())?;
    module.add("fingerprint", fingerprint_module)?;

    let group_cipher_module = PyModule::new(py, "group_cipher")?;
    group_cipher::init_submodule(&group_cipher_module.clone().into_bound())?;
    module.add("group_cipher", group_cipher_module)?;

    let identity_key_module = PyModule::new(py, "identity_key")?;
    identity_key::init_submodule(&identity_key_module.clone().into_bound())?;
    module.add("identity_key", identity_key_module)?;

    let protocol_module = PyModule::new(py, "protocol")?;
    protocol::init_submodule(&protocol_module.clone().into_bound())?;
    module.add("protocol", protocol_module)?;

    let ratchet_module = PyModule::new(py, "ratchet")?;
    ratchet::init_submodule(&ratchet_module.clone().into_bound())?;
    module.add("ratchet", ratchet_module)?;

    let sealed_sender_module = PyModule::new(py, "sealed_sender")?;
    sealed_sender::init_submodule(&sealed_sender_module.clone().into_bound())?;
    module.add("sealed_sender", sealed_sender_module)?;

    let sender_keys_module = PyModule::new(py, "sender_keys")?;
    sender_keys::init_submodule(&sender_keys_module.clone().into_bound())?;
    module.add("sender_keys", sender_keys_module)?;

    let session_module = PyModule::new(py, "session")?;
    session::init_submodule(&session_module.clone().into_bound())?;
    module.add("session", session_module)?;

    let session_cipher_module = PyModule::new(py, "session_cipher")?;
    session_cipher::init_submodule(&session_cipher_module.clone().into_bound())?;
    module.add("session_cipher", session_cipher_module)?;

    let state_module = PyModule::new(py, "state")?;
    state::init_submodule(&state_module.clone().into_bound())?;
    module.add("state", state_module)?;

    let storage_module = PyModule::new(py, "storage")?;
    storage::init_submodule(&storage_module.clone().into_bound())?;
    module.add("storage", storage_module)?;

    Ok(())
}
