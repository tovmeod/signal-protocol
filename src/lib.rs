use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

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
    // Add submodules first
    let address_submod = PyModule::new(py, "address")?;
    address::init_submodule(&address_submod)?;
    module.add_submodule(&address_submod)?;

    let curve_submod = PyModule::new(py, "curve")?;
    curve::init_curve_submodule(&curve_submod)?;
    module.add_submodule(&curve_submod)?;

    let error_submod = PyModule::new(py, "error")?;
    error::init_submodule(py, &error_submod)?;
    module.add_submodule(&error_submod)?;

    let fingerprint_submod = PyModule::new(py, "fingerprint")?;
    fingerprint::init_submodule(&fingerprint_submod)?;
    module.add_submodule(&fingerprint_submod)?;

    let group_cipher_submod = PyModule::new(py, "group_cipher")?;
    group_cipher::init_submodule(&group_cipher_submod)?;
    module.add_submodule(&group_cipher_submod)?;

    let identity_key_submod = PyModule::new(py, "identity_key")?;
    identity_key::init_submodule(&identity_key_submod)?;
    module.add_submodule(&identity_key_submod)?;

    let protocol_submod = PyModule::new(py, "protocol")?;
    protocol::init_submodule(&protocol_submod)?;
    module.add_submodule(&protocol_submod)?;

    let ratchet_submod = PyModule::new(py, "ratchet")?;
    ratchet::init_submodule(&ratchet_submod)?;
    module.add_submodule(&ratchet_submod)?;

    let sealed_sender_submod = PyModule::new(py, "sealed_sender")?;
    sealed_sender::init_submodule(&sealed_sender_submod)?;
    module.add_submodule(&sealed_sender_submod)?;

    let sender_keys_submod = PyModule::new(py, "sender_keys")?;
    sender_keys::init_submodule(&sender_keys_submod)?;
    module.add_submodule(&sender_keys_submod)?;

    let session_cipher_submod = PyModule::new(py, "session_cipher")?;
    session_cipher::init_submodule(&session_cipher_submod)?;
    module.add_submodule(&session_cipher_submod)?;

    let session_submod = PyModule::new(py, "session")?;
    session::init_submodule(&session_submod)?;
    module.add_submodule(&session_submod)?;

    let state_submod = PyModule::new(py, "state")?;
    state::init_submodule(&state_submod)?;
    module.add_submodule(&state_submod)?;

    let storage_submod = PyModule::new(py, "storage")?;
    storage::init_submodule(&storage_submod)?;
    module.add_submodule(&storage_submod)?;

    // Explicitly set each submodule as an attribute of the main module
    module.setattr("address", address_submod)?;
    module.setattr("curve", curve_submod)?;
    module.setattr("error", error_submod)?;
    module.setattr("fingerprint", fingerprint_submod)?;
    module.setattr("group_cipher", group_cipher_submod)?;
    module.setattr("identity_key", identity_key_submod)?;
    module.setattr("protocol", protocol_submod)?;
    module.setattr("ratchet", ratchet_submod)?;
    module.setattr("sealed_sender", sealed_sender_submod)?;
    module.setattr("sender_keys", sender_keys_submod)?;
    module.setattr("session_cipher", session_cipher_submod)?;
    module.setattr("session", session_submod)?;
    module.setattr("state", state_submod)?;
    module.setattr("storage", storage_submod)?;

    // Now expose all classes and functions at the top level for pyo3-stubgen
    
    // Address module classes
    module.add_class::<address::ProtocolAddress>()?;
    
    // Curve module classes and functions
    module.add_class::<curve::KeyPair>()?;
    module.add_class::<curve::PublicKey>()?;
    module.add_class::<curve::PrivateKey>()?;
    module.add_function(wrap_pyfunction!(curve::generate_keypair, module)?)?;
    module.add_function(wrap_pyfunction!(curve::verify_signature, module)?)?;
    
    // Error module classes
    module.add_class::<error::SignalProtocolError>()?;
    
    // Ratchet module classes
    module.add_class::<ratchet::BobSignalProtocolParameters>()?;
    
    // Sender keys module classes
    module.add_class::<sender_keys::SenderKeyName>()?;
    module.add_class::<sender_keys::SenderKeyRecord>()?;
    
    // Add classes from other modules as needed...
    // You'll need to add similar lines for all other classes in your modules

    Ok(())
}
