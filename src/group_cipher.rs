use pyo3::prelude::*;
use pyo3::types::PyBytes;

use futures::executor::block_on;
use rand::rngs::OsRng;

use crate::error::{Result, SignalProtocolError};
use crate::protocol::{CiphertextMessage, SenderKeyDistributionMessage};
use crate::sender_keys::SenderKeyName;
use crate::storage::InMemSignalProtocolStore;

#[pyfunction]
pub fn group_encrypt(
    py: Python<'_>,
    protocol_store: &mut InMemSignalProtocolStore,
    sender_key_id: &SenderKeyName,
    plaintext: &[u8],
) -> Result<PyObject> {
    let mut csprng = OsRng;
    let ciphertext = block_on(libsignal_protocol_rust::group_encrypt(
        &mut protocol_store.store.sender_key_store,
        &sender_key_id.state,
        plaintext,
        &mut csprng,
        None,
    ))?;
    Ok(PyBytes::new(py, &ciphertext).into())
}

#[pyfunction]
pub fn group_decrypt(
    py: Python<'_>,
    skm_bytes: &[u8],
    protocol_store: &mut InMemSignalProtocolStore,
    sender_key_id: &SenderKeyName,
) -> Result<PyObject> {
    let plaintext = block_on(libsignal_protocol_rust::group_decrypt(
        skm_bytes,
        &mut protocol_store.store.sender_key_store,
        &sender_key_id.state,
        None,
    ))?;
    Ok(PyBytes::new(py, &plaintext).into())
}

#[pyfunction]
pub fn process_sender_key_distribution_message(
    sender_key_name: &SenderKeyName,
    skdm: &SenderKeyDistributionMessage,
    protocol_store: &mut InMemSignalProtocolStore,
) -> Result<()> {
    Ok(block_on(
        libsignal_protocol_rust::process_sender_key_distribution_message(
            &sender_key_name.state,
            &skdm.data,
            &mut protocol_store.store.sender_key_store,
            None,
        ),
    )?)
}

#[pyfunction]
pub fn create_sender_key_distribution_message(
    sender_key_name: &SenderKeyName,
    protocol_store: &mut InMemSignalProtocolStore,
) -> PyResult<Py<SenderKeyDistributionMessage>> {
    let mut csprng = OsRng;
    let upstream_data = match block_on(
        libsignal_protocol_rust::create_sender_key_distribution_message(
            &sender_key_name.state,
            &mut protocol_store.store.sender_key_store,
            &mut csprng,
            None,
        ),
    ) {
        Ok(data) => data,
        Err(err) => return Err(SignalProtocolError::new_err(err)),
    };
    let ciphertext = libsignal_protocol_rust::CiphertextMessage::SenderKeyDistributionMessage(
        upstream_data.clone(),
    );

    // The CiphertextMessage is required as it is the base class for SenderKeyDistributionMessage
    // on the Python side, so we must create _both_ a CiphertextMessage and a SenderKeyDistributionMessage
    // on the Rust side for inheritance to work.
    Python::with_gil(|py| {
        Py::new(
            py,
            (
                SenderKeyDistributionMessage {
                    data: upstream_data,
                },
                CiphertextMessage { data: ciphertext },
            ),
        )
    })
}

pub fn init_submodule(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(group_encrypt, module)?)?;
    module.add_function(wrap_pyfunction!(group_decrypt, module)?)?;
    module.add_function(wrap_pyfunction!(process_sender_key_distribution_message, module)?)?;
    module.add_function(wrap_pyfunction!(create_sender_key_distribution_message, module)?)?;
    Ok(())
}
