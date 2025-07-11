use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::basic::CompareOp;


use rand::rngs::OsRng;

use crate::error::Result;

#[pyfunction]
pub fn generate_keypair(py: Python<'_>) -> PyResult<(PyObject, PyObject)> {
    let mut csprng = OsRng;
    let key_pair = libsignal_protocol_rust::KeyPair::generate(&mut csprng);

    Ok((
        PyBytes::new(py, &key_pair.public_key.serialize()).into(),
        PyBytes::new(py, &key_pair.private_key.serialize()).into(),
    ))
}

#[pyclass]
#[derive(Clone)]
pub struct KeyPair {
    pub key: libsignal_protocol_rust::KeyPair,
}

#[pymethods]
impl KeyPair {
    #[new]
    fn new(public_key: PublicKey, private_key: PrivateKey) -> Self {
        let keypair = libsignal_protocol_rust::KeyPair::new(public_key.key, private_key.key);
        KeyPair { key: keypair }
    }

    #[staticmethod]
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let keypair = libsignal_protocol_rust::KeyPair::generate(&mut csprng);
        KeyPair { key: keypair }
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        Ok(PublicKey::deserialize(&self.key.public_key.serialize())?)
    }

    pub fn private_key(&self) -> Result<PrivateKey> {
        Ok(PrivateKey::deserialize(&self.key.private_key.serialize())?)
    }

    pub fn serialize(&self, py: Python<'_>) -> PyObject {
        let result = self.key.public_key.serialize();
        PyBytes::new(py, &result).into()
    }

    pub fn calculate_signature(&self, py: Python<'_>, message: &[u8]) -> Result<PyObject> {
        let mut csprng = OsRng;
        let sig = self.key.calculate_signature(&message, &mut csprng)?;
        Ok(PyBytes::new(py, &sig).into())
    }

    pub fn calculate_agreement(&self, py: Python<'_>, their_key: &PublicKey) -> Result<PyObject> {
        let agreement = self.key.calculate_agreement(&their_key.key)?;
        Ok(PyBytes::new(py, &agreement).into())
    }

    #[staticmethod]
    pub fn from_public_and_private(public_key: &[u8], private_key: &[u8]) -> Result<Self> {
        Ok(KeyPair {
            key: libsignal_protocol_rust::KeyPair::from_public_and_private(
                public_key,
                private_key,
            )?,
        })
    }
}

#[pyclass]
#[derive(Debug, Clone, Copy)]
pub struct PublicKey {
    pub key: libsignal_protocol_rust::PublicKey,
}

impl PublicKey {
    pub fn new(key: libsignal_protocol_rust::PublicKey) -> Self {
        PublicKey { key }
    }
}

/// key_type is not implemented for PublicKey.
#[pymethods]
impl PublicKey {
    #[staticmethod]
    pub fn deserialize(key: &[u8]) -> Result<Self> {
        Ok(Self {
            key: libsignal_protocol_rust::PublicKey::deserialize(key)?,
        })
    }

    pub fn serialize(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.key.serialize()).into()
    }

    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        Ok(self.key.verify_signature(&message, &signature)?)
    }

    fn __richcmp__(&self, other: &Bound<'_, PyAny>, op: CompareOp) -> PyResult<bool> {
        let other = other.extract::<PyRef<'_, PublicKey>>()?;
        match op {
            CompareOp::Eq => Ok(self.key.serialize() == other.key.serialize()),
            CompareOp::Ne => Ok(self.key.serialize() != other.key.serialize()),
            _ => Err(exceptions::PyNotImplementedError::new_err(())),
        }
    }
}


#[pyclass]
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PrivateKey {
    pub key: libsignal_protocol_rust::PrivateKey,
}

impl PrivateKey {
    pub fn new(key: libsignal_protocol_rust::PrivateKey) -> Self {
        PrivateKey { key }
    }
}

/// key_type() is not implemented on this struct.
#[pymethods]
impl PrivateKey {
    #[staticmethod]
    pub fn deserialize(key: &[u8]) -> Result<Self> {
        Ok(Self {
            key: libsignal_protocol_rust::PrivateKey::deserialize(key)?,
        })
    }

    pub fn serialize(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.key.serialize()).into()
    }

    pub fn calculate_signature(&self, message: &[u8], py: Python<'_>) -> Result<PyObject> {
        let mut csprng = OsRng;
        let sig = self.key.calculate_signature(message, &mut csprng)?;
        Ok(PyBytes::new(py, &sig).into())
    }

    pub fn calculate_agreement(&self, py: Python<'_>, their_key: &PublicKey) -> Result<PyObject> {
        let result = self.key.calculate_agreement(&their_key.key)?;
        Ok(PyBytes::new(py, &result).into())
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        Ok(PublicKey {
            key: self.key.public_key()?,
        })
    }
}

#[pyfunction]
pub fn verify_signature(public_key: &PublicKey, message: &[u8], signature: &[u8]) -> Result<bool> {
    Ok(public_key.verify_signature(message, signature)?)
}

pub fn init_curve_submodule(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<KeyPair>()?;
    module.add_class::<PublicKey>()?;
    module.add_class::<PrivateKey>()?;
    module.add_function(wrap_pyfunction!(generate_keypair, module)?)?;
    module.add_function(wrap_pyfunction!(verify_signature, module)?)?;
    Ok(())
}
