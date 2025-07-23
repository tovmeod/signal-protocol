use pyo3::prelude::*;

#[pyclass]
#[derive(Clone, Debug)]
pub struct ProtocolAddress {
    pub state: libsignal_protocol_rust::ProtocolAddress,
}

#[pymethods]
impl ProtocolAddress {
    #[new]
    fn new(name: String, device_id: u32) -> ProtocolAddress {
        ProtocolAddress {
            state: libsignal_protocol_rust::ProtocolAddress::new(name, device_id),
        }
    }

    pub fn name(&self) -> &str {
        self.state.name()
    }

    pub fn device_id(&self) -> u32 {
        self.state.device_id()
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(String::from(format!(
            "{} {}",
            self.name(),
            self.device_id()
        )))
    }

    fn __repr__(&self) -> PyResult<String> {
        Ok(String::from(format!(
            "ProtocolAddress({}, {})",
            self.name(),
            self.device_id()
        )))
    }
}

/// Parse an address string in the format "recipient_name:device_id"
/// Returns a ProtocolAddress or an error if the format is invalid
pub fn parse_address_string(address_str: &str) -> Result<libsignal_protocol_rust::ProtocolAddress, String> {
    let parts: Vec<&str> = address_str.rsplitn(2, ':').collect();
    
    if parts.len() != 2 {
        return Err(format!(
            "Address must be in format 'recipient_name:device_id', got: '{}'", 
            address_str
        ));
    }
    
    // Since we used rsplitn, the order is reversed: [device_id, recipient_name]
    let device_id_str = parts[0];
    let recipient_name = parts[1];
    
    if recipient_name.is_empty() {
        return Err("Recipient name cannot be empty".to_string());
    }
    
    let device_id = device_id_str.parse::<u32>()
        .map_err(|_| format!("Invalid device ID '{}', must be a positive integer", device_id_str))?;
    
    Ok(libsignal_protocol_rust::ProtocolAddress::new(
        recipient_name.to_string(),
        device_id,
    ))
}

pub fn init_submodule(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<ProtocolAddress>()?;
    Ok(())
}
