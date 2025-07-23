use pyo3::prelude::*;
use std::sync::RwLock;

// Remove unused imports
use crate::persistence::PersistenceManager;

#[pyclass(name = "InMemSignalProtocolStore")]
pub struct InMemSignalProtocolStore {
    pub store: RwLock<libsignal_protocol_rust::InMemSignalProtocolStore>,
    persistence_manager: Option<PersistenceManager>,
}

impl Clone for InMemSignalProtocolStore {
    fn clone(&self) -> Self {
        Self {
            store: RwLock::new(self.store.read().unwrap().clone()),
            persistence_manager: None, // Can't easily clone async database connections
        }
    }
}

#[pymethods]
impl InMemSignalProtocolStore {

    #[new]
    #[pyo3(signature = (key_pair, registration_id, connection_string=None, device_jid=None))]
    fn new(
        key_pair: &crate::identity_key::IdentityKeyPair,
        registration_id: u32,
        connection_string: Option<String>,
        device_jid: Option<String>,
    ) -> PyResult<InMemSignalProtocolStore> {
        let store = libsignal_protocol_rust::InMemSignalProtocolStore::new(
            key_pair.key,
            registration_id,
        ).map_err(crate::error::SignalProtocolError::new_err)?;

        let persistence_manager = match (connection_string, device_jid) {
            (Some(conn_str), Some(device_id)) => {
                // Serialize the identity key for the device record
                let identity_key_bytes = key_pair.key.public_key().serialize();
                
                // Use centralized Tokio runtime to handle async persistence setup synchronously
                let persistence = crate::runtime::block_on(PersistenceManager::new_with_device_setup(
                    &conn_str, 
                    device_id,
                    registration_id,
                    &identity_key_bytes
                )).map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                    format!("Failed to create persistence manager: {}", e)
                ))?;
                Some(persistence)
            }
            (None, None) => {
                // No persistence
                None
            }
            _ => {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    "Both connection_string and device_jid must be provided together, or both omitted"
                ));
            }
        };

        Ok(InMemSignalProtocolStore { 
            store: RwLock::new(store), 
            persistence_manager,
        })
    }


    // Identity Store Methods - these are needed for basic store operations
    fn get_identity_key_pair(&self) -> PyResult<crate::identity_key::IdentityKeyPair> {
        use libsignal_protocol_rust::IdentityKeyStore;
        let key = crate::runtime::block_on(self.store.read().unwrap().get_identity_key_pair(None))
            .map_err(crate::error::SignalProtocolError::new_err)?;
        Ok(crate::identity_key::IdentityKeyPair { key })
    }

    fn get_local_registration_id(&self) -> PyResult<u32> {
        use libsignal_protocol_rust::IdentityKeyStore;
        Ok(crate::runtime::block_on(
            self.store.read().unwrap().get_local_registration_id(None),
        ).map_err(crate::error::SignalProtocolError::new_err)?)
    }

    /// Close the store and clean up resources
    /// 
    /// This method closes database connections and cleans up resources.
    /// After calling this method, the store should not be used for database operations.
    fn close(&mut self) -> PyResult<()> {
        if let Some(ref mut persistence) = self.persistence_manager {
            // Close the database connection pool
            crate::runtime::block_on(persistence.close());
        }
        Ok(())
    }

    // Signal Protocol Store Methods - properly expose the trait implementations to Python
    // These methods use the cache + backing store implementation via the traits

    // Session Store Methods - use cache + backing store pattern via SessionStore trait
    fn load_session(&self, address: &crate::address::ProtocolAddress) -> PyResult<Option<crate::state::SessionRecord>> {
        use libsignal_protocol_rust::SessionStore;
        // Use centralized runtime for async-to-sync bridging
        let result = crate::runtime::block_on(
            SessionStore::load_session(self, &address.state, None)
        );
        
        let result = result.map_err(crate::error::SignalProtocolError::new_err)?;
        match result {
            Some(record) => Ok(Some(crate::state::SessionRecord { state: record })),
            None => Ok(None),
        }
    }
    
    fn store_session(&mut self, address: &crate::address::ProtocolAddress, session_record: &crate::state::SessionRecord) -> PyResult<()> {
        use libsignal_protocol_rust::SessionStore;
        // Use centralized Tokio runtime
        let result = crate::runtime::block_on(SessionStore::store_session(self, &address.state, &session_record.state, None));
        
        result.map_err(crate::error::SignalProtocolError::new_err)?;
        Ok(())
    }

    // PreKey Store Methods - delegate to PreKeyStore trait
    fn get_pre_key(&self, pre_key_id: u32) -> PyResult<crate::state::PreKeyRecord> {
        use libsignal_protocol_rust::PreKeyStore;
        let result = crate::runtime::block_on(
            PreKeyStore::get_pre_key(self, pre_key_id, None)
        ).map_err(crate::error::SignalProtocolError::new_err)?;
        Ok(crate::state::PreKeyRecord { state: result })
    }
    
    fn save_pre_key(&mut self, pre_key_id: u32, pre_key_record: &crate::state::PreKeyRecord) -> PyResult<()> {
        use libsignal_protocol_rust::PreKeyStore;
        crate::runtime::block_on(
            PreKeyStore::save_pre_key(self, pre_key_id, &pre_key_record.state, None)
        ).map_err(crate::error::SignalProtocolError::new_err)?;
        Ok(())
    }
    
    fn remove_pre_key(&mut self, pre_key_id: u32) -> PyResult<()> {
        use libsignal_protocol_rust::PreKeyStore;
        crate::runtime::block_on(
            PreKeyStore::remove_pre_key(self, pre_key_id, None)
        ).map_err(crate::error::SignalProtocolError::new_err)?;
        Ok(())
    }

    // SignedPreKey Store Methods - delegate to SignedPreKeyStore trait
    fn get_signed_pre_key(&self, signed_pre_key_id: u32) -> PyResult<crate::state::SignedPreKeyRecord> {
        use libsignal_protocol_rust::SignedPreKeyStore;
        let result = crate::runtime::block_on(
            SignedPreKeyStore::get_signed_pre_key(self, signed_pre_key_id, None)
        ).map_err(crate::error::SignalProtocolError::new_err)?;
        Ok(crate::state::SignedPreKeyRecord { state: result })
    }
    
    fn save_signed_pre_key(&mut self, signed_pre_key_id: u32, signed_pre_key_record: &crate::state::SignedPreKeyRecord) -> PyResult<()> {
        use libsignal_protocol_rust::SignedPreKeyStore;
        crate::runtime::block_on(
            SignedPreKeyStore::save_signed_pre_key(self, signed_pre_key_id, &signed_pre_key_record.state, None)
        ).map_err(crate::error::SignalProtocolError::new_err)?;
        Ok(())
    }

    // Identity Store Methods - delegate to IdentityKeyStore trait  
    fn save_identity(&mut self, address: &crate::address::ProtocolAddress, identity_key: &crate::identity_key::IdentityKey) -> PyResult<bool> {
        use libsignal_protocol_rust::IdentityKeyStore;
        let result = crate::runtime::block_on(
            IdentityKeyStore::save_identity(self, &address.state, &identity_key.key, None)
        ).map_err(crate::error::SignalProtocolError::new_err)?;
        Ok(result)
    }
    
    fn get_identity(&self, address: &crate::address::ProtocolAddress) -> PyResult<Option<crate::identity_key::IdentityKey>> {
        use libsignal_protocol_rust::IdentityKeyStore;
        let result = crate::runtime::block_on(
            IdentityKeyStore::get_identity(self, &address.state, None)
        ).map_err(crate::error::SignalProtocolError::new_err)?;
        
        match result {
            Some(key) => Ok(Some(crate::identity_key::IdentityKey { key })),
            None => Ok(None),
        }
    }

    // SenderKey Store Methods - delegate to SenderKeyStore trait
    fn store_sender_key(&mut self, sender_key_name: &crate::sender_keys::SenderKeyName, sender_key_record: &crate::sender_keys::SenderKeyRecord) -> PyResult<()> {
        use libsignal_protocol_rust::SenderKeyStore;
        crate::runtime::block_on(
            SenderKeyStore::store_sender_key(self, &sender_key_name.state, &sender_key_record.state, None)
        ).map_err(crate::error::SignalProtocolError::new_err)?;
        Ok(())
    }
    
    fn load_sender_key(&mut self, sender_key_name: &crate::sender_keys::SenderKeyName) -> PyResult<Option<crate::sender_keys::SenderKeyRecord>> {
        use libsignal_protocol_rust::SenderKeyStore;
        let result = crate::runtime::block_on(
            SenderKeyStore::load_sender_key(self, &sender_key_name.state, None)
        ).map_err(crate::error::SignalProtocolError::new_err)?;
        
        match result {
            Some(record) => Ok(Some(crate::sender_keys::SenderKeyRecord { state: record })),
            None => Ok(None),
        }
    }

    // Database utility methods (only available when persistence is enabled)
    
    /// Run database migrations (only available when persistence is enabled)
    fn migrate<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        if let Some(ref persistence) = self.persistence_manager {
            let persistence_clone = persistence.clone();
            pyo3_async_runtimes::tokio::future_into_py(py, async move {
                persistence_clone.migrate().await
                    .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Migration failed: {}", e)))?;
                Ok(())
            })
        } else {
            Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                "Migration only available when persistence is enabled"
            ))
        }
    }

    /// Get the device JID (only available when persistence is enabled)
    fn device_jid(&self) -> PyResult<String> {
        if let Some(ref persistence) = self.persistence_manager {
            Ok(persistence.device_jid().to_string())
        } else {
            Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                "Device JID only available when persistence is enabled"
            ))
        }
    }

    /// Check if a session exists for the given address
    fn contains_session(&self, address: &crate::address::ProtocolAddress) -> PyResult<bool> {
        // First check in-memory cache (always available)
        let cache_has_session = match self.load_session(address) {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(_) => false, // Treat cache errors as "not found"
        };
        
        if cache_has_session {
            // Found in cache, return immediately
            Ok(true)
        } else if let Some(ref persistence) = self.persistence_manager {
            // Not in cache, check database if persistence enabled
            // Handle async database call synchronously using centralized runtime
            let result = crate::runtime::block_on(persistence.contains_session(&address.state));
            
            match result {
                Ok(exists) => Ok(exists),
                Err(_) => {
                    // Database error, treat as "not found"
                    Ok(false)
                }
            }
        } else {
            // No persistence, cache miss means no session
            Ok(false)
        }
    }

    /// Delete a specific session (only available when persistence is enabled)
    fn delete_session<'py>(&self, py: Python<'py>, recipient_name: String, recipient_device_id: i32) -> PyResult<Bound<'py, PyAny>> {
        if let Some(ref persistence) = self.persistence_manager {
            let persistence_clone = persistence.clone();
            pyo3_async_runtimes::tokio::future_into_py(py, async move {
                let result = persistence_clone.delete_session(&recipient_name, recipient_device_id).await
                    .map_err(crate::error::SignalProtocolError::new_err)?;
                Ok(result)
            })
        } else {
            Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                "Session deletion only available when persistence is enabled"
            ))
        }
    }

    /// Delete all sessions for a user (only available when persistence is enabled)
    fn delete_all_sessions_for_user<'py>(&self, py: Python<'py>, user_prefix: String) -> PyResult<Bound<'py, PyAny>> {
        if let Some(ref persistence) = self.persistence_manager {
            let persistence_clone = persistence.clone();
            pyo3_async_runtimes::tokio::future_into_py(py, async move {
                let result = persistence_clone.delete_all_sessions_for_user(&user_prefix).await
                    .map_err(crate::error::SignalProtocolError::new_err)?;
                Ok(result)
            })
        } else {
            Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                "Session deletion only available when persistence is enabled"
            ))
        }
    }

    // Convenient session deletion wrapper methods

    /// Delete a session by address string (convenient wrapper)
    fn delete_session_by_address<'py>(&self, py: Python<'py>, address: String) -> PyResult<Bound<'py, PyAny>> {
        if let Some(ref persistence) = self.persistence_manager {
            let persistence_clone = persistence.clone();
            pyo3_async_runtimes::tokio::future_into_py(py, async move {
                // Parse address string - try "name:device_id" format first
                let (recipient_name, recipient_device_id) = match address.rsplit_once(':') {
                    Some((name, device_id_str)) => {
                        match device_id_str.parse::<i32>() {
                            Ok(device_id) => (name.to_string(), device_id),
                            Err(_) => {
                                // If parsing fails, treat as device_id=0
                                (address.clone(), 0)
                            }
                        }
                    }
                    None => {
                        // No colon found, treat as device_id=0
                        (address.clone(), 0)
                    }
                };

                let result = persistence_clone.delete_session(&recipient_name, recipient_device_id).await
                    .map_err(crate::error::SignalProtocolError::new_err)?;
                Ok(result)
            })
        } else {
            Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                "Session deletion only available when persistence is enabled"
            ))
        }
    }

    /// Delete all sessions for a phone number (convenient wrapper)
    fn delete_all_sessions_by_phone<'py>(&self, py: Python<'py>, phone: String) -> PyResult<Bound<'py, PyAny>> {
        if let Some(ref persistence) = self.persistence_manager {
            let persistence_clone = persistence.clone();
            pyo3_async_runtimes::tokio::future_into_py(py, async move {
                // Create pattern for phone-based sessions: "phone:"
                let phone_pattern = format!("{}:", phone);
                let result = persistence_clone.delete_all_sessions_for_user(&phone_pattern).await
                    .map_err(crate::error::SignalProtocolError::new_err)?;
                Ok(result)
            })
        } else {
            Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                "Session deletion only available when persistence is enabled"
            ))
        }
    }

    /// Mark a pre-key as uploaded (only available when persistence is enabled)
    fn mark_pre_key_uploaded<'py>(&self, py: Python<'py>, pre_key_id: u32) -> PyResult<Bound<'py, PyAny>> {
        if let Some(ref persistence) = self.persistence_manager {
            let persistence_clone = persistence.clone();
            pyo3_async_runtimes::tokio::future_into_py(py, async move {
                let result = persistence_clone.mark_pre_key_uploaded(pre_key_id).await
                    .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                        format!("Failed to mark pre-key as uploaded: {}", e)
                    ))?;
                Ok(result)
            })
        } else {
            Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                "Pre-key upload marking only available when persistence is enabled"
            ))
        }
    }

    /// Delete all identity keys for recipients whose names start with the given phone number
    fn delete_all_identities<'py>(&self, py: Python<'py>, phone: String) -> PyResult<Bound<'py, PyAny>> {
        if let Some(ref persistence) = self.persistence_manager {
            let persistence_clone = persistence.clone();
            pyo3_async_runtimes::tokio::future_into_py(py, async move {
                let result = persistence_clone.delete_all_identities(&phone).await
                    .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                        format!("Failed to delete identities: {}", e)
                    ))?;
                Ok(result)
            })
        } else {
            Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                "Identity deletion only available when persistence is enabled"
            ))
        }
    }

    /// Delete a specific identity key for a given address string
    fn delete_identity<'py>(&self, py: Python<'py>, address_str: String) -> PyResult<Bound<'py, PyAny>> {
        if let Some(ref persistence) = self.persistence_manager {
            let persistence_clone = persistence.clone();
            pyo3_async_runtimes::tokio::future_into_py(py, async move {
                // Parse the address string to extract recipient_name and device_id
                // Expected format: "recipient_name:device_id"
                let address = match crate::address::parse_address_string(&address_str) {
                    Ok(addr) => addr,
                    Err(e) => {
                        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                            format!("Invalid address format '{}': {}", address_str, e)
                        ));
                    }
                };

                let result = persistence_clone.delete_identity(&address).await
                    .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                        format!("Failed to delete identity: {}", e)
                    ))?;
                Ok(result)
            })
        } else {
            Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                "Identity deletion only available when persistence is enabled"
            ))
        }
    }

    // Pre-key helper methods

    /// Get the next available pre-key ID
    fn get_next_pre_key_id<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        if let Some(ref persistence) = self.persistence_manager {
            let persistence_clone = persistence.clone();
            pyo3_async_runtimes::tokio::future_into_py(py, async move {
                let result = persistence_clone.get_next_pre_key_id().await
                    .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                        format!("Failed to get next pre-key ID: {}", e)
                    ))?;
                Ok(result)
            })
        } else {
            Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                "Pre-key ID generation only available when persistence is enabled"
            ))
        }
    }

    /// Get existing non-uploaded pre-keys, ordered by key_id
    #[pyo3(signature = (limit=None))]
    fn get_non_uploaded_pre_keys<'py>(&self, py: Python<'py>, limit: Option<u32>) -> PyResult<Bound<'py, PyAny>> {
        if let Some(ref persistence) = self.persistence_manager {
            let persistence_clone = persistence.clone();
            pyo3_async_runtimes::tokio::future_into_py(py, async move {
                let keys = persistence_clone.get_non_uploaded_pre_keys(limit).await
                    .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                        format!("Failed to get non-uploaded pre-keys: {}", e)
                    ))?;
                
                // Convert to Python list of tuples (key_id, serialized_data)
                let py_keys: Vec<(u32, Vec<u8>)> = keys;
                Ok(py_keys)
            })
        } else {
            Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                "Pre-key retrieval only available when persistence is enabled"
            ))
        }
    }

    /// Mark pre-keys as uploaded up to the given ID (inclusive)
    fn mark_pre_keys_as_uploaded_up_to<'py>(&self, py: Python<'py>, up_to_id: u32) -> PyResult<Bound<'py, PyAny>> {
        if let Some(ref persistence) = self.persistence_manager {
            let persistence_clone = persistence.clone();
            pyo3_async_runtimes::tokio::future_into_py(py, async move {
                let result = persistence_clone.mark_pre_keys_as_uploaded_up_to(up_to_id).await
                    .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                        format!("Failed to mark pre-keys as uploaded: {}", e)
                    ))?;
                Ok(result)
            })
        } else {
            Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                "Pre-key upload marking only available when persistence is enabled"
            ))
        }
    }

    /// Get the count of uploaded pre-keys
    fn uploaded_prekey_count<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        if let Some(ref persistence) = self.persistence_manager {
            let persistence_clone = persistence.clone();
            pyo3_async_runtimes::tokio::future_into_py(py, async move {
                let result = persistence_clone.uploaded_prekey_count().await
                    .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                        format!("Failed to get uploaded pre-key count: {}", e)
                    ))?;
                Ok(result)
            })
        } else {
            Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                "Pre-key count only available when persistence is enabled"
            ))
        }
    }

    /// Generate and save a pre-key with the given ID
    #[pyo3(signature = (key_id, mark_uploaded=false))]
    fn generate_and_save_pre_key<'py>(&self, py: Python<'py>, key_id: u32, mark_uploaded: bool) -> PyResult<Bound<'py, PyAny>> {
        if let Some(ref persistence) = self.persistence_manager {
            let persistence_clone = persistence.clone();
            pyo3_async_runtimes::tokio::future_into_py(py, async move {
                let pre_key_data = persistence_clone.generate_and_save_pre_key(key_id, mark_uploaded).await
                    .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                        format!("Failed to generate and save pre-key: {}", e)
                    ))?;
                
                // Return the serialized PreKeyRecord data
                Ok(pre_key_data)
            })
        } else {
            Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                "Pre-key generation only available when persistence is enabled"
            ))
        }
    }
}

// Implement the libsignal traits for our wrapper using cache + backing store pattern
#[async_trait::async_trait(?Send)]
impl libsignal_protocol_rust::SessionStore for InMemSignalProtocolStore {
    async fn load_session(
        &self,
        address: &libsignal_protocol_rust::ProtocolAddress,
        ctx: libsignal_protocol_rust::Context,
    ) -> std::result::Result<Option<libsignal_protocol_rust::SessionRecord>, libsignal_protocol_rust::SignalProtocolError> {
        // 1. Try cache first (fast path)
        match self.store.read().unwrap().load_session(address, ctx).await {
            Ok(Some(session)) => {
                // Found in cache
                return Ok(Some(session));
            }
            Ok(None) => {
                // Not in cache, try database if persistence enabled
                if let Some(ref persistence) = self.persistence_manager {
                    eprintln!("DEBUG: About to load session from database");
                    // We're already in an async context, just await directly
                    let db_result = persistence.load_session(address, ctx).await;
                    
                    match db_result {
                        Ok(Some(session)) => {
                            // Found in database
                            eprintln!("DEBUG: Session found in database, skipping cache update for now");
                            // TODO: Fix cache update mechanism
                            return Ok(Some(session));
                        }
                        Ok(None) => {
                            // Not found in database either
                            eprintln!("DEBUG: Session not found in database");
                            return Ok(None);
                        }
                        Err(err) => {
                            // Database error should be propagated, not silently ignored
                            eprintln!("Database error loading session: {:?}", err);
                            return Err(err);
                        }
                    }
                } else {
                    // No persistence, cache miss means no session
                    return Ok(None);
                }
            }
            Err(err) => {
                // Cache error, propagate it
                return Err(err);
            }
        }
    }

    async fn store_session(
        &mut self,
        address: &libsignal_protocol_rust::ProtocolAddress,
        record: &libsignal_protocol_rust::SessionRecord,
        ctx: libsignal_protocol_rust::Context,
    ) -> std::result::Result<(), libsignal_protocol_rust::SignalProtocolError> {
        // 1. Store in cache (fast access)
        self.store.write().unwrap().store_session(address, record, ctx).await?;

        // 2. Store in database if persistence enabled
        if let Some(ref persistence) = self.persistence_manager {
            eprintln!("DEBUG: About to store session in database");
            // Clone persistence manager for mutable operations
            let mut persistence_clone = persistence.clone();
            
            // Handle database operations using centralized runtime
            let db_result = crate::runtime::block_on(persistence_clone.store_session(address, record, ctx));
            
            // Note: This may fail if database is unavailable, but cache is still updated
            match db_result {
                Ok(()) => {
                    eprintln!("DEBUG: Session stored successfully in database");
                }
                Err(err) => {
                    eprintln!("Database error storing session: {:?}", err);
                    // Continue anyway - cache is updated
                }
            }
        }

        Ok(())
    }
}

// Implement the libsignal traits for our wrapper using cache + backing store pattern
#[async_trait::async_trait(?Send)]
impl libsignal_protocol_rust::IdentityKeyStore for InMemSignalProtocolStore {
    async fn get_identity_key_pair(&self, ctx: libsignal_protocol_rust::Context) -> std::result::Result<libsignal_protocol_rust::IdentityKeyPair, libsignal_protocol_rust::SignalProtocolError> {
        // Identity key pair is immutable, stored in cache only
        self.store.read().unwrap().get_identity_key_pair(ctx).await
    }

    async fn get_local_registration_id(&self, ctx: libsignal_protocol_rust::Context) -> std::result::Result<u32, libsignal_protocol_rust::SignalProtocolError> {
        // Registration ID is immutable, stored in cache only
        self.store.read().unwrap().get_local_registration_id(ctx).await
    }

    async fn save_identity(
        &mut self,
        address: &libsignal_protocol_rust::ProtocolAddress,
        identity: &libsignal_protocol_rust::IdentityKey,
        ctx: libsignal_protocol_rust::Context,
    ) -> std::result::Result<bool, libsignal_protocol_rust::SignalProtocolError> {
        // 1. Store in cache (fast access)
        let result = self.store.write().unwrap().save_identity(address, identity, ctx).await?;

        // 2. Store in database if persistence enabled
        if let Some(ref persistence) = self.persistence_manager {
            // Clone persistence manager for mutable operations
            let mut persistence_clone = persistence.clone();
            
            // Handle database operations using centralized runtime
            let db_result = crate::runtime::block_on(persistence_clone.save_identity(address, identity, ctx));
            
            // Note: This may fail if database is unavailable, but cache is still updated
            if let Err(err) = db_result {
                eprintln!("Database error storing identity: {:?}", err);
                // Continue anyway - cache is updated
            }
        }

        Ok(result)
    }

    async fn is_trusted_identity(
        &self,
        address: &libsignal_protocol_rust::ProtocolAddress,
        identity: &libsignal_protocol_rust::IdentityKey,
        direction: libsignal_protocol_rust::Direction,
        ctx: libsignal_protocol_rust::Context,
    ) -> std::result::Result<bool, libsignal_protocol_rust::SignalProtocolError> {
        // 1. Check cache first
        // Create direction values for both cache and database since Direction doesn't implement Copy
        let (cache_direction, db_direction) = match direction {
            libsignal_protocol_rust::Direction::Sending => (
                libsignal_protocol_rust::Direction::Sending,
                libsignal_protocol_rust::Direction::Sending,
            ),
            libsignal_protocol_rust::Direction::Receiving => (
                libsignal_protocol_rust::Direction::Receiving,
                libsignal_protocol_rust::Direction::Receiving,
            ),
        };
        
        match self.store.read().unwrap().is_trusted_identity(address, identity, cache_direction, ctx).await {
            Ok(result) => Ok(result),
            Err(_) => {
                // Cache doesn't have the identity, check database if persistence enabled
                
                if let Some(ref persistence) = self.persistence_manager {
                    // Handle database operations using centralized runtime
                    let db_result = crate::runtime::block_on(persistence.is_trusted_identity(address, identity, db_direction, ctx));
                    
                    match db_result {
                        Ok(result) => Ok(result),
                        Err(err) => {
                            // Database error, log but don't fail - trust on first use
                            eprintln!("Database error checking identity trust: {}", err);
                            Ok(true)
                        }
                    }
                } else {
                    // No persistence, trust on first use
                    Ok(true)
                }
            }
        }
    }

    async fn get_identity(
        &self,
        address: &libsignal_protocol_rust::ProtocolAddress,
        ctx: libsignal_protocol_rust::Context,
    ) -> std::result::Result<Option<libsignal_protocol_rust::IdentityKey>, libsignal_protocol_rust::SignalProtocolError> {
        // 1. Try cache first (fast path)
        match self.store.read().unwrap().get_identity(address, ctx).await {
            Ok(Some(identity)) => {
                // Found in cache
                return Ok(Some(identity));
            }
            Ok(None) => {
                // Not in cache, try database if persistence enabled
                if let Some(ref persistence) = self.persistence_manager {
                    // Handle Tokio runtime context properly for database operations
                    // We're already in an async context, just await directly
                    let db_result = persistence.get_identity(address, ctx).await;
                    
                    match db_result {
                        Ok(Some(identity)) => {
                            // Found in database - return it (cache update temporarily disabled to avoid deadlock)
                            eprintln!("DEBUG: Identity found in database, returning without cache update");
                            // TODO: Fix cache update mechanism that doesn't cause deadlocks
                            return Ok(Some(identity));
                        }
                        Ok(None) => {
                            // Not found in database either
                            return Ok(None);
                        }
                        Err(err) => {
                            // Database error should be propagated, not silently ignored
                            eprintln!("Database error loading identity: {:?}", err);
                            return Err(err);
                        }
                    }
                } else {
                    // No persistence, cache miss means no identity
                    return Ok(None);
                }
            }
            Err(err) => {
                // Cache error, propagate it
                return Err(err);
            }
        }
    }
}

#[async_trait::async_trait(?Send)]
impl libsignal_protocol_rust::PreKeyStore for InMemSignalProtocolStore {
    async fn get_pre_key(
        &self,
        prekey_id: u32,
        ctx: libsignal_protocol_rust::Context,
    ) -> std::result::Result<libsignal_protocol_rust::PreKeyRecord, libsignal_protocol_rust::SignalProtocolError> {
        // 1. Try cache first (fast path)
        match self.store.read().unwrap().get_pre_key(prekey_id, ctx).await {
            Ok(record) => {
                // Found in cache
                return Ok(record);
            }
            Err(_) => {
                // Not in cache, try database if persistence enabled
                if let Some(ref persistence) = self.persistence_manager {
                    // Handle database operations using centralized runtime
                    let db_result = crate::runtime::block_on(persistence.get_pre_key(prekey_id, ctx));
                    
                    match db_result {
                        Ok(record) => {
                            // Found in database, return it directly
                            // TODO: Update cache - requires &mut self but get_pre_key only has &self
                            // The libsignal store methods require mutable access for cache updates
                            return Ok(record);
                        }
                        Err(err) => {
                            // Database error or not found, return the original cache error
                            eprintln!("Database error loading pre-key: {}", err);
                            return self.store.read().unwrap().get_pre_key(prekey_id, ctx).await;
                        }
                    }
                } else {
                    // No persistence, return cache error
                    return self.store.read().unwrap().get_pre_key(prekey_id, ctx).await;
                }
            }
        }
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: u32,
        record: &libsignal_protocol_rust::PreKeyRecord,
        ctx: libsignal_protocol_rust::Context,
    ) -> std::result::Result<(), libsignal_protocol_rust::SignalProtocolError> {
        // 1. Store in cache (fast access)
        self.store.write().unwrap().save_pre_key(prekey_id, record, ctx).await?;

        // 2. Store in database if persistence enabled
        if let Some(ref mut persistence) = self.persistence_manager {
            // Handle database operations using centralized runtime
            let db_result = crate::runtime::block_on(persistence.save_pre_key(prekey_id, record, ctx));
            
            // Note: This may fail if database is unavailable, but cache is still updated
            if let Err(err) = db_result {
                eprintln!("Database error storing pre-key: {}", err);
                // Continue anyway - cache is updated
            }
        }

        Ok(())
    }

    async fn remove_pre_key(
        &mut self,
        prekey_id: u32,
        ctx: libsignal_protocol_rust::Context,
    ) -> std::result::Result<(), libsignal_protocol_rust::SignalProtocolError> {
        // 1. Remove from cache
        self.store.write().unwrap().remove_pre_key(prekey_id, ctx).await?;

        // 2. Remove from database if persistence enabled
        if let Some(ref mut persistence) = self.persistence_manager {
            // Handle database operations using centralized runtime
            let db_result = crate::runtime::block_on(persistence.remove_pre_key(prekey_id, ctx));
            
            // Note: This may fail if database is unavailable, but cache is still updated
            if let Err(err) = db_result {
                eprintln!("Database error removing pre-key: {}", err);
                // Continue anyway - cache is updated
            }
        }

        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl libsignal_protocol_rust::SignedPreKeyStore for InMemSignalProtocolStore {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: u32,
        ctx: libsignal_protocol_rust::Context,
    ) -> std::result::Result<libsignal_protocol_rust::SignedPreKeyRecord, libsignal_protocol_rust::SignalProtocolError> {
        // 1. Try cache first (fast path)
        match self.store.read().unwrap().get_signed_pre_key(signed_prekey_id, ctx).await {
            Ok(record) => {
                // Found in cache
                return Ok(record);
            }
            Err(_) => {
                // Not in cache, try database if persistence enabled
                if let Some(ref persistence) = self.persistence_manager {
                    // Handle database operations using centralized runtime
                    let db_result = crate::runtime::block_on(persistence.get_signed_pre_key(signed_prekey_id, ctx));
                    
                    match db_result {
                        Ok(record) => {
                            // Found in database, update cache before returning
                            eprintln!("DEBUG: Signed prekey found in database, updating cache");
                            let mut store = self.store.write().unwrap();
                            store.save_signed_pre_key(signed_prekey_id, &record, ctx).await?;
                            eprintln!("DEBUG: Signed prekey cache updated successfully");
                            return Ok(record);
                        }
                        Err(err) => {
                            // Database error or not found, return the original cache error
                            eprintln!("Database error loading signed pre-key: {}", err);
                            return self.store.read().unwrap().get_signed_pre_key(signed_prekey_id, ctx).await;
                        }
                    }
                } else {
                    // No persistence, return cache error
                    return self.store.read().unwrap().get_signed_pre_key(signed_prekey_id, ctx).await;
                }
            }
        }
    }

    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: u32,
        record: &libsignal_protocol_rust::SignedPreKeyRecord,
        ctx: libsignal_protocol_rust::Context,
    ) -> std::result::Result<(), libsignal_protocol_rust::SignalProtocolError> {
        // 1. Store in cache (fast access)
        self.store.write().unwrap().save_signed_pre_key(signed_prekey_id, record, ctx).await?;

        // 2. Store in database if persistence enabled
        if let Some(ref mut persistence) = self.persistence_manager {
            // Handle database operations using centralized runtime
            let db_result = crate::runtime::block_on(persistence.save_signed_pre_key(signed_prekey_id, record, ctx));
            
            // Note: This may fail if database is unavailable, but cache is still updated
            if let Err(err) = db_result {
                eprintln!("Database error storing signed pre-key: {}", err);
                // Continue anyway - cache is updated
            }
        }

        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl libsignal_protocol_rust::SenderKeyStore for InMemSignalProtocolStore {
    async fn store_sender_key(
        &mut self,
        sender_key_name: &libsignal_protocol_rust::SenderKeyName,
        record: &libsignal_protocol_rust::SenderKeyRecord,
        ctx: libsignal_protocol_rust::Context,
    ) -> std::result::Result<(), libsignal_protocol_rust::SignalProtocolError> {
        // 1. Store in cache (fast access)
        self.store.write().unwrap().store_sender_key(sender_key_name, record, ctx).await?;

        // 2. Store in database if persistence enabled
        if let Some(ref mut persistence) = self.persistence_manager {
            // Handle database operations using centralized runtime
            let db_result = crate::runtime::block_on(persistence.store_sender_key(sender_key_name, record, ctx));
            
            // Note: This may fail if database is unavailable, but cache is still updated
            if let Err(err) = db_result {
                eprintln!("Database error storing sender key: {}", err);
                // Continue anyway - cache is updated
            }
        }

        Ok(())
    }

    async fn load_sender_key(
        &mut self,
        sender_key_name: &libsignal_protocol_rust::SenderKeyName,
        ctx: libsignal_protocol_rust::Context,
    ) -> std::result::Result<Option<libsignal_protocol_rust::SenderKeyRecord>, libsignal_protocol_rust::SignalProtocolError> {
        // 1. Try cache first (fast path)
        match self.store.write().unwrap().load_sender_key(sender_key_name, ctx).await {
            Ok(Some(record)) => {
                // Found in cache
                return Ok(Some(record));
            }
            Ok(None) => {
                // Not in cache, try database if persistence enabled
                if let Some(ref mut persistence) = self.persistence_manager {
                    // Handle database operations using centralized runtime
                    let db_result = crate::runtime::block_on(persistence.load_sender_key(sender_key_name, ctx));
                    
                    match db_result {
                        Ok(Some(record)) => {
                            // Found in database, update cache before returning
                            eprintln!("DEBUG: Sender key found in database, updating cache");
                            let mut store = self.store.write().unwrap();
                            store.store_sender_key(sender_key_name, &record, ctx).await?;
                            eprintln!("DEBUG: Sender key cache updated successfully");
                            return Ok(Some(record));
                        }
                        Ok(None) => {
                            // Not found in database either
                            return Ok(None);
                        }
                        Err(err) => {
                            // Database error, log but don't fail - just return cache result
                            eprintln!("Database error loading sender key: {}", err);
                            return Ok(None);
                        }
                    }
                } else {
                    // No persistence, cache miss means no sender key
                    return Ok(None);
                }
            }
            Err(err) => {
                // Cache error, propagate it
                return Err(err);
            }
        }
    }
}

/// Initialize logging (no-op for backward compatibility)
#[pyfunction]
pub fn init_logging() {
    // No-op function for backward compatibility with existing tests
}

/// Initialize the storage submodule for Python
pub fn init_submodule(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<InMemSignalProtocolStore>()?;
    module.add_function(wrap_pyfunction!(init_logging, module)?)?;
    Ok(())
}