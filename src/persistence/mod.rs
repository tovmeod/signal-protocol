use sqlx::{AnyPool, any::install_default_drivers};

/// Main persistence manager that handles database operations
#[derive(Debug, Clone)]
pub struct PersistenceManager {
    pool: AnyPool,
    device_id: i64,  // Auto-incrementing BIGINT for simplicity and performance
    device_jid: Option<String>,  // JID can be None initially, set after pairing
}

impl PersistenceManager {
    /// Create a new persistence manager with the given connection string and device ID
    /// This is used when you already have a device_id (e.g., from previous sessions)
    #[allow(dead_code)]
    pub async fn new_with_device_id(connection_string: &str, device_id: i64) -> Result<Self, sqlx::Error> {
        // Required for Any backend
        install_default_drivers();
        let pool = AnyPool::connect(connection_string).await?;
        
        // Configure SQLite for optimal performance and concurrency
        if connection_string.starts_with("sqlite://") {
            Self::configure_sqlite_pragmas(&pool).await?;
        }
        
        // Load the JID if it exists for this device
        let device_jid = sqlx::query_as::<_, (String,)>(
            "SELECT jid FROM devices WHERE device_id = ? AND jid IS NOT NULL"
        )
        .bind(device_id)
        .fetch_optional(&pool)
        .await?
        .map(|(jid,)| jid);
        
        Ok(Self { pool, device_id, device_jid })
    }

    /// Create a new device and persistence manager (for initial pairing)
    /// This creates a new device record without JID and returns the device_id
    #[allow(dead_code)]
    pub async fn new_device(
        connection_string: &str,
        registration_id: u32,
        identity_key: &[u8]
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Required for Any backend
        install_default_drivers();
        let pool = AnyPool::connect(connection_string).await?;
        
        // For SQLite, set pragmas to ensure immediate consistency across connections
        if connection_string.starts_with("sqlite://") {
            let wal_result = sqlx::query("PRAGMA journal_mode = WAL")
                .execute(&pool)
                .await;
            let sync_result = sqlx::query("PRAGMA synchronous = FULL")
                .execute(&pool)
                .await;
            let busy_timeout = sqlx::query("PRAGMA busy_timeout = 30000")
                .execute(&pool)
                .await;
            log::debug!("PRAGMA journal_mode=WAL result: {:?}", wal_result);
            log::debug!("PRAGMA synchronous=FULL result: {:?}", sync_result);
            log::debug!("PRAGMA busy_timeout result: {:?}", busy_timeout);
        }
        
        let temp_manager = Self { pool, device_id: 0, device_jid: None };
        
        // Run migrations first to ensure tables exist
        temp_manager.migrate().await?;
        
        // Create new device record without JID
        let device_id = temp_manager.create_device_record(registration_id, identity_key).await?;
        log::info!("Created new device with ID: {}", device_id);
        
        Ok(Self { pool: temp_manager.pool, device_id, device_jid: None })
    }
    
    /// Create a new persistence manager with JID (backward compatibility)
    /// This is for when you have a JID and want to create/update the device
    pub async fn new_with_jid_setup(
        connection_string: &str,
        device_jid: String,
        registration_id: u32,
        identity_key: &[u8]
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Required for Any backend
        install_default_drivers();
        let pool = AnyPool::connect(connection_string).await?;
        
        // Configure SQLite for optimal performance and concurrency
        if connection_string.starts_with("sqlite://") {
            Self::configure_sqlite_pragmas(&pool).await?;
        }
        
        let temp_manager = Self { pool, device_id: 0, device_jid: None };
        log::debug!("Created PersistenceManager with pool at {:p} for connection: {}", temp_manager.pool() as *const _, connection_string);
        
        // Run migrations first to ensure tables exist
        temp_manager.migrate().await?;
        
        // Create or update device record with JID
        let device_id = temp_manager.ensure_device_record_with_jid(&device_jid, registration_id, identity_key).await?;
        
        Ok(Self { pool: temp_manager.pool, device_id, device_jid: Some(device_jid) })
    }

    /// Create a new device record without JID (for initial pairing)
    #[allow(dead_code)]
    async fn create_device_record(
        &self,
        registration_id: u32,
        identity_key: &[u8]
    ) -> Result<i64, sqlx::Error> {
        log::debug!("create_device_record called with reg_id={}, key_len={}", 
                   registration_id, identity_key.len());
        
        let result = sqlx::query(
            "INSERT INTO devices (registration_id, identity_key) VALUES (?, ?)"
        )
        .bind(registration_id as i64)
        .bind(identity_key)
        .execute(&self.pool)
        .await;
        
        log::debug!("Insert result: {:?}", result);
        let result = result?;
        log::debug!("Insert affected {} rows", result.rows_affected());
        
        match result.last_insert_id() {
            Some(id) => {
                log::debug!("Got last_insert_id: {}", id);
                Ok(id)
            },
            None => {
                log::error!("Failed to get last insert ID from database after inserting device");
                log::error!("Insert result: rows_affected={}", result.rows_affected());
                // Try to get the device_id using a different method - query for the most recent insert
                let fallback_query = sqlx::query_as::<_, (i64,)>(
                    "SELECT device_id FROM devices WHERE registration_id = ? AND identity_key = ? ORDER BY device_id DESC LIMIT 1"
                )
                .bind(registration_id as i64)
                .bind(identity_key)
                .fetch_one(&self.pool)
                .await;
                
                match fallback_query {
                    Ok((device_id,)) => {
                        log::debug!("Retrieved device_id using fallback query: {}", device_id);
                        Ok(device_id)
                    }
                    Err(e) => {
                        log::error!("Fallback query also failed: {}", e);
                        Err(sqlx::Error::RowNotFound)
                    }
                }
            }
        }
    }
    
    /// Create or update device record with JID (backward compatibility)
    async fn ensure_device_record_with_jid(
        &self,
        device_jid: &str,
        registration_id: u32,
        identity_key: &[u8]
    ) -> Result<i64, sqlx::Error> {
        log::debug!("ensure_device_record_with_jid called with jid={}, reg_id={}, key_len={}", 
                   device_jid, registration_id, identity_key.len());
        
        // First check if device already exists with this JID
        let existing_device = sqlx::query_as::<_, (i64, i64, Vec<u8>)>(
            "SELECT device_id, registration_id, identity_key FROM devices WHERE jid = ?"
        )
        .bind(device_jid)
        .fetch_optional(&self.pool)
        .await?;
        
        log::debug!("Existing device query result: {:?}", existing_device.is_some());
        
        match existing_device {
            Some((device_id, existing_reg_id, existing_key)) => {
                log::debug!("Found existing device with id={}", device_id);
                // Check if parameters match - if so, no need to update
                if existing_reg_id == registration_id as i64 && existing_key == identity_key {
                    log::debug!("Device record already exists with same parameters, skipping");
                    return Ok(device_id);
                }
                // Parameters differ - need to update but this will trigger CASCADE DELETE
                log::warn!("Device record exists but parameters differ - updating will trigger CASCADE DELETE");
                log::debug!("Existing: reg_id={}, key_len={}", existing_reg_id, existing_key.len());
                log::debug!("New: reg_id={}, key_len={}", registration_id, identity_key.len());
                
                let update_result = sqlx::query(
                    "UPDATE devices SET registration_id = ?, identity_key = ? WHERE device_id = ?"
                )
                .bind(registration_id as i64)
                .bind(identity_key)
                .bind(device_id)
                .execute(&self.pool)
                .await;
                
                log::debug!("Update result: {:?}", update_result);
                update_result?;
                
                Ok(device_id)
            }
            None => {
                log::debug!("No existing device record, inserting new one");
                let result = sqlx::query(
                    "INSERT INTO devices (jid, registration_id, identity_key) VALUES (?, ?, ?)"
                )
                .bind(device_jid)
                .bind(registration_id as i64)
                .bind(identity_key)
                .execute(&self.pool)
                .await;
                
                log::debug!("Insert result: {:?}", result);
                let result = result?;
                log::debug!("Insert affected {} rows", result.rows_affected());
                
                match result.last_insert_id() {
                    Some(id) => {
                        log::debug!("Got last_insert_id: {}", id);
                        Ok(id)
                    },
                    None => {
                        log::error!("Failed to get last insert ID from database after inserting device");
                        log::error!("Insert result: rows_affected={}", result.rows_affected());
                        // Try to get the device_id using a different method
                        let fallback_query = sqlx::query_as::<_, (i64,)>(
                            "SELECT device_id FROM devices WHERE jid = ? AND registration_id = ?"
                        )
                        .bind(device_jid)
                        .bind(registration_id as i64)
                        .fetch_one(&self.pool)
                        .await;
                        
                        match fallback_query {
                            Ok((device_id,)) => {
                                log::debug!("Retrieved device_id using fallback query: {}", device_id);
                                Ok(device_id)
                            }
                            Err(e) => {
                                log::error!("Fallback query also failed: {}", e);
                                Err(sqlx::Error::RowNotFound)
                            }
                        }
                    }
                }
            }
        }
    }

    /// Run database migrations to ensure schema is up to date
    pub async fn migrate(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }

    /// Get the device ID this manager is associated with
    #[allow(dead_code)]
    pub fn device_id(&self) -> i64 {
        self.device_id
    }
    
    /// Get the device JID this manager is associated with (if available)
    pub fn device_jid(&self) -> Option<&str> {
        self.device_jid.as_deref()
    }

    /// Get access to the database pool for direct queries
    pub fn pool(&self) -> &AnyPool {
        &self.pool
    }
    
    /// Configure SQLite with optimal pragmas for performance and concurrency
    async fn configure_sqlite_pragmas(pool: &AnyPool) -> Result<(), sqlx::Error> {
        // Enable WAL mode for better concurrent access
        // WAL allows multiple readers while one writer is active
        sqlx::query("PRAGMA journal_mode = WAL")
            .execute(pool)
            .await
            .map_err(|e| {
                log::error!("Failed to set WAL mode: {}", e);
                e
            })?;
        
        // Set synchronous to NORMAL for WAL mode (good balance of safety and performance)
        // FULL is overkill for WAL mode and hurts performance
        sqlx::query("PRAGMA synchronous = NORMAL")
            .execute(pool)
            .await
            .map_err(|e| {
                log::error!("Failed to set synchronous mode: {}", e);
                e
            })?;
        
        // Increase busy timeout to 30 seconds for better handling of concurrent access
        sqlx::query("PRAGMA busy_timeout = 30000")
            .execute(pool)
            .await
            .map_err(|e| {
                log::error!("Failed to set busy timeout: {}", e);
                e
            })?;
        
        // Enable foreign key constraints (important for our CASCADE DELETE)
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(pool)
            .await
            .map_err(|e| {
                log::error!("Failed to enable foreign keys: {}", e);
                e
            })?;
        
        // Set cache size to 64MB (default is usually 2MB)
        // Negative value means size in KB
        sqlx::query("PRAGMA cache_size = -65536")
            .execute(pool)
            .await
            .map_err(|e| {
                log::error!("Failed to set cache size: {}", e);
                e
            })?;
        
        // Enable memory-mapped I/O for better performance (256MB limit)
        sqlx::query("PRAGMA mmap_size = 268435456")
            .execute(pool)
            .await
            .map_err(|e| {
                log::error!("Failed to set mmap size: {}", e);
                e
            })?;
            
        log::info!("SQLite configured with WAL mode, 30s timeout, and performance optimizations");
        Ok(())
    }
    
    /// Update the JID for this device (called after pairing completes)
    #[allow(dead_code)]
    pub async fn update_jid(&mut self, jid: String) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE devices SET jid = ? WHERE device_id = ?"
        )
        .bind(&jid)
        .bind(self.device_id)
        .execute(&self.pool)
        .await?;
        
        self.device_jid = Some(jid);
        log::info!("Updated device {} with JID: {:?}", self.device_id, self.device_jid);
        
        Ok(())
    }

    /// Close the database connection pool
    /// 
    /// This method closes all connections in the pool and cleans up resources.
    /// After calling this method, the persistence manager should not be used for database operations.
    pub async fn close(&mut self) {
        // Attempt WAL checkpoint for SQLite databases (will be ignored by other database types)
        // This helps consolidate WAL files and release locks more reliably
        log::debug!("Attempting WAL checkpoint before closing database");
        
        let checkpoint_result = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(&self.pool)
            .await;
        
        match checkpoint_result {
            Ok(_) => {
                log::debug!("WAL checkpoint completed successfully");
                // Small delay to allow OS to release file handles for SQLite
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            },
            Err(e) => {
                // This is expected for non-SQLite databases, so just debug log
                log::debug!("WAL checkpoint not applicable or failed (expected for non-SQLite): {}", e);
            }
        }
        
        self.pool.close().await;
        log::debug!("Database connection pool closed");
    }

    /// Migrate sessions, identity keys, and sender keys from phone number to LID (Link ID)
    /// 
    /// This method performs atomic migration of all Signal Protocol data associated
    /// with a phone number to a Link ID format. It handles sessions, identity keys,
    /// and sender keys in a single transaction.
    /// 
    /// # Arguments
    /// * `pn_signal` - Phone number in signal address format
    /// * `lid_signal` - Link ID in signal address format
    /// 
    /// # Returns
    /// Returns a tuple of (sessions_updated, identity_keys_updated, sender_keys_updated)
    /// 
    /// # Behavior
    /// - Attempts to UPDATE existing records to new LID format
    /// - On conflict (LID already exists), ignores the update
    /// - Always deletes the old phone number records after migration attempt
    /// - All operations are performed in a single transaction for atomicity
    pub async fn migrate_pn_to_lid(
        &self,
        pn_signal: &str,
        lid_signal: &str,
    ) -> Result<(u64, u64, u64), libsignal_protocol_rust::SignalProtocolError> {
        use log::{info, warn};
        
        let mut sessions_updated = 0u64;
        let mut identity_keys_updated = 0u64;
        let mut sender_keys_updated = 0u64;

        // Start a transaction for atomic migration
        let mut tx = self.pool.begin().await
            .map_err(|e| libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                format!("Failed to start transaction: {}", e)
            ))?;

        // 1. Migrate Sessions
        // Try to update sessions to new LID - conflicts will be ignored
        let sessions_result = sqlx::query(
            "UPDATE signal_sessions SET recipient_name = ? WHERE device_id = ? AND recipient_name = ?"
        )
        .bind(lid_signal)
        .bind(self.device_id)
        .bind(pn_signal)
        .execute(&mut *tx)
        .await;

        match sessions_result {
            Ok(result) => {
                sessions_updated = result.rows_affected();
            }
            Err(e) => {
                // Log conflict but continue - this is expected if LID sessions already exist
                warn!("Could not migrate all sessions from {} to {} due to existing LID sessions: {}", 
                      pn_signal, lid_signal, e);
            }
        }

        // Always delete old phone number sessions after migration attempt
        let _delete_sessions = sqlx::query(
            "DELETE FROM signal_sessions WHERE device_id = ? AND recipient_name = ?"
        )
        .bind(self.device_id)
        .bind(pn_signal)
        .execute(&mut *tx)
        .await
        .map_err(|e| libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
            format!("Failed to delete old sessions: {}", e)
        ))?;

        // 2. Migrate Identity Keys
        // Try to update identity keys to new LID - conflicts will be ignored
        let identity_result = sqlx::query(
            "UPDATE signal_identity_keys SET recipient_name = ? WHERE device_id = ? AND recipient_name = ?"
        )
        .bind(lid_signal)
        .bind(self.device_id)
        .bind(pn_signal)
        .execute(&mut *tx)
        .await;

        match identity_result {
            Ok(result) => {
                identity_keys_updated = result.rows_affected();
            }
            Err(e) => {
                // Log conflict but continue
                warn!("Could not migrate all identity keys from {} to {} due to existing LID keys: {}", 
                      pn_signal, lid_signal, e);
            }
        }

        // Always delete old phone number identity keys after migration attempt
        let _delete_identities = sqlx::query(
            "DELETE FROM signal_identity_keys WHERE device_id = ? AND recipient_name = ?"
        )
        .bind(self.device_id)
        .bind(pn_signal)
        .execute(&mut *tx)
        .await
        .map_err(|e| libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
            format!("Failed to delete old identity keys: {}", e)
        ))?;

        // 3. Migrate Sender Keys - both chat_id and sender_name fields
        // 3a. Migrate sender keys where chat_id matches (group keys for this phone number)
        let sender_chat_result = sqlx::query(
            "UPDATE signal_sender_keys SET group_id = ? WHERE device_id = ? AND group_id = ?"
        )
        .bind(lid_signal)
        .bind(self.device_id)
        .bind(pn_signal)
        .execute(&mut *tx)
        .await;

        match sender_chat_result {
            Ok(result) => {
                sender_keys_updated += result.rows_affected();
            }
            Err(e) => {
                warn!("Could not migrate sender keys (group_id) from {} to {} due to existing LID keys: {}", 
                      pn_signal, lid_signal, e);
            }
        }

        // 3b. Migrate sender keys where sender_name matches (keys from this phone number in groups)
        let sender_name_result = sqlx::query(
            "UPDATE signal_sender_keys SET sender_name = ? WHERE device_id = ? AND sender_name = ?"
        )
        .bind(lid_signal)
        .bind(self.device_id)
        .bind(pn_signal)
        .execute(&mut *tx)
        .await;

        match sender_name_result {
            Ok(result) => {
                sender_keys_updated += result.rows_affected();
            }
            Err(e) => {
                warn!("Could not migrate sender keys (sender_name) from {} to {} due to existing LID keys: {}", 
                      pn_signal, lid_signal, e);
            }
        }

        // Always delete old phone number sender keys after migration attempt
        let _delete_sender_chat = sqlx::query(
            "DELETE FROM signal_sender_keys WHERE device_id = ? AND group_id = ?"
        )
        .bind(self.device_id)
        .bind(pn_signal)
        .execute(&mut *tx)
        .await
        .map_err(|e| libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
            format!("Failed to delete old sender keys (group_id): {}", e)
        ))?;

        let _delete_sender_name = sqlx::query(
            "DELETE FROM signal_sender_keys WHERE device_id = ? AND sender_name = ?"
        )
        .bind(self.device_id)
        .bind(pn_signal)
        .execute(&mut *tx)
        .await
        .map_err(|e| libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
            format!("Failed to delete old sender keys (sender_name): {}", e)
        ))?;

        // Commit the transaction
        tx.commit().await
            .map_err(|e| libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
                format!("Failed to commit migration transaction: {}", e)
            ))?;

        // Log successful migration if any data was migrated
        if sessions_updated > 0 || identity_keys_updated > 0 || sender_keys_updated > 0 {
            info!("Migrated {} sessions, {} identity keys and {} sender keys from {} to {}", 
                  sessions_updated, identity_keys_updated, sender_keys_updated, pn_signal, lid_signal);
        }

        Ok((sessions_updated, identity_keys_updated, sender_keys_updated))
    }
}

// Sub-modules for different storage implementations
pub mod session_store;
pub mod identity_store;
pub mod pre_key_store;
pub mod signed_pre_key_store;
pub mod sender_key_store;

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn get_temp_db_path(test_name: &str) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        use std::fs::File;
        let temp_dir = env::temp_dir();
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let db_path = temp_dir.join(format!("test_{}_{}.db", test_name, timestamp));
        
        // Create the file to ensure it exists
        File::create(&db_path).expect("Failed to create temp database file");
        
        format!("sqlite:{}", db_path.to_string_lossy())
    }

    #[tokio::test]
    async fn test_device_creation() {
        let db_path = get_temp_db_path("device_creation");
        let manager = PersistenceManager::new_device(&db_path, 123, &[1, 2, 3])
            .await
            .expect("Failed to create persistence manager");
        
        assert!(manager.device_id() > 0);
        assert!(manager.device_jid().is_none());
    }
    
    #[tokio::test]
    async fn test_jid_update() {
        let db_path = get_temp_db_path("jid_update");
        let mut manager = PersistenceManager::new_device(&db_path, 123, &[1, 2, 3])
            .await
            .expect("Failed to create persistence manager");
        
        assert!(manager.device_jid().is_none());
        
        manager.update_jid("test@example.com".to_string())
            .await
            .expect("Failed to update JID");
        
        assert_eq!(manager.device_jid(), Some("test@example.com"));
    }
}