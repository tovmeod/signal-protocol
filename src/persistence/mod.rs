use sqlx::{AnyPool, any::install_default_drivers};

/// Main persistence manager that handles database operations
#[derive(Debug, Clone)]
pub struct PersistenceManager {
    pool: AnyPool,
    device_jid: String,
}

impl PersistenceManager {
    /// Create a new persistence manager with the given connection string and device JID
    pub async fn new(connection_string: &str, device_jid: String) -> Result<Self, sqlx::Error> {
        // Required for Any backend
        install_default_drivers();
        let pool = AnyPool::connect(connection_string).await?;
        
        // For SQLite, set pragmas to ensure immediate consistency across connections
        if connection_string.starts_with("sqlite://") {
            // Try WAL mode which is better for concurrent access
            let wal_result = sqlx::query("PRAGMA journal_mode = WAL")
                .execute(&pool)
                .await;
            let sync_result = sqlx::query("PRAGMA synchronous = FULL")
                .execute(&pool)
                .await;
            let busy_timeout = sqlx::query("PRAGMA busy_timeout = 30000")
                .execute(&pool)
                .await;
            eprintln!("DEBUG PERSISTENCE: PRAGMA journal_mode=WAL result: {:?}", wal_result);
            eprintln!("DEBUG PERSISTENCE: PRAGMA synchronous=FULL result: {:?}", sync_result);
            eprintln!("DEBUG PERSISTENCE: PRAGMA busy_timeout result: {:?}", busy_timeout);
        }
        
        Ok(Self { pool, device_jid })
    }

    /// Create a new persistence manager and set up the device record
    pub async fn new_with_device_setup(
        connection_string: &str, 
        device_jid: String,
        registration_id: u32,
        identity_key: &[u8]
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let manager = Self::new(connection_string, device_jid.clone()).await?;
        eprintln!("DEBUG PERSISTENCE: Created PersistenceManager with pool at {:p} for connection: {}", manager.pool() as *const _, connection_string);
        
        // Run migrations first to ensure tables exist
        manager.migrate().await?;
        
        // Create or update device record
        manager.ensure_device_record(registration_id, identity_key).await?;
        
        Ok(manager)
    }

    /// Ensure the device record exists in the database
    async fn ensure_device_record(
        &self,
        registration_id: u32,
        identity_key: &[u8]
    ) -> Result<(), sqlx::Error> {
        // First check if device already exists with same parameters
        let existing_device = sqlx::query_as::<_, (i64, Vec<u8>)>(
            "SELECT registration_id, identity_key FROM devices WHERE jid = ?"
        )
        .bind(&self.device_jid)
        .fetch_optional(&self.pool)
        .await?;
        
        match existing_device {
            Some((existing_reg_id, existing_key)) => {
                // Check if parameters match - if so, no need to update
                if existing_reg_id == registration_id as i64 && existing_key == identity_key {
                    eprintln!("DEBUG PERSISTENCE: Device record already exists with same parameters, skipping");
                    return Ok(());
                }
                // Parameters differ - need to update but this will trigger CASCADE DELETE
                eprintln!("DEBUG PERSISTENCE: Device record exists but parameters differ - updating will trigger CASCADE DELETE");
                eprintln!("DEBUG PERSISTENCE: Existing: reg_id={}, key_len={}", existing_reg_id, existing_key.len());
                eprintln!("DEBUG PERSISTENCE: New: reg_id={}, key_len={}", registration_id, identity_key.len());
            }
            None => {
                eprintln!("DEBUG PERSISTENCE: No existing device record, inserting new one");
            }
        }
        
        sqlx::query(
            "INSERT OR REPLACE INTO devices (jid, registration_id, identity_key) VALUES (?, ?, ?)"
        )
        .bind(&self.device_jid)
        .bind(registration_id as i64)
        .bind(identity_key)
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }

    /// Run database migrations to ensure schema is up to date
    pub async fn migrate(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }

    /// Get the device JID this manager is associated with
    pub fn device_jid(&self) -> &str {
        &self.device_jid
    }

    /// Get access to the database pool for direct queries
    pub fn pool(&self) -> &AnyPool {
        &self.pool
    }

    /// Close the database connection pool
    /// 
    /// This method closes all connections in the pool and cleans up resources.
    /// After calling this method, the persistence manager should not be used for database operations.
    pub async fn close(&mut self) {
        self.pool.close().await;
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
            "UPDATE signal_sessions SET recipient_name = ? WHERE device_jid = ? AND recipient_name = ?"
        )
        .bind(lid_signal)
        .bind(&self.device_jid)
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
            "DELETE FROM signal_sessions WHERE device_jid = ? AND recipient_name = ?"
        )
        .bind(&self.device_jid)
        .bind(pn_signal)
        .execute(&mut *tx)
        .await
        .map_err(|e| libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
            format!("Failed to delete old sessions: {}", e)
        ))?;

        // 2. Migrate Identity Keys
        // Try to update identity keys to new LID - conflicts will be ignored
        let identity_result = sqlx::query(
            "UPDATE signal_identity_keys SET recipient_name = ? WHERE device_jid = ? AND recipient_name = ?"
        )
        .bind(lid_signal)
        .bind(&self.device_jid)
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
            "DELETE FROM signal_identity_keys WHERE device_jid = ? AND recipient_name = ?"
        )
        .bind(&self.device_jid)
        .bind(pn_signal)
        .execute(&mut *tx)
        .await
        .map_err(|e| libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
            format!("Failed to delete old identity keys: {}", e)
        ))?;

        // 3. Migrate Sender Keys - both chat_id and sender_name fields
        // 3a. Migrate sender keys where chat_id matches (group keys for this phone number)
        let sender_chat_result = sqlx::query(
            "UPDATE signal_sender_keys SET group_id = ? WHERE device_jid = ? AND group_id = ?"
        )
        .bind(lid_signal)
        .bind(&self.device_jid)
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
            "UPDATE signal_sender_keys SET sender_name = ? WHERE device_jid = ? AND sender_name = ?"
        )
        .bind(lid_signal)
        .bind(&self.device_jid)
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
            "DELETE FROM signal_sender_keys WHERE device_jid = ? AND group_id = ?"
        )
        .bind(&self.device_jid)
        .bind(pn_signal)
        .execute(&mut *tx)
        .await
        .map_err(|e| libsignal_protocol_rust::SignalProtocolError::InvalidArgument(
            format!("Failed to delete old sender keys (group_id): {}", e)
        ))?;

        let _delete_sender_name = sqlx::query(
            "DELETE FROM signal_sender_keys WHERE device_jid = ? AND sender_name = ?"
        )
        .bind(&self.device_jid)
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

    #[tokio::test]
    async fn test_sqlite_connection() {
        let manager = PersistenceManager::new("sqlite::memory:", "test_device".to_string())
            .await
            .expect("Failed to create persistence manager");
        
        assert_eq!(manager.device_jid(), "test_device");
    }
}