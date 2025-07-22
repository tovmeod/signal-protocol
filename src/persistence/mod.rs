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