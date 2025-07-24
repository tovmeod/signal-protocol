use sqlx::Any;
use libsignal_protocol_rust::{SessionStore, ProtocolAddress, SessionRecord, Context, SignalProtocolError};
use async_trait::async_trait;
use log::{debug, error, warn};

use super::PersistenceManager;

/// SessionStore implementation using database persistence
#[async_trait(?Send)]
impl SessionStore for PersistenceManager {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
        _ctx: Context,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        debug!(
            "Loading session for {}:{} (device_id: {})",
            address.name(),
            address.device_id(),
            self.device_id
        );

        debug!("SQL Query - SELECT session_data FROM signal_sessions WHERE device_id = {} AND recipient_name = '{}' AND recipient_device_id = {}", 
            self.device_id, address.name(), address.device_id());
            
        // Debug: Check what devices exist in this database connection
        let device_check = sqlx::query_as::<Any, (i64, Option<String>)>("SELECT device_id, jid FROM devices")
            .fetch_all(self.pool()).await;
        match device_check {
            Ok(devices) => {
                debug!("Devices in database: {:?}", devices);
            }
            Err(e) => {
                debug!("Error checking devices: {}", e);
            }
        }
        
        // Debug: Check what sessions exist
        let session_check = sqlx::query_as::<Any, (i64, String, i32)>("SELECT device_id, recipient_name, recipient_device_id FROM signal_sessions")
            .fetch_all(self.pool()).await;
        match session_check {
            Ok(sessions) => {
                debug!("Sessions in database: {:?}", sessions);
            }
            Err(e) => {
                debug!("Error checking sessions: {}", e);
            }
        }
        
        let session_data_result = sqlx::query_as::<Any, (Vec<u8>,)>(
            "SELECT session_data FROM signal_sessions WHERE device_id = ? AND recipient_name = ? AND recipient_device_id = ?"
        )
        .bind(self.device_id)
        .bind(address.name())
        .bind(address.device_id() as i32)
        .fetch_optional(self.pool()).await;

        match session_data_result {
            Ok(Some((session_data,))) => {
                match SessionRecord::deserialize(&session_data) {
                    Ok(session) => {
                        debug!("Successfully loaded session for {}:{}", address.name(), address.device_id());
                        Ok(Some(session))
                    }
                    Err(e) => {
                        error!("Failed to deserialize session for {}:{}: {}", address.name(), address.device_id(), e);
                        Err(SignalProtocolError::InvalidArgument(format!("Session deserialization failed: {}", e)))
                    }
                }
            }
            Ok(None) => {
                debug!("No session found for {}:{}", address.name(), address.device_id());
                Ok(None)
            }
            Err(e) => {
                error!("Database error loading session for {}:{}: {}", address.name(), address.device_id(), e);
                Err(SignalProtocolError::InvalidArgument(format!("Database error: {}", e)))
            }
        }
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        debug!(
            "Storing session for {}:{} (device_id: {})",
            address.name(),
            address.device_id(),
            self.device_id
        );

        let session_data = record.serialize()
            .map_err(|e| SignalProtocolError::InvalidArgument(format!("Session serialization failed: {}", e)))?;

        debug!("SQL Insert - INSERT OR REPLACE INTO signal_sessions (device_id={}, recipient_name='{}', recipient_device_id={}, session_data=<{} bytes>)", 
            self.device_id, address.name(), address.device_id(), session_data.len());
        
        if session_data.is_empty() {
            warn!("Session data is empty! This might not be suitable for persistence testing.");
        }
        
        // Use explicit transaction to ensure immediate visibility
        let mut transaction = self.pool().begin().await
            .map_err(|e| SignalProtocolError::InvalidArgument(format!("Failed to begin transaction: {}", e)))?;
            
        let store_result = sqlx::query(
            "INSERT OR REPLACE INTO signal_sessions (device_id, recipient_name, recipient_device_id, session_data) VALUES (?, ?, ?, ?)"
        )
        .bind(self.device_id)
        .bind(address.name())
        .bind(address.device_id() as i32)
        .bind(&session_data)
        .execute(&mut *transaction)
        .await;
        
        let final_result = match store_result {
            Ok(_) => {
                debug!("Insert successful, committing transaction");
                match transaction.commit().await {
                    Ok(_) => {
                        debug!("Successfully committed session for {}:{}", address.name(), address.device_id());
                        Ok(())
                    }
                    Err(e) => {
                        error!("Failed to commit transaction: {:?}", e);
                        Err(SignalProtocolError::InvalidArgument(format!("Failed to commit transaction: {}", e)))
                    }
                }
            }
            Err(e) => {
                error!("Insert failed, rolling back: {:?}", e);
                let _ = transaction.rollback().await;
                Err(SignalProtocolError::InvalidArgument(format!("Insert failed: {}", e)))
            }
        };
        
        match &final_result {
            Ok(_) => {
                // Immediately verify the session was inserted by querying it back
                let verify_result = sqlx::query_as::<Any, (Vec<u8>,)>(
                    "SELECT session_data FROM signal_sessions WHERE device_id = ? AND recipient_name = ? AND recipient_device_id = ?"
                )
                .bind(self.device_id)
                .bind(address.name())
                .bind(address.device_id() as i32)
                .fetch_optional(self.pool()).await;
                
                match verify_result {
                    Ok(Some((data,))) => {
                        debug!("VERIFICATION - Session found in database after commit, {} bytes", data.len());
                    }
                    Ok(None) => {
                        warn!("VERIFICATION - Session NOT found in database after commit!");
                    }
                    Err(e) => {
                        error!("VERIFICATION - Error querying session after commit: {}", e);
                    }
                }
            }
            Err(_) => {}
        }
        
        final_result
    }
}

impl PersistenceManager {
    /// Check if a session exists for the given address (app-level utility function)
    pub async fn contains_session(&self, address: &ProtocolAddress) -> Result<bool, SignalProtocolError> {
        debug!(
            "Checking if session exists for {}:{} (device_id: {})",
            address.name(),
            address.device_id(),
            self.device_id
        );

        let exists_result = sqlx::query_as::<Any, (i32,)>(
            "SELECT 1 FROM signal_sessions WHERE device_id = ? AND recipient_name = ? AND recipient_device_id = ? LIMIT 1"
        )
        .bind(self.device_id)
        .bind(address.name())
        .bind(address.device_id() as i32)
        .fetch_optional(self.pool()).await;

        match exists_result {
            Ok(row) => Ok(row.is_some()),
            Err(e) => {
                error!("Database error checking session existence for {}:{}: {}", address.name(), address.device_id(), e);
                Err(SignalProtocolError::InvalidArgument(format!("Database error: {}", e)))
            }
        }
    }

    /// Delete a specific session (app-level utility function)
    pub async fn delete_session(&self, recipient_name: &str, recipient_device_id: i32) -> Result<bool, SignalProtocolError> {
        debug!(
            "Deleting session for {}:{} (device_id: {})",
            recipient_name,
            recipient_device_id,
            self.device_id
        );

        // Use execute() to get proper row count information
        let delete_result = sqlx::query(
            "DELETE FROM signal_sessions WHERE device_id = ? AND recipient_name = ? AND recipient_device_id = ?"
        )
        .bind(self.device_id)
        .bind(recipient_name)
        .bind(recipient_device_id)
        .execute(self.pool())
        .await;

        match delete_result {
            Ok(result) => {
                let deleted = result.rows_affected() > 0;
                if deleted {
                    debug!("Successfully deleted session for {}:{}", recipient_name, recipient_device_id);
                } else {
                    debug!("No session found to delete for {}:{}", recipient_name, recipient_device_id);
                }
                Ok(deleted)
            }
            Err(e) => {
                error!("Database error deleting session for {}:{}: {}", recipient_name, recipient_device_id, e);
                Err(SignalProtocolError::InvalidArgument(format!("Database error: {}", e)))
            }
        }
    }

    /// Delete all sessions for a user prefix (app-level utility function)
    pub async fn delete_all_sessions_for_user(&self, user_prefix: &str) -> Result<i32, SignalProtocolError> {
        debug!(
            "Deleting all sessions for user prefix '{}' (device_id: {})",
            user_prefix,
            self.device_id
        );

        let pattern = format!("{}%", user_prefix);
        // Use execute() to get proper row count information
        let delete_result = sqlx::query(
            "DELETE FROM signal_sessions WHERE device_id = ? AND recipient_name LIKE ?"
        )
        .bind(self.device_id)
        .bind(pattern)
        .execute(self.pool())
        .await;

        match delete_result {
            Ok(result) => {
                let deleted_count = result.rows_affected() as i32;
                debug!("Successfully deleted {} sessions for user prefix '{}'", deleted_count, user_prefix);
                Ok(deleted_count)
            }
            Err(e) => {
                error!("Database error deleting sessions for user prefix '{}': {}", user_prefix, e);
                Err(SignalProtocolError::InvalidArgument(format!("Database error: {}", e)))
            }
        }
    }
}

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
    async fn test_session_store_basic_operations() {
        println!("🔧 Creating persistence manager...");
        let db_path = get_temp_db_path("session_store");
        let mut manager = PersistenceManager::new_device(&db_path, 123, &[1, 2, 3])
            .await
            .expect("Failed to create persistence manager");
        println!("✅ Persistence manager created");

        // Run migrations to create proper schema
        println!("🔧 Running migrations...");
        manager.migrate().await.expect("Failed to run migrations");
        println!("✅ Migrations completed");

        // Migrations have already created the tables

        let address_libsignal = libsignal_protocol_rust::ProtocolAddress::new("test_user".to_string(), 1);

        // Test 1: Load should return None initially
        let loaded = manager.load_session(&address_libsignal, None).await.unwrap();
        assert!(loaded.is_none());
        println!("✅ Load empty session works");

        // Test 2: Contains session should return false initially  
        assert!(!manager.contains_session(&address_libsignal).await.unwrap());
        println!("✅ Contains empty session works");

        // Test 3: Create and store a session
        let session = SessionRecord::new_fresh();
        manager.store_session(&address_libsignal, &session, None).await.unwrap();
        println!("✅ Store session works");

        // Test 4: Contains session should now return true
        assert!(manager.contains_session(&address_libsignal).await.unwrap());
        println!("✅ Contains stored session works");

        // Test 5: Load should return the stored session
        let loaded = manager.load_session(&address_libsignal, None).await.unwrap();
        assert!(loaded.is_some());
        println!("✅ Load stored session works");
        
        println!("🎉 SessionStore database implementation works completely!");
    }
}