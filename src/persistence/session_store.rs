use sqlx::Any;
use libsignal_protocol_rust::{SessionStore, ProtocolAddress, SessionRecord, Context, SignalProtocolError};
use async_trait::async_trait;
use log::{debug, error};

use super::PersistenceManager;

/// SessionStore implementation using database persistence
#[async_trait(?Send)]
impl SessionStore for PersistenceManager {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
        _ctx: Context,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        eprintln!(
            "DEBUG PERSISTENCE: Loading session for {}:{} (device: {})",
            address.name(),
            address.device_id(),
            self.device_jid
        );

        eprintln!("DEBUG PERSISTENCE: SQL Query - SELECT session_data FROM signal_sessions WHERE device_jid = '{}' AND recipient_name = '{}' AND recipient_device_id = {}", 
            &self.device_jid, address.name(), address.device_id());
            
        // Debug: Check what devices exist in this database connection
        let device_check = sqlx::query_as::<Any, (String,)>("SELECT jid FROM devices")
            .fetch_all(self.pool()).await;
        match device_check {
            Ok(devices) => {
                eprintln!("DEBUG PERSISTENCE: Devices in database: {:?}", devices);
            }
            Err(e) => {
                eprintln!("DEBUG PERSISTENCE: Error checking devices: {}", e);
            }
        }
        
        // Debug: Check what sessions exist
        let session_check = sqlx::query_as::<Any, (String, String, i32)>("SELECT device_jid, recipient_name, recipient_device_id FROM signal_sessions")
            .fetch_all(self.pool()).await;
        match session_check {
            Ok(sessions) => {
                eprintln!("DEBUG PERSISTENCE: Sessions in database: {:?}", sessions);
            }
            Err(e) => {
                eprintln!("DEBUG PERSISTENCE: Error checking sessions: {}", e);
            }
        }
        
        let session_data_result = sqlx::query_as::<Any, (Vec<u8>,)>(
            "SELECT session_data FROM signal_sessions WHERE device_jid = ? AND recipient_name = ? AND recipient_device_id = ?"
        )
        .bind(&self.device_jid)
        .bind(address.name())
        .bind(address.device_id() as i32)
        .fetch_optional(self.pool()).await;

        match session_data_result {
            Ok(Some((session_data,))) => {
                match SessionRecord::deserialize(&session_data) {
                    Ok(session) => {
                        eprintln!("DEBUG PERSISTENCE: Successfully loaded session for {}:{}", address.name(), address.device_id());
                        Ok(Some(session))
                    }
                    Err(e) => {
                        eprintln!("DEBUG PERSISTENCE: Failed to deserialize session for {}:{}: {}", address.name(), address.device_id(), e);
                        Err(SignalProtocolError::InvalidArgument(format!("Session deserialization failed: {}", e)))
                    }
                }
            }
            Ok(None) => {
                eprintln!("DEBUG PERSISTENCE: No session found for {}:{}", address.name(), address.device_id());
                Ok(None)
            }
            Err(e) => {
                eprintln!("DEBUG PERSISTENCE: Database error loading session for {}:{}: {}", address.name(), address.device_id(), e);
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
        eprintln!(
            "DEBUG PERSISTENCE: Storing session for {}:{} (device: {})",
            address.name(),
            address.device_id(),
            self.device_jid
        );

        let session_data = record.serialize()
            .map_err(|e| SignalProtocolError::InvalidArgument(format!("Session serialization failed: {}", e)))?;

        eprintln!("DEBUG PERSISTENCE: SQL Insert - INSERT OR REPLACE INTO signal_sessions (device_jid='{}', recipient_name='{}', recipient_device_id={}, session_data=<{} bytes>)", 
            &self.device_jid, address.name(), address.device_id(), session_data.len());
        
        if session_data.is_empty() {
            eprintln!("DEBUG PERSISTENCE: WARNING - Session data is empty! This might not be suitable for persistence testing.");
        }
        
        // Use explicit transaction to ensure immediate visibility
        let mut transaction = self.pool().begin().await
            .map_err(|e| SignalProtocolError::InvalidArgument(format!("Failed to begin transaction: {}", e)))?;
            
        let store_result = sqlx::query(
            "INSERT OR REPLACE INTO signal_sessions (device_jid, recipient_name, recipient_device_id, session_data) VALUES (?, ?, ?, ?)"
        )
        .bind(&self.device_jid)
        .bind(address.name())
        .bind(address.device_id() as i32)
        .bind(&session_data)
        .execute(&mut *transaction)
        .await;
        
        let final_result = match store_result {
            Ok(_) => {
                eprintln!("DEBUG PERSISTENCE: Insert successful, committing transaction");
                match transaction.commit().await {
                    Ok(_) => {
                        eprintln!("DEBUG PERSISTENCE: Successfully committed session for {}:{}", address.name(), address.device_id());
                        Ok(())
                    }
                    Err(e) => {
                        eprintln!("DEBUG PERSISTENCE: Failed to commit transaction: {:?}", e);
                        Err(SignalProtocolError::InvalidArgument(format!("Failed to commit transaction: {}", e)))
                    }
                }
            }
            Err(e) => {
                eprintln!("DEBUG PERSISTENCE: Insert failed, rolling back: {:?}", e);
                let _ = transaction.rollback().await;
                Err(SignalProtocolError::InvalidArgument(format!("Insert failed: {}", e)))
            }
        };
        
        match &final_result {
            Ok(_) => {
                // Immediately verify the session was inserted by querying it back
                let verify_result = sqlx::query_as::<Any, (Vec<u8>,)>(
                    "SELECT session_data FROM signal_sessions WHERE device_jid = ? AND recipient_name = ? AND recipient_device_id = ?"
                )
                .bind(&self.device_jid)
                .bind(address.name())
                .bind(address.device_id() as i32)
                .fetch_optional(self.pool()).await;
                
                match verify_result {
                    Ok(Some((data,))) => {
                        eprintln!("DEBUG PERSISTENCE: VERIFICATION - Session found in database after commit, {} bytes", data.len());
                    }
                    Ok(None) => {
                        eprintln!("DEBUG PERSISTENCE: VERIFICATION - Session NOT found in database after commit!");
                    }
                    Err(e) => {
                        eprintln!("DEBUG PERSISTENCE: VERIFICATION - Error querying session after commit: {}", e);
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
            "Checking if session exists for {}:{} (device: {})",
            address.name(),
            address.device_id(),
            self.device_jid
        );

        let exists_result = sqlx::query_as::<Any, (i32,)>(
            "SELECT 1 FROM signal_sessions WHERE device_jid = ? AND recipient_name = ? AND recipient_device_id = ? LIMIT 1"
        )
        .bind(&self.device_jid)
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
            "Deleting session for {}:{} (device: {})",
            recipient_name,
            recipient_device_id,
            self.device_jid
        );

        // Use execute() to get proper row count information
        let delete_result = sqlx::query(
            "DELETE FROM signal_sessions WHERE device_jid = ? AND recipient_name = ? AND recipient_device_id = ?"
        )
        .bind(&self.device_jid)
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
            "Deleting all sessions for user prefix '{}' (device: {})",
            user_prefix,
            self.device_jid
        );

        let pattern = format!("{}%", user_prefix);
        // Use execute() to get proper row count information
        let delete_result = sqlx::query(
            "DELETE FROM signal_sessions WHERE device_jid = ? AND recipient_name LIKE ?"
        )
        .bind(&self.device_jid)
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

    #[tokio::test]
    async fn test_session_store_basic_operations() {
        println!("🔧 Creating persistence manager...");
        let mut manager = PersistenceManager::new("sqlite://tmp/test_session_store.db", "test_device".to_string())
            .await
            .expect("Failed to create persistence manager");
        println!("✅ Persistence manager created");

        // Create table manually for test
        println!("🔧 Creating table...");
        let create_result = sqlx::query(
            r#"
            CREATE TABLE signal_sessions (
                device_jid VARCHAR(255) NOT NULL,
                recipient_name VARCHAR(255) NOT NULL,
                recipient_device_id INTEGER NOT NULL,
                session_data BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (device_jid, recipient_name, recipient_device_id)
            )
            "#
        )
        .execute(manager.pool())
        .await;
        
        match create_result {
            Ok(_) => println!("✅ Table created successfully"),
            Err(e) => {
                println!("❌ Failed to create table: {:?}", e);
                panic!("Table creation failed");
            }
        }

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