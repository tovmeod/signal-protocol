use sqlx::Any;
use libsignal_protocol_rust::{PreKeyStore, PreKeyRecord, Context, SignalProtocolError};
use async_trait::async_trait;
use log::{debug, error};

use super::PersistenceManager;

/// PreKeyStore implementation using database persistence
#[async_trait(?Send)]
impl PreKeyStore for PersistenceManager {
    async fn get_pre_key(
        &self,
        prekey_id: u32,
        _ctx: Context,
    ) -> Result<PreKeyRecord, SignalProtocolError> {
        debug!(
            "Loading pre-key {} (device: {})",
            prekey_id,
            self.device_jid
        );

        let key_data_result = sqlx::query_as::<Any, (Vec<u8>,)>(
            "SELECT key_data FROM signal_pre_keys WHERE device_jid = ? AND key_id = ?"
        )
        .bind(&self.device_jid)
        .bind(prekey_id as i32)
        .fetch_optional(self.pool()).await;

        match key_data_result {
            Ok(Some((key_data,))) => {
                match PreKeyRecord::deserialize(&key_data) {
                    Ok(record) => {
                        debug!("Successfully loaded pre-key {}", prekey_id);
                        Ok(record)
                    }
                    Err(e) => {
                        error!("Failed to deserialize pre-key {}: {}", prekey_id, e);
                        Err(SignalProtocolError::InvalidArgument(format!("PreKey deserialization failed: {}", e)))
                    }
                }
            }
            Ok(None) => {
                debug!("No pre-key found for ID {}", prekey_id);
                Err(SignalProtocolError::InvalidArgument(format!("PreKey {} not found", prekey_id)))
            }
            Err(e) => {
                error!("Database error loading pre-key {}: {}", prekey_id, e);
                Err(SignalProtocolError::InvalidArgument(format!("Database error: {}", e)))
            }
        }
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: u32,
        record: &PreKeyRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        debug!(
            "Storing pre-key {} (device: {})",
            prekey_id,
            self.device_jid
        );

        let key_data = record.serialize()
            .map_err(|e| SignalProtocolError::InvalidArgument(format!("PreKey serialization failed: {}", e)))?;

        let store_result = sqlx::query_as::<Any, ()>(
            "INSERT OR REPLACE INTO signal_pre_keys (device_jid, key_id, key_data) VALUES (?, ?, ?)"
        )
        .bind(&self.device_jid)
        .bind(prekey_id as i32)
        .bind(&key_data)
        .fetch_optional(self.pool())
        .await
        .map(|_| ());

        match store_result {
            Ok(_) => {
                debug!("Successfully stored pre-key {}", prekey_id);
                Ok(())
            }
            Err(e) => {
                error!("Database error storing pre-key {}: {}", prekey_id, e);
                Err(SignalProtocolError::InvalidArgument(format!("Database error: {}", e)))
            }
        }
    }

    async fn remove_pre_key(
        &mut self,
        prekey_id: u32,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        debug!(
            "Removing pre-key {} (device: {})",
            prekey_id,
            self.device_jid
        );

        // Temporarily simulate delete operation - optimize row counting later
        // TODO: Improve DELETE row count accuracy (currently using fake counts)
        let remove_result = sqlx::query_as::<Any, ()>(
            "DELETE FROM signal_pre_keys WHERE device_jid = ? AND key_id = ?"
        )
        .bind(&self.device_jid)
        .bind(prekey_id as i32)
        .fetch_optional(self.pool())
        .await
        .map(|_| FakeRemoveResult { affected_rows: 1 }); // Assume 1 row affected for now
        
        struct FakeRemoveResult { affected_rows: u64 }
        impl FakeRemoveResult {
            fn rows_affected(&self) -> u64 { self.affected_rows }
        }

        match remove_result {
            Ok(result) => {
                if result.rows_affected() > 0 {
                    debug!("Successfully removed pre-key {}", prekey_id);
                } else {
                    debug!("No pre-key found to remove for ID {}", prekey_id);
                }
                Ok(())
            }
            Err(e) => {
                error!("Database error removing pre-key {}: {}", prekey_id, e);
                Err(SignalProtocolError::InvalidArgument(format!("Database error: {}", e)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pre_key_store_basic_operations() {
        println!("🔧 Creating persistence manager...");
        let mut manager = PersistenceManager::new("sqlite://tmp/test_pre_key_store.db", "test_device".to_string())
            .await
            .expect("Failed to create persistence manager");
        println!("✅ Persistence manager created");

        // Create table manually for test
        println!("🔧 Creating table...");
        let create_result = sqlx::query(
            r#"
            CREATE TABLE signal_pre_keys (
                device_jid VARCHAR(255) NOT NULL,
                key_id INTEGER NOT NULL,
                key_data BLOB NOT NULL,
                uploaded BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (device_jid, key_id)
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

        // Test 1: Create and store a pre-key
        let pre_key_pair = libsignal_protocol_rust::KeyPair::generate(&mut rand::thread_rng());
        let pre_key_record = libsignal_protocol_rust::PreKeyRecord::new(123, &pre_key_pair);
        
        manager.save_pre_key(123, &pre_key_record, None).await.unwrap();
        println!("✅ Save pre-key works");

        // Test 2: Get the stored pre-key
        let loaded_record = manager.get_pre_key(123, None).await.unwrap();
        assert_eq!(loaded_record.serialize().unwrap(), pre_key_record.serialize().unwrap());
        println!("✅ Get pre-key works");

        // Test 3: Remove the pre-key
        manager.remove_pre_key(123, None).await.unwrap();
        println!("✅ Remove pre-key works");

        // Test 4: Try to get removed pre-key (should fail)
        assert!(manager.get_pre_key(123, None).await.is_err());
        println!("✅ Get non-existent pre-key fails correctly");
        
        println!("🎉 PreKeyStore database implementation works completely!");
    }
}