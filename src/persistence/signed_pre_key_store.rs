use sqlx::Any;
use libsignal_protocol_rust::{SignedPreKeyStore, SignedPreKeyRecord, Context, SignalProtocolError};
use async_trait::async_trait;
use log::{debug, error};

use super::PersistenceManager;

/// SignedPreKeyStore implementation using database persistence
#[async_trait(?Send)]
impl SignedPreKeyStore for PersistenceManager {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: u32,
        _ctx: Context,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        debug!(
            "Loading signed pre-key {} (device_id: {})",
            signed_prekey_id,
            self.device_id
        );

        let key_data_result = sqlx::query_as::<Any, (Vec<u8>,)>(
            "SELECT key_data FROM signal_signed_pre_keys WHERE device_id = ? AND key_id = ?"
        )
        .bind(self.device_id)
        .bind(signed_prekey_id as i32)
        .fetch_optional(self.pool()).await;

        match key_data_result {
            Ok(Some((key_data,))) => {
                match SignedPreKeyRecord::deserialize(&key_data) {
                    Ok(record) => {
                        debug!("Successfully loaded signed pre-key {}", signed_prekey_id);
                        Ok(record)
                    }
                    Err(e) => {
                        error!("Failed to deserialize signed pre-key {}: {}", signed_prekey_id, e);
                        Err(SignalProtocolError::InvalidArgument(format!("SignedPreKey deserialization failed: {}", e)))
                    }
                }
            }
            Ok(None) => {
                debug!("No signed pre-key found for ID {}", signed_prekey_id);
                Err(SignalProtocolError::InvalidArgument(format!("SignedPreKey {} not found", signed_prekey_id)))
            }
            Err(e) => {
                error!("Database error loading signed pre-key {}: {}", signed_prekey_id, e);
                Err(SignalProtocolError::InvalidArgument(format!("Database error: {}", e)))
            }
        }
    }

    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: u32,
        record: &SignedPreKeyRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        debug!(
            "Storing signed pre-key {} (device_id: {})",
            signed_prekey_id,
            self.device_id
        );

        let key_data = record.serialize()
            .map_err(|e| SignalProtocolError::InvalidArgument(format!("SignedPreKey serialization failed: {}", e)))?;

        let store_result = sqlx::query_as::<Any, ()>(
            "INSERT OR REPLACE INTO signal_signed_pre_keys (device_id, key_id, key_data) VALUES (?, ?, ?)"
        )
        .bind(self.device_id)
        .bind(signed_prekey_id as i32)
        .bind(&key_data)
        .fetch_optional(self.pool())
        .await
        .map(|_| ());

        match store_result {
            Ok(_) => {
                debug!("Successfully stored signed pre-key {}", signed_prekey_id);
                Ok(())
            }
            Err(e) => {
                error!("Database error storing signed pre-key {}: {}", signed_prekey_id, e);
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
    async fn test_signed_pre_key_store_basic_operations() {
        println!("🔧 Creating persistence manager...");
        
        // Generate test identity key
        let identity_key_pair = libsignal_protocol_rust::IdentityKeyPair::generate(&mut rand::thread_rng());
        let identity_key_bytes = identity_key_pair.public_key().serialize();
        
        let db_path = get_temp_db_path("signed_pre_key_store");
        let mut manager = PersistenceManager::new_with_jid_setup(
            &db_path, 
            "test_device".to_string(),
            123, // registration_id
            &identity_key_bytes
        )
        .await
        .expect("Failed to create persistence manager");
        println!("✅ Persistence manager created");

        // Run migrations to create proper schema
        println!("🔧 Running migrations...");
        manager.migrate().await.expect("Failed to run migrations");
        println!("✅ Migrations completed");

        // Test 1: Create and store a signed pre-key
        let signed_pre_key_pair = libsignal_protocol_rust::KeyPair::generate(&mut rand::thread_rng());
        let signature = [0u8; 64]; // Placeholder signature for test
        let signed_pre_key_record = libsignal_protocol_rust::SignedPreKeyRecord::new(
            456, 
            42, // timestamp
            &signed_pre_key_pair, 
            &signature
        );
        
        manager.save_signed_pre_key(456, &signed_pre_key_record, None).await.unwrap();
        println!("✅ Save signed pre-key works");

        // Test 2: Get the stored signed pre-key
        let loaded_record = manager.get_signed_pre_key(456, None).await.unwrap();
        assert_eq!(loaded_record.serialize().unwrap(), signed_pre_key_record.serialize().unwrap());
        println!("✅ Get signed pre-key works");

        // Test 3: Try to get non-existent signed pre-key (should fail)
        assert!(manager.get_signed_pre_key(999, None).await.is_err());
        println!("✅ Get non-existent signed pre-key fails correctly");
        
        println!("🎉 SignedPreKeyStore database implementation works completely!");
    }
}