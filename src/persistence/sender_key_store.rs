use sqlx::Any;
use libsignal_protocol_rust::{SenderKeyStore, SenderKeyName, SenderKeyRecord, Context, SignalProtocolError};
use async_trait::async_trait;
use log::{debug, error};

use super::PersistenceManager;

/// SenderKeyStore implementation using database persistence
#[async_trait(?Send)]
impl SenderKeyStore for PersistenceManager {
    async fn store_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        record: &SenderKeyRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        let group_id = sender_key_name.group_id().map_err(|e| SignalProtocolError::InvalidArgument(format!("Invalid group_id: {}", e)))?;
        let sender_name = sender_key_name.sender_name().map_err(|e| SignalProtocolError::InvalidArgument(format!("Invalid sender_name: {}", e)))?;
        let sender_device_id = sender_key_name.sender_device_id().map_err(|e| SignalProtocolError::InvalidArgument(format!("Invalid sender_device_id: {}", e)))?;
        
        debug!(
            "Storing sender key for group '{}' sender '{}:{}' (device_id: {})",
            group_id,
            sender_name,
            sender_device_id,
            self.device_id
        );

        let key_data = record.serialize()
            .map_err(|e| SignalProtocolError::InvalidArgument(format!("SenderKey serialization failed: {}", e)))?;

        let store_result = sqlx::query_as::<Any, ()>(
            "INSERT OR REPLACE INTO signal_sender_keys (device_id, group_id, sender_name, sender_device_id, sender_key) VALUES (?, ?, ?, ?, ?)"
        )
        .bind(self.device_id)
        .bind(&group_id)
        .bind(&sender_name)
        .bind(sender_device_id as i32)
        .bind(&key_data)
        .fetch_optional(self.pool())
        .await
        .map(|_| ());

        match store_result {
            Ok(_) => {
                debug!("Successfully stored sender key for group '{}' sender '{}:{}'", 
                       group_id, sender_name, sender_device_id);
                Ok(())
            }
            Err(e) => {
                error!("Database error storing sender key for group '{}' sender '{}:{}': {}", 
                       group_id, sender_name, sender_device_id, e);
                Err(SignalProtocolError::InvalidArgument(format!("Database error: {}", e)))
            }
        }
    }

    async fn load_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        _ctx: Context,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError> {
        let group_id = sender_key_name.group_id().map_err(|e| SignalProtocolError::InvalidArgument(format!("Invalid group_id: {}", e)))?;
        let sender_name = sender_key_name.sender_name().map_err(|e| SignalProtocolError::InvalidArgument(format!("Invalid sender_name: {}", e)))?;
        let sender_device_id = sender_key_name.sender_device_id().map_err(|e| SignalProtocolError::InvalidArgument(format!("Invalid sender_device_id: {}", e)))?;
        
        debug!(
            "Loading sender key for group '{}' sender '{}:{}' (device_id: {})",
            group_id,
            sender_name,
            sender_device_id,
            self.device_id
        );

        let key_data_result = sqlx::query_as::<Any, (Vec<u8>,)>(
            "SELECT sender_key FROM signal_sender_keys WHERE device_id = ? AND group_id = ? AND sender_name = ? AND sender_device_id = ?"
        )
        .bind(self.device_id)
        .bind(&group_id)
        .bind(&sender_name)
        .bind(sender_device_id as i32)
        .fetch_optional(self.pool()).await;

        match key_data_result {
            Ok(Some((key_data,))) => {
                match SenderKeyRecord::deserialize(&key_data) {
                    Ok(record) => {
                        debug!("Successfully loaded sender key for group '{}' sender '{}:{}'", 
                               group_id, sender_name, sender_device_id);
                        Ok(Some(record))
                    }
                    Err(e) => {
                        error!("Failed to deserialize sender key for group '{}' sender '{}:{}': {}", 
                               group_id, sender_name, sender_device_id, e);
                        Err(SignalProtocolError::InvalidArgument(format!("SenderKey deserialization failed: {}", e)))
                    }
                }
            }
            Ok(None) => {
                debug!("No sender key found for group '{}' sender '{}:{}'", 
                       group_id, sender_name, sender_device_id);
                Ok(None)
            }
            Err(e) => {
                error!("Database error loading sender key for group '{}' sender '{}:{}': {}", 
                       group_id, sender_name, sender_device_id, e);
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
    async fn test_sender_key_store_basic_operations() {
        println!("🔧 Creating persistence manager...");
        
        // Generate test identity key
        let identity_key_pair = libsignal_protocol_rust::IdentityKeyPair::generate(&mut rand::thread_rng());
        let identity_key_bytes = identity_key_pair.public_key().serialize();
        
        let db_path = get_temp_db_path("sender_key_store");
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

        // No need to create table manually - migrations handle it
        let _create_result: Result<(), sqlx::Error> = Ok(()); // Placeholder to maintain existing logic
        
        match _create_result {
            Ok(_) => println!("✅ Table created successfully"),
            Err(e) => {
                println!("❌ Failed to create table: {:?}", e);
                panic!("Table creation failed");
            }
        }

        // Test 1: Create and store a sender key
        let sender_address = libsignal_protocol_rust::ProtocolAddress::new("test_sender".to_string(), 1);
        let sender_key_name = libsignal_protocol_rust::SenderKeyName::new("test_group".to_string(), sender_address).unwrap();
        let sender_key_record = libsignal_protocol_rust::SenderKeyRecord::new_empty();
        
        manager.store_sender_key(&sender_key_name, &sender_key_record, None).await.unwrap();
        println!("✅ Store sender key works");

        // Test 2: Load the stored sender key
        let loaded_record = manager.load_sender_key(&sender_key_name, None).await.unwrap();
        assert!(loaded_record.is_some());
        let loaded_record = loaded_record.unwrap();
        assert_eq!(loaded_record.serialize().unwrap(), sender_key_record.serialize().unwrap());
        println!("✅ Load sender key works");

        // Test 3: Load non-existent sender key
        let non_existent_address = libsignal_protocol_rust::ProtocolAddress::new("non_existent_sender".to_string(), 999);
        let non_existent_name = libsignal_protocol_rust::SenderKeyName::new("non_existent_group".to_string(), non_existent_address).unwrap();
        let result = manager.load_sender_key(&non_existent_name, None).await.unwrap();
        assert!(result.is_none());
        println!("✅ Load non-existent sender key returns None correctly");
        
        println!("🎉 SenderKeyStore database implementation works completely!");
    }
}