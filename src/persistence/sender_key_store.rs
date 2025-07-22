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
            "Storing sender key for group '{}' sender '{}:{}' (device: {})",
            group_id,
            sender_name,
            sender_device_id,
            self.device_jid
        );

        let key_data = record.serialize()
            .map_err(|e| SignalProtocolError::InvalidArgument(format!("SenderKey serialization failed: {}", e)))?;

        let store_result = sqlx::query_as::<Any, ()>(
            "INSERT OR REPLACE INTO signal_sender_keys (device_jid, group_id, sender_name, sender_device_id, sender_key) VALUES (?, ?, ?, ?, ?)"
        )
        .bind(&self.device_jid)
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
            "Loading sender key for group '{}' sender '{}:{}' (device: {})",
            group_id,
            sender_name,
            sender_device_id,
            self.device_jid
        );

        let key_data_result = sqlx::query_as::<Any, (Vec<u8>,)>(
            "SELECT sender_key FROM signal_sender_keys WHERE device_jid = ? AND group_id = ? AND sender_name = ? AND sender_device_id = ?"
        )
        .bind(&self.device_jid)
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

    #[tokio::test]
    async fn test_sender_key_store_basic_operations() {
        println!("🔧 Creating persistence manager...");
        let mut manager = PersistenceManager::new("sqlite://tmp/test_sender_key_store.db", "test_device".to_string())
            .await
            .expect("Failed to create persistence manager");
        println!("✅ Persistence manager created");

        // Create table manually for test
        println!("🔧 Creating table...");
        let create_result = sqlx::query(
            r#"
            CREATE TABLE signal_sender_keys (
                device_jid VARCHAR(255) NOT NULL,
                group_id VARCHAR(255) NOT NULL,
                sender_name VARCHAR(255) NOT NULL,
                sender_device_id INTEGER NOT NULL,
                sender_key BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (device_jid, group_id, sender_name, sender_device_id)
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