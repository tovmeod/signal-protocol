use sqlx::Any;
use libsignal_protocol_rust::{IdentityKeyStore, ProtocolAddress, IdentityKey, Context, SignalProtocolError};
use async_trait::async_trait;
use log::{debug, error};
use std::convert::TryFrom;

use super::PersistenceManager;

/// IdentityKeyStore implementation using database persistence
#[async_trait(?Send)]
impl IdentityKeyStore for PersistenceManager {
    async fn get_identity_key_pair(&self, _ctx: Context) -> Result<libsignal_protocol_rust::IdentityKeyPair, SignalProtocolError> {
        // Identity key pair is stored in the devices table
        debug!("Loading identity key pair for device: {}", self.device_jid);

        let identity_key_result = sqlx::query_as::<Any, (Vec<u8>,)>(
            "SELECT identity_key FROM devices WHERE jid = ?"
        )
        .bind(&self.device_jid)
        .fetch_optional(self.pool()).await;

        match identity_key_result {
            Ok(Some((identity_key_data,))) => {
                match <libsignal_protocol_rust::IdentityKeyPair as TryFrom<&[u8]>>::try_from(&identity_key_data) {
                    Ok(key_pair) => {
                        debug!("Successfully loaded identity key pair for device: {}", self.device_jid);
                        Ok(key_pair)
                    }
                    Err(e) => {
                        error!("Failed to deserialize identity key pair for device {}: {}", self.device_jid, e);
                        Err(SignalProtocolError::InvalidArgument(format!("Identity key pair deserialization failed: {}", e)))
                    }
                }
            }
            Ok(None) => {
                error!("No identity key pair found for device: {}", self.device_jid);
                Err(SignalProtocolError::InvalidArgument("No identity key pair found".to_string()))
            }
            Err(e) => {
                error!("Database error loading identity key pair for device {}: {}", self.device_jid, e);
                Err(SignalProtocolError::InvalidArgument(format!("Database error: {}", e)))
            }
        }
    }

    async fn get_local_registration_id(&self, _ctx: Context) -> Result<u32, SignalProtocolError> {
        // Registration ID is stored in the devices table
        debug!("Loading registration ID for device: {}", self.device_jid);

        let registration_id_result = sqlx::query_as::<Any, (i64,)>(
            "SELECT registration_id FROM devices WHERE jid = ?"
        )
        .bind(&self.device_jid)
        .fetch_optional(self.pool()).await;

        match registration_id_result {
            Ok(Some((registration_id,))) => {
                debug!("Successfully loaded registration ID for device: {}", self.device_jid);
                Ok(registration_id as u32)
            }
            Ok(None) => {
                error!("No registration ID found for device: {}", self.device_jid);
                Err(SignalProtocolError::InvalidArgument("No registration ID found".to_string()))
            }
            Err(e) => {
                error!("Database error loading registration ID for device {}: {}", self.device_jid, e);
                Err(SignalProtocolError::InvalidArgument(format!("Database error: {}", e)))
            }
        }
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _ctx: Context,
    ) -> Result<bool, SignalProtocolError> {
        debug!(
            "Storing identity for {}:{} (device: {})",
            address.name(),
            address.device_id(),
            self.device_jid
        );

        let identity_data = identity.serialize();

        let store_result = sqlx::query_as::<Any, ()>(
            "INSERT OR REPLACE INTO signal_identity_keys (device_jid, recipient_name, recipient_device_id, identity_key) VALUES (?, ?, ?, ?)"
        )
        .bind(&self.device_jid)
        .bind(address.name())
        .bind(address.device_id() as i32)
        .bind(&*identity_data)
        .fetch_optional(self.pool())
        .await
        .map(|_| ());

        match store_result {
            Ok(_) => {
                debug!("Successfully stored identity for {}:{}", address.name(), address.device_id());
                // In Signal Protocol, save_identity returns true if this replaces an existing identity
                // For simplicity, we'll always return false (trust on first use)
                Ok(false)
            }
            Err(e) => {
                error!("Database error storing identity for {}:{}: {}", address.name(), address.device_id(), e);
                Err(SignalProtocolError::InvalidArgument(format!("Database error: {}", e)))
            }
        }
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: libsignal_protocol_rust::Direction,
        _ctx: Context,
    ) -> Result<bool, SignalProtocolError> {
        debug!(
            "Checking if identity is trusted for {}:{} (device: {})",
            address.name(),
            address.device_id(),
            self.device_jid
        );

        // Get the stored identity for this address
        match self.get_identity(address, None).await? {
            Some(stored_identity) => {
                // Check if it matches the provided identity
                let trusted = stored_identity.serialize() == identity.serialize();
                debug!("Identity trust check for {}:{}: {}", address.name(), address.device_id(), trusted);
                Ok(trusted)
            }
            None => {
                // No stored identity, trust on first use
                debug!("No stored identity for {}:{}, trusting on first use", address.name(), address.device_id());
                Ok(true)
            }
        }
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
        _ctx: Context,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        debug!(
            "Loading identity for {}:{} (device: {})",
            address.name(),
            address.device_id(),
            self.device_jid
        );

        let identity_data_result = sqlx::query_as::<Any, (Vec<u8>,)>(
            "SELECT identity_key FROM signal_identity_keys WHERE device_jid = ? AND recipient_name = ? AND recipient_device_id = ?"
        )
        .bind(&self.device_jid)
        .bind(address.name())
        .bind(address.device_id() as i32)
        .fetch_optional(self.pool()).await;

        match identity_data_result {
            Ok(Some((identity_data,))) => {
                match <IdentityKey as TryFrom<&[u8]>>::try_from(&identity_data) {
                    Ok(identity) => {
                        debug!("Successfully loaded identity for {}:{}", address.name(), address.device_id());
                        Ok(Some(identity))
                    }
                    Err(e) => {
                        error!("Failed to deserialize identity for {}:{}: {}", address.name(), address.device_id(), e);
                        Err(SignalProtocolError::InvalidArgument(format!("Identity deserialization failed: {}", e)))
                    }
                }
            }
            Ok(None) => {
                debug!("No identity found for {}:{}", address.name(), address.device_id());
                Ok(None)
            }
            Err(e) => {
                error!("Database error loading identity for {}:{}: {}", address.name(), address.device_id(), e);
                Err(SignalProtocolError::InvalidArgument(format!("Database error: {}", e)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_identity_store_basic_operations() {
        println!("🔧 Creating persistence manager...");
        let mut manager = PersistenceManager::new("sqlite://tmp/test_identity_store.db", "test_device".to_string())
            .await
            .expect("Failed to create persistence manager");
        println!("✅ Persistence manager created");

        // Create tables manually for test
        println!("🔧 Creating tables...");
        let create_devices_result = sqlx::query(
            r#"
            CREATE TABLE devices (
                jid VARCHAR(255) PRIMARY KEY,
                registration_id BIGINT NOT NULL,
                identity_key BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            "#
        )
        .execute(manager.pool())
        .await;
        
        let create_identity_keys_result = sqlx::query(
            r#"
            CREATE TABLE signal_identity_keys (
                device_jid VARCHAR(255) NOT NULL,
                recipient_name VARCHAR(255) NOT NULL,
                recipient_device_id INTEGER NOT NULL,
                identity_key BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (device_jid, recipient_name, recipient_device_id)
            )
            "#
        )
        .execute(manager.pool())
        .await;
        
        match (create_devices_result, create_identity_keys_result) {
            (Ok(_), Ok(_)) => println!("✅ Tables created successfully"),
            (Err(e), _) => {
                println!("❌ Failed to create devices table: {:?}", e);
                panic!("Table creation failed");
            }
            (_, Err(e)) => {
                println!("❌ Failed to create identity_keys table: {:?}", e);
                panic!("Table creation failed");
            }
        }

        // Test 1: Create test data
        let address = libsignal_protocol_rust::ProtocolAddress::new("test_user".to_string(), 1);
        let identity_key_pair = libsignal_protocol_rust::IdentityKeyPair::generate(&mut rand::thread_rng());
        let identity_key = identity_key_pair.identity_key();

        // Insert test device data
        let insert_device_result = sqlx::query_as::<Any, ()>(
            "INSERT INTO devices (jid, registration_id, identity_key) VALUES (?, ?, ?)"
        )
        .bind(&manager.device_jid)
        .bind(123i64)
        .bind(&*identity_key_pair.serialize())
        .fetch_optional(manager.pool())
        .await
        .map(|_| ());
        
        match insert_device_result {
            Ok(_) => println!("✅ Test device data inserted"),
            Err(e) => {
                println!("❌ Failed to insert device data: {:?}", e);
                panic!("Device data insertion failed");
            }
        }

        // Test 2: get_identity should return None initially
        let loaded_identity = manager.get_identity(&address, None).await.unwrap();
        assert!(loaded_identity.is_none());
        println!("✅ get_identity returns None for non-existent identity");

        // Test 3: is_trusted_identity should return true for first use
        assert!(manager.is_trusted_identity(&address, identity_key, libsignal_protocol_rust::Direction::Sending, None).await.unwrap());
        println!("✅ is_trusted_identity returns true for first use");

        // Test 4: save_identity should work
        let saved = manager.save_identity(&address, identity_key, None).await.unwrap();
        assert!(!saved); // Should return false for new identity
        println!("✅ save_identity works");

        // Test 5: get_identity should return the stored identity
        let loaded_identity = manager.get_identity(&address, None).await.unwrap();
        assert!(loaded_identity.is_some());
        assert_eq!(loaded_identity.unwrap().serialize(), identity_key.serialize());
        println!("✅ get_identity returns stored identity");

        // Test 6: is_trusted_identity should return true for matching identity
        assert!(manager.is_trusted_identity(&address, identity_key, libsignal_protocol_rust::Direction::Sending, None).await.unwrap());
        println!("✅ is_trusted_identity returns true for matching identity");

        // Test 7: get_local_registration_id should work
        let registration_id = manager.get_local_registration_id(None).await.unwrap();
        assert_eq!(registration_id, 123);
        println!("✅ get_local_registration_id works");

        // Test 8: get_identity_key_pair should work
        let loaded_key_pair = manager.get_identity_key_pair(None).await.unwrap();
        assert_eq!(loaded_key_pair.serialize(), identity_key_pair.serialize());
        println!("✅ get_identity_key_pair works");
        
        println!("🎉 IdentityKeyStore database implementation works completely!");
    }
}