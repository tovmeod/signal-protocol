-- Initial Signal Protocol database schema
-- Using device_id as PK to solve pairing chicken-and-egg problem

-- Core device table with auto-incrementing device_id
-- Cross-database auto-increment compatibility:
-- SQLite: INTEGER PRIMARY KEY is special - it's an alias for ROWID and auto-increments
-- PostgreSQL: SQLx migration engine is smart enough to convert INTEGER PRIMARY KEY to BIGSERIAL
-- Both map to i64 in Rust code for seamless cross-database compatibility
CREATE TABLE devices (
    device_id INTEGER PRIMARY KEY,          -- Auto-increments on both SQLite and PostgreSQL
    jid VARCHAR(255) UNIQUE,                -- Device JID (nullable, set after pairing)  
    registration_id BIGINT NOT NULL,        -- Signal registration ID
    identity_key BLOB NOT NULL,             -- Identity key pair (serialized)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Sessions table (based on SignalSessionModel)
CREATE TABLE signal_sessions (
    device_id INTEGER NOT NULL,             -- References devices.device_id
    recipient_name VARCHAR(255) NOT NULL,
    recipient_device_id INTEGER NOT NULL,
    session_data BLOB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (device_id, recipient_name, recipient_device_id),
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

-- PreKeys table (based on SignalPreKeyModel)
CREATE TABLE signal_pre_keys (
    device_id INTEGER NOT NULL,             -- References devices.device_id
    key_id INTEGER NOT NULL,
    key_data BLOB NOT NULL,
    uploaded BOOLEAN DEFAULT FALSE,         -- Keep uploaded tracking
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (device_id, key_id),
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

-- Signed PreKeys table (based on SignalSignedPreKeyModel)
CREATE TABLE signal_signed_pre_keys (
    device_id INTEGER NOT NULL,             -- References devices.device_id
    key_id INTEGER NOT NULL,
    key_data BLOB NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (device_id, key_id),
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

-- Identity keys table (based on SignalIdentityKeyModel)
CREATE TABLE signal_identity_keys (
    device_id INTEGER NOT NULL,             -- References devices.device_id
    recipient_name VARCHAR(255) NOT NULL,
    recipient_device_id INTEGER NOT NULL,
    identity_key BLOB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (device_id, recipient_name, recipient_device_id),
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

-- Sender keys table (based on SignalSenderKeyModel, optimized)
CREATE TABLE signal_sender_keys (
    device_id INTEGER NOT NULL,             -- References devices.device_id
    group_id VARCHAR(255) NOT NULL,         -- Your chat_id
    sender_name VARCHAR(255) NOT NULL,      -- Extracted from your sender_id
    sender_device_id INTEGER NOT NULL,      -- Extracted from your sender_id  
    sender_key BLOB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (device_id, group_id, sender_name, sender_device_id),
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

-- Indexes for performance
CREATE INDEX idx_devices_jid ON devices(jid);
CREATE INDEX idx_sessions_device ON signal_sessions(device_id);
CREATE INDEX idx_sessions_recipient ON signal_sessions(recipient_name);
CREATE INDEX idx_pre_keys_device ON signal_pre_keys(device_id);
CREATE INDEX idx_pre_keys_uploaded ON signal_pre_keys(uploaded);
CREATE INDEX idx_signed_pre_keys_device ON signal_signed_pre_keys(device_id);
CREATE INDEX idx_identity_keys_device ON signal_identity_keys(device_id);
CREATE INDEX idx_identity_keys_recipient ON signal_identity_keys(recipient_name);
CREATE INDEX idx_sender_keys_device ON signal_sender_keys(device_id);
CREATE INDEX idx_sender_keys_group ON signal_sender_keys(group_id);