-- Initial Signal Protocol database schema
-- Based on the existing Tortoise models but optimized for the new architecture

-- Core device table
CREATE TABLE devices (
    jid VARCHAR(255) PRIMARY KEY,           -- Device JID (matches existing pattern)
    registration_id BIGINT NOT NULL,        -- Signal registration ID
    identity_key BLOB NOT NULL,             -- Identity key pair (serialized)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Sessions table (based on SignalSessionModel)
CREATE TABLE signal_sessions (
    device_jid VARCHAR(255) NOT NULL,
    recipient_name VARCHAR(255) NOT NULL,
    recipient_device_id INTEGER NOT NULL,
    session_data BLOB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (device_jid, recipient_name, recipient_device_id),
    FOREIGN KEY (device_jid) REFERENCES devices(jid) ON DELETE CASCADE
);

-- PreKeys table (based on SignalPreKeyModel)
CREATE TABLE signal_pre_keys (
    device_jid VARCHAR(255) NOT NULL,
    key_id INTEGER NOT NULL,
    key_data BLOB NOT NULL,
    uploaded BOOLEAN DEFAULT FALSE,         -- Keep uploaded tracking
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (device_jid, key_id),
    FOREIGN KEY (device_jid) REFERENCES devices(jid) ON DELETE CASCADE
);

-- Signed PreKeys table (based on SignalSignedPreKeyModel)
CREATE TABLE signal_signed_pre_keys (
    device_jid VARCHAR(255) NOT NULL,
    key_id INTEGER NOT NULL,
    key_data BLOB NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (device_jid, key_id),
    FOREIGN KEY (device_jid) REFERENCES devices(jid) ON DELETE CASCADE
);

-- Identity keys table (based on SignalIdentityKeyModel)
CREATE TABLE signal_identity_keys (
    device_jid VARCHAR(255) NOT NULL,
    recipient_name VARCHAR(255) NOT NULL,
    recipient_device_id INTEGER NOT NULL,
    identity_key BLOB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (device_jid, recipient_name, recipient_device_id),
    FOREIGN KEY (device_jid) REFERENCES devices(jid) ON DELETE CASCADE
);

-- Sender keys table (based on SignalSenderKeyModel, optimized)
CREATE TABLE signal_sender_keys (
    device_jid VARCHAR(255) NOT NULL,
    group_id VARCHAR(255) NOT NULL,         -- Your chat_id
    sender_name VARCHAR(255) NOT NULL,      -- Extracted from your sender_id
    sender_device_id INTEGER NOT NULL,      -- Extracted from your sender_id  
    sender_key BLOB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (device_jid, group_id, sender_name, sender_device_id),
    FOREIGN KEY (device_jid) REFERENCES devices(jid) ON DELETE CASCADE
);

-- Indexes for performance
CREATE INDEX idx_sessions_device ON signal_sessions(device_jid);
CREATE INDEX idx_sessions_recipient ON signal_sessions(recipient_name);
CREATE INDEX idx_pre_keys_device ON signal_pre_keys(device_jid);
CREATE INDEX idx_pre_keys_uploaded ON signal_pre_keys(uploaded);
CREATE INDEX idx_signed_pre_keys_device ON signal_signed_pre_keys(device_jid);
CREATE INDEX idx_identity_keys_device ON signal_identity_keys(device_jid);
CREATE INDEX idx_identity_keys_recipient ON signal_identity_keys(recipient_name);
CREATE INDEX idx_sender_keys_device ON signal_sender_keys(device_jid);
CREATE INDEX idx_sender_keys_group ON signal_sender_keys(group_id);