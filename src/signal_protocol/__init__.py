"""
Signal Protocol Implementation for Python

This library provides Python bindings for the Signal Protocol, a secure messaging protocol
that provides end-to-end encryption for instant messaging. The implementation uses Rust
for the core cryptographic operations and PyO3 for Python bindings.

Key Features:
- Complete Signal Protocol implementation (Double Ratchet, X3DH key agreement)
- Fast in-memory storage with optional database persistence
- Async/sync compatible storage backends
- Support for SQLite, PostgreSQL, and MySQL databases
- Thread-safe operations with proper async/sync bridging

Quick Start:
    Basic usage (cache-only):
        from signal_protocol import InMemSignalProtocolStore
        from signal_protocol.identity_key import IdentityKeyPair
        
        # Generate identity key pair
        identity_key_pair = IdentityKeyPair.generate()
        
        # Create store
        store = InMemSignalProtocolStore(identity_key_pair, registration_id=1)

    With database persistence:
        # Create store with SQLite persistence
        store = InMemSignalProtocolStore(
            identity_key_pair, 
            registration_id=1,
            connection_string="sqlite://signal.db",
            device_jid="alice@example.com"
        )
        
        # Set up database tables
        await store.migrate()

Architecture:
    The storage system uses a cache + backing store pattern:
    - Fast in-memory cache for frequent operations
    - Optional database backing store for persistence
    - Automatic fallback: cache miss loads from database
    - Write-through: all writes go to both cache and database

Modules:
    address - Protocol addresses and device identifiers
    curve - Elliptic curve cryptography (Curve25519)
    error - Signal Protocol specific exceptions
    fingerprint - Safety number generation for key verification
    group_cipher - Group messaging encryption (sender keys)
    identity_key - Identity key pairs and verification
    protocol - Core protocol message processing
    ratchet - Double ratchet algorithm implementation
    sealed_sender - Anonymous message sending
    sender_keys - Group messaging key management
    session - Session establishment and management
    session_cipher - Message encryption/decryption
    state - Protocol state records (sessions, prekeys)
    storage - Storage implementations and persistence
"""

import sys
import asyncio
import threading
import inspect
from typing import Optional, Any, Coroutine, TypeVar
import concurrent.futures
import functools

# Import the compiled Rust extension module directly
from . import _signal_protocol

# Re-export all submodules and make them available in sys.modules
# so that "from signal_protocol.submodule import Foo" works.
_submodules = {
    "address": _signal_protocol.address,
    "curve": _signal_protocol.curve,
    "error": _signal_protocol.error,
    "fingerprint": _signal_protocol.fingerprint,
    "group_cipher": _signal_protocol.group_cipher,
    "identity_key": _signal_protocol.identity_key,
    "protocol": _signal_protocol.protocol,
    "ratchet": _signal_protocol.ratchet,
    "sealed_sender": _signal_protocol.sealed_sender,
    "sender_keys": _signal_protocol.sender_keys,
    "session_cipher": _signal_protocol.session_cipher,
    "session": _signal_protocol.session,
    "state": _signal_protocol.state,
    "storage": _signal_protocol.storage,
}

for name, module in _submodules.items():
    globals()[name] = module
    sys.modules[f"signal_protocol.{name}"] = module

# Re-export store classes for convenience
# The store now supports optional database persistence via connection strings
InMemSignalProtocolStore = _signal_protocol.storage.InMemSignalProtocolStore




# Export everything
__all__ = [
    'address',
    'curve',
    'error',
    'fingerprint',
    'group_cipher',
    'identity_key',
    'protocol',
    'ratchet',
    'sealed_sender',
    'sender_keys',
    'session_cipher',
    'session',
    'state',
    'storage',
    'InMemSignalProtocolStore',
]