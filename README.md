# signal-protocol

[![CircleCI](https://circleci.com/gh/freedomofpress/signal-protocol.svg?style=svg)](https://circleci.com/gh/freedomofpress/signal-protocol)
[![PyPI version](https://badge.fury.io/py/signal-protocol.svg)](https://badge.fury.io/py/signal-protocol)

Experimental Python bindings to Rust signal protocol implementation [`libsignal-client`](https://github.com/signalapp/libsignal-client).
This project provides a Rust extension using [PyO3](https://pyo3.rs/) to define a `signal_protocol` Python module.
See [here](https://cryptography.io/en/latest/limitations.html) for a fundamental limitation storing secrets in Python-allocated memory.

⚠️USE AT YOUR OWN RISK!⚠️

## Installation

To use the wheel distributions you do not need the Rust toolchain installed.
Simply run

```
pip install signal-protocol
```

## Usage

### Initial client setup

The following shows how to use this library to initialize a new Signal client.
This is the first step that must be completed before the protocol can begin.

For an overview of the Signal protocol, see [this blog post](https://www.redshiftzero.com/signal-protocol/).
Detailed [specifications](https://signal.org/docs/) are available from Signal.

First, import these modules:

```py
from signal_protocol import curve, identity_key, state, storage
```

Each client must generate a long-term identity key pair.
This should be stored somewhere safe and persistent.

```py
identity_key_pair = identity_key.IdentityKeyPair.generate()
```

Clients must generate prekeys.
The example generates a single prekey.
In practice, clients will generate many prekeys, as they are one-time use and consumed when a message from a new chat participant is sent.

```py
pre_key_pair = curve.KeyPair.generate()
```

Clients must generate a registration_id and store it somewhere safe and persistent.

```py
registration_id = 12  # TODO generate (not yet supported in upstream crate)
```

The InMemSignalProtocolStore is a single object which provide the four storage interfaces required:
IdentityKeyStore (for one's own identity key state and the (public) identity keys for other chat participants),
PreKeyStore (for one's own prekey state),
SignedPreKeyStore (for one's own signed prekeys),
and SessionStore (for established sessions with chat participants).

```py
store = storage.InMemSignalProtocolStore(identity_key_pair, registration_id)
```

Clients should also generate a signed prekey.

```py
signed_pre_key_pair = curve.KeyPair.generate()
serialized_signed_pre_pub_key = signed_pre_key_pair.public_key().serialize()
signed_pre_key_signature = (
    store.get_identity_key_pair()
    .private_key()
    .calculate_signature(serialized_signed_pre_pub_key)
)
```

Clients should store their prekeys (both one-time and signed) in the protocol store
along with IDs that can be used to retrieve them later.

```py
pre_key_id = 10
pre_key_record = state.PreKeyRecord(pre_key_id, pre_key_pair)
store.save_pre_key(pre_key_id, pre_key_record)

signed_pre_key_id = 33
signed_prekey = state.SignedPreKeyRecord(
            signed_pre_key_id,
            42, # This is a timestamp since this key should be periodically rotated
            signed_pre_key_pair,
            signed_pre_key_signature,
        )
store.save_signed_pre_key(signed_pre_key_id, signed_prekey)
```

### Sending a message to a new participant

With a client initialized, you can create a session and send messages.

To create a session, you must fetch a prekey bundle for the recipient from the server.
Here the prekey bundle is `recipient_bundle` for participant `recipient_address`.

```py
from signal_protocol import session, session_cipher

session.process_prekey_bundle(
    recipient_address,
    store,
    recipient_bundle,
)
```

Once the prekey bundle is processed (storing data from the recipient in your local
protocol store), you can encrypt messages:

```py
ciphertext = session_cipher.message_encrypt(store, recipient_address, b"hello")
```

### Persistent Storage

The library supports persistent storage by allowing you to implement custom storage backends that will be automatically used alongside the in-memory cache. This enables sessions, keys, and other protocol state to persist across application restarts.

#### Implementing a Persistent Storage Backend

To use persistent storage, create a class that inherits from `storage.PersistentStorageBase` and implement the required methods:

```py
from signal_protocol.storage import PersistentStorageBase
import sqlite3
import pickle

class SQLiteStorage(PersistentStorageBase):
    def __init__(self, db_path):
        super().__init__()
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute('''CREATE TABLE IF NOT EXISTS sessions 
                       (address TEXT PRIMARY KEY, session_data BLOB)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS identities 
                       (address TEXT PRIMARY KEY, identity_data BLOB)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS prekeys 
                       (key_id INTEGER PRIMARY KEY, prekey_data BLOB)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS signed_prekeys 
                       (key_id INTEGER PRIMARY KEY, signed_prekey_data BLOB)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS sender_keys 
                       (name TEXT PRIMARY KEY, sender_key_data BLOB)''')
        conn.commit()
        conn.close()

    # Session Store Methods
    def store_session(self, address, session_record):
        conn = sqlite3.connect(self.db_path)
        address_str = f"{address.name}:{address.device_id}"
        session_data = pickle.dumps(session_record.serialize())
        conn.execute("INSERT OR REPLACE INTO sessions VALUES (?, ?)", 
                    (address_str, session_data))
        conn.commit()
        conn.close()

    def load_session(self, address):
        conn = sqlite3.connect(self.db_path)
        address_str = f"{address.name}:{address.device_id}"
        cursor = conn.execute("SELECT session_data FROM sessions WHERE address = ?", 
                             (address_str,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            from signal_protocol.state import SessionRecord
            session_data = pickle.loads(row[0])
            return SessionRecord.deserialize(session_data)
        return None

    # Identity Store Methods  
    def save_identity(self, address, identity_key):
        conn = sqlite3.connect(self.db_path)
        address_str = f"{address.name}:{address.device_id}"
        identity_data = pickle.dumps(identity_key.serialize())
        conn.execute("INSERT OR REPLACE INTO identities VALUES (?, ?)", 
                    (address_str, identity_data))
        conn.commit()
        conn.close()
        return True

    def get_identity(self, address):
        conn = sqlite3.connect(self.db_path)
        address_str = f"{address.name}:{address.device_id}"
        cursor = conn.execute("SELECT identity_data FROM identities WHERE address = ?", 
                             (address_str,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            from signal_protocol.identity_key import IdentityKey
            identity_data = pickle.loads(row[0])
            return IdentityKey.deserialize(identity_data)
        return None

    # PreKey Store Methods
    def save_pre_key(self, pre_key_id, pre_key_record):
        conn = sqlite3.connect(self.db_path)
        prekey_data = pickle.dumps(pre_key_record.serialize())
        conn.execute("INSERT OR REPLACE INTO prekeys VALUES (?, ?)", 
                    (pre_key_id, prekey_data))
        conn.commit()
        conn.close()

    def get_pre_key(self, pre_key_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute("SELECT prekey_data FROM prekeys WHERE key_id = ?", 
                             (pre_key_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            from signal_protocol.state import PreKeyRecord
            prekey_data = pickle.loads(row[0])
            return PreKeyRecord.deserialize(prekey_data)
        raise Exception(f"PreKey {pre_key_id} not found")

    def remove_pre_key(self, pre_key_id):
        conn = sqlite3.connect(self.db_path)
        conn.execute("DELETE FROM prekeys WHERE key_id = ?", (pre_key_id,))
        conn.commit()
        conn.close()

    # Signed PreKey Store Methods
    def save_signed_pre_key(self, signed_pre_key_id, signed_pre_key_record):
        conn = sqlite3.connect(self.db_path)
        signed_prekey_data = pickle.dumps(signed_pre_key_record.serialize())
        conn.execute("INSERT OR REPLACE INTO signed_prekeys VALUES (?, ?)", 
                    (signed_pre_key_id, signed_prekey_data))
        conn.commit()
        conn.close()

    def get_signed_pre_key(self, signed_pre_key_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute("SELECT signed_prekey_data FROM signed_prekeys WHERE key_id = ?", 
                             (signed_pre_key_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            from signal_protocol.state import SignedPreKeyRecord
            signed_prekey_data = pickle.loads(row[0])
            return SignedPreKeyRecord.deserialize(signed_prekey_data)
        raise Exception(f"SignedPreKey {signed_pre_key_id} not found")

    # Sender Key Store Methods
    def store_sender_key(self, sender_key_name, sender_key_record):
        conn = sqlite3.connect(self.db_path)
        name_str = f"{sender_key_name.group_id}:{sender_key_name.sender.name}:{sender_key_name.sender.device_id}"
        sender_key_data = pickle.dumps(sender_key_record.serialize())
        conn.execute("INSERT OR REPLACE INTO sender_keys VALUES (?, ?)", 
                    (name_str, sender_key_data))
        conn.commit()
        conn.close()

    def load_sender_key(self, sender_key_name):
        conn = sqlite3.connect(self.db_path)
        name_str = f"{sender_key_name.group_id}:{sender_key_name.sender.name}:{sender_key_name.sender.device_id}"
        cursor = conn.execute("SELECT sender_key_data FROM sender_keys WHERE name = ?", 
                             (name_str,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            from signal_protocol.sender_keys import SenderKeyRecord
            sender_key_data = pickle.loads(row[0])
            return SenderKeyRecord.deserialize(sender_key_data)
        return None
```

#### Using Persistent Storage

To use your persistent storage implementation, pass it when creating the protocol store:

```py
# Create your persistent storage implementation
persistent_storage = SQLiteStorage("signal_store.db")

# Create the protocol store with persistent storage
store = storage.InMemSignalProtocolStore(
    identity_key_pair, 
    registration_id, 
    persistent_storage=persistent_storage
)

# Use the store normally - all operations will be cached in memory 
# and automatically persisted to your storage backend
session.process_prekey_bundle(recipient_address, store, recipient_bundle)
ciphertext = session_cipher.message_encrypt(store, recipient_address, b"hello")

# Remember to close the storage when done to clean up resources
store.close()
```

#### Async Storage Support

The library automatically detects whether your storage methods are synchronous or asynchronous and handles them appropriately:

```py
class AsyncRedisStorage(PersistentStorageBase):
    def __init__(self, redis_url):
        super().__init__()
        import aioredis
        self.redis_url = redis_url
        self._redis = None

    async def _get_redis(self):
        if not self._redis:
            import aioredis
            self._redis = await aioredis.from_url(self.redis_url)
        return self._redis

    async def store_session(self, address, session_record):
        redis = await self._get_redis()
        address_str = f"session:{address.name}:{address.device_id}"
        session_data = session_record.serialize()
        await redis.set(address_str, session_data)

    async def load_session(self, address):
        redis = await self._get_redis()
        address_str = f"session:{address.name}:{address.device_id}"
        session_data = await redis.get(address_str)
        if session_data:
            from signal_protocol.state import SessionRecord
            return SessionRecord.deserialize(session_data)
        return None

    # ... implement other async methods
```

#### Key Features

- **Hybrid Architecture**: The library uses a two-tier approach with fast in-memory caching and persistent storage fallback
- **Auto-Detection**: Methods can be either sync or async - the library automatically detects and handles both
- **Error Resilience**: Persistent storage errors don't break the protocol - operations fall back to memory-only mode
- **Resource Management**: Call `store.close()` to properly clean up async executors and connections

## Developer Getting Started

You will need both [Rust](https://rustup.rs/) and Python 3.7+ installed on your system.
To install the project in your virtualenv:

```sh
pip install -r requirements.txt
python setup.py develop
```
Then run the tests via `pytest -v tests/` to confirm all is working.
Tests are ported to Python from the upstream crate.
You can use the tests as a reference for how to use the library.

When developing, simply run `python setup.py develop` as you make changes to rebuild the library.
This script will handle compilation on the Rust side.

# Building wheels

See instructions [here](https://github.com/PyO3/setuptools-rust#binary-wheels-on-linux). In brief:

```
docker pull quay.io/pypa/manylinux2014_x86_64
docker run --rm -v `pwd`:/io quay.io/pypa/manylinux2014_x86_64 /io/build-wheels.sh
```
