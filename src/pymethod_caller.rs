use pyo3::prelude::*;
use log::debug;
use crate::address::ProtocolAddress;
use crate::identity_key::IdentityKey;
use crate::state::{SessionRecord, PreKeyRecord, SignedPreKeyRecord, PreKeyId, SignedPreKeyId};
use crate::sender_keys::{SenderKeyName, SenderKeyRecord};

pub fn call_save_identity(
    py: Python<'_>,
    obj: &Bound<'_, PyAny>,
    address: &ProtocolAddress,
    identity: &IdentityKey,
) -> PyResult<bool> {
    let method = obj.getattr("save_identity")?;
    let inspect = py.import("inspect")?;
    let is_coroutine = inspect.call_method1("iscoroutinefunction", (&method,))?;

    // Clone the objects to own them for Python conversion
    let address_owned = address.clone();
    let identity_owned = identity.clone();

    if is_coroutine.is_truthy()? {
        debug!("Calling async save_identity");
        let coroutine = method.call1((address_owned, identity_owned))?;
        let asyncio = py.import("asyncio")?;
        let result = match asyncio.call_method0("get_running_loop") {
            Ok(event_loop) => event_loop.call_method1("run_until_complete", (coroutine,)),
            Err(_) => {
                debug!("No running event loop, creating a new one");
                asyncio.call_method1("run", (coroutine,))
            }
        }?;
        Ok(result.extract::<bool>()?)
    } else {
        debug!("Calling sync save_identity");
        let result = method.call1((address_owned, identity_owned))?;
        Ok(result.extract::<bool>()?)
    }
}

pub fn call_get_identity(
    py: Python<'_>,
    obj: &Bound<'_, PyAny>,
    address: &ProtocolAddress,
) -> PyResult<Option<IdentityKey>> {
    let method = obj.getattr("get_identity")?;
    let inspect = py.import("inspect")?;
    let is_coroutine = inspect.call_method1("iscoroutinefunction", (&method,))?;

    let address_owned = address.clone();

    if is_coroutine.is_truthy()? {
        debug!("Calling async get_identity");
        let coroutine = method.call1((address_owned,))?;
        let asyncio = py.import("asyncio")?;
        let result = match asyncio.call_method0("get_running_loop") {
            Ok(event_loop) => event_loop.call_method1("run_until_complete", (coroutine,)),
            Err(_) => {
                debug!("No running event loop, creating a new one");
                asyncio.call_method1("run", (coroutine,))
            }
        }?;
        Ok(result.extract::<Option<IdentityKey>>()?)
    } else {
        debug!("Calling sync get_identity");
        let result = method.call1((address_owned,))?;
        Ok(result.extract::<Option<IdentityKey>>()?)
    }
}

pub fn call_store_session(
    py: Python<'_>,
    obj: &Bound<'_, PyAny>,
    address: &ProtocolAddress,
    record: &SessionRecord,
) -> PyResult<()> {
    let method = obj.getattr("store_session")?;
    let inspect = py.import("inspect")?;
    let is_coroutine = inspect.call_method1("iscoroutinefunction", (&method,))?;

    let address_owned = address.clone();
    let record_owned = record.clone();

    if is_coroutine.is_truthy()? {
        debug!("Calling async store_session");
        let coroutine = method.call1((address_owned, record_owned))?;
        let asyncio = py.import("asyncio")?;
        match asyncio.call_method0("get_running_loop") {
            Ok(event_loop) => event_loop.call_method1("run_until_complete", (coroutine,)),
            Err(_) => {
                debug!("No running event loop, creating a new one");
                asyncio.call_method1("run", (coroutine,))
            }
        }?;
        Ok(())
    } else {
        debug!("Calling sync store_session");
        method.call1((address_owned, record_owned))?;
        Ok(())
    }
}

pub fn call_load_session(
    py: Python<'_>,
    obj: &Bound<'_, PyAny>,
    address: &ProtocolAddress,
) -> PyResult<Option<SessionRecord>> {
    let method = obj.getattr("load_session")?;
    let inspect = py.import("inspect")?;
    let is_coroutine = inspect.call_method1("iscoroutinefunction", (&method,))?;

    let address_owned = address.clone();

    if is_coroutine.is_truthy()? {
        debug!("Calling async load_session");
        let coroutine = method.call1((address_owned,))?;
        let asyncio = py.import("asyncio")?;
        let result = match asyncio.call_method0("get_running_loop") {
            Ok(event_loop) => event_loop.call_method1("run_until_complete", (coroutine,)),
            Err(_) => {
                debug!("No running event loop, creating a new one");
                asyncio.call_method1("run", (coroutine,))
            }
        }?;
        Ok(result.extract::<Option<SessionRecord>>()?)
    } else {
        debug!("Calling sync load_session");
        let result = method.call1((address_owned,))?;
        Ok(result.extract::<Option<SessionRecord>>()?)
    }
}

pub fn call_save_pre_key(
    py: Python<'_>,
    obj: &Bound<'_, PyAny>,
    pre_key_id: PreKeyId,
    record: &PreKeyRecord,
) -> PyResult<()> {
    let method = obj.getattr("save_pre_key")?;
    let inspect = py.import("inspect")?;
    let is_coroutine = inspect.call_method1("iscoroutinefunction", (&method,))?;

    let record_owned = record.clone();

    if is_coroutine.is_truthy()? {
        debug!("Calling async save_pre_key");
        let coroutine = method.call1((pre_key_id, record_owned))?;
        let asyncio = py.import("asyncio")?;
        match asyncio.call_method0("get_running_loop") {
            Ok(event_loop) => event_loop.call_method1("run_until_complete", (coroutine,)),
            Err(_) => {
                debug!("No running event loop, creating a new one");
                asyncio.call_method1("run", (coroutine,))
            }
        }?;
        Ok(())
    } else {
        debug!("Calling sync save_pre_key");
        method.call1((pre_key_id, record_owned))?;
        Ok(())
    }
}

pub fn call_get_pre_key(
    py: Python<'_>,
    obj: &Bound<'_, PyAny>,
    pre_key_id: PreKeyId,
) -> PyResult<PreKeyRecord> {
    let method = obj.getattr("get_pre_key")?;
    let inspect = py.import("inspect")?;
    let is_coroutine = inspect.call_method1("iscoroutinefunction", (&method,))?;

    if is_coroutine.is_truthy()? {
        debug!("Calling async get_pre_key");
        let coroutine = method.call1((pre_key_id,))?;
        let asyncio = py.import("asyncio")?;
        let result = match asyncio.call_method0("get_running_loop") {
            Ok(event_loop) => event_loop.call_method1("run_until_complete", (coroutine,)),
            Err(_) => {
                debug!("No running event loop, creating a new one");
                asyncio.call_method1("run", (coroutine,))
            }
        }?;
        Ok(result.extract::<PreKeyRecord>()?)
    } else {
        debug!("Calling sync get_pre_key");
        let result = method.call1((pre_key_id,))?;
        Ok(result.extract::<PreKeyRecord>()?)
    }
}

pub fn call_remove_pre_key(
    py: Python<'_>,
    obj: &Bound<'_, PyAny>,
    pre_key_id: PreKeyId,
) -> PyResult<()> {
    let method = obj.getattr("remove_pre_key")?;
    let inspect = py.import("inspect")?;
    let is_coroutine = inspect.call_method1("iscoroutinefunction", (&method,))?;

    if is_coroutine.is_truthy()? {
        debug!("Calling async remove_pre_key");
        let coroutine = method.call1((pre_key_id,))?;
        let asyncio = py.import("asyncio")?;
        match asyncio.call_method0("get_running_loop") {
            Ok(event_loop) => event_loop.call_method1("run_until_complete", (coroutine,)),
            Err(_) => {
                debug!("No running event loop, creating a new one");
                asyncio.call_method1("run", (coroutine,))
            }
        }?;
        Ok(())
    } else {
        debug!("Calling sync remove_pre_key");
        method.call1((pre_key_id,))?;
        Ok(())
    }
}

pub fn call_save_signed_pre_key(
    py: Python<'_>,
    obj: &Bound<'_, PyAny>,
    signed_pre_key_id: SignedPreKeyId,
    record: &SignedPreKeyRecord,
) -> PyResult<()> {
    let method = obj.getattr("save_signed_pre_key")?;
    let inspect = py.import("inspect")?;
    let is_coroutine = inspect.call_method1("iscoroutinefunction", (&method,))?;

    let record_owned = record.clone();

    if is_coroutine.is_truthy()? {
        debug!("Calling async save_signed_pre_key");
        let coroutine = method.call1((signed_pre_key_id, record_owned))?;
        let asyncio = py.import("asyncio")?;
        match asyncio.call_method0("get_running_loop") {
            Ok(event_loop) => event_loop.call_method1("run_until_complete", (coroutine,)),
            Err(_) => {
                debug!("No running event loop, creating a new one");
                asyncio.call_method1("run", (coroutine,))
            }
        }?;
        Ok(())
    } else {
        debug!("Calling sync save_signed_pre_key");
        method.call1((signed_pre_key_id, record_owned))?;
        Ok(())
    }
}

pub fn call_get_signed_pre_key(
    py: Python<'_>,
    obj: &Bound<'_, PyAny>,
    signed_pre_key_id: SignedPreKeyId,
) -> PyResult<SignedPreKeyRecord> {
    let method = obj.getattr("get_signed_pre_key")?;
    let inspect = py.import("inspect")?;
    let is_coroutine = inspect.call_method1("iscoroutinefunction", (&method,))?;

    if is_coroutine.is_truthy()? {
        debug!("Calling async get_signed_pre_key");
        let coroutine = method.call1((signed_pre_key_id,))?;
        let asyncio = py.import("asyncio")?;
        let result = match asyncio.call_method0("get_running_loop") {
            Ok(event_loop) => event_loop.call_method1("run_until_complete", (coroutine,)),
            Err(_) => {
                debug!("No running event loop, creating a new one");
                asyncio.call_method1("run", (coroutine,))
            }
        }?;
        Ok(result.extract::<SignedPreKeyRecord>()?)
    } else {
        debug!("Calling sync get_signed_pre_key");
        let result = method.call1((signed_pre_key_id,))?;
        Ok(result.extract::<SignedPreKeyRecord>()?)
    }
}

pub fn call_store_sender_key(
    py: Python<'_>,
    obj: &Bound<'_, PyAny>,
    sender_key_name: &SenderKeyName,
    record: &SenderKeyRecord,
) -> PyResult<()> {
    let method = obj.getattr("store_sender_key")?;
    let inspect = py.import("inspect")?;
    let is_coroutine = inspect.call_method1("iscoroutinefunction", (&method,))?;

    let sender_key_name_owned = sender_key_name.clone();
    let record_owned = record.clone();

    if is_coroutine.is_truthy()? {
        debug!("Calling async store_sender_key");
        let coroutine = method.call1((sender_key_name_owned, record_owned))?;
        let asyncio = py.import("asyncio")?;
        match asyncio.call_method0("get_running_loop") {
            Ok(event_loop) => event_loop.call_method1("run_until_complete", (coroutine,)),
            Err(_) => {
                debug!("No running event loop, creating a new one");
                asyncio.call_method1("run", (coroutine,))
            }
        }?;
        Ok(())
    } else {
        debug!("Calling sync store_sender_key");
        method.call1((sender_key_name_owned, record_owned))?;
        Ok(())
    }
}

pub fn call_load_sender_key(
    py: Python<'_>,
    obj: &Bound<'_, PyAny>,
    sender_key_name: &SenderKeyName,
) -> PyResult<Option<SenderKeyRecord>> {
    let method = obj.getattr("load_sender_key")?;
    let inspect = py.import("inspect")?;
    let is_coroutine = inspect.call_method1("iscoroutinefunction", (&method,))?;

    let sender_key_name_owned = sender_key_name.clone();

    if is_coroutine.is_truthy()? {
        debug!("Calling async load_sender_key");
        let coroutine = method.call1((sender_key_name_owned,))?;
        let asyncio = py.import("asyncio")?;
        let result = match asyncio.call_method0("get_running_loop") {
            Ok(event_loop) => event_loop.call_method1("run_until_complete", (coroutine,)),
            Err(_) => {
                debug!("No running event loop, creating a new one");
                asyncio.call_method1("run", (coroutine,))
            }
        }?;
        Ok(result.extract::<Option<SenderKeyRecord>>()?)
    } else {
        debug!("Calling sync load_sender_key");
        let result = method.call1((sender_key_name_owned,))?;
        Ok(result.extract::<Option<SenderKeyRecord>>()?)
    }
}

pub fn call_contains_session(
    py: Python<'_>,
    obj: &Bound<'_, PyAny>,
    address: &ProtocolAddress,
) -> PyResult<bool> {
    let method = obj.getattr("contains_session")?;
    let inspect = py.import("inspect")?;
    let is_coroutine = inspect.call_method1("iscoroutinefunction", (&method,))?;

    let address_owned = address.clone();

    if is_coroutine.is_truthy()? {
        debug!("Calling async contains_session");
        let coroutine = method.call1((address_owned,))?;
        let asyncio = py.import("asyncio")?;
        let result = match asyncio.call_method0("get_running_loop") {
            Ok(event_loop) => event_loop.call_method1("run_until_complete", (coroutine,)),
            Err(_) => {
                debug!("No running event loop, creating a new one");
                asyncio.call_method1("run", (coroutine,))
            }
        }?;
        Ok(result.extract::<bool>()?)
    } else {
        debug!("Calling sync contains_session");
        let result = method.call1((address_owned,))?;
        Ok(result.extract::<bool>()?)
    }
}