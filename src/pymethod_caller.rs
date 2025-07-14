use pyo3::prelude::*;
use log::debug;
use crate::address::ProtocolAddress;
use crate::identity_key::IdentityKey;
use crate::state::{SessionRecord, PreKeyRecord, SignedPreKeyRecord, PreKeyId, SignedPreKeyId};
use crate::sender_keys::{SenderKeyName, SenderKeyRecord};

// All methods now call _call_method which handles async execution in Python
pub fn call_save_identity(
    _py: Python<'_>,
    obj: &Bound<'_, PyAny>,
    address: &ProtocolAddress,
    identity: &IdentityKey,
) -> PyResult<bool> {
    let address_owned = address.clone();
    let identity_owned = identity.clone();
    let result = obj.call_method1("_call_method", ("save_identity", address_owned, identity_owned))?;
    Ok(result.extract::<bool>()?)
}

pub fn call_get_identity(
    _py: Python<'_>,
    obj: &Bound<'_, PyAny>,
    address: &ProtocolAddress,
) -> PyResult<Option<IdentityKey>> {
    let address_owned = address.clone();
    let result = obj.call_method1("_call_method", ("get_identity", address_owned))?;
    Ok(result.extract::<Option<IdentityKey>>()?)
}

pub fn call_store_session(
    _py: Python<'_>,
    obj: &Bound<'_, PyAny>,
    address: &ProtocolAddress,
    record: &SessionRecord,
) -> PyResult<()> {
    let address_owned = address.clone();
    let record_owned = record.clone();
    obj.call_method1("_call_method", ("store_session", address_owned, record_owned))?;
    Ok(())
}

pub fn call_load_session(
    _py: Python<'_>,
    obj: &Bound<'_, PyAny>,
    address: &ProtocolAddress,
) -> PyResult<Option<SessionRecord>> {
    let address_owned = address.clone();
    let result = obj.call_method1("_call_method", ("load_session", address_owned))?;
    Ok(result.extract::<Option<SessionRecord>>()?)
}

pub fn call_contains_session(
    _py: Python<'_>,
    obj: &Bound<'_, PyAny>,
    address: &ProtocolAddress,
) -> PyResult<bool> {
    debug!("Calling _call_method for contains_session");
    let address_owned = address.clone();
    
    let result = obj.call_method1("_call_method", ("contains_session", address_owned))?;
    Ok(result.extract::<bool>()?)
}

pub fn call_save_pre_key(
    _py: Python<'_>,
    obj: &Bound<'_, PyAny>,
    pre_key_id: PreKeyId,
    record: &PreKeyRecord,
) -> PyResult<()> {
    let record_owned = record.clone();
    obj.call_method1("_call_method", ("save_pre_key", pre_key_id, record_owned))?;
    Ok(())
}

pub fn call_get_pre_key(
    _py: Python<'_>,
    obj: &Bound<'_, PyAny>,
    pre_key_id: PreKeyId,
) -> PyResult<PreKeyRecord> {
    let result = obj.call_method1("_call_method", ("get_pre_key", pre_key_id))?;
    Ok(result.extract::<PreKeyRecord>()?)
}

pub fn call_remove_pre_key(
    _py: Python<'_>,
    obj: &Bound<'_, PyAny>,
    pre_key_id: PreKeyId,
) -> PyResult<()> {
    obj.call_method1("_call_method", ("remove_pre_key", pre_key_id))?;
    Ok(())
}

pub fn call_save_signed_pre_key(
    _py: Python<'_>,
    obj: &Bound<'_, PyAny>,
    signed_pre_key_id: SignedPreKeyId,
    record: &SignedPreKeyRecord,
) -> PyResult<()> {
    let record_owned = record.clone();
    obj.call_method1("_call_method", ("save_signed_pre_key", signed_pre_key_id, record_owned))?;
    Ok(())
}

pub fn call_get_signed_pre_key(
    _py: Python<'_>,
    obj: &Bound<'_, PyAny>,
    signed_pre_key_id: SignedPreKeyId,
) -> PyResult<SignedPreKeyRecord> {
    let result = obj.call_method1("_call_method", ("get_signed_pre_key", signed_pre_key_id))?;
    Ok(result.extract::<SignedPreKeyRecord>()?)
}

pub fn call_store_sender_key(
    _py: Python<'_>,
    obj: &Bound<'_, PyAny>,
    sender_key_name: &SenderKeyName,
    record: &SenderKeyRecord,
) -> PyResult<()> {
    let sender_key_name_owned = sender_key_name.clone();
    let record_owned = record.clone();
    obj.call_method1("_call_method", ("store_sender_key", sender_key_name_owned, record_owned))?;
    Ok(())
}

pub fn call_load_sender_key(
    _py: Python<'_>,
    obj: &Bound<'_, PyAny>,
    sender_key_name: &SenderKeyName,
) -> PyResult<Option<SenderKeyRecord>> {
    let sender_key_name_owned = sender_key_name.clone();
    let result = obj.call_method1("_call_method", ("load_sender_key", sender_key_name_owned))?;
    Ok(result.extract::<Option<SenderKeyRecord>>()?)
}