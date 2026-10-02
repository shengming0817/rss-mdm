//! One protected operation input; searchable metadata is authenticated with its execution identity.
use super::{Create, NativeTarget};
use crate::{Error, Failure};
use rss_mdm_native_protection::{DerivedAad, ProtectionContext, Protector};
use rss_request_context::TenantId;
use serde::{Deserialize, Serialize};
use sqlx::{Row, postgres::PgRow};
use uuid::Uuid;
use zeroize::Zeroizing;
#[derive(Serialize)]
pub(crate) struct Identity<'a> {
    pub operation: Uuid,
    pub device: &'a str,
    pub registration: Uuid,
    pub generation: i64,
}
#[derive(Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Metadata {
    platform: String,
    deadline: i64,
    input_version: String,
    target: NativeTarget,
}
impl Metadata {
    fn of(input: &Create) -> Self {
        Self {
            platform: match &input.task {
                super::Task::Windows { .. } => "windows",
                super::Task::Macos { .. } => "macos",
            }
            .into(),
            deadline: input.deadline,
            input_version: input.input_version.clone(),
            target: input.target.clone(),
        }
    }
}
fn invalid() -> Error {
    Error::Unavailable(Failure::NativeProtection)
}
fn aad(
    tenant: TenantId,
    identity: &Identity<'_>,
    metadata: &Metadata,
) -> Result<DerivedAad, Error> {
    let owner = serde_json::to_string(identity).map_err(|_| invalid())?;
    let field =
        serde_json::to_string(&("native.operation.input/v1", metadata)).map_err(|_| invalid())?;
    ProtectionContext::new(tenant, &owner, &field, 1)
        .map(|v| v.derive())
        .map_err(|_| invalid())
}
pub(crate) fn seal(
    protector: &Protector,
    tenant: TenantId,
    identity: &Identity<'_>,
    input: &Create,
) -> Result<(serde_json::Value, Vec<u8>), Error> {
    if identity.operation != input.operation_id {
        return Err(invalid());
    }
    let metadata = Metadata::of(input);
    let bytes = Zeroizing::new(serde_json::to_vec(input).map_err(|_| invalid())?);
    let sealed = protector
        .seal_bytes(&bytes, &aad(tenant, identity, &metadata)?)
        .map_err(|_| invalid())?;
    Ok((
        serde_json::to_value(metadata).map_err(|_| invalid())?,
        sealed,
    ))
}
pub(crate) fn open_row(
    protector: &Protector,
    tenant: TenantId,
    operation: Uuid,
    row: &PgRow,
    column: &str,
) -> Result<Create, Error> {
    let device: String = row.try_get("device").map_err(crate::database::db)?;
    let identity = Identity {
        operation,
        device: &device,
        registration: row.try_get("registration").map_err(crate::database::db)?,
        generation: row
            .try_get("registration_generation")
            .map_err(crate::database::db)?,
    };
    let metadata: Metadata =
        serde_json::from_value(row.try_get("input_context").map_err(crate::database::db)?)
            .map_err(|_| invalid())?;
    let sealed: Vec<u8> = row.try_get(column).map_err(crate::database::db)?;
    let plain = protector
        .open_bytes(&sealed, &aad(tenant, &identity, &metadata)?)
        .map_err(|_| invalid())?;
    let input: Create = serde_json::from_slice(plain.expose()).map_err(|_| invalid())?;
    if input.operation_id != operation || Metadata::of(&input) != metadata {
        return Err(invalid());
    }
    Ok(input)
}
