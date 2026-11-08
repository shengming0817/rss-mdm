//! Secret response redaction and input copies belong to the Apple protocol owner.
use crate::{Error, protocol};
use sqlx::{PgConnection, Row};
/// Secret carriers are absent from ordinary evidence and retained raw responses.
/// The original response HMAC still proves exact replay without retaining another secret copy.
pub(crate) fn redact(body: &mut plist::Dictionary) {
    // Keep bounded native error codes, never descriptions, arbitrary domains or extensions.
    // ref: https://developer.apple.com/documentation/devicemanagement/sending-mdm-commands-to-a-device
    if let Some(chain) = body.remove("ErrorChain") {
        let safe: Vec<_> = chain
            .as_array()
            .into_iter()
            .flatten()
            .take(16)
            .filter_map(plist::Value::as_dictionary)
            .filter_map(|item| {
                item.get("ErrorCode")
                    .and_then(plist::Value::as_signed_integer)
            })
            .map(|code| {
                plist::Value::Dictionary(protocol::dictionary([("ErrorCode", code.into())]))
            })
            .collect();
        if !safe.is_empty() {
            body.insert("ErrorChain".into(), plist::Value::Array(safe));
        }
    }
    for key in [
        "FDE_PersonalRecoveryKeyCMS",
        "EncryptedNewRecoveryKey",
        "RecoveryKey",
        "RecoveryKeyCMS64",
        "BootstrapToken",
        "UnlockToken",
        "PIN",
        "Password",
        "CurrentPassword",
        "NewPassword",
        "FirmwarePassword",
        "ActivationLockBypassCode",
        "FileVaultUnlock",
    ] {
        body.remove(key);
    }
    for value in body.values_mut() {
        match value {
            plist::Value::Dictionary(v) => redact(v),
            plist::Value::Array(values) => {
                for v in values {
                    if let plist::Value::Dictionary(v) = v {
                        redact(v)
                    }
                }
            }
            _ => {}
        }
    }
}

pub(crate) async fn purge_inputs(
    c: &mut PgConnection,
    key: &rss_mdm_native_protection::Protector,
    tenant: &str,
    operation: uuid::Uuid,
    command: &rss_device_command::Command,
) -> Result<rss_mdm_recovery_credentials::cleanup::CopyState, Error> {
    // ACK settles delivery, not recovery validity. Once the material owner permits expiry,
    // an accepted execute receipt proves these inputs cannot be dispatched again.
    use rss_mdm_recovery_credentials::cleanup::CopyState;
    if command.spec().id().as_str() != operation.to_string()
        || command.spec().scope().tenant().to_string() != tenant
    {
        return Err(Error::Conflict);
    }
    if !command.status().is_terminal() {
        let settled:bool=sqlx::query_scalar("SELECT coalesce((SELECT accepted AND state IN('acknowledged','error') FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND operation=$2 AND phase='execute' ORDER BY ordinal DESC LIMIT 1),false)").bind(tenant).bind(operation).fetch_one(&mut *c).await.map_err(crate::database::db)?;
        if !settled {
            return Ok(CopyState::Retained);
        }
    }
    let rows=sqlx::query("SELECT id, device, request FROM mdm_apple.attempts WHERE tenant_id = CAST($1 AS uuid) AND operation = $2 FOR UPDATE")
        .bind(tenant).bind(operation).fetch_all(&mut *c).await.map_err(crate::database::db)?;
    for row in rows {
        let id = row.try_get("id").map_err(crate::database::db)?;
        let device = row.try_get("device").map_err(crate::database::db)?;

        let plain = crate::protection::open(
            key,
            tenant,
            device,
            id,
            crate::protection::Part::Request,
            &row.try_get::<Vec<u8>, _>("request")
                .map_err(crate::database::db)?,
        )?;
        let mut value = protocol::decode(plain.expose())?;
        redact(&mut value);
        let encoded = zeroize::Zeroizing::new(protocol::xml(value)?);
        let sealed = crate::protection::seal(
            key,
            tenant,
            device,
            id,
            crate::protection::Part::Request,
            &encoded,
        )?;
        sqlx::query("UPDATE mdm_apple.attempts SET request=$3 WHERE tenant_id=$1::uuid AND id=$2")
            .bind(tenant)
            .bind(id)
            .bind(sealed)
            .execute(&mut *c)
            .await
            .map_err(crate::database::db)?;
    }
    Ok(CopyState::Purged)
}
