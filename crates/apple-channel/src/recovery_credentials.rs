//! Native receipt extraction occurs once, inside the original command transaction.
use crate::{Error, Failure, protocol};
use rss_mdm_execution_service::channels::{AppleCommand, AppleRegistration};
use rss_mdm_recovery_credentials::storage as vault;
use sqlx::{PgConnection, Row};

fn failed(_: rss_mdm_recovery_credentials::Error) -> Error {
    Error::Unavailable(Failure::AppleStorage)
}
pub(crate) async fn receive(
    c: &mut PgConnection,
    command: &AppleCommand,
    target: &AppleRegistration,
    report: &plist::Dictionary,
    status: protocol::Status,
) -> Result<(), Error> {
    let tenant = uuid::Uuid::parse_str(&target.tenant).map_err(|_| Error::Malformed)?;
    let Some(action) = vault::native_action_in(
        c,
        tenant,
        command.operation,
        &target.device,
        target.registration,
        target.generation,
    )
    .await
    .map_err(failed)?
    else {
        return Ok(());
    };
    let protection = command
        .recovery
        .as_ref()
        .ok_or(Error::Unavailable(Failure::AppleStorage))?;
    if status != protocol::Status::Acknowledged {
        if status == protocol::Status::Error {
            vault::unknown_in(c, tenant, command.operation)
                .await
                .map_err(failed)?;
        }
        return Ok(());
    }
    let Some(coordinates) = action.coordinates else {
        return Ok(());
    };
    match action.action.as_str() {
        "collect_filevault" | "rotate_filevault" => {
            let value = if action.action == "collect_filevault" {
                report
                    .get("SecurityInfo")
                    .and_then(plist::Value::as_dictionary)
                    .and_then(|v| v.get("FDE_PersonalRecoveryKeyCMS"))
            } else {
                report
                    .get("RotateResult")
                    .and_then(plist::Value::as_dictionary)
                    .and_then(|v| v.get("EncryptedNewRecoveryKey"))
            };
            let Some(cms) = value.and_then(plist::Value::as_data) else {
                vault::unknown_in(c, tenant, command.operation)
                    .await
                    .map_err(failed)?;
                return Ok(());
            };
            let operation = vault::source_operation_in(c, &coordinates)
                .await
                .map_err(failed)?;
            let value = rss_mdm_recovery_credentials::filevault::receive_reserved_cms(
                c,
                protection,
                &coordinates,
                operation,
                &action.recipient,
                cms,
            )
            .await
            .map_err(failed)?;
            vault::replace_native_coordinates_in(c, tenant, command.operation, &value)
                .await
                .map_err(failed)?;
        }
        "verify_recovery_lock" => {
            if report
                .get("PasswordVerified")
                .and_then(plist::Value::as_boolean)
                == Some(true)
            {
                let operation = vault::source_operation_in(c, &coordinates)
                    .await
                    .map_err(failed)?;
                if let Some(original) = action.reconciles {
                    vault::reconcile_in(c, &coordinates, original)
                        .await
                        .map_err(failed)?;
                } else {
                    vault::verify_in(c, &coordinates, operation)
                        .await
                        .map_err(failed)?;
                }
            } else {
                vault::uncertain_version_in(c, &coordinates)
                    .await
                    .map_err(failed)?;
            }
        }
        "clear_recovery_lock" => {
            vault::cleared_in(c, &coordinates).await.map_err(failed)?;
        }
        "set_recovery_lock" => {
            vault::unknown_in(c, tenant, command.operation)
                .await
                .map_err(failed)?;
        }
        "lock_pin" => {
            vault::settled_in(c, &coordinates, command.operation)
                .await
                .map_err(failed)?;
        }
        _ => return Err(Error::Malformed),
    }
    Ok(())
}

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
    terminal: bool,
) -> Result<bool, Error> {
    // ACK settles delivery, not recovery validity. Once the material owner permits expiry,
    // an accepted execute receipt proves these inputs cannot be dispatched again.
    if !terminal {
        let settled:bool=sqlx::query_scalar("SELECT coalesce((SELECT accepted AND state IN('acknowledged','error') FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND operation=$2 AND phase='execute' ORDER BY ordinal DESC LIMIT 1),false)").bind(tenant).bind(operation).fetch_one(&mut *c).await.map_err(crate::database::db)?;
        if !settled {
            return Ok(false);
        }
    }
    let rows=sqlx::query("SELECT id,registration,generation,request FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND operation=$2 FOR UPDATE")
        .bind(tenant).bind(operation).fetch_all(&mut *c).await.map_err(crate::database::db)?;
    for row in rows {
        let id = row.try_get("id").map_err(crate::database::db)?;
        let registration = row.try_get("registration").map_err(crate::database::db)?;
        let generation = row.try_get("generation").map_err(crate::database::db)?;
        let plain = crate::protection::open(
            key,
            tenant,
            registration,
            generation,
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
            registration,
            generation,
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
    Ok(true)
}
