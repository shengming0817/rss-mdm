//! Windows request construction, response correlation and session retirement.
use crate::{Error, Failure, database::db};
use rss_mdm_inventory::FieldKey;
use rss_mdm_inventory_service::collection::{Attempts, CollectionError, store};
use rss_mdm_windows_mdm::{
    CodecLimits,
    syncml::{self, Command, Item},
};
use rss_observation::Scope;
use sqlx::Row;
use uuid::Uuid;
const NATIVE_FIELDS: &[(FieldKey, &str)] = &[
    (rss_mdm_inventory::builtin::MODEL, "./DevInfo/Mod"),
    (rss_mdm_inventory::builtin::OS_VERSION, "./DevDetail/SwV"),
];
fn corrupt() -> Error {
    Error::Unavailable(Failure::Database)
}
fn field_index(command: u32, first: u32, count: usize) -> Option<usize> {
    command
        .checked_sub(first)
        .map(|n| n as usize)
        .filter(|n| *n < count)
}

fn apply(
    attempts: &mut Attempts,
    correlated: &rss_mdm_windows_mdm::syncml::Correlated,
    message: u32,
    first: u32,
    received_at: i64,
) -> Result<(), CollectionError> {
    for status in &correlated.statuses {
        if status.command_id == 0 {
            continue;
        }
        // Only Get statuses affect collection. Other sent command acknowledgements are harmless.
        if status.message_id == message
            && let Some(index) = field_index(status.command_id, first, NATIVE_FIELDS.len())
        {
            attempts
                .observe_status(
                    NATIVE_FIELDS
                        .get(index)
                        .ok_or(CollectionError::CorrelationConflict)?
                        .0,
                    status.code,
                    received_at,
                )
                .map_err(|_| CollectionError::CorrelationConflict)?;
        }
    }
    for result in &correlated.results {
        if !result.explicit_message_ref
            || !result.explicit_command_ref
            || result.reference.message_id != message
        {
            return Err(CollectionError::CorrelationConflict);
        }
        let index = field_index(result.reference.command_id, first, NATIVE_FIELDS.len())
            .ok_or(CollectionError::CorrelationConflict)?;
        if result.reference.uri != NATIVE_FIELDS[index].1 {
            return Err(CollectionError::CorrelationConflict);
        }
        attempts
            .observe_value(
                NATIVE_FIELDS
                    .get(index)
                    .ok_or(CollectionError::CorrelationConflict)?
                    .0,
                rss_mdm_inventory::CollectedValue::Value(rss_mdm_inventory::Scalar::String(
                    result.value.0.clone(),
                )),
                received_at,
            )
            .map_err(|_| CollectionError::CorrelationConflict)?;
    }
    Ok(())
}
pub async fn create(
    tx: &mut sqlx::PgConnection,
    protection: &rss_mdm_native_protection::Protector,
    scope: &Scope,
    response: &mut syncml::Message,
) -> Result<Uuid, Error> {
    let (sequence, first) = crate::device::store::allocate_report_in(
        tx,
        &scope.tenant().to_string(),
        scope.registration().as_str(),
        rss_mdm_inventory::ReportSource::MdmWindows,
        scope.epoch().as_str(),
        NATIVE_FIELDS.len() as i64,
        i64::from(u32::MAX),
    )
    .await
    .map_err(db)?
    .ok_or(Error::Conflict)?;
    for (index, (_, uri)) in NATIVE_FIELDS.iter().enumerate() {
        response.commands.push(Command::Get {
            id: first as u32 + index as u32,
            meta: None,
            items: vec![Item {
                more_data: false,
                source: None,
                target: Some((*uri).into()),
                meta: None,
                data: None,
            }],
        });
    }
    let (request, _) =
        syncml::encode_request(response, &CodecLimits::default()).map_err(|_| corrupt())?;
    let keys: Vec<_> = NATIVE_FIELDS.iter().map(|(field, _)| *field).collect();
    let definition = store::freeze_in(tx, scope, 1, &keys).await?;
    let id = store::start_in(tx, scope, sequence, definition).await?;
    let request = protection
        .seal_bytes(&request, &crate::protection::collection_aad(scope, id)?)
        .map_err(|_| corrupt())?;
    sqlx::query("INSERT INTO mdm_windows.collections(tenant_id,id,registration,session_id,request_message,first_command,request) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5,$6,$7)")
        .bind(scope.tenant().to_string()).bind(id.to_string()).bind(scope.registration().as_str()).bind(response.header.session_id.to_string()).bind(i64::from(response.header.message_id)).bind(first).bind(request)
        .execute(&mut *tx).await.map_err(db)?;
    Ok(id)
}
pub async fn accept(
    tx: &mut sqlx::PgConnection,
    _protection: &rss_mdm_native_protection::Protector,
    facts: &mut Vec<rss_mdm_audit_integration::Fact>,
    tenant: &str,
    id: Uuid,
    message: &syncml::Message,
    history: &syncml::Expected,
) -> Result<bool, Error> {
    let mut run = store::load_on(tx, tenant, id).await?;
    if run.scope.source().as_str() != "mdm.windows" {
        return Err(corrupt());
    }
    if run.sealed_at.is_some() {
        if message
            .commands
            .iter()
            .any(|c| matches!(c, Command::Results(_)))
        {
            return Err(Error::Conflict);
        }
        return Ok(true);
    }
    let limits = CodecLimits::default();
    let row = sqlx::query("SELECT request,request_message,first_command FROM mdm_windows.collections WHERE tenant_id=$1::uuid AND id=$2::uuid AND registration=$3::uuid")
        .bind(tenant).bind(id.to_string()).bind(run.scope.registration().as_str()).fetch_one(&mut *tx).await.map_err(db)?;
    let request_message: u32 = row
        .try_get::<i64, _>("request_message")
        .map_err(db)?
        .try_into()
        .map_err(|_| corrupt())?;
    let first_command: u32 = row
        .try_get::<i64, _>("first_command")
        .map_err(db)?
        .try_into()
        .map_err(|_| corrupt())?;
    let correlated = syncml::correlate(history, message, &limits).map_err(|_| Error::Conflict)?;
    let received_at: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
    apply(
        &mut run.attempts,
        &correlated,
        request_message,
        first_command,
        received_at,
    )?;
    let terminal = (run.attempts.complete() && message.final_message)
        || message.header.message_id as usize >= CodecLimits::default().session_messages;
    if terminal {
        let reason = if run.attempts.complete() {
            "complete"
        } else {
            "message_budget"
        };
        facts.extend(store::seal(tx, &mut run, reason).await?);
    } else {
        store::save_attempts_in(tx, &run).await?;
    }
    Ok(terminal)
}

pub async fn terminate_session(
    tx: &mut sqlx::PgConnection,
    facts: &mut Vec<rss_mdm_audit_integration::Fact>,
    tenant: &str,
    registration: &str,
    session: &str,
    reason: &str,
) -> Result<(), Error> {
    let ids: Vec<String> = sqlx::query_scalar("SELECT id::text FROM mdm_windows.collections WHERE tenant_id=$1::uuid AND registration=$2::uuid AND session_id=$3 ORDER BY first_command,id")
        .bind(tenant).bind(registration).bind(session).fetch_all(&mut *tx).await.map_err(db)?;
    for id in ids {
        let native:bool=sqlx::query_scalar("SELECT channel_state IS NOT NULL FROM mdm_windows.collections WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(&id).fetch_one(&mut *tx).await.map_err(db)?;
        if native {
            facts.extend(
                rss_mdm_inventory_service::collection::channel::abandon_in(
                    tx,
                    tenant,
                    Uuid::parse_str(&id).map_err(|_| corrupt())?,
                    reason,
                )
                .await?,
            );
            continue;
        }
        let mut run =
            store::load_on(tx, tenant, Uuid::parse_str(&id).map_err(|_| corrupt())?).await?;
        if run.sealed_at.is_none() {
            facts.extend(store::seal(tx, &mut run, reason).await?);
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn command_range_covers_catalog_and_rejects_outside_without_overflow() {
        let first = u32::MAX - NATIVE_FIELDS.len() as u32 + 1;
        for (index, (_, uri)) in NATIVE_FIELDS.iter().enumerate() {
            assert_eq!(
                field_index(first + index as u32, first, NATIVE_FIELDS.len()),
                Some(index)
            );
            assert!(uri.starts_with("./"));
        }
        assert_eq!(field_index(first - 1, first, NATIVE_FIELDS.len()), None);
        assert_eq!(
            field_index(1024 + NATIVE_FIELDS.len() as u32, 1024, NATIVE_FIELDS.len()),
            None
        );
    }
}
