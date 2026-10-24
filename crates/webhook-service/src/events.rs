//! Public event bytes and the existing SQL Outbox contract, never a second queue.
use crate::{Error, PgTransaction, model::*};
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_request_context::TenantId;
use rss_transactional_messaging::{message::*, outbox::PendingMessage};
use sha2::{Digest, Sha256};
use sqlx::PgConnection;
use uuid::Uuid;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum Source {
    Event(Event),
    Compliance(CompliancePublication),
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompliancePublication {
    pub id: Uuid,
    pub tenant: Uuid,
    pub run: Uuid,
    pub previous: Option<Uuid>,
    pub rule: Uuid,
    pub rule_version: i64,
    pub occurred_at: i64,
}
pub async fn compliance_in(
    tx: &mut PgTransaction<'_>,
    source: CompliancePublication,
) -> Result<(), Error> {
    if tx.tenant_id().to_string() != source.tenant.to_string()
        || source.id.is_nil()
        || source.run.is_nil()
        || source.rule.is_nil()
        || source.rule_version < 1
    {
        return Err(Error::Invalid);
    }
    tx.with_connection(move|c|Box::pin(async move {Ok(async {
        sqlx::query("INSERT INTO mdm_webhook.compliance_sources(tenant_id,id,document) VALUES($1,$2,$3) ON CONFLICT(tenant_id,id) DO NOTHING").bind(source.tenant).bind(source.id).bind(serde_json::to_value(&source)?).execute(&mut *c).await?;
        let pending=message(source.id,source.tenant,source.occurred_at,SOURCE_DOMAIN,serde_json::to_vec(&Source::Compliance(source))?)?;
        append_on(c,pending).await
    }.await)})).await??;
    Ok(())
}

pub const SOURCE_DOMAIN: &str = "mdm-webhook-source";
pub const DELIVERY_DOMAIN: &str = "mdm-webhook-delivery";
pub const SOURCE_SCHEMA: &str = include_str!("../schema/source-v1.json");
pub const EVENT_SCHEMA: &str = include_str!("../schema/event-v1.json");
pub fn identity(namespace: Uuid, value: &str) -> Uuid {
    Uuid::new_v5(&namespace, value.as_bytes())
}
pub fn domain(name: &str) -> MessagingDomain {
    MessagingDomain::parse(name).expect("constant webhook domain")
}
pub fn message(
    id: Uuid,
    tenant: Uuid,
    at: i64,
    name: &str,
    body: Vec<u8>,
) -> Result<PendingMessage<Vec<u8>>, Error> {
    let (contract, schema, route) = if name == SOURCE_DOMAIN {
        ("mdm.webhook.source", SOURCE_SCHEMA, "mdm.webhook.source.v1")
    } else {
        ("mdm.webhook.event", EVENT_SCHEMA, "mdm.webhook.v1")
    };
    let metadata = MessageMetadata::new(
        AuthoredMessageMetadata::new(
            TenantId::parse(&tenant.to_string()).map_err(|_| Error::Invalid)?,
            Timepoint::try_from(at).map_err(|_| Error::Invalid)?,
            domain(name),
            MessageRoute::parse(route).map_err(|_| Error::Invalid)?,
            ContractIdentity::new(
                ContractId::parse(contract).map_err(|_| Error::Invalid)?,
                ContractVersion::from_static_major(1),
                SchemaDigest::parse(&format!("sha256:{:x}", Sha256::digest(schema.as_bytes())))
                    .map_err(|_| Error::Invalid)?,
            ),
        ),
        MessageMetadataExtensions::new(None, None, None, Default::default()),
    );
    Ok(PendingMessage::new(MessageEnvelope::new(
        MessageId::parse(&id.to_string()).map_err(|_| Error::Invalid)?,
        metadata,
        body,
    )))
}
/// The caller owns the same tenant/fence-bound transaction, deadline and settlement.
/// SQL callers must propagate Conflict and SQL errors; the business transaction must roll back.
pub async fn append_on(
    c: &mut PgConnection,
    message: PendingMessage<Vec<u8>>,
) -> Result<(), Error> {
    let e = message.envelope();
    let outcome:String=sqlx::query_scalar("SELECT rss_transactional_messaging.append_outbox($1,$2)")
        .bind(e.canonical_bytes()).bind(serde_json::json!({"trace":e.transport_context().trace(),"tenant_authority":e.transport_context().tenant_authority()}))
        .fetch_one(c).await?;
    match outcome.as_str() {
        "inserted" | "already_present" => Ok(()),
        "conflict" => Err(Error::Conflict),
        _ => Err(Error::Storage),
    }
}
pub async fn emit_on(c: &mut PgConnection, event: &Event) -> Result<(), Error> {
    emit_derived_on(c, event, None).await
}
pub(crate) async fn emit_derived_on(
    c: &mut PgConnection,
    event: &Event,
    origin: Option<Uuid>,
) -> Result<(), Error> {
    event.validate()?;
    let body = serde_json::to_vec(event)?;
    let insert = if origin.is_some() {
        "INSERT INTO mdm_webhook.events(tenant_id,id,document,body,created_at) VALUES($1,$2,$3,$4,(SELECT created_at FROM mdm_webhook.compliance_sources WHERE tenant_id=$1 AND id=$5)) ON CONFLICT(tenant_id,id) DO NOTHING"
    } else {
        "INSERT INTO mdm_webhook.events(tenant_id,id,document,body,created_at) SELECT $1,$2,$3,$4,clock_timestamp() WHERE $5::uuid IS NULL ON CONFLICT(tenant_id,id) DO NOTHING"
    };
    let inserted = sqlx::query(insert)
        .bind(event.tenant_id)
        .bind(event.event_id)
        .bind(serde_json::to_value(event)?)
        .bind(&body)
        .bind(origin)
        .execute(&mut *c)
        .await?
        .rows_affected();
    if inserted == 0 {
        let old: Vec<u8> =
            sqlx::query_scalar("SELECT body FROM mdm_webhook.events WHERE tenant_id=$1 AND id=$2")
                .bind(event.tenant_id)
                .bind(event.event_id)
                .fetch_one(&mut *c)
                .await?;
        if old != body {
            return Err(Error::Conflict);
        }
    }
    append_on(
        c,
        message(
            event.event_id,
            event.tenant_id,
            event.occurred_at,
            SOURCE_DOMAIN,
            serde_json::to_vec(&Source::Event(event.clone()))?,
        )?,
    )
    .await
}
pub async fn emit_in(tx: &mut PgTransaction<'_>, event: Event) -> Result<(), Error> {
    if tx.tenant_id().to_string() != event.tenant_id.to_string() {
        return Err(Error::Denied);
    }
    tx.with_connection(move |c| Box::pin(async move { Ok(emit_on(c, &event).await) }))
        .await??;
    Ok(())
}
pub async fn now_on(c: &mut PgConnection) -> Result<i64, Error> {
    Ok(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(c)
            .await?,
    )
}
