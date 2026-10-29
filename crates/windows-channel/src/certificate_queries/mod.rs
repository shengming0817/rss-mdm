//! Original Windows certificate requests, located only through their device/enrollment owner.
//! ref: sqlx v0.9.0 sqlx-postgres/src/transaction.rs; sqlx-core/src/query_builder.rs.
mod http;
use crate::{Error, Failure, Store, database::db};
pub use http::mount;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_pki_service::signing_queries as pki;
use rss_mdm_query::{
    Page,
    cursor::CursorCodec,
    directory::{Field, Kind, Projection, Query, Schema},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub static REQUESTS: Schema = Schema {
    id: "windows_certificate_requests",
    keys: &["attempt"],
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    fields: &[
        Field::scalar("attempt", Kind::Uuid),
        Field::scalar("kind", Kind::Text),
        Field::scalar("enrollmentId", Kind::Uuid),
        Field::scalar("registration", Kind::Uuid),
        Field::output("device"),
        Field::output("operationId"),
        Field::output("expectedGeneration"),
        Field::output("generation"),
        Field::output("registrationState"),
        Field::output("enrollmentState"),
        Field::output("predecessor"),
        Field::output("linked"),
        Field::output("activated"),
        Field::output("signing"),
        Field::output("requirements"),
    ],
};
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RequestKind {
    Enrollment,
    Renewal,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Requirement {
    AwaitingOriginalDispatch,
    OriginalCaResponse,
    AwaitingNativeContinuation,
    AwaitingDevicePossession,
    Expired,
    Revoked,
    Superseded,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Request {
    #[serde(flatten)]
    pub context: Context,
    pub signing: pki::Signing,
    pub requirements: Vec<Requirement>,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Context {
    pub attempt: Uuid,
    pub kind: RequestKind,
    pub device: String,
    pub enrollment_id: Option<Uuid>,
    pub registration: Uuid,
    pub operation_id: Uuid,
    pub expected_generation: i64,
    pub generation: Option<i64>,
    pub registration_state:
        Option<rss_mdm_registration_service::enrollment::read::RegistrationState>,
    pub enrollment_state: Option<rss_mdm_registration_service::enrollment::read::State>,
    pub predecessor: Option<Uuid>,
    pub linked: bool,
    pub activated: bool,
}
// Reverse successor edges retain original attempts after the live intent points at a replacement.
// UNION (not UNION ALL) makes even a corrupt cycle finite; the transaction has a statement budget.
const HISTORY: &str = r#"
), roots AS (
 SELECT i.signing_attempt AS attempt,'enrollment'::text AS kind,coalesce(g.device,parent.device) AS device,q.id AS enrollment_id,i.registration,
        q.issuance_operation AS operation_id,q.expected_generation,NULL::uuid AS predecessor
 FROM mdm_access.enrollment_intents i JOIN params p ON i.tenant_id=p.tenant
 JOIN mdm_access.requests q ON(q.tenant_id,q.id)=(i.tenant_id,i.request_id)
 LEFT JOIN mdm_access.grants g ON(g.tenant_id,g.id)=(q.tenant_id,q.grant_id)
 LEFT JOIN mdm_access.registrations parent ON(parent.tenant_id,parent.id)=(q.tenant_id,q.parent_id)
 WHERE coalesce(g.device,parent.device)=p.device
 UNION ALL
 SELECT i.signing_attempt,'renewal',r.device,r.request_id,i.registration,i.id,i.generation,i.previous_credential
 FROM mdm_windows.renewal_intents i JOIN params p ON i.tenant_id=p.tenant
 JOIN mdm_access.registrations r ON(r.tenant_id,r.id)=(i.tenant_id,i.registration)
 WHERE r.device=p.device
), history AS (
 SELECT * FROM roots
 UNION
 SELECT s.attempt,h.kind,h.device,h.enrollment_id,h.registration,h.operation_id,h.expected_generation,h.predecessor
 FROM history h JOIN mdm_pki.signing s ON s.successor=h.attempt
 JOIN params p ON s.tenant_id=p.tenant WHERE s.purpose='windows'
), candidates AS (
 SELECT h.*,r.generation,r.state AS registration_state,
 CASE WHEN q.state='pending' AND q.expires_at<=statement_timestamp() THEN 'expired' ELSE q.state END AS enrollment_state,
 CASE WHEN h.kind='enrollment' THEN r.id IS NOT NULL ELSE n.id IS NOT NULL END AS linked,
 CASE WHEN h.kind='enrollment' THEN r.first_authenticated_at IS NOT NULL ELSE n.activated_at IS NOT NULL END AS activated
 FROM history h CROSS JOIN params p
 LEFT JOIN mdm_access.registrations r ON(r.tenant_id,r.id)=(p.tenant,h.registration)
 LEFT JOIN mdm_access.requests q ON(q.tenant_id,q.id)=(p.tenant,h.enrollment_id)
 LEFT JOIN mdm_windows.renewals n ON(n.tenant_id,n.id)=(p.tenant,h.operation_id) AND h.kind='renewal'
)
SELECT jsonb_build_object('attempt',attempt,'kind',kind,'device',device,'enrollmentId',enrollment_id,'registration',registration,
 'operationId',operation_id,'expectedGeneration',expected_generation,'generation',generation,'registrationState',registration_state,
 'enrollmentState',enrollment_state,'predecessor',predecessor,'linked',linked,'activated',activated)
FROM candidates WHERE true
"#;
fn sql(tenant: &str, device: &str) -> sqlx::QueryBuilder<sqlx::Postgres> {
    let mut sql = sqlx::QueryBuilder::new("WITH RECURSIVE params AS (SELECT ");
    sql.push_bind(tenant.to_owned())
        .push("::uuid AS tenant,")
        .push_bind(device.to_owned())
        .push("::text AS device")
        .push(HISTORY);
    sql
}
fn column(name: &str) -> &'static str {
    match name {
        "attempt" => "attempt::text COLLATE \"C\"",
        "kind" => "kind COLLATE \"C\"",
        "enrollmentId" => "enrollment_id::text COLLATE \"C\"",
        "registration" => "registration::text COLLATE \"C\"",
        _ => unreachable!("checked Windows request field"),
    }
}
fn query_error(e: rss_mdm_query::Error) -> Error {
    match e {
        rss_mdm_query::Error::CursorInvalidated => Error::Conflict,
        _ => Error::Malformed,
    }
}
fn pki_error(e: rss_mdm_pki_service::Error) -> Error {
    use rss_mdm_pki_service::Error as P;
    match e {
        P::Request => Error::Malformed,
        P::Forbidden => Error::Forbidden,
        P::NotFound => Error::NotFound,
        P::Conflict | P::ReadConflict | P::CursorInvalidated => Error::Conflict,
        _ => Error::Unavailable(Failure::Database),
    }
}
async fn authorize(
    c: &mut sqlx::PgConnection,
    p: &AuthorizedPrincipal,
    device: &str,
) -> Result<String, Error> {
    p.credentials(device)?;
    let auth =
        rss_mdm_authorization_service::snapshot_on(c, p.tenant_id(), p.instance_id()).await?;
    auth.require(p, Permission::Credentials, Some(device))?;
    Ok(auth.query_binding(p)?)
}
async fn context(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &str,
    attempt: Uuid,
) -> Result<Context, Error> {
    let mut sql = sql(tenant, device);
    sql.push(" AND attempt=").push_bind(attempt);
    let row: Option<serde_json::Value> = sql
        .build_query_scalar()
        .fetch_optional(c)
        .await
        .map_err(db)?;
    serde_json::from_value(row.ok_or(Error::NotFound)?)
        .map_err(|_| Error::Unavailable(Failure::Database))
}
fn view(mut context: Context, signing: pki::Signing, now: i64) -> Request {
    if matches!(signing.state, pki::State::Superseded) {
        context.linked = false;
        context.activated = false;
    }
    let mut requirements = vec![];
    match signing.state {
        pki::State::Prepared => requirements.push(if signing.deadline <= now {
            Requirement::Expired
        } else {
            Requirement::AwaitingOriginalDispatch
        }),
        pki::State::Signing | pki::State::Unknown => {
            requirements.push(Requirement::OriginalCaResponse)
        }
        pki::State::Issued if !context.linked => {
            requirements.push(Requirement::AwaitingNativeContinuation)
        }
        pki::State::Issued if !context.activated => {
            requirements.push(Requirement::AwaitingDevicePossession)
        }
        pki::State::Superseded => requirements.push(Requirement::Superseded),
        _ => {}
    }
    use rss_mdm_registration_service::enrollment::read::{RegistrationState, State};
    if matches!(context.registration_state, Some(RegistrationState::Revoked))
        || matches!(context.enrollment_state, Some(State::Cancelled))
    {
        requirements.push(Requirement::Revoked);
    }
    if matches!(
        context.registration_state,
        Some(RegistrationState::Superseded)
    ) {
        requirements.push(Requirement::Superseded);
    }
    if matches!(context.enrollment_state, Some(State::Expired)) || signing.not_after <= now {
        requirements.push(Requirement::Expired);
    }
    Request {
        context,
        signing,
        requirements,
    }
}
impl Store {
    pub async fn certificate_requests(
        &self,
        p: &AuthorizedPrincipal,
        device: &str,
        q: &Query,
        codec: &CursorCodec,
        now: i64,
    ) -> Result<Page<Projection<Request>>, Error> {
        q.require_schema(&REQUESTS).map_err(query_error)?;
        let mut tx = self.snapshot(p.tenant_id()).await?;
        let before = authorize(&mut tx, p, device).await?;
        let binding = q
            .binding(&(
                p.tenant_id(),
                p.principal_id(),
                p.instance_id(),
                device,
                &before,
            ))
            .map_err(query_error)?;
        let after = q.after(codec, &binding).map_err(query_error)?;
        let mut sql = sql(p.tenant_id(), device);
        rss_mdm_query_postgres::append(&mut sql, q, after.as_ref(), column).map_err(query_error)?;
        let rows: Vec<serde_json::Value> = sql
            .build_query_scalar()
            .fetch_all(&mut *tx)
            .await
            .map_err(db)?;
        let rows = rows
            .into_iter()
            .map(serde_json::from_value::<Context>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::Unavailable(Failure::Database))?;
        let mut signing = pki::read_many_in(
            &mut tx,
            p.tenant_id(),
            &rows.iter().map(|r| r.attempt).collect::<Vec<_>>(),
        )
        .await
        .map_err(pki_error)?;
        let rows = rows
            .into_iter()
            .map(|r| {
                let s = signing
                    .remove(&r.attempt)
                    .ok_or(Error::Unavailable(Failure::Database))?;
                Ok(view(r, s, now))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let page = q.page_typed(rows, codec, &binding).map_err(query_error)?;
        tx.rollback().await.map_err(db)?;
        self.confirm_certificate_query(p, &before).await?;
        Ok(page)
    }
    pub async fn certificate_request(
        &self,
        p: &AuthorizedPrincipal,
        device: &str,
        attempt: Uuid,
        now: i64,
    ) -> Result<Request, Error> {
        let mut tx = self.snapshot(p.tenant_id()).await?;
        let before = authorize(&mut tx, p, device).await?;
        let context = context(&mut tx, p.tenant_id(), device, attempt).await?;
        let signing = pki::read_in(&mut tx, p.tenant_id(), attempt)
            .await
            .map_err(pki_error)?;
        let result = view(context, signing, now);
        tx.rollback().await.map_err(db)?;
        self.confirm_certificate_query(p, &before).await?;
        Ok(result)
    }
    pub async fn certificate_recovery_operations(
        &self,
        p: &AuthorizedPrincipal,
        device: &str,
        attempt: Uuid,
        q: &Query,
        codec: &CursorCodec,
    ) -> Result<Page<Projection<pki::Operation>>, Error> {
        let mut tx = self.snapshot(p.tenant_id()).await?;
        let before = authorize(&mut tx, p, device).await?;
        context(&mut tx, p.tenant_id(), device, attempt).await?;
        let binding = q
            .binding(&(
                p.tenant_id(),
                p.principal_id(),
                p.instance_id(),
                device,
                attempt,
                &before,
            ))
            .map_err(query_error)?;
        let page = pki::operations_in(&mut tx, p.tenant_id(), attempt, q, codec, &binding)
            .await
            .map_err(pki_error)?;
        tx.rollback().await.map_err(db)?;
        self.confirm_certificate_query(p, &before).await?;
        Ok(page)
    }
    pub async fn certificate_recovery_operation(
        &self,
        p: &AuthorizedPrincipal,
        device: &str,
        attempt: Uuid,
        operation: Uuid,
        identity: &pki::ReceiptIdentity,
    ) -> Result<Option<rss_mdm_pki_service::recovery::Receipt>, Error> {
        let mut tx = self.snapshot(p.tenant_id()).await?;
        let before = authorize(&mut tx, p, device).await?;
        context(&mut tx, p.tenant_id(), device, attempt).await?;
        let result = pki::operation_in(&mut tx, p.tenant_id(), attempt, operation, identity)
            .await
            .map_err(pki_error)?;
        tx.rollback().await.map_err(db)?;
        self.confirm_certificate_query(p, &before).await?;
        Ok(result)
    }
}
