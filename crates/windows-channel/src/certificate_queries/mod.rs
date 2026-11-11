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
    directory::{Projection, Query, Schema},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub static REQUESTS: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| Schema::derived::<Request>("windows_certificate_requests", &["attempt"], rss_mdm_query::DEFAULT_PAGE_LIMIT, rss_mdm_query::MAX_PAGE_LIMIT, &[]).expect("Public directory model"));
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
    pub operation_id: Uuid,
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
 SELECT i.signing_attempt AS attempt,'enrollment'::text AS kind,q.device,q.id AS enrollment_id,
        q.issuance_operation AS operation_id,NULL::uuid AS predecessor
 FROM mdm_access.enrollment_intents i JOIN params p ON i.tenant_id=p.tenant
 JOIN mdm_access.requests q ON(q.tenant_id,q.id,q.device)=(i.tenant_id,i.request_id,i.device)
 WHERE q.device=p.device
 UNION ALL
 SELECT i.signing_attempt,'renewal',i.device,coalesce(k.protocol_request,r.request_id),i.id,i.previous_credential
 FROM mdm_windows.renewal_intents i JOIN params p ON i.tenant_id=p.tenant
 JOIN mdm_access.devices r ON(r.tenant_id,r.id)=(i.tenant_id,i.device)
 JOIN mdm_access.credentials k ON(k.tenant_id,k.id,k.device)=(i.tenant_id,i.previous_credential,i.device)
 WHERE i.device=p.device
), history AS (
 SELECT * FROM roots
 UNION
 SELECT s.attempt,h.kind,h.device,h.enrollment_id,h.operation_id,h.predecessor
 FROM history h JOIN mdm_pki.signing s ON s.successor=h.attempt
 JOIN params p ON s.tenant_id=p.tenant WHERE s.purpose='windows'
), candidates AS (
 SELECT h.*,r.state AS registration_state,
 CASE WHEN q.state='pending' AND q.expires_at<=statement_timestamp() THEN 'expired' ELSE q.state END AS enrollment_state,
 CASE WHEN h.kind='enrollment' THEN q.state='bound' ELSE n.id IS NOT NULL END AS linked,
 CASE WHEN h.kind='enrollment' THEN CASE WHEN q.authority_kind='parent_certificate' THEN q.protocol_ready ELSE r.first_authenticated_at IS NOT NULL END ELSE n.activated_at IS NOT NULL END AS activated
 FROM history h CROSS JOIN params p
 LEFT JOIN mdm_access.devices r ON(r.tenant_id,r.id)=(p.tenant,h.device)
 LEFT JOIN mdm_access.requests q ON(q.tenant_id,q.id)=(p.tenant,h.enrollment_id)
 LEFT JOIN mdm_windows.renewals n ON(n.tenant_id,n.id)=(p.tenant,h.operation_id) AND h.kind='renewal'
)
SELECT jsonb_build_object('attempt',attempt,'kind',kind,'device',device,'enrollmentId',enrollment_id,
 'operationId',operation_id,'registrationState',registration_state,
 'enrollmentState',enrollment_state,'predecessor',predecessor,'linked',coalesce(linked,false),'activated',coalesce(activated,false)) AS context
FROM candidates WHERE true
"#;
fn append_context(sql: &mut sqlx::QueryBuilder<sqlx::Postgres>, tenant: &str, device: &str) {
    sql.push("WITH RECURSIVE params AS (SELECT ").push_bind(tenant.to_owned())
        .push("::uuid AS tenant,").push_bind(device.to_owned()).push("::text AS device").push(HISTORY);
}
fn sql(tenant: &str, device: &str) -> sqlx::QueryBuilder<sqlx::Postgres> {
    let mut sql = sqlx::QueryBuilder::new("");
    append_context(&mut sql, tenant, device);
    sql
}
fn directory_sql(tenant: &str, device: &str, now: i64) -> sqlx::QueryBuilder<sqlx::Postgres> {
    let mut sql = sqlx::QueryBuilder::new("WITH contexts AS (");
    append_context(&mut sql, tenant, device);
    sql.push("), clock AS (SELECT ").push_bind(now).push("::bigint AS now), signing AS (SELECT c.context,s.attempt,s.state,s.issuer,s.deadline,s.successor,floor(extract(epoch FROM s.created_at))::bigint created_at,convert_from(s.binding,'UTF8')::jsonb frozen FROM contexts c JOIN mdm_pki.signing s ON s.tenant_id=$1::uuid AND s.attempt=(c.context->>'attempt')::uuid AND s.purpose='windows'), corrected AS (SELECT context || jsonb_build_object('linked',state<>'superseded' AND (context->>'linked')::boolean,'activated',state<>'superseded' AND (context->>'activated')::boolean) context,attempt,state,issuer,deadline,successor,created_at,frozen FROM signing), rows AS (SELECT context || jsonb_build_object('signing',jsonb_build_object('attempt',attempt,'state',state,'issuer',frozen->>'issuer','createdAt',created_at,'deadline',deadline,'notBefore',(frozen->>'start')::bigint,'notAfter',(frozen->>'end')::bigint,'successor',successor),'requirements',to_jsonb(array_remove(ARRAY[CASE WHEN state='prepared' THEN CASE WHEN deadline<=clock.now THEN 'expired' ELSE 'awaiting_original_dispatch' END WHEN state IN('signing','unknown') THEN 'original_ca_response' WHEN state='issued' AND NOT(context->>'linked')::boolean THEN 'awaiting_native_continuation' WHEN state='issued' AND NOT(context->>'activated')::boolean THEN 'awaiting_device_possession' WHEN state='superseded' THEN 'superseded' END,CASE WHEN context->>'registrationState'='revoked' OR context->>'enrollmentState'='cancelled' THEN 'revoked' END,CASE WHEN context->>'enrollmentState'='expired' OR (frozen->>'end')::bigint<=clock.now THEN 'expired' END],NULL))) row FROM corrected CROSS JOIN clock) SELECT row FROM rows WHERE true");
    sql
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
    let auth = rss_mdm_authorization_service::snapshot_on(
        rss_mdm_install_support::StorageProfile::Mdm,
        c,
        p.tenant_id(),
        p.instance_id(),
    )
    .await?;
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
        let mut sql = directory_sql(p.tenant_id(), device, now);
        rss_mdm_query_postgres::append(&mut sql, q, after.as_ref(), &*REQUEST_BINDINGS).map_err(query_error)?;
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
            rss_mdm_install_support::StorageProfile::Mdm,
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
        let signing = pki::read_in(
            rss_mdm_install_support::StorageProfile::Mdm,
            &mut tx,
            p.tenant_id(),
            attempt,
        )
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
        let page = pki::operations_in(
            rss_mdm_install_support::StorageProfile::Mdm,
            &mut tx,
            p.tenant_id(),
            attempt,
            q,
            codec,
            &binding,
        )
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
        let result = pki::operation_in(
            rss_mdm_install_support::StorageProfile::Mdm,
            &mut tx,
            p.tenant_id(),
            attempt,
            operation,
            identity,
        )
        .await
        .map_err(pki_error)?;
        tx.rollback().await.map_err(db)?;
        self.confirm_certificate_query(p, &before).await?;
        Ok(result)
    }
}

pub static REQUEST_BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> = std::sync::LazyLock::new(|| rss_mdm_query_postgres::Bindings::new(&REQUESTS, &[rss_mdm_query_postgres::Source::json("", "row")]).expect("Complete public model storage binding"));
