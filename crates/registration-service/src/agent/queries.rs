//! Device-scoped enrollment facts. No query borrows the issuance or activation write path.
//! ref: sqlx v0.9.0 sqlx-postgres/src/transaction.rs; sqlx-core/src/query_builder.rs.
use super::*;
use rss_mdm_authorization_service::Permission;
use rss_mdm_query::{
    Page,
    directory::{Field, Kind, Projection, Query, Schema},
};

pub static REQUESTS: Schema = Schema {
    id: "agent_requests",
    keys: &["id"],
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    fields: &[
        Field::scalar("id", Kind::Uuid),
        Field::scalar("source", Kind::Text),
        Field::scalar("state", Kind::Text),
        Field::scalar("registration", Kind::Uuid),
        Field::scalar("createdAt", Kind::Integer),
        Field::output("device"),
        Field::output("operationId"),
        Field::output("actor"),
        Field::output("instance"),
        Field::output("expiresAt"),
        Field::output("predecessor"),
        Field::output("generation"),
        Field::output("registrationState"),
        Field::output("issuance"),
        Field::output("issuanceState"),
        Field::output("issuanceOperation"),
        Field::output("issuer"),
        Field::output("notBefore"),
        Field::output("notAfter"),
        Field::output("activationOperation"),
        Field::output("activated"),
        Field::output("requirements"),
    ],
};
pub static OPERATIONS: Schema = Schema {
    id: "agent_issuance_recovery_operations",
    keys: &["actor", "operationId"],
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    fields: &[
        Field::scalar("actor", Kind::Text),
        Field::scalar("operationId", Kind::Uuid),
        Field::output("instance"),
    ],
};
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReceiptIdentity {
    pub actor: String,
    pub instance: String,
}
impl ReceiptIdentity {
    fn validate(&self) -> Result<(), Error> {
        if self.actor.is_empty()
            || self.instance.is_empty()
            || self.actor.len() > 1024
            || self.instance.len() > 1024
        {
            Err(Error::Malformed)
        } else {
            Ok(())
        }
    }
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Operation {
    pub actor: String,
    pub instance: String,
    pub operation_id: Uuid,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Requirement {
    AwaitingAuthorization,
    OriginalClientMaterial,
    OriginalCaResponse,
    AwaitingDeviceActivation,
    Expired,
    Revoked,
    PredecessorUnavailable,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Download,
    Browser,
    Native,
    Recovery,
    Renewal,
    Configuration,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IssuanceState {
    Signing,
    Unknown,
    Issued,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Request {
    pub id: Uuid,
    pub device: String,
    pub source: Source,
    pub state: wire::GrantState,
    pub operation_id: Uuid,
    pub actor: Option<String>,
    pub instance: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub registration: Option<Uuid>,
    pub generation: Option<i64>,
    pub registration_state: Option<crate::enrollment::read::RegistrationState>,
    pub predecessor: Option<Uuid>,
    pub issuance: Option<Uuid>,
    pub issuance_state: Option<IssuanceState>,
    pub issuance_operation: Option<Uuid>,
    pub issuer: Option<String>,
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
    pub activation_operation: Option<Uuid>,
    pub activated: bool,
    pub requirements: Vec<Requirement>,
}
const REQUEST_SQL: &str = r#"SELECT jsonb_build_object(
'id',g.id,'device',g.device,'source',g.source,'state',CASE WHEN g.state='revoked' THEN 'revoked' WHEN g.expires_at<=statement_timestamp() THEN 'expired' ELSE g.state END,
'operationId',g.operation_id,'actor',g.actor,'instance',g.instance,'createdAt',floor(extract(epoch FROM g.created_at))::bigint,'expiresAt',floor(extract(epoch FROM g.expires_at))::bigint,
'registration',r.id,'generation',r.generation,'registrationState',r.state,'predecessor',g.predecessor,
'issuance',i.id,'issuanceState',i.state,'issuanceOperation',i.operation_id,'issuer',i.signing_issuer,'notBefore',i.not_before,'notAfter',i.not_after,
'activationOperation',i.activation_operation,'activated',i.activation_result IS NOT NULL,'requirements',to_jsonb(array_remove(ARRAY[
 CASE WHEN g.state='pending' THEN 'awaiting_authorization' END,
 CASE WHEN g.state='revoked' THEN 'revoked' END,
 CASE WHEN g.expires_at<=statement_timestamp() THEN 'expired' END,
 CASE WHEN g.target_registration IS NOT NULL AND (r.state<>'active' OR NOT EXISTS(SELECT 1 FROM mdm_access.credentials k WHERE k.tenant_id=g.tenant_id AND k.id=g.predecessor AND k.registration=r.id AND k.state='active')) AND i.activation_result IS NULL THEN 'predecessor_unavailable' END,
 CASE WHEN i.id IS NULL AND g.state='available' THEN 'original_client_material' END,
 CASE WHEN i.state IN ('signing','unknown') THEN 'original_ca_response' END,
 CASE WHEN i.state='issued' AND i.activation_result IS NULL THEN 'awaiting_device_activation' END
 ],NULL)))
 FROM mdm_access.agent_grants g LEFT JOIN mdm_access.agent_issuances i ON(i.tenant_id,i.grant_id)=(g.tenant_id,g.id)
 LEFT JOIN mdm_access.registrations r ON r.tenant_id=g.tenant_id AND (r.id=g.target_registration OR (g.target_registration IS NULL AND r.agent_grant_id=g.id))
 WHERE g.tenant_id="#;
fn request_column(name: &str) -> &'static str {
    match name {
        "id" => "g.id::text COLLATE \"C\"",
        "source" => "g.source COLLATE \"C\"",
        "state" => {
            "(CASE WHEN g.state='revoked' THEN 'revoked' WHEN g.expires_at<=statement_timestamp() THEN 'expired' ELSE g.state END) COLLATE \"C\""
        }
        "registration" => "r.id::text COLLATE \"C\"",
        "createdAt" => "floor(extract(epoch FROM g.created_at))::bigint",
        _ => unreachable!("checked Agent request field"),
    }
}
fn operation_column(name: &str) -> &'static str {
    match name {
        "actor" => "actor COLLATE \"C\"",
        "operationId" => "operation_id::text COLLATE \"C\"",
        _ => unreachable!("checked operation field"),
    }
}
fn conceal(e: Error) -> Error {
    if matches!(e, Error::Forbidden) {
        Error::NotFound
    } else {
        e
    }
}
fn query_error(e: rss_mdm_query::Error) -> Error {
    match e {
        rss_mdm_query::Error::CursorInvalidated => Error::CursorInvalidated,
        _ => Error::Malformed,
    }
}
async fn authorize(
    c: &mut PgConnection,
    p: &AuthorizedPrincipal,
    device: &str,
) -> Result<String, Error> {
    p.credentials(device)?;
    let auth =
        rss_mdm_authorization_service::snapshot_on(c, p.tenant_id(), p.instance_id()).await?;
    auth.require(p, Permission::Credentials, Some(device))
        .map_err(rss_mdm_authorization_service::Error::from)?;
    Ok(auth.query_binding(p)?)
}
async fn issuance_device(c: &mut PgConnection, tenant: &str, id: Uuid) -> Result<String, Error> {
    sqlx::query_scalar("SELECT g.device FROM mdm_access.agent_issuances i JOIN mdm_access.agent_grants g ON(g.tenant_id,g.id)=(i.tenant_id,i.grant_id) WHERE i.tenant_id=$1::uuid AND i.id=$2")
        .bind(tenant).bind(id).fetch_optional(c).await.map_err(db)?.ok_or(Error::NotFound)
}
impl Service {
    fn query_tenant(&self, p: &AuthorizedPrincipal) -> Result<(), Error> {
        p.check_live()?;
        if p.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        Ok(())
    }
    pub async fn request_directory(
        &self,
        p: &AuthorizedPrincipal,
        device: &str,
        q: &Query,
    ) -> Result<Page<Projection<Request>>, Error> {
        self.query_tenant(p)?;
        q.require_schema(&REQUESTS).map_err(query_error)?;
        let mut tx = self.store.snapshot(p.tenant_id()).await?;
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
        let after = q.after(&self.cursor, &binding).map_err(query_error)?;
        let mut sql = sqlx::QueryBuilder::new(REQUEST_SQL);
        sql.push_bind(p.tenant_id().to_owned())
            .push("::uuid AND g.device=")
            .push_bind(device.to_owned());
        rss_mdm_query_postgres::append(&mut sql, q, after.as_ref(), request_column)
            .map_err(query_error)?;
        let rows: Vec<serde_json::Value> = sql
            .build_query_scalar()
            .fetch_all(&mut *tx)
            .await
            .map_err(db)?;
        let rows = rows
            .into_iter()
            .map(serde_json::from_value::<Request>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::Corrupt)?;
        let page = q
            .page_typed(rows, &self.cursor, &binding)
            .map_err(query_error)?;
        tx.rollback().await.map_err(db)?;
        self.store.confirm_query(p, &before).await?;
        Ok(page)
    }
    pub async fn request_details(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
    ) -> Result<Request, Error> {
        self.query_tenant(p)?;
        let mut tx = self.store.snapshot(p.tenant_id()).await?;
        let device: String = sqlx::query_scalar(
            "SELECT device FROM mdm_access.agent_grants WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(p.tenant_id())
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?
        .ok_or(Error::NotFound)?;
        let before = authorize(&mut tx, p, &device).await.map_err(conceal)?;
        let mut sql = sqlx::QueryBuilder::new(REQUEST_SQL);
        sql.push_bind(p.tenant_id().to_owned())
            .push("::uuid AND g.id=")
            .push_bind(id);
        let row: serde_json::Value = sql
            .build_query_scalar()
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        let value = serde_json::from_value(row).map_err(|_| Error::Corrupt)?;
        tx.rollback().await.map_err(db)?;
        self.store.confirm_query(p, &before).await?;
        Ok(value)
    }
    pub async fn registration_recovery_operation(
        &self,
        p: &AuthorizedPrincipal,
        registration: Uuid,
        operation: Uuid,
        identity: &ReceiptIdentity,
    ) -> Result<Option<wire::GrantReceipt>, Error> {
        self.query_tenant(p)?;
        identity.validate()?;
        let mut tx = self.store.snapshot(p.tenant_id()).await?;
        let device:String=sqlx::query_scalar("SELECT device FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2 AND channel='agent'").bind(p.tenant_id()).bind(registration).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::NotFound)?;
        let before = authorize(&mut tx, p, &device).await.map_err(conceal)?;
        let row=sqlx::query("SELECT id,state,platform,floor(extract(epoch FROM expires_at))::bigint AS expiry,expires_at>statement_timestamp() AS live,actor,instance,target_registration FROM mdm_access.agent_grants WHERE tenant_id=$1::uuid AND source='recovery' AND operation_id=$2 AND target_registration=$3").bind(p.tenant_id()).bind(operation).bind(registration).fetch_optional(&mut *tx).await.map_err(db)?;
        let value = if let Some(row) = row {
            if row.try_get::<String, _>("actor").map_err(db)? != identity.actor
                || row.try_get::<String, _>("instance").map_err(db)? != identity.instance
                || row.try_get::<Uuid, _>("target_registration").map_err(db)? != registration
            {
                return Err(Error::Conflict);
            }
            Some(receipt(&row)?)
        } else {
            None
        };
        tx.rollback().await.map_err(db)?;
        self.store.confirm_query(p, &before).await?;
        Ok(value)
    }
    pub async fn issuance_recovery_operations(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
        q: &Query,
    ) -> Result<Page<Projection<Operation>>, Error> {
        self.query_tenant(p)?;
        q.require_schema(&OPERATIONS).map_err(query_error)?;
        let mut tx = self.store.snapshot(p.tenant_id()).await?;
        let device = issuance_device(&mut tx, p.tenant_id(), id).await?;
        let before = authorize(&mut tx, p, &device).await.map_err(conceal)?;
        let binding = q
            .binding(&(
                p.tenant_id(),
                p.principal_id(),
                p.instance_id(),
                &device,
                id,
                &before,
            ))
            .map_err(query_error)?;
        let after = q.after(&self.cursor, &binding).map_err(query_error)?;
        let mut sql = sqlx::QueryBuilder::new(
            "SELECT jsonb_build_object('actor',actor,'instance',instance,'operationId',operation_id) FROM mdm_access.registration_operations WHERE tenant_id=",
        );
        sql.push_bind(p.tenant_id().to_owned())
            .push("::uuid AND agent_issuance_recovery=")
            .push_bind(id);
        rss_mdm_query_postgres::append(&mut sql, q, after.as_ref(), operation_column)
            .map_err(query_error)?;
        let rows: Vec<serde_json::Value> = sql
            .build_query_scalar()
            .fetch_all(&mut *tx)
            .await
            .map_err(db)?;
        let rows = rows
            .into_iter()
            .map(serde_json::from_value::<Operation>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::Corrupt)?;
        let page = q
            .page_typed(rows, &self.cursor, &binding)
            .map_err(query_error)?;
        tx.rollback().await.map_err(db)?;
        self.store.confirm_query(p, &before).await?;
        Ok(page)
    }
    /// The selected submitter is a locator. Only the current caller's device permission grants access.
    pub async fn issuance_recovery_operation(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
        operation: Uuid,
        identity: &ReceiptIdentity,
    ) -> Result<Option<wire::Candidate>, Error> {
        self.query_tenant(p)?;
        identity.validate()?;
        let mut tx = self.store.snapshot(p.tenant_id()).await?;
        let device = issuance_device(&mut tx, p.tenant_id(), id).await?;
        let before = authorize(&mut tx, p, &device).await.map_err(conceal)?;
        let row = sqlx::query(
            "SELECT * FROM mdm_access.agent_issuances WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(p.tenant_id())
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
        let grant=sqlx::query("SELECT *,floor(extract(epoch FROM expires_at))::bigint AS expiry,expires_at>statement_timestamp() AS live FROM mdm_access.agent_grants WHERE tenant_id=$1::uuid AND id=$2").bind(p.tenant_id()).bind(row.try_get::<Uuid,_>("grant_id").map_err(db)?).fetch_one(&mut *tx).await.map_err(db)?;
        let record=sqlx::query("SELECT result,digest,instance,agent_issuance_recovery FROM mdm_access.registration_operations WHERE tenant_id=$1::uuid AND actor=$2 AND operation_id=$3 AND agent_issuance_recovery=$4").bind(p.tenant_id()).bind(&identity.actor).bind(operation).bind(id).fetch_optional(&mut *tx).await.map_err(db)?;
        let value = if let Some(record) = record {
            if record.try_get::<String, _>("instance").map_err(db)? != identity.instance
                || record
                    .try_get::<Option<Uuid>, _>("agent_issuance_recovery")
                    .map_err(db)?
                    != Some(id)
                || serde_json::from_str::<Uuid>(&record.try_get::<String, _>("result").map_err(db)?)
                    .ok()
                    != Some(id)
            {
                return Err(Error::Conflict);
            }
            let value = issuance::candidate(&grant, &row)?;
            let chain = value
                .certificate_chain
                .iter()
                .map(|v| STANDARD.decode(v).map_err(|_| Error::Corrupt))
                .collect::<Result<Vec<_>, _>>()?;
            if digest(&("agent_issuance_recovery", id, chain))?
                != record.try_get::<String, _>("digest").map_err(db)?
            {
                return Err(Error::Corrupt);
            }
            Some(value)
        } else {
            None
        };
        tx.rollback().await.map_err(db)?;
        self.store.confirm_query(p, &before).await?;
        Ok(value)
    }
}

#[cfg(feature = "integration")]
impl Service {
    pub fn pause_query_before_authority(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        std::sync::Arc<tokio::sync::Notify>,
    ) {
        self.store.pause_query_before_authority()
    }
}
