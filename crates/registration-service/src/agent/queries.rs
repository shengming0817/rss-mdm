//! Device-scoped enrollment facts. No query borrows the issuance or activation write path.
//! ref: sqlx v0.9.0 sqlx-postgres/src/transaction.rs; sqlx-core/src/query_builder.rs.
use super::*;
use rss_mdm_authorization_service::Permission;
use rss_mdm_query::{
    Page,
    directory::{Projection, Query, Schema},
};

pub static REQUESTS: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
    Schema::derived::<Request>(
        "agent_requests",
        &["id"],
        rss_mdm_query::DEFAULT_PAGE_LIMIT,
        rss_mdm_query::MAX_PAGE_LIMIT,
        &[],
    )
    .expect("Public directory model")
});
pub static OPERATIONS: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
    Schema::derived::<Operation>(
        "agent_issuance_recovery_operations",
        &["actor", "operationId"],
        rss_mdm_query::DEFAULT_PAGE_LIMIT,
        rss_mdm_query::MAX_PAGE_LIMIT,
        &[],
    )
    .expect("Public directory model")
});
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
    #[schemars(extend("x-rss-maxUtf8Bytes" = 1024))]
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
    Administrator,
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
const REQUEST_SQL: &str = r#"SELECT row FROM (SELECT jsonb_build_object(
'id',g.id,'device',g.device,'source',g.source,'state',CASE WHEN g.state='revoked' THEN 'revoked' WHEN g.expires_at<=statement_timestamp() THEN 'expired' ELSE g.state END,
'operationId',g.operation_id,'actor',g.actor,'instance',g.instance,'createdAt',floor(extract(epoch FROM g.created_at))::bigint,'expiresAt',floor(extract(epoch FROM g.expires_at))::bigint,
'registrationState',r.state,'predecessor',g.predecessor,
'issuance',i.id,'issuanceState',i.state,'issuanceOperation',i.operation_id,'issuer',i.signing_issuer,'notBefore',i.not_before,'notAfter',i.not_after,
'activationOperation',i.activation_operation,'activated',i.activation_result IS NOT NULL,'requirements',to_jsonb(array_remove(ARRAY[
 CASE WHEN g.state='pending' THEN 'awaiting_authorization' END,
 CASE WHEN g.state='revoked' THEN 'revoked' END,
 CASE WHEN g.expires_at<=statement_timestamp() THEN 'expired' END,
 CASE WHEN g.predecessor IS NOT NULL AND (r.state<>'active' OR NOT EXISTS(SELECT 1 FROM mdm_access.credentials k WHERE k.tenant_id=g.tenant_id AND k.id=g.predecessor AND k.device=r.id AND k.state='active')) AND i.activation_result IS NULL THEN 'predecessor_unavailable' END,
 CASE WHEN i.id IS NULL AND g.state='available' THEN 'original_client_material' END,
 CASE WHEN i.state IN ('signing','unknown') THEN 'original_ca_response' END,
 CASE WHEN i.state='issued' AND i.activation_result IS NULL THEN 'awaiting_device_activation' END
 ],NULL))) AS row
 FROM mdm_access.certificate_grants g LEFT JOIN mdm_access.certificate_issuances i ON(i.tenant_id,i.grant_id)=(g.tenant_id,g.id)
 LEFT JOIN mdm_access.devices r ON(r.tenant_id,r.id)=(g.tenant_id,g.device)
 WHERE g.tenant_id="#;
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
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    p: &AuthorizedPrincipal,
    device: &str,
) -> Result<String, Error> {
    if profile != p.profile() {
        return Err(crate::Error::Forbidden);
    }

    p.credentials(device)?;
    let auth = rss_mdm_authorization_service::snapshot_on(
        p.authority_profile(),
        c,
        p.tenant_id(),
        p.instance_id(),
    )
    .await?;
    auth.require(p, Permission::Credentials, Some(device))
        .map_err(rss_mdm_authorization_service::Error::from)?;
    Ok(auth.query_binding(p)?)
}
async fn issuance_device(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: &str,
    id: Uuid,
) -> Result<String, Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).agent_queries_issuance_device_1)
        .bind(tenant)
        .bind(id)
        .fetch_optional(c)
        .await
        .map_err(db)?
        .ok_or(Error::NotFound)
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
        request: &rss_mdm_authorization_service::context::RequestAuth,
        device: &str,
        q: &Query,
    ) -> Result<Page<Projection<Request>>, Error> {
        let p = request.proof.as_ref();
        let profile = self.profile();

        self.query_tenant(p)?;
        q.require_schema(&REQUESTS).map_err(query_error)?;
        let mut tx = self.store.snapshot(p.tenant_id()).await?;
        let before = authorize(profile, &mut tx, p, device).await?;
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
        sql.push(") records WHERE true");
        rss_mdm_query_postgres::append(&mut sql, q, after.as_ref(), &*REQUEST_BINDINGS)
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
        self.store.confirm_query(request, &before).await?;
        Ok(page)
    }
    pub async fn request_details(
        &self,
        request: &rss_mdm_authorization_service::context::RequestAuth,
        id: Uuid,
    ) -> Result<Request, Error> {
        let p = request.proof.as_ref();
        let profile = self.profile();

        self.query_tenant(p)?;
        let mut tx = self.store.snapshot(p.tenant_id()).await?;
        let device: String = sqlx::query_scalar(
            crate::storage_profile::sql(profile).agent_queries_request_details_1,
        )
        .bind(p.tenant_id())
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?
        .ok_or(Error::NotFound)?;
        let before = authorize(profile, &mut tx, p, &device)
            .await
            .map_err(conceal)?;
        let mut sql = sqlx::QueryBuilder::new(REQUEST_SQL);
        sql.push_bind(p.tenant_id().to_owned())
            .push("::uuid AND g.id=")
            .push_bind(id)
            .push(") records");
        let row: serde_json::Value = sql
            .build_query_scalar()
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        let value = serde_json::from_value(row).map_err(|_| Error::Corrupt)?;
        tx.rollback().await.map_err(db)?;
        self.store.confirm_query(request, &before).await?;
        Ok(value)
    }
    pub async fn registration_recovery_operation(
        &self,
        request: &rss_mdm_authorization_service::context::RequestAuth,
        device_id: &str,
        operation: Uuid,
        identity: &ReceiptIdentity,
    ) -> Result<Option<wire::GrantReceipt>, Error> {
        self.query_tenant(&request.proof)?;
        registration_recovery_operation(&self.store, request, device_id, operation, identity).await
    }
    pub async fn issuance_recovery_operations(
        &self,
        request: &rss_mdm_authorization_service::context::RequestAuth,
        id: Uuid,
        q: &Query,
    ) -> Result<Page<Projection<Operation>>, Error> {
        let p = request.proof.as_ref();
        let profile = self.profile();

        self.query_tenant(p)?;
        q.require_schema(&OPERATIONS).map_err(query_error)?;
        let mut tx = self.store.snapshot(p.tenant_id()).await?;
        let device = issuance_device(profile, &mut tx, p.tenant_id(), id).await?;
        let before = authorize(profile, &mut tx, p, &device)
            .await
            .map_err(conceal)?;
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
            crate::storage_profile::sql(profile).agent_queries_issuance_recovery_operations_1,
        );
        sql.push_bind(p.tenant_id().to_owned())
            .push("::uuid AND agent_issuance_recovery=")
            .push_bind(id);
        rss_mdm_query_postgres::append(&mut sql, q, after.as_ref(), &*OPERATION_BINDINGS)
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
        self.store.confirm_query(request, &before).await?;
        Ok(page)
    }
    /// The selected submitter is a locator. Only the current caller's device permission grants access.
    pub async fn issuance_recovery_operation(
        &self,
        request: &rss_mdm_authorization_service::context::RequestAuth,
        id: Uuid,
        operation: Uuid,
        identity: &ReceiptIdentity,
    ) -> Result<Option<wire::Candidate>, Error> {
        let p = request.proof.as_ref();
        let profile = self.profile();

        self.query_tenant(p)?;
        identity.validate()?;
        let mut tx = self.store.snapshot(p.tenant_id()).await?;
        let device = issuance_device(profile, &mut tx, p.tenant_id(), id).await?;
        let before = authorize(profile, &mut tx, p, &device)
            .await
            .map_err(conceal)?;
        let row = sqlx::query(
            crate::storage_profile::sql(profile).agent_queries_issuance_recovery_operation_1,
        )
        .bind(p.tenant_id())
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
        let grant = sqlx::query(
            crate::storage_profile::sql(profile).agent_queries_issuance_recovery_operation_2,
        )
        .bind(p.tenant_id())
        .bind(row.try_get::<Uuid, _>("grant_id").map_err(db)?)
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
        let record = sqlx::query(
            crate::storage_profile::sql(profile).agent_queries_issuance_recovery_operation_3,
        )
        .bind(p.tenant_id())
        .bind(&identity.actor)
        .bind(operation)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
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
            if digest(&("certificate_issuance_recovery", id, chain))?
                != record.try_get::<String, _>("digest").map_err(db)?
            {
                return Err(Error::Corrupt);
            }
            Some(value)
        } else {
            None
        };
        tx.rollback().await.map_err(db)?;
        self.store.confirm_query(request, &before).await?;
        Ok(value)
    }
}

/// Query retained recovery provenance without requiring a live issuer or recovery writer.
pub async fn registration_recovery_operation(
    store: &crate::database::Store,
    request: &rss_mdm_authorization_service::context::RequestAuth,
    device_id: &str,
    operation: Uuid,
    identity: &ReceiptIdentity,
) -> Result<Option<wire::GrantReceipt>, Error> {
    let p = request.proof.as_ref();
    let profile = store.profile();

    p.check_live()?;
    if p.profile() != profile {
        return Err(Error::Forbidden);
    }
    identity.validate()?;
    let mut tx = store.snapshot(p.tenant_id()).await?;
    let device: String = sqlx::query_scalar(
        crate::storage_profile::sql(profile).agent_queries_registration_recovery_operation_1,
    )
    .bind(p.tenant_id())
    .bind(device_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db)?
    .ok_or(Error::NotFound)?;
    let before = authorize(profile, &mut tx, p, &device)
        .await
        .map_err(conceal)?;
    let row = sqlx::query(
        crate::storage_profile::sql(profile).agent_queries_registration_recovery_operation_2,
    )
    .bind(p.tenant_id())
    .bind(operation)
    .bind(device_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db)?;
    let value = if let Some(row) = row {
        if row.try_get::<String, _>("actor").map_err(db)? != identity.actor
            || row.try_get::<String, _>("instance").map_err(db)? != identity.instance
            || row.try_get::<String, _>("device").map_err(db)? != device_id
        {
            return Err(Error::Conflict);
        }
        Some(receipt(&row)?)
    } else {
        None
    };
    tx.rollback().await.map_err(db)?;
    store.confirm_query(request, &before).await?;
    Ok(value)
}

pub static REQUEST_BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> =
    std::sync::LazyLock::new(|| {
        rss_mdm_query_postgres::Bindings::new(
            &REQUESTS,
            &[
                rss_mdm_query_postgres::Source::json("id", "row#>'{id}'"),
                rss_mdm_query_postgres::Source::json("device", "row#>'{device}'"),
                rss_mdm_query_postgres::Source::json("source", "row#>'{source}'"),
                rss_mdm_query_postgres::Source::json("state", "row#>'{state}'"),
                rss_mdm_query_postgres::Source::json("operationId", "row#>'{operationId}'"),
                rss_mdm_query_postgres::Source::json("actor", "row#>'{actor}'"),
                rss_mdm_query_postgres::Source::json("instance", "row#>'{instance}'"),
                rss_mdm_query_postgres::Source::json("createdAt", "row#>'{createdAt}'"),
                rss_mdm_query_postgres::Source::json("expiresAt", "row#>'{expiresAt}'"),
                rss_mdm_query_postgres::Source::json(
                    "registrationState",
                    "row#>'{registrationState}'",
                ),
                rss_mdm_query_postgres::Source::json("predecessor", "row#>'{predecessor}'"),
                rss_mdm_query_postgres::Source::json("issuance", "row#>'{issuance}'"),
                rss_mdm_query_postgres::Source::json("issuanceState", "row#>'{issuanceState}'"),
                rss_mdm_query_postgres::Source::json(
                    "issuanceOperation",
                    "row#>'{issuanceOperation}'",
                ),
                rss_mdm_query_postgres::Source::json("issuer", "row#>'{issuer}'"),
                rss_mdm_query_postgres::Source::json("notBefore", "row#>'{notBefore}'"),
                rss_mdm_query_postgres::Source::json("notAfter", "row#>'{notAfter}'"),
                rss_mdm_query_postgres::Source::json(
                    "activationOperation",
                    "row#>'{activationOperation}'",
                ),
                rss_mdm_query_postgres::Source::json("activated", "row#>'{activated}'"),
                rss_mdm_query_postgres::Source::json("requirements", "row#>'{requirements}'"),
            ],
        )
        .expect("Complete public model storage binding")
    });

pub static OPERATION_BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> =
    std::sync::LazyLock::new(|| {
        rss_mdm_query_postgres::Bindings::new(
            &OPERATIONS,
            &[
                rss_mdm_query_postgres::Source::required_column("actor", "actor COLLATE \"C\""),
                rss_mdm_query_postgres::Source::required_column(
                    "operationId",
                    "operation_id::text COLLATE \"C\"",
                ),
                rss_mdm_query_postgres::Source::column("instance", "instance COLLATE \"C\""),
            ],
        )
        .expect("Complete public model storage binding")
    });
