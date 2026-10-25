//! Installation tenant HTTP adapter; CLI and HTTP share the registry mutation owner.
use super::*;
use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::HeaderMap,
};
use rss_mdm_audit_integration::{AuditStore, Fact, RequestAudit, budget::AuditBudget};
use rss_mdm_authorization_service::{
    Permission,
    context::{AuthorizedPrincipal, RequestAuth},
};
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{
    Router,
    routing::{get, post},
};
use rss_request_context::TenantId;
use serde::Deserialize;
use sqlx::PgPool;
use std::{path::PathBuf, sync::Arc};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub registry_database: config::Database,
    pub provisioning_database: config::Database,
    pub fingerprint_key_file: PathBuf,
}
pub(crate) struct Service {
    pool: PgPool,
    source_runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    audit: AuditStore,
    config: Config,
    installation: Installation,
    management: TenantId,
    kdf: Arc<rss_identity_core::account::PasswordKdf>,
    policy: Arc<rss_mdm_authorization_service::identity_management::IdentityManagementPolicy>,
    fingerprint: ring::hmac::Key,
}
impl Service {
    pub(crate) async fn connect(
        config: &crate::config::Config,
        management: TenantId,
        kdf: Arc<rss_identity_core::account::PasswordKdf>,
        policy: Arc<rss_mdm_authorization_service::identity_management::IdentityManagementPolicy>,
    ) -> std::result::Result<Option<Arc<Self>>, Error> {
        let Some(options) = &config.tenant_administration else {
            return Ok(None);
        };
        let invalid = |stage| {
            eprintln!("tenant administration admission rejected: {stage}");
            Error::Configuration(ConfigIssue::IdentityConfiguration)
        };
        if options.registry_database.user != "mdm_tenant_registry"
            || options.provisioning_database.user != "mdm_identity_provisioning"
        {
            return Err(invalid("configuration"));
        }
        let key = config::read(&options.fingerprint_key_file, 128, true)?;
        if key.len() != 32 {
            return Err(invalid("configuration"));
        }
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(3))
            .connect_with(options.registry_database.options()?)
            .await
            .map_err(|_| invalid("registry connection"))?;
        let installation = Installation {
            instance_id: config.identity.instance_id.clone(),
            target: config.flow.storage.target,
            lineage: config.flow.storage.lineage,
            audit_mode: config.audit.mode(),
        };
        let source_runtime = match crate::identity::open_runtime(
            &options.registry_database,
            &installation.target,
            &installation.lineage,
            &[(
                management,
                rss_mdm_authorization_service::tenancy::MANAGEMENT_EPOCH,
            )],
        )
        .await
        {
            Ok(runtime) => runtime,
            Err(error) => {
                pool.close().await;
                return Err(error);
            }
        };
        let service = async {
            let mut connection = pool.acquire().await.map_err(|_| invalid("registry acquire"))?;
            migration::verify_current_manifest(&mut connection).await.map_err(|_| invalid("manifest"))?;
            migration::verify_identity(&mut connection, &installation).await.map_err(|_| invalid("installation"))?;
            let safe: bool = sqlx::query_scalar("SELECT current_user=session_user AND current_user='mdm_tenant_registry' AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=pg_roles.oid) AND has_function_privilege(current_user,'public.create_new_tenant(uuid,bigint,text,text)','EXECUTE') AND (SELECT count(*)=2 AND bool_and(NOT has_function_privilege(current_user,p.oid,'EXECUTE')) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE (n.nspname,p.proname) IN (('mdm','seed_tenant_catalog'),('mdm_access','seed_tenant_settings'))) FROM pg_roles WHERE rolname=current_user")
                .fetch_one(&mut *connection).await.map_err(|_| invalid("role query"))?;
            if !safe { return Err(invalid("registry role")); }
            let bounded: bool = sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND c.relkind IN ('r','p','v','m','f') AND n.nspname||'.'||c.relname NOT IN ('public.mdm_tenants','public.mdm_tenant_operations','mdm_audit.receipts','mdm_audit.backlog') AND (has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES')))")
                .fetch_one(&mut *connection).await.map_err(|_| invalid("capabilities query"))?;
            let body = include_str!("../schema/tenant-administration.sql").split("$create$").nth(1).expect("create function body");
            let exact: bool = sqlx::query_scalar("SELECT count(*)=1 AND coalesce(bool_and(p.prosecdef AND p.proowner='mdm_owner'::regrole AND p.prosrc=$1 AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp'] AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 OR a.is_grantable OR pg_get_userbyid(a.grantee) NOT IN ('mdm_owner','mdm_tenant_registry'))),false) FROM pg_proc p WHERE p.oid='public.create_new_tenant(uuid,bigint,text,text)'::regprocedure")
                .bind(body).fetch_one(&mut *connection).await.map_err(|_| invalid("creation function query"))?;
            if !bounded || !exact { return Err(invalid("registry capabilities")); }
            drop(connection);
            let budget = AuditBudget::new(Duration::from_secs(5));
            let audit = AuditStore::new(pool.clone(), config.audit.integrity()?, source_runtime.clone(), management, config.audit_projection.limits()?, &budget.control()).await.map_err(|_| invalid("audit"))?;
            let this = Self { pool: pool.clone(), source_runtime: source_runtime.clone(), audit, config: options.clone(), installation, management, kdf, policy,
                fingerprint: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key) };
            let target = TenantId::parse(&config.identity.tenant_id).map_err(|_| invalid("configuration"))?;
            let (runtime, _, _) = this.provisioner(target, config.flow.storage.epoch).await?;
            runtime.close().await;
            Ok(Arc::new(this))
        }.await;
        if service.is_err() {
            source_runtime.close().await;
            pool.close().await;
        }
        service.map(Some)
    }
    async fn authorize(
        &self,
        c: &mut PgConnection,
        proof: &AuthorizedPrincipal,
        permission: Permission,
    ) -> Result<()> {
        if proof.tenant_id() != self.management.to_string()
            || proof.instance_id() != self.installation.instance_id
        {
            return Err(Reason::Forbidden);
        }
        scope(c, proof.tenant_id()).await?;
        rss_mdm_authorization_service::lock_on(c, proof.tenant_id(), proof.instance_id())
            .await
            .map_err(|_| Reason::Storage)?;
        let rules =
            rss_mdm_authorization_service::snapshot_on(c, proof.tenant_id(), proof.instance_id())
                .await
                .map_err(|_| Reason::Storage)?;
        rules
            .require(proof, permission, None)
            .map_err(|_| Reason::Forbidden)?;
        Ok(())
    }
    async fn read(
        &self,
        proof: &AuthorizedPrincipal,
        query: Read,
    ) -> std::result::Result<serde_json::Value, Error> {
        proof.require(Permission::TenantRead, None)?;
        self.registry_read((self, proof, query), |(service, proof, query), c| Box::pin(async move {
            sqlx::query("SELECT pg_advisory_xact_lock(2346)").execute(&mut *c).await.map_err(|_| Reason::Storage)?;
            service.authorize(c, proof, Permission::TenantRead).await?;
            match query {
                Read::Tenant(tenant) => {
                    validate_tenant(&service.installation, tenant)?;
                    serde_json::to_value(tenant_on(c, tenant, false).await?).map_err(|_| Reason::Storage)
                }
                Read::Operation(operation) => {
                    if operation.is_nil() { return Err(Reason::Invalid); }
                    let receipt = receipt_on(c, *operation).await?.ok_or(Reason::NotFound)?.0;
                    serde_json::to_value(receipt).map_err(|_| Reason::Storage)
                }
                Read::Provisionings(page) => provisionings_on(c, page).await,
                Read::Hosts => {
                    let items:Vec<serde_json::Value>=sqlx::query_scalar("SELECT o.receipt FROM public.mdm_tenant_operations o JOIN public.mdm_tenants t USING(tenant_id) WHERE o.action='provision' AND NOT t.deleted ORDER BY o.operation_id").fetch_all(&mut *c).await.map_err(|_|Reason::Storage)?;
                    Ok(serde_json::json!({"items":items}))
                }
                Read::List => {
                    let ids: Vec<String> = sqlx::query_scalar("SELECT tenant_id::text FROM public.mdm_tenants WHERE NOT deleted ORDER BY tenant_id")
                        .fetch_all(&mut *c).await.map_err(|_| Reason::Storage)?;
                    let mut items = Vec::new();
                    for id in ids { items.push(tenant_on(c, &id, false).await?); }
                    Ok(serde_json::json!({"items":items}))
                }
            }
        })).await
    }
    pub(crate) async fn directory(
        &self,
        proof: &AuthorizedPrincipal,
        hosts: bool,
    ) -> std::result::Result<serde_json::Value, Error> {
        self.read(proof, if hosts { Read::Hosts } else { Read::List })
            .await
    }
    async fn registry_read<C: Send, T: Send>(
        &self,
        mut context: C,
        operation: impl for<'a> FnOnce(
            &'a mut C,
            &'a mut PgConnection,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<T>> + Send + 'a>,
        >,
    ) -> std::result::Result<T, Error> {
        // Keep cancellation safe even when the entire caller future is dropped.
        struct ReadConnection {
            inner: sqlx::pool::PoolConnection<sqlx::Postgres>,
            settled: bool,
        }
        impl Drop for ReadConnection {
            fn drop(&mut self) {
                if !self.settled {
                    self.inner.close_on_drop();
                }
            }
        }
        let mut connection = None;
        let outcome = tokio::time::timeout(Duration::from_secs(6), async {
            connection = Some(ReadConnection {
                inner: self
                    .pool
                    .acquire()
                    .await
                    .map_err(|_| project(Reason::Storage))?,
                settled: false,
            });
            let mut tx = connection
                .as_mut()
                .expect("acquired connection")
                .inner
                .begin()
                .await
                .map_err(|_| project(Reason::Storage))?;
            sqlx::raw_sql("SET LOCAL statement_timeout='6s'; SET LOCAL lock_timeout='6s'")
                .execute(&mut *tx)
                .await
                .map_err(|_| project(Reason::Storage))?;
            let result = operation(&mut context, &mut tx).await;
            tx.rollback().await.map_err(|_| Error::RollbackFailed)?;
            connection.as_mut().expect("acquired connection").settled = true;
            result.map_err(project)
        })
        .await;
        outcome.unwrap_or(Err(Error::RollbackFailed))
    }
    async fn mutate(
        &self,
        proof: &AuthorizedPrincipal,
        audit: &RequestAudit,
        input: Mutation<'_>,
    ) -> std::result::Result<Receipt, Error> {
        validate(&input).map_err(project)?;
        let permission = match input.action {
            Action::Create => Permission::TenantCreate,
            Action::Update => Permission::TenantUpdate,
            Action::Delete => Permission::TenantDelete,
            Action::AdministratorCreate | Action::Provision => return Err(Error::Malformed),
        };
        proof.require(permission, None)?;
        audit.operation(
            input.operation_id,
            "tenant_registry_write",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.target(input.tenant_id);
        audit.require_final_request();
        let fingerprint = serde_json::to_vec(&request(&input)).map_err(|_| Error::Malformed)?;
        let fact = Fact::business(
            audit,
            &format!("tenant-registry:{}", input.operation_id),
            &fingerprint,
            200,
            "success",
            None,
        )
        .map_err(|_| Error::Malformed)?;
        let budget = AuditBudget::new(Duration::from_secs(6));
        let outcome = self.audit.write(self.management, &budget.source_control(), (self, proof, audit, input, fact), move |(service, proof, audit, input, fact), tx| Box::pin(async move {
            let mut context = (&**service, *proof, &*input);
            let result = tx.with_connection_context(&mut context, |(service, proof, input), c| Box::pin(async move { async {
                sqlx::query("SELECT pg_advisory_xact_lock(2346)").execute(&mut *c).await.map_err(|_| Reason::Storage)?;
                service.authorize(c, proof, permission).await?;
                let actor = serde_json::json!({"kind":"session","tenantId":proof.tenant_id(),"instanceId":proof.instance_id(),"principalId":proof.principal_id()});
                sqlx::query("SELECT set_config('mdm.operator',$1,true)").bind(actor.to_string()).execute(&mut *c).await.map_err(|_| Reason::Storage)?;
                let result = apply_on(c, input).await?;
                scope(c, proof.tenant_id()).await?;
                Ok::<_, Reason>(result)
            }.await.map_err(project) })).await?;
            let receipt = match result {
                Outcome::Replay(receipt) => { audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed); receipt }
                Outcome::Changed(receipt) => { service.audit.append(tx, fact, false).await?; receipt }
            };
            audit.mark_commit_started();
            Ok::<_, Error>(receipt)
        })).await;
        outcome.fold(
            |value| {
                audit.mark_committed();
                Ok(value)
            },
            |error| Err(tx_error(error)),
            |error| {
                audit.mark_rolled_back();
                Err(tx_error(error))
            },
            |_| {
                audit.mark_rollback_failed();
                Err(Error::RollbackFailed)
            },
            |_| Err(Error::CommitUnknown),
            |error| Err(tx_error(error)),
        )
    }
}
fn tx_error(error: rss_mdm_audit_integration::TransactionError<Error>) -> Error {
    match error {
        rss_mdm_audit_integration::TransactionError::Operation(error) => error,
        rss_mdm_audit_integration::TransactionError::Storage(error) => error.into(),
        rss_mdm_audit_integration::TransactionError::Rollback { .. } => Error::RollbackFailed,
    }
}
fn project(reason: Reason) -> Error {
    match reason {
        Reason::Invalid => Error::Malformed,
        Reason::Forbidden | Reason::Reserved | Reason::Binding => Error::Forbidden,
        Reason::NotFound => Error::Http(rss_mdm_management_http::Error::NotFound),
        Reason::Conflict | Reason::InUse | Reason::Capacity => Error::Conflict,
        Reason::CommitUnknown | Reason::Deadline => Error::CommitUnknown,
        Reason::Cleanup => Error::RollbackFailed,
        Reason::Storage => Error::Unavailable(Failure::Database),
    }
}
pub(crate) struct Resource(pub Arc<Service>);
impl rss_runtime::ManagedResource for Resource {
    fn name(&self) -> &str {
        "tenant-administration"
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
    async fn shutdown(&self) -> std::result::Result<(), rss_runtime::ShutdownError> {
        self.0.source_runtime.close().await;
        self.0.pool.close().await;
        Ok(())
    }
}
enum Read {
    List,
    Hosts,
    Provisionings(ProvisioningPage),
    Tenant(String),
    Operation(Uuid),
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpdateBody {
    expected_revision: i64,
    name: Option<String>,
    notes: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeleteBody {
    expected_revision: i64,
}
fn operation(headers: &HeaderMap) -> std::result::Result<Uuid, Error> {
    let mut values = headers.get_all("Idempotency-Key").iter();
    let text = values
        .next()
        .ok_or(Error::Malformed)?
        .to_str()
        .map_err(|_| Error::Malformed)?;
    let id = Uuid::parse_str(text).map_err(|_| Error::Malformed)?;
    if values.next().is_some() || id.is_nil() || id.to_string() != text {
        return Err(Error::Malformed);
    }
    Ok(id)
}
pub(crate) fn routes(service: Option<Arc<Service>>) -> Router {
    let Some(service) = service else {
        return Router::new();
    };
    Router::new()
        .route(
            "/tenants",
            get(list).owned(&contracts::TENANTS, &[RouteOperation::List]),
        )
        .route(
            "/provisionings",
            get(provisionings)
                .owned(&contracts::PROVISIONINGS, &[RouteOperation::List])
                .post(provisioning::create)
                .owned(&contracts::TENANTS, &[RouteOperation::Create]),
        )
        .route(
            "/provisionings/{operation}",
            get(receipt).owned(&contracts::PROVISIONINGS, &[RouteOperation::Get]),
        )
        .route(
            "/tenants/{tenant}",
            get(detail)
                .owned(&contracts::TENANTS, &[RouteOperation::Get])
                .put(update)
                .owned(&contracts::TENANTS, &[RouteOperation::Update])
                .delete(delete)
                .owned(&contracts::TENANTS, &[RouteOperation::Delete]),
        )
        .route(
            "/tenants/{tenant}/administrators",
            post(administrator).owned(&contracts::TENANTS, &[RouteOperation::Action]),
        )
        .route(
            "/operations/{operation}",
            get(receipt).owned(&contracts::PROVISIONINGS, &[RouteOperation::Get]),
        )
        .with_state(service)
}
async fn list(
    State(service): State<Arc<Service>>,
    Extension(auth): Extension<RequestAuth>,
) -> std::result::Result<Json<serde_json::Value>, HttpFailure> {
    service
        .read(&auth.proof, Read::List)
        .await
        .map(Json)
        .map_err(HttpFailure)
}
async fn provisionings(
    State(service): State<Arc<Service>>,
    Extension(auth): Extension<RequestAuth>,
    query: std::result::Result<Query<ProvisioningPage>, axum::extract::rejection::QueryRejection>,
) -> std::result::Result<Json<serde_json::Value>, HttpFailure> {
    let Query(page) = query.map_err(|_| HttpFailure(Error::Malformed))?;
    if page.after.is_some_and(|id| id.is_nil()) || !(1..=1000).contains(&page.limit) {
        return Err(HttpFailure(Error::Malformed));
    }
    service
        .read(&auth.proof, Read::Provisionings(page))
        .await
        .map(Json)
        .map_err(HttpFailure)
}
async fn detail(
    State(service): State<Arc<Service>>,
    Extension(auth): Extension<RequestAuth>,
    Path(tenant): Path<String>,
) -> std::result::Result<Json<serde_json::Value>, HttpFailure> {
    service
        .read(&auth.proof, Read::Tenant(tenant))
        .await
        .map(Json)
        .map_err(HttpFailure)
}
async fn receipt(
    State(service): State<Arc<Service>>,
    Extension(auth): Extension<RequestAuth>,
    path: std::result::Result<Path<Uuid>, axum::extract::rejection::PathRejection>,
) -> std::result::Result<Json<serde_json::Value>, HttpFailure> {
    service
        .read(
            &auth.proof,
            Read::Operation(path.map_err(|_| HttpFailure(Error::Malformed))?.0),
        )
        .await
        .map(Json)
        .map_err(HttpFailure)
}
async fn update(
    State(service): State<Arc<Service>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    body: std::result::Result<Json<UpdateBody>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<Json<Receipt>, HttpFailure> {
    let Json(body) = body.map_err(|e| HttpFailure(Error::Http(e.into())))?;
    service
        .mutate(
            &auth.proof,
            &audit,
            Mutation {
                installation: &service.installation,
                tenant_id: &tenant,
                operation_id: operation(&headers)?,
                action: Action::Update,
                initial_epoch: None,
                expected_revision: Some(body.expected_revision),
                name: body.name.as_deref(),
                notes: body.notes.as_deref(),
            },
        )
        .await
        .map(Json)
        .map_err(HttpFailure)
}
async fn delete(
    State(service): State<Arc<Service>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    body: std::result::Result<Json<DeleteBody>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<Json<Receipt>, HttpFailure> {
    let Json(body) = body.map_err(|e| HttpFailure(Error::Http(e.into())))?;
    service
        .mutate(
            &auth.proof,
            &audit,
            Mutation {
                installation: &service.installation,
                tenant_id: &tenant,
                operation_id: operation(&headers)?,
                action: Action::Delete,
                initial_epoch: None,
                expected_revision: Some(body.expected_revision),
                name: None,
                notes: None,
            },
        )
        .await
        .map(Json)
        .map_err(HttpFailure)
}
#[path = "tenant_provisioning.rs"]
mod provisioning;

#[path = "tenant_administrator.rs"]
mod administrator;
use administrator::administrator;

#[derive(Debug)]
pub(super) struct HttpFailure(Error);
impl From<Error> for HttpFailure {
    fn from(error: Error) -> Self {
        Self(error)
    }
}
impl axum::response::IntoResponse for HttpFailure {
    fn into_response(self) -> axum::response::Response {
        use rss_mdm_management_http::Error as Http;
        let error = match self.0 {
            Error::Http(error) => error,
            Error::Malformed => Http::Malformed,
            Error::Unauthorized => Http::Unauthorized,
            Error::Forbidden => Http::Forbidden,
            Error::Conflict => Http::Conflict,
            Error::CommitUnknown => Http::CommitUnknown,
            Error::RollbackFailed => Http::RollbackFailed,
            Error::Authorization(error) => error.into(),
            Error::Unavailable(reason) => {
                use rss_mdm_management_http::Failure as F;
                Http::Unavailable(match reason {
                    Failure::RequestDeadline => F::RequestDeadline,
                    Failure::Audit => F::Audit,
                    Failure::AuditIntegrity => F::AuditIntegrity,
                    Failure::AuditIsolation => F::AuditIsolation,
                    Failure::AuditAdmission => F::AuditAdmission,
                    Failure::AuditContract => F::AuditContract,
                    Failure::AuditBackpressure => F::AuditBackpressure,
                    Failure::AuditReserveExhausted => F::AuditReserveExhausted,
                    _ => F::Database,
                })
            }
            _ => Http::Unavailable(rss_mdm_management_http::Failure::Database),
        };
        error.into_response()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProvisioningPage {
    after: Option<Uuid>,
    #[serde(default = "provisioning_page_limit")]
    limit: u16,
}
fn provisioning_page_limit() -> u16 {
    100
}
async fn provisionings_on(
    c: &mut sqlx::PgConnection,
    page: &ProvisioningPage,
) -> std::result::Result<serde_json::Value, Reason> {
    let mut rows: Vec<(Uuid, serde_json::Value)> = sqlx::query_as("SELECT operation_id,receipt FROM public.mdm_tenant_operations WHERE action='provision' AND ($1::uuid IS NULL OR operation_id>$1) ORDER BY operation_id LIMIT $2")
        .bind(page.after).bind(i64::from(page.limit)+1).fetch_all(c).await.map_err(|_| Reason::Storage)?;
    let more = rows.len() > usize::from(page.limit);
    rows.truncate(usize::from(page.limit));
    let next = if more {
        rows.last().map(|(id, _)| *id)
    } else {
        None
    };
    Ok(
        serde_json::json!({"items":rows.into_iter().map(|(_,receipt)|receipt).collect::<Vec<_>>(),"nextAfter":next}),
    )
}
