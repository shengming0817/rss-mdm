use super::*;
use crate::database::db;
use axum::{
    Extension, Json,
    extract::{Path, RawQuery, State},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::Permission;
use rss_mdm_authorization_service::context::RequestAuth;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrganizationChange {
    expected_revision: i64,
    domain: String,
    server_uuid: Uuid,
    signing_key: String,
    enabled: bool,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountChange {
    expected_revision: i64,
    principal_id: Uuid,
    instance_id: Uuid,
    enabled: bool,
}
pub(crate) fn operation(headers: &HeaderMap) -> Result<Uuid, Error> {
    if headers.get_all("idempotency-key").iter().count() != 1 {
        return Err(Error::Malformed);
    }
    let id = Uuid::parse_str(
        headers
            .get("idempotency-key")
            .and_then(|v| v.to_str().ok())
            .ok_or(Error::Malformed)?,
    )
    .map_err(|_| Error::Malformed)?;
    if id.is_nil() {
        return Err(Error::Malformed);
    }
    Ok(id)
}
pub(super) async fn list(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    RawQuery(raw): RawQuery,
) -> Result<Json<serde_json::Value>, Error> {
    crate::management_query::page(
        &app,
        &auth.proof,
        crate::management_query::Collection::Organizations,
        raw.as_deref().unwrap_or(""),
    )
    .await
    .map(Json)
}
pub(super) async fn accounts(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Path(id): Path<Uuid>,
    RawQuery(raw): RawQuery,
) -> Result<Json<serde_json::Value>, Error> {
    crate::management_query::page(
        &app,
        &auth.proof,
        crate::management_query::Collection::Accounts(id),
        raw.as_deref().unwrap_or(""),
    )
    .await
    .map(Json)
}
pub(super) async fn organization_detail(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, Error> {
    crate::management_query::detail(&app, &auth.proof, id, None)
        .await
        .map(Json)
}
pub(super) async fn account_detail(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Path((id, account)): Path<(Uuid, String)>,
) -> Result<Json<serde_json::Value>, Error> {
    crate::management_query::detail(&app, &auth.proof, id, Some(&account_name(&account)?))
        .await
        .map(Json)
}
pub(super) async fn organization(
    State(app): State<Arc<HttpState>>,
    Path(id): Path<Uuid>,
    Extension(auth): Extension<RequestAuth>,
    headers: HeaderMap,
    Extension(audit): Extension<RequestAudit>,
    Json(mut input): Json<OrganizationChange>,
) -> Result<Json<serde_json::Value>, Error> {
    input.domain = domain(&input.domain)?;
    if id.is_nil()
        || input.server_uuid.is_nil()
        || input.expected_revision < 0
        || input.expected_revision == i64::MAX
    {
        return Err(Error::Malformed);
    }
    if input.enabled
        && !app
            .apple()?
            .account_keys
            .get(&input.signing_key)
            .is_some_and(|s| {
                app.clock
                    .unix_seconds()
                    .is_some_and(|now| s.expires() > now as u64)
            })
    {
        return Err(Error::Conflict);
    }
    change(
        &app,
        &auth.proof,
        &headers,
        &audit,
        id,
        Change::Organization(input),
    )
    .await
    .map(Json)
}
pub(super) async fn account(
    State(app): State<Arc<HttpState>>,
    Path((id, account)): Path<(Uuid, String)>,
    Extension(auth): Extension<RequestAuth>,
    headers: HeaderMap,
    Extension(audit): Extension<RequestAudit>,
    Json(input): Json<AccountChange>,
) -> Result<Json<serde_json::Value>, Error> {
    let name = account_name(&account)?;
    if input.principal_id.is_nil()
        || input.instance_id.is_nil()
        || input.expected_revision < 0
        || input.expected_revision == i64::MAX
    {
        return Err(Error::Malformed);
    }
    change(
        &app,
        &auth.proof,
        &headers,
        &audit,
        id,
        Change::Account(name, input),
    )
    .await
    .map(Json)
}
#[derive(Serialize)]
enum Change {
    Organization(OrganizationChange),
    Account(String, AccountChange),
}
async fn change(
    app: &HttpState,
    proof: &AuthorizedPrincipal,
    headers: &HeaderMap,
    audit: &RequestAudit,
    id: Uuid,
    input: Change,
) -> Result<serde_json::Value, Error> {
    proof.manage(Permission::RegistrationConfigurationWrite)?;
    proof.bind_audit(audit)?;
    let operation = operation(headers)?;
    audit.operation(
        operation,
        "apple_account_configuration",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(2));
    let outcome = app
        .audit_store
        .write(
            app.identity.tenant(),
            &budget.source_control(),
            (app, proof, audit, id, operation, &input),
            |(app, proof, audit, id, operation, input), tx| {
                Box::pin(async move {
                    let (value, replayed) = tx
                        .with_connection_context(
                            &mut (proof, *id, *operation, input),
                            |(proof, id, operation, input), c| {
                                Box::pin(change_on(c, proof, *id, *operation, input))
                            },
                        )
                        .await?;
                    let fact = rss_mdm_audit_integration::Fact::business(
                        audit,
                        &format!("apple-account-configuration:{id}:{operation}"),
                        200,
                        "success",
                        Some(*id),
                    )
                    .map_err(Error::from)?;
                    (if replayed {
                        Ok(())
                    } else {
                        app.audit_store.append(tx, &fact).await
                    })
                    .map_err(Error::from)?;
                    if replayed {
                        audit.management_result(
                            rss_mdm_audit_integration::ManagementResult::Replayed,
                        )
                    }
                    audit.mark_commit_started();
                    Ok(value)
                })
            },
        )
        .await;
    crate::operations::settle(outcome, audit)
}
async fn change_on(
    c: &mut sqlx::PgConnection,
    p: &AuthorizedPrincipal,
    id: Uuid,
    operation: Uuid,
    input: &Change,
) -> Result<(serde_json::Value, bool), Error> {
    p.manage(Permission::RegistrationConfigurationWrite)?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2672))")
        .bind(format!("apple-organization:{}:{id}", p.tenant_id()))
        .execute(&mut *c)
        .await
        .map_err(db)?;
    let (revision, replayed) = match input {
        Change::Organization(v) => {
            crate::organizations::ensure_in(c, p.tenant_id(), id).await?;
            let old=sqlx::query("SELECT * FROM mdm_apple.account_configuration WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE").bind(p.tenant_id()).bind(id).fetch_optional(&mut *c).await.map_err(db)?;
            let replayed = old.as_ref().is_some_and(|r| {
                r.try_get::<i64, _>("revision").ok() == Some(v.expected_revision + 1)
                    && r.try_get::<Uuid, _>("operation").ok() == Some(operation)
                    && r.try_get::<String, _>("domain").ok().as_deref() == Some(&v.domain)
                    && r.try_get::<Uuid, _>("server_uuid").ok() == Some(v.server_uuid)
                    && r.try_get::<String, _>("signing_key").ok().as_deref() == Some(&v.signing_key)
                    && r.try_get::<bool, _>("enabled").ok() == Some(v.enabled)
            });
            if !replayed {
                let revision = old
                    .as_ref()
                    .map(|r| r.try_get::<i64, _>("revision").map_err(db))
                    .transpose()?
                    .unwrap_or(0);
                if revision != v.expected_revision {
                    return Err(Error::Conflict);
                }
                sqlx::query("INSERT INTO mdm_apple.account_configuration(tenant_id,id,domain,server_uuid,signing_key,enabled,revision,operation) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(tenant_id,id) DO UPDATE SET domain=excluded.domain,server_uuid=excluded.server_uuid,signing_key=excluded.signing_key,enabled=excluded.enabled,revision=excluded.revision,operation=excluded.operation")
                    .bind(p.tenant_id()).bind(id).bind(&v.domain).bind(v.server_uuid).bind(&v.signing_key).bind(v.enabled).bind(revision+1).bind(operation).execute(&mut *c).await.map_err(unique)?;
            }
            (v.expected_revision + 1, replayed)
        }
        Change::Account(name, v) => {
            if v.instance_id.to_string() != p.instance_id() {
                return Err(Error::Forbidden);
            }
            let host:String=sqlx::query_scalar("SELECT domain FROM mdm_apple.account_configuration WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE").bind(p.tenant_id()).bind(id).fetch_optional(&mut *c).await.map_err(db)?.ok_or(Error::NotFound)?;
            if name.rsplit_once('@').map(|(_, d)| d) != Some(host.as_str()) {
                return Err(Error::Malformed);
            }
            let old=sqlx::query("SELECT * FROM mdm_apple.account_bindings WHERE tenant_id=$1::uuid AND organization=$2 AND account=$3 FOR UPDATE").bind(p.tenant_id()).bind(id).bind(name).fetch_optional(&mut *c).await.map_err(db)?;
            let replayed = old.as_ref().is_some_and(|r| {
                r.try_get::<i64, _>("revision").ok() == Some(v.expected_revision + 1)
                    && r.try_get::<Uuid, _>("operation").ok() == Some(operation)
                    && r.try_get::<Uuid, _>("principal").ok() == Some(v.principal_id)
                    && r.try_get::<Uuid, _>("instance").ok() == Some(v.instance_id)
                    && r.try_get::<bool, _>("enabled").ok() == Some(v.enabled)
            });
            if !replayed {
                let revision = old
                    .as_ref()
                    .map(|r| r.try_get::<i64, _>("revision").map_err(db))
                    .transpose()?
                    .unwrap_or(0);
                if revision != v.expected_revision {
                    return Err(Error::Conflict);
                }
                sqlx::query("INSERT INTO mdm_apple.account_bindings(tenant_id,organization,account,principal,instance,enabled,revision,operation) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(tenant_id,organization,account) DO UPDATE SET principal=excluded.principal,instance=excluded.instance,enabled=excluded.enabled,revision=excluded.revision,operation=excluded.operation")
                    .bind(p.tenant_id()).bind(id).bind(name).bind(v.principal_id).bind(v.instance_id).bind(v.enabled).bind(revision+1).bind(operation).execute(&mut *c).await.map_err(unique)?;
            }
            (v.expected_revision + 1, replayed)
        }
    };
    p.check_live()?;
    Ok((serde_json::json!({"revision":revision}), replayed))
}
fn unique(e: sqlx::Error) -> Error {
    if e.as_database_error()
        .is_some_and(|e| e.is_unique_violation())
    {
        Error::Conflict
    } else {
        db(e)
    }
}
