use super::*;
use crate::database::db;
use axum::{
    Extension, Json,
    extract::{Path, State},
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
) -> Result<Json<serde_json::Value>, Error> {
    directory(&app, &auth.proof).await.map(Json)
}
pub async fn directory(
    app: &HttpState,
    proof: &AuthorizedPrincipal,
) -> Result<serde_json::Value, Error> {
    proof.manage(Permission::RegistrationConfigurationRead)?;
    let mut tx = app.access.begin_read(proof.tenant_id()).await?;
    let rows = sqlx::query(
        "SELECT id FROM mdm_apple.organizations WHERE tenant_id=$1::uuid ORDER BY id LIMIT 1001",
    )
    .bind(proof.tenant_id())
    .fetch_all(&mut *tx)
    .await
    .map_err(db)?;
    if rows.len() > 1000 {
        return Err(Error::Unavailable(Failure::Capacity));
    }
    let mut organizations = Vec::new();
    for row in rows {
        let id: Uuid = row.try_get("id").map_err(db)?;
        let ade = sqlx::query(
            "SELECT * FROM mdm_apple.ade_servers WHERE tenant_id=$1::uuid AND organization=$2",
        )
        .bind(proof.tenant_id())
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
        let ade = ade
            .as_ref()
            .map(|r| crate::ade::management::status_row(r, crate::ade::now(app)?))
            .transpose()?;
        let Some(row) = sqlx::query(
            "SELECT * FROM mdm_apple.account_configuration WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(proof.tenant_id())
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?
        else {
            organizations.push(serde_json::json!({"id":id,"accountEnrollment":null,"ade":ade}));
            continue;
        };
        let key: String = row.try_get("signing_key").map_err(db)?;
        let accounts=sqlx::query("SELECT account,principal,instance,revision,enabled FROM mdm_apple.account_bindings WHERE tenant_id=$1::uuid AND organization=$2 ORDER BY account LIMIT 1001").bind(proof.tenant_id()).bind(id).fetch_all(&mut *tx).await.map_err(db)?;
        if accounts.len() > 1000 {
            return Err(Error::Unavailable(Failure::Capacity));
        }
        let accounts=accounts.into_iter().map(|r|Ok(serde_json::json!({"account":r.try_get::<String,_>("account").map_err(db)?,"principalId":r.try_get::<Uuid,_>("principal").map_err(db)?,"instanceId":r.try_get::<Uuid,_>("instance").map_err(db)?,"revision":r.try_get::<i64,_>("revision").map_err(db)?,"enabled":r.try_get::<bool,_>("enabled").map_err(db)?}))).collect::<Result<Vec<_>,Error>>()?;
        let configured = app
            .apple()
            .ok()
            .and_then(|apple| apple.account_keys.get(&key))
            .is_some_and(|s| {
                app.clock
                    .unix_seconds()
                    .is_some_and(|now| s.expires() > now as u64)
            });
        organizations.push(serde_json::json!({"id":id,"ade":ade,"accountEnrollment":{"domain":row.try_get::<String,_>("domain").map_err(db)?,"serverUuid":row.try_get::<Uuid,_>("server_uuid").map_err(db)?,"signingKey":key,"enabled":row.try_get::<bool,_>("enabled").map_err(db)?,"revision":row.try_get::<i64,_>("revision").map_err(db)?,"signingKeyConfigured":configured,"accounts":accounts,"externalOrganizationVerification":"not_observed"}}));
    }
    proof.check_live()?;
    Ok(serde_json::json!({"items":organizations}))
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
    audit.operation(operation, "apple_account_configuration");
    let fingerprint = rss_mdm_registration_service::enrollment::digest(&(id, &input));
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(2));
    let control = budget.control();
    let outcome = app
        .audit_store
        .write(
            app.identity.tenant(),
            &control,
            (app, proof, audit, id, operation, &input, &fingerprint),
            |(app, proof, audit, id, operation, input, fingerprint), tx| {
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
                        fingerprint.as_bytes(),
                        200,
                        "success",
                        Some(*id),
                    )
                    .map_err(Error::from)?;
                    app.audit_store
                        .append(tx, &fact, replayed)
                        .await
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
