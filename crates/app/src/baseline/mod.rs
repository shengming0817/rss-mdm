//! Once-only tenant baseline orchestration over the existing domain owners.
//! ref: sqlx sqlx-postgres/src/migrate.rs@v0.8.6 (stable intent and serialized recovery).
use crate::Error;
use rss_mdm_audit_integration::RequestAudit;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;
pub(crate) mod manifest;
use manifest::{Action, Manifest, Step};

/// Persist with the authenticated initialization/account transaction. Never replace old intent.
pub(crate) async fn reserve_on(
    c: &mut sqlx::PgConnection,
    authority: &rss_mdm_authorization_service::baseline::Authority,
) -> Result<bool, Error> {
    let tenant = Uuid::parse_str(&authority.user().tenant_id).map_err(|_| Error::Malformed)?;
    let manifest = manifest::build(tenant)?;
    let inserted=sqlx::query("INSERT INTO mdm_initialization.baselines(tenant_id,authority,manifest) VALUES($1,$2,$3) ON CONFLICT DO NOTHING")
        .bind(tenant).bind(serde_json::to_value(authority).map_err(|_|Error::Malformed)?).bind(serde_json::to_value(manifest).map_err(|_|Error::Malformed)?)
        .execute(c).await.map_err(|_|Error::Unavailable(crate::Failure::Database))?.rows_affected()==1;
    Ok(inserted)
}
/// Resume only existing initialization intent; serve never seeds an arbitrary or historical tenant.
pub(crate) async fn resume(state: &crate::api::Assembly) -> Result<(), Error> {
    let tenant = state.identity.tenant.to_string();
    let pool = state.access.archive_pool();
    let mut c = pool
        .acquire()
        .await
        .map_err(|_| Error::Unavailable(crate::Failure::Database))?;
    c.close_on_drop();
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false),set_config('statement_timeout','6000',false),set_config('lock_timeout','6000',false)").bind(&tenant).execute(&mut *c).await.map_err(|_|Error::Unavailable(crate::Failure::Database))?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtextextended($1,2863))")
        .bind(&tenant)
        .fetch_one(&mut *c)
        .await
        .map_err(|_| Error::Unavailable(crate::Failure::Database))?;
    if !locked {
        return Ok(());
    }
    let row=sqlx::query("SELECT authority,manifest,completed,phase FROM mdm_initialization.baselines WHERE tenant_id=$1::uuid").bind(&tenant).fetch_optional(&mut *c).await.map_err(|_|Error::Unavailable(crate::Failure::Database))?;
    let Some(row) = row else { return Ok(()) };
    if row
        .try_get::<String, _>("phase")
        .map_err(|_| Error::Malformed)?
        == "configured"
    {
        return Ok(());
    }
    let authority: rss_mdm_authorization_service::baseline::Authority =
        serde_json::from_value(row.try_get("authority").map_err(|_| Error::Malformed)?)
            .map_err(|_| Error::Malformed)?;
    if authority.user().tenant_id != tenant
        || authority.user().instance_id != state.identity.instance.to_string()
    {
        return Err(Error::Forbidden);
    }
    let manifest: Manifest =
        serde_json::from_value(row.try_get("manifest").map_err(|_| Error::Malformed)?)
            .map_err(|_| Error::Malformed)?;
    if manifest.version != 1 || manifest.steps.len() > 512 {
        return Err(Error::Malformed);
    }
    let mut completed: serde_json::Map<String, Value> =
        serde_json::from_value(row.try_get("completed").map_err(|_| Error::Malformed)?)
            .map_err(|_| Error::Malformed)?;
    let tenant_id = Uuid::parse_str(&tenant).map_err(|_| Error::Malformed)?;
    for step in &manifest.steps {
        if completed.contains_key(&step.key) {
            continue;
        }
        let result = execute(state, &authority, tenant_id, step).await;
        match result {
            Ok(receipt) => {
                use sha2::{Digest, Sha256};
                completed.insert(
                    step.key.clone(),
                    json!(format!(
                        "{:x}",
                        Sha256::digest(serde_json::to_vec(&receipt).map_err(|_| Error::Malformed)?)
                    )),
                );
                sqlx::query("UPDATE mdm_initialization.baselines SET completed=$2,phase='pending',blocked=NULL WHERE tenant_id=$1::uuid")
                    .bind(&tenant).bind(Value::Object(completed.clone())).execute(&mut *c).await.map_err(|_|Error::CommitUnknown)?;
            }
            Err(error) => {
                let reason = blocked_reason(&error);
                eprintln!("baseline step {} blocked: {}", step.key, error);
                sqlx::query("UPDATE mdm_initialization.baselines SET phase='blocked',blocked=$2 WHERE tenant_id=$1::uuid").bind(&tenant).bind(reason).execute(&mut *c).await.map_err(|_|Error::CommitUnknown)?;
                return Err(error);
            }
        }
    }
    let blocked = state.telemetry.is_none();
    sqlx::query(
        "UPDATE mdm_initialization.baselines SET phase=$2,blocked=$3 WHERE tenant_id=$1::uuid",
    )
    .bind(&tenant)
    .bind(if blocked { "blocked" } else { "configured" })
    .bind(if blocked {
        Some("telemetry_backend")
    } else {
        None
    })
    .execute(&mut *c)
    .await
    .map_err(|_| Error::CommitUnknown)?;
    Ok(())
}
// Owner wrappers retain the semantic category at this orchestration boundary.
fn blocked_reason(error: &Error) -> &'static str {
    use rss_mdm_authorization_service::Error as A;
    use rss_mdm_content_service::{Error as C, service::Error as U};
    use rss_mdm_flow_service::Error as F;
    use rss_mdm_inventory_service::Error as I;
    match error {
        Error::Forbidden
        | Error::Unauthorized
        | Error::Authorization(A::Forbidden | A::Unauthorized)
        | Error::Flow(F::Forbidden | F::Unauthorized)
        | Error::Inventory(I::Forbidden | I::Unauthorized)
        | Error::ContentRequest(U::Forbidden | U::Authorization(A::Forbidden | A::Unauthorized)) => {
            "authorization"
        }
        Error::Conflict
        | Error::Authorization(A::Conflict)
        | Error::Flow(F::Conflict)
        | Error::Inventory(I::Conflict)
        | Error::Content(C::Conflict)
        | Error::ContentRequest(U::Conflict | U::Missing | U::Content(C::Conflict))
        | Error::Flow(F::NotFound | F::Planning(_) | F::Resource(_))
        | Error::Inventory(I::NotFound | I::Group(_)) => "conflict",
        Error::Unsupported
        | Error::Flow(F::Unsupported)
        | Error::ContentRequest(U::Unsupported) => "content",
        Error::CommitUnknown
        | Error::RollbackFailed
        | Error::Authorization(A::CommitUnknown | A::RollbackFailed)
        | Error::Flow(F::CommitUnknown | F::RollbackFailed)
        | Error::Inventory(I::CommitUnknown | I::RollbackFailed)
        | Error::Content(C::CommitUnknown)
        | Error::ContentRequest(
            U::CommitUnknown | U::RollbackFailed | U::Content(C::CommitUnknown),
        ) => "outcome_unknown",
        _ => "storage",
    }
}
async fn execute(
    state: &crate::api::Assembly,
    authority: &rss_mdm_authorization_service::baseline::Authority,
    tenant: Uuid,
    step: &Step,
) -> Result<Value, Error> {
    let proof = authority
        .principal(&state.access.authorization_store())
        .await?;
    proof.require_initialization_target(&step.target)?;
    let audit = RequestAudit::new(
        tenant.to_string(),
        "baseline_initialize",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    proof.bind_audit(&audit)?;
    let operation = manifest::id(tenant, &format!("operation:{}", step.key));
    audit.operation(
        operation,
        "baseline_initialize",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    let result = execute_owned(state, &proof, &audit, operation, step).await;
    audit.finalize(
        result
            .as_ref()
            .err()
            .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
    );
    result
}
async fn execute_owned(
    state: &crate::api::Assembly,
    proof: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
    audit: &RequestAudit,
    operation: Uuid,
    step: &Step,
) -> Result<Value, Error> {
    use rss_mdm_flow_service::operation::Operation;
    let target = || Uuid::parse_str(&step.target).map_err(|_| Error::Malformed);
    match &step.action {
        Action::Group { selector, name } => {
            let command = rss_mdm_inventory_service::groups::Command::Group {
                id: target()?,
                change: Box::new(rss_mdm_inventory_service::operation::Operation {
                    operation_id: operation,
                    expected_revision: 0,
                    input: rss_mdm_inventory_service::groups::GroupChange::CreateSystem {
                        selector: *selector,
                        presentation: serde_json::Map::from_iter([
                            ("name".into(), json!(name)),
                            (
                                "description".into(),
                                json!("成员由受管设备生命周期自动维护"),
                            ),
                        ]),
                    },
                }),
            };
            state
                .flow
                .groups
                .execute_initialization(&command, audit, proof)
                .await
                .map_err(Error::from)
        }
        Action::Scope { group } => {
            let command = rss_mdm_flow_service::planning::Command::Scope {
                id: target()?,
                change: Operation {
                    operation_id: operation,
                    expected_revision: 0,
                    input: rss_mdm_scope_service::ScopeChange::Put {
                        definition: rss_mdm_scope::ScopeDefinition {
                            targets: [rss_mdm_scope::Reference::Group(*group)].into(),
                            limitations: None,
                            exclusions: Default::default(),
                        },
                    },
                },
            };
            state
                .flow
                .planning
                .execute_initialization(&command, audit, proof)
                .await
                .map(|value| serde_json::to_value(value).expect("asset envelope serializes"))
                .map_err(Error::from)
        }
        Action::Resource { expected, input } => {
            let command = rss_mdm_flow_service::resource_catalog::Command::Resource {
                id: step.target.clone(),
                change: Operation {
                    operation_id: operation,
                    expected_revision: *expected,
                    input: serde_json::from_value(input.clone()).map_err(|_| Error::Malformed)?,
                },
            };
            state
                .flow
                .catalog
                .execute_initialization(&command, audit, proof)
                .await
                .map(|value| serde_json::to_value(value).expect("asset envelope serializes"))
                .map_err(Error::from)
        }
        Action::Upload {
            version,
            reference,
            platform,
            architecture,
            bytes,
        } => {
            let content = rss_mdm_content_service::service::Access {
                sessions: rss_mdm_authorization_service::session::SessionAuthority::new(
                    state.identity.authority.clone(),
                    state.identity.tenant,
                ),
                authorization: state.access.authorization_store(),
                runtime: state.flow.runtime.clone(),
                audit_store: state.flow.audit_store.clone(),
                tenant: state.identity.tenant,
                content: state.content_writer.clone(),
                clock: std::sync::Arc::new(crate::clock::ContentClock(state.clock.clone())),
                catalog: std::sync::Arc::new(rss_mdm_software_service::catalog::Reader::new(
                    state.identity.tenant,
                )),
            };
            rss_mdm_content_service::service::upload(
                &content,
                rss_mdm_content_service::service::UploadAuthority::initialization(proof)
                    .map_err(Error::from)?,
                audit,
                &step.target,
                &rss_mdm_content_service::service::Selection {
                    version: version.clone(),
                    variant: match architecture {
                        rss_mdm_resource::Architecture::X86_64 => "x86_64",
                        rss_mdm_resource::Architecture::Aarch64 => "aarch64",
                    }
                    .into(),
                    platform: *platform,
                    architecture: *architecture,
                    artifact: Some(reference.clone()),
                    operation: Some(operation),
                },
                bytes.as_slice(),
            )
            .await
            .map_err(Error::from)?;
            Ok(json!({"uploaded":true}))
        }
        Action::Field { definition } => {
            let command = rss_mdm_inventory_service::assets::Command::FieldWrite {
                field: definition.key,
                change: rss_mdm_inventory_service::operation::Operation {
                    operation_id: operation,
                    expected_revision: 0,
                    input: rss_mdm_inventory_service::assets::FieldChange::Put {
                        definition: Box::new(definition.clone()),
                    },
                },
            };
            state
                .flow
                .assets
                .execute_initialization(&command, audit, proof)
                .await
                .map(|value| serde_json::to_value(value).expect("asset envelope serializes"))
                .map_err(Error::from)
        }
        Action::Retention { policy } => {
            let command = rss_mdm_inventory_service::assets::Command::RetentionWrite {
                change: rss_mdm_inventory_service::operation::Operation {
                    operation_id: operation,
                    expected_revision: 0,
                    input: policy.clone(),
                },
            };
            state
                .flow
                .assets
                .execute_initialization(&command, audit, proof)
                .await
                .map(|value| serde_json::to_value(value).expect("asset envelope serializes"))
                .map_err(Error::from)
        }
        Action::Policy { definition } => {
            let policies = rss_mdm_flow_service::planning::policies::Policies::new(
                &state.flow.cursor_key,
                state.flow.runtime.clone(),
                state.flow.planning.reconcile_messaging.clone(),
                state.flow.audit_store.clone(),
                state.identity.tenant,
                state.flow.policy_store.clone(),
                state.inputs.clone(),
            );
            policies
                .change(
                    proof,
                    target()?,
                    &Operation {
                        operation_id: operation,
                        expected_revision: 0,
                        input: rss_mdm_policy::Change::Put {
                            enabled: true,
                            definition: Box::new(definition.clone()),
                        },
                    },
                    audit,
                )
                .await
                .map(|view| serde_json::to_value(view).expect("policy view serializes"))
                .map_err(Error::from)
        }
    }
}

/// Persist the first-install intent with its own audited transaction and original authority.
pub(crate) async fn reserve(
    pool: &sqlx::PgPool,
    store: &rss_mdm_audit_integration::AuditStore,
    authority: rss_mdm_authorization_service::baseline::Authority,
) -> Result<(), Error> {
    let tenant = Uuid::parse_str(&authority.user().tenant_id).map_err(|_| Error::Malformed)?;
    // Repeated deployment retains the original immutable intent, even when the
    // bundled catalog has changed. The original provisioning owner already audited it.
    if status(pool, &tenant.to_string()).await?.is_some() {
        return Ok(());
    }
    let operation = manifest::id(tenant, "intent");
    let audit = RequestAudit::new(
        tenant.to_string(),
        "baseline_initialize",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.set_principal(
        &authority.user().principal_id,
        &authority.user().instance_id,
    );
    audit.operation(
        operation,
        "baseline_initialize",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    let fact = rss_mdm_audit_integration::Fact::business(
        &audit,
        &format!("baseline:{operation}"),
        200,
        "success",
        None,
    )?;
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(6));
    let result = store
        .write(
            rss_request_context::TenantId::parse(&tenant.to_string())
                .map_err(|_| Error::Malformed)?,
            &budget.source_control(),
            (store, authority, fact),
            |(store, authority, fact), tx| {
                Box::pin(async move {
                    let authority = authority.clone();
                    let inserted = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                reserve_on(c, &authority)
                                    .await
                                    .map_err(|_| rss_mdm_audit_integration::Error::Receipt)
                            })
                        })
                        .await?;
                    (if !inserted {
                        Ok(())
                    } else {
                        store.append(tx, fact).await
                    })?;
                    Ok::<_, rss_mdm_audit_integration::Error>(())
                })
            },
        )
        .await;
    let result = result.fold(
        |_| Ok(()),
        |_| Err(Error::Unavailable(crate::Failure::Database)),
        |_| Err(Error::Unavailable(crate::Failure::Database)),
        |_| Err(Error::RollbackFailed),
        |_| Err(Error::CommitUnknown),
        |_| Err(Error::Unavailable(crate::Failure::Database)),
    );
    audit.finalize(
        result
            .as_ref()
            .err()
            .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
    );
    result
}

pub(crate) async fn status(
    pool: &sqlx::PgPool,
    tenant: &str,
) -> Result<Option<(String, Option<String>, u64, u64)>, Error> {
    use sqlx::Acquire;
    let mut c = pool
        .acquire()
        .await
        .map_err(|_| Error::Unavailable(crate::Failure::Database))?;
    let mut tx = c
        .begin()
        .await
        .map_err(|_| Error::Unavailable(crate::Failure::Database))?;
    sqlx::query(
        "SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','2000',true)",
    )
    .bind(tenant)
    .execute(&mut *tx)
    .await
    .map_err(|_| Error::Unavailable(crate::Failure::Database))?;
    let row=sqlx::query("SELECT phase,blocked,manifest,completed FROM mdm_initialization.baselines WHERE tenant_id=$1::uuid").bind(tenant).fetch_optional(&mut *tx).await.map_err(|_|Error::Unavailable(crate::Failure::Database))?;
    tx.rollback()
        .await
        .map_err(|_| Error::Unavailable(crate::Failure::Database))?;
    let Some(row) = row else { return Ok(None) };
    let manifest: Manifest =
        serde_json::from_value(row.try_get("manifest").map_err(|_| Error::Malformed)?)
            .map_err(|_| Error::Malformed)?;
    let completed: serde_json::Map<String, Value> =
        serde_json::from_value(row.try_get("completed").map_err(|_| Error::Malformed)?)
            .map_err(|_| Error::Malformed)?;
    let mut assets = 0;
    let mut telemetry = 0;
    for step in manifest
        .steps
        .iter()
        .filter(|s| !completed.contains_key(&s.key))
    {
        if step.key.starts_with("performance:")
            || step.key.starts_with("profile:")
            || step.key.starts_with("field:")
        {
            telemetry += 1;
        } else {
            assets += 1;
        }
    }
    Ok(Some((
        row.try_get("phase").map_err(|_| Error::Malformed)?,
        row.try_get("blocked").map_err(|_| Error::Malformed)?,
        assets,
        telemetry,
    )))
}

/// Initialization retries share RSS task ownership and the original durable receipts.
pub(crate) fn registration(
    state: std::sync::Arc<crate::api::Assembly>,
) -> rss_runtime::ManagedTaskRegistration {
    let (task, _) =
        rss_runtime::ManagedTask::prepare("tenant-baseline", std::time::Duration::from_secs(10));
    task.into_registration(move|cancel|async move {
        let mut previous=None;
        loop {
            let result=tokio::select! {
                _=cancel.cancelled()=>return Ok(()),
                result=tokio::time::timeout(std::time::Duration::from_secs(120),resume(&state))=>result,
            };
            let failure=match result {Ok(Ok(()))=>None,Ok(Err(error))=>Some(error.to_string()),Err(_)=>Some("initialization outcome unknown".into())};
            if failure!=previous {
                if let Some(reason)=&failure {eprintln!("baseline initialization blocked: {reason}");}
                previous=failure;
            }
            tokio::select! {_=cancel.cancelled()=>return Ok(()),_=tokio::time::sleep(std::time::Duration::from_secs(60))=>{}}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owner_errors_keep_actionable_initialization_diagnostics() {
        assert_eq!(
            blocked_reason(&rss_mdm_authorization_service::Error::Forbidden.into()),
            "authorization"
        );
        assert_eq!(
            blocked_reason(&rss_mdm_flow_service::Error::Conflict.into()),
            "conflict"
        );
        assert_eq!(
            blocked_reason(&rss_mdm_inventory_service::Error::Conflict.into()),
            "conflict"
        );
        assert_eq!(
            blocked_reason(&rss_mdm_content_service::service::Error::Unsupported.into()),
            "content"
        );
        assert_eq!(
            blocked_reason(
                &rss_mdm_content_service::service::Error::Content(
                    rss_mdm_content_service::Error::CommitUnknown
                )
                .into()
            ),
            "outcome_unknown"
        );
    }
}
