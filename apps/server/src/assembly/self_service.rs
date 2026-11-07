//! One authorized self-service directory and receipt-first composition of concrete owners.
use super::agent_tasks::{AgentTasks, registration_fault, script_fault, software_fault};
use rss_mdm_agent_channel::{Error, Failure};
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_audit_integration::{AuditStore, RequestAudit};
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_query::{
    Parameters,
    directory::{Field, Kind, Query, Schema},
};
use rss_mdm_registration_service::DevicePrincipal;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgError, PgRuntime, PgTransaction};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use uuid::Uuid;
type Result<T> = std::result::Result<T, Error>;
fn stored<T>(value: std::result::Result<T, impl std::fmt::Debug>) -> Result<T> {
    value.map_err(|_| Error::Unavailable(Failure::Business))
}
fn checked<T>(value: std::result::Result<T, impl std::fmt::Debug>) -> Result<T> {
    value.map_err(|_| Error::Conflict)
}
fn json(value: &impl serde::Serialize) -> Result<Value> {
    stored(serde_json::to_value(value))
}
pub(crate) struct Requests {
    pub runtime: Arc<PgRuntime>,
    pub tenant: TenantId,
    pub audit: Arc<AuditStore>,
    pub instance: String,
    pub policy_reader: rss_mdm_policy_postgres::PolicyReader,
    pub cursor: rss_mdm_query::cursor::CursorCodec,
}
impl Requests {
    pub(crate) fn new(
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        audit: Arc<AuditStore>,
        instance: String,
        key: &[u8],
    ) -> Self {
        Self {
            policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(
                rss_mdm_install_support::StorageProfile::Mdm,
                runtime.clone(),
                tenant,
            ),
            runtime,
            tenant,
            audit,
            instance,
            cursor: rss_mdm_query::cursor::CursorCodec::from_key(ring::hmac::Key::new(
                ring::hmac::HMAC_SHA256,
                key,
            )),
        }
    }
    async fn transaction<C: Send, R: Send, F>(
        &self,
        audit: Option<&RequestAudit>,
        context: C,
        operation: F,
    ) -> Result<R>
    where
        F: for<'a> FnOnce(
                &'a mut C,
                &'a mut PgTransaction<'_>,
            ) -> rss_mdm_agent_channel::delivery::Pending<'a, R>
            + Send,
    {
        let failure = Mutex::new(None);
        let attempt = self
            .runtime
            .local_tx_with_context(
                self.tenant,
                rss_mdm_script_service::transaction::deadline(),
                (context, Some(operation), &failure, audit, &self.audit),
                |(context, operation, failure, audit, store), tx| {
                    Box::pin(async move {
                        if audit.is_some() {
                            store
                                .bind_in(tx)
                                .await
                                .map_err(|e| reject(e.into(), failure))?;
                        }
                        match operation.take().expect("one request")(context, tx).await {
                            Ok(value) => {
                                if let Some(audit) = audit {
                                    audit.mark_commit_started();
                                }
                                Ok(value)
                            }
                            Err(e) => Err(reject(e, failure)),
                        }
                    })
                },
            )
            .await;
        attempt.fold(
            |v| {
                if let Some(a) = audit {
                    a.mark_committed();
                }
                Ok(v)
            },
            |_| Err(Error::Unavailable(Failure::Database)),
            |_| {
                if let Some(a) = audit {
                    a.mark_rolled_back();
                }
                Err(failure
                    .into_inner()
                    .expect("request result")
                    .unwrap_or(Error::Unavailable(Failure::Database)))
            },
            |_| {
                if let Some(a) = audit {
                    a.mark_rollback_failed();
                }
                Err(Error::RollbackFailed)
            },
            |_| Err(Error::CommitUnknown),
            |_| Err(Error::Unavailable(Failure::Database)),
        )
    }
    async fn inspect<C: Send, R: Send, F>(&self, context: C, operation: F) -> Result<R>
    where
        F: for<'a> FnOnce(
                &'a mut C,
                &'a mut PgTransaction<'_>,
            ) -> rss_mdm_agent_channel::delivery::Pending<'a, R>
            + Send,
    {
        self.transaction(None, context, operation).await
    }
}
fn reject(e: Error, failure: &Mutex<Option<Error>>) -> PgError {
    *failure.lock().expect("request result") = Some(e);
    sqlx::Error::Protocol("self-service rejected".into()).into()
}
fn bind(
    p: &DevicePrincipal,
    proof: Option<&AuthorizedPrincipal>,
    audit: &RequestAudit,
) -> Result<()> {
    if let Some(proof) = proof {
        if proof.tenant_id() != p.tenant().to_string() {
            return Err(Error::Forbidden);
        }
        proof.check_live()?;
        proof.bind_audit(audit)?;
    }
    Ok(())
}
async fn current(
    tx: &mut PgTransaction<'_>,
    proof: &AuthorizedPrincipal,
) -> Result<rss_mdm_authorization_service::Snapshot> {
    let tenant = proof.tenant_id().to_owned();
    let instance = proof.instance_id().to_owned();
    tx.with_connection(move |c| {
        Box::pin(async move {
            rss_mdm_authorization_service::lock_shared_on(
                rss_mdm_install_support::StorageProfile::Mdm,
                c,
                &tenant,
                &instance,
            )
            .await
            .map_err(|_| sqlx::Error::Protocol("authorization lock".into()))?;
            Ok(rss_mdm_authorization_service::snapshot_on(
                rss_mdm_install_support::StorageProfile::Mdm,
                c,
                &tenant,
                &instance,
            )
            .await)
        })
    })
    .await?
    .map_err(Into::into)
}
fn actors(p: &DevicePrincipal, proof: Option<&AuthorizedPrincipal>) -> Result<Vec<String>> {
    let mut actors = Vec::new();
    if let Some(proof) = proof {
        actors.push(format!(
            "self-service:{}:{}:{}:{}",
            Uuid::parse_str(proof.instance_id()).map_err(|_| Error::Unauthorized)?,
            Uuid::parse_str(proof.principal_id()).map_err(|_| Error::Unauthorized)?,
            p.registration(),
            p.generation()
        ));
    }
    actors.push(format!(
        "self-service:device:{}:{}",
        p.registration(),
        p.generation()
    ));
    Ok(actors)
}
async fn policy_owner(
    service: &AgentTasks,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<rss_mdm_policy::ActionKind> {
    let policy =
        checked(service.requests.policy_reader.locked_in(tx, id).await?)?.ok_or(Error::NotFound)?;
    match policy.definition.action.kind() {
        kind @ (rss_mdm_policy::ActionKind::Execution
        | rss_mdm_policy::ActionKind::Software
        | rss_mdm_policy::ActionKind::RequestMdmEnrollment) => Ok(kind),
        _ => Err(Error::Forbidden),
    }
}
async fn describe_in(
    service: &AgentTasks,
    tx: &mut PgTransaction<'_>,
    p: &DevicePrincipal,
    proof: Option<&AuthorizedPrincipal>,
    source: wire::SelfServiceCaller,
    id: Uuid,
    now: i64,
) -> Result<Option<wire::SelfServiceDirectoryItem>> {
    match policy_owner(service, tx, id).await? {
        rss_mdm_policy::ActionKind::Execution => {
            rss_mdm_script_service::self_service::directory::describe_in(
                &service.scripts,
                tx,
                p,
                proof,
                source,
                id,
                now,
            )
            .await
            .map_err(script_fault)
        }
        rss_mdm_policy::ActionKind::Software => {
            rss_mdm_software_service::deployment::self_service::directory::describe_in(
                &service.software,
                tx,
                p,
                proof,
                source,
                id,
                now,
            )
            .await
            .map_err(software_fault)
        }
        rss_mdm_policy::ActionKind::RequestMdmEnrollment => {
            rss_mdm_registration_service::enrollment::tasks::self_service::directory::describe_in(
                rss_mdm_install_support::StorageProfile::Mdm,
                &service.registration,
                tx,
                p,
                proof,
                source,
                id,
                now,
            )
            .await
            .map_err(registration_fault)
        }
        _ => Err(Error::Forbidden),
    }
}
pub static SCHEMA: Schema = Schema {
    id: "self_service",
    keys: &["id"],
    default_limit: 64,
    max_limit: 64,
    fields: &[
        Field {
            name: "id",
            kind: Kind::Uuid,
            filter: true,
            sort: true,
            output: false,
        },
        Field {
            name: "toolName",
            kind: Kind::Text,
            filter: true,
            sort: true,
            output: false,
        },
        Field {
            name: "alias",
            kind: Kind::Text,
            filter: true,
            sort: true,
            output: false,
        },
        Field {
            name: "displayName",
            kind: Kind::Text,
            filter: true,
            sort: true,
            output: false,
        },
        Field {
            name: "category",
            kind: Kind::Text,
            filter: true,
            sort: true,
            output: false,
        },
        Field::output("capability"),
        Field::output("policyId"),
        Field::output("policyRevision"),
        Field::output("policyVersion"),
        Field::output("subject"),
        Field::output("selfService"),
        Field::output("task"),
    ],
};
/// Captured input keeps parsing after the service's existing identity binding.
pub struct Input(String);
impl Input {
    pub fn new(raw: &str) -> Self {
        Self(raw.to_owned())
    }
    pub fn schema() -> &'static Schema {
        &SCHEMA
    }
}
fn column(field: &str) -> &'static str {
    match field {
        "id" => "id::text COLLATE \"C\"",
        "toolName" => "('policy_' || replace(id::text,'-','')) COLLATE \"C\"",
        "alias" => "(definition->>'alias') COLLATE \"C\"",
        "displayName" => {
            "(definition->'selfService'->'presentation'->>'displayName') COLLATE \"C\""
        }
        "category" => "(definition->'selfService'->'presentation'->>'category') COLLATE \"C\"",
        _ => unreachable!("checked field"),
    }
}
impl AgentTasks {
    pub async fn self_service_directory(
        &self,
        p: &DevicePrincipal,
        proof: Option<&AuthorizedPrincipal>,
        input: &Input,
        audit: &RequestAudit,
    ) -> std::result::Result<wire::SelfServiceDirectoryResponse, Error> {
        bind(p, proof, audit)?;
        let (parameters, context) =
            Parameters::parse_with_context(&input.0, &["source"]).map_err(|_| Error::Malformed)?;
        let source = match context.get("source").map(String::as_str) {
            Some("human") => wire::SelfServiceCaller::Human,
            Some("ai") => wire::SelfServiceCaller::Ai,
            _ => return Err(Error::Malformed),
        };
        let query = Query::new(&SCHEMA, parameters).map_err(|_| Error::Malformed)?;
        self.requests.inspect( (self, p, proof, &query, audit), |ctx, tx| Box::pin(async move {
            let (service, p, proof, query, _audit) = *ctx;
            super::agent_tasks::prepare(tx,p).await?;
            let subject = if let Some(proof) = proof {
                Some(current(tx, proof).await?.query_binding(proof)?)
            } else { None };
            let binding = query.binding(&(service.requests.instance.as_str(), p.tenant().to_string(), p.device(), p.registration(), p.generation(), source, subject)).map_err(|_| Error::Malformed)?;
            let after = query.after(&service.requests.cursor, &binding).map_err(|_| Error::Conflict)?;
            let mut sql = sqlx::QueryBuilder::new("SELECT jsonb_build_object('id',id,'toolName','policy_' || replace(id::text,'-',''),'alias',definition->>'alias','displayName',definition->'selfService'->'presentation'->>'displayName','category',definition->'selfService'->'presentation'->>'category') FROM mdm_policy.policies WHERE tenant_id=");
            sql.push_bind(tx.tenant_id().to_string()).push("::uuid AND state='enabled' AND definition->'selfService'->>'published'='true'");
            rss_mdm_query_postgres::append(&mut sql, query, after.as_ref(), column).map_err(|_| Error::Malformed)?;
            let rows: Vec<Value> = tx.with_connection(move |c| Box::pin(async move { sql.build_query_scalar().fetch_all(c).await })).await?;
            // Cursor advances over examined candidates, including invisible ones.
            let page = query.unprojected_page(rows, &service.requests.cursor, &binding).map_err(|_| Error::Malformed)?;
            let now = rss_mdm_script_service::storage::now(tx).await.map_err(script_fault)?;
            let mut items = Vec::new();
            for mut row in page.items {
                let id = stored(serde_json::from_value(row["id"].clone()))?;
                if let Some(item) = describe_in(service, tx, p, proof, source, id, now).await? {
                    row.as_object_mut().ok_or(Error::Malformed)?.extend(json(&item)?.as_object().ok_or(Error::Malformed)?.clone());
                    items.push(query.project(row).map_err(|_| Error::Malformed)?);
                }
            }
            if let Some(proof) = proof { proof.check_live()?; }
            Ok(wire::SelfServiceDirectoryResponse { items: stored(serde_json::from_value(json!(items)))?, next_cursor:page.next_cursor, as_of:now })
        })).await
    }
    pub async fn resolve_self_service(
        &self,
        p: &DevicePrincipal,
        proof: Option<&AuthorizedPrincipal>,
        input: &wire::SelfServiceResolve,
        audit: &RequestAudit,
    ) -> std::result::Result<wire::SelfServiceDirectoryItem, Error> {
        bind(p, proof, audit)?;
        self.requests
            .inspect((self, p, proof, input, audit), |ctx, tx| {
                Box::pin(async move {
                    let (service, p, proof, input, _audit) = *ctx;
                    super::agent_tasks::prepare(tx, p).await?;
                    let id = checked(
                        service
                            .requests
                            .policy_reader
                            .resolve_in(tx, &input.selector)
                            .await?,
                    )?
                    .ok_or(Error::NotFound)?;
                    let now = rss_mdm_script_service::storage::now(tx)
                        .await
                        .map_err(script_fault)?;
                    let item = describe_in(service, tx, p, proof, input.source, id, now)
                        .await?
                        .ok_or(Error::NotFound)?;
                    if let wire::CapabilitySelector::Alias { alias } = &input.selector
                        && item.capability.alias.as_ref() != Some(alias)
                    {
                        return Err(Error::NotFound);
                    }
                    if let Some(proof) = proof {
                        proof.check_live()?;
                    }
                    Ok(item)
                })
            })
            .await
    }
}

impl AgentTasks {
    pub(crate) async fn invoke_self_service(
        &self,
        p: &DevicePrincipal,
        proof: Option<&AuthorizedPrincipal>,
        input: &wire::SelfServiceInvoke,
        audit: &RequestAudit,
    ) -> Result<wire::SelfServiceAccepted> {
        bind(p, proof, audit)?;
        if input.operation_id.is_nil()
            || input.policy_id.is_nil()
            || input.parameters.len() > 32
            || serde_json::to_vec(input)
                .map_err(|_| Error::Malformed)?
                .len()
                > 131072
        {
            return Err(Error::Malformed);
        }
        audit.operation(
            input.operation_id,
            "command_accept",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        let response = self
            .requests
            .transaction(Some(audit), (self, p, proof, input, audit), |ctx, tx| {
                Box::pin(async move {
                    let (service, p, proof, input, audit) = *ctx;
                    super::agent_tasks::prepare(tx, p).await?;
                    let actors = actors(p, proof)?;
                    for actor in &actors {
                        rss_mdm_script_service::storage::lock_request(
                            tx,
                            actor,
                            input.operation_id,
                        )
                        .await
                        .map_err(script_fault)?;
                    }
                    for actor in &actors {
                        let script = service
                            .scripts
                            .replay_self_service_in(tx, p, actor, input)
                            .await
                            .map_err(script_fault)?;
                        let software = service
                            .software
                            .replay_self_service_in(tx, p, actor, input)
                            .await
                            .map_err(software_fault)?;
                        let enrollment = service
                            .registration
                            .replay_self_service_in(tx, p, actor, input)
                            .await
                            .map_err(registration_fault)?;
                        use rss_mdm_audit_integration::operation::OperationOwner as O;
                        let mut receipts = [
                            (O::ScriptInvocation, script),
                            (O::SoftwareInvocation, software),
                            (O::EnrollmentInvocation, enrollment),
                        ]
                        .into_iter()
                        .filter_map(|(owner, value)| value.map(|value| (owner, value)));
                        if let Some((owner, receipt)) = receipts.next() {
                            if receipts.next().is_some() {
                                return Err(Error::Unavailable(Failure::Business));
                            }
                            if let Some(proof) = proof {
                                proof.check_live()?;
                            }
                            audit.owned_operation(
                                owner,
                                input.operation_id,
                                "self_service_invoke",
                                rss_mdm_audit_integration::AuditIntent::Management,
                            );
                            audit.receipt_actor(actor);
                            audit.registration_at(p.registration(), p.generation());
                            audit.management_result(
                                rss_mdm_audit_integration::ManagementResult::Replayed,
                            );
                            return Ok(receipt);
                        }
                    }
                    match policy_owner(service, tx, input.policy_id).await? {
                        rss_mdm_policy::ActionKind::Execution => service
                            .scripts
                            .invoke_self_service_in(tx, p, proof, input, audit)
                            .await
                            .map_err(script_fault),
                        rss_mdm_policy::ActionKind::Software => service
                            .software
                            .invoke_self_service_in(tx, p, proof, input, audit)
                            .await
                            .map_err(software_fault),
                        rss_mdm_policy::ActionKind::RequestMdmEnrollment => service
                            .registration
                            .invoke_self_service_in(tx, p, proof, input, audit)
                            .await
                            .map_err(registration_fault),
                        _ => Err(Error::Forbidden),
                    }
                })
            })
            .await?;
        stored(serde_json::from_value(response))
    }
    pub(crate) async fn self_service_status(
        &self,
        p: &DevicePrincipal,
        proof: Option<&AuthorizedPrincipal>,
        request: Uuid,
        audit: &RequestAudit,
    ) -> Result<wire::SelfServiceStatus> {
        bind(p, proof, audit)?;
        if request.is_nil() {
            return Err(Error::Malformed);
        }
        self.requests
            .inspect((self, p, proof, request, audit), |ctx, tx| {
                Box::pin(async move {
                    let (service, p, proof, request, audit) = *ctx;
                    super::agent_tasks::prepare(tx, p).await?;
                    for actor in actors(p, proof)? {
                        let script = service
                            .scripts
                            .self_service_status_in(tx, p, proof, &actor, request, audit)
                            .await
                            .map_err(script_fault)?;
                        let software = service
                            .software
                            .self_service_status_in(tx, p, proof, &actor, request, audit)
                            .await
                            .map_err(software_fault)?;
                        let enrollment = service
                            .registration
                            .self_service_status_in(tx, p, proof, &actor, request, audit)
                            .await
                            .map_err(registration_fault)?;
                        let mut statuses = [script, software, enrollment].into_iter().flatten();
                        if let Some(status) = statuses.next() {
                            if statuses.next().is_some() {
                                return Err(Error::Unavailable(Failure::Business));
                            }
                            return Ok(status);
                        }
                    }
                    Err(Error::NotFound)
                })
            })
            .await
    }
}
