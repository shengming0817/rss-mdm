//! Tenant-owned webhook configuration, RSS publishing and authorized management ingress.
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_management_http::{Error as HttpError, webhooks::Command};
use rss_mdm_webhook_service as webhooks;
use rss_request_context::TenantId;
use serde_json::Value;
use sqlx::PgConnection;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use uuid::Uuid;
use webhooks::{PgError, PgRuntime, events, model::*, storage};
mod authority;
mod config;
mod recovery;
mod worker;
pub use config::Config;
use webhooks::fanout::Eligibility;

#[derive(Clone)]
pub(crate) struct Backend {
    runtime: Arc<PgRuntime>,
    tenant: TenantId,
    host: Arc<authority::Host>,
    audit: Arc<rss_mdm_audit_integration::AuditStore>,
    recovery: Arc<
        rss_transactional_messaging_postgres::PgRecoveryStore<rss_mdm_native_protection::Protector>,
    >,
}
pub(super) fn deadline() -> rss_transactional_messaging::policy::OperationDeadline {
    rss_transactional_messaging::policy::OperationDeadline::from_remaining(Duration::from_secs(6))
}
pub(super) fn map_error(error: webhooks::Error) -> HttpError {
    match error {
        webhooks::Error::Invalid => HttpError::Malformed,
        webhooks::Error::NotFound => HttpError::NotFound,
        webhooks::Error::Conflict => HttpError::Conflict,
        webhooks::Error::Denied => HttpError::Forbidden,
        webhooks::Error::CommitUnknown => HttpError::CommitUnknown,
        webhooks::Error::Storage => {
            HttpError::Unavailable(rss_mdm_management_http::Failure::Database)
        }
    }
}
fn unavailable() -> HttpError {
    map_error(webhooks::Error::Storage)
}
fn operation(c: &Command) -> Option<Uuid> {
    match c {
        Command::Change(_, v) => Some(v.operation_id),
        Command::Test { operation, .. }
        | Command::Replay { operation, .. }
        | Command::Redrive { operation, .. } => Some(*operation),
        _ => None,
    }
}
fn required(c: &Command) -> Permission {
    match c {
        Command::Change(..) | Command::Test { .. } => Permission::WebhookWrite,
        Command::Replay { .. } | Command::Redrive { .. } => Permission::WebhookReplay,
        _ => Permission::WebhookRead,
    }
}
impl Backend {
    pub(crate) async fn open(
        config: Config,
        runtime: Arc<PgRuntime>,
        tenant: TenantId,
        audit: Arc<rss_mdm_audit_integration::AuditStore>,
        clock: Arc<dyn crate::clock::Clock>,
        protection: Arc<rss_mdm_native_protection::Protector>,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
    ) -> Result<Arc<Self>, crate::Error> {
        use rss_transactional_messaging_postgres::{
            PgConfig, PgPassword, PgPrivateCa, PgRecoveryStore,
        };
        let db = &config.recovery_database;
        let pg = PgConfig::new(
            &db.host,
            db.port,
            &db.name,
            &db.user,
            PgPassword::new(crate::config::secret(&db.password_file)?.as_str()),
            PgPrivateCa::from_pem(crate::config::read(&db.ca_file, 1024 * 1024, false)?.to_vec())
                .map_err(|_| crate::Error::Malformed)?,
        );
        let recovery =
            PgRecoveryStore::connect(pg, crate::lifecycle::RuntimeTimer, binding, protection)
                .await
                .map_err(|_| crate::Error::Unavailable(crate::Failure::Database))?;
        let policies = match config.compile() {
            Ok(v) => v,
            Err(_) => {
                recovery.close().await;
                return Err(crate::Error::Malformed);
            }
        };
        let result = Arc::new(Self {
            runtime,
            tenant,
            host: Arc::new(authority::Host {
                tenant: Uuid::parse_str(&tenant.to_string())
                    .map_err(|_| crate::Error::Malformed)?,
                policies,
                clock,
            }),
            audit,
            recovery: Arc::new(recovery),
        });
        let check=result.runtime.local_tx(tenant,deadline(),|tx|Box::pin(async move {
            tx.with_connection(|c|Box::pin(async move {let ok:bool=sqlx::query_scalar("SELECT to_regclass('mdm_webhook.events') IS NOT NULL AND to_regclass('mdm_webhook.deliveries') IS NOT NULL").fetch_one(c).await?;if ok{Ok(())}else{Err(sqlx::Error::Protocol("webhook installation missing".into()))}})).await
        })).await.fold(Ok,Err,Err,Err,Err,Err);
        if check.is_err() {
            result.recovery.close().await;
            return Err(crate::Error::Unavailable(crate::Failure::Database));
        }
        Ok(result)
    }
    async fn execute_transaction(
        &self,
        proof: Arc<AuthorizedPrincipal>,
        audit: RequestAudit,
        command: Command,
    ) -> Result<Value, HttpError> {
        proof.manage(required(&command))?;
        proof.bind_audit(&audit)?;
        if proof.tenant_id() != self.tenant.to_string() {
            return Err(HttpError::Forbidden);
        }
        let op = operation(&command);
        if let Some(id) = op {
            if id.is_nil() {
                return Err(HttpError::Malformed);
            }
            audit.operation(
                id,
                if matches!(command, Command::Redrive { .. }) {
                    "webhook_redrive_intent"
                } else {
                    "webhook_write"
                },
            );
        } else {
            audit.set_action("webhook_read");
        }
        let failure = Mutex::new(None);
        let attempt = self
            .runtime
            .local_tx_with_context(
                self.tenant,
                deadline(),
                (
                    self,
                    proof.clone(),
                    audit.clone(),
                    command.clone(),
                    &failure,
                ),
                |ctx, tx| {
                    Box::pin(async move {
                        let (backend, proof, audit, command, failure) = ctx;
                        backend.audit.lock_in(tx).await.map_err(PgError::from)?;
                        let owned = (*backend).clone();
                        let p = proof.clone();
                        let cmd = command.clone();
                        let result = tx
                            .with_connection(move |c| {
                                Box::pin(async move { Ok(owned.execute_on(c, &p, &cmd).await) })
                            })
                            .await?;
                        let (value, replayed) = match result {
                            Ok(v) => v,
                            Err(error) => {
                                *failure.lock().map_err(|_| {
                                    PgError::from(sqlx::Error::Protocol(
                                        "webhook result lock".into(),
                                    ))
                                })? = Some(error);
                                return Err(webhooks::Error::Invalid.into());
                            }
                        };
                        proof
                            .check_live()
                            .map_err(|_| PgError::from(webhooks::Error::Denied))?;
                        if let Some(id) = operation(command) {
                            use sha2::{Digest, Sha256};
                            let digest = Sha256::digest(
                                serde_json::to_vec(command)
                                    .map_err(|_| PgError::from(webhooks::Error::Invalid))?,
                            );
                            let fact = rss_mdm_audit_integration::Fact::business(
                                audit,
                                &format!("webhook:{id}"),
                                &digest,
                                200,
                                "success",
                                None,
                            )
                            .map_err(|_| PgError::from(webhooks::Error::Invalid))?;
                            backend
                                .audit
                                .append_in(tx, &fact, replayed)
                                .await
                                .map_err(PgError::from)?;
                        } else {
                            backend
                                .audit
                                .append_request_in(tx, audit, 200, "success")
                                .await
                                .map_err(PgError::from)?;
                        }
                        audit.mark_commit_started();
                        Ok(value)
                    })
                },
            )
            .await;
        attempt.fold(
            |v| {
                audit.mark_committed();
                Ok(v)
            },
            |_| Err(unavailable()),
            |_| {
                audit.mark_rolled_back();
                Err(failure
                    .into_inner()
                    .ok()
                    .flatten()
                    .unwrap_or_else(unavailable))
            },
            |_| {
                audit.mark_rollback_failed();
                Err(HttpError::RollbackFailed)
            },
            |_| Err(HttpError::CommitUnknown),
            |_| Err(unavailable()),
        )
    }
    async fn execute_on(
        &self,
        c: &mut PgConnection,
        p: &AuthorizedPrincipal,
        command: &Command,
    ) -> Result<(Value, bool), HttpError> {
        p.manage(required(command))?;
        let t = self.host.tenant;
        let replayed = if let Some(op) = operation(command) {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2796))")
                .bind(format!("{t}:{op}"))
                .execute(&mut *c)
                .await
                .map_err(|_| unavailable())?;
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM mdm_webhook.operations WHERE tenant_id=$1 AND id=$2)",
            )
            .bind(t)
            .bind(op)
            .fetch_one(&mut *c)
            .await
            .map_err(|_| unavailable())?
        } else {
            false
        };
        let value = match command {
            Command::Health => {
                let counts=sqlx::query_scalar::<_,Value>("SELECT coalesce(jsonb_agg(jsonb_build_object('domain',domain,'status',status,'count',n)),'[]'::jsonb) FROM (SELECT domain,status,count(*) AS n FROM rss_transactional_messaging.outbox WHERE tenant_id=$1 AND domain IN('mdm-webhook-source','mdm-webhook-delivery') GROUP BY domain,status) s").bind(t).fetch_one(&mut *c).await.map_err(|_|unavailable())?;
                serde_json::json!({"outbox":counts})
            }
            Command::Types => serde_json::json!({"items":EventType::BUSINESS,"version":1}),
            Command::Subscriptions(after) => {
                serde_json::json!({"items":storage::list(c,t,*after).await.map_err(map_error)?})
            }
            Command::Subscription(id) => {
                serde_json::to_value(storage::get(c, t, *id).await.map_err(map_error)?)
                    .map_err(|_| HttpError::Malformed)?
            }
            Command::Change(id, mutation) => {
                match &mutation.change {
                    storage::Change::Put(settings) => {
                        self.host.policies.check(t, settings)?;
                        authority::settings(p, settings)?;
                    }
                    storage::Change::Enabled(true) => {
                        let settings = storage::get(c, t, *id).await.map_err(map_error)?.settings;
                        self.host.policies.check(t, &settings)?;
                        authority::settings(p, &settings)?;
                    }
                    // Stopping an integration must work even after its network/key config is removed.
                    storage::Change::Enabled(false) | storage::Change::Delete => (),
                }
                storage::mutate(c, t, *id, mutation)
                    .await
                    .map_err(map_error)?
            }
            Command::Test {
                subscription,
                operation,
                device,
            } => {
                let input = ("test", subscription, operation, device);
                let s = storage::get(c, t, *subscription).await.map_err(map_error)?;
                p.require(Permission::InventoryRead, Some(device))?;
                if let Some(old) = storage::replay_operation(c, t, *operation, &input)
                    .await
                    .map_err(map_error)?
                {
                    return Ok((old, true));
                }
                if !s.enabled || s.deleted {
                    return Err(HttpError::Conflict);
                }
                let event = Event {
                    event_id: events::identity(*operation, "webhook-test"),
                    event_type: EventType::Test,
                    version: 1,
                    occurred_at: events::now_on(c).await.map_err(map_error)?,
                    tenant_id: t,
                    device_id: device.clone(),
                    data: EventData::Test,
                };
                if !self.host.eligible(c, &s, &event).await.map_err(map_error)? {
                    return Err(HttpError::Forbidden);
                }
                // Test is targeted, so persist its immutable event without broadcasting a source job.
                event.validate().map_err(map_error)?;
                sqlx::query("INSERT INTO mdm_webhook.events(tenant_id,id,document,body) VALUES($1,$2,$3,$4)")
                    .bind(t)
                    .bind(event.event_id)
                    .bind(serde_json::to_value(&event).map_err(|_| HttpError::Malformed)?)
                    .bind(serde_json::to_vec(&event).map_err(|_| HttpError::Malformed)?)
                    .execute(&mut *c)
                    .await
                    .map_err(|_| unavailable())?;
                let id = webhooks::fanout::queue(c, &event, &s, Some(*operation), None)
                    .await
                    .map_err(map_error)?;
                let response = serde_json::json!({"id":id,"eventId":event.event_id});
                storage::record_operation(c, t, *operation, &input, &response)
                    .await
                    .map_err(map_error)?;
                response
            }
            Command::Deliveries(_) | Command::Delivery(_) => {
                let (after, only) = match command {
                    Command::Deliveries(a) => (*a, None),
                    Command::Delivery(id) => (None, Some(*id)),
                    _ => unreachable!(),
                };
                let rows = storage::deliveries(c, t, after, only)
                    .await
                    .map_err(map_error)?;
                let next = rows.last().and_then(|v| v.get("id")).cloned();
                let mut items = Vec::new();
                for row in rows {
                    let id = serde_json::from_value(row["eventId"].clone())
                        .map_err(|_| unavailable())?;
                    let event = storage::event(c, t, id).await.map_err(map_error)?;
                    if authority::read(p, &event).is_ok() {
                        items.push(row)
                    }
                }
                if only.is_some() && items.is_empty() {
                    return Err(HttpError::NotFound);
                }
                serde_json::json!({"items":items,"nextCursor":next})
            }
            Command::Replay {
                delivery,
                operation,
            } => {
                let event = storage::delivery_event(c, t, *delivery)
                    .await
                    .map_err(map_error)?;
                authority::read(p, &event)?;
                webhooks::fanout::replay(c, t, *delivery, *operation)
                    .await
                    .map_err(map_error)?
            }
            Command::Redrive { delivery, .. } => {
                let b = storage::binding(c, t, *delivery).await.map_err(map_error)?;
                authority::read(p, &b.event)?;
                let op = operation(command).ok_or(HttpError::Malformed)?;
                let input = ("redrive-intent", command);
                if let Some(old) = storage::replay_operation(c, t, op, &input)
                    .await
                    .map_err(map_error)?
                {
                    return Ok((old, true));
                }
                let response = serde_json::json!({"authorized":true});
                storage::record_operation(c, t, op, &input, &response)
                    .await
                    .map_err(map_error)?;
                response
            }
        };
        Ok((value, replayed))
    }
}
impl rss_mdm_management_http::webhooks::Source for Backend {
    fn execute<'a>(
        &'a self,
        proof: Arc<AuthorizedPrincipal>,
        audit: RequestAudit,
        command: Command,
    ) -> futures::future::BoxFuture<'a, Result<Value, HttpError>> {
        Box::pin(async move {
            if matches!(command, Command::Redrive { .. }) {
                self.redrive(proof, audit, command).await
            } else {
                self.execute_transaction(proof, audit, command).await
            }
        })
    }
}
impl rss_runtime::ManagedResource for Backend {
    fn name(&self) -> &str {
        "webhook-recovery"
    }
    async fn shutdown(&self) -> Result<(), rss_runtime::ShutdownError> {
        self.recovery.close().await;
        Ok(())
    }
    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
}
