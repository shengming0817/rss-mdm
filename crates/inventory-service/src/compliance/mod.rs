//! Product composition: Inventory owns facts, Group owns predicates and membership,
//! Compliance owns assessments. Existing automation owns all task progress.
use crate::authorization::{Permission, Snapshot, context::AuthorizedPrincipal};
use crate::transaction::*;
use crate::{Error, Failure};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_compliance_postgres as pg;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::{Value, json};
use sqlx::Row;
use std::sync::Arc;
use uuid::Uuid;
pub mod directory;
mod dispatch;
mod evaluation;
mod freshness;
mod model;
mod read;
pub use dispatch::group_changed;

pub use model::*;
pub struct Compliance {
    audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    tenant: TenantId,
    clock: Arc<dyn crate::clock::Clock>,
    groups: Arc<rss_mdm_group_postgres::GroupStore>,
    asset_reader: crate::assets::planning::SnapshotReader,
    tasks: Arc<dyn crate::tasks::Tasks>,
    cursor_key: ring::hmac::Key,
}
pub struct Dependencies {
    pub audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    pub tenant: TenantId,
    pub clock: Arc<dyn crate::clock::Clock>,
    pub groups: Arc<rss_mdm_group_postgres::GroupStore>,
    pub tasks: Arc<dyn crate::tasks::Tasks>,
    pub cursor_key: ring::hmac::Key,
}
impl Compliance {
    pub fn new(d: Dependencies) -> Self {
        Self {
            audit_store: d.audit_store,
            runtime: d.runtime,
            tenant: d.tenant,
            clock: d.clock,
            groups: d.groups,
            tasks: d.tasks,
            asset_reader: crate::assets::planning::SnapshotReader { tenant: d.tenant },
            cursor_key: d.cursor_key,
        }
    }
    fn tenant(&self) -> TenantId {
        self.tenant
    }
    async fn rule(&self, tx: &mut PgTransaction<'_>, id: Uuid) -> Result<Rule> {
        let t = self.tenant();
        tx.with_connection(move |c| {
            Box::pin(async move { pg::rule::<crate::assets::InventoryCondition>(c, t, id).await })
        })
        .await?
        .ok_or_else(|| Error::NotFound.into())
    }
    pub async fn execute(
        &self,
        command: &Command,
        audit: &RequestAudit,
        proof: &AuthorizedPrincipal,
    ) -> std::result::Result<Value, Error> {
        proof.check_live()?;
        proof.bind_audit(audit)?;
        crate::transaction::run(
            &self.audit_store,
            &self.runtime,
            self.tenant(),
            audit,
            (self, command, audit, proof),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, command, audit, proof) = *ctx;
                    if command.operation().is_some() {
                        let tenant = tx.tenant_id();
                        tx.with_connection(move |c| {
                            Box::pin(async move {
                                rss_mdm_inventory_postgres::lock_watermark_in(c, tenant).await
                            })
                        })
                        .await?;
                    }
                    let current = query_authority(tx, proof).await?;
                    authorize(&current, proof, command)?;
                    crate::transaction::lock(tx).await?;
                    s.audit_store.prepare_in(tx, audit, &[]).await?;
                    let actor = audit.snapshot();
                    let hash = fingerprint(&(
                        "compliance",
                        audit.tenant(),
                        actor.actor,
                        actor.instance,
                        command,
                    ))?;
                    let operation = command.operation();
                    let t = s.tenant();
                    if let Some(id) = operation {
                        if id.is_nil() {
                            return Err(Error::Malformed.into());
                        }
                        if let Some((old, response)) = tx
                            .with_connection(move |c| {
                                Box::pin(async move { pg::replay(c, t, id).await })
                            })
                            .await?
                        {
                            if old != hash {
                                return Err(Error::Conflict.into());
                            }
                            s.audit(tx, audit, operation, true).await?;
                            proof.check_live()?;
                            return Ok(response);
                        }
                    }
                    let response = s.handle(tx, command).await?;
                    if let Some(id) = operation {
                        let h = hash.clone();
                        let v = response.clone();
                        tx.with_connection(move |c| {
                            Box::pin(async move { pg::receipt(c, t, id, &h, &v).await })
                        })
                        .await?;
                    }
                    s.audit(tx, audit, operation, false).await?;
                    proof.check_live()?;
                    Ok(response)
                })
            },
            TransactionOwner::Compliance,
        )
        .await
    }
    async fn audit(
        &self,
        tx: &mut PgTransaction<'_>,
        audit: &RequestAudit,
        id: Option<Uuid>,
        replay: bool,
    ) -> Result<()> {
        if let Some(id) = id {
            let fact = rss_mdm_audit_integration::Fact::business(
                audit,
                &format!("compliance:{id}"),
                200,
                "success",
                None,
            )?;
            (if replay {
                Ok(())
            } else {
                self.audit_store.append_in(tx, &fact).await
            })?;
        } else {
            audit.require_final_request();
        }
        Ok(())
    }
    async fn handle(&self, tx: &mut PgTransaction<'_>, command: &Command) -> Result<Value> {
        let t = self.tenant();
        match command {
            Command::Read { id } => json(&RuleView::from(self.rule(tx, *id).await?)),
            Command::Version { id, revision } => {
                let id = *id;
                let revision = *revision;
                if revision < 1 {
                    return Err(Error::Malformed.into());
                }
                let row = tx
                    .with_connection(move |c| {
                        Box::pin(async move {
                            pg::version::<crate::assets::InventoryCondition>(c, t, id, revision)
                                .await
                        })
                    })
                    .await?
                    .ok_or(Error::NotFound)?;
                Ok(json!({"id":id,"revision":revision,"definition":row}))
            }
            Command::Put { id, request } => self.put(tx, *id, request).await,
            Command::Delete { id, request } => {
                let mut rule = self.rule(tx, *id).await?;
                if rule.revision as u64 != request.expected_revision {
                    return Err(Error::Conflict.into());
                }
                rule.revision = rule.revision.checked_add(1).ok_or(Error::Malformed)?;
                rule.enabled = false;
                rule.definition.enabled = false;
                let copy = rule.clone();
                let id = *id;
                tx.with_connection(move |c| {
                    Box::pin(async move {
                        if !pg::put(c, t, &copy, &[], &[]).await? {
                            return Err(sqlx::Error::Protocol("rule deletion rejected".into()));
                        }
                        pg::delete(c, t, id).await
                    })
                })
                .await?;
                Ok(json!({"id":id,"revision":rule.revision,"deleted":true}))
            }
            Command::Recompute { id, request } => {
                let r = self.rule(tx, *id).await?;
                if r.revision as u64 != request.expected_revision || !r.enabled {
                    return Err(Error::Conflict.into());
                }
                let task = self.enqueue(tx, &r).await?;
                Ok(json!({"task":task}))
            }
            Command::Task { id, task } => self.task(tx, *id, *task).await,
            Command::Current { device } => self.current(tx, device).await,
            Command::History {
                device,
                subject,
                page,
            } => self.history(tx, device, subject, page).await,
        }
    }
}

impl Compliance {
    async fn put(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        request: &crate::operation::Operation<Definition>,
    ) -> Result<Value> {
        let t = self.tenant();
        if id.is_nil() {
            return Err(Error::Malformed.into());
        }
        crate::assets::filter::require_visible(
            &crate::assets::catalog_in(tx, t, i64::MAX).await?,
            &request.input.criteria.criteria,
        )?;
        let fields = validate_definition(
            &request.input,
            t,
            id,
            &crate::assets::catalog_in(tx, t, i64::MAX).await?,
        )?;
        let target = id;
        let old = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    pg::rule::<crate::assets::InventoryCondition>(c, t, target).await
                })
            })
            .await?;
        if old.as_ref().map_or(0, |r| r.revision as u64) != request.expected_revision {
            return Err(Error::Conflict.into());
        }
        if old.is_none() {
            let rules = tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        pg::rules::<crate::assets::InventoryCondition>(c, t, None, 101).await
                    })
                })
                .await?;
            if rules.len() >= 100 {
                return Err(Error::Malformed.into());
            }
        }
        let groups = request.input.groups();
        for id in &groups {
            let g = checked_input(rss_mdm_group_postgres::GroupId::parse(&id.to_string()))?;
            let group = checked(self.groups.lock_reference_target_in(tx, g).await?)?;
            if group.asset_context != rss_mdm_group_postgres::AssetContext::Endpoint {
                return Err(Error::Malformed.into());
            }
        }
        let revision = i64::try_from(request.expected_revision)
            .ok()
            .and_then(|v| v.checked_add(1))
            .ok_or(Error::Malformed)?;
        let rule = Rule {
            id,
            revision,
            enabled: request.input.enabled,
            desired: None,
            current_run: old.and_then(|r| r.current_run),
            definition: request.input.clone(),
        };
        let row = rule.clone();
        let stored = tx
            .with_connection(move |c| {
                Box::pin(async move { pg::put(c, t, &row, &fields, &groups).await })
            })
            .await?;
        if !stored {
            return Err(Error::Malformed.into());
        }
        let task = if rule.enabled {
            Some(self.enqueue(tx, &rule).await?)
        } else {
            None
        };
        Ok(json!({"id":id,"revision":revision,"task":task}))
    }
}

fn authorize(
    current: &Snapshot,
    proof: &AuthorizedPrincipal,
    command: &Command,
) -> std::result::Result<(), Error> {
    let (permission, device) = match command {
        Command::Put { .. } | Command::Delete { .. } => (Permission::ComplianceWrite, None),
        Command::Recompute { .. } => (Permission::ComplianceRecompute, None),
        Command::Current { device } | Command::History { device, .. } => {
            (Permission::ComplianceRead, Some(device.as_str()))
        }
        _ => (Permission::ComplianceRuleRead, None),
    };
    current.require(proof, permission, device)?;
    if matches!(command, Command::Put { .. }) {
        current.inventory_devices(proof)?;
    }
    if let Command::Put { request, .. } = command
        && !request.input.groups().is_empty()
    {
        current.require(proof, Permission::GroupRead, None)?;
    }
    if matches!(command, Command::Task { .. }) {
        current.require_all_devices(proof, Permission::ComplianceRead)?;
    }
    Ok(())
}
