use crate::*;
use rss_reconcile::{Scope, Target};
pub const fn domain(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    match profile {
        rss_mdm_install_support::StorageProfile::Mdm => "mdm.scopes",
        rss_mdm_install_support::StorageProfile::Da => "da.scopes",
    }
}
pub fn target(
    profile: rss_mdm_install_support::StorageProfile,
    tenant: rss_request_context::TenantId,
    id: Uuid,
) -> Target {
    Target::new(
        Scope::new(tenant, domain(profile)).expect("constant Scope domain"),
        format!("task:{id}"),
    )
    .expect("UUID task")
}
impl Scopes {
    pub(crate) async fn enqueue_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        scope: Uuid,
    ) -> transaction::Result<Uuid> {
        let id = self.store.enqueue_in(tx, id, scope).await?;
        self.reconcile_messaging
            .wake_in(
                tx,
                &target(self.profile(), tx.tenant_id(), id),
                &rss_reconcile::ResourceSet::empty(tx.tenant_id()),
                (),
                |_, tx| {
                    Box::pin(async {
                        tx.with_connection(|c| {
                            Box::pin(async {
                                sqlx::query("SELECT pg_notify('mdm_work','scopes')")
                                    .execute(c)
                                    .await?;
                                Ok(())
                            })
                        })
                        .await
                    })
                },
            )
            .await?;
        Ok(id)
    }
    pub(crate) async fn finish_in(
        &self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        failure: Option<&str>,
    ) -> transaction::Result<()> {
        let task = self.store.task_in(tx, id).await?;
        if !self.store.finish_task_in(tx, id, failure).await? {
            return Ok(());
        }
        let action = match failure {
            None => "automation_completed",
            Some("superseded") => "automation_superseded",
            Some(_) => "automation_failed",
        };
        let audit = RequestAudit::new(
            rss_mdm_audit_integration::Origin::Background,
            self.profile(),
            binding,
            action,
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("service:scope");
        audit.resource_target(
            rss_mdm_audit_integration::TargetKind::Scope,
            &task.scope.to_string(),
        );
        audit.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::ScopeTask,
            id,
            action,
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        let fact = rss_mdm_audit_integration::Fact::business(
            &audit,
            rss_mdm_audit_integration::operation::OperationOwner::ScopeTask,
            &format!("scope-task:{id}:{action}"),
            200,
            if failure.is_none() {
                "success"
            } else {
                "failed"
            },
            None,
        )?;
        self.audit_store.append_in(tx, &fact).await?;
        audit.finalize(None);
        Ok(())
    }
    pub async fn task_read_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        target: Option<&str>,
    ) -> transaction::Result<Value> {
        let task = self.store.task_in(tx, id).await?;
        if target.is_some_and(|t| t != task.scope.to_string()) {
            return Err(Error::NotFound.into());
        }
        let run = self.store.run_in(tx, id).await?;
        let (processed, members) = run
            .as_ref()
            .map_or((0, 0), |r| (r.object_count, r.member_count));
        let status = match task.failure.as_deref() {
            Some("superseded") => "superseded",
            Some(_) => "failed",
            None if task.completed => "completed",
            None if task.forwarded => "running",
            _ => "pending",
        };
        Ok(
            serde_json::json!({"replacement_task":task.replacement,"failure_detail":task.failure_detail,"task":id,"kind":"scope","target":task.scope.to_string(),"status":status,"processed":processed,"members":members,"failure":task.failure}),
        )
    }
}

impl Scopes {
    pub async fn task_receipt(
        &self,
        p: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
        id: Uuid,
    ) -> std::result::Result<Option<rss_mdm_audit_integration::operation::ReceiptSummary>, Error>
    {
        crate::transaction::inspect(&self.runtime, p.binding(), (self, p), |(s, p), tx| {
            Box::pin(async move {
                crate::action_admission::current(tx, p).await?.require(
                    p,
                    rss_mdm_authorization_service::Permission::PolicyRead,
                    None,
                )?;
                let task = s.store.task_in(tx, id).await?;
                let mut value = rss_mdm_audit_integration::operation::ReceiptSummary::new(id);
                value.object = Some(task.scope.to_string());
                value.accepted = Some(true);
                value.executions.push(id);
                value.state = Some(
                    match task.failure.as_deref() {
                        Some("superseded") => "superseded",
                        Some(_) => "failed",
                        None if task.completed => "completed",
                        None if task.forwarded => "running",
                        _ => "pending",
                    }
                    .into(),
                );
                p.check_live()?;
                Ok(Some(value))
            })
        })
        .await
    }
}

/// Wake only this owner's input target in the caller's already-admitted runtime.
pub async fn wake_inputs_in(
    profile: rss_mdm_install_support::StorageProfile,
    store: &rss_reconcile_postgres::PgMessagingStore,
    tx: &mut PgTransaction<'_>,
) -> std::result::Result<(), rss_transactional_messaging_postgres::PgError> {
    let tenant = tx.tenant_id();
    let epoch = tx.expected_epoch().get();
    let t = tenant.to_string();
    tx.with_connection(move |c| Box::pin(async move {
        let (insert, read) = match profile {
            rss_mdm_install_support::StorageProfile::Mdm => ("INSERT INTO mdm_scope.asset_dispatch(tenant_id,expected_epoch) VALUES($1::uuid,$2) ON CONFLICT DO NOTHING", "SELECT expected_epoch FROM mdm_scope.asset_dispatch WHERE tenant_id=$1::uuid"),
            rss_mdm_install_support::StorageProfile::Da => ("INSERT INTO rss_da.scope_asset_dispatch(tenant_id,expected_epoch) VALUES($1::uuid,$2) ON CONFLICT DO NOTHING", "SELECT expected_epoch FROM rss_da.scope_asset_dispatch WHERE tenant_id=$1::uuid"),
        };
        sqlx::query(insert).bind(&t).bind(epoch).execute(&mut *c).await?;
        let accepted: i64 = sqlx::query_scalar(read).bind(t).fetch_one(c).await?;
        if accepted != epoch { return Err(sqlx::Error::Protocol("scope input epoch mismatch".into())); }
        Ok(())
    })).await?;
    let target = Target::new(
        Scope::new(tenant, domain(profile)).expect("constant scope"),
        "inputs",
    )
    .expect("constant target");
    store
        .wake_in(
            tx,
            &target,
            &rss_reconcile::ResourceSet::empty(tenant),
            (),
            |_, tx| {
                Box::pin(async move {
                    tx.with_connection(|c| {
                        Box::pin(async move {
                            sqlx::query("SELECT pg_notify('mdm_work','scopes')")
                                .execute(c)
                                .await?;
                            Ok(())
                        })
                    })
                    .await
                })
            },
        )
        .await
}
