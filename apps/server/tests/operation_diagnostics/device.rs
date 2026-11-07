//! Retained background association metadata and current scoped authorization.
use super::*;
use rss_mdm_audit_integration::{
    AuditIntent, Fact, Origin, RequestAudit, StorageProfile, budget::AuditBudget,
};
use rss_mdm_device_service::{Association, Member, ReceiptNamespace, State};
use rss_mdm_inventory::Channel;

pub(super) struct Seed {
    pub operation: Uuid,
    pub restricted_cookie: String,
}
pub(super) async fn seed(c: &Context) -> Result<Seed> {
    let operation = Uuid::new_v4();
    let value = Association {
        id: Uuid::new_v4(),
        version: 1,
        state: State::Confirmed,
        members: vec![
            Member {
                device: "background-mdm".into(),
                channel: Channel::Mdm,
                registration_id: Uuid::new_v4(),
                generation: 1,
            },
            Member {
                device: "background-agent".into(),
                channel: Channel::Agent,
                registration_id: Uuid::new_v4(),
                generation: 1,
            },
        ],
        evidence: "automatic unique hardware match".into(),
        hardware: Default::default(),
        confirmed_by: ReceiptNamespace::AUTOMATIC_ACTOR.into(),
        confirmed_at: 1700000000,
        revoked_by: None,
        revoked_at: None,
        reason: None,
    };
    sqlx::query("INSERT INTO mdm_devices.operations(tenant_id,operation_id,actor,instance,digest,result) VALUES($1::uuid,$2,$3,'system',$4,$5)")
        .bind(c.tenant.to_string()).bind(operation).bind(ReceiptNamespace::AUTOMATIC_ACTOR)
        .bind(vec![17_u8;32]).bind(serde_json::to_value(&value)?).execute(&c.operator).await?;
    let audit = RequestAudit::new(
        Origin::Background,
        StorageProfile::Mdm,
        c.tenant.to_string(),
        "device_association_automatic",
        AuditIntent::Management,
    );
    audit.identify_service(ReceiptNamespace::AUTOMATIC_ACTOR);
    audit.owned_operation(
        rss_mdm_audit_integration::operation::OperationOwner::DeviceManagement,
        operation,
        "device_association_automatic",
        AuditIntent::Management,
    );
    audit.target(&value.id.to_string());
    let fact = Fact::business(
        &audit,
        rss_mdm_audit_integration::operation::OperationOwner::DeviceManagement,
        &format!("device_association:{operation}"),
        200,
        "success",
        None,
    )?
    .with_details(serde_json::json!({"association":value}))?;
    let budget = AuditBudget::new(Duration::from_secs(5));
    c.audit
        .write(
            c.tenant,
            &budget.source_control(),
            (&c.audit, &fact),
            |(store, fact), tx| Box::pin(async move { store.append(tx, fact).await }),
        )
        .await
        .fold(Ok, Err, Err, Err, Err, Err)?;
    audit.finalize(None);
    let restricted = c.account(&[Permission::InventoryRead]).await?;
    let rule = Rule {
        subject: Subject::User {
            user: restricted.user.clone(),
        },
        grants: vec![access::Grant {
            operation: Permission::InventoryRead,
            scope: Scope::Device {
                id: "background-mdm".into(),
            },
        }],
    };
    sqlx::query("UPDATE mdm_access.authorization_rules SET document=$3,revision=revision+1 WHERE tenant_id=$1::uuid AND id=$2")
        .bind(c.tenant.to_string()).bind(restricted.rule).bind(serde_json::to_value(rule)?).execute(&c.operator).await?;
    let access::credential::RequestCredential::Cookie(cookie) = restricted.credential()? else {
        anyhow::bail!("cookie required")
    };
    Ok(Seed {
        operation,
        restricted_cookie: format!("__Host-identity-session={}", cookie.expose()),
    })
}

/// The production scheduler's lease isolates progress observations without holding database locks.
pub(super) struct ProgressLease {
    store: rss_reconcile_postgres::PgStore,
    claim: rss_reconcile_postgres::PgClaim,
    pool: sqlx::PgPool,
}
pub(super) async fn hold_retirement(c: &Context, operation: Uuid) -> Result<ProgressLease> {
    use rss_reconcile::DurableStore;
    let pool = c.inputs.pool("shared", "mdm_scheduler_runtime").await?;
    let timer = rss_mdm_device_service::control::recovery::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
    let store = rss_reconcile_postgres::PgStore::new(pool.clone(), &control).await?;
    let scope = rss_mdm_device_service::control::recovery_scope(c.tenant);
    let target = rss_reconcile::Target::new(scope.clone(), format!("retirement:{operation}"))?;
    store
        .wake(
            &target,
            &rss_reconcile::ResourceSet::empty(c.tenant),
            &control,
        )
        .await?;
    let batch = store
        .claim_due(&scope, 1, Duration::from_secs(120), &control)
        .await?;
    let claim = batch
        .claims
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("retirement claim missing"))?;
    anyhow::ensure!(claim.target() == &target, "another retirement claimed");
    Ok(ProgressLease { store, claim, pool })
}
impl ProgressLease {
    pub(super) async fn release(self) -> Result<()> {
        use rss_reconcile::DurableStore;
        let timer = rss_mdm_device_service::control::recovery::Timer::new();
        let cancel = tokio_util::sync::CancellationToken::new();
        let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
        self.store.release(&self.claim, &control).await?;
        self.pool.close().await;
        Ok(())
    }
}
