//! Native collection delivery is independent of the report's authoritative terminal facts.
use super::{
    frozen::Published,
    model::{NativeDelivery, NativeRun, Target},
    policy::CollectionPolicy,
    service::Transactions,
};
use crate::{Error, transaction::*};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::{PgConnection, Row};
use uuid::Uuid;
pub async fn advance_in(
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    run: &mut NativeRun,
    plan: &CollectionPolicy,
    now: i64,
) -> Result<()> {
    let Published::NativeCollection { action, .. } = &plan.frozen else {
        return Err(Error::Malformed.into());
    };
    if run.delivery != NativeDelivery::Queued || run.available_at > now || run.deadline <= now {
        return Ok(());
    }
    if plan
        .entry_in(service, tx, &run.target.device, now)
        .await?
        .is_none()
        || !plan.run_admission_in(service, tx, &run.target).await?
    {
        return Ok(());
    }
    let tenant = tx.tenant_id().to_string();
    let id = run.id;
    let accepted:bool=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT gateway_accepted FROM mdm_inventory.collection_tasks WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).fetch_one(c).await})).await?;
    if !accepted {
        return Ok(());
    }
    let target = crate::collection::native::Target {
        tenant: tx.tenant_id(),
        device: run.target.device,
    };
    let definition = action.collection.clone();
    let template = action.definition.clone();
    let deadline = run.deadline;
    tx.with_connection(move |c| {
        Box::pin(async move {
            crate::collection::native::start(c, &target, id, definition, template, deadline)
                .await
                .map_err(|_| sqlx::Error::Protocol("native collection admission".into()))
        })
    })
    .await?;
    let native = service.native.clone();
    let tenant = tx.tenant_id();
    let platform = action.input.platform;
    let facts = tx
        .with_connection(move |c| {
            Box::pin(async move { Ok(native.prepare_on(c, tenant, id, platform).await) })
        })
        .await??;
    service.audit_store.append_batch_in(tx, &facts).await?;
    run.collection_run = Some(id);
    run.delivery = NativeDelivery::Prepared;
    super::storage::save_native(service, tx, run).await
}
pub async fn sent_on(c: &mut PgConnection, tenant: &str, id: Uuid) -> Result<()> {
    sqlx::query("UPDATE mdm_inventory.collection_tasks SET native_delivery='sent',started_at=floor(extract(epoch FROM clock_timestamp()))::bigint WHERE tenant_id=$1::uuid AND id=$2 AND channel='mdm' AND native_delivery='prepared' AND collection_run IS NOT NULL")
        .bind(tenant).bind(id).execute(c).await?;
    Ok(())
}
pub async fn eligible_on(
    service: &Transactions,
    c: &mut PgConnection,
    tenant: TenantId,
    target: &Target,
    id: Uuid,
) -> Result<bool> {
    let row=sqlx::query("SELECT v.frozen, t.native_delivery, t.started_at, t.source_objects FROM mdm_inventory.collection_tasks AS t INNER JOIN mdm_policy.versions AS v ON (v.tenant_id, v.id) = (t.tenant_id, t.policy_version) INNER JOIN mdm_policy.policies AS p ON (p.tenant_id, p.id) = (v.tenant_id, v.policy) WHERE t.tenant_id = CAST($1 AS uuid) AND t.id = $2 AND t.device = $3 AND t.device = $4 AND t.channel = 'mdm' AND t.deadline > floor(EXTRACT(EPOCH FROM clock_timestamp())) AND p.state = 'enabled' AND t.native_delivery <> 'cancelled'")
        .bind(tenant.to_string()).bind(id).bind(target.device.into_uuid()).bind(target.device.into_uuid()).fetch_optional(&mut *c).await?;
    let Some(row) = row else {
        return Ok(false);
    };
    if row.try_get::<Option<i64>, _>("started_at")?.is_none() {
        let evidence: Vec<crate::objects::DeviceObject> =
            stored(serde_json::from_value(row.try_get("source_objects")?))?;
        if !service
            .source
            .evidence_valid_on(
                c,
                tenant,
                rss_mdm_inventory::Channel::Mdm,
                &target.device,
                &evidence,
            )
            .await?
        {
            return Ok(false);
        }
    }
    let Published::NativeCollection { action, .. } =
        stored(serde_json::from_value::<Published>(row.try_get("frozen")?))?
    else {
        return Err(Error::Malformed.into());
    };
    service
        .native
        .eligible_on(c, tenant, target, &action.definition)
        .await
}
pub async fn definition_on(
    c: &mut PgConnection,
    tenant: &str,
    id: Uuid,
) -> Result<rss_mdm_resource::NativeCollectionDefinition> {
    let value=sqlx::query_scalar("SELECT v.frozen FROM mdm_inventory.collection_tasks t JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(t.tenant_id,t.policy_version) WHERE t.tenant_id=$1::uuid AND t.id=$2 AND t.channel='mdm'").bind(tenant).bind(id).fetch_optional(c).await?.ok_or(Error::NotFound)?;
    let Published::NativeCollection { action, .. } = stored(serde_json::from_value(value))? else {
        return Err(Error::Malformed.into());
    };
    Ok(action.definition)
}

impl super::CollectionService {
    pub async fn eligible_on(
        &self,
        c: &mut PgConnection,
        p: &rss_mdm_registration_service::DevicePrincipal,
        id: Uuid,
        delivery: bool,
    ) -> Result<bool> {
        if p.tenant() != self.transactions.tenant {
            return Err(Error::Unauthorized.into());
        }
        if delivery
            && !rss_mdm_registration_service::lifecycle::work_allowed_in(
                rss_mdm_install_support::StorageProfile::Mdm,
                c,
                &p.tenant().to_string(),
                p.device(),
            )
            .await?
        {
            return Ok(false);
        }
        eligible_on(
            &self.transactions,
            c,
            p.tenant(),
            &Target {
                device: *p.device(),
            },
            id,
        )
        .await
    }
    pub async fn authenticated_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &rss_mdm_registration_service::DevicePrincipal,
    ) -> Result<()> {
        self.transactions.validate_in(tx)?;
        super::checkins::record(&self.transactions.reconcile_messaging, tx, p).await
    }
    pub async fn finished_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &rss_mdm_registration_service::DevicePrincipal,
        ids: &[Uuid],
    ) -> Result<()> {
        self.transactions.validate_in(tx)?;
        for &id in ids {
            let run = super::storage::native_run(tx, id).await?;
            if run.target.device != *p.device() {
                return Err(Error::Unauthorized.into());
            }
            super::recovery::recover_one(self, tx, id).await?;
        }
        Ok(())
    }
}
