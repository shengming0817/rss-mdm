use super::*;
impl Transactions {
    /// Revision, durable wake and source acknowledgement share one transaction.
    pub async fn wake_devices_in(
        &self,
        tx: &mut PgTransaction<'_>,
        devices: &[rss_mdm_agent_wire::DeviceId],
    ) -> Result<()> {
        self.runtime.validate_transaction(tx)?;
        if devices.len() > 1000 {
            return Err(Error::Malformed.into());
        }
        let devices = devices
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if devices.is_empty() {
            return Ok(());
        }
        let tenant = tx.tenant_id();
        let names = devices.clone();
        let known:Vec<rss_mdm_agent_wire::DeviceId>=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar("SELECT device FROM mdm_planning.configuration_devices WHERE tenant_id=$1::uuid AND device=ANY($2)").bind(tenant.to_string()).bind(names.iter().map(|id|id.into_uuid()).collect::<Vec<_>>()).fetch_all(c).await.and_then(crate::configuration::device_ids)
        })).await?;
        let mut interested = known.into_iter().collect::<std::collections::BTreeSet<_>>();
        let missing = devices
            .into_iter()
            .filter(|d| !interested.contains(d))
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            let more = tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        rss_mdm_policy_postgres::candidates::native_interests_on(
                            rss_mdm_install_support::StorageProfile::Mdm,
                            c,
                            tenant,
                            &missing,
                            &["configuration"],
                        )
                        .await
                    })
                })
                .await?;
            interested.extend(more);
        }
        let names = interested.into_iter().collect::<Vec<_>>();
        let updated:Vec<rss_mdm_agent_wire::DeviceId>=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar("INSERT INTO mdm_planning.configuration_devices(tenant_id,device) SELECT $1::uuid,device FROM unnest($2::uuid[]) wanted(device) ORDER BY device ON CONFLICT(tenant_id,device) DO UPDATE SET input_revision=mdm_planning.configuration_devices.input_revision+1 RETURNING device").bind(tenant.to_string()).bind(names.iter().map(|id|id.into_uuid()).collect::<Vec<_>>()).fetch_all(c).await.and_then(crate::configuration::device_ids)
        })).await?;
        for device in updated {
            self.reconcile_messaging
                .wake_in(
                    tx,
                    &target(tenant, &device),
                    &rss_mdm_registration_service::lifecycle::resources::device(
                        tenant,
                        &device,
                        rss_mdm_registration_service::lifecycle::resources::Work::Exclusive,
                    ),
                    (),
                    |_, _| Box::pin(async { Ok(()) }),
                )
                .await?;
        }
        crate::worker_wake::notify_in(tx, crate::worker_wake::Work::Automation).await?;
        Ok(())
    }
}

impl Transactions {
    /// Protocol evidence only wakes desired work; it does not bypass current registration checks.
    pub async fn wake_registration_on(
        &self,
        c: &mut sqlx::PgConnection,
        p: &rss_mdm_registration_service::DevicePrincipal,
    ) -> std::result::Result<(), Error> {
        let tenant = p.tenant().to_string();
        let current:bool=sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM mdm_access.devices WHERE tenant_id = CAST($1 AS uuid) AND id = $2 AND id = $3 AND state = 'active')").bind(&tenant).bind(p.device().into_uuid()).bind(p.device().into_uuid()).fetch_one(&mut *c).await.map_err(db)?;
        if !current {
            return Err(Error::Conflict);
        }
        sqlx::query("INSERT INTO mdm_planning.configuration_devices(tenant_id,device) VALUES($1::uuid,$2) ON CONFLICT(tenant_id,device) DO UPDATE SET input_revision=configuration_devices.input_revision+1").bind(&tenant).bind(p.device().into_uuid()).execute(&mut *c).await.map_err(db)?;
        sqlx::query("SELECT rss_reconcile.wake($1::uuid,$2,$3,$4)")
            .bind(tenant)
            .bind("mdm.policy")
            .bind(target(p.tenant(), p.device()).entity())
            .bind(
                rss_mdm_registration_service::lifecycle::resources::device(
                    p.tenant(),
                    p.device(),
                    rss_mdm_registration_service::lifecycle::resources::Work::Exclusive,
                )
                .keys(),
            )
            .execute(&mut *c)
            .await
            .map_err(db)?;
        crate::worker_wake::notify(c, crate::worker_wake::Work::Automation)
            .await
            .map_err(db)?;
        Ok(())
    }
}

/// Register committed asset/object inputs without interpreting any Policy business state.
pub async fn inputs_in(
    profile: rss_mdm_install_support::StorageProfile,
    store: &rss_reconcile_postgres::PgMessagingStore,
    tx: &mut PgTransaction<'_>,
) -> std::result::Result<(), rss_transactional_messaging_postgres::PgError> {
    let tenant = tx.tenant_id();
    let target = rss_reconcile::Target::new(
        rss_reconcile::Scope::new(tenant, crate::worker::jobs::domain(profile))
            .expect("constant scope"),
        "configuration-inputs",
    )
    .expect("constant target");
    store.wake_in(tx, &target, &rss_reconcile::ResourceSet::empty(tenant), (), |_, tx| Box::pin(async move {
        tx.with_connection(|c| Box::pin(async move {
            sqlx::query("SELECT pg_notify('mdm_work_'||replace(current_setting('rss.tenant_id')::uuid::text,'-',''),'policy')").execute(c).await?;
            Ok(())
        })).await
    })).await
}
