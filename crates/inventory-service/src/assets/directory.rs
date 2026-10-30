//! Bounded asset-presence projection for the product management identity directory.
use super::*;
impl AssetService {
    pub async fn directory_presence(
        &self,
        proof: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
        devices: &[String],
        _audit: &RequestAudit,
    ) -> std::result::Result<BTreeSet<String>, Error> {
        if devices.len() > 1000 || proof.tenant_id() != self.tenant.to_string() {
            return Err(Error::Malformed);
        }
        for device in devices {
            proof.require(
                rss_mdm_authorization_service::Permission::InventoryRead,
                Some(device),
            )?;
        }
        crate::transaction::inspect(
            &self.runtime,
            self.tenant,
            (self, devices.to_vec(), proof),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, devices, proof) = ctx;
                    let current = crate::transaction::query_authority(tx, proof).await?;
                    for device in devices.iter() {
                        current.require(
                            proof,
                            rss_mdm_authorization_service::Permission::InventoryRead,
                            Some(device),
                        )?;
                    }
                    let tenant = s.tenant;
                    let ids = devices.clone();
                    let result = tx
                        .with_connection(move |c| {
                            Box::pin(async move { Ok(Self::presence_on(c, tenant, &ids).await) })
                        })
                        .await??;
                    proof.check_live()?;
                    Ok(result)
                })
            },
            crate::transaction::TransactionOwner::Assets,
        )
        .await
    }
    /// Read only the already-authorized devices on the caller's consistent snapshot.
    pub async fn directory_presence_on(
        &self,
        c: &mut sqlx::PgConnection,
        devices: &[String],
    ) -> crate::transaction::Result<BTreeSet<String>> {
        Self::presence_on(c, self.tenant, devices).await
    }
    async fn presence_on(
        c: &mut sqlx::PgConnection,
        tenant: TenantId,
        devices: &[String],
    ) -> crate::transaction::Result<BTreeSet<String>> {
        if devices.len() > 1000 {
            return Err(Error::Malformed.into());
        }
        let catalog = stored(rss_mdm_inventory_postgres::catalog_in(c, tenant).await)?;
        let fields = catalog.fields().map(|f| f.key).collect::<Vec<_>>();
        let rows = sqlx::query("SELECT * FROM mdm_access.asset_sources_at($1,NULL)")
            .bind(devices)
            .fetch_all(&mut *c)
            .await?;
        let selected = planning::SnapshotReader { tenant }
            .select_sources_on(
                c,
                rows,
                &rss_mdm_inventory::CollectionScope::Device,
                &fields,
            )
            .await?;
        let mut owners = selected
            .subjects
            .into_iter()
            .map(|(scope, (device, _))| (scope, device))
            .collect::<BTreeMap<_, _>>();
        let (present, manual) = rss_mdm_inventory_postgres::directory_presence_in(
            c,
            tenant,
            owners.keys().cloned().collect(),
            devices.to_vec(),
        )
        .await?;
        let mut result: BTreeSet<String> = manual.into_iter().collect();
        for scope in present {
            result.insert(owners.remove(&scope).ok_or(Error::Malformed)?);
        }
        Ok(result)
    }
}
