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
                    let watermark = s.list_watermark(tx).await?;
                    let catalog = catalog_in(tx, s.tenant, watermark).await?;
                    let fields = catalog.fields().map(|f| f.key).collect::<Vec<_>>();
                    let tenant = s.tenant;
                    let ids = devices.clone();
                    let selected = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                Ok(planning::SnapshotReader { tenant }
                                    .sources_on(
                                        c,
                                        watermark,
                                        &ids,
                                        &rss_mdm_inventory::CollectionScope::Device,
                                        &fields,
                                    )
                                    .await)
                            })
                        })
                        .await??;
                    let mut owners = selected
                        .subjects
                        .into_iter()
                        .map(|(scope, (device, _))| (scope, device))
                        .collect::<BTreeMap<_, _>>();
                    let scopes = owners.keys().cloned().collect();
                    let ids = devices.clone();
                    let tenant = s.tenant;
                    let (present, manual) = tx
                        .with_connection(move |c| {
                            Box::pin(rss_mdm_inventory_postgres::directory_presence_in(
                                c, tenant, scopes, ids,
                            ))
                        })
                        .await?;
                    let mut result: BTreeSet<String> = manual.into_iter().collect();
                    for scope in present {
                        result.insert(owners.remove(&scope).ok_or(Error::Malformed)?);
                    }
                    proof.check_live()?;
                    Ok(result)
                })
            },
            crate::transaction::TransactionOwner::Assets,
        )
        .await
    }
}
