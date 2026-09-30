//! Bounded asset-presence projection for the product management identity directory.
use super::*;
use sqlx::Row;
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
                    let tenant = s.tenant.to_string();
                    let ids = devices.clone();
                    let rows = tx
                        .with_connection(move |c| {
                            Box::pin(crate::device::read::active_sources(c, tenant, ids))
                        })
                        .await?;
                    let mut owners = BTreeMap::new();
                    for row in rows {
                        let source: String = row.try_get("source")?;
                        let scope = crate::device::scope(
                            s.tenant,
                            stored(Uuid::parse_str(row.try_get("registration")?))?,
                            &source,
                            stored(Uuid::parse_str(row.try_get("epoch")?))?,
                        )?;
                        owners.insert(
                            checked_input(scope.encode())?,
                            row.try_get::<String, _>("device")?,
                        );
                    }
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
