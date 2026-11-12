//! The Inventory owner supplies identical presence and field admission for device directory queries.
use super::*;

/// Validate the real catalog, field permissions and bounded dataset selection on the caller's snapshot.
pub fn directory_prepare_on<'a>(
    c: &'a mut sqlx::PgConnection,
    authority: &'a rss_mdm_authorization_service::Snapshot,
    principal: &'a rss_mdm_authorization_service::context::AuthorizedPrincipal,
    query: &'a rss_mdm_query::directory::Query,
) -> std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = std::result::Result<(), rss_mdm_registration_service::Error>,
            > + Send
            + 'a,
    >,
> {
    Box::pin(async move {
        use rss_mdm_registration_service::Error as E;
        let tenant = TenantId::parse(principal.tenant_id()).map_err(|_| E::Malformed)?;
        let catalog = rss_mdm_inventory_postgres::catalog_in(c, tenant)
            .await
            .map_err(|_| E::Storage)?;
        let fields = catalog.fields().map(|f| f.key).collect::<Vec<_>>();
        rss_mdm_inventory_postgres::datasets_in(
            c,
            tenant,
            &rss_mdm_inventory::CollectionScope::Device,
            &fields,
        )
        .await
        .map_err(|_| E::Capacity)?;
        for (selector, key) in [
            ("serialNumber", "device.serial_number"),
            ("hardwareUuid", "device.hardware_uuid"),
        ] {
            if !query.mentions(selector) {
                continue;
            }
            let key = rss_mdm_inventory::FieldKey::parse(key).map_err(|_| E::Corrupt)?;
            let field = catalog.definition(key).map_err(|_| E::Forbidden)?;
            match field.sensitivity {
                rss_mdm_inventory::Sensitivity::Secret => return Err(E::Forbidden),
                rss_mdm_inventory::Sensitivity::Sensitive => authority
                    .require(
                        principal,
                        rss_mdm_authorization_service::Permission::InventorySensitiveRead,
                        None,
                    )
                    .map_err(rss_mdm_authorization_service::Error::from)?,
                rss_mdm_inventory::Sensitivity::Standard => {}
            }
            if !field
                .operations()
                .contains(&rss_mdm_inventory::Operator::Eq)
            {
                return Err(E::Malformed);
            }
            let mut pending = query.filter().into_iter().collect::<Vec<_>>();
            while let Some(expression) = pending.pop() {
                match expression {
                    rss_mdm_query::Expression::Compare {
                        field: name,
                        values,
                        ..
                    } if name == selector => {
                        for value in values {
                            field
                                .validate_scalar(&rss_mdm_inventory::Scalar::String(
                                    value.as_str().ok_or(E::Malformed)?.into(),
                                ))
                                .map_err(|_| E::Malformed)?;
                        }
                    }
                    rss_mdm_query::Expression::And(children)
                    | rss_mdm_query::Expression::Or(children) => pending.extend(children),
                    _ => {}
                }
            }
        }
        Ok(())
    })
}

pub async fn directory_presence_on(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    devices: &[rss_mdm_agent_wire::DeviceId],
) -> crate::transaction::Result<BTreeSet<rss_mdm_agent_wire::DeviceId>> {
    if devices.len() > 1000 {
        return Err(Error::Malformed.into());
    }
    let rows:Vec<uuid::Uuid>=sqlx::query_scalar("SELECT device FROM mdm_assets.device_inventory_presence WHERE tenant_id=$1::uuid AND device=ANY($2)")
        .bind(tenant.to_string()).bind(devices.iter().map(|id| id.into_uuid()).collect::<Vec<_>>()).fetch_all(c).await?;
    Ok(rows
        .into_iter()
        .map(crate::database::device_id)
        .collect::<std::result::Result<_, _>>()?)
}
