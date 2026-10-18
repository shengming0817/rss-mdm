//! One installation-owned policy, read afresh at every programmatic ingress.
use crate::{Error, Permission, Store, context::AuthorizedPrincipal, database::db};
use rss_mdm_audit_integration::{AuditStore, RequestAudit};
use serde::{Deserialize, Serialize};
use sqlx::{Acquire, Row};
use std::net::IpAddr;
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkPolicy {
    pub revision: u64,
    pub networks: Vec<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkChange {
    pub operation_id: Uuid,
    pub expected_revision: u64,
    pub networks: Vec<String>,
}
fn normalized(values: &[String]) -> Result<Vec<String>, Error> {
    if values.len() > 256 {
        return Err(Error::Malformed);
    }
    let mut networks = std::collections::BTreeSet::new();
    for value in values {
        let network: ipnet::IpNet = if value.contains('/') {
            value.parse().map_err(|_| Error::Malformed)?
        } else {
            ipnet::IpNet::from(
                value
                    .parse::<IpAddr>()
                    .map_err(|_| Error::Malformed)?
                    .to_canonical(),
            )
        };
        if let ipnet::IpNet::V6(v6) = network
            && v6.addr().to_ipv4_mapped().is_some()
        {
            return Err(Error::Malformed);
        }
        networks.insert(network.trunc().to_string());
    }
    Ok(networks.into_iter().collect())
}
async fn read_on(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    instance: &str,
) -> Result<NetworkPolicy, Error> {
    let row = sqlx::query("SELECT revision,networks FROM mdm_access.api_network_policy WHERE tenant_id=$1::uuid AND instance=$2::uuid")
        .bind(tenant).bind(instance).fetch_optional(c).await.map_err(db)?;
    match row {
        None => Ok(NetworkPolicy {
            revision: 0,
            networks: Vec::new(),
        }),
        Some(row) => {
            let networks: serde_json::Value = row.try_get("networks").map_err(db)?;
            let networks: Vec<String> =
                serde_json::from_value(networks).map_err(|_| Error::Corrupt)?;
            if normalized(&networks)? != networks {
                return Err(Error::Corrupt);
            }
            Ok(NetworkPolicy {
                revision: row.try_get::<i64, _>("revision").map_err(db)? as u64,
                networks,
            })
        }
    }
}
impl Store {
    async fn installation_network_policy(&self) -> Result<NetworkPolicy, Error> {
        let mut connection = None;
        let result = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            connection = Some(self.acquire().await?);
            let mut tx = connection
                .as_mut()
                .expect("acquired")
                .begin()
                .await
                .map_err(db)?;
            let binding = crate::tenancy::InstallationTenants::load(&mut tx).await?;
            let instance: String = sqlx::query_scalar(
                "SELECT instance_id::text FROM public.mdm_installation WHERE singleton",
            )
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
            Self::configure_transaction(&mut tx, binding.management_tenant()).await?;
            let policy = read_on(&mut tx, binding.management_tenant(), &instance).await?;
            tx.rollback().await.map_err(db)?;
            Ok(policy)
        })
        .await;
        if !matches!(result, Ok(Ok(_)))
            && let Some(connection) = &mut connection
        {
            connection.close_on_drop();
        }
        result.map_err(|_| Error::Deadline)?
    }
    pub async fn require_api_source(&self, address: IpAddr) -> Result<(), Error> {
        let policy = self.installation_network_policy().await?;
        for network in policy.networks {
            if network
                .parse::<ipnet::IpNet>()
                .map_err(|_| Error::Corrupt)?
                .contains(&address.to_canonical())
            {
                return Ok(());
            }
        }
        Err(Error::Forbidden)
    }
    pub async fn network_policy(
        &self,
        proof: &AuthorizedPrincipal,
    ) -> Result<NetworkPolicy, Error> {
        require_cookie(proof)?;
        self.require_tenant_purpose(proof, true).await?;
        proof.require(Permission::AuthorizationRead, None)?;
        self.installation_network_policy().await
    }
}
fn require_cookie(proof: &AuthorizedPrincipal) -> Result<(), Error> {
    if proof.session()?.view().credential_kind != rss_identity_core::session::CredentialKind::Cookie
    {
        return Err(Error::Forbidden);
    }
    proof.check_live()
}
pub async fn change_network_policy(
    store: &AuditStore,
    proof: &AuthorizedPrincipal,
    mut change: NetworkChange,
    audit: &RequestAudit,
) -> Result<NetworkPolicy, Error> {
    use sha2::{Digest, Sha256};
    require_cookie(proof)?;
    proof.require(Permission::AuthorizationWrite, None)?;
    if change.operation_id.is_nil() || change.expected_revision >= i64::MAX as u64 {
        return Err(Error::Malformed);
    }
    change.networks = normalized(&change.networks)?;
    let digest = format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(&("api_network_policy", &change)).map_err(|_| Error::Malformed)?
        )
    );
    let operation = crate::operations::Operation {
        actor: crate::operations::Actor::from_authorized(proof),
        key: change.operation_id,
        digest: &digest,
    };
    audit.operation(change.operation_id, "api_network_policy_change");
    let fact = rss_mdm_audit_integration::Fact::business(
        audit,
        &format!(
            "api_network_policy:{}:{}",
            proof.principal_id(),
            change.operation_id
        ),
        digest.as_bytes(),
        200,
        "success",
        None,
    )?;
    let context = NetworkWrite {
        proof,
        change: &change,
        operation: &operation,
        audit,
    };
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(3));
    let control = budget.control();
    let attempt = store
        .write(
            rss_request_context::TenantId::parse(proof.tenant_id())
                .map_err(|_| Error::Malformed)?,
            &control,
            (store, context, fact),
            |(store, context, fact), tx| {
                Box::pin(async move {
                    let (policy, replayed) = tx
                        .with_connection_context(context, |context, c| {
                            Box::pin(change_on(c, context))
                        })
                        .await?;
                    store
                        .append(tx, fact, replayed)
                        .await
                        .map_err(Error::from)?;
                    if replayed {
                        context.audit.management_result(
                            rss_mdm_audit_integration::ManagementResult::Replayed,
                        );
                    }
                    context.audit.mark_commit_started();
                    Ok(policy)
                })
            },
        )
        .await;
    crate::operations::settle(attempt, audit)
}
struct NetworkWrite<'a> {
    proof: &'a AuthorizedPrincipal,
    change: &'a NetworkChange,
    operation: &'a crate::operations::Operation<'a>,
    audit: &'a RequestAudit,
}
async fn change_on(
    c: &mut sqlx::PgConnection,
    context: &NetworkWrite<'_>,
) -> Result<(NetworkPolicy, bool), Error> {
    let NetworkWrite {
        proof,
        change,
        operation,
        audit,
    } = context;
    require_cookie(proof)?;
    crate::store::lock(c, proof.tenant_id(), proof.instance_id()).await?;
    let snapshot = crate::snapshot_on(c, proof.tenant_id(), proof.instance_id()).await?;
    snapshot.require(proof, Permission::AuthorizationWrite, None)?;
    if !snapshot
        .installation
        .as_ref()
        .ok_or(Error::Corrupt)?
        .is_management(proof.tenant_id())
    {
        return Err(Error::Forbidden);
    }
    if let Some(raw) = crate::operations::replay(c, operation).await? {
        let receipt: crate::Receipt = serde_json::from_str(&raw).map_err(|_| Error::Corrupt)?;
        return Ok((
            NetworkPolicy {
                revision: receipt.revision,
                networks: change.networks.clone(),
            },
            true,
        ));
    }
    let current = read_on(c, proof.tenant_id(), proof.instance_id()).await?;
    if current.revision != change.expected_revision {
        return Err(Error::Conflict);
    }
    let revision = current.revision + 1;
    sqlx::query("INSERT INTO mdm_access.api_network_policy(tenant_id,instance,revision,networks) VALUES($1::uuid,$2::uuid,$3,$4) ON CONFLICT(tenant_id) DO UPDATE SET revision=excluded.revision,networks=excluded.networks")
        .bind(proof.tenant_id()).bind(proof.instance_id()).bind(revision as i64).bind(serde_json::to_value(&change.networks).map_err(|_| Error::Malformed)?).execute(&mut *c).await.map_err(db)?;
    let receipt = crate::Receipt {
        id: Uuid::parse_str(proof.instance_id()).map_err(|_| Error::Corrupt)?,
        revision,
        deleted: false,
    };
    crate::operations::save(
        c,
        operation,
        &serde_json::to_string(&receipt).map_err(|_| Error::Corrupt)?,
        audit,
    )
    .await?;
    Ok((
        NetworkPolicy {
            revision,
            networks: change.networks.clone(),
        },
        false,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn networks_canonicalize_without_expanding_host_authority() {
        let values = [
            "192.0.2.9/24",
            "192.0.2.0/24",
            "::ffff:127.0.0.1",
            "2001:db8::1",
        ]
        .map(str::to_owned);
        assert_eq!(
            normalized(&values).unwrap(),
            vec!["127.0.0.1/32", "192.0.2.0/24", "2001:db8::1/128"]
        );
        for invalid in [
            "::ffff:127.0.0.1/128",
            "192.0.2.1/33",
            "localhost",
            " 127.0.0.1",
        ] {
            assert!(normalized(&[invalid.into()]).is_err());
        }
        assert!(normalized(&vec!["127.0.0.1".into(); 257]).is_err());
    }
}
