//! Batch source facts and the sole source-authorization decision for execution grants.
use super::*;
use crate::frozen::Frozen;
use rss_mdm_scope_service::channels::ChannelTargets;
use serde_json::{Value, json};
use sqlx::Row;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub(super) async fn many(
    _source: &ChannelTargets,
    c: &mut PgConnection,
    _key: &rss_mdm_native_protection::Protector,
    requests: &[(ExecutionAuthority, Vec<Permission>)],
    _now: i64,
    lock: bool,
) -> Result<Vec<bool>, Error> {
    let mut results = vec![false; requests.len()];
    let mut groups = BTreeMap::<String, Vec<usize>>::new();
    for (index, (a, permissions)) in requests.iter().enumerate() {
        if permissions.is_empty() {
            continue;
        }
        let permissions = permissions.iter().chain(a.required());
        let valid = permissions.clone().all(|p| match a {
            ExecutionAuthority::DeviceControl { required, .. }
            | ExecutionAuthority::Credential { required, .. }
            | ExecutionAuthority::Retirement { required, .. } => required.contains(p),
            ExecutionAuthority::Software { .. } => *p == Permission::SoftwareDeploy,
            ExecutionAuthority::AgentInstall { stage, .. } => match stage {
                AgentInstallStage::Install => *p == Permission::SoftwareDeploy,
                AgentInstallStage::Bootstrap | AgentInstallStage::Cleanup { .. } => matches!(
                    p,
                    Permission::SecurityOperate
                        | Permission::ConfigurationWrite
                        | Permission::Enrollment
                ),
            },
        });
        if !valid {
            continue;
        }
        match a {
            ExecutionAuthority::DeviceControl { .. } | ExecutionAuthority::Credential { .. } => {
                results[index] = true
            }
            ExecutionAuthority::Software { tenant, .. }
            | ExecutionAuthority::Retirement { tenant, .. }
            | ExecutionAuthority::AgentInstall { tenant, .. } => {
                groups.entry(tenant.clone()).or_default().push(index)
            }
        }
    }
    for (tenant, indices) in groups {
        let tenant_id =
            rss_request_context::TenantId::parse(&tenant).map_err(|_| Error::Malformed)?;
        if lock {
            let versions = indices
                .iter()
                .filter_map(|i| match &requests[*i].0 {
                    ExecutionAuthority::Software { version, .. }
                    | ExecutionAuthority::AgentInstall { version, .. } => Some(*version),
                    _ => None,
                })
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let policies:Vec<Uuid>=sqlx::query_scalar("SELECT DISTINCT policy FROM mdm_policy.versions WHERE tenant_id=$1::uuid AND id=ANY($2) ORDER BY policy").bind(&tenant).bind(versions).fetch_all(&mut *c).await.map_err(db)?;
            for policy in policies {
                sqlx::query("SELECT mdm_policy.lock_policy($1)")
                    .bind(policy)
                    .execute(&mut *c)
                    .await
                    .map_err(db)?;
            }
        }
        let (software, indices): (Vec<_>, Vec<_>) = indices
            .into_iter()
            .partition(|index| matches!(requests[*index].0, ExecutionAuthority::Software { .. }));
        if !software.is_empty() {
            let inputs = software
                .into_iter()
                .map(|index| (index, requests[index].0.clone()))
                .collect::<Vec<_>>();
            for (index, valid) in
                crate::native_software::authorities_on(c, tenant_id, &inputs, lock).await?
            {
                results[index] = valid;
            }
        }
        let (cleanup, indices): (Vec<_>, Vec<_>) = indices.into_iter().partition(|index| {
            matches!(
                requests[*index].0,
                ExecutionAuthority::AgentInstall {
                    stage: AgentInstallStage::Cleanup { .. },
                    ..
                }
            )
        });
        if !cleanup.is_empty() {
            let inputs = cleanup
                .into_iter()
                .map(|index| (index, requests[index].0.clone()))
                .collect::<Vec<_>>();
            for (index, valid) in
                crate::agent_install::cleanup_authorities_on(c, &tenant, &inputs).await?
            {
                results[index] = valid;
            }
        }
        let (retirements, indices): (Vec<_>, Vec<_>) = indices
            .into_iter()
            .partition(|index| matches!(requests[*index].0, ExecutionAuthority::Retirement { .. }));
        if !retirements.is_empty() {
            let inputs = retirements
                .into_iter()
                .map(|index| (index, requests[index].0.clone()))
                .collect::<Vec<_>>();
            for (index, valid) in retirement_sources(c, &tenant, &inputs).await? {
                results[index] = valid;
            }
        }
        if indices.is_empty() {
            continue;
        }
        // A caller validating Agent installation may not read configuration/retirement tables.
        // Load only the facts belonging to the requested authority families.
        let mut consumers = BTreeMap::<Uuid, Vec<usize>>::new();
        for &index in &indices {
            let version = match &requests[index].0 {
                ExecutionAuthority::AgentInstall { version, .. } => *version,
                _ => return Err(Error::Malformed),
            };
            consumers.entry(version).or_default().push(index);
        }
        let versions = consumers.keys().copied().collect::<Vec<_>>();
        let sizes = sqlx::query_as::<_, (Uuid, i64)>("SELECT id,octet_length(frozen::text)::bigint FROM mdm_policy.versions WHERE tenant_id=$1::uuid AND id=ANY($2) ORDER BY id")
            .bind(&tenant).bind(&versions).fetch_all(&mut *c).await.map_err(db)?;
        let releases = indices
            .iter()
            .filter_map(|i| match &requests[*i].0 {
                ExecutionAuthority::AgentInstall {
                    stage: AgentInstallStage::Install | AgentInstallStage::Bootstrap,
                    package,
                    ..
                } => Some(package.release.release_id),
                _ => None,
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let packages = if lock {
            rss_mdm_software_service::agent_packages::admitted_many_locked_on(
                c, tenant_id, &releases,
            )
            .await
        } else {
            rss_mdm_software_service::agent_packages::admitted_many_on(c, tenant_id, &releases)
                .await
        }
        .map_err(|_| Error::Unavailable(crate::Failure::SoftwareCatalogStorage))?;
        let mut offset = 0;
        while offset < sizes.len() {
            let end =
                offset + crate::transaction::input_prefix(sizes[offset..].iter().map(|v| v.1))?;
            let ids = sizes[offset..end].iter().map(|v| v.0).collect::<Vec<_>>();
            let rows=sqlx::query("WITH facts AS MATERIALIZED(SELECT v.id,v.frozen,v.policy,p.state='enabled' AS live FROM mdm_policy.versions v LEFT JOIN mdm_policy.policies p ON(p.tenant_id,p.id)=(v.tenant_id,v.policy) WHERE v.tenant_id=$1::uuid AND v.id=ANY($2)),budget AS(SELECT coalesce(sum(octet_length(frozen::text)),0)::bigint AS bytes FROM facts) SELECT facts.*,budget.bytes FROM budget LEFT JOIN facts ON budget.bytes<=16777216")
                .bind(&tenant).bind(ids).fetch_all(&mut *c).await.map_err(db)?;
            if rows
                .first()
                .is_some_and(|r| r.get::<i64, _>("bytes") > 16777216)
            {
                return Err(Error::Unavailable(crate::Failure::Capacity));
            }
            // ref: async-graphql src/dataloader/mod.rs — one fact per unique key, then fan out.
            for row in rows {
                let Some(version) = row.try_get::<Option<Uuid>, _>("id").map_err(db)? else {
                    continue;
                };
                let policy: Uuid = row.try_get("policy").map_err(db)?;
                let live: bool = row
                    .try_get::<Option<bool>, _>("live")
                    .map_err(db)?
                    .unwrap_or(false);
                let frozen: Frozen = serde_json::from_value(row.try_get("frozen").map_err(db)?)
                    .map_err(|_| Error::Malformed)?;
                for &index in consumers.get(&version).ok_or(Error::Malformed)? {
                    match &requests[index].0 {
                        ExecutionAuthority::AgentInstall {
                            policy: expected,
                            package,
                            ..
                        } => {
                            results[index] = policy == *expected
                                && live
                                && matches!(frozen, Frozen::AgentInstall { .. })
                                && packages.get(&package.release.release_id).is_some_and(
                                    |current| {
                                        current.installer_sha256 == package.artifact.sha256
                                            && current.version == package.version
                                    },
                                );
                        }

                        _ => return Err(Error::Malformed),
                    }
                }
            }
            offset = end;
        }
    }
    Ok(results)
}

async fn retirement_sources(
    c: &mut PgConnection,
    tenant: &str,
    requests: &[(usize, ExecutionAuthority)],
) -> Result<BTreeMap<usize, bool>, Error> {
    let mut targets = Vec::new();
    let mut executions = BTreeMap::new();
    for (index, authority) in requests {
        let ExecutionAuthority::Retirement {
            execution, device, ..
        } = authority
        else {
            return Err(Error::Malformed);
        };
        targets.push((*execution, device.clone()));
        executions.insert(*index, *execution);
    }
    let lifecycle =
        rss_mdm_device_service::lifecycle::execution_permissions_in(c, tenant, &targets)
            .await
            .map_err(Error::from)?;
    let inputs = requests
        .iter()
        .map(|(n, a)| json!({"n":n,"a":a}))
        .collect::<Vec<_>>();
    let rows=sqlx::query_as::<_,(i64,bool)>("WITH input AS(SELECT value->'a' AS a,(value->>'n')::bigint AS n FROM jsonb_array_elements($2)) SELECT x.n,EXISTS(SELECT 1 FROM mdm_devices.retirement_work w JOIN mdm_access.registrations r ON(r.tenant_id,r.id)=(w.tenant_id,w.registration) WHERE w.tenant_id=$1::uuid AND w.operation=(x.a->>'retirement')::uuid AND w.registration=(x.a->>'registration')::uuid AND w.execution=(x.a->>'execution')::uuid AND r.device=x.a->>'device' AND r.state='active') FROM input x").bind(tenant).bind(Value::Array(inputs)).fetch_all(c).await.map_err(db)?;
    rows.into_iter()
        .map(|(index, valid)| {
            let index = index as usize;
            let execution = executions.get(&index).ok_or(Error::Malformed)?;
            Ok((index, valid && lifecycle.get(execution) == Some(&true)))
        })
        .collect()
}
