//! Batch source facts and the sole source-authorization decision for execution grants.
use super::*;
use crate::{frozen::Frozen, source_authority::SourceAuthority};
use serde_json::{Value, json};
use sqlx::Row;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub(super) async fn many(
    source: &dyn SourceAuthority,
    c: &mut PgConnection,
    key: &rss_mdm_native_protection::Protector,
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
            ExecutionAuthority::Policy { .. } => true,
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
            | ExecutionAuthority::AgentInstall { tenant, .. }
            | ExecutionAuthority::Policy { tenant, .. } => {
                groups.entry(tenant.clone()).or_default().push(index)
            }
        }
    }
    for (tenant, indices) in groups {
        let tenant_id =
            rss_request_context::TenantId::parse(&tenant).map_err(|_| Error::Malformed)?;
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
        let policy_claims = configuration_claims(c, &tenant, &indices, requests).await?;
        let ids = indices
            .iter()
            .map(|index| *index as i64)
            .collect::<Vec<_>>();
        let versions = indices
            .iter()
            .map(|index| match &requests[*index].0 {
                ExecutionAuthority::Policy { version, .. }
                | ExecutionAuthority::AgentInstall { version, .. } => Ok(*version),
                _ => Err(Error::Malformed),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let rows=sqlx::query("WITH input AS(SELECT * FROM unnest($2::bigint[],$3::uuid[]) AS x(n,version)),facts AS MATERIALIZED(SELECT x.n,v.frozen,v.policy,p.state='enabled' AS live FROM input x LEFT JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=($1::uuid,x.version) LEFT JOIN mdm_policy.policies p ON(p.tenant_id,p.id)=(v.tenant_id,v.policy)),budget AS(SELECT coalesce(sum(octet_length(frozen::text)),0)::bigint AS bytes FROM facts) SELECT facts.*,budget.bytes FROM budget LEFT JOIN facts ON budget.bytes<=16777216").bind(&tenant).bind(ids).bind(versions).fetch_all(&mut *c).await.map_err(db)?;
        if rows
            .first()
            .ok_or(Error::Malformed)?
            .try_get::<i64, _>("bytes")
            .map_err(db)?
            > 16777216
        {
            return Err(Error::Unavailable(crate::Failure::Capacity));
        }
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
        let mut removals = Vec::new();
        for row in rows {
            let index = row.try_get::<i64, _>("n").map_err(db)? as usize;
            let a = &requests[index].0;
            match a {
                ExecutionAuthority::AgentInstall {
                    policy, package, ..
                } => {
                    let frozen: Option<Value> = row.try_get("frozen").map_err(db)?;
                    if row.try_get::<Option<Uuid>, _>("policy").map_err(db)? != Some(*policy)
                        || !row
                            .try_get::<Option<bool>, _>("live")
                            .map_err(db)?
                            .unwrap_or(false)
                    {
                        continue;
                    }
                    if let Some(value) = frozen
                        && matches!(
                            serde_json::from_value::<Frozen>(value)
                                .map_err(|_| Error::Malformed)?,
                            Frozen::AgentInstall { .. }
                        )
                    {
                        results[index] =
                            packages
                                .get(&package.release.release_id)
                                .is_some_and(|current| {
                                    current.installer_sha256 == package.artifact.sha256
                                        && current.version == package.version
                                });
                    }
                }
                ExecutionAuthority::Policy {
                    policy,
                    version,
                    device,
                    remove,
                    unit,
                    ..
                } => {
                    if row.try_get::<Option<Uuid>, _>("policy").map_err(db)? != Some(*policy) {
                        continue;
                    }
                    let Some(value) = row.try_get::<Option<Value>, _>("frozen").map_err(db)? else {
                        continue;
                    };
                    let Frozen::Configuration { native, exit, .. } =
                        serde_json::from_value(value).map_err(|_| Error::Malformed)?
                    else {
                        continue;
                    };
                    let native = native.open(
                        key,
                        tenant_id,
                        crate::configuration::Owner::Policy {
                            policy: *policy,
                            version: *version,
                        },
                    )?;
                    if *remove
                        && (!matches!(exit, rss_mdm_policy::Exit::Remove)
                            || native.remove.is_none())
                    {
                        continue;
                    }
                    if native.unit_key(key, tenant_id, device)? != *unit {
                        continue;
                    }
                    if *remove {
                        removals.push((index, device.clone(), native.objects()?));
                        results[index] = true;
                    } else {
                        let retain = matches!(exit, rss_mdm_policy::Exit::Retain)
                            && matches!(
                                native.apply,
                                crate::Task::Macos {
                                    request:
                                        rss_mdm_apple_mdm::native::request::Request::Declarations { .. }
                                }
                            );
                        results[index] = retain
                            || row
                                .try_get::<Option<bool>, _>("live")
                                .map_err(db)?
                                .unwrap_or(false)
                            || policy_claims.get(&index) == Some(&true);
                    }
                }
                _ => {}
            }
        }
        if !removals.is_empty() {
            let devices = removals
                .iter()
                .map(|r| r.1.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let mut after = None;
            loop {
                let page = source
                    .configuration_candidates_batch_on(c, tenant_id, &devices, after.as_ref())
                    .await?;
                let versions = page
                    .items
                    .iter()
                    .map(|(_, v)| v.version)
                    .collect::<Vec<_>>();
                if !versions.is_empty() {
                    let sizes=sqlx::query_as::<_,(Uuid,i64)>("SELECT id,octet_length(frozen::text)::bigint FROM mdm_policy.versions WHERE tenant_id=$1::uuid AND id=ANY($2) ORDER BY id").bind(&tenant).bind(&versions).fetch_all(&mut *c).await.map_err(db)?;
                    let expected = versions.iter().copied().collect::<BTreeSet<_>>();
                    if sizes.len() != expected.len() {
                        return Err(Error::Malformed);
                    }
                    let mut offset = 0;
                    while offset < sizes.len() {
                        let end = offset
                            + crate::transaction::input_prefix(
                                sizes[offset..].iter().map(|v| v.1),
                            )?;
                        let ids = sizes[offset..end].iter().map(|v| v.0).collect::<Vec<_>>();
                        let rows=sqlx::query_as::<_,(Option<Uuid>,Option<Uuid>,Option<Value>,i64)>("WITH selected AS MATERIALIZED(SELECT id,policy,frozen FROM mdm_policy.versions WHERE tenant_id=$1::uuid AND id=ANY($2)),budget AS(SELECT coalesce(sum(octet_length(frozen::text)),0)::bigint AS bytes FROM selected) SELECT selected.*,budget.bytes FROM budget LEFT JOIN selected ON budget.bytes<=16777216").bind(&tenant).bind(&ids).fetch_all(&mut *c).await.map_err(db)?;
                        if rows.first().is_some_and(|row| row.3 > 16 * 1024 * 1024) {
                            return Err(Error::Unavailable(crate::Failure::Capacity));
                        }
                        if rows.len() != ids.len() {
                            return Err(Error::Malformed);
                        }
                        for (version, policy, value, _) in rows {
                            let (version, policy, value) = (
                                version.ok_or(Error::Conflict)?,
                                policy.ok_or(Error::Conflict)?,
                                value.ok_or(Error::Conflict)?,
                            );
                            let objects = match serde_json::from_value::<Frozen>(value)
                                .map_err(|_| Error::Malformed)?
                            {
                                Frozen::Configuration { native, .. } => Some(
                                    native
                                        .open(
                                            key,
                                            tenant_id,
                                            crate::configuration::Owner::Policy { policy, version },
                                        )?
                                        .objects()?,
                                ),
                                _ => None,
                            };
                            for (device, candidate) in
                                page.items.iter().filter(|(_, v)| v.version == version)
                            {
                                if policy != candidate.policy {
                                    return Err(Error::Malformed);
                                }
                                for (index, target, expected) in &removals {
                                    if target == device
                                        && objects.as_ref().is_none_or(|objects| {
                                            objects
                                                .iter()
                                                .any(|o| expected.iter().any(|e| o.overlaps(e)))
                                        })
                                    {
                                        results[*index] = false;
                                    }
                                }
                            }
                        }
                        offset = end;
                    }
                }
                if !page.has_more {
                    break;
                }
                after = page.scanned_after;
                if after.is_none() {
                    return Err(Error::Malformed);
                }
            }
        }
    }
    Ok(results)
}

async fn configuration_claims(
    c: &mut PgConnection,
    tenant: &str,
    indices: &[usize],
    requests: &[(ExecutionAuthority, Vec<Permission>)],
) -> Result<BTreeMap<usize, bool>, Error> {
    let input = indices
        .iter()
        .filter_map(|index| match &requests[*index].0 {
            ExecutionAuthority::Policy {
                device,
                unit,
                remove: false,
                ..
            } => Some(json!({"n":index,"device":device,"unit":unit})),
            _ => None,
        })
        .collect::<Vec<_>>();
    if input.is_empty() {
        return Ok(BTreeMap::new());
    }
    let rows=sqlx::query_as::<_,(i64,bool)>("WITH input AS(SELECT value FROM jsonb_array_elements($2)) SELECT (x.value->>'n')::bigint,EXISTS(SELECT 1 FROM mdm_planning.configuration_claims cc JOIN mdm_commands.operations o ON(o.tenant_id,o.id)=(cc.tenant_id,cc.operation) JOIN mdm_policy.policies p ON(p.tenant_id,p.id)=(cc.tenant_id,cc.policy) WHERE cc.tenant_id=$1::uuid AND cc.device=x.value->>'device' AND o.authority->>'unit'=x.value->>'unit' AND p.state='enabled') FROM input x").bind(tenant).bind(Value::Array(input)).fetch_all(c).await.map_err(db)?;
    Ok(rows
        .into_iter()
        .map(|(index, valid)| (index as usize, valid))
        .collect())
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
