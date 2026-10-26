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
        if indices.is_empty() {
            continue;
        }
        let input = indices
            .iter()
            .map(|i| json!({"n":i,"a":requests[*i].0}))
            .collect::<Vec<_>>();
        let rows=sqlx::query(r#"
WITH input AS (SELECT (value->>'n')::bigint AS n,value->'a' AS a FROM jsonb_array_elements($2)),
facts AS MATERIALIZED (
 SELECT x.n,x.a,v.frozen,v.policy,p.state='enabled' AS live,
 EXISTS(SELECT 1 FROM mdm_planning.configuration_claims cc JOIN mdm_commands.operations o ON(o.tenant_id,o.id)=(cc.tenant_id,cc.operation) JOIN mdm_policy.policies cp ON(cp.tenant_id,cp.id)=(cc.tenant_id,cc.policy) WHERE cc.tenant_id=$1::uuid AND cc.device=x.a->>'device' AND o.authority->>'unit'=x.a->>'unit' AND cp.state='enabled') AS claimed,

 EXISTS(SELECT 1 FROM mdm_devices.retirement_work w JOIN mdm_access.registrations r ON(r.tenant_id,r.id)=(w.tenant_id,w.registration) WHERE w.tenant_id=$1::uuid AND w.operation=(x.a->>'retirement')::uuid AND w.registration=(x.a->>'registration')::uuid AND w.execution=(x.a->>'execution')::uuid AND r.device=x.a->>'device' AND r.state='active') AS retirement

 FROM input x LEFT JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=($1::uuid,(x.a->>'version')::uuid) AND x.a->>'kind' IN('policy','agent_install')
 LEFT JOIN mdm_policy.policies p ON(p.tenant_id,p.id)=(v.tenant_id,v.policy)
),budget AS(SELECT coalesce(sum(octet_length(frozen::text)),0)::bigint AS bytes FROM facts)
SELECT facts.*,budget.bytes FROM budget LEFT JOIN facts ON budget.bytes<=16777216
"#).bind(&tenant).bind(Value::Array(input)).fetch_all(&mut *c).await.map_err(db)?;
        if rows
            .first()
            .ok_or(Error::Malformed)?
            .try_get::<i64, _>("bytes")
            .map_err(db)?
            > 16777216
        {
            return Err(Error::Unavailable(crate::Failure::Capacity));
        }
        let retirement_targets = indices
            .iter()
            .filter_map(|i| match &requests[*i].0 {
                ExecutionAuthority::Retirement {
                    execution, device, ..
                } => Some((*execution, device.clone())),
                _ => None,
            })
            .collect::<Vec<_>>();
        let lifecycle = if retirement_targets.is_empty() {
            BTreeMap::new()
        } else {
            rss_mdm_device_service::lifecycle::execution_permissions_in(
                c,
                &tenant,
                &retirement_targets,
            )
            .await
            .map_err(Error::from)?
        };
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
                ExecutionAuthority::Retirement { execution, .. } => {
                    results[index] = row.try_get("retirement").map_err(db)?
                        && lifecycle.get(execution) == Some(&true)
                }
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
                    if let Some(value) = frozen {
                        if matches!(
                            serde_json::from_value::<Frozen>(value)
                                .map_err(|_| Error::Malformed)?,
                            Frozen::AgentInstall { .. }
                        ) {
                            results[index] =
                                packages
                                    .get(&package.release.release_id)
                                    .is_some_and(|current| {
                                        current.installer_sha256 == package.artifact.sha256
                                            && current.version == package.version
                                    });
                        }
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
                            || row.try_get::<bool, _>("claimed").map_err(db)?;
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
                    let rows=sqlx::query_as::<_,(Uuid,Uuid,Value)>("SELECT id,policy,frozen FROM mdm_policy.versions WHERE tenant_id=$1::uuid AND id=ANY($2)").bind(&tenant).bind(versions).fetch_all(&mut *c).await.map_err(db)?;
                    let definitions = rows
                        .into_iter()
                        .map(|(id, policy, frozen)| (id, (policy, frozen)))
                        .collect::<BTreeMap<_, _>>();
                    for (device, candidate) in page.items {
                        let (policy, value) = definitions
                            .get(&candidate.version)
                            .ok_or(Error::Malformed)?;
                        if *policy != candidate.policy {
                            return Err(Error::Malformed);
                        }
                        let objects = match serde_json::from_value::<Frozen>(value.clone())
                            .map_err(|_| Error::Malformed)?
                        {
                            Frozen::Configuration { native, .. } => Some(
                                native
                                    .open(
                                        key,
                                        tenant_id,
                                        crate::configuration::Owner::Policy {
                                            policy: *policy,
                                            version: candidate.version,
                                        },
                                    )?
                                    .objects()?,
                            ),
                            _ => None,
                        };
                        for (index, target, expected) in &removals {
                            if target == &device
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
