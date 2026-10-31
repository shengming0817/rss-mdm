//! Read each immutable version once per bounded snapshot batch, then fan out decisions.
//! ref: async-graphql src/dataloader/mod.rs — deduplicate keys before provider reads.
use super::*;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) async fn many(
    source: &rss_mdm_scope_service::channels::ChannelTargets,
    c: &mut PgConnection,
    key: &rss_mdm_native_protection::Protector,
    requests: &[(Authority, Vec<Permission>)],
) -> std::result::Result<Vec<bool>, Error> {
    if requests.len() > 1000 {
        return Err(Error::Malformed);
    }
    let mut results = vec![false; requests.len()];
    let mut groups = BTreeMap::<String, Vec<usize>>::new();
    for (index, (authority, permissions)) in requests.iter().enumerate() {
        if permissions.is_empty() {
            continue;
        }
        let tenant = match authority {
            Authority::Policy { tenant, .. } | Authority::Retirement { tenant, .. } => tenant,
        };
        if matches!(authority, Authority::Retirement { .. })
            && !permissions.iter().all(|p| authority.required().contains(p))
        {
            continue;
        }
        groups.entry(tenant.clone()).or_default().push(index);
    }
    for (tenant, indices) in groups {
        let tenant_id = TenantId::parse(&tenant).map_err(|_| Error::Malformed)?;
        let (retirements, indices): (Vec<_>, Vec<_>) = indices
            .into_iter()
            .partition(|i| matches!(requests[*i].0, Authority::Retirement { .. }));
        if !retirements.is_empty() {
            let inputs = retirements
                .into_iter()
                .map(|i| (i, requests[i].0.clone()))
                .collect::<Vec<_>>();
            for (i, valid) in retirement_sources(c, &tenant, &inputs).await? {
                results[i] = valid
            }
        }
        if indices.is_empty() {
            continue;
        }
        let claims = configuration_claims(c, &tenant, &indices, requests).await?;
        let mut consumers = BTreeMap::<Uuid, Vec<usize>>::new();
        for &index in &indices {
            consumers
                .entry(requests[index].0.version())
                .or_default()
                .push(index);
        }
        let versions = consumers.keys().copied().collect::<Vec<_>>();
        let sizes=sqlx::query_as::<_,(Uuid,i64)>("SELECT id,octet_length(frozen::text)::bigint FROM mdm_policy.versions WHERE tenant_id=$1::uuid AND id=ANY($2) ORDER BY id").bind(&tenant).bind(&versions).fetch_all(&mut *c).await.map_err(db)?;
        let mut removals = Vec::new();
        let mut offset = 0;
        while offset < sizes.len() {
            let end = offset + input_prefix(sizes[offset..].iter().map(|v| v.1))?;
            let ids = sizes[offset..end].iter().map(|v| v.0).collect::<Vec<_>>();
            let rows=sqlx::query("WITH facts AS MATERIALIZED(SELECT v.id,v.frozen,v.policy,p.state='enabled' AS live FROM mdm_policy.versions v LEFT JOIN mdm_policy.policies p ON(p.tenant_id,p.id)=(v.tenant_id,v.policy) WHERE v.tenant_id=$1::uuid AND v.id=ANY($2)),budget AS(SELECT coalesce(sum(octet_length(frozen::text)),0)::bigint AS bytes FROM facts) SELECT facts.*,budget.bytes FROM budget LEFT JOIN facts ON budget.bytes<=16777216")
                .bind(&tenant).bind(ids).fetch_all(&mut *c).await.map_err(db)?;
            rss_mdm_query_postgres::observe_rows("configuration.authority", &rows).map_err(db)?;
            if rows
                .first()
                .is_some_and(|r| r.get::<i64, _>("bytes") > 16777216)
            {
                return Err(Error::Unavailable(Failure::Capacity));
            }
            for row in rows {
                let Some(version) = row.try_get::<Option<Uuid>, _>("id").map_err(db)? else {
                    continue;
                };
                let policy: Uuid = row.try_get("policy").map_err(db)?;
                let live = row
                    .try_get::<Option<bool>, _>("live")
                    .map_err(db)?
                    .unwrap_or(false);
                let Frozen::Configuration { native, exit, .. } =
                    serde_json::from_value(row.try_get("frozen").map_err(db)?)
                        .map_err(|_| Error::Unavailable(Failure::NativeInputIntegrity))?;
                let native = native.open(key, tenant_id, Owner::Policy { policy, version })?;
                let mut accepted = native.apply.permissions()?;
                if let Some(remove) = &native.remove {
                    accepted.extend(remove.permissions()?)
                }
                for &index in consumers.get(&version).ok_or(Error::Malformed)? {
                    let Authority::Policy {
                        policy: expected,
                        device,
                        remove,
                        unit,
                        ..
                    } = &requests[index].0
                    else {
                        return Err(Error::Malformed);
                    };
                    if policy != *expected
                        || !requests[index]
                            .1
                            .iter()
                            .chain(requests[index].0.required())
                            .all(|p| accepted.contains(p))
                    {
                        continue;
                    }
                    if native.unit_key(key, tenant_id, device)? != *unit {
                        continue;
                    }
                    if *remove {
                        if !matches!(exit, rss_mdm_policy::Exit::Remove) || native.remove.is_none()
                        {
                            continue;
                        }
                        removals.push((index, device.clone(), native.objects()?));
                        results[index] = true;
                    } else {
                        let retained = matches!(exit, rss_mdm_policy::Exit::Retain)
                            && matches!(
                                native.apply,
                                Task::Macos {
                                    request:
                                        rss_mdm_apple_mdm::native::request::Request::Declarations { .. }
                                }
                            );
                        results[index] = retained || live || claims.get(&index) == Some(&true);
                    }
                }
            }
            offset = end;
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
                let page = super::super::candidates::PolicyCandidates {
                    objects: source.objects.clone(),
                }
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
                        let end = offset + input_prefix(sizes[offset..].iter().map(|v| v.1))?;
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
                            let Frozen::Configuration { native, .. } =
                                serde_json::from_value::<Frozen>(value).map_err(|_| {
                                    Error::Unavailable(Failure::NativeInputIntegrity)
                                })?;
                            let objects = native
                                .open(key, tenant_id, Owner::Policy { policy, version })?
                                .objects()?;
                            for (device, candidate) in
                                page.items.iter().filter(|(_, v)| v.version == version)
                            {
                                if policy != candidate.policy {
                                    return Err(Error::Malformed);
                                }
                                for (index, target, expected) in &removals {
                                    if target == device
                                        && objects
                                            .iter()
                                            .any(|o| expected.iter().any(|e| o.overlaps(e)))
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
    requests: &[(Authority, Vec<Permission>)],
) -> std::result::Result<BTreeMap<usize, bool>, Error> {
    let input = indices
        .iter()
        .filter_map(|index| match &requests[*index].0 {
            Authority::Policy {
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
    let rows=sqlx::query_as::<_,(i64,bool)>("WITH input AS(SELECT value FROM jsonb_array_elements($2)) SELECT (x.value->>'n')::bigint,EXISTS(SELECT 1 FROM mdm_planning.configuration_claims cc JOIN mdm_planning.configuration_operations o ON(o.tenant_id,o.id)=(cc.tenant_id,cc.operation) JOIN mdm_policy.policies p ON(p.tenant_id,p.id)=(cc.tenant_id,cc.policy) WHERE cc.tenant_id=$1::uuid AND cc.device=x.value->>'device' AND o.authority->>'unit'=x.value->>'unit' AND p.state='enabled') FROM input x").bind(tenant).bind(Value::Array(input)).fetch_all(c).await.map_err(db)?;
    Ok(rows
        .into_iter()
        .map(|(index, valid)| (index as usize, valid))
        .collect())
}
async fn retirement_sources(
    c: &mut PgConnection,
    tenant: &str,
    requests: &[(usize, Authority)],
) -> std::result::Result<BTreeMap<usize, bool>, Error> {
    let mut targets = Vec::new();
    let mut executions = BTreeMap::new();
    for (index, authority) in requests {
        let Authority::Retirement {
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

/// Bound each decoded source batch to the same 16 MiB input limit as the command directory.
fn input_prefix(sizes: impl IntoIterator<Item = i64>) -> std::result::Result<usize, Error> {
    let mut bytes = 0i64;
    let mut count = 0;
    for size in sizes.into_iter().take(1000) {
        if !(0..=16 * 1024 * 1024).contains(&size) {
            return Err(Error::Unavailable(Failure::Capacity));
        }
        if bytes + size > 16 * 1024 * 1024 {
            break;
        }
        bytes += size;
        count += 1;
    }
    Ok(count)
}
