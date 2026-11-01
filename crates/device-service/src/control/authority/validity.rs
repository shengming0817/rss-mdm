//! Batch source facts and the sole source-authorization decision for execution grants.
use super::*;
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(super) async fn many(
    c: &mut PgConnection,
    _key: &rss_mdm_native_protection::Protector,
    requests: &[(Authority, Vec<Permission>)],
    _now: i64,
    _lock: bool,
) -> Result<Vec<bool>, Error> {
    let mut results = vec![false; requests.len()];
    let mut groups = BTreeMap::<String, Vec<usize>>::new();
    for (index, (a, permissions)) in requests.iter().enumerate() {
        if permissions.is_empty() {
            continue;
        }
        let permissions = permissions.iter().chain(a.required());
        let valid = permissions.clone().all(|p| match a {
            Authority::DeviceControl { required, .. } | Authority::Retirement { required, .. } => {
                required.contains(p)
            }
        });
        if !valid {
            continue;
        }
        match a {
            Authority::DeviceControl { .. } => results[index] = true,
            Authority::Retirement { tenant, .. } => {
                groups.entry(tenant.clone()).or_default().push(index)
            }
        }
    }
    for (tenant, indices) in groups {
        let inputs = indices
            .into_iter()
            .map(|index| (index, requests[index].0.clone()))
            .collect::<Vec<_>>();
        for (index, valid) in retirement_sources(c, &tenant, &inputs).await? {
            results[index] = valid;
        }
    }
    Ok(results)
}

async fn retirement_sources(
    c: &mut PgConnection,
    tenant: &str,
    requests: &[(usize, Authority)],
) -> Result<BTreeMap<usize, bool>, Error> {
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
    let lifecycle = crate::lifecycle::execution_permissions_in(c, tenant, &targets)
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
