//! Batch source facts and the sole source-authorization decision for execution grants.
use super::*;
use crate::deployment::frozen::Published;
use crate::deployment::scope::Sources;
use sqlx::Row;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

#[expect(
    clippy::cognitive_complexity,
    reason = "bounded batch qualification preserves separate Software and Agent installation authority decisions"
)]
pub(super) async fn many(
    _source: &dyn Sources,
    _lifecycle: &dyn crate::deployment::retirement::Lifecycle,
    c: &mut PgConnection,
    _key: &rss_mdm_native_protection::Protector,
    requests: &[(Authority, Vec<Permission>)],
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
            Authority::Software { .. } => *p == Permission::SoftwareDeploy,
            Authority::AgentInstall { .. } => *p == Permission::SoftwareDeploy,
        });
        if !valid {
            continue;
        }
        match a {
            Authority::Software { tenant, .. } | Authority::AgentInstall { tenant, .. } => {
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
                .map(|i| match &requests[*i].0 {
                    Authority::Software { version, .. }
                    | Authority::AgentInstall { version, .. } => *version,
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
            .partition(|index| matches!(requests[*index].0, Authority::Software { .. }));
        if !software.is_empty() {
            let inputs = software
                .into_iter()
                .map(|index| (index, requests[index].0.clone()))
                .collect::<Vec<_>>();
            for (index, valid) in
                crate::deployment::native_software::authorities_on(c, tenant_id, &inputs, lock)
                    .await?
            {
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
                Authority::AgentInstall { version, .. } => *version,
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
                Authority::AgentInstall { package, .. } => Some(package.release.release_id),
                _ => None,
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let packages = if lock {
            crate::agent_packages::admitted_many_locked_on(c, tenant_id, &releases).await
        } else {
            crate::agent_packages::admitted_many_on(c, tenant_id, &releases).await
        }
        .map_err(|_| Error::Unavailable(crate::deployment::Failure::SoftwareCatalogStorage))?;
        let mut offset = 0;
        while offset < sizes.len() {
            let end = offset
                + crate::deployment::transaction::input_prefix(
                    sizes[offset..].iter().map(|v| v.1),
                )?;
            let ids = sizes[offset..end].iter().map(|v| v.0).collect::<Vec<_>>();
            let rows=sqlx::query("WITH facts AS MATERIALIZED(SELECT v.id,v.frozen,v.policy,p.state='enabled' AS live FROM mdm_policy.versions v LEFT JOIN mdm_policy.policies p ON(p.tenant_id,p.id)=(v.tenant_id,v.policy) WHERE v.tenant_id=$1::uuid AND v.id=ANY($2)),budget AS(SELECT coalesce(sum(octet_length(frozen::text)),0)::bigint AS bytes FROM facts) SELECT facts.*,budget.bytes FROM budget LEFT JOIN facts ON budget.bytes<=16777216")
                .bind(&tenant).bind(ids).fetch_all(&mut *c).await.map_err(db)?;
            if rows
                .first()
                .is_some_and(|r| r.get::<i64, _>("bytes") > 16777216)
            {
                return Err(Error::Unavailable(crate::deployment::Failure::Capacity));
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
                let frozen: Published = serde_json::from_value(row.try_get("frozen").map_err(db)?)
                    .map_err(|_| Error::Malformed)?;
                for &index in consumers.get(&version).ok_or(Error::Malformed)? {
                    match &requests[index].0 {
                        Authority::AgentInstall {
                            policy: expected,
                            package,
                            ..
                        } => {
                            results[index] = policy == *expected
                                && live
                                && matches!(frozen, Published::AgentInstall { .. })
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
