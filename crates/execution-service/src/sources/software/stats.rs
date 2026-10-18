//! Bounded rollout reduction on the existing policy recovery worker.
//! ref: kube-rs kube-runtime/src/controller/mod.rs@1be7f0d96c3b211680b173c1fc83aa6ad4adba34
//! ref: PostgreSQL 18 docs, plpgsql-trigger.html, summary tables and change capture.
use super::*;
use sqlx::Row;
type Original = rss_mdm_registration_service::device::endpoints::PrimaryRegistration;
#[derive(serde::Serialize, serde::Deserialize)]
pub(super) struct Input {
    scopes: Vec<Uuid>,
    runs: Vec<Uuid>,
    revisions: Vec<i64>,
    results: i64,
    bindings: i64,
}
struct Build {
    input: Input,
    generation: Uuid,
    cursor: Option<String>,
    complete: bool,
    counts: StageCounts,
}
impl SoftwareAssignment {
    pub(super) async fn stats_input_in(
        &self,
        source: &std::sync::Arc<dyn crate::source_authority::SourceAuthority>,
        tx: &mut PgTransaction<'_>,
        index: usize,
    ) -> Result<Option<Input>> {
        let stage = self.rollout.stages.get(index).ok_or(Error::Malformed)?;
        let mut scopes = vec![self.scope, stage.scope];
        scopes.extend(self.rollout.stages[..index].iter().map(|s| s.scope));
        let reader = source.clone();
        let tenant = tx.tenant_id();
        let scope_input = scopes.clone();
        let channel = self.channel();
        let resolved = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(reader
                        .rollout_input_on(c, tenant, &scope_input, channel)
                        .await)
                })
            })
            .await??;
        let Some(resolved) = resolved else {
            return Ok(None);
        };
        let tenant = tenant.to_string();
        let version = self.version;
        let (results,bindings)=tx.with_connection(move|c|Box::pin(async move {sqlx::query_as::<_,(i64,i64)>("SELECT coalesce((SELECT stats_revision FROM mdm_commands.policy_recovery r JOIN mdm_policy.versions v ON(v.tenant_id,v.policy)=(r.tenant_id,r.policy) WHERE r.tenant_id=$1::uuid AND v.id=$2),0),coalesce((SELECT revision FROM mdm_commands.software_binding_revisions WHERE tenant_id=$1::uuid),0)").bind(tenant).bind(version).fetch_one(c).await})).await?;
        Ok(Some(Input {
            scopes,
            runs: resolved.iter().map(|r| r.run).collect(),
            revisions: resolved.iter().map(|r| r.revision).collect(),
            results,
            bindings,
        }))
    }
    pub(crate) async fn advance_stats_in(
        &self,
        service: &crate::queries::Admission,
        tx: &mut PgTransaction<'_>,
        policy: Uuid,
    ) -> Result<()> {
        let Some(version) = self.version else {
            return Ok(());
        };
        let now = crate::storage::now(tx).await?;
        for index in 0..self.rollout.stages.len() {
            let Some(current) = self.stats_input_in(&service.source, tx, index).await? else {
                return Ok(());
            };
            let tenant = tx.tenant_id().to_string();
            let row=tx.with_connection(move|c|Box::pin(async move {sqlx::query("SELECT input,cursor,generation,membership_complete,counts FROM mdm_commands.software_stage_stats WHERE tenant_id=$1::uuid AND version=$2 AND stage=$3 FOR UPDATE").bind(tenant).bind(version).bind(index as i32).fetch_optional(c).await})).await?;
            let old = if let Some(row) = row {
                let input: Input = crate::stored(serde_json::from_value(row.try_get("input")?))?;
                if input.scopes == current.scopes && input.revisions == current.revisions {
                    Some(Build {
                        input,
                        generation: row.try_get("generation")?,
                        cursor: row.try_get("cursor")?,
                        complete: row.try_get("membership_complete")?,
                        counts: crate::stored(serde_json::from_value(row.try_get("counts")?))?,
                    })
                } else {
                    None
                }
            } else {
                None
            };
            let mut build = old.unwrap_or_else(|| Build {
                input: Input {
                    scopes: current.scopes.clone(),
                    runs: current.runs.clone(),
                    revisions: current.revisions.clone(),
                    results: current.results,
                    bindings: current.bindings,
                },
                generation: Uuid::new_v4(),
                cursor: None,
                complete: false,
                counts: StageCounts::default(),
            });
            build.counts.ready = false;
            // The parent exists before its per-target contributions, in this same transaction.
            save(tx, version, index, &build).await?;
            let mut processed = false;
            if !build.complete {
                let reader = service.source.clone();
                let tenant = tx.tenant_id();
                let runs = build.input.runs.clone();
                let cursor = build.cursor.clone();
                let channel = self.channel();
                let page = tx
                    .with_connection(move |c| {
                        Box::pin(async move {
                            Ok(reader
                                .rollout_devices_on(c, tenant, &runs, channel, cursor.as_deref())
                                .await)
                        })
                    })
                    .await??;
                build.counts.scanned += page.scanned;
                if build.counts.scanned > 1_000_000 {
                    return Err(Error::Malformed.into());
                }
                for target in page.targets {
                    self.reduce_in(service, tx, index, &target, &mut build, now)
                        .await?;
                }
                build.cursor = page.after;
                build.complete = !page.has_more;
                processed = true;
            } else if build.input.results < current.results
                || build.input.bindings < current.bindings
            {
                let results = build.input.results < current.results;
                let after = if results {
                    build.input.results
                } else {
                    build.input.bindings
                };
                let through = if results {
                    current.results
                } else {
                    current.bindings
                };
                let tenant = tx.tenant_id().to_string();
                let mut changes=tx.with_connection(move|c|Box::pin(async move {
                    let query=if results{"SELECT device,revision FROM mdm_commands.software_result_changes WHERE tenant_id=$1::uuid AND policy=$4 AND revision>$2 AND revision<=$3 ORDER BY revision LIMIT 17"}else{"SELECT device,revision FROM mdm_commands.software_binding_changes WHERE tenant_id=$1::uuid AND revision>$2 AND revision<=$3 AND $4::uuid IS NOT NULL ORDER BY revision LIMIT 17"};
                    sqlx::query_as::<_,(String,i64)>(query).bind(tenant).bind(after).bind(through).bind(policy).fetch_all(c).await
                })).await?;
                let more = changes.len() > 16;
                changes.truncate(16);
                let next = if more {
                    changes.last().map(|r| r.1).unwrap_or(after)
                } else {
                    through
                };
                for (device, _) in changes {
                    if let Some(target) =
                        member_in(tx, version, index, build.generation, &device).await?
                    {
                        self.reduce_in(service, tx, index, &target, &mut build, now)
                            .await?;
                    }
                }
                if results {
                    build.input.results = next
                } else {
                    build.input.bindings = next
                };
                processed = true;
            }
            if build.complete
                && build.input.results == current.results
                && build.input.bindings == current.bindings
            {
                let tenant = tx.tenant_id().to_string();
                let generation = build.generation;
                let mut expired=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,serde_json::Value>("SELECT target FROM mdm_commands.software_stats_members WHERE tenant_id=$1::uuid AND version=$2 AND stage=$3 AND generation=$4 AND waiting_until<=$5 ORDER BY waiting_until,device LIMIT 17").bind(tenant).bind(version).bind(index as i32).bind(generation).bind(now).fetch_all(c).await})).await?;
                let more = expired.len() > 16;
                expired.truncate(16);
                processed |= !expired.is_empty();
                for target in expired {
                    self.reduce_in(
                        service,
                        tx,
                        index,
                        &crate::stored(serde_json::from_value(target))?,
                        &mut build,
                        now,
                    )
                    .await?;
                }
                build.counts.ready = !more;
                if build.counts.ready {
                    build.counts.as_of = Some(now);
                }
            }
            save(tx, version, index, &build).await?;
            if processed {
                return Ok(());
            }; // One membership/change/expiry page per transaction.
        }
        Ok(())
    }
    async fn reduce_in(
        &self,
        service: &crate::queries::Admission,
        tx: &mut PgTransaction<'_>,
        index: usize,
        target: &Original,
        build: &mut Build,
        now: i64,
    ) -> Result<()> {
        let version = self.version.ok_or(Error::Malformed)?;
        let tenant = tx.tenant_id().to_string();
        let device = target.device.clone();
        let generation = build.generation;
        let old:Option<serde_json::Value>=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar("SELECT counts FROM mdm_commands.software_stats_members WHERE tenant_id=$1::uuid AND version=$2 AND stage=$3 AND device=$4 AND generation=$5").bind(tenant).bind(version).bind(index as i32).bind(device).bind(generation).fetch_optional(c).await})).await?;
        let old: StageCounts = match old {
            Some(v) => crate::stored(serde_json::from_value(v))?,
            None => StageCounts::default(),
        };
        let mut count = StageCounts {
            total: 1,
            ..Default::default()
        };
        let tenant = tx.tenant_id().to_string();
        let device = target.device.clone();
        let registration = target.registration_id;
        let epoch = target.generation;
        let prefix = format!("software:stage:{}:%", self.rollout.stages[index].scope);
        let result=tx.with_connection(move|c|Box::pin(async move {sqlx::query_as::<_,(serde_json::Value,Option<serde_json::Value>)>("SELECT state,result FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND policy_version=$2 AND device=$3 AND registration=$4 AND generation=$5 AND occurrence LIKE $6 ORDER BY created_at DESC,id DESC LIMIT 1").bind(tenant).bind(version).bind(device).bind(registration).bind(epoch).bind(prefix).fetch_optional(c).await})).await?;
        let mut waiting_until = None;
        if let Some((state, result)) = result {
            count.reported = u64::from(result.is_some());
            let effect = result.as_ref().and_then(|r| r["effect"].as_str());
            count.unknown = u64::from(effect == Some("unknown") || state["execution"] == "unknown");
            count.waiting_reboot = u64::from(effect == Some("waiting_reboot"));
            count.failed = u64::from(effect == Some("failed"));
            count.verified = u64::from(effect == Some("verified"));
            let lease = state["delivery"]["leaseUntil"].as_i64();
            if matches!(self.intent(), SoftwareIntent::AvailableInstall)
                && state["execution"] == "not_started"
                && state["cancellation"] == "none"
                && matches!(
                    state["delivery"]["kind"].as_str(),
                    Some("claimed" | "received")
                )
                && lease.is_some_and(|at| at > now)
            {
                count.waiting_user = 1;
                waiting_until = lease;
            }
        }
        count.unsupported_capability = 1;
        if self.channel() == rss_mdm_inventory::Channel::Mdm {
            count.unsupported_capability = u64::from(
                crate::native_software::target_in(tx, &target.device)
                    .await?
                    .is_none(),
            );
        } else {
            for binding in crate::channels::agent_targets_in(
                tx,
                service.agent_store.clone(),
                vec![target.device.clone()],
            )
            .await?
            {
                if binding.registration == target.registration_id
                    && binding.generation == target.generation
                    && self.supported_in(service, tx, &binding.binding).await?
                {
                    count.unsupported_capability = 0;
                }
            }
        }
        macro_rules! replace {($($field:ident),*)=>{$(build.counts.$field=build.counts.$field.checked_sub(old.$field).and_then(|v|v.checked_add(count.$field)).ok_or(Error::Malformed)?;)*};}
        replace!(
            total,
            reported,
            waiting_user,
            unknown,
            waiting_reboot,
            failed,
            verified,
            unsupported_capability
        );
        let tenant = tx.tenant_id().to_string();
        let device = target.device.clone();
        let target = crate::checked_input(serde_json::to_value(target))?;
        let counts = crate::checked_input(serde_json::to_value(count))?;
        tx.with_connection(move|c|Box::pin(async move {sqlx::query("INSERT INTO mdm_commands.software_stats_members(tenant_id,version,stage,device,generation,target,counts,waiting_until) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(tenant_id,version,stage,device) DO UPDATE SET generation=EXCLUDED.generation,target=EXCLUDED.target,counts=EXCLUDED.counts,waiting_until=EXCLUDED.waiting_until").bind(tenant).bind(version).bind(index as i32).bind(device).bind(generation).bind(target).bind(counts).bind(waiting_until).execute(c).await?;Ok(())})).await?;
        Ok(())
    }
}
async fn member_in(
    tx: &mut PgTransaction<'_>,
    version: Uuid,
    index: usize,
    generation: Uuid,
    device: &str,
) -> Result<Option<Original>> {
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    let target:Option<serde_json::Value>=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar("SELECT target FROM mdm_commands.software_stats_members WHERE tenant_id=$1::uuid AND version=$2 AND stage=$3 AND generation=$4 AND device=$5").bind(tenant).bind(version).bind(index as i32).bind(generation).bind(device).fetch_optional(c).await})).await?;
    target
        .map(|v| crate::stored(serde_json::from_value(v)))
        .transpose()
}
async fn save(
    tx: &mut PgTransaction<'_>,
    version: Uuid,
    index: usize,
    build: &Build,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let input = crate::checked_input(serde_json::to_value(&build.input))?;
    let cursor = build.cursor.clone();
    let generation = build.generation;
    let complete = build.complete;
    let ready = build.counts.ready;
    let counts = crate::checked_input(serde_json::to_value(&build.counts))?;
    tx.with_connection(move|c|Box::pin(async move {sqlx::query("INSERT INTO mdm_commands.software_stage_stats(tenant_id,version,stage,input,cursor,generation,membership_complete,ready,counts) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(tenant_id,version,stage) DO UPDATE SET input=EXCLUDED.input,cursor=EXCLUDED.cursor,generation=EXCLUDED.generation,membership_complete=EXCLUDED.membership_complete,ready=EXCLUDED.ready,counts=EXCLUDED.counts").bind(tenant).bind(version).bind(index as i32).bind(input).bind(cursor).bind(generation).bind(complete).bind(ready).bind(counts).execute(c).await?;Ok(())})).await?;
    Ok(())
}
