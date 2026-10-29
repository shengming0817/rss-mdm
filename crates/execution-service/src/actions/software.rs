//! Software-specific admission and task material; shared Run owns delivery and recovery.
use super::{
    production::{RunInput, queue_run_in},
    storage as db,
};
use crate::Target;
use crate::{Error, ExecutionService, Result};
use rss_mdm_policy::schedule::Trigger;
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;

pub async fn accept_for_device(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    policy: &crate::sources::software::SoftwareExecutionPolicy,
    target: &Target,
    now: i64,
    id: Uuid,
) -> Result<()> {
    if policy.assignment.intent() == rss_mdm_policy::SoftwareIntent::AvailableInstall {
        return Ok(());
    }
    let Preparation::Ready(slot) = slot_in(service, tx, policy, target, None, now, None).await?
    else {
        return Ok(());
    };
    queue_run_in(
        service,
        tx,
        RunInput {
            origin: rss_mdm_audit_integration::activity::ActivityOrigin::Policy,
            invocation: None,
            triggered_at: None,
            source: db::Source::Policy { version: policy.id },
            target,
            id,
            occurrence: slot.occurrence,
            available: slot.available,
            deadline: slot.deadline,
            now,
        },
    )
    .await?;
    persist_effect_in(tx, id, &slot.effect).await?;

    Ok(())
}

#[derive(Clone, Copy)]
pub enum Invocation {
    SelfService(Uuid),
    Event(Uuid),
}

pub enum Preparation {
    Ready(Slot),
    Satisfied,
    NotEligible,
}

pub struct Slot {
    pub occurrence: String,
    pub available: i64,
    pub deadline: i64,
    pub effect: serde_json::Value,
    pub steps: Vec<rss_mdm_agent_wire::runtime::SoftwareTaskStep>,
}
pub async fn slot_in(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    policy: &crate::sources::software::SoftwareExecutionPolicy,
    target: &Target,
    request: Option<Invocation>,
    now: i64,
    existing: Option<Uuid>,
) -> Result<Preparation> {
    let stage = match policy
        .assignment
        .entry_in(&service.source, tx, &target.device, now)
        .await?
    {
        Some((stage, _)) => stage,
        None if matches!(request, Some(Invocation::SelfService(_)))
            && !policy.assignment.stages().is_empty() =>
        {
            0
        }
        None => return Ok(Preparation::NotEligible),
    };
    let mut prepared = Vec::new();
    let effect = if policy.assignment.channel() == rss_mdm_inventory::Channel::Mdm {
        if !service.inputs.software_distribution.mdm_enabled {
            return Ok(Preparation::NotEligible);
        }
        let crate::native_software::TargetAdmission::Eligible(
            crate::native_software::NativeTarget {
                target: current,
                platform: p,
                architecture: a,
            },
        ) = crate::native_software::target_admission_in(tx, &target.device).await?
        else {
            return Ok(Preparation::NotEligible);
        };
        if current.registration != target.registration
            || current.generation != target.generation
            || policy
                .assignment
                .admitted_in(&service.admission(), tx, p, a)
                .await?
                .is_none()
        {
            return Ok(Preparation::NotEligible);
        }
        let package = policy
            .assignment
            .frozen
            .native_packages
            .get(&rss_mdm_policy::SoftwareTarget::new(p, a))
            .ok_or(Error::Unsupported)?;
        serde_json::json!({"channel":"mdm","generation":target.generation,"resource":policy.assignment.frozen.resource,"version":policy.assignment.frozen.version,"digest":policy.assignment.frozen.resource_digest,"intent":"install","target":{"kind":"device"},"packages":[package.effect_identity()],"packageVersions":{(package.effect_identity()):package.effect_version()}})
    } else {
        let Some(binding) =
            crate::channels::agent_binding_in(tx, service.agent_store.clone(), target.registration)
                .await?
        else {
            return Ok(Preparation::NotEligible);
        };
        if !matches!(request, Some(Invocation::SelfService(_)))
            && !policy
                .assignment
                .supported_in(&service.admission(), tx, &binding)
                .await?
        {
            return Ok(Preparation::NotEligible);
        }
        let Some((platform, architecture)) =
            db::agent_profile_in(service, tx, target.registration).await?
        else {
            return Ok(Preparation::NotEligible);
        };
        if policy
            .assignment
            .admitted_in(&service.admission(), tx, platform, architecture)
            .await?
            .is_none()
        {
            return Ok(Preparation::NotEligible);
        }
        let steps = policy
            .assignment
            .prepared_in(
                &service.admission(),
                tx,
                platform,
                architecture,
                &binding.execution_context,
            )
            .await?
            .ok_or(Error::Forbidden)?;
        let effect = effect_key(policy, target, &steps)?;
        prepared = steps;
        effect
    };
    let source = service.source.clone();
    let tenant_id = tx.tenant_id();
    let device = target.device.clone();
    let devices = tx
        .with_connection(move |c| {
            Box::pin(async move { Ok(source.effect_devices_on(c, tenant_id, &device).await) })
        })
        .await??;
    let ordered: std::collections::BTreeSet<_> = devices.iter().cloned().collect();
    for endpoint in ordered {
        let fence = format!("{}:{endpoint}", tx.tenant_id());
        tx.with_connection(move |c| {
            Box::pin(async move {
                let locked: bool = sqlx::query_scalar(
                    "SELECT pg_try_advisory_xact_lock(hashtextextended($1,2793))",
                )
                .bind(fence)
                .fetch_one(c)
                .await?;
                if !locked {
                    return Err(sqlx::Error::Protocol("device effect busy".into()));
                }
                Ok(())
            })
        })
        .await?;
    }
    // The transaction admission fence serializes conflicting effects across associated endpoints.
    let tenant = tx.tenant_id().to_string();
    let device = devices;

    let version = policy.id;
    let stage_scope = policy.assignment.stages()[stage].scope;
    let prefix = format!("software:stage:{stage_scope}:%");
    let key = effect.clone();
    let (pending, last, satisfied, failures, attempts): (bool, Option<i64>, bool, i64, i64) = tx.with_connection(move |c| Box::pin(async move {
        // Unresolved effects conflict across intent, version, digest and registration generations.
        // Only the latest precisely ordered completion can satisfy the requested effect;
        // a later removal, replacement or known failure invalidates earlier success.
        sqlx::query_as(r#"
            WITH effects AS (
                SELECT r.* FROM mdm_commands.action_runs r
                WHERE r.tenant_id=$1::uuid AND r.device=ANY($3::text[]) AND ($7::uuid IS NULL OR r.id<>$7)
                  AND r.software_effect->'target'=$2::jsonb->'target'
                  AND (r.software_effect->'resource'=$2::jsonb->'resource' OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(r.software_effect->'packages') a JOIN jsonb_array_elements_text($2::jsonb->'packages') b ON a.value=b.value))
            )
            SELECT coalesce(bool_or(state->>'execution' IN ('unknown','waiting_reboot')
                       OR ((state->>'execution'='running'
                            OR (state->>'execution'='not_started' AND deadline>$5))
                           AND state->>'cancellation'<>'confirmed')),false),
                   max(created_at) FILTER(WHERE software_effect=$2 AND policy_version=$4 AND occurrence LIKE $6),
                   coalesce((SELECT (software_effect=$2 OR (software_effect->'target'=$2::jsonb->'target' AND software_effect->'intent'=$2::jsonb->'intent' AND $2::jsonb->'packageVersions'<>'{}'::jsonb AND (software_effect->'packageVersions') @> ($2::jsonb->'packageVersions'))) AND result->>'effect'='verified'
                             FROM effects
                             WHERE software_effect->'generation'=$2::jsonb->'generation'
                               AND result->>'effect' IN ('verified','failed')
                               AND jsonb_typeof(result->'effectObservedAt')='number'
                             ORDER BY (result->>'effectObservedAt')::bigint DESC,(result->>'effectReceivedAt')::bigint DESC NULLS LAST LIMIT 1),false),
                   count(*) FILTER(WHERE software_effect=$2 AND policy_version=$4 AND result->>'effect'='failed'),
                   count(*) FILTER(WHERE software_effect=$2 AND policy_version=$4 AND occurrence LIKE $6)
            FROM effects
        "#)
            .bind(tenant).bind(key).bind(device).bind(version).bind(now).bind(prefix).bind(existing).fetch_one(c).await
    })).await?;
    if satisfied && !pending {
        return Ok(Preparation::Satisfied);
    }
    if pending || failures >= 3 {
        return Ok(Preparation::NotEligible);
    }
    let schedule = &policy.assignment.frozen.schedule;
    let coordinate = if matches!(request, Some(Invocation::Event(_))) {
        now
    } else {
        match &schedule.trigger {
            Trigger::Manual if request.is_some() => now,
            Trigger::Manual => return Ok(Preparation::NotEligible),
            Trigger::CheckIn { minimum_seconds } => {
                let delay =
                    i64::from(*minimum_seconds).saturating_mul(1_i64 << failures.clamp(0, 3));
                if last.is_some_and(|at| now.saturating_sub(at) < delay) {
                    return Ok(Preparation::NotEligible);
                }
                now
            }
            Trigger::Registration => now,
            Trigger::Once { .. } | Trigger::Interval { .. } | Trigger::Weekly { .. } => {
                let Some(due) = schedule.due(-1, now, target.device.as_bytes())? else {
                    return Ok(Preparation::NotEligible);
                };
                due.coordinate
            }
        }
    };
    let Some(slot) = schedule.occurrence(coordinate, target.device.as_bytes())? else {
        return Ok(Preparation::NotEligible);
    };
    let available = slot.available_at.max(now);
    let deadline = available
        .checked_add(i64::from(policy.assignment.frozen.run_lifetime_seconds))
        .ok_or(Error::Malformed)?
        .min(schedule.ends_at())
        .min(slot.window_end.unwrap_or(i64::MAX));
    if deadline <= available {
        return Ok(Preparation::NotEligible);
    }
    let occurrence = match request {
        Some(Invocation::SelfService(request)) => {
            format!("software:stage:{stage_scope}:self-service:{request}")
        }
        Some(Invocation::Event(request)) => format!("software:stage:{stage_scope}:event:{request}"),
        None => format!(
            "software:stage:{stage_scope}:desired:{}:{attempts}",
            target.registration
        ),
    };
    let tenant = tx.tenant_id().to_string();
    let version = policy.id;
    let device = target.device.clone();
    let key = occurrence.clone();
    let (exists, active): (bool, i64) = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_as("SELECT EXISTS(SELECT 1 FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND policy_version=$2::uuid AND device=$3 AND occurrence=$4 AND ($6::uuid IS NULL OR id<>$6)), (SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND device=$3 AND state->>'execution' IN ('not_started','running') AND state->>'cancellation'<>'confirmed' AND deadline>$5 AND ($6::uuid IS NULL OR id<>$6))")
            .bind(tenant).bind(version).bind(device).bind(key).bind(now).bind(existing).fetch_one(c).await
    })).await?;
    if exists || active >= 128 {
        return Ok(Preparation::NotEligible);
    }
    Ok(Preparation::Ready(Slot {
        occurrence,
        available,
        deadline,
        effect,
        steps: prepared,
    }))
}
pub(crate) fn effect_key(
    policy: &crate::sources::software::SoftwareExecutionPolicy,
    target: &Target,
    steps: &[rss_mdm_agent_wire::runtime::SoftwareTaskStep],
) -> Result<serde_json::Value> {
    let root = steps.last().ok_or(Error::Malformed)?;
    // Installation effects survive logout; Start still binds the complete OS session target.
    let effect_target = match &root.target {
        rss_mdm_agent_wire::runtime::SoftwareExecutionTarget::Device => {
            serde_json::json!({"kind":"device"})
        }
        rss_mdm_agent_wire::runtime::SoftwareExecutionTarget::User { identity, .. } => {
            serde_json::json!({"kind":"user", "identity":identity})
        }
    };
    use rss_mdm_agent_wire::runtime::{SoftwareTaskBehavior as B, SoftwareTaskDetection as D};
    let versions: std::collections::BTreeMap<String, String> = steps
        .iter()
        .filter_map(|step| {
            let identity = match &step.action.behavior {
                B::Msi(v) => match &v.detect {
                    D::MsiProduct { product_code, .. } => {
                        Uuid::parse_str(product_code.trim_matches(['{', '}']))
                            .ok()
                            .map(|id| format!("msi:{id}"))
                    }
                    _ => None,
                },
                B::Pkg(v) => match &v.detect {
                    D::PkgReceipt { receipt, .. } => Some(format!("pkg:{receipt}")),
                    _ => None,
                },
                B::Msix(v) => Some(format!(
                    "msix:{}",
                    crate::agent_preparation::family(&v.identity.name, &v.identity.publisher)
                )),
                _ => None,
            };
            identity.map(|id| {
                (
                    id,
                    rss_mdm_software_service::preparation::evidence::detected_version(&step.action),
                )
            })
        })
        .collect();
    let packages: Vec<_> = versions.keys().collect();
    Ok(
        serde_json::json!({"packages":packages,"packageVersions":versions,"channel":"agent","generation":target.generation,"resource":policy.assignment.frozen.resource,"version":policy.assignment.frozen.version,"digest":policy.assignment.frozen.resource_digest,"intent":if policy.assignment.intent()==rss_mdm_policy::SoftwareIntent::ExplicitUninstall {"uninstall"} else {"install"},"target":effect_target}),
    )
}
pub async fn persist_effect_in(
    tx: &mut PgTransaction<'_>,
    run: Uuid,
    effect: &serde_json::Value,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let effect = effect.clone();
    tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("UPDATE mdm_commands.action_runs SET software_effect=$3 WHERE tenant_id=$1::uuid AND id=$2 AND software_effect IS NULL").bind(tenant).bind(run).bind(effect).execute(c).await?;
        Ok(())
    })).await?;
    Ok(())
}

/// Receipt ordering disambiguates observations whose device clock has only second precision.
pub(crate) async fn effect_received_at(tx: &mut PgTransaction<'_>) -> Result<i64> {
    Ok(tx
        .with_connection(|c| {
            Box::pin(async move {
                sqlx::query_scalar(
                    "SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint",
                )
                .fetch_one(c)
                .await
            })
        })
        .await?)
}
