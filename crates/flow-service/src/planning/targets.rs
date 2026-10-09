//! Map frozen sources to one selected original channel before Scope set algebra.
use super::{Reference, automation::ScopeInput};
use rss_contract::Timepoint;
use rss_mdm_execution_service::source_authority::*;
use rss_mdm_scope as s;
use rss_request_context::TenantId;
use sqlx::{PgConnection, Row};
use std::collections::BTreeSet;
use uuid::Uuid;
struct RowInput {
    source: usize,
    unknown: bool,
    input: DeviceObject,
}
async fn resolution(
    c: &mut PgConnection,
    tenant: TenantId,
    scope: Uuid,
) -> Result<(Uuid, i64, ScopeInput, bool), SourceError> {
    // The owner fence precedes Scope/head locks, matching publication transactions.
    rss_mdm_inventory_postgres::lock_watermark_in(c, tenant).await?;
    let status: serde_json::Value =
        sqlx::query_scalar("SELECT mdm_planning.scope_admission($1,NULL)")
            .bind(scope)
            .fetch_one(&mut *c)
            .await?;
    let row=sqlx::query("SELECT s.resolution,s.resolution_revision,r.input FROM mdm_planning.scopes s JOIN mdm_planning.scope_runs r ON(r.tenant_id,r.id)=(s.tenant_id,s.resolution) WHERE s.tenant_id=$1::uuid AND s.id=$2 AND NOT s.deleted").bind(tenant.to_string()).bind(scope).fetch_optional(c).await?.ok_or(SourceError::Missing)?;
    let frozen =
        serde_json::from_value(row.try_get("input")?).map_err(|_| SourceError::Invariant)?;
    Ok((
        row.try_get("resolution")?,
        row.try_get("resolution_revision")?,
        frozen,
        status["state"] == "fresh",
    ))
}
async fn rows_for(
    c: &mut PgConnection,
    tenant: TenantId,
    run: Uuid,
    channel: Channel,
    device: &str,
) -> Result<Vec<RowInput>, SourceError> {
    let rows=sqlx::query("SELECT source,unknown,input FROM mdm_planning.scope_source_members WHERE tenant_id=$1::uuid AND run=$2 AND EXISTS(SELECT 1 FROM jsonb_array_elements(input->'members') m WHERE m->>'device'=$3 AND m->>'channel'=$4) ORDER BY source,device LIMIT 16001")
        .bind(tenant.to_string()).bind(run).bind(device).bind(channel.as_str()).fetch_all(c).await?;
    if rows.len() > 16000 {
        return Err(SourceError::Invariant);
    }
    rows.into_iter()
        .map(|r| {
            Ok(RowInput {
                source: r.try_get::<i32, _>("source")? as usize,
                unknown: r.try_get("unknown")?,
                input: serde_json::from_value(r.try_get("input")?)
                    .map_err(|_| SourceError::Invariant)?,
            })
        })
        .collect()
}
async fn current(
    reader: &dyn rss_mdm_inventory_service::objects::ObjectReader,
    c: &mut PgConnection,
    tenant: TenantId,
    input: &DeviceObject,
    channel: Channel,
) -> Result<Option<rss_mdm_registration_service::device::endpoints::PrimaryRegistration>, SourceError>
{
    Ok(reader.validate(c, tenant, input, channel).await?)
}
pub async fn admission_on(
    reader: &dyn rss_mdm_inventory_service::objects::ObjectReader,
    c: &mut PgConnection,
    tenant: TenantId,
    scope: Uuid,
    channel: Channel,
    device: &str,
) -> Result<ScopeAdmission, SourceError> {
    let (run, entry, frozen, fresh) = resolution(c, tenant, scope).await?;
    if !fresh {
        return Ok(ScopeAdmission::Pending);
    }
    let result = explanation_on(c, tenant, run, &frozen, channel, device, Some(reader)).await?;
    Ok(match result {
        None => ScopeAdmission::Excluded,
        Some(result) if result.reasons.is_empty() => ScopeAdmission::Eligible { entry },
        Some(result)
            if result.reasons.iter().any(|r| {
                matches!(
                    r,
                    s::ExclusionReason::UnknownTarget
                        | s::ExclusionReason::UnknownLimitation
                        | s::ExclusionReason::UnknownExclusion
                )
            }) =>
        {
            ScopeAdmission::Pending
        }
        Some(_) => ScopeAdmission::Excluded,
    })
}
async fn explanation_on(
    c: &mut PgConnection,
    tenant: TenantId,
    run: Uuid,
    frozen: &ScopeInput,
    channel: Channel,
    device: &str,
    reader: Option<&dyn rss_mdm_inventory_service::objects::ObjectReader>,
) -> Result<Option<s::MemberExplanation>, SourceError> {
    let rows = rows_for(c, tenant, run, channel, device).await?;
    let at = Timepoint::try_from(frozen.as_of).map_err(|_| SourceError::Invariant)?;
    let mut known = BTreeSet::new();
    let mut uncertain = BTreeSet::new();
    for row in &rows {
        let invalid = if row.unknown || !row.input.verified {
            true
        } else if let Some(reader) = reader {
            current(reader, c, tenant, &row.input, channel)
                .await?
                .is_none()
        } else {
            false
        };
        if invalid {
            uncertain.insert(row.source);
        } else {
            known.insert(row.source);
        }
    }
    let membership = |refs: &BTreeSet<Reference>| -> Result<Vec<s::SourceMembership>, SourceError> {
        frozen
            .sources
            .iter()
            .enumerate()
            .filter(|(_, source)| refs.contains(&source.reference))
            .map(|(index, source)| {
                let id = match &source.reference {
                    Reference::Device(id) => s::SourceId::Direct(
                        s::DeviceId::new(tenant, id).map_err(|_| SourceError::Invariant)?,
                    ),
                    Reference::Group(id) => s::SourceId::Group(
                        s::GroupId::new(tenant, id.to_string())
                            .map_err(|_| SourceError::Invariant)?,
                    ),
                };
                Ok(s::SourceMembership {
                    source: s::SourceRef::new(
                        id,
                        source.member_version + source.authority_version + 1,
                        at,
                    )
                    .map_err(|_| SourceError::Invariant)?,
                    contains: if known.contains(&index) {
                        s::Membership::Known(true)
                    } else if uncertain.contains(&index) {
                        s::Membership::Unknown
                    } else {
                        s::Membership::Known(false)
                    },
                })
            })
            .collect()
    };
    let result = s::resolve_device(&s::DeviceInput {
        device: s::DeviceId::new(tenant, device).map_err(|_| SourceError::Invariant)?,
        targets: membership(&frozen.definition.targets)?,
        limitations: frozen
            .definition
            .limitations
            .as_ref()
            .map(membership)
            .transpose()?,
        exclusions: membership(&frozen.definition.exclusions)?,
    })
    .map_err(|_| SourceError::Invariant)?;
    Ok(result)
}

pub async fn devices_on(
    c: &mut PgConnection,
    tenant: TenantId,
    scope: Uuid,
    channel: Channel,
    after: Option<&str>,
) -> Result<ScopePreview, SourceError> {
    devices_page(c, tenant, scope, channel, after, 64).await
}
pub async fn devices_page(
    c: &mut PgConnection,
    tenant: TenantId,
    scope: Uuid,
    channel: Channel,
    after: Option<&str>,
    limit: usize,
) -> Result<ScopePreview, SourceError> {
    if !(1..=1000).contains(&limit) {
        return Err(SourceError::Invariant);
    }
    let (run, _, frozen, _) = resolution(c, tenant, scope).await?;
    let targets: Vec<i32> = frozen
        .sources
        .iter()
        .enumerate()
        .filter(|(_, s)| frozen.definition.targets.contains(&s.reference))
        .map(|(i, _)| i as i32)
        .collect();
    let devices=sqlx::query_scalar("SELECT DISTINCT m->>'device' COLLATE \"C\" AS device FROM mdm_planning.scope_source_members s CROSS JOIN LATERAL jsonb_array_elements(s.input->'members') m WHERE s.tenant_id=$1::uuid AND s.run=$2 AND s.source=ANY($3) AND m->>'channel'=$4 AND m->>'device'>coalesce($5,'') COLLATE \"C\" ORDER BY device LIMIT $6")
        .bind(tenant.to_string()).bind(run).bind(targets).bind(channel.as_str()).bind(after).bind((limit+1) as i64).fetch_all(c).await?;
    Ok(ScopePreview {
        result: run,
        devices,
    })
}
pub async fn objects_on(
    reader: &dyn rss_mdm_inventory_service::objects::ObjectReader,
    c: &mut PgConnection,
    tenant: TenantId,
    scope: Uuid,
    channel: Channel,
    after: Option<&str>,
) -> Result<Vec<AssignmentObject>, SourceError> {
    let (run, _, frozen, fresh) = resolution(c, tenant, scope).await?;
    let targets: Vec<i32> = frozen
        .sources
        .iter()
        .enumerate()
        .filter(|(_, s)| frozen.definition.targets.contains(&s.reference))
        .map(|(i, _)| i as i32)
        .collect();
    let rows=sqlx::query("SELECT DISTINCT ON(object_key) input,unknown FROM (SELECT input,unknown,CASE input->'object'->>'kind' WHEN 'endpoint' THEN 'endpoint:'||(input->'object'->>'id') ELSE 'association:'||(input->'object'->>'id') END COLLATE \"C\" AS object_key FROM mdm_planning.scope_source_members WHERE tenant_id=$1::uuid AND run=$2 AND source=ANY($3)) objects WHERE object_key>coalesce($4,'') COLLATE \"C\" ORDER BY object_key,unknown LIMIT 65")
        .bind(tenant.to_string()).bind(run).bind(targets).bind(after).fetch_all(&mut *c).await?;
    let mut result = Vec::new();
    for row in rows {
        let input: DeviceObject =
            serde_json::from_value(row.try_get("input")?).map_err(|_| SourceError::Invariant)?;
        let target = current(reader, c, tenant, &input, channel).await?;
        let uncertain = row.try_get::<bool, _>("unknown")?;
        let admission = if !fresh || uncertain {
            ScopeAdmission::Pending
        } else if let Some(target) = &target {
            admission_on(reader, c, tenant, scope, channel, &target.device).await?
        } else {
            ScopeAdmission::Pending
        };
        let ready = target.is_some() && matches!(admission, ScopeAdmission::Eligible { .. });
        let sources = if ready {
            evidence_on(
                reader,
                c,
                tenant,
                scope,
                channel,
                &target.as_ref().unwrap().device,
            )
            .await?
        } else {
            vec![input.clone()]
        };
        result.push(AssignmentObject {
            object: input.object.clone(),
            channel,
            availability: if ready {
                Availability::Ready
            } else {
                Availability::Unavailable
            },
            reason: if ready {
                None
            } else {
                Some(
                    if !input.verified {
                        "association_unverified"
                    } else if target.is_none() {
                        "channel_unavailable"
                    } else if admission == ScopeAdmission::Excluded {
                        "scope_excluded"
                    } else {
                        "source_pending"
                    }
                    .into(),
                )
            },
            target,
            admission,
            sources,
            scope_result: run,
        });
    }
    Ok(result)
}

pub async fn evidence_on(
    reader: &dyn rss_mdm_inventory_service::objects::ObjectReader,
    c: &mut PgConnection,
    tenant: TenantId,
    scope: Uuid,
    channel: Channel,
    device: &str,
) -> Result<Vec<DeviceObject>, SourceError> {
    let (run, _, _, fresh) = resolution(c, tenant, scope).await?;
    if !fresh
        || !matches!(
            admission_on(reader, c, tenant, scope, channel, device).await?,
            ScopeAdmission::Eligible { .. }
        )
    {
        return Err(SourceError::Conflict);
    }
    Ok(rows_for(c, tenant, run, channel, device)
        .await?
        .into_iter()
        .filter(|r| !r.unknown)
        .map(|r| r.input)
        .collect())
}
pub async fn evidence_valid_on(
    reader: &dyn rss_mdm_inventory_service::objects::ObjectReader,
    c: &mut PgConnection,
    tenant: TenantId,
    channel: Channel,
    device: &str,
    evidence: &[DeviceObject],
) -> Result<bool, SourceError> {
    if evidence.is_empty() {
        return Ok(false);
    }
    for input in evidence {
        if current(reader, c, tenant, input, channel)
            .await?
            .is_none_or(|m| m.device != device)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn historical(
    c: &mut PgConnection,
    tenant: TenantId,
    scope: Uuid,
    run: Uuid,
) -> Result<ScopeInput, SourceError> {
    let input:serde_json::Value=sqlx::query_scalar("SELECT input FROM mdm_planning.scope_runs WHERE tenant_id=$1::uuid AND scope=$2 AND id=$3 AND phase='published'").bind(tenant.to_string()).bind(scope).bind(run).fetch_optional(c).await?.ok_or(SourceError::Missing)?;
    serde_json::from_value(input).map_err(|_| SourceError::Invariant)
}
pub async fn result_admission_on(
    c: &mut PgConnection,
    tenant: TenantId,
    scope: Uuid,
    run: Uuid,
    channel: Channel,
    device: &str,
) -> Result<ScopeAdmission, SourceError> {
    let frozen = historical(c, tenant, scope, run).await?;
    let result = explanation_on(c, tenant, run, &frozen, channel, device, None).await?;
    Ok(match result {
        Some(result) if result.reasons.is_empty() => ScopeAdmission::Eligible { entry: 1 },
        Some(result)
            if result.reasons.iter().any(|r| {
                matches!(
                    r,
                    s::ExclusionReason::UnknownTarget
                        | s::ExclusionReason::UnknownLimitation
                        | s::ExclusionReason::UnknownExclusion
                )
            }) =>
        {
            ScopeAdmission::Pending
        }
        _ => ScopeAdmission::Excluded,
    })
}
pub async fn result_devices_on(
    c: &mut PgConnection,
    tenant: TenantId,
    scope: Uuid,
    run: Uuid,
    channel: Channel,
    after: Option<&str>,
    limit: usize,
) -> Result<ScopePreview, SourceError> {
    let frozen = historical(c, tenant, scope, run).await?;
    let targets: Vec<i32> = frozen
        .sources
        .iter()
        .enumerate()
        .filter(|(_, s)| frozen.definition.targets.contains(&s.reference))
        .map(|(i, _)| i as i32)
        .collect();
    let devices=sqlx::query_scalar("SELECT DISTINCT m->>'device' COLLATE \"C\" AS device FROM mdm_planning.scope_source_members s CROSS JOIN LATERAL jsonb_array_elements(s.input->'members') m WHERE s.tenant_id=$1::uuid AND s.run=$2 AND s.source=ANY($3) AND m->>'channel'=$4 AND m->>'device'>coalesce($5,'') COLLATE \"C\" ORDER BY device LIMIT $6").bind(tenant.to_string()).bind(run).bind(targets).bind(channel.as_str()).bind(after).bind((limit+1) as i64).fetch_all(c).await?;
    Ok(ScopePreview {
        result: run,
        devices,
    })
}

pub async fn result_explanation_on(
    c: &mut PgConnection,
    tenant: TenantId,
    scope: Uuid,
    run: Uuid,
    channel: Channel,
    device: &str,
) -> Result<Option<s::MemberExplanation>, SourceError> {
    let frozen = historical(c, tenant, scope, run).await?;
    explanation_on(c, tenant, run, &frozen, channel, device, None).await
}
