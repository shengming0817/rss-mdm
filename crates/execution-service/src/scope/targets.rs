//! Map frozen sources to one selected original channel before Scope set algebra.
use crate::source_authority::*;
use rss_contract::Timepoint;
use rss_mdm_scope as s;
use rss_mdm_scope::Reference;
use rss_mdm_scope_service::results::SourceRow as RowInput;
use rss_mdm_scope_service::sources::ScopeInput;
use rss_request_context::TenantId;
use sqlx::{PgConnection, Row};
use std::collections::BTreeSet;
use uuid::Uuid;
async fn resolution(
    c: &mut PgConnection,
    tenant: TenantId,
    scope: Uuid,
) -> Result<Option<(Uuid, i64, ScopeInput, bool)>, SourceError> {
    rss_mdm_scope_service::results::resolution_on(c, tenant, scope)
        .await
        .map_err(|error| match error {
            sqlx::Error::RowNotFound => SourceError::Missing,
            error => SourceError::Storage(error),
        })
}
async fn rows_for(
    c: &mut PgConnection,
    tenant: TenantId,
    run: Uuid,
    channel: Channel,
    device: &str,
) -> Result<Vec<RowInput>, SourceError> {
    rss_mdm_scope_service::results::source_rows_on(c, tenant, run, channel, device)
        .await
        .map_err(|error| match error {
            sqlx::Error::RowNotFound => SourceError::Missing,
            error => SourceError::Storage(error),
        })
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
    // Missing/deleted scopes exclude; an existing unpublished scope remains pending.
    let status = rss_mdm_scope_postgres::admission_on(c, tenant, scope).await?;
    match status["state"].as_str() {
        Some("excluded") => return Ok(ScopeAdmission::Excluded),
        Some("pending") => return Ok(ScopeAdmission::Pending),
        Some("fresh") => {}
        _ => return Err(SourceError::Invariant),
    }
    let (run, _, _, fresh) = resolution(c, tenant, scope)
        .await?
        .ok_or(SourceError::Invariant)?;
    if !fresh {
        return Ok(ScopeAdmission::Pending);
    }
    // Preserve the authentication path's bounded object/lifecycle locks. The
    // qualification itself belongs to the same pure SQL kernel used by read models.
    for row in rows_for(c, tenant, run, channel, device).await? {
        if !row.unknown && row.input.verified {
            current(reader, c, tenant, &row.input, channel).await?;
        }
    }
    channel_state_on(c, scope, channel, device).await
}
pub(crate) async fn channel_state_on(
    c: &mut PgConnection,
    scope: Uuid,
    channel: Channel,
    device: &str,
) -> Result<ScopeAdmission, SourceError> {
    let value: serde_json::Value =
        sqlx::query_scalar("SELECT mdm_commands.channel_admission($1,$2,$3)")
            .bind(scope)
            .bind(channel.as_str())
            .bind(device)
            .fetch_one(c)
            .await?;
    match value["state"].as_str() {
        Some("eligible") => {
            let entry = value["entry"]
                .as_i64()
                .filter(|entry| *entry > 0)
                .ok_or(SourceError::Invariant)?;
            Ok(ScopeAdmission::Eligible { entry })
        }
        Some("pending") => Ok(ScopeAdmission::Pending),
        Some("excluded") => Ok(ScopeAdmission::Excluded),
        _ => Err(SourceError::Invariant),
    }
}
pub(crate) async fn explanation_on(
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
    let mut current_target = false;
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
            current_target |= frozen.definition.targets.contains(
                &frozen
                    .sources
                    .get(row.source)
                    .ok_or(SourceError::Invariant)?
                    .reference,
            );
        }
    }
    if reader.is_some() {
        if !current_target {
            return Ok(None);
        }
        // Direct membership is the immutable identity predicate. Current target
        // qualification is checked above; Group evidence may still be unknown.
        for (index, source) in frozen.sources.iter().enumerate() {
            if let Reference::Device(id) = &source.reference {
                uncertain.remove(&index);
                if id == device {
                    known.insert(index);
                } else {
                    known.remove(&index);
                }
            }
        }
    }
    resolve_membership(tenant, frozen, device, at, &known, &uncertain, None)
}

fn resolve_membership(
    tenant: TenantId,
    frozen: &ScopeInput,
    device: &str,
    at: Timepoint,
    known: &BTreeSet<usize>,
    uncertain: &BTreeSet<usize>,
    object: Option<(&DeviceObject, u64)>,
) -> Result<Option<s::MemberExplanation>, SourceError> {
    let membership = |refs: &BTreeSet<Reference>| -> Result<Vec<s::SourceMembership>, SourceError> {
        frozen
            .sources
            .iter()
            .enumerate()
            .filter(|(_, source)| refs.contains(&source.reference))
            .map(|(index, source)| {
                let id = match &source.reference {
                    Reference::Device(id) => {
                        // Normalize direct endpoint references into the same object
                        // universe as the verified complete-device target. Multiple
                        // member references coalesce to one direct object source.
                        let key = match object {
                            Some((object, _)) if object.members.iter().any(|m| m.device == *id) => {
                                object.object.key()
                            }
                            Some(_) => ObjectRef::Endpoint(id.clone()).key(),
                            None => id.clone(),
                        };
                        s::SourceId::Direct(
                            s::DeviceId::new(tenant, key).map_err(|_| SourceError::Invariant)?,
                        )
                    }
                    Reference::Group(id) => s::SourceId::Group(
                        s::GroupId::new(tenant, id.to_string())
                            .map_err(|_| SourceError::Invariant)?,
                    ),
                };
                Ok(s::SourceMembership {
                    source: s::SourceRef::new(
                        id,
                        match (object, &source.reference) {
                            (Some((_, revision)), Reference::Device(_)) => revision,
                            _ => {
                                source.coordinates.member_version
                                    + source.coordinates.authority_version
                                    + 1
                            }
                        },
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
    let (run, _, frozen) = rss_mdm_scope_service::results::published_on(c, tenant, scope)
        .await?
        .ok_or(SourceError::Conflict)?;
    let targets: Vec<i32> = frozen
        .sources
        .iter()
        .enumerate()
        .filter(|(_, s)| frozen.definition.targets.contains(&s.reference))
        .map(|(i, _)| i as i32)
        .collect();
    let devices = rss_mdm_scope_service::results::source_devices_on(
        c,
        tenant,
        run,
        &targets,
        channel,
        after,
        limit + 1,
    )
    .await?;
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
    limit: usize,
) -> Result<Vec<AssignmentObject>, SourceError> {
    let Some((run, _, frozen, fresh)) =
        rss_mdm_scope_service::results::read_resolution_on(c, tenant, scope).await?
    else {
        return Ok(Vec::new());
    };
    let targets: Vec<i32> = frozen
        .sources
        .iter()
        .enumerate()
        .filter(|(_, s)| frozen.definition.targets.contains(&s.reference))
        .map(|(i, _)| i as i32)
        .collect();
    let rows = rss_mdm_scope_service::results::source_objects_on(
        c,
        tenant,
        run,
        &targets,
        after,
        limit + 1,
    )
    .await?;
    let mut result = Vec::new();
    for row in rows {
        let input: DeviceObject =
            serde_json::from_value(row.input).map_err(|_| SourceError::Invariant)?;
        let target = current(reader, c, tenant, &input, channel).await?;
        let uncertain = row.unknown;
        let admission = if !fresh || uncertain {
            ScopeAdmission::Pending
        } else if let Some(target) = &target {
            channel_state_on(c, scope, channel, &target.device).await?
        } else {
            ScopeAdmission::Pending
        };
        let ready = target.is_some() && matches!(admission, ScopeAdmission::Eligible { .. });
        let sources = if ready {
            rows_for(c, tenant, run, channel, &target.as_ref().unwrap().device)
                .await?
                .into_iter()
                .filter(|row| !row.unknown)
                .map(|row| row.input)
                .collect()
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
    match admission_on(reader, c, tenant, scope, channel, device).await? {
        ScopeAdmission::Pending => return Ok(vec![]),
        ScopeAdmission::Excluded => return Err(SourceError::Conflict),
        ScopeAdmission::Eligible { .. } => (),
    }
    let (run, _, _, _) = resolution(c, tenant, scope)
        .await?
        .ok_or(SourceError::Conflict)?;
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
    rss_mdm_scope_service::results::historical_on(c, tenant, scope, run)
        .await
        .map_err(|error| match error {
            sqlx::Error::RowNotFound => SourceError::Missing,
            error => SourceError::Storage(error),
        })
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
        Some(result) if result.reasons.is_empty() => {
            published_admission(c, tenant, run, channel, device).await?
        }
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
pub async fn result_available_on(
    c: &mut PgConnection,
    tenant: TenantId,
    scope: Uuid,
    run: Uuid,
    channel: Channel,
    device: &str,
    reader: &dyn rss_mdm_inventory_service::objects::ObjectReader,
) -> Result<bool, SourceError> {
    let frozen = historical(c, tenant, scope, run).await?;
    Ok(
        explanation_on(c, tenant, run, &frozen, channel, device, Some(reader))
            .await?
            .is_some_and(|result| result.reasons.is_empty()),
    )
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
    let devices = rss_mdm_scope_service::results::source_devices_on(
        c,
        tenant,
        run,
        &targets,
        channel,
        after,
        limit + 1,
    )
    .await?;
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

async fn published_admission(
    c: &mut PgConnection,
    tenant: TenantId,
    run: Uuid,
    channel: Channel,
    device: &str,
) -> Result<ScopeAdmission, SourceError> {
    let row = sqlx::query_as::<_,(bool,bool,i64)>("SELECT matched,pending,entry_revision FROM mdm_commands.scope_channel_results WHERE tenant_id=$1::uuid AND run=$2 AND channel=$3 AND device=$4")
  .bind(tenant.to_string()).bind(run).bind(channel.as_str()).bind(device).fetch_optional(c).await?;
    Ok(match row {
        Some((true, false, entry)) if entry > 0 => ScopeAdmission::Eligible { entry },
        Some((_, true, _)) => ScopeAdmission::Pending,
        _ => ScopeAdmission::Excluded,
    })
}

/// Apply the same Scope algebra to the complete managed object. No member is
/// selected as a proxy transport, and exclusions on either member exclude it.
pub async fn lifecycle_objects_on(
    reader: &dyn rss_mdm_inventory_service::objects::ObjectReader,
    c: &mut PgConnection,
    tenant: TenantId,
    scope: Uuid,
    after: Option<&str>,
    limit: usize,
) -> Result<Vec<DeviceAssignment>, SourceError> {
    let Some((run, revision, frozen, fresh)) =
        rss_mdm_scope_service::results::read_resolution_on(c, tenant, scope).await?
    else {
        return Ok(Vec::new());
    };
    let targets: Vec<i32> = frozen
        .sources
        .iter()
        .enumerate()
        .filter(|(_, s)| frozen.definition.targets.contains(&s.reference))
        .map(|(i, _)| i as i32)
        .collect();
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!("SELECT DISTINCT ON(object_key) input,unknown FROM (SELECT m.input,m.unknown,CASE WHEN a.id IS NOT NULL THEN 'association:'||a.id::text WHEN m.input->'object'->>'kind'='endpoint' THEN 'endpoint:'||(m.input->'object'->>'id') ELSE 'association:'||(m.input->'object'->>'id') END COLLATE \"C\" AS object_key FROM ({}) m LEFT JOIN mdm_devices.members d ON d.tenant_id=m.tenant_id AND m.input->'object'->>'kind'='endpoint' AND d.device=m.input->'object'->>'id' AND NOT d.released LEFT JOIN mdm_devices.associations a ON(a.tenant_id,a.id)=(d.tenant_id,d.association_id) AND a.state<>'revoked') objects WHERE object_key>coalesce($4,'') COLLATE \"C\" ORDER BY object_key,unknown LIMIT $5",rss_mdm_scope_service::results::SOURCE_MEMBER_FACTS_SQL).as_str()))
        .bind(tenant.to_string()).bind(run).bind(targets).bind(after).bind((limit+1) as i64).fetch_all(&mut *c).await?;
    let at = Timepoint::try_from(frozen.as_of).map_err(|_| SourceError::Invariant)?;
    let mut out = Vec::new();
    for row in rows {
        let input: DeviceObject =
            serde_json::from_value(row.try_get("input")?).map_err(|_| SourceError::Invariant)?;
        let input = rss_mdm_device_service::lifecycle::complete_target_in(c, tenant, &input)
            .await
            .map_err(|_| SourceError::Invariant)?;
        let cursor = input.object.key();
        let mut known = BTreeSet::new();
        let mut uncertain = BTreeSet::new();
        let mut valid = fresh
            && input.verified
            && !row.try_get::<bool, _>("unknown")?
            && !input.members.is_empty();
        for member in &input.members {
            valid &= current(reader, c, tenant, &input, member.channel)
                .await?
                .as_ref()
                == Some(member);
            for source in rows_for(c, tenant, run, member.channel, &member.device).await? {
                if source.unknown
                    || !source.input.verified
                    || current(reader, c, tenant, &source.input, member.channel)
                        .await?
                        .is_none()
                {
                    uncertain.insert(source.source);
                } else {
                    known.insert(source.source);
                }
            }
        }
        // A direct reference is exact only when its original source snapshot is
        // complete. Do not turn unavailable evidence into a synthetic membership.
        valid &= frozen
            .sources
            .iter()
            .enumerate()
            .all(|(index, source)| match &source.reference {
                Reference::Device(device) => {
                    !uncertain.contains(&index)
                        && known.contains(&index)
                            == input.members.iter().any(|m| m.device == *device)
                }
                Reference::Group(_) => true,
            });
        let result = if valid {
            let mapped_revision = u64::try_from(revision)
                .map_err(|_| SourceError::Invariant)?
                .checked_add(1)
                .ok_or(SourceError::Invariant)?;
            resolve_membership(
                tenant,
                &frozen,
                &input.object.key(),
                at,
                &known,
                &uncertain,
                Some((&input, mapped_revision)),
            )?
        } else {
            None
        };
        let admission = if !valid {
            ScopeAdmission::Pending
        } else {
            match result {
                Some(r) if r.reasons.is_empty() => ScopeAdmission::Eligible { entry: revision },
                Some(r)
                    if r.reasons.iter().any(|r| {
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
            }
        };
        out.push(DeviceAssignment {
            cursor,
            object: input,
            admission,
            scope_result: run,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod lifecycle_mapping_tests {
    use super::*;
    use rss_mdm_scope::ScopeDefinition;
    use rss_mdm_scope_service::sources::SourceSet;
    #[test]
    fn complete_device_direct_sources_keep_limits_and_peer_exclusions() {
        let tenant = TenantId::parse("11111111-1111-1111-1111-111111111111").unwrap();
        let native = Reference::Device("native".into());
        let agent = Reference::Device("agent".into());
        let other = Reference::Device("other".into());
        let object = DeviceObject {
            object: ObjectRef::Association(Uuid::from_u128(1)),
            association_version: Some(1),
            verified: true,
            members: vec![
                rss_mdm_registration_service::device::endpoints::PrimaryRegistration {
                    device: "native".into(),
                    channel: Channel::Mdm,
                    registration_id: Uuid::from_u128(2),
                    generation: 1,
                },
                rss_mdm_registration_service::device::endpoints::PrimaryRegistration {
                    device: "agent".into(),
                    channel: Channel::Agent,
                    registration_id: Uuid::from_u128(3),
                    generation: 4,
                },
            ],
        };
        let mut frozen = ScopeInput {
            definition: ScopeDefinition {
                targets: BTreeSet::from([native.clone(), agent.clone()]),
                limitations: Some(BTreeSet::from([agent.clone()])),
                exclusions: BTreeSet::from([other.clone()]),
            },
            sources: [native.clone(), agent.clone(), other]
                .into_iter()
                .enumerate()
                .map(|(i, reference)| SourceSet {
                    reference,
                    coordinates: rss_mdm_group::SourceCoordinates {
                        member_set: None,
                        member_version: i as u64 + 1,
                        definition_version: 1,
                        authority_version: i as u64,
                        asset_context: rss_mdm_group::AssetContext::Endpoint,
                    },
                    snapshot: None,
                })
                .collect(),
            as_of: 1,
        };
        let at = Timepoint::try_from(1).unwrap();
        let known = BTreeSet::from([0, 1]);
        let unknown = BTreeSet::new();
        let result = resolve_membership(
            tenant,
            &frozen,
            &object.object.key(),
            at,
            &known,
            &unknown,
            Some((&object, 10)),
        )
        .unwrap()
        .unwrap();
        assert!(
            result.reasons.is_empty(),
            "two endpoint sources of one device must coalesce despite different source versions"
        );
        frozen.definition.targets = BTreeSet::from([native.clone()]);
        assert!(
            resolve_membership(
                tenant,
                &frozen,
                &object.object.key(),
                at,
                &known,
                &unknown,
                Some((&object, 10))
            )
            .unwrap()
            .unwrap()
            .reasons
            .is_empty(),
            "peer membership satisfies the device-level limitation"
        );
        frozen.definition.exclusions = BTreeSet::from([agent]);
        assert!(
            !resolve_membership(
                tenant,
                &frozen,
                &object.object.key(),
                at,
                &known,
                &unknown,
                Some((&object, 10))
            )
            .unwrap()
            .unwrap()
            .reasons
            .is_empty(),
            "excluding either endpoint excludes the complete device"
        );
        frozen.definition.limitations = None;
        frozen.definition.exclusions.clear();
        assert!(
            resolve_membership(
                tenant,
                &frozen,
                "native",
                at,
                &BTreeSet::from([0]),
                &unknown,
                None
            )
            .unwrap()
            .unwrap()
            .reasons
            .is_empty(),
            "ordinary endpoint resolution keeps its existing identity contract"
        );
    }
}
