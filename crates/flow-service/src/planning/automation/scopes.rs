use super::*;
use rss_mdm_scope as s;
use sqlx::Row;
use std::collections::{BTreeMap, BTreeSet};

fn check_scope_page(processed: usize, added: usize) -> std::result::Result<(), Error> {
    match processed.checked_add(added) {
        Some(total) if total <= 1_000_000 => Ok(()),
        _ => Err(Error::Unavailable(Failure::AssetObjectLimit)),
    }
}

#[cfg(test)]
include!("../../../tests/planning/automation/scopes_unit.rs");
fn fingerprint(revision: u64, frozen: &ScopeInput) -> Result<Vec<u8>> {
    use sha2::Digest;
    let sources: Vec<_> = frozen
        .sources
        .iter()
        .map(|s| {
            (
                &s.reference,
                s.member_version,
                s.definition_version,
                s.authority_version,
            )
        })
        .collect();
    Ok(sha2::Sha256::digest(checked_input(serde_json::to_vec(&(
        revision,
        &frozen.definition,
        sources,
    )))?)
    .to_vec())
}

pub fn references(
    scope: Uuid,
    revision: u64,
    input: &ScopeInput,
) -> Vec<crate::planning::sources::SourceReference> {
    let mut refs = vec![crate::planning::sources::SourceReference {
        id: format!("scope-definition.{scope}"),
        revision,
    }];
    for source in &input.sources {
        match &source.reference {
            Reference::Group(id) => {
                for (prefix, revision) in [
                    ("group-definition", source.definition_version),
                    ("group-members", source.member_version),
                    ("group-authority", source.authority_version),
                ] {
                    refs.push(crate::planning::sources::SourceReference {
                        id: format!("{prefix}.{id}"),
                        revision,
                    });
                }
            }
            Reference::Device(id) => refs.push(crate::planning::sources::SourceReference {
                id: device_reference(id),
                revision: source.authority_version,
            }),
        }
    }
    refs
}
impl Planning {
    /// Revalidate the frozen source identities in the head-locked publication/save
    /// transaction. The ingress worker may not have forwarded a committed change yet.
    pub async fn scope_authority_current_in(
        &self,
        tx: &mut PgTransaction<'_>,
        run: Uuid,
    ) -> Result<bool> {
        let tenant = self.tenant.to_string();
        Ok(tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM mdm_access.asset_authority_history h WHERE h.tenant_id=r.tenant_id AND h.revision>r.asset_watermark AND EXISTS(SELECT 1 FROM mdm_planning.scope_source_members m WHERE m.tenant_id=r.tenant_id AND m.run=r.id AND m.device=h.device)) FROM mdm_planning.scope_runs r WHERE r.tenant_id=$1::uuid AND r.id=$2::uuid")
                .bind(tenant).bind(run.to_string()).fetch_one(c).await
        })).await?)
    }

    async fn capture_scope_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        scope: Uuid,
    ) -> Result<()> {
        let (revision, definition) = self.scope_definition(tx, scope).await?;
        let tenant = self.tenant;
        let watermark = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    rss_mdm_inventory_postgres::watermark_in(c, tenant)
                        .await
                        .map_err(|_| sqlx::Error::Protocol("asset watermark unavailable".into()))
                })
            })
            .await?;
        let mut sources = Vec::new();
        for reference in definition.references() {
            let mut source = SourceSet {
                reference: reference.clone(),
                member_set: None,
                member_version: 0,
                definition_version: 0,
                authority_version: 0,
            };
            match reference {
                Reference::Group(id) => {
                    let gid =
                        checked_input(rss_mdm_group_postgres::GroupId::parse(&id.to_string()))?;
                    let group =
                        group_checked(self.groups.lock_reference_target_in(tx, gid).await?)?;
                    source.member_set = checked(self.groups.current_member_set_in(tx, gid).await?)?
                        .map(|id| stored(Uuid::parse_str(&id.to_string())))
                        .transpose()?;
                    if group.kind == rss_mdm_group_postgres::GroupKind::Dynamic {
                        let run = source
                            .member_set
                            .ok_or(Error::Unavailable(Failure::PlanningStorage))?;
                        let build = checked(
                            self.groups
                                .build_in(
                                    tx,
                                    checked_input(rss_mdm_group_postgres::OperationId::parse(
                                        &run.to_string(),
                                    ))?,
                                )
                                .await?,
                        )?;
                        if build.request.rule_version != group.rule_version {
                            return Err(Error::Unavailable(Failure::PlanningStorage).into());
                        }
                    }
                    source.member_version = group.member_version as u64;
                    source.definition_version = checked(
                        self.sources
                            .reference_in(tx, &format!("group-definition.{id}"))
                            .await?,
                    )?
                    .ok_or(Error::Conflict)?;
                    source.authority_version = checked(
                        self.sources
                            .reference_in(tx, &format!("group-authority.{id}"))
                            .await?,
                    )?
                    .ok_or(Error::Conflict)?;
                }
                Reference::Device(device) => {
                    let tenant = self.tenant.to_string();
                    let name = device.clone();
                    let version:i64=tx.with_connection(move |c|Box::pin(async move {
                        sqlx::query_scalar("SELECT coalesce(max(revision),0) FROM mdm_access.asset_authority_history WHERE tenant_id=$1::uuid AND device=$2 AND revision<=$3")
                            .bind(tenant).bind(name).bind(watermark).fetch_one(c).await
                    })).await?;
                    source.authority_version = version as u64;
                    checked(
                        self.sources
                            .advance_reference_in(
                                tx,
                                &device_reference(&device),
                                source.authority_version,
                            )
                            .await?,
                    )?;
                }
            }
            sources.push(source);
        }
        let frozen = ScopeInput {
            definition,
            sources,
            as_of: self
                .clock
                .unix_seconds()
                .map_err(|_| Error::Unavailable(Failure::Clock))?,
        };
        let document = checked_input(serde_json::to_string(&frozen))?;
        let fingerprint = fingerprint(revision, &frozen)?;
        let tenant = self.tenant.to_string();
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("INSERT INTO mdm_planning.scope_runs(tenant_id,id,scope,definition_revision,asset_watermark,input,fingerprint,phase) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5,$6::jsonb,$7,'sources')")
                .bind(tenant).bind(id.to_string()).bind(scope.to_string()).bind(revision as i64).bind(watermark).bind(document).bind(fingerprint).execute(c).await?;Ok(())
        })).await?;
        Ok(())
    }

    pub async fn advance_scope_job_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        scope: Uuid,
        cursor: Option<String>,
    ) -> Result<()> {
        let tenant = self.tenant.to_string();
        let row=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT phase,input::text,fingerprint,definition_revision,asset_watermark,source_index,source_cursor,evaluation_cursor,object_count,member_count FROM mdm_planning.scope_runs WHERE tenant_id=$1::uuid AND id=$2::uuid FOR UPDATE")
                .bind(tenant).bind(id.to_string()).fetch_optional(c).await
        })).await?;
        let Some(row) = row else {
            return self.capture_scope_in(tx, id, scope).await;
        };
        let frozen: ScopeInput = stored(serde_json::from_str(row.try_get("input")?))?;
        let revision = row.try_get::<i64, _>("definition_revision")? as u64;
        if fingerprint(revision, &frozen)? != row.try_get::<Vec<u8>, _>("fingerprint")? {
            return Err(Error::Unavailable(Failure::PlanningStorage).into());
        }
        let watermark: i64 = row.try_get("asset_watermark")?;
        match row.try_get::<&str, _>("phase")? {
            "sources" => {
                let index = row.try_get::<i32, _>("source_index")? as usize;
                let after: Option<String> = row.try_get("source_cursor")?;
                if index == frozen.sources.len() {
                    return self.scope_phase(tx, id, "evaluate").await;
                }
                let source = frozen
                    .sources
                    .get(index)
                    .ok_or(Error::Unavailable(Failure::PlanningStorage))?;
                let records = match &source.reference {
                    Reference::Device(device) => {
                        if after.is_none() {
                            vec![(device.clone(), false, true)]
                        } else {
                            vec![]
                        }
                    }
                    Reference::Group(_) => match source.member_set {
                        None => vec![],
                        Some(set) => {
                            let operation = checked_input(
                                rss_mdm_group_postgres::OperationId::parse(&set.to_string()),
                            )?;
                            let build = checked(self.groups.build_in(tx, operation).await?)?;
                            if build.receipt.is_none() {
                                return Err(Error::Unavailable(Failure::PlanningStorage).into());
                            }
                            checked(
                                self.groups
                                    .build_decisions_in(tx, operation, after, 1000)
                                    .await?,
                            )?
                            .into_iter()
                            .map(|d| {
                                (
                                    d.device,
                                    d.decision == rss_mdm_group_postgres::DecisionValue::Unknown,
                                    d.decision != rss_mdm_group_postgres::DecisionValue::NoMatch,
                                )
                            })
                            .collect()
                        }
                    },
                };
                // Evidence byte budgets may shorten a page; only an empty page seals a source.
                let more = !records.is_empty();
                let last = records.last().map(|r| r.0.clone());
                let (devices, unknown): (Vec<_>, Vec<_>) = records
                    .into_iter()
                    .filter(|r| r.2)
                    .map(|r| (r.0, r.1))
                    .unzip();
                let tenant = self.tenant.to_string();
                tx.with_connection(move |c|Box::pin(async move {
                    sqlx::query("INSERT INTO mdm_planning.scope_source_members(tenant_id,run,source,device,unknown) SELECT $1::uuid,$2::uuid,$3,d,u FROM unnest($4::text[],$5::boolean[]) AS p(d,u)")
                        .bind(&tenant).bind(id.to_string()).bind(index as i32).bind(devices).bind(unknown).execute(&mut *c).await?;
                    sqlx::query("UPDATE mdm_planning.scope_runs SET source_index=$3,source_cursor=$4 WHERE tenant_id=$1::uuid AND id=$2::uuid")
                        .bind(tenant).bind(id.to_string()).bind(if more {index as i32}else{index as i32+1}).bind(if more {last}else{None}).execute(c).await?;Ok(())
                })).await?;
                Ok(())
            }
            "evaluate" => {
                self.evaluate_scope_page_in(
                    tx,
                    id,
                    &frozen,
                    row.try_get("evaluation_cursor")?,
                    row.try_get::<i64, _>("object_count")? as usize,
                    watermark,
                )
                .await
            }
            "ready" => {
                self.publish_scope_in(tx, id, scope, revision, &frozen)
                    .await
            }
            "published" => self.propagate_scope_in(tx, id, scope, cursor).await,
            "superseded" => {
                crate::automation::jobs::finish_job_in(
                    tx,
                    &self.audit_store,
                    id,
                    Some("superseded"),
                )
                .await
            }
            _ => Err(Error::Unavailable(Failure::PlanningStorage).into()),
        }
    }

    async fn scope_phase(&self, tx: &mut PgTransaction<'_>, id: Uuid, phase: &str) -> Result<()> {
        let tenant = self.tenant.to_string();
        let phase = phase.to_owned();
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("UPDATE mdm_planning.scope_runs SET phase=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id.to_string()).bind(phase).execute(c).await?;Ok(())
        })).await?;
        Ok(())
    }

    async fn evaluate_scope_page_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        frozen: &ScopeInput,
        after: Option<String>,
        processed: usize,
        watermark: i64,
    ) -> Result<()> {
        let targets: Vec<i32> = frozen
            .sources
            .iter()
            .enumerate()
            .filter(|(_, s)| frozen.definition.targets.contains(&s.reference))
            .map(|(i, _)| i as i32)
            .collect();
        let limit = 1000usize.min(16000 / frozen.sources.len().max(1));
        let tenant = self.tenant.to_string();
        let mut devices:Vec<String>=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar("SELECT DISTINCT device FROM mdm_planning.scope_source_members WHERE tenant_id=$1::uuid AND run=$2::uuid AND source=ANY($3) AND device>coalesce($4::text,'') COLLATE \"C\" ORDER BY device LIMIT $5")
                .bind(tenant).bind(id.to_string()).bind(targets).bind(after).bind((limit+1) as i64).fetch_all(c).await
        })).await?;
        let more = devices.len() > limit;
        devices.truncate(limit);
        check_scope_page(processed, devices.len())?;
        let tenant = self.tenant.to_string();
        let selected = devices.clone();
        let rows=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT device,source,unknown FROM mdm_planning.scope_source_members WHERE tenant_id=$1::uuid AND run=$2::uuid AND device=ANY($3) ORDER BY device,source")
                .bind(tenant).bind(id.to_string()).bind(selected).fetch_all(c).await
        })).await?;
        let mut hits: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();
        let mut unknowns: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();
        for row in rows {
            if row.try_get::<bool, _>("unknown")? {
                unknowns
                    .entry(row.try_get("device")?)
                    .or_default()
                    .insert(row.try_get::<i32, _>("source")? as usize);
                continue;
            }
            hits.entry(row.try_get("device")?)
                .or_default()
                .insert(row.try_get::<i32, _>("source")? as usize);
        }
        let tenant = self.tenant.to_string();
        let selected = devices.clone();
        let authority=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_as::<_,(String,i64)>("SELECT device,max(revision) FROM mdm_access.asset_authority_history WHERE tenant_id=$1::uuid AND device=ANY($2) AND revision<=$3 GROUP BY device").bind(tenant).bind(selected).bind(watermark).fetch_all(c).await
        })).await?.into_iter().collect::<BTreeMap<_,_>>();
        let at = checked_input(Timepoint::try_from(frozen.as_of))?;
        let live = self
            .asset_reader
            .live_devices_at_in(tx, watermark, &devices)
            .await?;
        let tenant = self.tenant.to_string();
        let selected = devices.clone();
        let identity:i64=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar("SELECT coalesce(max((SELECT revision FROM mdm_access.asset_authority_history h WHERE h.tenant_id=$1::uuid AND h.device=d AND h.revision<=$3 ORDER BY revision DESC LIMIT 1)),0) FROM unnest($2::text[]) d")
                .bind(tenant).bind(selected).bind(watermark).fetch_one(c).await
        })).await?;
        let mut matched = Vec::new();
        let mut explanations = Vec::new();
        for device in &devices {
            let key = checked_input(s::DeviceId::new(self.tenant, device))?;
            let empty_hits = BTreeSet::new();
            let source_hits = hits.get(device).unwrap_or(&empty_hits);
            let resolve = |refs: &BTreeSet<Reference>| -> Result<Vec<s::SourceMembership>> {
                frozen
                    .sources
                    .iter()
                    .enumerate()
                    .filter(|(_, source)| refs.contains(&source.reference))
                    .map(|(index, source)| {
                        let (identity, version) = match &source.reference {
                            Reference::Device(d) => (
                                s::SourceId::Direct(checked_input(s::DeviceId::new(
                                    self.tenant,
                                    d,
                                ))?),
                                source.authority_version.max(1),
                            ),
                            Reference::Group(g) => (
                                s::SourceId::Group(checked_input(s::GroupId::new(
                                    self.tenant,
                                    g.to_string(),
                                ))?),
                                source.member_version + 1,
                            ),
                        };
                        Ok(s::SourceMembership {
                            source: checked_input(s::SourceRef::new(identity, version, at))?,
                            contains: if unknowns.get(device).is_some_and(|v| v.contains(&index)) {
                                s::Membership::Unknown
                            } else {
                                s::Membership::Known(source_hits.contains(&index))
                            },
                        })
                    })
                    .collect()
            };
            let result = checked_input(s::resolve_device(&s::DeviceInput {
                device: key,
                targets: resolve(&frozen.definition.targets)?,
                limitations: frozen
                    .definition
                    .limitations
                    .as_ref()
                    .map(resolve)
                    .transpose()?,
                exclusions: resolve(&frozen.definition.exclusions)?,
            }))?
            .ok_or(Error::Unavailable(Failure::PlanningStorage))?;
            matched.push(result.reasons.is_empty() && live.contains(device));
            explanations.push(checked_input(serde_json::to_string(&serde_json::json!({"device":device,"identityRevision":authority.get(device).copied().unwrap_or(0),"identity":if live.contains(device){"active"}else{"inactive"},"reasons":result.reasons.iter().map(|r|match r {s::ExclusionReason::MissingLimitationMatch=>"missing_limitation_match",s::ExclusionReason::ExplicitExclusion=>"explicit_exclusion",s::ExclusionReason::UnknownTarget=>"unknown_target",s::ExclusionReason::UnknownLimitation=>"unknown_limitation",s::ExclusionReason::UnknownExclusion=>"unknown_exclusion"}).collect::<Vec<_>>(),"sources":source_hits})))?);
        }
        let tenant = self.tenant.to_string();
        let count = devices.len() as i64;
        let members = matched.iter().filter(|v| **v).count() as i64;
        let last = devices.last().cloned();
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("INSERT INTO mdm_planning.scope_results(tenant_id,run,device,matched,explanation) SELECT $1::uuid,$2::uuid,d,m,e::jsonb FROM unnest($3::text[],$4::boolean[],$5::text[]) AS p(d,m,e)")
                .bind(&tenant).bind(id.to_string()).bind(devices).bind(matched).bind(explanations).execute(&mut *c).await?;
            sqlx::query("UPDATE mdm_planning.scope_runs SET object_count=object_count+$3,member_count=member_count+$4,evaluation_cursor=$5,phase=$6,identity_revision=greatest(identity_revision,$7),result_fingerprint=CASE WHEN $6='ready' THEN sha256(fingerprint||int8send(greatest(identity_revision,$7))) ELSE NULL END WHERE tenant_id=$1::uuid AND id=$2::uuid")
                .bind(tenant).bind(id.to_string()).bind(count).bind(members).bind(last).bind(if more {"evaluate"}else{"ready"}).bind(identity).execute(c).await?;Ok(())
        })).await?;
        Ok(())
    }

    async fn publish_scope_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        scope: Uuid,
        revision: u64,
        frozen: &ScopeInput,
    ) -> Result<()> {
        let (current, _) = self.scope_definition(tx, scope).await?;
        if current != revision || !self.scope_authority_current_in(tx, id).await? {
            return Err(Error::Conflict.into());
        }
        for reference in references(scope, revision, frozen) {
            if checked(self.sources.reference_in(tx, &reference.id).await?)?
                != Some(reference.revision)
            {
                return Err(Error::Conflict.into());
            }
        }
        let tenant = self.tenant.to_string();
        let version:i64=tx.with_connection(move|c|Box::pin(async move {
            let (previous,old_version)=sqlx::query_as::<_,(Option<Uuid>,i64)>("SELECT resolution,resolution_revision FROM mdm_planning.scopes WHERE tenant_id=$1::uuid AND id=$2::uuid FOR UPDATE").bind(&tenant).bind(scope.to_string()).fetch_one(&mut *c).await?;
            let changed=sqlx::query_scalar::<_,bool>("WITH old AS (SELECT device,matched,explanation->'reasons' AS reasons,explanation->'identityRevision' AS identity FROM mdm_planning.scope_results WHERE tenant_id=$1::uuid AND run=$2), new AS (SELECT device,matched,explanation->'reasons' AS reasons,explanation->'identityRevision' AS identity FROM mdm_planning.scope_results WHERE tenant_id=$1::uuid AND run=$3) SELECT EXISTS((SELECT * FROM old EXCEPT SELECT * FROM new) UNION ALL (SELECT * FROM new EXCEPT SELECT * FROM old))")
                .bind(&tenant).bind(previous).bind(id).fetch_one(&mut *c).await? || previous.is_none();
            let version=old_version.checked_add(i64::from(changed)).ok_or_else(||sqlx::Error::Protocol("scope revision overflow".into()))?;
            sqlx::query("UPDATE mdm_planning.scope_results n SET entry_revision=coalesce((SELECT o.entry_revision FROM mdm_planning.scope_results o WHERE o.tenant_id=n.tenant_id AND o.run=$3 AND o.device=n.device AND o.matched),$4) WHERE n.tenant_id=$1::uuid AND n.run=$2 AND n.matched")
                .bind(&tenant).bind(id).bind(previous).bind(version).execute(&mut *c).await?;
            sqlx::query("UPDATE mdm_planning.scope_runs SET previous_resolution=$3,semantic_changed=$4 WHERE tenant_id=$1::uuid AND id=$2").bind(&tenant).bind(id).bind(previous).bind(changed).execute(&mut *c).await?;
            sqlx::query("UPDATE mdm_planning.scopes SET resolution=$3,resolution_revision=$4,calculation_revision=calculation_revision+1 WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(scope).bind(id).bind(version).execute(c).await?;
            Ok(version)
        })).await?;
        checked(
            self.sources
                .advance_reference_in(tx, &format!("scope-resolution.{scope}"), version as u64)
                .await?,
        )?;
        self.scope_phase(tx, id, "published").await
    }

    async fn propagate_scope_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        scope: Uuid,
        after: Option<String>,
    ) -> Result<()> {
        let tenant = self.tenant.to_string();
        let interested=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND definition->>'scope'=$2 AND definition->'action'->>'kind' IN('configuration','ensure_agent_installed'))").bind(tenant).bind(scope.to_string()).fetch_one(c).await
        })).await?;
        if !interested {
            return crate::automation::jobs::finish_job_in(tx, &self.audit_store, task, None).await;
        }
        let tenant = self.tenant.to_string();
        let mut devices=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar::<_,String>("WITH source AS (SELECT previous_resolution FROM mdm_planning.scope_runs WHERE tenant_id=$1::uuid AND id=$2 AND semantic_changed), old AS (SELECT device,matched,explanation->'reasons' AS reasons,explanation->'identityRevision' AS identity FROM mdm_planning.scope_results WHERE tenant_id=$1::uuid AND run=(SELECT previous_resolution FROM source)), new AS (SELECT device,matched,explanation->'reasons' AS reasons,explanation->'identityRevision' AS identity FROM mdm_planning.scope_results WHERE tenant_id=$1::uuid AND run=$2 AND EXISTS(SELECT 1 FROM source)) SELECT device FROM (SELECT coalesce(n.device,o.device) COLLATE \"C\" AS device FROM new n FULL JOIN old o USING(device) WHERE (n.matched,n.reasons,n.identity) IS DISTINCT FROM (o.matched,o.reasons,o.identity) UNION SELECT c.device COLLATE \"C\" FROM mdm_planning.configuration_claims c JOIN mdm_policy.policies p ON(p.tenant_id,p.id)=(c.tenant_id,c.policy) JOIN mdm_planning.configuration_objects d ON(d.tenant_id,d.device,d.user_key,d.platform,d.object_kind,d.object_key)=(c.tenant_id,c.device,c.user_key,c.platform,c.object_kind,c.object_key) WHERE c.tenant_id=$1::uuid AND p.definition->>'scope'=$4 AND d.diagnosis=$5) changes WHERE device>coalesce($3,'') COLLATE \"C\" ORDER BY device LIMIT 65")
                .bind(tenant).bind(task).bind(after).bind(scope.to_string()).bind(rss_mdm_execution_service::ConfigurationDiagnosis::WaitingScope.as_str()).fetch_all(c).await
        })).await?;
        let more = devices.len() > 64;
        devices.truncate(64);
        for device in &devices {
            rss_mdm_execution_service::wake::wake_native_in(tx, device).await?;
        }
        if !more {
            return crate::automation::jobs::finish_job_in(tx, &self.audit_store, task, None).await;
        }
        let tenant = self.tenant.to_string();
        let next = devices.last().cloned();
        tx.with_connection(move|c|Box::pin(async move {
            sqlx::query("UPDATE mdm_automation.automation_jobs SET cursor=$3 WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(task).bind(next).execute(c).await?;Ok(())
        })).await?;
        Ok(())
    }
}
