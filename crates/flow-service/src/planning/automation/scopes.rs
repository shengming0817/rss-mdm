use super::*;
use sqlx::Row;

fn check_scope_page(processed: usize, added: usize) -> std::result::Result<(), Error> {
    match processed.checked_add(added) {
        Some(total) if i64::try_from(total).is_ok() => Ok(()),
        _ => Err(Error::Unavailable(Failure::AssetObjectLimit)),
    }
}

#[cfg(test)]
include!("../../../tests/planning/automation/scopes_unit.rs");
fn fingerprint(revision: u64, frozen: &ScopeInput) -> Result<Vec<u8>> {
    use sha2::Digest;
    Ok(sha2::Sha256::digest(checked_input(serde_json::to_vec(&(
        revision,
        &frozen.definition,
        &frozen.sources,
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
                    ("group-definition", source.coordinates.definition_version),
                    ("group-members", source.coordinates.member_version),
                    ("group-authority", source.coordinates.authority_version),
                ] {
                    refs.push(crate::planning::sources::SourceReference {
                        id: format!("{prefix}.{id}"),
                        revision,
                    });
                }
            }
            Reference::Device(id) => refs.push(crate::planning::sources::SourceReference {
                id: device_reference(id),
                revision: source.coordinates.authority_version,
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
        let input: Value = tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar("SELECT input FROM mdm_planning.scope_runs WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(run).fetch_one(c).await})).await?;
        let input: ScopeInput = stored(serde_json::from_value(input))?;
        for source in &input.sources {
            if let Reference::Group(id) = source.reference {
                let frozen = rss_mdm_group::GroupSource {
                    group: checked_input(rss_mdm_group::GroupId::parse(&id.to_string()))?,
                    coordinates: source.coordinates.clone(),
                };
                if !self.source_current_in(tx, &frozen).await? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    async fn capture_scope_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        scope: Uuid,
    ) -> Result<()> {
        let rss_mdm_scope_postgres::DefinitionSnapshot {
            revision,
            definition,
        } = self.scope_definition(tx, scope).await?;
        let tenant = self.tenant;
        let watermark = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    rss_mdm_inventory_postgres::watermark_in(c, tenant)
                        .await
                        .map_err(|_| sqlx::Error::Protocol("asset coordinate unavailable".into()))
                })
            })
            .await?;
        let mut sources = Vec::new();
        for reference in definition.references() {
            let mut source = SourceSet {
                reference: reference.clone(),
                coordinates: rss_mdm_group::SourceCoordinates {
                    member_set: None,
                    member_version: 0,
                    definition_version: 0,
                    authority_version: 0,
                    asset_context: rss_mdm_group::AssetContext::Endpoint,
                },
                snapshot: None,
            };
            match reference {
                Reference::Group(id) => {
                    let frozen = self.capture_group_source_in(tx, id).await?;
                    source.coordinates = frozen.coordinates;
                    if let Some(run) = source.coordinates.member_set {
                        let build = checked(self.groups.build_in(tx, run).await?)?;
                        source.snapshot =
                            super::groups::object_snapshot(&build.request.input_version)?;
                    }
                }
                Reference::Device(device) => {
                    let tenant = self.tenant.to_string();
                    let name = device.clone();
                    let version:i64=tx.with_connection(move |c|Box::pin(async move {
                        sqlx::query_scalar("SELECT coalesce(max(revision),0) FROM mdm_access.asset_authority_history WHERE tenant_id=$1::uuid AND device=$2 AND revision<=$3")
                            .bind(tenant).bind(name).bind(watermark).fetch_one(c).await
                    })).await?;
                    source.coordinates.authority_version = version as u64;
                    checked(
                        self.sources
                            .advance_reference_in(
                                tx,
                                &device_reference(&device),
                                source.coordinates.authority_version,
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
            sqlx::query("SELECT phase,input::text,fingerprint,definition_revision,asset_watermark,source_index,source_cursor,evaluation_cursor,projection_cursor,object_count,member_count FROM mdm_planning.scope_runs WHERE tenant_id=$1::uuid AND id=$2::uuid FOR UPDATE")
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
        let phase = row.try_get::<&str, _>("phase")?;
        if !matches!(phase, "published" | "superseded") {
            // A definition update must not remain behind an unavailable old source.
            if self.scope_definition(tx, scope).await?.revision != revision {
                return Err(Error::Conflict.into());
            }
            for source in &frozen.sources {
                if let Reference::Group(id) = source.reference {
                    let source = rss_mdm_group::GroupSource {
                        group: checked_input(rss_mdm_group::GroupId::parse(&id.to_string()))?,
                        coordinates: source.coordinates.clone(),
                    };
                    if !self.source_ready_in(tx, &source).await? {
                        return Ok(());
                    }
                }
            }
        }
        match phase {
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
                    Reference::Group(_) => match source.coordinates.member_set {
                        None => vec![],
                        Some(set) => {
                            let operation =
                                checked_input(rss_mdm_group::OperationId::parse(&set.to_string()))?;
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
                let mut devices = Vec::new();
                let mut unknown = Vec::new();
                let mut inputs = Vec::new();
                for (key, uncertain, included) in records {
                    if !included {
                        continue;
                    }
                    let object =
                        group_checked(rss_mdm_inventory_service::objects::ObjectRef::from_key(
                            source.coordinates.asset_context,
                            &key,
                        ))?;
                    let reader = self.objects.clone();
                    let tenant = self.tenant;
                    let key = object.clone();
                    let input = if let Some(snapshot) = &source.snapshot {
                        let snapshot = snapshot.id;
                        tx.with_connection(move |c| {
                            Box::pin(async move { reader.lookup(c, tenant, snapshot, &key).await })
                        })
                        .await?
                    } else {
                        let rss_mdm_inventory_service::objects::ObjectRef::Endpoint(endpoint) = key
                        else {
                            return Err(Error::Conflict.into());
                        };
                        tx.with_connection(move |c| {
                            Box::pin(async move { reader.endpoint(c, tenant, &endpoint).await })
                        })
                        .await?
                    };
                    devices.push(object.key());
                    unknown.push(uncertain);
                    inputs.push(checked_input(serde_json::to_value(input))?);
                }
                let projection_target = frozen.definition.targets.contains(&source.reference);
                let tenant = self.tenant.to_string();
                tx.with_connection(move |c|Box::pin(async move {
                    if projection_target {
                        sqlx::query("INSERT INTO mdm_planning.scope_channel_results(tenant_id,run,channel,device,matched,pending,target,entry_revision) SELECT $1::uuid,$2::uuid,m->>'channel',m->>'device',false,false,m,0 FROM unnest($3::jsonb[]) i CROSS JOIN LATERAL jsonb_array_elements(i->'members') m GROUP BY m ON CONFLICT(tenant_id,run,channel,device) DO UPDATE SET pending=mdm_planning.scope_channel_results.pending OR mdm_planning.scope_channel_results.target IS DISTINCT FROM EXCLUDED.target").bind(&tenant).bind(id).bind(&inputs).execute(&mut *c).await?;
                    }
                    sqlx::query("INSERT INTO mdm_planning.scope_source_members(tenant_id,run,source,device,unknown,input) SELECT $1::uuid,$2::uuid,$3,d,u,i FROM unnest($4::text[],$5::boolean[],$6::jsonb[]) AS p(d,u,i)")
                        .bind(&tenant).bind(id.to_string()).bind(index as i32).bind(devices).bind(unknown).bind(inputs).execute(&mut *c).await?;
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
            "project" => {
                self.project_scope_page_in(
                    tx,
                    id,
                    scope,
                    &frozen,
                    row.try_get("projection_cursor")?,
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
        _watermark: i64,
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
        let matched = vec![true; devices.len()];
        let explanations: Vec<_> = devices
            .iter()
            .map(|key| {
                serde_json::json!({"objectKey":key,"reasons":[],"identityRevision":0}).to_string()
            })
            .collect();
        let identity = 0i64;
        let tenant = self.tenant.to_string();
        let count = devices.len() as i64;
        let members = matched.iter().filter(|v| **v).count() as i64;
        let last = devices.last().cloned();
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("INSERT INTO mdm_planning.scope_results(tenant_id,run,device,matched,explanation) SELECT $1::uuid,$2::uuid,d,m,e::jsonb FROM unnest($3::text[],$4::boolean[],$5::text[]) AS p(d,m,e)")
                .bind(&tenant).bind(id.to_string()).bind(devices).bind(matched).bind(explanations).execute(&mut *c).await?;
            sqlx::query("UPDATE mdm_planning.scope_runs SET object_count=object_count+$3,member_count=member_count+$4,evaluation_cursor=$5,phase=$6,identity_revision=greatest(identity_revision,$7),result_fingerprint=CASE WHEN $6='project' THEN sha256(fingerprint||int8send(greatest(identity_revision,$7))) ELSE NULL END WHERE tenant_id=$1::uuid AND id=$2::uuid")
                .bind(tenant).bind(id.to_string()).bind(count).bind(members).bind(last).bind(if more {"evaluate"}else{"project"}).bind(identity).execute(c).await?;Ok(())
        })).await?;
        Ok(())
    }

    // Fixed source evidence is projected before publication. Policy reconciliation cannot
    // erase an intermediate published exit, even when it observes only the latest run.
    async fn project_scope_page_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        scope: Uuid,
        frozen: &ScopeInput,
        after: Option<String>,
    ) -> Result<()> {
        let tenant = self.tenant;
        let (previous, epoch) = self
            .scope_projection_head_in(tx, id, scope, after.is_none())
            .await?;
        let page=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_as::<_,(String,String,String)>("SELECT channel,device,channel||':'||device AS key FROM mdm_planning.scope_channel_results WHERE tenant_id=$1::uuid AND run=$2 AND channel||':'||device>coalesce($3,'') COLLATE \"C\" ORDER BY (channel||':'||device) COLLATE \"C\" LIMIT 17").bind(tenant.to_string()).bind(id).bind(after).fetch_all(c).await
        })).await?;
        let hashes:serde_json::Value=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar("SELECT channel_hashes FROM mdm_planning.scope_runs WHERE tenant_id=$1::uuid AND id=$2").bind(tenant.to_string()).bind(id).fetch_one(c).await})).await?;
        let mut hashes: std::collections::BTreeMap<String, String> =
            stored(serde_json::from_value(hashes))?;
        for (channel, device, _) in page.iter().take(16) {
            let channel = match channel.as_str() {
                "agent" => rss_mdm_inventory::Channel::Agent,
                "mdm" => rss_mdm_inventory::Channel::Mdm,
                _ => return Err(Error::Malformed.into()),
            };
            let device = device.clone();
            let frozen = frozen.clone();
            let row_hash=tx.with_connection(move |c|Box::pin(async move {
                let result=super::super::targets::explanation_on(c,tenant,id,&frozen,channel,&device,None).await.map_err(|_|sqlx::Error::Protocol("scope projection invalid".into()))?;
                let identities:Vec<serde_json::Value>=sqlx::query_scalar("SELECT DISTINCT m FROM mdm_planning.scope_source_members s CROSS JOIN LATERAL jsonb_array_elements(s.input->'members') m WHERE s.tenant_id=$1::uuid AND s.run=$2 AND s.input->'members' @> jsonb_build_array(jsonb_build_object('device',$4::text,'channel',$3::text)) AND m->>'channel'=$3 AND m->>'device'=$4").bind(tenant.to_string()).bind(id).bind(channel.as_str()).bind(&device).fetch_all(&mut *c).await?;
                let target=identities.first().ok_or_else(||sqlx::Error::Protocol("scope target missing".into()))?.clone();
                let excluded=result.as_ref().is_some_and(|r| r.reasons.contains(&rss_mdm_scope::ExclusionReason::ExplicitExclusion));
                let pending=!excluded && (identities.len()!=1 || result.as_ref().is_some_and(|r|r.reasons.iter().any(|r|matches!(r,rss_mdm_scope::ExclusionReason::UnknownTarget|rss_mdm_scope::ExclusionReason::UnknownLimitation|rss_mdm_scope::ExclusionReason::UnknownExclusion))));
                let matched=!pending && result.as_ref().is_some_and(|r|r.reasons.is_empty());
                let entry=if matched || pending {sqlx::query_scalar::<_,i64>("SELECT entry_revision FROM mdm_planning.scope_channel_results WHERE tenant_id=$1::uuid AND run=$2 AND channel=$3 AND device=$4 AND (matched OR pending) AND entry_revision>0 AND target=$5").bind(tenant.to_string()).bind(previous).bind(channel.as_str()).bind(&device).bind(&target).fetch_optional(&mut *c).await?.unwrap_or(if matched {epoch}else{0})}else{0};
                sqlx::query("UPDATE mdm_planning.scope_channel_results SET matched=$5,pending=$6,target=$7,entry_revision=$8 WHERE tenant_id=$1::uuid AND run=$2 AND channel=$3 AND device=$4").bind(tenant.to_string()).bind(id).bind(channel.as_str()).bind(&device).bind(matched).bind(pending).bind(&target).bind(entry).execute(c).await?;
                Ok(serde_json::json!([device,matched,pending,target]))
            })).await?;
            use sha2::Digest;
            let key = channel.as_str();
            let previous = hashes.get(key).ok_or(Error::Malformed)?;
            let bytes = checked_input(serde_json::to_vec(&row_hash))?;
            let mut digest = sha2::Sha256::new();
            digest.update(previous.as_bytes());
            digest.update((bytes.len() as u64).to_be_bytes());
            digest.update(bytes);
            hashes.insert(key.into(), format!("{:x}", digest.finalize()));
        }
        let hashes = checked_input(serde_json::to_value(hashes))?;
        let tenant = tenant.to_string();
        let next = page.iter().take(16).next_back().map(|r| r.2.clone());
        let more = page.len() > 16;
        tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_planning.scope_runs SET projection_cursor=$3,phase=$4,channel_hashes=$5 WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).bind(next).bind(if more{"project"}else{"ready"}).bind(hashes).execute(c).await?;Ok(())})).await?;
        Ok(())
    }
    async fn scope_projection_head_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        scope: Uuid,
        first: bool,
    ) -> Result<(Option<Uuid>, i64)> {
        let tenant = self.tenant.to_string();
        Ok(tx.with_connection(move|c|Box::pin(async move {
            let (previous,calculation)=sqlx::query_as::<_,(Option<Uuid>,i64)>("SELECT resolution,calculation_revision FROM mdm_planning.scopes WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE").bind(&tenant).bind(scope).fetch_one(&mut *c).await?;
            if first {sqlx::query("UPDATE mdm_planning.scope_runs SET previous_resolution=$3 WHERE tenant_id=$1::uuid AND id=$2").bind(&tenant).bind(id).bind(previous).execute(&mut *c).await?;}
            else {let captured:Option<Uuid>=sqlx::query_scalar("SELECT previous_resolution FROM mdm_planning.scope_runs WHERE tenant_id=$1::uuid AND id=$2").bind(&tenant).bind(id).fetch_one(&mut *c).await?;if captured!=previous{return Err(sqlx::Error::Protocol("scope projection superseded".into()));}}
            Ok((previous,calculation.checked_add(1).ok_or_else(||sqlx::Error::Protocol("scope entry overflow".into()))?))
        })).await?)
    }

    async fn publish_scope_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        scope: Uuid,
        revision: u64,
        frozen: &ScopeInput,
    ) -> Result<()> {
        let current = self.scope_definition(tx, scope).await?.revision;
        if current != revision || !self.scope_authority_current_in(tx, id).await? {
            return Err(Error::Conflict.into());
        }
        for reference in references(scope, revision, frozen).into_iter().filter(|r| {
            r.id.starts_with("scope-definition.") || r.id.starts_with("group-definition.")
        }) {
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
            let (agent_changed,mdm_changed)=sqlx::query_as::<_,(bool,bool)>("SELECT o.id IS NULL OR n.channel_hashes->>'agent' IS DISTINCT FROM o.channel_hashes->>'agent',o.id IS NULL OR n.channel_hashes->>'mdm' IS DISTINCT FROM o.channel_hashes->>'mdm' FROM mdm_planning.scope_runs n LEFT JOIN mdm_planning.scope_runs o ON(o.tenant_id,o.id)=(n.tenant_id,$2) WHERE n.tenant_id=$1::uuid AND n.id=$3").bind(&tenant).bind(previous).bind(id).fetch_one(&mut *c).await?;
            let changed = changed || agent_changed || mdm_changed;
            let version=old_version.checked_add(i64::from(changed)).ok_or_else(||sqlx::Error::Protocol("scope revision overflow".into()))?;
            let captured:Option<Uuid>=sqlx::query_scalar("SELECT previous_resolution FROM mdm_planning.scope_runs WHERE tenant_id=$1::uuid AND id=$2").bind(&tenant).bind(id).fetch_one(&mut *c).await?;
            if captured!=previous {return Err(sqlx::Error::Protocol("scope projection superseded".into()));}
            sqlx::query("UPDATE mdm_planning.scope_runs SET previous_resolution=$3,semantic_changed=$4 WHERE tenant_id=$1::uuid AND id=$2").bind(&tenant).bind(id).bind(previous).bind(changed).execute(&mut *c).await?;
            sqlx::query("UPDATE mdm_planning.scopes SET resolution=$3,resolution_revision=$4,calculation_revision=calculation_revision+1,agent_resolution_revision=agent_resolution_revision+$5,mdm_resolution_revision=mdm_resolution_revision+$6 WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(scope).bind(id).bind(version).bind(i64::from(agent_changed)).bind(i64::from(mdm_changed)).execute(c).await?;
            Ok(version)
        })).await?;
        checked(
            self.sources
                .advance_reference_in(tx, &format!("scope-resolution.{scope}"), version as u64)
                .await?,
        )?;
        self.scope_phase(tx, id, "published").await?;
        let mut successor = false;
        for reference in references(scope, revision, frozen) {
            successor |= checked(self.sources.reference_in(tx, &reference.id).await?)?
                != Some(reference.revision);
        }
        if successor {
            crate::automation::jobs::enqueue_job_in(tx, Uuid::new_v4(), &JobInput::Scope { scope })
                .await?;
        }
        Ok(())
    }

    async fn propagate_scope_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        scope: Uuid,
        after: Option<String>,
    ) -> Result<()> {
        let tenant = self.tenant.to_string();
        let policies: Vec<Uuid> = tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar("SELECT id FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND definition->>'scope'=$2 AND id>coalesce($3::uuid,'00000000-0000-0000-0000-000000000000'::uuid) ORDER BY id LIMIT 65").bind(tenant).bind(scope.to_string()).bind(after).fetch_all(c).await
        })).await?;
        for policy in policies.iter().take(64) {
            crate::automation::jobs::enqueue_job_in(
                tx,
                Uuid::new_v4(),
                &JobInput::PolicyReconcile { policy: *policy },
            )
            .await?;
        }
        if policies.len() <= 64 {
            return crate::automation::jobs::finish_job_in(tx, &self.audit_store, task, None).await;
        }
        let tenant = self.tenant.to_string();
        let next = policies[63];
        tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_automation.automation_jobs SET cursor=$3 WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(task).bind(next.to_string()).execute(c).await?;Ok(())})).await?;
        Ok(())
    }
}

use rss_mdm_scope::Reference;
