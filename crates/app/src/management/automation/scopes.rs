use super::*;
use rss_mdm_scope as s;
use sqlx::Row;
use std::collections::{BTreeMap, BTreeSet};
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
    Ok(sha2::Sha256::digest(input(serde_json::to_vec(&(
        revision,
        &frozen.definition,
        sources,
    )))?)
    .to_vec())
}

pub(super) fn references(
    scope: Uuid,
    revision: u64,
    input: &ScopeInput,
) -> Vec<rss_mdm_policy_postgres::AssignmentReference> {
    let mut refs = vec![rss_mdm_policy_postgres::AssignmentReference {
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
                    refs.push(rss_mdm_policy_postgres::AssignmentReference {
                        id: format!("{prefix}.{id}"),
                        revision,
                    });
                }
            }
            Reference::Device(id) => refs.push(rss_mdm_policy_postgres::AssignmentReference {
                id: device_reference(id),
                revision: source.authority_version,
            }),
        }
    }
    refs
}
impl Management {
    /// Revalidate the frozen source identities in the serializable publication/save
    /// transaction. The ingress worker may not have forwarded a committed change yet.
    pub(super) async fn scope_authority_current_in(
        &self,
        tx: &mut PgTransaction<'_>,
        run: Uuid,
    ) -> Result<bool> {
        let tenant = self.tenant.to_string();
        Ok(tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM mdm_access.asset_authority_history h WHERE h.tenant_id=r.tenant_id AND h.revision>r.asset_watermark AND EXISTS(SELECT 1 FROM mdm_management.scope_source_members m WHERE m.tenant_id=r.tenant_id AND m.run=r.id AND m.device=h.device)) FROM mdm_management.scope_runs r WHERE r.tenant_id=$1::uuid AND r.id=$2::uuid")
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
                    let gid = input(rss_mdm_group_postgres::GroupId::parse(&id.to_string()))?;
                    let group =
                        group_checked(self.groups.lock_reference_target_in(tx, gid).await?)?;
                    source.member_set = checked(self.groups.current_member_set_in(tx, gid).await?)?
                        .map(|id| stored(Uuid::parse_str(&id.to_string())))
                        .transpose()?;
                    if group.kind == rss_mdm_group_postgres::GroupKind::Dynamic {
                        let run = source
                            .member_set
                            .ok_or(Error::Unavailable(Failure::ManagementStorage))?;
                        let build = checked(
                            self.groups
                                .build_in(
                                    tx,
                                    input(rss_mdm_group_postgres::OperationId::parse(
                                        &run.to_string(),
                                    ))?,
                                )
                                .await?,
                        )?;
                        if build.request.rule_version != group.rule_version {
                            return Err(Error::Unavailable(Failure::ManagementStorage).into());
                        }
                    }
                    source.member_version = group.member_version as u64;
                    source.definition_version = checked(
                        self.policies
                            .reference_in(tx, &format!("group-definition.{id}"))
                            .await?,
                    )?
                    .ok_or(Error::Conflict)?;
                    source.authority_version = checked(
                        self.policies
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
                        self.policies
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
        let document = input(serde_json::to_string(&frozen))?;
        let fingerprint = fingerprint(revision, &frozen)?;
        let tenant = self.tenant.to_string();
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("INSERT INTO mdm_management.scope_runs(tenant_id,id,scope,definition_revision,asset_watermark,input,fingerprint,phase) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5,$6::jsonb,$7,'sources')")
                .bind(tenant).bind(id.to_string()).bind(scope.to_string()).bind(revision as i64).bind(watermark).bind(document).bind(fingerprint).execute(c).await?;Ok(())
        })).await?;
        Ok(())
    }

    pub(super) async fn advance_scope_job_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        scope: Uuid,
        cursor: Option<String>,
    ) -> Result<()> {
        let tenant = self.tenant.to_string();
        let row=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT phase,input::text,fingerprint,definition_revision,asset_watermark,source_index,source_cursor,evaluation_cursor,object_count,member_count FROM mdm_management.scope_runs WHERE tenant_id=$1::uuid AND id=$2::uuid FOR UPDATE")
                .bind(tenant).bind(id.to_string()).fetch_optional(c).await
        })).await?;
        let Some(row) = row else {
            return self.capture_scope_in(tx, id, scope).await;
        };
        let frozen: ScopeInput = stored(serde_json::from_str(row.try_get("input")?))?;
        let revision = row.try_get::<i64, _>("definition_revision")? as u64;
        if fingerprint(revision, &frozen)? != row.try_get::<Vec<u8>, _>("fingerprint")? {
            return Err(Error::Unavailable(Failure::ManagementStorage).into());
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
                    .ok_or(Error::Unavailable(Failure::ManagementStorage))?;
                let devices = match &source.reference {
                    Reference::Device(device) => {
                        if after.is_none() {
                            vec![device.clone()]
                        } else {
                            vec![]
                        }
                    }
                    Reference::Group(_) => match source.member_set {
                        None => vec![],
                        Some(run) => {
                            let operation = input(rss_mdm_group_postgres::OperationId::parse(
                                &run.to_string(),
                            ))?;
                            let build = checked(self.groups.build_in(tx, operation).await?)?;
                            let receipt = build
                                .receipt
                                .ok_or(Error::Unavailable(Failure::ManagementStorage))?;
                            if source.reference
                                != Reference::Group(stored(Uuid::parse_str(
                                    &receipt.group.id.to_string(),
                                ))?)
                                || receipt.group.member_version as u64 != source.member_version
                            {
                                return Err(Error::Unavailable(Failure::ManagementStorage).into());
                            }
                            checked(
                                self.groups
                                    .build_members_in(tx, operation, after, 1000)
                                    .await?,
                            )?
                        }
                    },
                };
                let more = devices.len() == 1000;
                let last = devices.last().cloned();
                let tenant = self.tenant.to_string();
                tx.with_connection(move |c|Box::pin(async move {
                    sqlx::query("INSERT INTO mdm_management.scope_source_members SELECT $1::uuid,$2::uuid,$3,d FROM unnest($4::text[]) d")
                        .bind(&tenant).bind(id.to_string()).bind(index as i32).bind(devices).execute(&mut *c).await?;
                    sqlx::query("UPDATE mdm_management.scope_runs SET source_index=$3,source_cursor=$4 WHERE tenant_id=$1::uuid AND id=$2::uuid")
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
            "superseded" => self.finish_job_in(tx, id, Some("superseded")).await,
            _ => Err(Error::Unavailable(Failure::ManagementStorage).into()),
        }
    }

    async fn scope_phase(&self, tx: &mut PgTransaction<'_>, id: Uuid, phase: &str) -> Result<()> {
        let tenant = self.tenant.to_string();
        let phase = phase.to_owned();
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("UPDATE mdm_management.scope_runs SET phase=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id.to_string()).bind(phase).execute(c).await?;Ok(())
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
            sqlx::query_scalar("SELECT DISTINCT device FROM mdm_management.scope_source_members WHERE tenant_id=$1::uuid AND run=$2::uuid AND source=ANY($3) AND device>coalesce($4::text,'') COLLATE \"C\" ORDER BY device LIMIT $5")
                .bind(tenant).bind(id.to_string()).bind(targets).bind(after).bind((limit+1) as i64).fetch_all(c).await
        })).await?;
        let more = devices.len() > limit;
        devices.truncate(limit);
        if processed + devices.len() > 1_000_000 {
            return Err(Error::Unavailable(Failure::AssetObjectLimit).into());
        }
        let tenant = self.tenant.to_string();
        let selected = devices.clone();
        let rows=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT device,source FROM mdm_management.scope_source_members WHERE tenant_id=$1::uuid AND run=$2::uuid AND device=ANY($3) ORDER BY device,source")
                .bind(tenant).bind(id.to_string()).bind(selected).fetch_all(c).await
        })).await?;
        let mut hits: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();
        for row in rows {
            hits.entry(row.try_get("device")?)
                .or_default()
                .insert(row.try_get::<i32, _>("source")? as usize);
        }
        let at = input(Timepoint::try_from(frozen.as_of))?;
        let live = self.live_devices_at_in(tx, watermark, &devices).await?;
        let tenant = self.tenant.to_string();
        let selected = devices.clone();
        let identity:i64=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar("SELECT coalesce(max((SELECT revision FROM mdm_access.asset_authority_history h WHERE h.tenant_id=$1::uuid AND h.device=d AND h.revision<=$3 ORDER BY revision DESC LIMIT 1)),0) FROM unnest($2::text[]) d")
                .bind(tenant).bind(selected).bind(watermark).fetch_one(c).await
        })).await?;
        let mut matched = Vec::new();
        let mut explanations = Vec::new();
        for device in &devices {
            let key = input(s::DeviceId::new(self.tenant, device))?;
            let source_hits = hits
                .get(device)
                .ok_or(Error::Unavailable(Failure::ManagementStorage))?;
            let resolve = |refs: &BTreeSet<Reference>| -> Result<Vec<s::SourceMembership>> {
                frozen
                    .sources
                    .iter()
                    .enumerate()
                    .filter(|(_, source)| refs.contains(&source.reference))
                    .map(|(index, source)| {
                        let (identity, version) = match &source.reference {
                            Reference::Device(d) => (
                                s::SourceId::Direct(input(s::DeviceId::new(self.tenant, d))?),
                                source.authority_version.max(1),
                            ),
                            Reference::Group(g) => (
                                s::SourceId::Group(input(s::GroupId::new(
                                    self.tenant,
                                    g.to_string(),
                                ))?),
                                source.member_version + 1,
                            ),
                        };
                        Ok(s::SourceMembership {
                            source: input(s::SourceRef::new(identity, version, at))?,
                            contains: s::Membership::Known(source_hits.contains(&index)),
                        })
                    })
                    .collect()
            };
            let result = input(s::resolve_device(&s::DeviceInput {
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
            .ok_or(Error::Unavailable(Failure::ManagementStorage))?;
            matched.push(result.reasons.is_empty() && live.contains(device));
            explanations.push(input(serde_json::to_string(&serde_json::json!({"device":device,"identity":if live.contains(device){"active"}else{"inactive"},"reasons":result.reasons.iter().map(|r|match r {s::ExclusionReason::MissingLimitationMatch=>"missing_limitation_match",s::ExclusionReason::ExplicitExclusion=>"explicit_exclusion"}).collect::<Vec<_>>(),"sources":source_hits})))?);
        }
        let tenant = self.tenant.to_string();
        let count = devices.len() as i64;
        let members = matched.iter().filter(|v| **v).count() as i64;
        let last = devices.last().cloned();
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("INSERT INTO mdm_management.scope_results SELECT $1::uuid,$2::uuid,d,m,e::jsonb FROM unnest($3::text[],$4::boolean[],$5::text[]) AS p(d,m,e)")
                .bind(&tenant).bind(id.to_string()).bind(devices).bind(matched).bind(explanations).execute(&mut *c).await?;
            sqlx::query("UPDATE mdm_management.scope_runs SET object_count=object_count+$3,member_count=member_count+$4,evaluation_cursor=$5,phase=$6,identity_revision=greatest(identity_revision,$7),result_fingerprint=CASE WHEN $6='ready' THEN sha256(fingerprint||int8send(greatest(identity_revision,$7))) ELSE NULL END WHERE tenant_id=$1::uuid AND id=$2::uuid")
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
            if checked(self.policies.reference_in(tx, &reference.id).await?)?
                != Some(reference.revision)
            {
                return Err(Error::Conflict.into());
            }
        }
        let tenant = self.tenant.to_string();
        let expected:Vec<u8>=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar("SELECT result_fingerprint FROM mdm_management.scope_runs WHERE tenant_id=$1::uuid AND id=$2::uuid")
                .bind(tenant).bind(id.to_string()).fetch_one(c).await
        })).await?;
        let tenant = self.tenant.to_string();
        let same:bool=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_management.scopes s JOIN mdm_management.scope_runs r ON (r.tenant_id,r.id)=(s.tenant_id,s.resolution) WHERE s.tenant_id=$1::uuid AND s.id=$2::uuid AND r.result_fingerprint=$3)")
                .bind(tenant).bind(scope.to_string()).bind(expected).fetch_one(c).await
        })).await?;
        if same {
            return self.scope_phase(tx, id, "published").await;
        }
        let tenant = self.tenant.to_string();
        let version:i64=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar("UPDATE mdm_management.scopes SET resolution=$3::uuid,resolution_revision=resolution_revision+1 WHERE tenant_id=$1::uuid AND id=$2::uuid RETURNING resolution_revision")
                .bind(tenant).bind(scope.to_string()).bind(id.to_string()).fetch_one(c).await
        })).await?;
        checked(
            self.policies
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
        let active:bool=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_management.scopes WHERE tenant_id=$1::uuid AND id=$2::uuid AND resolution=$3::uuid)")
                .bind(tenant).bind(scope.to_string()).bind(task.to_string()).fetch_one(c).await
        })).await?;
        if !active {
            return self.finish_job_in(tx, task, None).await;
        }
        let tenant = self.tenant.to_string();
        let rows=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT policy,revision FROM mdm_management.policy_assignments WHERE tenant_id=$1::uuid AND scope=$2::uuid AND ($3::text IS NULL OR policy COLLATE \"C\">$3 COLLATE \"C\") ORDER BY policy COLLATE \"C\" LIMIT 65")
                .bind(tenant).bind(scope.to_string()).bind(after).fetch_all(c).await
        })).await?;
        for row in rows.iter().take(64) {
            let policy: String = row.try_get("policy")?;
            let state = checked(
                self.policies
                    .get_in(
                        tx,
                        &input(rss_mdm_policy::PolicyId::new(self.tenant, &policy))?,
                    )
                    .await?,
            )?
            .ok_or(Error::Conflict)?;
            self.enqueue_job_in(
                tx,
                Uuid::new_v4(),
                &JobInput::Policy {
                    policy,
                    scope,
                    resolution: task,
                    assignment_revision: Some(row.try_get("revision")?),
                    expected_revision: state.storage_revision(),
                    as_of: self
                        .clock
                        .unix_seconds()
                        .map_err(|_| Error::Unavailable(Failure::Clock))?,
                },
            )
            .await?;
        }
        if rows.len() <= 64 {
            return self.finish_job_in(tx, task, None).await;
        }
        let tenant = self.tenant.to_string();
        let cursor: String = rows[63].try_get("policy")?;
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("UPDATE mdm_management.automation_jobs SET cursor=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(task.to_string()).bind(cursor).execute(c).await?;Ok(())
        })).await?;
        Ok(())
    }
}
