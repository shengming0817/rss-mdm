//! Scope-only persistence. Every write borrows and validates its initiating transaction.
use crate::*;
use serde_json::Value;
use sqlx::Row;

pub struct OwnedScope {
    pub id: Uuid,
    pub retired: bool,
    pub head: Head,
}
pub struct Head {
    pub revision: u64,
    pub definition: ScopeDefinition,
    pub resolution: Option<Uuid>,
    pub resolution_revision: u64,
    pub calculation_revision: u64,
}
pub struct Run {
    pub covered_inputs: i64,
    pub id: Uuid,
    pub scope: Uuid,
    pub definition_revision: u64,
    pub asset_cut: rss_mdm_inventory::AssetCut,
    pub input: Value,
    pub fingerprint: Vec<u8>,
    pub phase: String,
    pub source_index: usize,
    pub source_cursor: Option<String>,
    pub evaluation_cursor: Option<String>,
    pub object_count: usize,
    pub member_count: u64,
}
pub struct SourceMember {
    pub object: String,
    pub unknown: bool,
    pub input: Value,
}
pub struct Task {
    pub scope: Uuid,
    pub completed: bool,
    pub forwarded: bool,
    pub failure: Option<String>,
    pub failure_detail: Option<Value>,
    pub replacement: Option<Uuid>,
}
fn invariant() -> BindingError {
    sqlx::Error::Protocol("Scope storage invariant".into()).into()
}
impl From<sqlx::Error> for BindingError {
    fn from(e: sqlx::Error) -> Self {
        Self::Storage(e.into())
    }
}
impl ScopeBinding {
    /// Lock a Scope identity before creation or mutation, including an absent head.
    pub async fn lock_scope_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
    ) -> Result<(), BindingError> {
        self.validate_in(tx)?;
        let key = format!("scope:{}:{id}", self.tenant);
        let locked = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_scalar::<_, bool>(
                        "SELECT pg_try_advisory_xact_lock(hashtextextended($1,3048))",
                    )
                    .bind(key)
                    .fetch_one(c)
                    .await
                })
            })
            .await?;
        if !locked {
            tx.with_connection(|c| Box::pin(async {
                sqlx::query("DO $$ BEGIN RAISE EXCEPTION 'scope aggregate busy' USING ERRCODE='40001'; END $$").execute(c).await?;
                Ok(())
            })).await?;
        }
        Ok(())
    }

    pub async fn admit_in(&self, tx: &mut PgTransaction<'_>) -> Result<(), BindingError> {
        let profile = self.profile();

        self.validate_in(tx)?;
        let ok = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    crate::verify_authority(profile, c).await?;
                    let definitions: bool =
                        sqlx::query_scalar(crate::storage_profile::sql(profile).admission)
                            .fetch_one(&mut *c)
                            .await?;
                    let projections: bool =
                        sqlx::query_scalar(crate::projection_admission_sql(profile))
                            .bind(true)
                            .fetch_one(c)
                            .await?;
                    Ok::<_, sqlx::Error>(definitions && projections)
                })
            })
            .await?;
        if !ok {
            return Err(invariant());
        }
        Ok(())
    }
    /// Exact privileges for the Policy's configuration participant, without calculation writes.
    pub async fn admit_configuration_in(
        &self,
        tx: &mut PgTransaction<'_>,
    ) -> Result<(), BindingError> {
        self.validate_in(tx)?;
        let profile = self.profile();
        let ok = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    crate::verify_authority(profile, c).await?;
                    sqlx::query_scalar::<_, bool>(
                        crate::storage_profile::sql(profile).configuration_admission,
                    )
                    .fetch_one(c)
                    .await
                })
            })
            .await?;
        if ok { Ok(()) } else { Err(invariant()) }
    }
    pub async fn head_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        write: bool,
    ) -> Result<Head, BindingError> {
        let profile = self.profile();

        if write {
            self.lock_scope_in(tx, id).await?;
        }
        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        let row = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    let sql = if write {
                        crate::storage_profile::sql(profile).store_head_in_1
                    } else {
                        crate::storage_profile::sql(profile).store_head_in_2
                    };
                    sqlx::query(sql)
                        .bind(tenant)
                        .bind(id)
                        .fetch_optional(c)
                        .await
                })
            })
            .await?
            .ok_or(BindingError::Missing)?;
        Ok(Head {
            revision: row.try_get::<i64, _>("revision")? as u64,
            definition: serde_json::from_value(row.try_get("definition")?)
                .map_err(|_| invariant())?,
            resolution: row.try_get("resolution")?,
            resolution_revision: row.try_get::<i64, _>("resolution_revision")? as u64,
            calculation_revision: row.try_get::<i64, _>("calculation_revision")? as u64,
        })
    }
    pub async fn put_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        expected: u64,
        owner: ScopeOwner,
        definition: &ScopeDefinition,
    ) -> Result<u64, BindingError> {
        let profile = self.profile();

        self.lock_scope_in(tx, id).await?;
        self.validate_in(tx)?;
        if !owner.is_valid() {
            return Err(BindingError::Invalid);
        }
        let revision = expected
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or(BindingError::Conflict)?;
        let tenant = self.tenant.to_string();
        let document = serde_json::to_value(definition).map_err(|_| BindingError::Invalid)?;
        let changed = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    let changed = if expected == 0 {
                        sqlx::query(crate::storage_profile::sql(profile).store_put_in_1)
                            .bind(&tenant)
                            .bind(id)
                            .bind(owner.policy)
                            .bind(owner.stage)
                            .execute(&mut *c)
                            .await?
                            .rows_affected()
                    } else {
                        sqlx::query(crate::storage_profile::sql(profile).store_put_in_2)
                            .bind(&tenant)
                            .bind(id)
                            .bind(expected as i64)
                            .bind(owner.policy)
                            .bind(owner.stage)
                            .execute(&mut *c)
                            .await?
                            .rows_affected()
                    };
                    if changed == 1 {
                        sqlx::query(crate::storage_profile::sql(profile).store_put_in_3)
                            .bind(tenant)
                            .bind(id)
                            .bind(revision as i64)
                            .bind(document)
                            .execute(c)
                            .await?;
                    }
                    Ok(changed)
                })
            })
            .await?;
        if changed != 1 {
            return Err(BindingError::Conflict);
        }
        self.replace_sources_in(tx, id, definition.references())
            .await?;
        Ok(revision)
    }
    /// Close current dependencies while preserving definitions and result history.
    pub async fn retire_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        expected: u64,
        owner: ScopeOwner,
    ) -> Result<(), BindingError> {
        self.lock_scope_in(tx, id).await?;
        self.validate_in(tx)?;
        if !owner.is_valid() {
            return Err(BindingError::Invalid);
        }
        let tenant = self.tenant.to_string();
        let profile = self.profile();
        let changed = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(
                        sqlx::query(crate::storage_profile::sql(profile).store_retire_in)
                            .bind(tenant)
                            .bind(id)
                            .bind(expected as i64)
                            .bind(owner.policy)
                            .bind(owner.stage)
                            .execute(c)
                            .await?
                            .rows_affected(),
                    )
                })
            })
            .await?;
        if changed != 1 {
            return Err(BindingError::Conflict);
        }
        self.replace_sources_in(tx, id, Default::default()).await
    }
    /// Read a child's original owner, including retired children used by history.
    pub async fn owner_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
    ) -> Result<ScopeOwner, BindingError> {
        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        let profile = self.profile();
        let row = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_as::<_, (Uuid, Option<Uuid>)>(
                        crate::storage_profile::sql(profile).store_owner_in,
                    )
                    .bind(tenant)
                    .bind(id)
                    .fetch_optional(c)
                    .await
                })
            })
            .await?
            .ok_or(BindingError::Missing)?;
        Ok(ScopeOwner {
            policy: row.0,
            stage: row.1,
        })
    }
    /// Resolve an owner without accepting an administrator-selected Scope UUID.
    pub async fn owned_in(
        &self,
        tx: &mut PgTransaction<'_>,
        owner: ScopeOwner,
    ) -> Result<Option<OwnedScope>, BindingError> {
        self.validate_in(tx)?;
        if !owner.is_valid() {
            return Err(BindingError::Invalid);
        }
        let tenant = self.tenant.to_string();
        let profile = self.profile();
        let row = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query(crate::storage_profile::sql(profile).store_owned_in)
                        .bind(tenant)
                        .bind(owner.policy)
                        .bind(owner.stage)
                        .fetch_optional(c)
                        .await
                })
            })
            .await?;
        row.map(|r| {
            Ok(OwnedScope {
                id: r.try_get("id")?,
                retired: r.try_get("deleted")?,
                head: Head {
                    revision: r.try_get::<i64, _>("revision")? as u64,
                    definition: serde_json::from_value(r.try_get("definition")?)
                        .map_err(|_| invariant())?,
                    resolution: r.try_get("resolution")?,
                    resolution_revision: r.try_get::<i64, _>("resolution_revision")? as u64,
                    calculation_revision: r.try_get::<i64, _>("calculation_revision")? as u64,
                },
            })
        })
        .transpose()
    }
    async fn replace_sources_in(
        &self,
        tx: &mut PgTransaction<'_>,
        scope: Uuid,
        refs: std::collections::BTreeSet<rss_mdm_scope::Reference>,
    ) -> Result<(), BindingError> {
        let profile = self.profile();

        let (kinds, targets): (Vec<String>, Vec<String>) = refs
            .into_iter()
            .map(|r| match r {
                rss_mdm_scope::Reference::Device(id) => ("device".into(), id),
                rss_mdm_scope::Reference::Group(id) => ("group".into(), id.to_string()),
            })
            .unzip();
        let tenant = self.tenant.to_string();
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(crate::storage_profile::sql(profile).store_replace_sources_in_1)
                    .bind(&tenant)
                    .bind(scope)
                    .execute(&mut *c)
                    .await?;
                sqlx::query(crate::storage_profile::sql(profile).store_replace_sources_in_2)
                    .bind(tenant)
                    .bind(scope)
                    .bind(kinds)
                    .bind(targets)
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await?;
        Ok(())
    }
    pub async fn create_run_in(
        &self,
        tx: &mut PgTransaction<'_>,
        run: &Run,
    ) -> Result<(), BindingError> {
        let profile = self.profile();

        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        let id = run.id;
        let scope = run.scope;
        let revision = run.definition_revision as i64;
        let asset_cut = run.asset_cut.to_json();
        let input = run.input.clone();
        let fingerprint = run.fingerprint.clone();
        let covered_inputs = run.covered_inputs;
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(crate::storage_profile::sql(profile).store_create_run_in_1)
                    .bind(tenant)
                    .bind(id)
                    .bind(scope)
                    .bind(revision)
                    .bind(asset_cut)
                    .bind(input)
                    .bind(fingerprint)
                    .bind(covered_inputs)
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await?;
        Ok(())
    }
    pub async fn run_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
    ) -> Result<Option<Run>, BindingError> {
        let profile = self.profile();

        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        let row = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query(crate::storage_profile::sql(profile).store_run_in_1)
                        .bind(tenant)
                        .bind(id)
                        .fetch_optional(c)
                        .await
                })
            })
            .await?;
        row.map(|r| {
            Ok(Run {
                covered_inputs: r.try_get("covered_inputs")?,
                id,
                scope: r.try_get("scope")?,
                definition_revision: r.try_get::<i64, _>("definition_revision")? as u64,
                asset_cut: rss_mdm_inventory::AssetCut::from_json(r.try_get("asset_cut")?)
                    .map_err(|_| invariant())?,
                input: r.try_get("input")?,
                fingerprint: r.try_get("fingerprint")?,
                phase: r.try_get("phase")?,
                source_index: r.try_get::<i32, _>("source_index")? as usize,
                source_cursor: r.try_get("source_cursor")?,
                evaluation_cursor: r.try_get("evaluation_cursor")?,
                object_count: r.try_get::<i64, _>("object_count")? as usize,
                member_count: r.try_get::<i64, _>("member_count")? as u64,
            })
        })
        .transpose()
    }
    pub async fn stage_sources_in(
        &self,
        tx: &mut PgTransaction<'_>,
        run: Uuid,
        index: usize,
        members: Vec<SourceMember>,
        cursor: Option<String>,
        more: bool,
    ) -> Result<(), BindingError> {
        let profile = self.profile();

        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        let mut objects = Vec::new();
        let mut unknown = Vec::new();
        let mut inputs = Vec::new();
        for m in members {
            objects.push(m.object);
            unknown.push(m.unknown);
            inputs.push(m.input);
        }
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(crate::storage_profile::sql(profile).store_stage_sources_in_1)
                    .bind(&tenant)
                    .bind(run)
                    .bind(index as i32)
                    .bind(objects)
                    .bind(unknown)
                    .bind(inputs)
                    .execute(&mut *c)
                    .await?;
                sqlx::query(crate::storage_profile::sql(profile).store_stage_sources_in_2)
                    .bind(tenant)
                    .bind(run)
                    .bind((index + usize::from(!more)) as i32)
                    .bind(if more { cursor } else { None })
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await?;
        Ok(())
    }
    pub async fn phase_in(
        &self,
        tx: &mut PgTransaction<'_>,
        run: Uuid,
        phase: &str,
    ) -> Result<(), BindingError> {
        let profile = self.profile();

        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        let phase = phase.to_owned();
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(crate::storage_profile::sql(profile).store_phase_in_1)
                    .bind(tenant)
                    .bind(run)
                    .bind(phase)
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await?;
        Ok(())
    }
    pub async fn publish_in(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &Publication,
        channel_changed: bool,
    ) -> Result<(), BindingError> {
        let profile = self.profile();

        self.validate_in(tx)?;
        let head = self.head_in(tx, p.scope, true).await?;
        let run = self.run_in(tx, p.run).await?.ok_or(BindingError::Missing)?;
        if run.scope != p.scope
            || run.definition_revision != p.definition_revision
            || run.phase != "ready"
        {
            return Err(BindingError::Conflict);
        }
        if head.revision != p.definition_revision || head.resolution != p.previous_resolution {
            return Err(BindingError::Conflict);
        }
        let tenant = self.tenant.to_string();
        let scope = p.scope;
        let id = p.run;
        let previous = head.resolution;
        let old_version = head.resolution_revision;
        tx.with_connection(move |c| {
            Box::pin(async move {
                let changed = sqlx::query_scalar::<_, bool>(
                    crate::storage_profile::sql(profile).store_publish_in_1,
                )
                .bind(&tenant)
                .bind(previous)
                .bind(id)
                .fetch_one(&mut *c)
                .await?
                    || previous.is_none()
                    || channel_changed;
                let version = i64::try_from(old_version)
                    .ok()
                    .and_then(|v| v.checked_add(i64::from(changed)))
                    .ok_or_else(|| sqlx::Error::Protocol("scope revision overflow".into()))?;
                sqlx::query(crate::storage_profile::sql(profile).store_publish_in_2)
                    .bind(&tenant)
                    .bind(id)
                    .execute(&mut *c)
                    .await?;
                sqlx::query(crate::storage_profile::sql(profile).store_publish_in_3)
                    .bind(tenant)
                    .bind(scope)
                    .bind(id)
                    .bind(version)
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await?;
        Ok(())
    }
    pub async fn definition_at_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        revision: u64,
    ) -> Result<ScopeDefinition, BindingError> {
        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        let sql = crate::storage_profile::sql(self.profile()).store_definition_at_1;
        let revision = i64::try_from(revision).map_err(|_| BindingError::Invalid)?;
        let value: Value = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_scalar(sql)
                        .bind(tenant)
                        .bind(id)
                        .bind(revision)
                        .fetch_optional(c)
                        .await
                })
            })
            .await?
            .ok_or(BindingError::Missing)?;
        serde_json::from_value(value).map_err(|_| invariant())
    }
    /// The caller keeps the Scope aggregate lock while replacing the returned task.
    pub async fn pending_task_in(
        &self,
        tx: &mut PgTransaction<'_>,
        scope: Uuid,
    ) -> Result<Option<Uuid>, BindingError> {
        self.head_in(tx, scope, true).await?;
        let tenant = self.tenant.to_string();
        let sql = crate::storage_profile::sql(self.profile()).store_enqueue_in_1;
        Ok(tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_scalar(sql)
                        .bind(tenant)
                        .bind(scope)
                        .fetch_optional(c)
                        .await
                })
            })
            .await?)
    }
    pub async fn enqueue_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        scope: Uuid,
    ) -> Result<Uuid, BindingError> {
        let profile = self.profile();

        self.head_in(tx, scope, true).await?;
        let tenant = self.tenant.to_string();
        Ok(tx
            .with_connection(move |c| {
                Box::pin(async move {
                    let old = sqlx::query_scalar::<_, Uuid>(
                        crate::storage_profile::sql(profile).store_enqueue_in_1,
                    )
                    .bind(&tenant)
                    .bind(scope)
                    .fetch_optional(&mut *c)
                    .await?;
                    if let Some(old) = old {
                        sqlx::query(crate::storage_profile::sql(profile).store_request_inputs)
                            .bind(&tenant)
                            .bind(scope)
                            .execute(&mut *c)
                            .await?;
                        return Ok(old);
                    }
                    sqlx::query(crate::storage_profile::sql(profile).store_enqueue_in_2)
                        .bind(tenant)
                        .bind(id)
                        .bind(scope)
                        .execute(c)
                        .await?;
                    Ok(id)
                })
            })
            .await?)
    }
    pub async fn task_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
    ) -> Result<Task, BindingError> {
        let profile = self.profile();

        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        let r = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query(crate::storage_profile::sql(profile).store_task_in_1)
                        .bind(tenant)
                        .bind(id)
                        .fetch_optional(c)
                        .await
                })
            })
            .await?
            .ok_or(BindingError::Missing)?;
        Ok(Task {
            scope: r.try_get("scope")?,
            completed: r.try_get("completed")?,
            forwarded: r.try_get("forwarded")?,
            failure: r.try_get("failure")?,
            failure_detail: r.try_get("failure_detail")?,
            replacement: r.try_get("replacement_task")?,
        })
    }
    pub async fn finish_task_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        failure: Option<&str>,
    ) -> Result<bool, BindingError> {
        let profile = self.profile();

        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        let failure = failure.map(str::to_owned);
        Ok(tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query(crate::storage_profile::sql(profile).store_finish_task_in_1)
                        .bind(tenant)
                        .bind(id)
                        .bind(failure)
                        .execute(c)
                        .await
                        .map(|r| r.rows_affected() == 1)
                })
            })
            .await?)
    }
    pub async fn replace_task_in(
        &self,
        tx: &mut PgTransaction<'_>,
        old: Uuid,
        new: Uuid,
    ) -> Result<(), BindingError> {
        let profile = self.profile();

        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(crate::storage_profile::sql(profile).store_replace_task_in_1)
                    .bind(tenant)
                    .bind(old)
                    .bind(new)
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await?;
        Ok(())
    }
}
impl ScopeBinding {
    pub async fn evaluate_page_in(
        &self,
        tx: &mut PgTransaction<'_>,
        run: &Run,
        targets: Vec<i32>,
        source_count: usize,
    ) -> Result<(), BindingError> {
        let profile = self.profile();

        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        let id = run.id;
        let after = run.evaluation_cursor.clone();
        let limit = 1000usize.min(16000 / source_count.max(1));
        let mut devices = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_scalar::<_, String>(
                        crate::storage_profile::sql(profile).store_evaluate_page_in_1,
                    )
                    .bind(tenant)
                    .bind(id)
                    .bind(targets)
                    .bind(after)
                    .bind((limit + 1) as i64)
                    .fetch_all(c)
                    .await
                })
            })
            .await?;
        let more = devices.len() > limit;
        devices.truncate(limit);
        check_page_count(run.object_count, devices.len())?;
        let matched = vec![true; devices.len()];
        let explanations: Vec<Value> = devices
            .iter()
            .map(|key| serde_json::json!({"objectKey":key,"reasons":[],"identityRevision":0}))
            .collect();
        let count = devices.len() as i64;
        let last = devices.last().cloned();
        let tenant = self.tenant.to_string();
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(crate::storage_profile::sql(profile).store_evaluate_page_in_2)
                    .bind(&tenant)
                    .bind(id)
                    .bind(devices)
                    .bind(matched)
                    .bind(explanations)
                    .execute(&mut *c)
                    .await?;
                sqlx::query(crate::storage_profile::sql(profile).store_evaluate_page_in_3)
                    .bind(tenant)
                    .bind(id)
                    .bind(count)
                    .bind(last)
                    .bind(if more { "evaluate" } else { "project" })
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await?;
        Ok(())
    }
}
pub struct AssetPage {
    to_cut: rss_mdm_inventory::AssetCut,
    event_after: i64,
    through: i64,
    pub scopes: Vec<Uuid>,
    pub more: bool,
}
impl ScopeBinding {
    pub async fn asset_page_in(
        &self,
        tx: &mut PgTransaction<'_>,
        candidate: &rss_mdm_inventory::AssetCut,
    ) -> Result<Option<AssetPage>, BindingError> {
        let profile = self.profile();

        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        let row = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query(crate::storage_profile::sql(profile).store_asset_page_in_1)
                        .bind(&tenant)
                        .execute(&mut *c)
                        .await?;
                    sqlx::query(crate::storage_profile::sql(profile).store_asset_page_in_2)
                        .bind(tenant)
                        .fetch_one(c)
                        .await
                })
            })
            .await?;
        let from: Option<Value> = row.try_get("from_cut")?;
        let to: Value = row
            .try_get::<Option<Value>, _>("to_cut")?
            .unwrap_or_else(|| candidate.to_json());
        let to_cut = rss_mdm_inventory::AssetCut::from_json(to.clone()).map_err(|_| invariant())?;
        let event_after: i64 = row.try_get("event_after")?;
        let cursor: Option<Uuid> = row.try_get("cursor")?;
        let through: Option<i64> = match row.try_get::<Option<i64>, _>("page_through")? {
            Some(value) => Some(value),
            None => {
                let tenant = self.tenant.to_string();
                let f = from.clone();
                let t = to.clone();
                tx.with_connection(move|c|Box::pin(async move {
                    sqlx::query_scalar("WITH asset_cut_2 AS MATERIALIZED (SELECT * FROM mdm.asset_cut_context($2)),asset_cut_3 AS MATERIALIZED (SELECT * FROM mdm.asset_cut_context($3)) SELECT max(revision) FROM (SELECT revision FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND NOT coalesce((SELECT CASE WHEN source_epoch=epoch THEN pg_visible_in_snapshot(writer_xid,visibility) ELSE source_epoch=ANY(ancestors) END FROM asset_cut_2),false) AND coalesce((SELECT CASE WHEN source_epoch=epoch THEN pg_visible_in_snapshot(writer_xid,visibility) ELSE source_epoch=ANY(ancestors) END FROM asset_cut_3),false) AND revision>$4 ORDER BY revision LIMIT 1000) page")
                        .bind(tenant).bind(f).bind(t).bind(event_after).fetch_one(c).await
                })).await?
            }
        };
        let Some(through) = through else {
            let tenant = self.tenant.to_string();
            tx.with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query(crate::storage_profile::sql(profile).store_asset_page_in_3)
                        .bind(tenant)
                        .bind(to)
                        .execute(c)
                        .await?;
                    Ok(())
                })
            })
            .await?;
            return Ok(None);
        };
        let tenant = self.tenant.to_string();
        let frozen = to.clone();
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(crate::storage_profile::sql(profile).store_asset_page_in_4)
                    .bind(tenant)
                    .bind(frozen)
                    .bind(through)
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await?;
        let tenant = self.tenant.to_string();
        let mut scopes = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_scalar::<_, Uuid>(
                        crate::storage_profile::sql(profile).store_asset_page_in_5,
                    )
                    .bind(tenant)
                    .bind(from)
                    .bind(to)
                    .bind(event_after)
                    .bind(through)
                    .bind(cursor)
                    .fetch_all(c)
                    .await
                })
            })
            .await?;
        let more = scopes.len() > 32;
        scopes.truncate(32);
        Ok(Some(AssetPage {
            to_cut,
            event_after,
            through,
            scopes,
            more,
        }))
    }
    pub async fn complete_asset_page_in(
        &self,
        tx: &mut PgTransaction<'_>,
        page: &AssetPage,
    ) -> Result<(), BindingError> {
        let profile = self.profile();

        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        let frozen = page.to_cut.to_json();
        let after = if page.more {
            page.event_after
        } else {
            page.through
        };
        let through = page.more.then_some(page.through);
        let cursor = if page.more {
            page.scopes.last().copied()
        } else {
            None
        };
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(crate::storage_profile::sql(profile).store_complete_asset_page_in_1)
                    .bind(tenant)
                    .bind(after)
                    .bind(through)
                    .bind(cursor)
                    .bind(frozen)
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await?;
        Ok(())
    }
}

fn check_page_count(processed: usize, added: usize) -> Result<(), BindingError> {
    processed
        .checked_add(added)
        .and_then(|v| i64::try_from(v).ok())
        .map(|_| ())
        .ok_or(BindingError::Invalid)
}
impl ScopeBinding {
    pub async fn queue_counts_in(
        &self,
        tx: &mut PgTransaction<'_>,
    ) -> Result<[u64; 5], BindingError> {
        let profile = self.profile();
        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        let row = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_as::<_, (i64, i64, i64, i64, i64)>(
                        crate::storage_profile::sql(profile).queue_counts,
                    )
                    .bind(tenant)
                    .fetch_one(c)
                    .await
                })
            })
            .await?;
        Ok([
            row.0 as u64,
            row.1 as u64,
            row.2 as u64,
            row.3 as u64,
            row.4 as u64,
        ])
    }
}

impl ScopeBinding {
    /// Each input stream has its own completion coordinate; notices are only hints.
    pub async fn inputs_pending_in(
        &self,
        tx: &mut PgTransaction<'_>,
        relation: i64,
    ) -> Result<bool, BindingError> {
        let profile = self.profile();

        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        Ok(tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_scalar(
                        crate::storage_profile::sql(profile).store_inputs_pending_in_1,
                    )
                    .bind(tenant)
                    .bind(relation)
                    .fetch_one(c)
                    .await
                })
            })
            .await?)
    }
    /// Freeze a Device-owned change window; the scope cursor only pages matching references.
    pub async fn relation_window_in(
        &self,
        tx: &mut PgTransaction<'_>,
        revision: i64,
    ) -> Result<Option<RelationWindow>, BindingError> {
        let profile = self.profile();

        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        let (consumed, mut watermark, mut position, mut cursor): (i64, i64, i64, Option<Uuid>) = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query(crate::storage_profile::sql(profile).store_relation_window_in_1)
                        .bind(&tenant)
                        .execute(&mut *c)
                        .await?;
                    sqlx::query_as(crate::storage_profile::sql(profile).store_relation_window_in_2)
                        .bind(tenant)
                        .fetch_one(c)
                        .await
                })
            })
            .await?;
        if consumed == watermark {
            watermark = revision;
            position = consumed;
            cursor = None;
        }
        if watermark < consumed {
            return Err(BindingError::Invalid);
        }
        Ok((watermark != consumed).then_some(RelationWindow {
            consumed,
            watermark,
            position,
            cursor,
        }))
    }
    pub async fn relation_targets_in(
        &self,
        tx: &mut PgTransaction<'_>,
        window: &RelationWindow,
        devices: Vec<String>,
    ) -> Result<Vec<Uuid>, BindingError> {
        let profile = self.profile();

        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        let cursor = window.cursor;
        Ok(tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_scalar(
                        crate::storage_profile::sql(profile).store_relation_targets_in_1,
                    )
                    .bind(tenant)
                    .bind(devices)
                    .bind(cursor)
                    .fetch_all(c)
                    .await
                })
            })
            .await?)
    }
    pub async fn complete_relation_page_in(
        &self,
        tx: &mut PgTransaction<'_>,
        window: &RelationWindow,
        through: i64,
        more_changes: bool,
        scopes: &[Uuid],
    ) -> Result<(), BindingError> {
        let profile = self.profile();

        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        let more_scopes = scopes.len() > 32;
        let cursor = more_scopes.then(|| scopes[31]);
        let consumed = if more_scopes || more_changes {
            window.consumed
        } else {
            window.watermark
        };
        let position = if more_scopes {
            window.position
        } else if more_changes {
            through
        } else {
            // Sealing an object cut advances publication order without an object
            // change. An exhausted window must close that sparse tail as well.
            window.watermark
        };
        let watermark = window.watermark;
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(crate::storage_profile::sql(profile).store_complete_relation_page_in_1)
                    .bind(tenant)
                    .bind(consumed)
                    .bind(watermark)
                    .bind(position)
                    .bind(cursor)
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await?;
        Ok(())
    }
}
pub struct RelationWindow {
    pub consumed: i64,
    pub watermark: i64,
    pub position: i64,
    pub cursor: Option<Uuid>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scope_page_budget_is_inclusive_and_rejects_overflow() {
        assert!(check_page_count(1_000_000, 1).is_ok());
        for (processed, added) in [(i64::MAX as usize, 1), (usize::MAX, 1)] {
            assert!(matches!(
                check_page_count(processed, added),
                Err(BindingError::Invalid)
            ));
        }
    }
}

impl ScopeBinding {
    /// Freeze the demand coordinate in the same snapshot as the original AssetCut.
    pub async fn covered_inputs_in(
        &self,
        tx: &mut PgTransaction<'_>,
        scope: Uuid,
        cut: &rss_mdm_inventory::AssetCut,
    ) -> Result<i64, BindingError> {
        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        let profile = self.profile();
        let cut = cut.to_json();
        Ok(tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_scalar(crate::storage_profile::sql(profile).store_covered_inputs)
                        .bind(tenant)
                        .bind(scope)
                        .bind(cut)
                        .fetch_one(c)
                        .await
                })
            })
            .await?)
    }
    /// A coalesced request is not covered merely because an older task existed.
    pub async fn inputs_uncovered_in(
        &self,
        tx: &mut PgTransaction<'_>,
        scope: Uuid,
        covered: i64,
    ) -> Result<bool, BindingError> {
        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        let profile = self.profile();
        Ok(tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_scalar(crate::storage_profile::sql(profile).store_uncovered_inputs)
                        .bind(tenant)
                        .bind(scope)
                        .bind(covered)
                        .fetch_optional(c)
                        .await
                })
            })
            .await?
            .unwrap_or(false))
    }
}
