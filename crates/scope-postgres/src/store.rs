//! Scope-only persistence. Every write borrows and validates its initiating transaction.
use crate::*;
use serde_json::Value;
use sqlx::Row;

pub struct Head {
    pub revision: u64,
    pub definition: ScopeDefinition,
    pub resolution: Option<Uuid>,
    pub resolution_revision: u64,
    pub calculation_revision: u64,
}
pub struct Run {
    pub id: Uuid,
    pub scope: Uuid,
    pub definition_revision: u64,
    pub watermark: i64,
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
        self.validate_in(tx)?;
        let ok = tx
            .with_connection(|c| {
                Box::pin(async {
                    crate::verify_authority(c).await?;
                    sqlx::query_scalar::<_, bool>(include_str!("admission.sql"))
                        .fetch_one(c)
                        .await
                })
            })
            .await?;
        if !ok {
            return Err(invariant());
        }
        Ok(())
    }
    pub async fn head_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        write: bool,
    ) -> Result<Head, BindingError> {
        if write {
            self.lock_scope_in(tx, id).await?;
        }
        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        let row=tx.with_connection(move |c|Box::pin(async move {
            let sql=if write {
                "SELECT s.revision,s.resolution,s.resolution_revision,s.calculation_revision,v.definition FROM mdm_scope.scopes s JOIN mdm_scope.scope_versions v USING(tenant_id,id,revision) WHERE s.tenant_id=$1::uuid AND s.id=$2 AND NOT s.deleted FOR UPDATE OF s"
            } else {
                "SELECT s.revision,s.resolution,s.resolution_revision,s.calculation_revision,v.definition FROM mdm_scope.scopes s JOIN mdm_scope.scope_versions v USING(tenant_id,id,revision) WHERE s.tenant_id=$1::uuid AND s.id=$2 AND NOT s.deleted FOR SHARE OF s"
            };
            sqlx::query(sql).bind(tenant).bind(id).fetch_optional(c).await
        })).await?.ok_or(BindingError::Missing)?;
        Ok(Head {
            revision: row.try_get::<i64, _>("revision")? as u64,
            definition: serde_json::from_value(row.try_get("definition")?)
                .map_err(|_| invariant())?,
            resolution: row.try_get("resolution")?,
            resolution_revision: row.try_get::<i64, _>("resolution_revision")? as u64,
            calculation_revision: row.try_get::<i64, _>("calculation_revision")? as u64,
        })
    }
    pub async fn lock_references_in(
        &self,
        tx: &mut PgTransaction<'_>,
        scopes: &[Uuid],
    ) -> Result<(), BindingError> {
        let mut scopes = scopes.to_vec();
        scopes.sort_unstable();
        scopes.dedup();
        for id in scopes {
            self.head_in(tx, id, false).await?;
        }
        Ok(())
    }
    pub async fn put_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        expected: u64,
        definition: &ScopeDefinition,
    ) -> Result<u64, BindingError> {
        self.lock_scope_in(tx, id).await?;
        self.validate_in(tx)?;
        let revision = expected
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or(BindingError::Conflict)?;
        let tenant = self.tenant.to_string();
        let document = serde_json::to_value(definition).map_err(|_| BindingError::Invalid)?;
        let changed=tx.with_connection(move |c|Box::pin(async move {
            let changed=if expected==0 {
                sqlx::query("INSERT INTO mdm_scope.scopes(tenant_id,id,revision,deleted) VALUES($1::uuid,$2,1,false) ON CONFLICT DO NOTHING").bind(&tenant).bind(id).execute(&mut *c).await?.rows_affected()
            } else {
                sqlx::query("UPDATE mdm_scope.scopes SET revision=revision+1 WHERE tenant_id=$1::uuid AND id=$2 AND revision=$3 AND NOT deleted").bind(&tenant).bind(id).bind(expected as i64).execute(&mut *c).await?.rows_affected()
            };
            if changed==1 { sqlx::query("INSERT INTO mdm_scope.scope_versions(tenant_id,id,revision,definition) VALUES($1::uuid,$2,$3,$4)").bind(tenant).bind(id).bind(revision as i64).bind(document).execute(c).await?; }
            Ok(changed)
        })).await?;
        if changed != 1 {
            return Err(BindingError::Conflict);
        }
        self.replace_sources_in(tx, id, definition.references())
            .await?;
        Ok(revision)
    }
    pub async fn delete_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        expected: u64,
    ) -> Result<u64, BindingError> {
        self.lock_scope_in(tx, id).await?;
        self.validate_in(tx)?;
        let revision = expected
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or(BindingError::Conflict)?;
        let tenant = self.tenant.to_string();
        let count=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("UPDATE mdm_scope.scopes SET deleted=true,revision=$4 WHERE tenant_id=$1::uuid AND id=$2 AND revision=$3 AND NOT deleted").bind(tenant).bind(id).bind(expected as i64).bind(revision as i64).execute(c).await.map(|r|r.rows_affected())
        })).await?;
        if count != 1 {
            return Err(BindingError::Conflict);
        }
        self.replace_sources_in(tx, id, Default::default()).await?;
        Ok(revision)
    }
    async fn replace_sources_in(
        &self,
        tx: &mut PgTransaction<'_>,
        scope: Uuid,
        refs: std::collections::BTreeSet<rss_mdm_scope::Reference>,
    ) -> Result<(), BindingError> {
        let (kinds, targets): (Vec<String>, Vec<String>) = refs
            .into_iter()
            .map(|r| match r {
                rss_mdm_scope::Reference::Device(id) => ("device".into(), id),
                rss_mdm_scope::Reference::Group(id) => ("group".into(), id.to_string()),
            })
            .unzip();
        let tenant = self.tenant.to_string();
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("DELETE FROM mdm_scope.scope_sources WHERE tenant_id=$1::uuid AND scope=$2").bind(&tenant).bind(scope).execute(&mut *c).await?;
            sqlx::query("INSERT INTO mdm_scope.scope_sources SELECT $1::uuid,$2,* FROM unnest($3::text[],$4::text[])").bind(tenant).bind(scope).bind(kinds).bind(targets).execute(c).await?;
            Ok(())
        })).await?;
        Ok(())
    }
    pub async fn create_run_in(
        &self,
        tx: &mut PgTransaction<'_>,
        run: &Run,
    ) -> Result<(), BindingError> {
        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        let id = run.id;
        let scope = run.scope;
        let revision = run.definition_revision as i64;
        let watermark = run.watermark;
        let input = run.input.clone();
        let fingerprint = run.fingerprint.clone();
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("INSERT INTO mdm_scope.scope_runs(tenant_id,id,scope,definition_revision,asset_watermark,input,fingerprint,phase) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,'sources')").bind(tenant).bind(id).bind(scope).bind(revision).bind(watermark).bind(input).bind(fingerprint).execute(c).await?;
            Ok(())
        })).await?;
        Ok(())
    }
    pub async fn run_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
    ) -> Result<Option<Run>, BindingError> {
        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        let row=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT * FROM mdm_scope.scope_runs WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE").bind(tenant).bind(id).fetch_optional(c).await
        })).await?;
        row.map(|r| {
            Ok(Run {
                id,
                scope: r.try_get("scope")?,
                definition_revision: r.try_get::<i64, _>("definition_revision")? as u64,
                watermark: r.try_get("asset_watermark")?,
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
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("INSERT INTO mdm_scope.scope_source_members(tenant_id,run,source,device,unknown,input) SELECT $1::uuid,$2,$3,d,u,i FROM unnest($4::text[],$5::boolean[],$6::jsonb[]) AS p(d,u,i)").bind(&tenant).bind(run).bind(index as i32).bind(objects).bind(unknown).bind(inputs).execute(&mut *c).await?;
            sqlx::query("UPDATE mdm_scope.scope_runs SET source_index=$3,source_cursor=$4 WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(run).bind((index+usize::from(!more)) as i32).bind(if more {cursor}else{None}).execute(c).await?;
            Ok(())
        })).await?;
        Ok(())
    }
    pub async fn phase_in(
        &self,
        tx: &mut PgTransaction<'_>,
        run: Uuid,
        phase: &str,
    ) -> Result<(), BindingError> {
        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        let phase = phase.to_owned();
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(
                    "UPDATE mdm_scope.scope_runs SET phase=$3 WHERE tenant_id=$1::uuid AND id=$2",
                )
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
        tx.with_connection(move |c|Box::pin(async move {
            let changed=sqlx::query_scalar::<_,bool>("WITH old AS (SELECT device,matched,explanation->'reasons' AS reasons,explanation->'identityRevision' AS identity FROM mdm_scope.scope_results WHERE tenant_id=$1::uuid AND run=$2), new AS (SELECT device,matched,explanation->'reasons' AS reasons,explanation->'identityRevision' AS identity FROM mdm_scope.scope_results WHERE tenant_id=$1::uuid AND run=$3) SELECT EXISTS((SELECT * FROM old EXCEPT SELECT * FROM new) UNION ALL (SELECT * FROM new EXCEPT SELECT * FROM old))")
                .bind(&tenant).bind(previous).bind(id).fetch_one(&mut *c).await? || previous.is_none() || channel_changed;
            let version=i64::try_from(old_version).ok().and_then(|v|v.checked_add(i64::from(changed))).ok_or_else(||sqlx::Error::Protocol("scope revision overflow".into()))?;
            sqlx::query("UPDATE mdm_scope.scope_runs SET phase='published' WHERE tenant_id=$1::uuid AND id=$2 AND phase='ready'").bind(&tenant).bind(id).execute(&mut *c).await?;
            sqlx::query("UPDATE mdm_scope.scopes SET resolution=$3,resolution_revision=$4,calculation_revision=calculation_revision+1 WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(scope).bind(id).bind(version).execute(c).await?;
            Ok(())
        })).await?;
        Ok(())
    }
    pub async fn enqueue_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        scope: Uuid,
    ) -> Result<Uuid, BindingError> {
        self.head_in(tx, scope, true).await?;
        let tenant = self.tenant.to_string();
        Ok(tx.with_connection(move |c|Box::pin(async move {
            let old=sqlx::query_scalar::<_,Uuid>("SELECT id FROM mdm_scope.tasks WHERE tenant_id=$1::uuid AND scope=$2 AND NOT completed").bind(&tenant).bind(scope).fetch_optional(&mut *c).await?;
            if let Some(old)=old { return Ok(old); }
            sqlx::query("INSERT INTO mdm_scope.tasks(tenant_id,id,scope) VALUES($1::uuid,$2,$3)").bind(tenant).bind(id).bind(scope).execute(c).await?;
            Ok(id)
        })).await?)
    }
    pub async fn task_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
    ) -> Result<Task, BindingError> {
        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        let r=tx.with_connection(move |c|Box::pin(async move { sqlx::query("SELECT t.*,EXISTS(SELECT 1 FROM mdm_scope.scope_runs r WHERE r.tenant_id=t.tenant_id AND r.id=t.id) AS forwarded FROM mdm_scope.tasks t WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).fetch_optional(c).await })).await?.ok_or(BindingError::Missing)?;
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
        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        let failure = failure.map(str::to_owned);
        Ok(tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("UPDATE mdm_scope.tasks SET completed=true,failure=$3 WHERE tenant_id=$1::uuid AND id=$2 AND NOT completed").bind(tenant).bind(id).bind(failure).execute(c).await.map(|r|r.rows_affected()==1)
        })).await?)
    }
    pub async fn replace_task_in(
        &self,
        tx: &mut PgTransaction<'_>,
        old: Uuid,
        new: Uuid,
    ) -> Result<(), BindingError> {
        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        tx.with_connection(move |c|Box::pin(async move {sqlx::query("UPDATE mdm_scope.tasks SET replacement_task=$3 WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(old).bind(new).execute(c).await?;Ok(())})).await?;
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
        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        let id = run.id;
        let after = run.evaluation_cursor.clone();
        let limit = 1000usize.min(16000 / source_count.max(1));
        let mut devices=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar::<_,String>("SELECT DISTINCT device FROM mdm_scope.scope_source_members WHERE tenant_id=$1::uuid AND run=$2 AND source=ANY($3) AND device>coalesce($4::text,'') COLLATE \"C\" ORDER BY device LIMIT $5").bind(tenant).bind(id).bind(targets).bind(after).bind((limit+1) as i64).fetch_all(c).await
        })).await?;
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
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("INSERT INTO mdm_scope.scope_results(tenant_id,run,device,matched,explanation) SELECT $1::uuid,$2,d,m,e FROM unnest($3::text[],$4::boolean[],$5::jsonb[]) AS p(d,m,e)").bind(&tenant).bind(id).bind(devices).bind(matched).bind(explanations).execute(&mut *c).await?;
            sqlx::query("UPDATE mdm_scope.scope_runs SET object_count=object_count+$3,member_count=member_count+$3,evaluation_cursor=$4,phase=$5 WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).bind(count).bind(last).bind(if more {"evaluate"}else{"project"}).execute(c).await?;
            Ok(())
        })).await?;
        Ok(())
    }
}
pub struct AssetPage {
    pub consumed: i64,
    pub watermark: i64,
    pub scopes: Vec<Uuid>,
    pub more: bool,
}
impl ScopeBinding {
    pub async fn asset_page_in(
        &self,
        tx: &mut PgTransaction<'_>,
    ) -> Result<Option<AssetPage>, BindingError> {
        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        let row=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("INSERT INTO mdm_scope.asset_dispatch(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING").bind(&tenant).execute(&mut *c).await?;
            sqlx::query_as::<_,(i64,i64,Option<Uuid>)>("SELECT consumed,watermark,cursor FROM mdm_scope.asset_dispatch WHERE tenant_id=$1::uuid FOR UPDATE").bind(tenant).fetch_one(c).await
        })).await?;
        let (consumed, mut watermark, mut cursor) = row;
        if consumed == watermark {
            let tenant = self.tenant.to_string();
            watermark=tx.with_connection(move |c|Box::pin(async move {
                sqlx::query_scalar("SELECT coalesce(max(revision),$2) FROM (SELECT revision FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND revision>$2 ORDER BY revision LIMIT 1000) page").bind(tenant).bind(consumed).fetch_one(c).await
            })).await?;
            cursor = None;
            if watermark == consumed {
                return Ok(None);
            }
        }
        let tenant = self.tenant.to_string();
        let mut scopes=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar::<_,Uuid>("WITH changed AS (SELECT DISTINCT coalesce(c.identity->>'device',r.device) AS device FROM mdm.asset_changes c LEFT JOIN mdm_access.registrations r ON r.tenant_id=c.tenant_id AND r.id::text=c.identity->>'registration' WHERE c.tenant_id=$1::uuid AND c.revision>$2 AND c.revision<=$3 AND (c.kind IN('device','registration','source','credential') OR 'channel.agent.installation'=ANY(c.fields))) SELECT DISTINCT s.scope FROM changed JOIN mdm_scope.scope_sources s ON s.tenant_id=$1::uuid AND s.kind='device' AND s.target=changed.device JOIN mdm_scope.scopes h ON(h.tenant_id,h.id)=(s.tenant_id,s.scope) WHERE NOT h.deleted AND ($4::uuid IS NULL OR s.scope>$4) ORDER BY s.scope LIMIT 33").bind(tenant).bind(consumed).bind(watermark).bind(cursor).fetch_all(c).await
        })).await?;
        let more = scopes.len() > 32;
        scopes.truncate(32);
        Ok(Some(AssetPage {
            consumed,
            watermark,
            scopes,
            more,
        }))
    }
    pub async fn complete_asset_page_in(
        &self,
        tx: &mut PgTransaction<'_>,
        page: &AssetPage,
    ) -> Result<(), BindingError> {
        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        let consumed = if page.more {
            page.consumed
        } else {
            page.watermark
        };
        let watermark = page.watermark;
        let cursor = if page.more {
            page.scopes.last().copied()
        } else {
            None
        };
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("UPDATE mdm_scope.asset_dispatch SET consumed=$2,watermark=$3,cursor=$4 WHERE tenant_id=$1::uuid").bind(tenant).bind(consumed).bind(watermark).bind(cursor).execute(c).await?;Ok(())
        })).await?;
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
        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        let row=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_as::<_,(i64,i64,i64,i64,i64)>("SELECT
            (SELECT count(*) FROM (SELECT 1 FROM mdm_scope.tasks t WHERE t.tenant_id=$1::uuid AND NOT completed AND NOT EXISTS(SELECT 1 FROM mdm_scope.scope_runs r WHERE(r.tenant_id,r.id)=(t.tenant_id,t.id)) LIMIT 1001) q),
            (SELECT count(*) FROM (SELECT 1 FROM mdm_scope.tasks t WHERE t.tenant_id=$1::uuid AND NOT completed AND EXISTS(SELECT 1 FROM mdm_scope.scope_runs r WHERE(r.tenant_id,r.id)=(t.tenant_id,t.id)) LIMIT 1001) q),
            (SELECT count(*) FROM (SELECT 1 FROM mdm_scope.tasks WHERE tenant_id=$1::uuid AND completed AND failure IS NULL LIMIT 1001) q),
            (SELECT count(*) FROM (SELECT 1 FROM mdm_scope.tasks WHERE tenant_id=$1::uuid AND failure IS NOT NULL AND failure<>'superseded' LIMIT 1001) q),
            (SELECT count(*) FROM (SELECT 1 FROM mdm_scope.tasks WHERE tenant_id=$1::uuid AND failure='superseded' LIMIT 1001) q)").bind(tenant).fetch_one(c).await
        })).await?;
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
        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        Ok(tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT coalesce((SELECT revision FROM mdm.asset_clock WHERE tenant_id=$1::uuid),0)>coalesce((SELECT consumed FROM mdm_scope.asset_dispatch WHERE tenant_id=$1::uuid),0) OR $2>coalesce((SELECT relation_consumed FROM mdm_scope.asset_dispatch WHERE tenant_id=$1::uuid),0) OR EXISTS(SELECT 1 FROM mdm_scope.group_changes WHERE tenant_id=$1::uuid AND NOT completed)")
                .bind(tenant).bind(relation).fetch_one(c).await
        })).await?)
    }
    /// Freeze a Device-owned change window; the scope cursor only pages matching references.
    pub async fn relation_window_in(
        &self,
        tx: &mut PgTransaction<'_>,
        revision: i64,
    ) -> Result<Option<RelationWindow>, BindingError> {
        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        let (consumed,mut watermark,mut position,mut cursor):(i64,i64,i64,Option<Uuid>)=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query("INSERT INTO mdm_scope.asset_dispatch(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING").bind(&tenant).execute(&mut *c).await?;
            sqlx::query_as("SELECT relation_consumed,relation_watermark,relation_position,relation_cursor FROM mdm_scope.asset_dispatch WHERE tenant_id=$1::uuid FOR UPDATE").bind(tenant).fetch_one(c).await
        })).await?;
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
        self.validate_in(tx)?;
        let tenant = self.tenant.to_string();
        let cursor = window.cursor;
        Ok(tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar("SELECT DISTINCT s.scope FROM mdm_scope.scope_sources s JOIN mdm_scope.scopes h ON(h.tenant_id,h.id)=(s.tenant_id,s.scope) WHERE s.tenant_id=$1::uuid AND s.kind='device' AND s.target=ANY($2) AND NOT h.deleted AND ($3::uuid IS NULL OR s.scope>$3) ORDER BY s.scope LIMIT 33").bind(tenant).bind(devices).bind(cursor).fetch_all(c).await
        })).await?)
    }
    pub async fn complete_relation_page_in(
        &self,
        tx: &mut PgTransaction<'_>,
        window: &RelationWindow,
        through: i64,
        more_changes: bool,
        scopes: &[Uuid],
    ) -> Result<(), BindingError> {
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
        } else {
            through
        };
        let watermark = window.watermark;
        tx.with_connection(move|c|Box::pin(async move {
            sqlx::query("UPDATE mdm_scope.asset_dispatch SET relation_consumed=$2,relation_watermark=$3,relation_position=$4,relation_cursor=$5 WHERE tenant_id=$1::uuid").bind(tenant).bind(consumed).bind(watermark).bind(position).bind(cursor).execute(c).await?;Ok(())
        })).await?;
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
