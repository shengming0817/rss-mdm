use rss_mdm_scope_postgres::{Publication, ScopeBinding};
use rss_mdm_scope_service::{
    Error, Failure,
    sources::{
        ChannelProjectionPublisher, Pending, ResultDetail, ResultDevices, ResultPage, ScopeInput,
    },
    transaction::{Fault, Result, checked_input, stored},
};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgRuntime, PgTransaction};
use sqlx::Row;
use std::sync::Arc;
use uuid::Uuid;
pub struct ScopeProjection {
    runtime: Arc<PgRuntime>,
    tenant: TenantId,
    scope: ScopeBinding,
}
impl ScopeProjection {
    pub fn new(runtime: Arc<PgRuntime>, tenant: TenantId) -> Self {
        Self {
            scope: ScopeBinding::new(runtime.clone(), tenant),
            runtime,
            tenant,
        }
    }
    fn validate(&self, tx: &PgTransaction<'_>) -> Result<()> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant {
            return Err(Error::Forbidden.into());
        }
        Ok(())
    }
    async fn admit(&self, tx: &mut PgTransaction<'_>) -> Result<()> {
        self.validate(tx)?;
        tx.with_connection(|c| {
            Box::pin(async {
                crate::verify_authority(c).await?;
                let valid: bool = sqlx::query_scalar(include_str!("admission.sql"))
                    .bind(true)
                    .fetch_one(c)
                    .await?;
                if !valid {
                    return Err(sqlx::Error::Protocol(
                        "Scope projection admission rejected".into(),
                    ));
                }
                Ok(())
            })
        })
        .await?;
        Ok(())
    }
    async fn advance(&self, tx: &mut PgTransaction<'_>, p: &Publication) -> Result<bool> {
        self.admit(tx).await?;
        let head = self.scope.head_in(tx, p.scope, true).await?;
        if head.revision != p.definition_revision || head.resolution != p.previous_resolution {
            return Err(Error::Conflict.into());
        }
        let tenant = self.tenant.to_string();
        let id = p.run;
        let scope = p.scope;
        let previous = head.resolution;
        let epoch = i64::try_from(head.calculation_revision)
            .ok()
            .and_then(|n| n.checked_add(1))
            .ok_or(Error::Conflict)?;
        let row=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("INSERT INTO mdm_commands.scope_projection_runs(tenant_id,id,scope,previous_resolution,next_entry,phase) VALUES($1::uuid,$2,$3,$4,$5,'sources') ON CONFLICT DO NOTHING").bind(&tenant).bind(id).bind(scope).bind(previous).bind(epoch).execute(&mut *c).await?;
            sqlx::query("SELECT * FROM mdm_commands.scope_projection_runs WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE").bind(tenant).bind(id).fetch_one(c).await
        })).await?;
        if row.try_get::<Option<Uuid>, _>("previous_resolution")? != previous
            || row.try_get::<Uuid, _>("scope")? != scope
        {
            return Err(Error::Conflict.into());
        }
        match row.try_get::<&str, _>("phase")? {
            "sources" => {
                self.stage(tx, id, row.try_get("source_cursor")?).await?;
                Ok(false)
            }
            "project" => {
                let run = self.scope.run_in(tx, id).await?.ok_or(Error::NotFound)?;
                let input: ScopeInput = stored(serde_json::from_value(run.input))?;
                self.project(tx, id, &input, &row).await?;
                Ok(false)
            }
            "ready" => Ok(true),
            _ => Err(Error::Conflict.into()),
        }
    }
    async fn stage(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        after: Option<String>,
    ) -> Result<()> {
        let tenant = self.tenant.to_string();
        tx.with_connection(move |c|Box::pin(async move {
            let rows=sqlx::query_as::<_,(String,serde_json::Value)>("SELECT m.source::text||':'||m.device AS key,m.input FROM mdm_scope.scope_source_members m JOIN mdm_scope.scope_runs r ON(r.tenant_id,r.id)=(m.tenant_id,m.run) WHERE m.tenant_id=$1::uuid AND m.run=$2 AND r.input->'definition'->'targets' @> jsonb_build_array(r.input->'sources'->m.source->'reference') AND (m.source::text||':'||m.device)>coalesce($3,'') COLLATE \"C\" ORDER BY (m.source::text||':'||m.device) COLLATE \"C\" LIMIT 1001").bind(&tenant).bind(id).bind(after).fetch_all(&mut *c).await?;
            let more=rows.len()>1000;let last=rows.iter().take(1000).next_back().map(|r|r.0.clone());let inputs:Vec<_>=rows.into_iter().take(1000).map(|r|r.1).collect();
            sqlx::query("INSERT INTO mdm_commands.scope_channel_results(tenant_id,run,channel,device,matched,pending,target,entry_revision) SELECT $1::uuid,$2,m->>'channel',m->>'device',false,count(DISTINCT m)>1,(array_agg(m ORDER BY m::text))[1],0 FROM unnest($3::jsonb[]) i CROSS JOIN LATERAL jsonb_array_elements(i->'members') m GROUP BY m->>'channel',m->>'device' ON CONFLICT(tenant_id,run,channel,device) DO UPDATE SET pending=mdm_commands.scope_channel_results.pending OR EXCLUDED.pending OR mdm_commands.scope_channel_results.target IS DISTINCT FROM EXCLUDED.target").bind(&tenant).bind(id).bind(inputs).execute(&mut *c).await?;
            sqlx::query("UPDATE mdm_commands.scope_projection_runs SET source_cursor=$3,phase=$4 WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).bind(last).bind(if more {"sources"}else{"project"}).execute(c).await?;Ok(())
        })).await?;
        Ok(())
    }
    async fn project(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        frozen: &ScopeInput,
        progress: &sqlx::postgres::PgRow,
    ) -> Result<()> {
        let after: Option<String> = progress.try_get("projection_cursor")?;
        let previous: Option<Uuid> = progress.try_get("previous_resolution")?;
        let epoch: i64 = progress.try_get("next_entry")?;
        let hashes: serde_json::Value = progress.try_get("channel_hashes")?;
        let tenant = self.tenant;
        let page=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_as::<_,(String,String,String)>("SELECT channel,device,channel||':'||device AS key FROM mdm_commands.scope_channel_results WHERE tenant_id=$1::uuid AND run=$2 AND channel||':'||device>coalesce($3,'') COLLATE \"C\" ORDER BY (channel||':'||device) COLLATE \"C\" LIMIT 17").bind(tenant.to_string()).bind(id).bind(after).fetch_all(c).await
        })).await?;
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
                let result=super::targets::explanation_on(c,tenant,id,&frozen,channel,&device,None).await.map_err(|_|sqlx::Error::Protocol("scope projection invalid".into()))?;
                let identities:Vec<serde_json::Value>=sqlx::query_scalar("SELECT DISTINCT m FROM mdm_scope.scope_source_members s CROSS JOIN LATERAL jsonb_array_elements(s.input->'members') m WHERE s.tenant_id=$1::uuid AND s.run=$2 AND s.input->'members' @> jsonb_build_array(jsonb_build_object('device',$4::text,'channel',$3::text)) AND m->>'channel'=$3 AND m->>'device'=$4").bind(tenant.to_string()).bind(id).bind(channel.as_str()).bind(&device).fetch_all(&mut *c).await?;
                let target=identities.first().ok_or_else(||sqlx::Error::Protocol("scope target missing".into()))?.clone();
                let excluded=result.as_ref().is_some_and(|r|r.reasons.contains(&rss_mdm_scope::ExclusionReason::ExplicitExclusion));
                let pending=!excluded && (identities.len()!=1 || result.as_ref().is_some_and(|r|r.reasons.iter().any(|r|matches!(r,rss_mdm_scope::ExclusionReason::UnknownTarget|rss_mdm_scope::ExclusionReason::UnknownLimitation|rss_mdm_scope::ExclusionReason::UnknownExclusion))));
                let matched=!pending && result.as_ref().is_some_and(|r|r.reasons.is_empty());
                let entry=if matched||pending {sqlx::query_scalar::<_,i64>("SELECT entry_revision FROM mdm_commands.scope_channel_results WHERE tenant_id=$1::uuid AND run=$2 AND channel=$3 AND device=$4 AND (matched OR pending) AND entry_revision>0 AND target=$5").bind(tenant.to_string()).bind(previous).bind(channel.as_str()).bind(&device).bind(&target).fetch_optional(&mut *c).await?.unwrap_or(if matched {epoch}else{0})}else{0};
                sqlx::query("UPDATE mdm_commands.scope_channel_results SET matched=$5,pending=$6,target=$7,entry_revision=$8 WHERE tenant_id=$1::uuid AND run=$2 AND channel=$3 AND device=$4").bind(tenant.to_string()).bind(id).bind(channel.as_str()).bind(&device).bind(matched).bind(pending).bind(&target).bind(entry).execute(c).await?;
                Ok(serde_json::json!([device,matched,pending,target]))
            })).await?;
            use sha2::Digest;
            let key = channel.as_str();
            let old = hashes.get(key).ok_or(Error::Malformed)?;
            let bytes = checked_input(serde_json::to_vec(&row_hash))?;
            let mut digest = sha2::Sha256::new();
            digest.update(old.as_bytes());
            digest.update((bytes.len() as u64).to_be_bytes());
            digest.update(bytes);
            hashes.insert(key.into(), format!("{:x}", digest.finalize()));
        }
        let hashes = checked_input(serde_json::to_value(hashes))?;
        let next = page.iter().take(16).next_back().map(|r| r.2.clone());
        let more = page.len() > 16;
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("UPDATE mdm_commands.scope_projection_runs SET projection_cursor=$3,phase=$4,channel_hashes=$5 WHERE tenant_id=$1::uuid AND id=$2").bind(tenant.to_string()).bind(id).bind(next).bind(if more {"project"}else{"ready"}).bind(hashes).execute(c).await?;Ok(())
        })).await?;
        Ok(())
    }
    async fn publish(&self, tx: &mut PgTransaction<'_>, p: &Publication) -> Result<bool> {
        self.admit(tx).await?;
        let head = self.scope.head_in(tx, p.scope, true).await?;
        if head.revision != p.definition_revision || head.resolution != p.previous_resolution {
            return Err(Error::Conflict.into());
        }
        let tenant = self.tenant.to_string();
        let id = p.run;
        let previous = p.previous_resolution;
        let changed=tx.with_connection(move |c|Box::pin(async move {
            let row=sqlx::query_as::<_,(bool,bool,i64,i64)>("SELECT o.id IS NULL OR n.channel_hashes->>'agent' IS DISTINCT FROM o.channel_hashes->>'agent',o.id IS NULL OR n.channel_hashes->>'mdm' IS DISTINCT FROM o.channel_hashes->>'mdm',coalesce(o.agent_revision,0),coalesce(o.mdm_revision,0) FROM mdm_commands.scope_projection_runs n LEFT JOIN mdm_commands.scope_projection_runs o ON(o.tenant_id,o.id)=(n.tenant_id,$3) WHERE n.tenant_id=$1::uuid AND n.id=$2 AND n.phase='ready' AND n.previous_resolution IS NOT DISTINCT FROM $3").bind(&tenant).bind(id).bind(previous).fetch_optional(&mut *c).await?;
            let Some((agent,mdm,a,m))=row else {return Ok(None);};
            let a=a.checked_add(i64::from(agent)).ok_or_else(||sqlx::Error::Protocol("projection revision overflow".into()))?;
            let m=m.checked_add(i64::from(mdm)).ok_or_else(||sqlx::Error::Protocol("projection revision overflow".into()))?;
            sqlx::query("UPDATE mdm_commands.scope_projection_runs SET phase='published',agent_revision=$3,mdm_revision=$4 WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).bind(a).bind(m).execute(c).await?;
            Ok(Some(agent||mdm))
        })).await?;
        changed.ok_or(Error::Conflict.into())
    }
}
fn source_error(e: crate::source_authority::SourceError) -> Fault {
    use crate::source_authority::SourceError as E;
    match e {
        E::Storage(e) => Fault::Sql(e),
        E::Missing => Error::NotFound.into(),
        E::Conflict => Error::Conflict.into(),
        E::Capacity => Error::Unavailable(Failure::Capacity).into(),
        E::Invariant => Error::Unavailable(Failure::Storage).into(),
    }
}
impl ChannelProjectionPublisher for ScopeProjection {
    fn advance_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a Publication,
    ) -> Pending<'a, bool, Fault> {
        Box::pin(self.advance(tx, p))
    }
    fn publish_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a Publication,
    ) -> Pending<'a, bool, Fault> {
        Box::pin(self.publish(tx, p))
    }
    fn result_devices_on<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        page: ResultPage<'a>,
    ) -> Pending<'a, ResultDevices, Fault> {
        Box::pin(async move {
            let ResultPage {
                tenant,
                scope,
                run,
                channel,
                after,
                limit,
            } = page;
            if tenant != self.tenant {
                return Err(Error::Forbidden.into());
            }
            let page =
                super::targets::result_devices_on(c, tenant, scope, run, channel, after, limit)
                    .await
                    .map_err(source_error)?;
            let current=sqlx::query_scalar::<_,bool>("SELECT NOT deleted AND resolution=$3 FROM mdm_scope.scopes WHERE tenant_id=$1::uuid AND id=$2").bind(tenant.to_string()).bind(scope).bind(run).fetch_one(c).await?;
            Ok(ResultDevices {
                result: page.result,
                devices: page.devices,
                current,
            })
        })
    }
    fn result_detail_on<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        tenant: TenantId,
        scope: Uuid,
        run: Uuid,
        channel: rss_mdm_inventory::Channel,
        device: &'a str,
    ) -> Pending<'a, ResultDetail, Fault> {
        Box::pin(async move {
            if tenant != self.tenant {
                return Err(Error::Forbidden.into());
            }
            let status =
                super::targets::result_admission_on(c, tenant, scope, run, channel, device)
                    .await
                    .map_err(source_error)?;
            let explanation =
                super::targets::result_explanation_on(c, tenant, scope, run, channel, device)
                    .await
                    .map_err(source_error)?;
            use crate::source_authority::ScopeAdmission as A;
            Ok(ResultDetail {
                matched: matches!(status, A::Eligible { .. }),
                pending: status == A::Pending,
                entry: if let A::Eligible { entry } = status {
                    entry
                } else {
                    0
                },
                explanation,
            })
        })
    }
}
