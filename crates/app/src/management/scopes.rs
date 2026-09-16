use super::*;
use rss_mdm_scope as s;
use serde_json::json;
use sqlx::Row;
use std::collections::{BTreeMap, BTreeSet};
impl Management {
    pub(super) async fn scope_read(&self, tx: &mut PgTransaction<'_>, id: Uuid) -> Result<Value> {
        let (revision, definition) = self.scope_definition(tx, id).await?;
        Ok(json!({"id":id,"revision":revision,"definition":definition}))
    }
    pub(super) async fn scope_definition(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
    ) -> Result<(u64, ScopeDefinition)> {
        let tenant = self.tenant.to_string();
        let row=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT s.revision,v.definition::text FROM mdm_management.scopes s JOIN mdm_management.scope_versions v USING(tenant_id,id,revision) WHERE s.tenant_id=$1::uuid AND s.id=$2::uuid AND NOT s.deleted FOR UPDATE OF s")
                .bind(tenant).bind(id.to_string()).fetch_optional(c).await
        })).await?.ok_or(Error::ManagementNotFound(Missing::Scope))?;
        Ok((
            row.try_get::<i64, _>("revision")? as u64,
            stored(serde_json::from_str(
                &row.try_get::<String, _>("definition")?,
            ))?,
        ))
    }
    pub(super) async fn scope_change(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        op: &Operation<ScopeChange>,
        at: Timepoint,
    ) -> Result<Value> {
        if id.is_nil() {
            return Err(Error::Malformed.into());
        }
        let revision = op
            .expected_revision
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or(Error::Conflict)?;
        match &op.input {
            ScopeChange::Put { definition } => {
                if definition.references().len() > 1000 {
                    return Err(Error::Malformed.into());
                }
                self.sources(tx, definition, at).await?;
                let tenant = self.tenant.to_string();
                let definition = input(serde_json::to_string(definition))?;
                let expected = op.expected_revision as i64;
                let changed=tx.with_connection(move |c|Box::pin(async move {
                    let changed=if expected==0 {
                        sqlx::query("INSERT INTO mdm_management.scopes VALUES($1::uuid,$2::uuid,1,false) ON CONFLICT DO NOTHING").bind(&tenant).bind(id.to_string()).execute(&mut *c).await?.rows_affected()
                    }else {
                        sqlx::query("UPDATE mdm_management.scopes SET revision=revision+1 WHERE tenant_id=$1::uuid AND id=$2::uuid AND revision=$3 AND NOT deleted").bind(&tenant).bind(id.to_string()).bind(expected).execute(&mut *c).await?.rows_affected()
                    };
                    if changed==1 {sqlx::query("INSERT INTO mdm_management.scope_versions VALUES($1::uuid,$2::uuid,$3,$4::jsonb)").bind(tenant).bind(id.to_string()).bind(revision as i64).bind(definition).execute(c).await?;}
                    Ok(changed)
                })).await?;
                if changed != 1 {
                    return Err(Error::Conflict.into());
                }
            }
            ScopeChange::Delete => {
                let (current, _) = self.scope_definition(tx, id).await?;
                if current != op.expected_revision {
                    return Err(Error::Conflict.into());
                }
                let tenant = self.tenant.to_string();
                let changed=tx.with_connection(move |c|Box::pin(async move {
                    sqlx::query("UPDATE mdm_management.scopes SET deleted=true,revision=revision+1 WHERE tenant_id=$1::uuid AND id=$2::uuid AND NOT EXISTS(SELECT 1 FROM mdm_management.previews p JOIN mdm_management.plan_references r ON (r.tenant_id,r.preview)=(p.tenant_id,p.id) WHERE p.tenant_id=$1::uuid AND p.scope=$2::uuid)")
                        .bind(tenant).bind(id.to_string()).execute(c).await.map(|r|r.rows_affected())
                })).await?;
                if changed != 1 {
                    return Err(Error::Conflict.into());
                }
            }
        }
        Ok(json!({"id":id,"revision":revision}))
    }
    pub(super) async fn reject_group_reference(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
    ) -> Result<()> {
        let tenant = self.tenant.to_string();
        let rows=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar::<_,String>("SELECT v.definition::text FROM mdm_management.scope_versions v JOIN mdm_management.scopes s USING(tenant_id,id) WHERE v.tenant_id=$1::uuid AND NOT s.deleted AND (v.revision=s.revision OR EXISTS(SELECT 1 FROM mdm_management.previews p JOIN mdm_management.plan_references r ON (r.tenant_id,r.preview)=(p.tenant_id,p.id) WHERE (p.tenant_id,p.scope,p.scope_revision)=(v.tenant_id,v.id,v.revision))) LIMIT 10001")
                .bind(tenant).fetch_all(c).await
        })).await?;
        if rows.len() > 10_000 {
            return Err(Error::Conflict.into());
        }
        for row in rows {
            let def: ScopeDefinition = stored(serde_json::from_str(&row))?;
            if def.references().contains(&Reference::Group(id)) {
                return Err(Error::Conflict.into());
            }
        }
        Ok(())
    }
    pub(super) async fn sources(
        &self,
        tx: &mut PgTransaction<'_>,
        definition: &ScopeDefinition,
        at: Timepoint,
    ) -> Result<(Vec<Source>, s::ScopeResolution)> {
        let mut sources = Vec::new();
        let mut resolved = BTreeMap::new();
        let refs = definition.references();
        if refs.len() > 1000 {
            return Err(Error::Malformed.into());
        }
        let mut total = 0usize;
        for reference in refs {
            let (identity, revision, member_version, members) = match &reference {
                Reference::Device(id) => (
                    s::SourceId::Direct(input(s::DeviceId::new(self.tenant, id))?),
                    storage::device(tx, id).await?.revision,
                    None,
                    vec![id.clone()],
                ),
                Reference::Group(id) => {
                    let id = input(rss_mdm_group_postgres::GroupId::parse(&id.to_string()))?;
                    let g = group_checked(self.groups.lock_reference_target_in(tx, id).await?)?;
                    let members = checked(self.groups.members_in(tx, id).await?)?;
                    (
                        s::SourceId::Group(input(s::GroupId::new(self.tenant, id.to_string()))?),
                        g.revision.get() as u64,
                        Some(g.member_version),
                        members.iter().map(|m| m.id().to_owned()).collect(),
                    )
                }
            };
            total = total.checked_add(members.len()).ok_or(Error::Malformed)?;
            if total > 10_000 {
                return Err(Error::Malformed.into());
            }
            let devices = members
                .iter()
                .map(|id| input(s::DeviceId::new(self.tenant, id)))
                .collect::<Result<Vec<_>>>()?;
            resolved.insert(
                reference.clone(),
                s::ResolvedSource {
                    source: input(s::SourceRef::new(identity, revision, at))?,
                    resolution: s::Resolution::Complete(devices),
                },
            );
            sources.push(Source {
                reference,
                revision,
                member_version,
                members,
            });
        }
        let select =
            |refs: &BTreeSet<Reference>| refs.iter().map(|r| resolved[r].clone()).collect();
        let output = input(s::resolve(&s::ScopeInput {
            tenant: self.tenant,
            targets: select(&definition.targets),
            limitations: match &definition.limitations {
                None => s::Limitations::Unrestricted,
                Some(r) => s::Limitations::Restricted(select(r)),
            },
            exclusions: select(&definition.exclusions),
        }))?;
        for id in &output.members {
            storage::device(tx, id.value()).await?;
        }
        Ok((sources, output))
    }
}
pub(super) fn explanation(resolution: &s::ScopeResolution) -> Value {
    let refs = |values: &[s::SourceRef]| {
        values.iter().map(|r| {
        let reference=match r.id() {s::SourceId::Direct(id)=>json!({"kind":"device","id":id.value()}),s::SourceId::Group(id)=>json!({"kind":"group","id":id.value()})};
        json!({"reference":reference,"revision":r.version(),"resolved_at":r.resolved_at().unix_seconds()})
    }).collect::<Vec<_>>()
    };
    json!({"targets":refs(&resolution.target_sources),"limitations":resolution.limitation_sources.as_ref().map(|s|refs(s)),"exclusions":refs(&resolution.exclusion_sources),"members":resolution.explanations.iter().map(|e|json!({"device":e.object.value(),"targets":refs(&e.targets),"limitations":refs(&e.limitations),"exclusions":refs(&e.exclusions),"reasons":e.reasons.iter().map(|r|match r {s::ExclusionReason::MissingLimitationMatch=>"missing_limitation_match",s::ExclusionReason::ExplicitExclusion=>"explicit_exclusion"}).collect::<Vec<_>>()})).collect::<Vec<_>>()})
}
