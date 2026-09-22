use super::*;
use serde_json::json;
use sqlx::Row;
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
    async fn validate_scope_references_in(
        &self,
        tx: &mut PgTransaction<'_>,
        definition: &ScopeDefinition,
    ) -> Result<()> {
        if definition.references().len() > 1000 {
            return Err(Error::Malformed.into());
        }
        for reference in definition.references() {
            match reference {
                Reference::Group(id) => {
                    group_checked(
                        self.groups
                            .lock_reference_target_in(
                                tx,
                                input(rss_mdm_group_postgres::GroupId::parse(&id.to_string()))?,
                            )
                            .await?,
                    )?;
                }
                Reference::Device(id) => {
                    storage::device(tx, &id).await?;
                }
            }
        }
        Ok(())
    }
    pub(super) async fn scope_change(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        op: &Operation<ScopeChange>,
        _at: Timepoint,
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
                self.validate_scope_references_in(tx, definition).await?;
                let tenant = self.tenant.to_string();
                let definition = input(serde_json::to_string(definition))?;
                let expected = op.expected_revision as i64;
                let changed=tx.with_connection(move |c|Box::pin(async move {
                    let changed=if expected==0 {
                        sqlx::query("INSERT INTO mdm_management.scopes(tenant_id,id,revision,deleted) VALUES($1::uuid,$2::uuid,1,false) ON CONFLICT DO NOTHING").bind(&tenant).bind(id.to_string()).execute(&mut *c).await?.rows_affected()
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
                    sqlx::query("UPDATE mdm_management.scopes SET deleted=true,revision=revision+1 WHERE tenant_id=$1::uuid AND id=$2::uuid AND NOT EXISTS(SELECT 1 FROM mdm_policy.candidates c JOIN mdm_management.automation_jobs j ON j.tenant_id=c.tenant_id AND j.id::text=c.id WHERE c.tenant_id=$1::uuid AND c.phase='saved' AND j.input->>'scope'=$2::text)")
                        .bind(tenant).bind(id.to_string()).execute(c).await.map(|r|r.rows_affected())
                })).await?;
                if changed != 1 {
                    return Err(Error::Conflict.into());
                }
            }
        }
        let refs = match &op.input {
            ScopeChange::Put { definition } => definition.references(),
            ScopeChange::Delete => Default::default(),
        };
        let mut kinds = Vec::new();
        let mut targets = Vec::new();
        for reference in refs {
            match reference {
                Reference::Group(id) => {
                    kinds.push("group");
                    targets.push(id.to_string());
                }
                Reference::Device(id) => {
                    kinds.push("device");
                    targets.push(id);
                }
            }
        }
        let tenant = self.tenant.to_string();
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("DELETE FROM mdm_management.scope_sources WHERE tenant_id=$1::uuid AND scope=$2::uuid").bind(&tenant).bind(id.to_string()).execute(&mut *c).await?;
            sqlx::query("INSERT INTO mdm_management.scope_sources SELECT $1::uuid,$2::uuid,* FROM unnest($3::text[],$4::text[])").bind(tenant).bind(id.to_string()).bind(kinds).bind(targets).execute(c).await?;Ok(())
        })).await?;
        checked(
            self.policies
                .advance_reference_in(tx, &format!("scope-definition.{id}"), revision)
                .await?,
        )?;
        let task = if matches!(op.input, ScopeChange::Put { .. }) {
            let task = Uuid::new_v4();
            self.enqueue_job_in(tx, task, &automation::JobInput::Scope { scope: id })
                .await?;
            Some(task)
        } else {
            None
        };
        Ok(json!({"id":id,"revision":revision,"task":task}))
    }
    pub(super) async fn reject_group_reference(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
    ) -> Result<()> {
        let tenant = self.tenant.to_string();
        let used:bool=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_management.scope_sources WHERE tenant_id=$1::uuid AND kind='group' AND target=$2) OR EXISTS(SELECT 1 FROM mdm_policy.candidate_references r JOIN mdm_policy.candidates p ON (p.tenant_id,p.id)=(r.tenant_id,r.candidate) WHERE r.tenant_id=$1::uuid AND p.phase='saved' AND r.reference='group-members.'||$2)")
                .bind(tenant).bind(id.to_string()).fetch_one(c).await
        })).await?;
        if used {
            return Err(Error::Conflict.into());
        }
        Ok(())
    }
}
