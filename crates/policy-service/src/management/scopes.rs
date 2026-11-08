//! Policy context and editing CAS for the existing Scope capabilities.
use super::*;
use rss_mdm_scope_postgres::ScopeOwner;
use rss_mdm_scope_service::{pages, preview, wire};

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Preview {
    pub expected_revision: u64,
    pub definition: rss_mdm_scope::ScopeDefinition,
    pub channel: rss_mdm_inventory::Channel,
}
#[derive(Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Recompute {
    pub operation_id: Uuid,
    pub expected_revision: u64,
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Qualification {
    pub expected_revision: u64,
    #[serde(deserialize_with = "rss_mdm_policy::definition_input")]
    #[schemars(
        schema_with = "rss_mdm_policy::definition_input_schema::<rss_mdm_scope::ScopeDefinition>"
    )]
    pub definition: Box<rss_mdm_policy::Definition<rss_mdm_scope::ScopeDefinition>>,
    pub scope_result: Option<Uuid>,
}
impl Policies {
    async fn scope_context_in(
        &self,
        tx: &mut PgTransaction<'_>,
        proof: &AuthorizedPrincipal,
        owner: ScopeOwner,
        expected: Option<u64>,
    ) -> Result<Option<Policy>> {
        if !owner.is_valid() {
            return Err(Error::Malformed.into());
        }
        let grant = crate::action_admission::current(tx, proof).await?;
        grant.require(proof, Permission::PolicyRead, None)?;
        let policy = checked(
            self.policy_store
                .reader()
                .locked_in(tx, owner.policy)
                .await?,
        )?;
        if expected.is_some_and(|r| r != policy.as_ref().map_or(0, |p| p.revision as u64)) {
            return Err(Error::Conflict.into());
        }
        if policy.is_none() && expected != Some(0) {
            return Err(Error::PolicyMissing.into());
        }
        Ok(policy)
    }
    pub async fn scope_read(
        &self,
        proof: &AuthorizedPrincipal,
        audit: &RequestAudit,
        owner: ScopeOwner,
    ) -> std::result::Result<wire::ScopeRead, Error> {
        inspect(
            &self.runtime,
            self.tenant,
            (self, proof, owner),
            |(s, p, owner), tx| {
                Box::pin(async move {
                    s.scope_context_in(tx, p, *owner, None).await?;
                    let child = s.scopes.read_owned_in(tx, *owner).await?;
                    s.scopes
                        .authorize_definition_in(tx, p, &child.definition)
                        .await?;
                    p.check_live()?;
                    Ok(child)
                })
            },
        )
        .await
        .map(|v| {
            audit.resource_target(
                rss_mdm_audit_integration::TargetKind::Policy,
                &owner.policy.to_string(),
            );
            v
        })
    }
    pub async fn scope_preview(
        &self,
        proof: &AuthorizedPrincipal,
        audit: &RequestAudit,
        owner: ScopeOwner,
        input: &Preview,
    ) -> std::result::Result<preview::Response, Error> {
        let editing = inspect(
            &self.runtime,
            self.tenant,
            (self, proof, owner, input),
            |(s, p, owner, input), tx| {
                Box::pin(async move {
                    let policy = s
                        .scope_context_in(tx, p, *owner, Some(input.expected_revision))
                        .await?;
                    if policy
                        .as_ref()
                        .is_some_and(|p| p.state == rss_mdm_policy::State::Archived)
                    {
                        return Err(Error::Conflict.into());
                    }
                    let child = s.scopes.owned_in(tx, *owner).await?;
                    if child.as_ref().is_some_and(|c| c.retired) {
                        return Err(Error::Conflict.into());
                    }
                    Ok(child.map(|c| preview::Editing {
                        scope_id: c.id,
                        expected_revision: c.head.revision,
                    }))
                })
            },
        )
        .await?;
        let result = self
            .scopes
            .preview(
                proof,
                &preview::Request {
                    definition: input.definition.clone(),
                    channel: input.channel,
                    editing,
                    owner,
                },
                audit,
            )
            .await?;
        inspect(
            &self.runtime,
            self.tenant,
            (self, proof, input),
            |(s, p, input), tx| {
                Box::pin(async move {
                    s.scope_context_in(tx, p, owner, Some(input.expected_revision))
                        .await?;
                    p.check_live()?;
                    Ok(())
                })
            },
        )
        .await?;
        Ok(result)
    }
    pub async fn scope_page(
        &self,
        proof: &AuthorizedPrincipal,
        audit: &RequestAudit,
        owner: ScopeOwner,
        result: Uuid,
        projection: pages::ScopePageKind,
        query: pages::ResultQuery,
    ) -> std::result::Result<pages::ScopePage, Error> {
        let child = self.scope_read(proof, audit, owner).await?;
        let value = self
            .scopes
            .page(
                proof,
                &pages::PageRequest {
                    scope: child.id,
                    result,
                    projection,
                    query,
                },
                audit,
            )
            .await?;
        serde_json::from_value(value).map_err(|_| Error::Unavailable(crate::Failure::PolicyStorage))
    }
    pub async fn scope_task(
        &self,
        proof: &AuthorizedPrincipal,
        audit: &RequestAudit,
        owner: ScopeOwner,
        task: Uuid,
    ) -> std::result::Result<rss_mdm_inventory_service::tasks::TaskRead, Error> {
        audit.resource_target(
            rss_mdm_audit_integration::TargetKind::Policy,
            &owner.policy.to_string(),
        );
        let value = inspect(
            &self.runtime,
            self.tenant,
            (self, proof, owner),
            |(s, p, owner), tx| {
                Box::pin(async move {
                    s.scope_context_in(tx, p, *owner, None).await?;
                    let child = s.scopes.read_owned_in(tx, *owner).await?;
                    s.scopes
                        .authorize_definition_in(tx, p, &child.definition)
                        .await?;
                    let value = s
                        .scopes
                        .task_read_in(tx, task, Some(&child.id.to_string()))
                        .await?;
                    p.check_live()?;
                    Ok(value)
                })
            },
        )
        .await?;
        serde_json::from_value(value).map_err(|_| Error::Unavailable(crate::Failure::PolicyStorage))
    }
    pub async fn scope_recompute(
        &self,
        proof: &AuthorizedPrincipal,
        audit: &RequestAudit,
        owner: ScopeOwner,
        input: &Recompute,
    ) -> std::result::Result<wire::ScopeReceipt, Error> {
        proof.manage(Permission::PolicyWrite)?;
        audit.resource_target(
            rss_mdm_audit_integration::TargetKind::Policy,
            &owner.policy.to_string(),
        );
        audit.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::Scope,
            input.operation_id,
            "scope_recompute",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        run(
            &self.audit_store,
            &self.runtime,
            self.tenant,
            audit,
            (self, proof, audit, owner, input),
            |(s, p, a, owner, input), tx| {
                Box::pin(async move {
                    crate::action_admission::current(tx, p).await?.require(
                        p,
                        Permission::PolicyWrite,
                        None,
                    )?;
                    s.audit_store.prepare_in(tx, a, &[]).await?;
                    let policy =
                        checked(s.policy_store.read_for_update_in(tx, owner.policy).await?)?
                            .ok_or(Error::PolicyMissing)?;
                    let result = s
                        .scopes
                        .recompute_owned_in(
                            tx,
                            p,
                            a,
                            *owner,
                            input.operation_id,
                            input.expected_revision,
                            policy.revision as u64,
                        )
                        .await?;
                    p.check_live()?;
                    Ok(result)
                })
            },
        )
        .await
    }
    /// An action preview may reuse only the caller's exact saved range definitions.
    pub async fn qualify(
        &self,
        proof: &AuthorizedPrincipal,
        policy: Uuid,
        input: &Qualification,
    ) -> std::result::Result<rss_mdm_policy::pages::Preview, Error> {
        inspect(
            &self.runtime,
            self.tenant,
            (self, proof, input),
            |(s, p, input), tx| {
                Box::pin(async move {
                    s.scope_context_in(
                        tx,
                        p,
                        ScopeOwner {
                            policy,
                            stage: None,
                        },
                        Some(input.expected_revision),
                    )
                    .await?
                    .ok_or(Error::PolicyMissing)?;
                    let mut drafts = Vec::new();
                    input
                        .definition
                        .as_ref()
                        .clone()
                        .try_map_scopes(|stage, definition| {
                            drafts.push((stage, definition));
                            Ok::<_, Error>(Uuid::from_u128(1))
                        })?;
                    let mut ids = std::collections::BTreeMap::new();
                    for (stage, definition) in drafts {
                        let child = s
                            .scopes
                            .read_owned_in(tx, ScopeOwner { policy, stage })
                            .await?;
                        if child.retired || child.definition != definition {
                            return Err(Error::Conflict.into());
                        }
                        s.scopes.authorize_definition_in(tx, p, &definition).await?;
                        ids.insert(stage, child.id);
                    }
                    let definition = input
                        .definition
                        .as_ref()
                        .clone()
                        .try_map_scopes(|stage, _| ids.remove(&stage).ok_or(Error::Conflict))?;
                    definition.validate()?;
                    p.check_live()?;
                    Ok(rss_mdm_policy::pages::Preview {
                        definition: Box::new(definition),
                        scope_result: input.scope_result,
                    })
                })
            },
        )
        .await
    }
}
