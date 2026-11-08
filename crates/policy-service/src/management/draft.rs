//! Policy owns the editing contract; execution keeps opaque Scope identities.
use super::*;
use rss_mdm_scope::ScopeDefinition;
use rss_mdm_scope_postgres::ScopeOwner;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(
    tag = "action",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Change {
    Put {
        #[serde(deserialize_with = "rss_mdm_policy::definition_input")]
        #[schemars(schema_with = "rss_mdm_policy::definition_input_schema::<ScopeDefinition>")]
        definition: Box<rss_mdm_policy::Definition<ScopeDefinition>>,
        enabled: bool,
    },
    Enable,
    Disable,
    #[serde(skip_deserializing)]
    #[schemars(skip)]
    Archive,
}
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct View {
    pub id: Uuid,
    pub revision: i64,
    pub version: i64,
    pub version_id: Uuid,
    pub state: rss_mdm_policy::State,
    pub definition: rss_mdm_policy::Definition<ScopeDefinition>,
    pub scopes: Vec<rss_mdm_scope_service::wire::ScopeRead>,
}
impl Change {
    /// Scope placeholders are request-local and never persisted or returned.
    pub(crate) fn checked_shape(&self) -> std::result::Result<rss_mdm_policy::Change, Error> {
        Ok(match self {
            Self::Put {
                definition,
                enabled,
            } => {
                if serde_json::to_vec(definition)
                    .map_err(|_| Error::Malformed)?
                    .len()
                    > 1024 * 1024
                {
                    return Err(Error::Malformed);
                }
                let mut next = 1_u128;
                let definition = (**definition).clone().try_map_scopes(|_, _| {
                    let id = Uuid::from_u128(next);
                    next += 1;
                    Ok::<_, Error>(id)
                })?;
                definition.validate()?;
                rss_mdm_policy::Change::Put {
                    definition: Box::new(definition),
                    enabled: *enabled,
                }
            }
            Self::Enable => rss_mdm_policy::Change::Enable,
            Self::Disable => rss_mdm_policy::Change::Disable,
            Self::Archive => rss_mdm_policy::Change::Archive,
        })
    }
}
pub(crate) fn scope_refs(definition: &rss_mdm_policy::Definition) -> Vec<(Option<Uuid>, Uuid)> {
    let mut refs = vec![(None, definition.scope)];
    if let Action::Software { rollout, .. } = &definition.action {
        refs.extend(rollout.stages.iter().map(|s| (Some(s.id), s.scope)));
    }
    refs
}
impl Policies {
    pub(crate) async fn bind_change_in(
        &self,
        tx: &mut PgTransaction<'_>,
        proof: &AuthorizedPrincipal,
        id: Uuid,
        old: Option<&Policy>,
        input: &Change,
    ) -> Result<rss_mdm_policy::Change> {
        let Change::Put {
            definition,
            enabled,
        } = input
        else {
            return Ok(input.checked_shape()?);
        };
        let previous = old
            .map(|p| scope_refs(&p.definition))
            .unwrap_or_default()
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        let mut children = Vec::new();
        let definition = (**definition).clone().try_map_scopes(|stage, definition| {
            let scope = previous.get(&stage).copied().unwrap_or_else(Uuid::new_v4);
            children.push((scope, ScopeOwner { policy: id, stage }, definition));
            Ok::<_, Error>(scope)
        })?;
        definition.validate()?;
        let mut locks: Vec<_> = children
            .iter()
            .map(|c| c.0)
            .chain(previous.values().copied())
            .collect();
        locks.sort_unstable();
        locks.dedup();
        self.scopes.lock_owned_in(tx, &locks).await?;
        children.sort_by_key(|c| c.0);
        for (scope, owner, definition) in children {
            self.scopes
                .save_owned_in(tx, proof, owner, scope, &definition)
                .await?;
        }
        Ok(rss_mdm_policy::Change::Put {
            definition: Box::new(definition),
            enabled: *enabled,
        })
    }
    pub(crate) async fn retire_children_in(
        &self,
        tx: &mut PgTransaction<'_>,
        old: Option<&Policy>,
        policy: &Policy,
    ) -> Result<()> {
        let Some(old) = old else {
            return Ok(());
        };
        let current: BTreeMap<_, _> = if policy.state == rss_mdm_policy::State::Archived {
            BTreeMap::new()
        } else {
            scope_refs(&policy.definition).into_iter().collect()
        };
        let mut retired = scope_refs(&old.definition)
            .into_iter()
            .filter(|(stage, _)| !current.contains_key(stage))
            .collect::<Vec<_>>();
        retired.sort_by_key(|r| r.1);
        for (stage, _) in retired {
            self.scopes
                .retire_owned_in(
                    tx,
                    ScopeOwner {
                        policy: policy.id,
                        stage,
                    },
                )
                .await?;
        }
        Ok(())
    }
    pub(crate) async fn view_in(
        &self,
        tx: &mut PgTransaction<'_>,
        proof: &AuthorizedPrincipal,
        policy: &Policy,
    ) -> Result<View> {
        let mut scopes = Vec::new();
        let mut definitions = BTreeMap::new();
        for (stage, id) in scope_refs(&policy.definition) {
            let child = self
                .scopes
                .read_owned_in(
                    tx,
                    ScopeOwner {
                        policy: policy.id,
                        stage,
                    },
                )
                .await?;
            if child.id != id {
                return Err(Error::Conflict.into());
            }
            self.scopes
                .authorize_definition_in(tx, proof, &child.definition)
                .await?;
            definitions.insert(stage, child.definition.clone());
            scopes.push(child);
        }
        let definition = policy
            .definition
            .clone()
            .try_map_scopes(|stage, _| definitions.remove(&stage).ok_or(Error::Conflict))?;
        Ok(View {
            id: policy.id,
            revision: policy.revision,
            version: policy.number,
            version_id: policy.version,
            state: policy.state,
            definition,
            scopes,
        })
    }
}
