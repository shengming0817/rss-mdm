//! Native query quality enters the existing CollectionRun/Observation path.
use super::storage::Run;
use crate::{Error, Result, action_contract::FrozenAgentCollection, checked_input, stored};
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_inventory::{CollectedValue, CollectionProgress, FieldKey, NativeValue};
use rss_transactional_messaging_postgres::PgTransaction;
pub async fn reserve(
    tx: &mut PgTransaction<'_>,
    frozen: &FrozenAgentCollection,
    run: &Run,
    spec: &wire::CollectionTaskSpec,
    now: i64,
) -> Result<()> {
    let tenant = tx.tenant_id();
    let registration = run.target.registration;
    let task = run.id;
    let attempt = run.state.attempt().ok_or(Error::Conflict)?;
    let definition = bind_definition(frozen, spec)?;
    tx.with_connection(move |c| {
        Box::pin(crate::collection::enterprise::start_in(
            c,
            tenant,
            registration,
            task,
            attempt,
            definition,
            now,
        ))
    })
    .await?;
    Ok(())
}
pub async fn finish(
    tx: &mut PgTransaction<'_>,
    frozen: &FrozenAgentCollection,
    run: &mut Run,
    result: &wire::NativeCollectionResult,
    allowed: bool,
    now: i64,
) -> Result<()> {
    let attempt = run.state.attempt().ok_or(Error::Conflict)?;
    let tenant = tx.tenant_id().to_string();
    let registration = run.target.registration;
    let (definition, execution) = tx.with_connection(move |c| Box::pin(async move {
        use sqlx::Row;
        let row = sqlx::query("SELECT c.attempts,a.offer FROM mdm_access.collection_runs c JOIN mdm_commands.action_attempts a ON(a.tenant_id,a.id)=(c.tenant_id,c.id) WHERE c.tenant_id=$1::uuid AND c.id=$2 AND c.registration=$3")
            .bind(tenant).bind(attempt).bind(registration).fetch_one(c).await?;
        let progress: CollectionProgress = serde_json::from_str(row.try_get("attempts")?).map_err(|_|sqlx::Error::Protocol("collection reservation".into()))?;
        let offer: wire::SignedTask = serde_json::from_value(row.try_get("offer")?).map_err(|_|sqlx::Error::Protocol("collection offer".into()))?;
        let wire::TaskPayload::Collection(spec) = offer.payload else { return Err(sqlx::Error::Protocol("collection payload".into())); };
        Ok((progress.definition().clone(), spec.execution))
    })).await?;
    let spec = frozen.definition.spec();
    if spec
        .mappings
        .values()
        .any(|m| m.counter_normalization.is_some())
    {
        return Err(Error::Unsupported.into());
    }
    checked_input(result.validate_for(&spec.plan, now))?;
    if result.queries.iter().any(|(id, answer)| {
        let query = &spec.plan.spec().queries[id].definition;
        matches!(query, wire::NativeQueryDefinition::System { .. })
            && !owners_match(answer, query, &execution)
    }) {
        return Err(Error::Malformed.into());
    }

    let observed_at = result
        .queries
        .values()
        .map(|q| q.collected_at)
        .max()
        .ok_or(Error::Malformed)?;
    let trusted = run
        .state
        .trusts_result(observed_at, spec.plan.spec().budget.timeout_seconds)
        && run
            .state
            .started_at
            .is_some_and(|at| result.queries.values().all(|q| q.collected_at >= at));
    let mut values = std::collections::BTreeMap::new();
    for (name, binding) in &spec.mappings {
        let key = stored(FieldKey::parse(name))?;
        let field = stored(definition.field(key))?;
        let query = &spec.plan.spec().queries[&binding.query];
        let answer = &result.queries[&binding.query];
        let complete =
            answer.complete_for(query, now) && owners_match(answer, &query.definition, &execution);
        let missing = serde_json::to_vec(answer)
            .is_ok_and(|v| v.len() <= query.budget.output_bytes as usize)
            && answer.enumeration_complete
            && answer.rows.is_empty()
            && answer.row_count == 0
            && query.cardinality == wire::NativeCardinality::ExactlyOne
            && matches!(
                answer.status,
                wire::NativeQueryStatus::Missing | wire::NativeQueryStatus::Complete
            );
        let value = if !trusted {
            NativeValue::Failed
        } else if complete {
            let raw = match query.cardinality {
                wire::NativeCardinality::ExactlyOne => serde_json::to_value(&answer.rows[0]),
                wire::NativeCardinality::List => serde_json::to_value(&answer.rows),
            };
            rss_mdm_inventory_service::collection::native::mapped_value(
                field,
                &binding.mapping,
                &stored(raw)?,
            )
        } else if missing {
            NativeValue::Missing
        } else {
            match answer.status {
                wire::NativeQueryStatus::Unsupported => {
                    NativeValue::Value(CollectedValue::Unsupported)
                }
                wire::NativeQueryStatus::Invalid | wire::NativeQueryStatus::Complete => {
                    NativeValue::Invalid
                }
                wire::NativeQueryStatus::Missing => NativeValue::Missing,
                _ => NativeValue::Failed,
            }
        };
        let value = if trusted && (complete || missing) {
            apply_missing(value, binding.missing, field.nullable)
        } else {
            value
        };
        values.insert(key, value);
    }
    let mut progress = stored(CollectionProgress::native(
        definition,
        values,
        result.collected_at,
    ))?;
    for (name, binding) in &frozen.definition.spec().mappings {
        let answer = &result.queries[&binding.query];
        let query = &frozen.definition.spec().plan.spec().queries[&binding.query];
        let reason = if !trusted {
            "untrusted"
        } else if !owners_match(answer, &query.definition, &execution) {
            "owner_mismatch"
        } else {
            match answer.status {
                wire::NativeQueryStatus::Complete if !answer.complete_for(query, now) => {
                    "incomplete"
                }
                wire::NativeQueryStatus::Complete => "complete",
                wire::NativeQueryStatus::Failed => "failed",
                wire::NativeQueryStatus::Partial => "partial",
                wire::NativeQueryStatus::NotScanned => "not_scanned",
                wire::NativeQueryStatus::SourceUnavailable => "source_unavailable",
                wire::NativeQueryStatus::UserAbsent => "user_absent",
                wire::NativeQueryStatus::StoreUnavailable => "store_unavailable",
                wire::NativeQueryStatus::Unsupported => "unsupported",
                wire::NativeQueryStatus::Denied => "denied",
                wire::NativeQueryStatus::Timeout => "timeout",
                wire::NativeQueryStatus::Truncated => "truncated",
                wire::NativeQueryStatus::Missing => "missing",
                wire::NativeQueryStatus::Invalid => "invalid",
            }
        };
        stored(progress.reason(stored(rss_mdm_inventory::FieldKey::parse(name))?, reason))?;
    }
    let tenant = tx.tenant_id();
    let attempt = run.state.attempt().ok_or(Error::Conflict)?;
    let report = crate::collection::enterprise::Report {
        registration: run.target.registration,
        task: run.id,
        attempt,
        progress,
        now,
        observed_at,
        trusted,
        project: allowed && trusted,
    };
    tx.with_connection(move |c| {
        Box::pin(crate::collection::enterprise::accept_in(c, tenant, report))
    })
    .await?;
    // Both inline and chunked input retain the same recoverable canonical evidence.
    super::output::retain_native(tx, run, result).await?;
    run.state.result(attempt, true)?;
    use sha2::{Digest, Sha256};
    let bytes = stored(serde_json::to_vec(result))?;
    let queries:std::collections::BTreeMap<_,_>=result.queries.iter().map(|(id,q)|(id,serde_json::json!({"queryDigest":q.query_digest,"collectedAt":q.collected_at,"status":q.status,"enumerationComplete":q.enumeration_complete,"rowCount":q.row_count}))).collect();
    run.result = Some(
        serde_json::json!({"native":if bytes.len()<=256*1024{stored(serde_json::to_value(result))?}else{serde_json::Value::Null},"queries":queries,"planDigest":result.plan_digest,"outputReference":{"bytes":bytes.len(),"sha256":format!("{:x}",Sha256::digest(&bytes))},"trusted":trusted,"receivedAt":now}),
    );
    Ok(())
}

fn apply_missing(
    value: NativeValue,
    policy: rss_mdm_agent_wire::runtime::NativeMissing,
    nullable: bool,
) -> NativeValue {
    if !matches!(value, NativeValue::Missing) {
        return value;
    }
    match policy {
        rss_mdm_agent_wire::runtime::NativeMissing::Missing => NativeValue::Missing,
        rss_mdm_agent_wire::runtime::NativeMissing::Null if nullable => {
            NativeValue::Value(CollectedValue::Null)
        }
        rss_mdm_agent_wire::runtime::NativeMissing::Delete => {
            NativeValue::Value(CollectedValue::Deleted)
        }
        _ => NativeValue::Invalid,
    }
}

fn bind_definition(
    frozen: &FrozenAgentCollection,
    spec: &wire::CollectionTaskSpec,
) -> Result<rss_mdm_inventory::CollectionDefinition> {
    use rss_mdm_inventory::{CollectionDefinition, CollectionField, Source};
    use sha2::{Digest, Sha256};
    checked_input(spec.execution.validate(&spec.plan))?;
    let fields = frozen
        .fields
        .iter()
        .map(rss_mdm_inventory_service::collection::wire::to_wire_field)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| Error::Malformed)?;
    if spec.fields != fields
        || spec.mappings != frozen.definition.spec().mappings
        || spec.plan != frozen.definition.spec().plan
        || spec.resource_digest != frozen.resource_digest
        || spec.resource != frozen.resource
    {
        return Err(Error::Conflict.into());
    }
    let uid = match &spec.execution.target {
        wire::SoftwareExecutionTarget::Device => None,
        wire::SoftwareExecutionTarget::User { identity, .. } => Some(identity.clone()),
    };
    let identity = stored(serde_json::to_vec(&(
        &frozen.resource.id,
        &frozen.resource.variant,
        uid,
        &spec.execution.generated_uid,
    )))?;
    let dataset = format!("resource.{:x}", Sha256::digest(identity));
    let version = format!("{:x}", Sha256::digest(frozen.resource_digest));
    let fields = frozen
        .fields
        .iter()
        .map(|field| {
            let mapping = frozen
                .definition
                .spec()
                .mappings
                .get(field.key.as_str())
                .ok_or(Error::Malformed)?;
            let query = &spec.plan.spec().queries[&mapping.query];
            Ok(CollectionField {
                definition: field.clone(),
                scope: field_scope(&query.definition, &spec.execution)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    checked_input(CollectionDefinition::new(
        &dataset,
        version,
        Source::AgentNative,
        fields,
    ))
}
fn field_scope(
    query: &wire::NativeQueryDefinition,
    execution: &wire::NativeExecutionBinding,
) -> Result<rss_mdm_inventory::CollectionScope> {
    use rss_mdm_inventory::{ApplicationRoot as R, BrewPackage as P, CollectionScope as S};
    let uid = || match &execution.target {
        wire::SoftwareExecutionTarget::User { identity, .. } => identity
            .parse::<u32>()
            .ok()
            .filter(|u| *u > 0)
            .ok_or(Error::Malformed),
        _ => Err(Error::Malformed),
    };
    let scope = match query {
        wire::NativeQueryDefinition::MacosApplications { root, .. } => match root {
            wire::MacosApplicationRoot::LocalApplications => S::MacosApplications {
                root: R::Local,
                uid: None,
            },
            wire::MacosApplicationRoot::SystemApplications => S::MacosApplications {
                root: R::System,
                uid: None,
            },
            wire::MacosApplicationRoot::UserApplications => S::MacosApplications {
                root: R::User,
                uid: Some(uid()?),
            },
        },
        wire::NativeQueryDefinition::MacosBrew {
            prefix,
            package,
            taps,
        } => S::MacosBrew {
            uid: uid()?,
            prefix: prefix.clone(),
            package: match package {
                wire::MacosBrewPackage::Formula => P::Formula,
                wire::MacosBrewPackage::Cask => P::Cask,
            },
            taps: taps.clone(),
        },
        wire::NativeQueryDefinition::System { query } => {
            use wire::NativeSystemQuery as Q;
            let platform = match query.platform() {
                wire::TaskPlatform::Windows => rss_mdm_inventory::Platform::Windows,
                wire::TaskPlatform::Macos => rss_mdm_inventory::Platform::Macos,
            };
            let owner = || -> Result<rss_mdm_inventory::LocalAccountIdentity> {
                let wire::SoftwareExecutionTarget::User { identity, .. } = &execution.target else {
                    return Err(Error::Malformed.into());
                };
                Ok(match platform {
                    rss_mdm_inventory::Platform::Windows => {
                        rss_mdm_inventory::LocalAccountIdentity::Windows {
                            sid: identity.clone(),
                        }
                    }
                    rss_mdm_inventory::Platform::Macos => {
                        rss_mdm_inventory::LocalAccountIdentity::Macos {
                            uid: uid()?,
                            generated_uid: execution
                                .generated_uid
                                .clone()
                                .ok_or(Error::Malformed)?,
                        }
                    }
                })
            };
            match query {
                Q::WindowsCertificates { .. } | Q::MacosCertificates { .. } => {
                    S::NativeCertificates {
                        platform,
                        owner: if query.execution_identity()
                            == wire::ExecutionIdentity::LoggedInUser
                        {
                            Some(owner()?)
                        } else {
                            None
                        },
                        store: query.certificate_store().ok_or(Error::Malformed)?.into(),
                    }
                }
                Q::WindowsAccounts { selection, .. } | Q::MacosAccounts { selection, .. } => {
                    S::NativeAccounts {
                        platform,
                        identities: match selection {
                            wire::AccountSelection::Local => Default::default(),
                            wire::AccountSelection::Selected { identities } => identities.clone(),
                        },
                    }
                }
                Q::WindowsApplication { .. } | Q::MacosApplication { .. } => S::NativeApplication {
                    platform,
                    identity: stored(serde_json::to_string(query))?,
                    owner: if query.execution_identity() == wire::ExecutionIdentity::LoggedInUser {
                        Some(owner()?)
                    } else {
                        None
                    },
                },
                Q::MacosSecurity {
                    section: wire::MacosSecuritySection::SecureToken,
                } => S::NativeUser { owner: owner()? },
                Q::WindowsBitlocker
                | Q::WindowsFirewall
                | Q::WindowsDefender
                | Q::WindowsSecureBoot
                | Q::WindowsJoin
                | Q::WindowsUpdates { .. }
                | Q::MacosUpdates { .. }
                | Q::MacosSecurity { .. } => S::Device,
            }
        }
        wire::NativeQueryDefinition::WindowsWmi { .. }
        | wire::NativeQueryDefinition::WindowsRegistry { .. }
        | wire::NativeQueryDefinition::WindowsCpu
        | wire::NativeQueryDefinition::WindowsSoftware
        | wire::NativeQueryDefinition::WindowsNetwork
        | wire::NativeQueryDefinition::WindowsBattery
        | wire::NativeQueryDefinition::MacosHardware { .. }
        | wire::NativeQueryDefinition::MacosPkgReceipts {}
        | wire::NativeQueryDefinition::WindowsPerformance { .. }
        | wire::NativeQueryDefinition::MacosPerformance { .. } => S::Device,
    };
    checked_input(scope.validate_executable())?;
    Ok(scope)
}
fn owners_match(
    result: &wire::NativeQueryResult,
    query: &wire::NativeQueryDefinition,
    execution: &wire::NativeExecutionBinding,
) -> bool {
    if let wire::NativeQueryDefinition::System { query } = query {
        if query.execution_identity() != wire::ExecutionIdentity::LoggedInUser {
            return true;
        }
        let wire::SoftwareExecutionTarget::User { identity, .. } = &execution.target else {
            return false;
        };
        // Application rows bind their declared application identity, not an invented owner column.
        if matches!(query, wire::NativeSystemQuery::MacosApplication { .. }) {
            return true;
        }
        let owner = match query.platform() {
            wire::TaskPlatform::Windows => Some(identity.as_str()),
            wire::TaskPlatform::Macos => execution.generated_uid.as_deref(),
        };
        return owner.is_some()
            && result
                .rows
                .iter()
                .all(|r| r.get("owner").and_then(|v| v.as_str()) == owner);
    }
    let user = matches!(
        query,
        wire::NativeQueryDefinition::MacosApplications {
            root: wire::MacosApplicationRoot::UserApplications,
            ..
        } | wire::NativeQueryDefinition::MacosBrew { .. }
    );
    if !user {
        return true;
    }
    let wire::SoftwareExecutionTarget::User { identity, .. } = &execution.target else {
        return false;
    };
    result
        .rows
        .iter()
        .all(|row| row.get("owner").and_then(|v| v.as_str()) == Some(identity.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn user_field_scope_is_stable_across_sessions_and_disjoint_across_users_and_recipes() {
        use wire::{ExecutionIdentity, NativeQueryDefinition as Q, SoftwareExecutionTarget as T};
        let binding = |uid: &str| wire::NativeExecutionBinding {
            generated_uid: Some("00000000-0000-0000-0000-000000000501".into()),
            identity: ExecutionIdentity::LoggedInUser,
            context_revision: 1,
            target: T::User {
                identity: uid.into(),
                session_id: uuid::Uuid::new_v4(),
            },
        };
        let query = Q::MacosApplications {
            root: wire::MacosApplicationRoot::UserApplications,
            max_depth: 4,
        };
        let first = binding("501");
        let mut another_session = binding("501");
        another_session.context_revision = 2;
        assert_eq!(
            field_scope(&query, &first).unwrap(),
            field_scope(&query, &another_session).unwrap()
        );
        assert_ne!(
            field_scope(&query, &first).unwrap(),
            field_scope(&query, &binding("502")).unwrap()
        );
        assert!(field_scope(&query, &binding("0")).is_err());
        let brew = |prefix: &str, package| Q::MacosBrew {
            prefix: prefix.into(),
            package,
            taps: Default::default(),
        };
        let formula = field_scope(
            &brew("/opt/homebrew", wire::MacosBrewPackage::Formula),
            &first,
        )
        .unwrap();
        assert_ne!(
            formula,
            field_scope(&brew("/usr/local", wire::MacosBrewPackage::Formula), &first).unwrap()
        );
        assert_ne!(
            formula,
            field_scope(&brew("/opt/homebrew", wire::MacosBrewPackage::Cask), &first).unwrap()
        );
        assert_ne!(formula, field_scope(&query, &first).unwrap());
    }
    #[test]
    fn explicit_absence_policy_does_not_promote_errors() {
        use rss_mdm_agent_wire::runtime::NativeMissing as M;
        assert!(matches!(
            apply_missing(NativeValue::Missing, M::Delete, false),
            NativeValue::Value(CollectedValue::Deleted)
        ));
        assert!(matches!(
            apply_missing(NativeValue::Missing, M::Null, true),
            NativeValue::Value(CollectedValue::Null)
        ));
        assert!(matches!(
            apply_missing(NativeValue::Missing, M::Null, false),
            NativeValue::Invalid
        ));
        assert!(matches!(
            apply_missing(NativeValue::Failed, M::Delete, false),
            NativeValue::Failed
        ));
        assert!(matches!(
            apply_missing(NativeValue::Invalid, M::Null, true),
            NativeValue::Invalid
        ));
    }
}
