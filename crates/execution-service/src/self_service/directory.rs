//! Bounded discovery and exact lookup share the same live qualification path.
use super::*;
use rss_mdm_query::{
    Parameters,
    directory::{Field, Kind, Query, Schema},
};

pub static SCHEMA: Schema = Schema {
    id: "self_service",
    keys: &["id"],
    default_limit: 64,
    max_limit: 64,
    fields: &[
        Field {
            name: "id",
            kind: Kind::Uuid,
            filter: true,
            sort: true,
            output: false,
        },
        Field {
            name: "toolName",
            kind: Kind::Text,
            filter: true,
            sort: true,
            output: false,
        },
        Field {
            name: "alias",
            kind: Kind::Text,
            filter: true,
            sort: true,
            output: false,
        },
        Field {
            name: "displayName",
            kind: Kind::Text,
            filter: true,
            sort: true,
            output: false,
        },
        Field {
            name: "category",
            kind: Kind::Text,
            filter: true,
            sort: true,
            output: false,
        },
        Field::output("capability"),
        Field::output("policyId"),
        Field::output("policyRevision"),
        Field::output("policyVersion"),
        Field::output("subject"),
        Field::output("selfService"),
        Field::output("task"),
    ],
};
fn column(field: &str) -> &'static str {
    match field {
        "id" => "id::text COLLATE \"C\"",
        "toolName" => "('policy_' || replace(id::text,'-','')) COLLATE \"C\"",
        "alias" => "(definition->>'alias') COLLATE \"C\"",
        "displayName" => {
            "(definition->'selfService'->'presentation'->>'displayName') COLLATE \"C\""
        }
        "category" => "(definition->'selfService'->'presentation'->>'category') COLLATE \"C\"",
        _ => unreachable!("checked field"),
    }
}
impl ExecutionService {
    pub async fn self_service_directory(
        &self,
        p: &DevicePrincipal,
        proof: Option<&AuthorizedPrincipal>,
        raw: &str,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        bind(p, proof, audit)?;
        let (parameters, context) =
            Parameters::parse_with_context(raw, &["source"]).map_err(|_| Error::Malformed)?;
        let source = match context.get("source").map(String::as_str) {
            Some("human") => wire::SelfServiceCaller::Human,
            Some("ai") => wire::SelfServiceCaller::Ai,
            _ => return Err(Error::Malformed),
        };
        let query = Query::new(&SCHEMA, parameters).map_err(|_| Error::Malformed)?;
        crate::transaction::inspect(&self.runtime, self.tenant, (self, p, proof, &query, audit), |ctx, tx| Box::pin(async move {
            let (service, p, proof, query, audit) = *ctx;
            storage::lock(tx, p.device()).await?;
            crate::actions::agent::principal(service, tx, p).await?;
            let subject = if let Some(proof) = proof {
                Some(crate::action_admission::current(tx, proof).await?.query_binding(proof)?)
            } else { None };
            let binding = query.binding(&(service.instance.as_str(), p.tenant().to_string(), p.device(), p.registration(), p.generation(), source, subject)).map_err(|_| Error::Malformed)?;
            let after = query.after(&service.cursor, &binding).map_err(|_| Error::Conflict)?;
            let mut sql = sqlx::QueryBuilder::new("SELECT jsonb_build_object('id',id,'toolName','policy_' || replace(id::text,'-',''),'alias',definition->>'alias','displayName',definition->'selfService'->'presentation'->>'displayName','category',definition->'selfService'->'presentation'->>'category') FROM mdm_policy.policies WHERE tenant_id=");
            sql.push_bind(tx.tenant_id().to_string()).push("::uuid AND state='enabled' AND definition->'selfService'->>'published'='true'");
            rss_mdm_query_postgres::append(&mut sql, query, after.as_ref(), column).map_err(|_| Error::Malformed)?;
            let rows: Vec<Value> = tx.with_connection(move |c| Box::pin(async move { sql.build_query_scalar().fetch_all(c).await })).await?;
            // Cursor advances over examined candidates, including invisible ones.
            let page = query.unprojected_page(rows, &service.cursor, &binding).map_err(|_| Error::Malformed)?;
            let now = storage::now(tx).await?;
            let mut items = Vec::new();
            for mut row in page.items {
                let id = stored(serde_json::from_value(row["id"].clone()))?;
                if let Some(item) = describe_in(service, tx, p, proof, source, id, now).await? {
                    row.as_object_mut().ok_or(Error::Malformed)?.extend(json(&item)?.as_object().ok_or(Error::Malformed)?.clone());
                    items.push(query.project(row).map_err(|_| Error::Malformed)?);
                }
            }
            if let Some(proof) = proof { proof.check_live()?; }
            audit.require_request_settlement();
            Ok(json!({"items":items,"nextCursor":page.next_cursor,"asOf":now}))
        })).await
    }
    pub async fn resolve_self_service(
        &self,
        p: &DevicePrincipal,
        proof: Option<&AuthorizedPrincipal>,
        input: &wire::SelfServiceResolve,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        bind(p, proof, audit)?;
        crate::transaction::inspect(
            &self.runtime,
            self.tenant,
            (self, p, proof, input, audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (service, p, proof, input, audit) = *ctx;
                    storage::lock(tx, p.device()).await?;
                    crate::actions::agent::principal(service, tx, p).await?;
                    let id = checked(
                        service
                            .policy_reader
                            .resolve_in(tx, &input.selector)
                            .await?,
                    )?
                    .ok_or(Error::NotFound)?;
                    let now = storage::now(tx).await?;
                    let item = describe_in(service, tx, p, proof, input.source, id, now)
                        .await?
                        .ok_or(Error::NotFound)?;
                    if let wire::CapabilitySelector::Alias { alias } = &input.selector
                        && item.capability.alias.as_ref() != Some(alias)
                    {
                        return Err(Error::NotFound.into());
                    }
                    if let Some(proof) = proof {
                        proof.check_live()?;
                    }
                    audit.require_request_settlement();
                    json(&item)
                })
            },
        )
        .await
    }
}
async fn describe_in(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    p: &DevicePrincipal,
    proof: Option<&AuthorizedPrincipal>,
    source: wire::SelfServiceCaller,
    id: Uuid,
    now: i64,
) -> Result<Option<wire::SelfServiceDirectoryItem>> {
    let Some(policy) = crate::sources::storage::read_in(&service.policy_reader, tx, id).await?
    else {
        return Ok(None);
    };
    let Some(config) = &policy.definition.self_service else {
        return Ok(None);
    };
    if !policy.state.is_enabled()
        || !config.published
        || (source == wire::SelfServiceCaller::Ai && config.allow_ai != Some(true))
    {
        return Ok(None);
    }
    let Some(basis) = access::select(config, proof)? else {
        return Ok(None);
    };
    let Some(subject) = access::qualify_in(service, tx, config, &basis).await? else {
        return Ok(None);
    };
    let plan = db::load_source(
        &service.policy_reader,
        tx,
        db::Source::Policy {
            version: policy.version,
        },
    )
    .await?;
    let Some(prepared) =
        prepare_in(service, tx, &plan, &target(p), Uuid::new_v4(), None, now).await?
    else {
        return Ok(None);
    };
    let (input_schema, output_schema) = match &plan {
        db::ScheduledPolicy::Script(script) => {
            let mut schema = script.frozen.definition.spec().parameters.clone();
            let inputs: Vec<_> = script
                .frozen
                .parameters
                .0
                .iter()
                .filter_map(|(name, source)| {
                    matches!(source, rss_mdm_policy::ParameterSource::Input {})
                        .then_some(name.clone())
                })
                .collect();
            if let Some(properties) = schema.get_mut("properties").and_then(Value::as_object_mut) {
                properties.retain(|name, _| inputs.contains(name));
            }
            schema["required"] = json!(inputs);
            (schema, script.frozen.definition.spec().output.clone())
        }
        db::ScheduledPolicy::Software(_) => (
            json!({"type":"object","properties":{},"additionalProperties":false}),
            serde_json::to_value(schemars::schema_for!(wire::SelfServiceSoftwareEffect))
                .map_err(|_| Error::Malformed)?,
        ),
        _ => (
            json!({"type":"object","properties":{},"additionalProperties":false}),
            serde_json::to_value(schemars::schema_for!(wire::EnrollmentEntryOutcome))
                .map_err(|_| Error::Malformed)?,
        ),
    };
    let mut metadata = metadata(config)?;
    metadata.risk_level = effective_risk(&policy);
    Ok(Some(wire::SelfServiceDirectoryItem {
        capability: wire::CapabilityDescriptor {
            id,
            object_type: wire::CapabilityObject::Policy,
            tool_name: wire::policy_tool_name(id),
            alias: policy.definition.alias.clone(),
            scope: policy.definition.scope,
            instance: service.instance.clone(),
            tenant: checked_input(Uuid::parse_str(&p.tenant().to_string()))?,
            revision: policy.revision as u64,
            version: policy.version,
            operations: vec![wire::CapabilityOperation::Invoke],
            input_schema,
            output_schema,
        },
        policy_id: id,
        policy_revision: policy.revision as u64,
        policy_version: policy.version,
        subject,
        self_service: metadata,
        task: prepared.task,
    }))
}
