use super::*;
use rss_mdm_group_postgres::{self as pg, core as g};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::collections::{BTreeMap, BTreeSet};
const FIELDS: [&str; 2] = ["device.model", "device.os.version"];
fn predicate(field: &str, op: g::Op, value: g::Value) -> Result<g::Criteria> {
    input(g::Criteria::predicate(g::Predicate {
        field: field.into(),
        op,
        operand: Some(g::Operand { value, unit: None }),
    }))
}
fn criteria(c: &Criteria) -> Result<g::Criteria> {
    let scalar = |value: &str| g::Value::Scalar(g::Scalar::String(value.into()));
    let set = |values: &BTreeSet<String>| g::Value::Set {
        element: g::ScalarType::String,
        values: values.iter().cloned().map(g::Scalar::String).collect(),
    };
    match c {
        Criteria::Eq { field, value } => predicate(field, g::Op::Eq, scalar(value)),
        Criteria::Ne { field, value } => predicate(field, g::Op::Ne, scalar(value)),
        Criteria::In { field, values } => predicate(field, g::Op::In, set(values)),
        Criteria::NotIn { field, values } => predicate(field, g::Op::NotIn, set(values)),
        Criteria::Contains { field, value } => predicate(field, g::Op::Contains, scalar(value)),
        Criteria::NotContains { field, value } => {
            predicate(field, g::Op::NotContains, scalar(value))
        }
        Criteria::And { children } => input(g::Criteria::and(
            children.iter().map(criteria).collect::<Result<_>>()?,
        )),
        Criteria::Or { children } => input(g::Criteria::or(
            children.iter().map(criteria).collect::<Result<_>>()?,
        )),
    }
}
fn rule(tenant: TenantId, id: Uuid, c: &Criteria) -> Result<g::Rule> {
    input(g::Rule::new(
        tenant,
        id.to_string(),
        "inventory-v1",
        FIELDS
            .iter()
            .map(|key| g::Field {
                key: (*key).into(),
                kind: g::FieldType::Scalar(g::ScalarType::String),
                unit: None,
                operations: BTreeSet::from([
                    g::Op::Eq,
                    g::Op::Ne,
                    g::Op::In,
                    g::Op::NotIn,
                    g::Op::Contains,
                    g::Op::NotContains,
                ]),
                nullable: false,
            })
            .collect(),
        criteria(c)?,
    ))
}
impl Management {
    pub(super) async fn group_read(&self, tx: &mut PgTransaction<'_>, id: Uuid) -> Result<Value> {
        let id = input(pg::GroupId::parse(&id.to_string()))?;
        let group = checked(self.groups.lock_reference_target_in(tx, id).await?)?;
        let members = checked(self.groups.members_in(tx, id).await?)?;
        let criteria = if let Some(version) = &group.rule_version {
            let rule = self
                .groups
                .rule(id, version, deadline())
                .await
                .map_err(|_| Error::Unavailable(Failure::Runtime))?
                .ok_or(Error::NotFound)?;
            Some(criteria_view(rule.view().criteria)?)
        } else {
            None
        };
        Ok(
            json!({"group":group,"criteria":criteria,"members":members.iter().map(|m|m.id()).collect::<Vec<_>>()}),
        )
    }
    pub(super) async fn group_change(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        op: &Operation<GroupChange>,
        at: Timepoint,
    ) -> Result<Value> {
        let group = input(pg::GroupId::parse(&id.to_string()))?;
        let operation = input(pg::OperationId::parse(&op.operation_id.to_string()))?;
        let expected = || {
            input(pg::Revision::new(
                i64::try_from(op.expected_revision).map_err(|_| Error::Malformed)?,
            ))
        };
        let command = match &op.input {
            GroupChange::Create {
                name,
                description,
                criteria,
            } => {
                if op.expected_revision != 0 {
                    return Err(Error::Conflict.into());
                }
                pg::Command::Create {
                    group,
                    name: name.clone(),
                    description: description.clone(),
                    definition: match criteria {
                        None => pg::Definition::Static,
                        Some(c) => pg::Definition::Dynamic(Box::new(rule(
                            self.tenant,
                            op.operation_id,
                            c,
                        )?)),
                    },
                }
            }
            GroupChange::Edit { name, description } => pg::Command::Edit {
                group,
                expected: expected()?,
                name: name.clone(),
                description: description.clone(),
            },
            GroupChange::Rule { criteria } => pg::Command::SetRule {
                group,
                expected: expected()?,
                rule: rule(self.tenant, op.operation_id, criteria)?,
            },
            GroupChange::Members { add, remove } => {
                if add.len() + remove.len() > 10_000 {
                    return Err(Error::Malformed.into());
                }
                for id in add {
                    storage::device(tx, id).await?;
                }
                for id in remove {
                    input(rss_mdm_scope::DeviceId::new(self.tenant, id))?;
                }
                pg::Command::Members {
                    group,
                    expected: expected()?,
                    add: add.clone(),
                    remove: remove.clone(),
                }
            }
            GroupChange::Delete => {
                checked(self.groups.lock_reference_target_in(tx, group).await?)?;
                self.reject_group_reference(tx, id).await?;
                pg::Command::Delete {
                    group,
                    expected: expected()?,
                }
            }
            GroupChange::Recompute { snapshot } => {
                let current = checked(self.groups.lock_reference_target_in(tx, group).await?)?;
                let (facts, _) = self.assets(tx, at).await?;
                if &facts.version != snapshot {
                    return Err(Error::Conflict.into());
                }
                let request = pg::RecalculationRequest {
                    id: operation,
                    group,
                    expected: expected()?,
                    rule_version: current.rule_version.ok_or(Error::Conflict)?,
                    trigger: pg::Trigger::Manual,
                    snapshot: facts,
                    as_of: at,
                };
                checked(self.groups.start_recalculation_in(tx, &request).await?)?;
                let run = checked(self.groups.resume_in(tx, operation).await?)?;
                return match run.state {
                    pg::RunState::Completed(receipt) => json(&receipt),
                    _ => Err(Error::Conflict.into()),
                };
            }
        };
        json(&checked(
            self.groups.execute_in(tx, operation, at, &command).await?,
        )?)
    }
    pub(super) async fn group_preview(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        revision: u64,
        at: Timepoint,
    ) -> Result<Value> {
        let group = input(pg::GroupId::parse(&id.to_string()))?;
        let current = checked(self.groups.lock_reference_target_in(tx, group).await?)?;
        if current.revision.get() as u64 != revision {
            return Err(Error::Conflict.into());
        }
        let version = current.rule_version.ok_or(Error::Conflict)?;
        // Immutable rule reads can use a separate read transaction; the group lock
        // prevents its selected rule or members changing during this preview.
        let rule = self
            .groups
            .rule(group, &version, deadline())
            .await
            .map_err(|_| Error::Unavailable(Failure::Runtime))?
            .ok_or(Error::NotFound)?;
        let (facts, provenance) = self.assets(tx, at).await?;
        let evaluated = input(rule.evaluate(&facts, at))?;
        Ok(
            json!({"revision":revision,"snapshot":facts.version,"members":evaluated.objects.iter().filter(|o|o.decision==g::Decision::Match).map(|o|o.key.id()).collect::<Vec<_>>(),"assets":provenance,"decisions":evaluated.objects.iter().map(|o|json!({"device":o.key.id(),"decision":decision(o.decision),"explanations":o.explanations.iter().map(|e|json!({"path":e.path,"outcome":outcome(e.outcome)})).collect::<Vec<_>>()})).collect::<Vec<_>>()}),
        )
    }
    async fn assets(
        &self,
        tx: &mut PgTransaction<'_>,
        at: Timepoint,
    ) -> Result<(g::Snapshot, Value)> {
        let tenant = self.tenant.to_string();
        let rows=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT d.id,r.id::text AS registration,s.epoch::text,s.source FROM mdm_access.devices d JOIN mdm_access.registrations r ON (r.tenant_id,r.device)=(d.tenant_id,d.id) JOIN mdm_access.report_sources s ON (s.tenant_id,s.registration)=(r.tenant_id,r.id) WHERE d.tenant_id=$1::uuid AND r.state='active' AND s.enabled AND s.source='mdm.windows' ORDER BY d.id LIMIT 10001")
                .bind(tenant).fetch_all(c).await
        })).await?;
        if rows.len() > 10_000 {
            return Err(Error::Malformed.into());
        }
        let mut objects = Vec::new();
        let mut provenance = Vec::new();
        for row in rows {
            let device: String = row.try_get("id")?;
            let registration: String = row.try_get("registration")?;
            let epoch: String = row.try_get("epoch")?;
            let source: String = row.try_get("source")?;
            let scope = crate::device::scope(
                self.tenant,
                input(Uuid::parse_str(&registration))?,
                &source,
                input(Uuid::parse_str(&epoch))?,
            )?;
            let fields = tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        rss_mdm_inventory_postgres::read_in(c, &scope)
                            .await
                            .map_err(|_| {
                                sqlx::Error::Protocol("management inventory read failed".into())
                            })
                    })
                })
                .await?;
            let mut facts = BTreeMap::new();
            let mut evidence = Vec::new();
            for key in FIELDS {
                let row = fields.iter().find(|r| r.field == key);
                let (state, observed, batch) = if let Some(row) = row {
                    let value = row.value.clone();
                    let observed = row.observed_at;
                    let batch = row.batch_id.clone();
                    evidence.push(json!([key, value, batch, observed, row.received_at]));
                    (
                        g::FactState::Known(g::Value::Scalar(g::Scalar::String(value))),
                        input(Timepoint::try_from(observed))?,
                        batch,
                    )
                } else {
                    (g::FactState::Missing, at, "missing".into())
                };
                facts.insert(
                    key.into(),
                    g::Fact {
                        state,
                        source: source.clone(),
                        snapshot_id: batch,
                        observed_at: observed,
                        valid_until: None,
                    },
                );
            }
            provenance.push(json!([device, registration, epoch, evidence]));
            objects.push(g::ObjectSnapshot {
                key: input(g::ObjectKey::new(self.tenant, device))?,
                facts,
            });
        }
        let version = format!(
            "{:x}",
            Sha256::digest(input(serde_json::to_vec(&provenance))?)
        );
        Ok((
            g::Snapshot {
                tenant: self.tenant,
                id: "trusted-inventory".into(),
                version,
                dictionary_version: "inventory-v1".into(),
                complete: true,
                coverage: FIELDS.into_iter().map(String::from).collect(),
                objects,
            },
            json!(provenance),
        ))
    }
}

fn criteria_view(c: &g::Criteria) -> Result<Criteria> {
    match c.view() {
        g::CriteriaView::And(children) => Ok(Criteria::And {
            children: children.iter().map(criteria_view).collect::<Result<_>>()?,
        }),
        g::CriteriaView::Or(children) => Ok(Criteria::Or {
            children: children.iter().map(criteria_view).collect::<Result<_>>()?,
        }),
        g::CriteriaView::Predicate(p) => {
            let field = p.field.clone();
            match (&p.op, p.operand.as_ref().map(|o| &o.value)) {
                (g::Op::Eq, Some(g::Value::Scalar(g::Scalar::String(value)))) => Ok(Criteria::Eq {
                    field,
                    value: value.clone(),
                }),
                (g::Op::Ne, Some(g::Value::Scalar(g::Scalar::String(value)))) => Ok(Criteria::Ne {
                    field,
                    value: value.clone(),
                }),
                (g::Op::Contains, Some(g::Value::Scalar(g::Scalar::String(value)))) => {
                    Ok(Criteria::Contains {
                        field,
                        value: value.clone(),
                    })
                }
                (g::Op::NotContains, Some(g::Value::Scalar(g::Scalar::String(value)))) => {
                    Ok(Criteria::NotContains {
                        field,
                        value: value.clone(),
                    })
                }
                (g::Op::In | g::Op::NotIn, Some(g::Value::Set { values, .. })) => {
                    let values = values
                        .iter()
                        .map(|v| match v {
                            g::Scalar::String(s) => Ok(s.clone()),
                            _ => Err(Error::Unsupported.into()),
                        })
                        .collect::<Result<_>>()?;
                    Ok(if p.op == g::Op::In {
                        Criteria::In { field, values }
                    } else {
                        Criteria::NotIn { field, values }
                    })
                }
                _ => Err(Error::Unsupported.into()),
            }
        }
    }
}

fn decision(d: g::Decision) -> &'static str {
    match d {
        g::Decision::Match => "match",
        g::Decision::NoMatch => "no_match",
        g::Decision::Unknown => "unknown",
    }
}
fn outcome(o: g::Outcome) -> Value {
    match o {
        g::Outcome::Match => json!({"kind":"match"}),
        g::Outcome::NoMatch => json!({"kind":"no_match"}),
        g::Outcome::Unknown(r) => {
            json!({"kind":"unknown","reason":match r {g::UnknownReason::Null=>"null",g::UnknownReason::Missing=>"missing",g::UnknownReason::Stale=>"stale",g::UnknownReason::Unsupported=>"unsupported",g::UnknownReason::Future=>"future"}})
        }
    }
}
