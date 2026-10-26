use super::*;
use rss_mdm_group_postgres::core as g;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Criteria {
    Predicate {
        field: assets::FieldKey,
        op: assets::Operator,
        #[serde(default)]
        value: Option<assets::Scalar>,
        #[serde(default)]
        values: Option<Vec<assets::Scalar>>,
    },
    Group {
        #[serde(rename = "groupId")]
        group_id: Uuid,
        op: MembershipOp,
    },
    And {
        children: Vec<Criteria>,
    },
    Or {
        children: Vec<Criteria>,
    },
}
impl Criteria {
    pub fn references_groups(&self) -> bool {
        match self {
            Self::Group { .. } => true,
            Self::And { children } | Self::Or { children } => {
                children.iter().any(Self::references_groups)
            }
            Self::Predicate { .. } => false,
        }
    }
}

#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipOp {
    MemberOf,
    NotMemberOf,
}
pub type Condition = assets::InventoryCondition<Criteria>;

pub fn rule(
    tenant: TenantId,
    version: Uuid,
    c: &Criteria,
    catalog: &rss_mdm_inventory::Catalog,
) -> Result<g::Rule> {
    fn compile(
        c: &Criteria,
        catalog: &rss_mdm_inventory::Catalog,
        fields: &mut BTreeMap<String, g::Field>,
        depth: usize,
        nodes: &mut usize,
    ) -> Result<g::Criteria> {
        *nodes += 1;
        if depth > g::limits::DEPTH || *nodes > g::limits::NODES {
            return Err(Error::Malformed.into());
        }
        match c {
            Criteria::Predicate {
                field,
                op,
                value,
                values,
            } => assets::filter::criteria(
                &assets::Criteria::Predicate {
                    field: *field,
                    op: *op,
                    value: value.clone(),
                    values: values.clone(),
                },
                catalog,
                fields,
                depth,
                &mut 0,
            ),
            Criteria::Group { group_id, op } => {
                if group_id.is_nil() {
                    return Err(Error::Malformed.into());
                }
                checked_input(g::Criteria::membership(
                    group_id.to_string(),
                    matches!(op, MembershipOp::NotMemberOf),
                ))
            }
            Criteria::And { children } | Criteria::Or { children } => {
                if children.len() > g::limits::NODES {
                    return Err(Error::Malformed.into());
                }
                let children = children
                    .iter()
                    .map(|c| compile(c, catalog, fields, depth + 1, nodes))
                    .collect::<Result<Vec<_>>>()?;
                checked_input(if matches!(c, Criteria::And { .. }) {
                    g::Criteria::and(children)
                } else {
                    g::Criteria::or(children)
                })
            }
        }
    }
    let mut fields = BTreeMap::new();
    let criteria = compile(c, catalog, &mut fields, 1, &mut 0)?;
    checked_input(g::Rule::new(
        tenant,
        version.to_string(),
        rss_mdm_inventory::DICTIONARY,
        fields.into_values().collect(),
        criteria,
    ))
}
pub fn view(c: &g::Criteria) -> Result<Criteria> {
    Ok(match c.view() {
        g::CriteriaView::Membership { group, negated } => Criteria::Group {
            group_id: checked_input(Uuid::parse_str(group))?,
            op: if negated {
                MembershipOp::NotMemberOf
            } else {
                MembershipOp::MemberOf
            },
        },
        g::CriteriaView::And(cs) => Criteria::And {
            children: cs.iter().map(view).collect::<Result<_>>()?,
        },
        g::CriteriaView::Or(cs) => Criteria::Or {
            children: cs.iter().map(view).collect::<Result<_>>()?,
        },
        g::CriteriaView::Predicate(_) => match assets::criteria_view(c)? {
            assets::Criteria::Predicate {
                field,
                op,
                value,
                values,
            } => Criteria::Predicate {
                field,
                op,
                value,
                values,
            },
            _ => return Err(Error::Conflict.into()),
        },
    })
}
