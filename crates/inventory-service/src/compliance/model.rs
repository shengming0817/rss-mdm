use super::*;
pub use rss_mdm_compliance::GroupInput;
use serde::{Deserialize, Serialize};
pub type Definition = rss_mdm_compliance::Definition<crate::assets::InventoryCondition>;
pub type Input = rss_mdm_compliance::Input<crate::assets::InventoryCondition>;
pub(super) type Rule = pg::Rule<crate::assets::InventoryCondition>;
pub(super) fn validate_definition(
    definition: &Definition,
    t: TenantId,
    id: Uuid,
    catalog: &rss_mdm_inventory::Catalog,
) -> Result<Vec<String>> {
    checked_input(definition.validate())?;
    if checked_input(serde_json::to_vec(definition))?.len() > 65536 {
        return Err(Error::Malformed.into());
    }
    definition.criteria.validate()?;
    let rule = crate::assets::rule(t, id, &definition.criteria.criteria, catalog)?;
    let out: std::collections::BTreeSet<_> = rule.view().fields.keys().cloned().collect();
    out.into_iter()
        .map(|name| {
            let key = checked_input(rss_mdm_inventory::FieldKey::parse(&name))?;
            Ok(checked_input(catalog.path(key))?
                .root
                .key
                .as_str()
                .to_owned())
        })
        .collect()
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Command {
    Read {
        id: Uuid,
    },
    Version {
        id: Uuid,
        revision: i64,
    },
    Put {
        id: Uuid,
        request: Box<crate::operation::Operation<Definition>>,
    },
    Delete {
        id: Uuid,
        request: crate::operation::Operation<Empty>,
    },
    Recompute {
        id: Uuid,
        request: crate::operation::Operation<Empty>,
    },
    Task {
        id: Uuid,
        task: Uuid,
    },
    Current {
        device: String,
    },
    History {
        device: String,
        subject: String,
        page: HistoryQuery,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Empty {}
pub static HISTORY: rss_mdm_query::window::Schema = rss_mdm_query::window::Schema {
    id: "compliance_history",
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    order: "evaluated_at DESC, task DESC",
    context: &["from", "until"],
};
#[derive(Clone, Debug, Serialize)]
pub struct HistoryQuery {
    pub page: rss_mdm_query::window::Query,
    pub bounds: HistoryBounds,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub struct HistoryBounds {
    pub from: Option<i64>,
    pub until: Option<i64>,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryPosition {
    pub evaluated_at: i64,
    pub task: Uuid,
}
pub struct HistoryRow {
    pub position: HistoryPosition,
    pub document: String,
    pub failure: Option<String>,
}
impl HistoryQuery {
    pub fn parse(raw: &str) -> Result<Self> {
        let (page, context) = checked_input(HISTORY.parse(raw))?;
        let from = context
            .get("from")
            .map(|v| checked_input(v.parse::<i64>()))
            .transpose()?;
        let until = context
            .get("until")
            .map(|v| checked_input(v.parse::<i64>()))
            .transpose()?;
        if from.zip(until).is_some_and(|(a, b)| a > b) {
            return Err(Error::Malformed.into());
        }
        Ok(Self {
            page,
            bounds: HistoryBounds { from, until },
        })
    }
}
impl Command {
    pub fn operation(&self) -> Option<Uuid> {
        match self {
            Self::Put { request, .. } => Some(request.operation_id),
            Self::Delete { request, .. } | Self::Recompute { request, .. } => {
                Some(request.operation_id)
            }
            _ => None,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RuleView {
    pub id: Uuid,
    pub revision: i64,
    pub definition: Definition,
}
impl From<Rule> for RuleView {
    fn from(row: Rule) -> Self {
        Self {
            id: row.id,
            revision: row.revision,
            definition: row.definition,
        }
    }
}
