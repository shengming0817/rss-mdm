use super::*;
pub type GroupInput = rss_mdm_compliance::GroupInput<rss_mdm_inventory::AssetCut>;
pub type Assessment = rss_mdm_compliance::Assessment<rss_mdm_inventory::AssetCut>;
use serde::{Deserialize, Serialize};
pub type Definition = rss_mdm_compliance::Definition<crate::assets::InventoryCondition>;
pub type Input =
    rss_mdm_compliance::Input<crate::assets::InventoryCondition, rss_mdm_inventory::AssetCut>;
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
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
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

#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleView {
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

#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Changed {
    pub id: Uuid,
    pub revision: i64,
    pub task: Option<Uuid>,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Deleted {
    pub id: Uuid,
    pub revision: i64,
    #[schemars(extend("const"=true))]
    pub deleted: bool,
}
#[derive(schemars::JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Accepted {
    pub task: Uuid,
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskView {
    pub task: Uuid,
    pub rule_id: Uuid,
    pub rule_version: i64,
    pub asset_cut: rss_mdm_inventory::AssetCut,
    pub phase: Phase,
    pub processed: i64,
    pub completed: bool,
    pub failure: Option<String>,
    pub diagnostic: Option<crate::tasks::TaskDiagnostic>,
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Queued,
    Evaluating,
    Published,
    Superseded,
    Failed,
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CurrentRule {
    pub rule_id: Uuid,
    pub rule_version: i64,
    pub status: rss_mdm_compliance::Current,
    pub current: Option<Assessment>,
    pub previous: Option<Assessment>,
}
#[derive(schemars::JsonSchema, Serialize)]
pub struct CurrentView {
    pub device: String,
    pub status: rss_mdm_compliance::Current,
    pub reason: Option<EmptyReason>,
    pub rules: Vec<CurrentRule>,
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EmptyReason {
    NoRules,
}
#[derive(schemars::JsonSchema, Serialize)]
pub struct HistoryEntry {
    #[serde(flatten)]
    pub assessment: Assessment,
    pub task: Uuid,
    pub disposition: Disposition,
}
#[derive(schemars::JsonSchema, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    Published,
    Superseded,
    Failed,
}
pub type History = rss_mdm_query::Page<HistoryEntry>;
#[derive(Serialize)]
#[serde(untagged)]
pub enum Reply {
    Rule(Box<RuleView>),
    Changed(Changed),
    Deleted(Deleted),
    Accepted(Accepted),
    Task(TaskView),
    Current(CurrentView),
    History(History),
}
impl Reply {
    pub(super) fn receipt(command: &Command, value: Value) -> Result<Self> {
        Ok(match command {
            Command::Put { .. } => Self::Changed(stored(serde_json::from_value(value))?),
            Command::Delete { .. } => Self::Deleted(stored(serde_json::from_value(value))?),
            Command::Recompute { .. } => Self::Accepted(stored(serde_json::from_value(value))?),
            _ => return Err(Error::Unavailable(Failure::ComplianceStorage).into()),
        })
    }
}
impl Reply {
    pub fn rule(self) -> std::result::Result<RuleView, Error> {
        if let Self::Rule(v) = self {
            Ok(*v)
        } else {
            Err(Error::Unavailable(Failure::ComplianceStorage))
        }
    }
}
impl Reply {
    pub fn changed(self) -> std::result::Result<Changed, Error> {
        if let Self::Changed(v) = self {
            Ok(v)
        } else {
            Err(Error::Unavailable(Failure::ComplianceStorage))
        }
    }
}
impl Reply {
    pub fn deleted(self) -> std::result::Result<Deleted, Error> {
        if let Self::Deleted(v) = self {
            Ok(v)
        } else {
            Err(Error::Unavailable(Failure::ComplianceStorage))
        }
    }
}
impl Reply {
    pub fn accepted(self) -> std::result::Result<Accepted, Error> {
        if let Self::Accepted(v) = self {
            Ok(v)
        } else {
            Err(Error::Unavailable(Failure::ComplianceStorage))
        }
    }
}
impl Reply {
    pub fn task(self) -> std::result::Result<TaskView, Error> {
        if let Self::Task(v) = self {
            Ok(v)
        } else {
            Err(Error::Unavailable(Failure::ComplianceStorage))
        }
    }
}
impl Reply {
    pub fn current(self) -> std::result::Result<CurrentView, Error> {
        if let Self::Current(v) = self {
            Ok(v)
        } else {
            Err(Error::Unavailable(Failure::ComplianceStorage))
        }
    }
}
impl Reply {
    pub fn history(self) -> std::result::Result<History, Error> {
        if let Self::History(v) = self {
            Ok(v)
        } else {
            Err(Error::Unavailable(Failure::ComplianceStorage))
        }
    }
}
