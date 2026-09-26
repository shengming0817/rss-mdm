use super::*;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Definition {
    pub name: String,
    pub severity: Severity,
    pub enabled: bool,
    pub platform: Platform,
    pub target: Target,
    pub criteria: crate::assets::Criteria,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Severity {
    Low,
    Medium,
    High,
    Critical,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Platform {
    All,
    Windows,
    Macos,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Target {
    All,
    Groups { ids: Vec<Uuid> },
}
impl Definition {
    pub(super) fn groups(&self) -> Vec<Uuid> {
        match &self.target {
            Target::All => vec![],
            Target::Groups { ids } => ids.clone(),
        }
    }
    pub(super) fn validate(&self, t: TenantId, id: Uuid) -> Result<Vec<String>> {
        if self.name.trim().is_empty()
            || self.name.chars().count() > 128
            || self.name.chars().any(char::is_control)
        {
            return Err(Error::Malformed.into());
        }
        if let Target::Groups { ids } = &self.target
            && (ids.is_empty()
                || ids.len() > 16
                || ids.iter().any(Uuid::is_nil)
                || ids.iter().collect::<std::collections::BTreeSet<_>>().len() != ids.len())
        {
            return Err(Error::Malformed.into());
        }
        if checked_input(serde_json::to_vec(self))?.len() > 65536 {
            return Err(Error::Malformed.into());
        }
        let rule = crate::assets::rule(t, id, &self.criteria)?;
        fn fields(
            c: &rss_mdm_group_postgres::core::Criteria,
            out: &mut std::collections::BTreeSet<String>,
        ) {
            use rss_mdm_group_postgres::core::CriteriaView;
            match c.view() {
                CriteriaView::Predicate(p) => {
                    out.insert(p.field.clone());
                }
                CriteriaView::And(cs) | CriteriaView::Or(cs) => {
                    for c in cs {
                        fields(c, out)
                    }
                }
            }
        }
        let mut out = std::collections::BTreeSet::new();
        fields(rule.view().criteria, &mut out);
        Ok(out.into_iter().collect())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GroupInput {
    pub id: Uuid,
    pub revision: i64,
    pub member_set: Option<Uuid>,
    pub member_version: i64,
    pub ready: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Input {
    pub rule: Uuid,
    pub revision: i64,
    pub definition: Definition,
    pub watermark: i64,
    pub evaluated_at: i64,
    pub groups: Vec<GroupInput>,
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Command {
    List {
        after: Option<Uuid>,
    },
    Read {
        id: Uuid,
    },
    Version {
        id: Uuid,
        revision: i64,
    },
    Put {
        id: Uuid,
        request: crate::http_operation::Operation<Definition>,
    },
    Recompute {
        id: Uuid,
        request: crate::http_operation::Operation<Empty>,
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
        page: HistoryPage,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Empty {}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct HistoryPage {
    pub cursor: Option<String>,
    pub from: Option<i64>,
    pub until: Option<i64>,
    pub limit: Option<usize>,
}
impl Command {
    pub(super) fn operation(&self) -> Option<Uuid> {
        match self {
            Self::Put { request, .. } => Some(request.operation_id),
            Self::Recompute { request, .. } => Some(request.operation_id),
            _ => None,
        }
    }
}
