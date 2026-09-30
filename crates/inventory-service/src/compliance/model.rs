use super::*;
pub use rss_mdm_compliance::GroupInput;
use serde::{Deserialize, Serialize};
pub type Definition = rss_mdm_compliance::Definition<crate::assets::Criteria>;
pub type Input = rss_mdm_compliance::Input<crate::assets::Criteria>;
pub(super) type Rule = pg::Rule<crate::assets::Criteria>;
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
    let rule = crate::assets::rule(t, id, &definition.criteria, catalog)?;
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
        request: crate::operation::Operation<Definition>,
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
        page: HistoryPage,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Empty {}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryPage {
    pub cursor: Option<String>,
    pub from: Option<i64>,
    pub until: Option<i64>,
    pub limit: Option<usize>,
}
impl Command {
    pub fn operation(&self) -> Option<Uuid> {
        match self {
            Self::Put { request, .. } => Some(request.operation_id),
            Self::Recompute { request, .. } => Some(request.operation_id),
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
