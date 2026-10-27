use crate::Error;
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_registration_service::DevicePrincipal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub enum Reader<'a> {
    Management {
        proof: &'a AuthorizedPrincipal,
        device: &'a str,
    },
    Agent {
        device: &'a DevicePrincipal,
        user: Option<&'a AuthorizedPrincipal>,
    },
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Query {
    pub view: Option<String>,
    pub related: Option<String>,
    pub from: Option<i64>,
    pub until: Option<i64>,
    pub source: Option<String>,
    pub kind: Option<String>,
    pub status: Option<String>,
    pub policy: Option<Uuid>,
    pub request: Option<Uuid>,
    pub batch: Option<Uuid>,
    pub task: Option<Uuid>,
    pub operation: Option<Uuid>,
    pub cursor: Option<String>,
    pub limit: Option<usize>,
}
pub static ACTIVITIES: rss_mdm_query::window::Schema = rss_mdm_query::window::Schema {
    id: "management_activities",
    default_limit: 50,
    max_limit: 200,
    order: "recordedAt DESC, id DESC",
    context: &[
        "from",
        "until",
        "source",
        "kind",
        "status",
        "policy",
        "request",
        "batch",
        "task",
        "operation",
        "view",
        "related",
    ],
};
impl Query {
    pub fn parse(raw: &str) -> Result<Self, Error> {
        let (page, context) = ACTIVITIES.parse(raw).map_err(|_| Error::Malformed)?;
        let mut values = serde_json::Map::new();
        for (key, value) in context {
            let value = if matches!(key.as_str(), "from" | "until") {
                serde_json::json!(value.parse::<i64>().map_err(|_| Error::Malformed)?)
            } else {
                serde_json::Value::String(value)
            };
            values.insert(key, value);
        }
        values.insert("limit".into(), serde_json::json!(page.limit()));
        values.insert("cursor".into(), serde_json::json!(page.cursor()));
        let query: Self = serde_json::from_value(serde_json::Value::Object(values))
            .map_err(|_| Error::Malformed)?;
        query.validate()?;
        Ok(query)
    }
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self
            .view
            .as_ref()
            .is_some_and(|v| !matches!(v.as_str(), "summary" | "personal"))
            || !(1..=200).contains(&self.limit.unwrap_or(50))
            || self.from.is_some_and(|v| v < 0)
            || self.until.is_some_and(|v| v < 0)
            || self.from.zip(self.until).is_some_and(|(a, b)| a >= b)
            || [&self.source, &self.kind, &self.status, &self.related]
                .into_iter()
                .flatten()
                .any(|s| !crate::model::identifier(s))
            || [
                self.policy,
                self.request,
                self.batch,
                self.task,
                self.operation,
            ]
            .into_iter()
            .flatten()
            .any(|id| id.is_nil())
            || self.cursor.as_ref().is_some_and(|v| v.len() > 4096)
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }
    pub(crate) fn binding(&self) -> Self {
        let mut value = self.clone();
        value.cursor = None;
        value.limit = None;
        value
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Member {
    pub device: String,
    pub registration: Uuid,
    pub generation: i64,
}
#[derive(Clone, Debug)]
pub(crate) struct Scope {
    pub members: Vec<Member>,
    pub binding: String,
    pub reasons: Vec<String>,
    pub personal: Option<rss_mdm_audit_integration::activity::ActivityUser>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Watermark {
    pub device: String,
    pub generation: Uuid,
    pub revision: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Cursor {
    pub binding: String,
    pub changes: bool,
    pub through: Vec<Watermark>,
    pub since: Vec<Watermark>,
    pub after: Option<(i64, String, i64)>,
    pub as_of: i64,
    pub caught_up: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_queries_and_context_binding() {
        for invalid in [
            "limit=0",
            "limit=201",
            "from=-1",
            "from=2&until=2",
            "view=raw",
            "after=1",
            "policy=00000000-0000-0000-0000-000000000000",
        ] {
            assert!(Query::parse(invalid).is_err(), "{invalid}");
        }
        let a = Query::parse("limit=1&kind=execution&view=personal").unwrap();
        let b = Query::parse("limit=200&kind=execution&view=personal").unwrap();
        assert_eq!(
            serde_json::to_value(a.binding()).unwrap(),
            serde_json::to_value(b.binding()).unwrap()
        );
        let c = Query::parse("kind=execution").unwrap();
        assert_ne!(
            serde_json::to_value(a.binding()).unwrap(),
            serde_json::to_value(c.binding()).unwrap()
        );
    }
}
