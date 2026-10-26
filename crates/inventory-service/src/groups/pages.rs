//! Immutable result pagination. Each request passes the normal authorization gate.
use super::*;
use rss_mdm_query::cursor::{CursorCodec, fingerprint};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupPageKind {
    Members,
    Changes,
    Decisions,
}
pub static SCHEMA: rss_mdm_query::window::Schema = rss_mdm_query::window::Schema {
    id: "group_results",
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    order: "object key ASC",
    context: &[],
};
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    tenant: String,
    result: Uuid,
    binding: ResultBinding,
    after: String,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupPage {
    pub result: Uuid,
    pub group: Uuid,
    pub current: bool,
    pub sources: Vec<rss_mdm_group_postgres::GroupSource>,
    pub total_objects: usize,
    pub total_members: usize,
    pub page: GroupPageItems,
    pub next_cursor: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GroupPageItems {
    Members {
        items: Vec<crate::objects::ObjectRef>,
    },
    Changes {
        added: Vec<crate::objects::ObjectRef>,
        removed: Vec<crate::objects::ObjectRef>,
    },
    Decisions {
        items: Vec<Value>,
    },
}

fn encode(key: &ring::hmac::Key, cursor: Cursor) -> Result<String> {
    let context = checked_input(fingerprint(&(
        SCHEMA.id,
        &cursor.tenant,
        cursor.result,
        &cursor.binding,
    )))?;
    Ok(
        checked_input(CursorCodec::from_key(key.clone()).encode(&context, &cursor.after))?
            .as_str()
            .to_owned(),
    )
}
fn decode(
    key: &ring::hmac::Key,
    token: &str,
    tenant: &str,
    result: Uuid,
    binding: &ResultBinding,
) -> Result<String> {
    let context = checked_input(fingerprint(&(SCHEMA.id, tenant, result, binding)))?;
    let token = checked_input(rss_contract::PageCursor::parse(token))?;
    CursorCodec::from_key(key.clone())
        .decode(&token, &context)
        .map_err(|_| Error::Conflict.into())
}
impl Groups {
    pub async fn group_page_in(
        &self,
        tx: &mut PgTransaction<'_>,
        group: Uuid,
        result: Uuid,
        kind: GroupPageKind,
        query: &rss_mdm_query::window::Query,
        flow: &dyn Flow,
        subject: &str,
    ) -> Result<Value> {
        use rss_mdm_group_postgres as pg;
        checked_input(query.require_schema(&SCHEMA))?;
        let tenant = self.tenant.to_string();
        let binding = ResultBinding::Group {
            group,
            kind,
            subject: subject.to_owned(),
        };
        let after = query
            .cursor()
            .as_ref()
            .map(|token| decode(&self.cursor_key, token, &tenant, result, &binding))
            .transpose()?;
        let owner = checked_input(pg::GroupId::parse(&group.to_string()))?;
        let id = checked_input(pg::OperationId::parse(&result.to_string()))?;
        let build = group_checked(self.groups.build_in(tx, id).await?)?;
        if build.request.group != owner {
            return Err(Error::Group(GroupMissing::Group).into());
        }
        if !build.ready {
            return Err(Error::Conflict.into());
        }
        let context = group_checked(self.groups.get_in(tx, owner).await?)?
            .ok_or(Error::Group(GroupMissing::Group))?
            .asset_context;
        let object = |key: &str| group_checked(crate::objects::ObjectRef::from_key(context, key));
        let (page, next) = match kind {
            GroupPageKind::Members => {
                let mut items = checked(
                    self.groups
                        .build_members_in(tx, id, after, query.limit() + 1)
                        .await?,
                )?;
                let next = if items.len() > query.limit() {
                    items.truncate(query.limit());
                    items.last().cloned()
                } else {
                    None
                };
                (
                    GroupPageItems::Members {
                        items: items.iter().map(|id| object(id)).collect::<Result<_>>()?,
                    },
                    next,
                )
            }
            GroupPageKind::Decisions => {
                let mut items = checked(
                    self.groups
                        .build_decisions_in(tx, id, after, query.limit() + 1)
                        .await?,
                )?;
                let more = items.len() > query.limit();
                items.truncate(query.limit());
                let next = if more {
                    items.last().map(|item| item.device.clone())
                } else {
                    None
                };
                let snapshot = group_checked(crate::objects::ObjectSnapshot::from_group_input(
                    &build.request.input_version,
                ))?;
                let mut decisions = Vec::new();
                for d in items {
                    let reference = object(&d.device)?;
                    let sources = if let Some(snapshot) = &snapshot {
                        let reader = self.objects.clone();
                        let tenant = self.tenant;
                        let snapshot = snapshot.id;
                        let key = reference.clone();
                        let input = tx
                            .with_connection(move |c| {
                                Box::pin(
                                    async move { reader.lookup(c, tenant, snapshot, &key).await },
                                )
                            })
                            .await?;
                        let input = checked_input(serde_json::to_value(input))?;
                        vec![input]
                    } else {
                        vec![]
                    };
                    decisions.push(serde_json::json!({"object":reference,"origin":d.origin,"decision":d.decision,"explanations":d.explanations,"provenance":d.provenance,"sourceObjects":sources}));
                }
                let items = decisions;
                (GroupPageItems::Decisions { items }, next)
            }
            GroupPageKind::Changes => {
                let delta = checked(
                    self.groups
                        .build_changes_in(tx, id, after, query.limit())
                        .await?,
                )?;
                (
                    GroupPageItems::Changes {
                        added: delta
                            .added
                            .iter()
                            .map(|id| object(id))
                            .collect::<Result<_>>()?,
                        removed: delta
                            .removed
                            .iter()
                            .map(|id| object(id))
                            .collect::<Result<_>>()?,
                    },
                    delta.next,
                )
            }
        };
        let next_cursor = next
            .map(|after| {
                encode(
                    &self.cursor_key,
                    Cursor {
                        tenant,
                        result,
                        binding,
                        after,
                    },
                )
            })
            .transpose()?;
        let current = match self.groups.current_member_set_in(tx, owner).await? {
            Ok(current) => current == Some(id),
            Err(pg::Rejection::NotFound | pg::Rejection::Deleted) => false,
            Err(error) => return group_checked(Err(error)),
        };
        let current = current && flow.current(tx, group).await?;
        json(&GroupPage {
            result,
            group,
            current,
            sources: build.request.sources,
            total_objects: build.objects,
            total_members: build.members,
            page,
            next_cursor,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "family", rename_all = "snake_case", deny_unknown_fields)]
enum ResultBinding {
    Group {
        group: Uuid,
        kind: GroupPageKind,
        subject: String,
    },
}

#[cfg(test)]
#[path = "../../tests/groups_pages.rs"]
mod tests;
