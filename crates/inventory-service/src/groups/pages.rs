//! Immutable result pagination. Each request passes the normal authorization gate.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupPageKind {
    Members,
    Changes,
    Decisions,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
    pub cursor: Option<String>,
}
fn default_limit() -> usize {
    1000
}
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
    let mut bytes = checked_input(serde_json::to_vec(&cursor))?;
    let signature = ring::hmac::sign(key, &bytes);
    bytes.extend_from_slice(signature.as_ref());
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
fn decode(
    key: &ring::hmac::Key,
    token: &str,
    tenant: &str,
    result: Uuid,
    binding: &ResultBinding,
) -> Result<String> {
    if token.len() > 4096 {
        return Err(Error::Malformed.into());
    }
    let bytes = checked_input(URL_SAFE_NO_PAD.decode(token))?;
    if bytes.len() <= 32 {
        return Err(Error::Malformed.into());
    }
    let (payload, signature) = bytes.split_at(bytes.len() - 32);
    ring::hmac::verify(key, payload, signature).map_err(|_| Error::Conflict)?;
    let cursor: Cursor = serde_json::from_slice(payload).map_err(|_| Error::Conflict)?;
    if cursor.tenant != tenant || cursor.result != result || &cursor.binding != binding {
        return Err(Error::Conflict.into());
    }
    Ok(cursor.after)
}
impl Groups {
    pub async fn group_page_in(
        &self,
        tx: &mut PgTransaction<'_>,
        group: Uuid,
        result: Uuid,
        kind: GroupPageKind,
        query: &PageQuery,
    ) -> Result<Value> {
        use rss_mdm_group_postgres as pg;
        if !(1..=1000).contains(&query.limit) {
            return Err(Error::Malformed.into());
        }
        let tenant = self.tenant.to_string();
        let binding = ResultBinding::Group { group, kind };
        let after = query
            .cursor
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
                let items = checked(
                    self.groups
                        .build_members_in(tx, id, after, query.limit)
                        .await?,
                )?;
                let next = if items.len() == query.limit {
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
                let items = checked(
                    self.groups
                        .build_decisions_in(tx, id, after, query.limit)
                        .await?,
                )?;
                let next = items.last().map(|item| item.device.clone());
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
                        .build_changes_in(tx, id, after, query.limit)
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
        json(&GroupPage {
            result,
            group,
            current,
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
    Group { group: Uuid, kind: GroupPageKind },
}

#[cfg(test)]
#[path = "../../tests/groups_pages.rs"]
mod tests;
