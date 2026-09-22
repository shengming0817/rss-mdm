//! Immutable result pagination. Each request passes the normal authorization gate.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum GroupPageKind {
    Members,
    Changes,
    Decisions,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PageQuery {
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
pub(super) struct GroupPage {
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
pub(super) enum GroupPageItems {
    Members {
        items: Vec<String>,
    },
    Changes {
        added: Vec<String>,
        removed: Vec<String>,
    },
    Decisions {
        items: Vec<rss_mdm_group_postgres::DecisionRecord>,
    },
}

fn encode(key: &ring::hmac::Key, cursor: Cursor) -> Result<String> {
    let mut bytes = input(serde_json::to_vec(&cursor))?;
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
    let bytes = input(URL_SAFE_NO_PAD.decode(token))?;
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
impl Management {
    pub(super) async fn group_page_in(
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
            .map(|token| decode(&self.asset_cursor_key, token, &tenant, result, &binding))
            .transpose()?;
        let owner = input(pg::GroupId::parse(&group.to_string()))?;
        group_checked(self.groups.lock_reference_target_in(tx, owner).await?)?;
        let id = input(pg::OperationId::parse(&result.to_string()))?;
        let build = group_checked(self.groups.build_in(tx, id).await?)?;
        if build.request.group != owner {
            return Err(Error::NotFound.into());
        }
        if !build.ready {
            return Err(Error::Conflict.into());
        }
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
                (GroupPageItems::Members { items }, next)
            }
            GroupPageKind::Decisions => {
                let items = checked(
                    self.groups
                        .build_decisions_in(tx, id, after, query.limit)
                        .await?,
                )?;
                let next = items.last().map(|item| item.device.clone());
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
                        added: delta.added,
                        removed: delta.removed,
                    },
                    delta.next,
                )
            }
        };
        let next_cursor = next
            .map(|after| {
                encode(
                    &self.asset_cursor_key,
                    Cursor {
                        tenant,
                        result,
                        binding,
                        after,
                    },
                )
            })
            .transpose()?;
        let current = checked(self.groups.current_member_set_in(tx, owner).await?)? == Some(id);
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
    Group {
        group: Uuid,
        kind: GroupPageKind,
    },
    Scope {
        scope: Uuid,
        kind: ScopePageKind,
    },
    Policy {
        policy: String,
        kind: PolicyPageKind,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ScopePageKind {
    Members,
    Decisions,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PolicyPageKind {
    Targets,
    Add,
    Supersede,
    Retain,
    Cancel,
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cursors_bind_tenant_owner_result_and_projection() {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"test-only");
        let group = Uuid::new_v4();
        let result = Uuid::new_v4();
        let binding = ResultBinding::Group {
            group,
            kind: GroupPageKind::Members,
        };
        let token = encode(
            &key,
            Cursor {
                tenant: "tenant-a".into(),
                result,
                binding: binding.clone(),
                after: "device-1".into(),
            },
        )
        .unwrap();
        assert_eq!(
            decode(&key, &token, "tenant-a", result, &binding).unwrap(),
            "device-1"
        );
        assert!(decode(&key, &token, "tenant-b", result, &binding).is_err());
        assert!(decode(&key, &token, "tenant-a", Uuid::new_v4(), &binding).is_err());
        for other in [
            ResultBinding::Group {
                group: Uuid::new_v4(),
                kind: GroupPageKind::Members,
            },
            ResultBinding::Group {
                group,
                kind: GroupPageKind::Decisions,
            },
            ResultBinding::Scope {
                scope: group,
                kind: ScopePageKind::Members,
            },
        ] {
            assert!(decode(&key, &token, "tenant-a", result, &other).is_err());
        }
        assert!(decode(&key, &format!("{token}x"), "tenant-a", result, &binding).is_err());
    }
}
mod policy;
mod scope;
pub(super) use policy::PolicyPage;
pub(super) use scope::ScopePage;
