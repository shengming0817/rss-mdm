//! Authorized relational selection followed by bounded presentation hydration.
use crate::views::{Group, ViewQuery, ViewRef};
use crate::*;
use rss_mdm_audit_integration::budget::AuditBudget;
use rss_mdm_authorization_service::{Permission, Snapshot, context::AuthorizedPrincipal};
use serde_json::{Value, json};
use sqlx::{Arguments, Row, postgres::PgArguments};
use std::{collections::BTreeSet, time::Duration};

const PEOPLE: &str = concat!(
    "WITH platform_configuration AS (SELECT $16::jsonb AS config),",
    include_str!("platform_sessions.sql"),
    ",people AS (SELECT principal_id,active,login,status,display_name FROM identity_personnel),",
    include_str!("directory.sql")
);
const REFERENCES: &str = concat!(
    "WITH platform_configuration AS (SELECT $16::jsonb AS config),",
    include_str!("platform_sessions.sql"),
    ",people AS (SELECT NULL::uuid AS principal_id,false AS active,NULL::text AS login,NULL::text AS status,NULL::text AS display_name WHERE false),",
    include_str!("directory.sql")
);
struct Access {
    allowed: Option<Vec<String>>,
    sensitive: Option<Vec<String>>,
    owners: Option<Vec<String>>,
    binding: String,
    display: bool,
    generation: Value,
}
fn permission_scope(
    snapshot: &Snapshot,
    proof: &AuthorizedPrincipal,
    permission: Permission,
) -> Result<Option<Vec<String>>> {
    match snapshot.devices_for(proof, permission) {
        Ok(scope) => Ok(scope.map(|s| s.into_iter().collect())),
        Err(rss_mdm_authorization_service::error::AuthorizationError::Forbidden) => {
            Ok(Some(Vec::new()))
        }
        Err(error) => Err(error.into()),
    }
}
pub(crate) async fn read_generation(c: &mut sqlx::PgConnection, tenant: &str) -> Result<Value> {
    Ok(sqlx::query_scalar("SELECT jsonb_build_array(coalesce((SELECT revision FROM mdm.asset_clock WHERE tenant_id=$1::uuid),0),coalesce((SELECT relation_revision FROM mdm_devices.checkpoints WHERE tenant_id=$1::uuid),0),coalesce((SELECT query_revision FROM mdm_devices.checkpoints WHERE tenant_id=$1::uuid),0))")
        .bind(tenant).fetch_one(c).await?)
}
fn revision(value: rss_identity_postgres::PersonnelRevision) -> Value {
    json!({"generation":value.generation,"logins":value.logins,"profiles":match value.profiles {
        rss_identity_postgres::PersonnelProfileScope::None=>"none",
        rss_identity_postgres::PersonnelProfileScope::SelfOnly=>"self",
        rss_identity_postgres::PersonnelProfileScope::All=>"all",
    }})
}
impl Associations {
    async fn directory_access(
        &self,
        proof: &AuthorizedPrincipal,
        budget: &AuditBudget,
    ) -> Result<Access> {
        self.audit
            .write(self.tenant, &budget.source_control(), proof, |proof, tx| {
                Box::pin(async move {
                    tx.with_connection_context(proof, |proof, c| {
                        Box::pin(async move {
                            let snapshot = read::authorization(c, proof).await?;
                            let (display, binding) = views::scope(&snapshot, proof)?;
                            Ok(Access {
                                allowed: snapshot
                                    .inventory_devices(proof)?
                                    .map(|s| s.into_iter().collect()),
                                sensitive: if display { None } else { Some(Vec::new()) },
                                owners: permission_scope(&snapshot, proof, Permission::Enrollment)?,
                                binding,
                                display,
                                generation: read_generation(c, proof.tenant_id()).await?,
                            })
                        })
                    })
                    .await
                })
            })
            .await
            .fold(
                Ok,
                |e| Err(model::transaction_error(e)),
                |e| Err(model::transaction_error(e)),
                |_| Err(Error::RollbackFailed),
                |_| Err(Error::CommitUnknown),
                |e| Err(model::transaction_error(e)),
            )
    }
    pub(super) async fn directory_page(
        &self,
        proof: &AuthorizedPrincipal,
        query: &ViewQuery,
        personnel: &personnel::Reader<'_>,
    ) -> Result<Value> {
        let budget = AuditBudget::new(Duration::from_secs(15));
        let access = self.directory_access(proof, &budget).await?;
        let binding = cursor::digest(
            &json!({"kind":"device-directory-v2","tenant":proof.tenant_id(),"instance":proof.instance_id(),"principal":proof.principal_id(),"scope":access.binding,"platform":personnel.platform_configuration()?,
            "query":{"search":query.search,"platform":query.platform,"status":query.status,"source":query.source,"channel":query.channel,"assetState":query.asset_state,"descending":query.descending}}),
        )?;
        let old = query
            .cursor
            .as_deref()
            .map(|token| self.decode(token))
            .transpose()?;
        if old
            .as_ref()
            .is_some_and(|old| old.offset != 0 || old.context["binding"] != binding)
        {
            return Err(Error::CursorInvalidated);
        }
        let after = old
            .as_ref()
            .map(|old| {
                old.context["after"]
                    .as_str()
                    .map(str::to_owned)
                    .ok_or(Error::Malformed)
            })
            .transpose()?;
        let mut args = PgArguments::default();
        macro_rules! arg {
            ($v:expr) => {
                args.add($v).map_err(|_| Error::Storage)?;
            };
        }
        arg!(proof.tenant_id().to_owned());
        arg!(access.allowed.clone());
        arg!(access.sensitive.clone());
        arg!(access.owners.clone());
        arg!(query.search.as_ref().map(|s| s.trim().to_lowercase()));
        arg!(query.platform.map(|p| match p {
            rss_mdm_inventory::Platform::Windows => "windows",
            rss_mdm_inventory::Platform::Macos => "macos",
        }));
        arg!(query.status.clone());
        arg!(query.source.clone());
        arg!(query.channel.clone());
        arg!(
            serde_json::to_value(
                query
                    .asset_state
                    .unwrap_or(crate::lifecycle_management::AssetState::Active)
            )
            .map_err(|_| Error::Storage)?
            .as_str()
            .ok_or(Error::Storage)?
            .to_owned()
        );
        arg!(after);
        arg!(query.descending);
        arg!((query.limit + 1) as i64);
        arg!(proof.instance_id().to_owned());
        arg!(access.display);
        arg!(personnel.platform_configuration()?);
        let (identity, rows) = personnel
            .query(
                proof,
                if proof.session().is_ok() {
                    PEOPLE
                } else {
                    REFERENCES
                },
                args,
                1,
            )
            .await?;
        let value: Value = rows.first().ok_or(Error::Storage)?.try_get("value")?;
        let generation = json!([
            value["watermark"],
            value["relationRevision"],
            value["queryRevision"]
        ]);
        if generation != access.generation {
            return Err(Error::CursorInvalidated);
        }
        let now = value["asOf"].as_i64().ok_or(Error::Storage)?;
        let mut until = identity
            .valid_until
            .min(value["validUntil"].as_i64().unwrap_or(i64::MAX));
        if let Some(old) = &old {
            let expires = old.context["expires"].as_i64().ok_or(Error::Malformed)?;
            if expires <= now
                || old.context["generation"] != generation
                || old.context["identity"] != revision(identity)
            {
                return Err(Error::CursorInvalidated);
            }
            until = until.min(expires);
        }
        let mut objects = value["objects"].as_array().ok_or(Error::Storage)?.clone();
        let more = objects.len() > query.limit;
        objects.truncate(query.limit);
        let selected = objects
            .iter()
            .flat_map(|o| o["devices"].as_array().into_iter().flatten())
            .map(|id| id.as_str().map(str::to_owned).ok_or(Error::Storage))
            .collect::<Result<BTreeSet<_>>>()?;
        let associations = objects
            .iter()
            .filter_map(|o| {
                o["key"]
                    .as_str()
                    .and_then(|k| k.strip_prefix("association:"))
            })
            .map(|id| uuid::Uuid::parse_str(id).map_err(|_| Error::Storage))
            .collect::<Result<Vec<_>>>()?;
        let (mut groups, bindings) = self
            .audit
            .write(
                self.tenant,
                &budget.source_control(),
                (
                    self,
                    proof,
                    selected,
                    associations,
                    &access.binding,
                    &generation,
                ),
                |ctx, tx| {
                    Box::pin(async move {
                        tx.with_connection_context(ctx, |ctx, c| {
                            Box::pin(async move {
                                let (service, proof, selected, associations, binding, expected) =
                                    ctx;
                                rss_mdm_inventory_postgres::lock_watermark_in(c, service.tenant)
                                    .await?;
                                let snapshot = read::authorization(c, proof).await?;
                                if snapshot.query_binding(proof)? != **binding
                                    || read_generation(c, proof.tenant_id()).await? != **expected
                                {
                                    return Err(Error::CursorInvalidated);
                                }
                                let ids = selected.iter().cloned().collect::<Vec<_>>();
                                let world =
                                    identity::local_world(c, service.tenant, &ids, associations)
                                        .await?;
                                views::groups(
                                    c,
                                    proof.tenant_id(),
                                    selected,
                                    &world,
                                    &snapshot,
                                    proof,
                                )
                                .await
                            })
                        })
                        .await
                    })
                },
            )
            .await
            .fold(
                Ok,
                |e| Err(model::transaction_error(e)),
                |e| Err(model::transaction_error(e)),
                |_| Err(Error::RollbackFailed),
                |_| Err(Error::CommitUnknown),
                |e| Err(model::transaction_error(e)),
            )?;
        let mut endpoints = groups
            .iter_mut()
            .flat_map(|g| std::mem::take(&mut g.endpoints))
            .collect::<Vec<_>>();
        personnel
            .current_users(proof, &mut endpoints, &bindings)
            .await?;
        personnel
            .project(proof, access.display, endpoints.iter_mut())
            .await?;
        for group in &mut groups {
            let ids = match &group.reference {
                ViewRef::Endpoint(id) => vec![id.clone()],
                ViewRef::Association(_) => group
                    .association
                    .as_ref()
                    .ok_or(Error::Storage)?
                    .members
                    .iter()
                    .map(|m| m.device.clone())
                    .collect(),
            };
            for id in ids {
                let index = endpoints
                    .iter()
                    .position(|e| e["id"] == id)
                    .ok_or(Error::Storage)?;
                group.endpoints.push(endpoints.remove(index));
            }
        }
        let final_access = self.directory_access(proof, &budget).await?;
        let (final_identity, final_rows) = personnel
            .query(
                proof,
                "SELECT floor(extract(epoch FROM statement_timestamp()))::bigint AS now",
                PgArguments::default(),
                1,
            )
            .await?;
        if final_access.binding != access.binding
            || final_access.generation != generation
            || revision(final_identity) != revision(identity)
        {
            return Err(Error::CursorInvalidated);
        }
        until = until.min(final_identity.valid_until);
        let final_now: i64 = final_rows.first().ok_or(Error::Storage)?.try_get("now")?;
        if until <= final_now {
            return Err(Error::CursorInvalidated);
        }
        if query.descending {
            groups.reverse();
        }
        let next = if more {
            Some(self.encode(json!({"binding":binding,"generation":generation,"identity":revision(identity),"expires":until,"after":groups.last().ok_or(Error::Storage)?.key()}),0)?)
        } else {
            None
        };
        proof.check_live()?;
        Ok(
            json!({"items":groups.iter().map(Group::summary).collect::<Vec<_>>(),"statistics":value["statistics"],"nextCursor":next}),
        )
    }
}
