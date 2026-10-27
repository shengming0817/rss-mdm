//! Authorized relational selection followed by bounded presentation hydration.
pub use crate::directory_filter::{SCHEMA, parse};
use crate::views::ViewRef;
use crate::*;
use rss_mdm_audit_integration::budget::AuditBudget;
use rss_mdm_authorization_service::{Permission, Snapshot, context::AuthorizedPrincipal};
use rss_mdm_query::{cursor::CursorCodec, directory::Query};
use serde_json::{Value, json};
use sqlx::{Arguments, Row, postgres::PgArguments};
use std::{collections::BTreeSet, time::Duration};

const PEOPLE: &str = concat!(
    "WITH platform_configuration AS (SELECT $7::jsonb AS config),",
    include_str!("platform_sessions.sql"),
    ",people AS (SELECT principal_id,active,login,status,display_name FROM identity_personnel),",
    include_str!("directory_relation.sql"),
    include_str!("directory.sql")
);
const REFERENCES: &str = concat!(
    "WITH platform_configuration AS (SELECT $7::jsonb AS config),",
    include_str!("platform_sessions.sql"),
    ",people AS (SELECT NULL::uuid AS principal_id,false AS active,NULL::text AS login,NULL::text AS status,NULL::text AS display_name WHERE false),",
    include_str!("directory_relation.sql"),
    include_str!("directory.sql")
);
const PEOPLE_STATISTICS: &str = concat!(
    "WITH platform_configuration AS (SELECT $7::jsonb AS config),",
    include_str!("platform_sessions.sql"),
    ",people AS (SELECT principal_id,active,login,status,display_name FROM identity_personnel),",
    include_str!("directory_relation.sql"),
    include_str!("directory_statistics.sql")
);
const REFERENCE_STATISTICS: &str = concat!(
    "WITH platform_configuration AS (SELECT $7::jsonb AS config),",
    include_str!("platform_sessions.sql"),
    ",people AS (SELECT NULL::uuid AS principal_id,false AS active,NULL::text AS login,NULL::text AS status,NULL::text AS display_name WHERE false),",
    include_str!("directory_relation.sql"),
    include_str!("directory_statistics.sql")
);
struct Access {
    allowed: Option<Vec<String>>,
    sensitive: Option<Vec<String>>,
    owners: Option<Vec<String>>,
    binding: String,
    generation: Value,
}
fn permission_scope(
    snapshot: &Snapshot,
    proof: &AuthorizedPrincipal,
    permission: Permission,
) -> Result<Option<Vec<String>>> {
    // Tenant capabilities (notably InventorySensitiveRead) apply only inside
    // the independently authorized device candidates. devices_for rejects these
    // capabilities; treating that rejection as denial would hide permitted data.
    // This adapter does not introduce device-scoped sensitive grants.
    let scope = if permission.device() {
        snapshot.devices_for(proof, permission)
    } else {
        snapshot.require(proof, permission, None).map(|()| None)
    };
    match scope {
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
                            let (_, binding) = views::scope(&snapshot, proof)?;
                            Ok(Access {
                                allowed: snapshot
                                    .inventory_devices(proof)?
                                    .map(|s| s.into_iter().collect()),
                                sensitive: permission_scope(
                                    &snapshot,
                                    proof,
                                    Permission::InventorySensitiveRead,
                                )?,
                                owners: permission_scope(&snapshot, proof, Permission::Enrollment)?,
                                binding,
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
        query: &Query,
        personnel: &personnel::Reader<'_>,
    ) -> Result<crate::view_response::Directory> {
        self.directory_read(proof, query, personnel, false)
            .await
            .and_then(crate::view_response::DirectoryReply::page)
    }
    pub async fn statistics(
        &self,
        proof: &AuthorizedPrincipal,
        query: &Query,
        personnel: &personnel::Reader<'_>,
    ) -> Result<crate::view_response::StatisticsResponse> {
        self.directory_read(proof, query, personnel, true)
            .await
            .and_then(crate::view_response::DirectoryReply::statistics)
    }
    async fn directory_read(
        &self,
        proof: &AuthorizedPrincipal,
        query: &Query,
        personnel: &personnel::Reader<'_>,
        statistics: bool,
    ) -> Result<crate::view_response::DirectoryReply> {
        if proof.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        let budget = AuditBudget::new(Duration::from_secs(15));
        let access = self.directory_access(proof, &budget).await?;
        query
            .require_schema(&SCHEMA)
            .map_err(|_| Error::Malformed)?;
        let binding = query
            .binding(&(
                proof.tenant_id(),
                proof.instance_id(),
                proof.principal_id(),
                &access.binding,
                &access.generation,
                personnel.platform_configuration()?,
            ))
            .map_err(|_| Error::Malformed)?;
        let codec = CursorCodec::from_key(self.key.clone());
        let old: Option<Continuation> = query
            .cursor()
            .map(|token| {
                codec
                    .decode(token, &binding)
                    .map_err(|_| Error::CursorInvalidated)
            })
            .transpose()?;
        let after = old.as_ref().map(|c| c.after.clone());
        let descending = query.sort()[0].descending;
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
        arg!(crate::directory_filter::predicate(query)?);
        arg!(proof.instance_id().to_owned());
        arg!(personnel.platform_configuration()?);
        arg!(query.mentions("search"));
        let candidate_limit: i64 = if statistics { 16384 } else { 4096 };
        arg!(candidate_limit);
        if !statistics {
            arg!(after);
            arg!(descending);
            arg!((query.limit() + 1) as i64);
        }
        let (identity, rows) = personnel
            .query(
                proof,
                match (statistics, proof.session().is_ok()) {
                    (false, true) => PEOPLE,
                    (false, false) => REFERENCES,
                    (true, true) => PEOPLE_STATISTICS,
                    (true, false) => REFERENCE_STATISTICS,
                },
                args,
                1,
            )
            .await?;
        let value: Value = rows.first().ok_or(Error::Storage)?.try_get("value")?;
        let measured = &value["budget"];
        let input_rows = measured["inputRows"].as_u64().ok_or(Error::Storage)?;
        if !rss_mdm_query_postgres::within_budget(
            if statistics {
                "device.statistics.sources"
            } else {
                "device.views.sources"
            },
            input_rows,
            input_rows * 16,
            candidate_limit as u64 * 256,
            candidate_limit as u64 * 4096,
        ) {
            return Err(Error::Capacity);
        }
        if !rss_mdm_query_postgres::within_budget(
            if statistics {
                "device.statistics.candidates"
            } else {
                "device.views.candidates"
            },
            measured["rows"].as_u64().ok_or(Error::Storage)?,
            measured["bytes"].as_u64().ok_or(Error::Storage)?,
            candidate_limit as u64,
            candidate_limit as u64 * 512,
        ) {
            return Err(Error::Capacity);
        }
        let generation = json!([
            value["watermark"],
            value["relationRevision"],
            value["queryRevision"]
        ]);
        if generation != access.generation {
            return Err(Error::CursorInvalidated);
        }
        if statistics {
            let final_access = self.directory_access(proof, &budget).await?;
            let (final_identity, _) = personnel
                .query(proof, "SELECT 1", PgArguments::default(), 1)
                .await?;
            if final_access.binding != access.binding
                || final_access.generation != generation
                || revision(final_identity) != revision(identity)
            {
                return Err(Error::CursorInvalidated);
            }
            proof.check_live()?;
            return crate::view_response::decode(
                json!({"statistics":value["statistics"],"asOf":value["asOf"]}),
            )
            .map(crate::view_response::DirectoryReply::Statistics);
        }
        let now = value["asOf"].as_i64().ok_or(Error::Storage)?;
        let mut until = identity
            .valid_until
            .min(value["validUntil"].as_i64().unwrap_or(i64::MAX));
        if let Some(old) = &old {
            let expires = old.expires;
            if expires <= now || old.identity != revision(identity) {
                return Err(Error::CursorInvalidated);
            }
            until = until.min(expires);
        }
        let mut objects = value["objects"].as_array().ok_or(Error::Storage)?.clone();
        let more = objects.len() > query.limit();
        objects.truncate(query.limit());
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
            .project(proof, false, endpoints.iter_mut())
            .await?;
        personnel
            .project(
                proof,
                true,
                endpoints.iter_mut().filter(|row| {
                    access.sensitive.as_ref().is_none_or(|ids| {
                        row["id"]
                            .as_str()
                            .is_some_and(|id| ids.iter().any(|v| v == id))
                    })
                }),
            )
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
        if descending {
            groups.reverse();
        }
        let next = if more {
            Some(
                codec
                    .encode(
                        &binding,
                        &Continuation {
                            identity: revision(identity),
                            expires: until,
                            after: groups.last().ok_or(Error::Storage)?.key(),
                        },
                    )
                    .map_err(|_| Error::Malformed)?
                    .as_str()
                    .to_owned(),
            )
        } else {
            None
        };
        proof.check_live()?;
        let items = groups
            .iter()
            .map(|g| {
                let mut row = g.summary();
                row["key"] = json!(g.key());
                query
                    .project_typed(crate::view_response::decode::<
                        crate::view_response::DirectoryRow,
                    >(row)?)
                    .map_err(|_| Error::Malformed)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(crate::view_response::DirectoryReply::Page(
            rss_mdm_query::Page {
                items,
                next_cursor: next,
            },
        ))
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Continuation {
    after: String,
    identity: Value,
    expires: i64,
}
