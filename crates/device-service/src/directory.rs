//! Live keyset selection and presentation share one authenticated SELECT snapshot.
pub use crate::directory_filter::{SCHEMA, parse};
use crate::*;
use rss_mdm_audit_integration::budget::AuditBudget;
use rss_mdm_authorization_service::{Permission, Snapshot, context::AuthorizedPrincipal};
use rss_mdm_query::{cursor::CursorCodec, directory::Query};
use serde_json::{Value, json};
use sqlx::{Arguments, Row, postgres::PgArguments};
use std::time::Duration;

const PEOPLE: &str = concat!(
    "WITH platform_configuration AS (SELECT $7::jsonb AS config),",
    include_str!("platform_sessions.sql"),
    ",people_display AS (SELECT principal_id,active,login,source,status,display_name,username FROM identity_personnel),people AS (SELECT principal_id,active,login,status,display_name FROM people_display),",
    include_str!("directory_relation.sql"),
    include_str!("directory.sql"),
    include_str!("snapshot.sql")
);
const REFERENCES: &str = concat!(
    "WITH platform_configuration AS (SELECT $7::jsonb AS config),",
    include_str!("platform_sessions.sql"),
    ",people_display AS (SELECT NULL::uuid AS principal_id,false AS active,NULL::text AS login,NULL::text AS source,NULL::text AS status,NULL::text AS display_name,NULL::text AS username WHERE false),people AS (SELECT principal_id,active,login,status,display_name FROM people_display),",
    include_str!("directory_relation.sql"),
    include_str!("directory.sql"),
    include_str!("snapshot.sql")
);
const PEOPLE_STATISTICS: &str = concat!(
    "WITH platform_configuration AS (SELECT $7::jsonb AS config),",
    include_str!("platform_sessions.sql"),
    ",people_display AS (SELECT principal_id,active,login,source,status,display_name,username FROM identity_personnel),people AS (SELECT principal_id,active,login,status,display_name FROM people_display),",
    include_str!("directory_relation.sql"),
    include_str!("directory_statistics.sql")
);
const REFERENCE_STATISTICS: &str = concat!(
    "WITH platform_configuration AS (SELECT $7::jsonb AS config),",
    include_str!("platform_sessions.sql"),
    ",people_display AS (SELECT NULL::uuid AS principal_id,false AS active,NULL::text AS login,NULL::text AS source,NULL::text AS status,NULL::text AS display_name,NULL::text AS username WHERE false),people AS (SELECT principal_id,active,login,status,display_name FROM people_display),",
    include_str!("directory_relation.sql"),
    include_str!("directory_statistics.sql")
);
pub(crate) struct Access {
    pub(crate) allowed: Option<Vec<String>>,
    pub(crate) sensitive: Option<Vec<String>>,
    pub(crate) owners: Option<Vec<String>>,
    pub(crate) binding: String,
    pub(crate) snapshot: Snapshot,
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
fn identity_access(value: rss_identity_postgres::PersonnelRevision) -> Value {
    json!({"logins":value.logins,"profiles":match value.profiles {
        rss_identity_postgres::PersonnelProfileScope::None=>"none",rss_identity_postgres::PersonnelProfileScope::SelfOnly=>"self",rss_identity_postgres::PersonnelProfileScope::All=>"all",
    }})
}
impl Associations {
    pub(crate) async fn directory_access(
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
                                snapshot,
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
                "live-device-views",
                proof.tenant_id(),
                proof.instance_id(),
                proof.principal_id(),
                &access.binding,
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
            arg!(vec![
                "device.name",
                "device.network.apple.host_name",
                "device.network.apple.local_host_name",
                "device.serial_number"
            ]);
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
        if old
            .as_ref()
            .is_some_and(|c| c.identity != identity_access(identity))
        {
            return Err(Error::CursorInvalidated);
        }
        #[cfg(feature = "integration")]
        self.read_checkpoint().await?;
        let subject = personnel.revalidate(proof).await?;
        self.confirm_scope(proof, &access.binding, subject.as_ref(), &budget)
            .await?;
        proof.check_live()?;
        if statistics {
            return crate::view_response::decode(
                json!({"statistics":value["statistics"],"asOf":value["asOf"]}),
            )
            .map(crate::view_response::DirectoryReply::Statistics);
        }
        let mut read = crate::snapshot::decode(proof, &access.snapshot, identity, &value)?;
        if descending {
            read.groups.reverse();
        }
        let more = value["more"].as_bool().ok_or(Error::Storage)?;
        let next_cursor = if more {
            Some(
                codec
                    .encode(
                        &binding,
                        &Continuation {
                            after: read.groups.last().ok_or(Error::Storage)?.key(),
                            identity: identity_access(identity),
                        },
                    )
                    .map_err(|_| Error::Storage)?
                    .as_str()
                    .to_owned(),
            )
        } else {
            None
        };
        let items = read
            .groups
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
            rss_mdm_query::Page { items, next_cursor },
        ))
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Continuation {
    after: String,
    identity: Value,
}
