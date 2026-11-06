use super::*;
use rss_mdm_group::{AssetContext, GroupId};
use serde::{Serialize, de::DeserializeOwned};
use sqlx::Row;

impl AssetService {
    pub(super) async fn software_revision(
        &self,
        tx: &mut PgTransaction<'_>,
        lock: bool,
    ) -> Result<u64> {
        let tenant = self.tenant.to_string();
        let value: Option<i64> = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    if lock {
                        sqlx::query(
                            "SELECT pg_advisory_xact_lock(hashtextextended($1::text,3026))",
                        )
                        .bind(&tenant)
                        .execute(&mut *c)
                        .await?;
                    } else {
                        sqlx::query(
                            "SELECT pg_advisory_xact_lock_shared(hashtextextended($1::text,3026))",
                        )
                        .bind(&tenant)
                        .execute(&mut *c)
                        .await?;
                    }
                    sqlx::query_scalar(
                        "SELECT revision FROM mdm_assets.software_heads WHERE tenant_id=$1::uuid",
                    )
                    .bind(tenant)
                    .fetch_optional(c)
                    .await
                })
            })
            .await?;
        Ok(value.unwrap_or(0) as u64)
    }
    pub(super) async fn software_configuration(
        &self,
        tx: &mut PgTransaction<'_>,
    ) -> Result<Configuration> {
        let revision = self.software_revision(tx, false).await?;
        let tenant = self.tenant.to_string();
        let (count,bytes):(i64,i64)=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_as("SELECT count(*),coalesce(sum(bytes),0)::bigint FROM (SELECT octet_length(document::text)::bigint bytes FROM mdm_assets.software_records WHERE tenant_id=$1::uuid AND document IS NOT NULL LIMIT 4097) bounded").bind(tenant).fetch_one(c).await
        })).await?;
        if count > 4096 || bytes > 768 * 1024 {
            return Err(Error::Unavailable(Failure::AssetBytesLimit).into());
        }
        let tenant = self.tenant.to_string();
        let rows=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query("SELECT kind,id,revision,document FROM mdm_assets.software_records WHERE tenant_id=$1::uuid AND document IS NOT NULL ORDER BY kind,id LIMIT 4096").bind(tenant).fetch_all(c).await
        })).await?;
        let mut configuration = Configuration {
            revision,
            standards: Vec::new(),
            mappings: Vec::new(),
        };
        for row in rows {
            match row.get::<String, _>("kind").as_str() {
                "standard" => configuration.standards.push(decode(&row)?),
                "mapping" => configuration.mappings.push(decode(&row)?),
                _ => return Err(Error::Unavailable(Failure::AssetsStorage).into()),
            }
        }
        Ok(configuration)
    }
    pub(super) async fn software_record<T: DeserializeOwned>(
        &self,
        tx: &mut PgTransaction<'_>,
        kind: &'static str,
        id: Uuid,
    ) -> Result<Record<T>> {
        let tenant = self.tenant.to_string();
        let row = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("SELECT id,revision,document FROM mdm_assets.software_records WHERE tenant_id=$1::uuid AND kind=$2 AND id=$3")
                .bind(tenant).bind(kind).bind(id).fetch_optional(c).await
        })).await?.ok_or(Error::NotFound)?;
        decode(&row)
    }
    async fn software_write<T: Serialize>(
        &self,
        tx: &mut PgTransaction<'_>,
        kind: &'static str,
        id: Uuid,
        change: &crate::operation::Operation<Change<T>>,
    ) -> Result<Response> {
        if id.is_nil() || change.expected_revision >= i64::MAX as u64 {
            return Err(Error::Malformed.into());
        }
        self.software_revision(tx, true).await?;
        let document = match &change.input {
            Change::Put(v) => Some(checked_input(serde_json::to_value(v))?),
            Change::Delete => None,
        };
        if document
            .as_ref()
            .is_some_and(|v| v.to_string().len() > 65536)
        {
            return Err(Error::Malformed.into());
        }
        let tenant = self.tenant.to_string();
        let expected = change.expected_revision as i64;
        let revision: i64 = tx.with_connection(move |c| Box::pin(async move {
            let revision = if expected == 0 && document.is_some() {
                sqlx::query_scalar("INSERT INTO mdm_assets.software_records(tenant_id,kind,id,revision,document) VALUES($1::uuid,$2,$3,1,$4) ON CONFLICT DO NOTHING RETURNING revision")
                    .bind(&tenant).bind(kind).bind(id).bind(document).fetch_optional(&mut *c).await?
            } else {
                sqlx::query_scalar("UPDATE mdm_assets.software_records SET revision=revision+1,document=$5 WHERE tenant_id=$1::uuid AND kind=$2 AND id=$3 AND revision=$4 AND document IS NOT NULL RETURNING revision")
                    .bind(&tenant).bind(kind).bind(id).bind(expected).bind(document).fetch_optional(&mut *c).await?
            };
            if revision.is_some() {
                sqlx::query("INSERT INTO mdm_assets.software_heads(tenant_id,revision) VALUES($1::uuid,1) ON CONFLICT(tenant_id) DO UPDATE SET revision=software_heads.revision+1")
                    .bind(tenant).execute(c).await?;
            }
            Ok(revision)
        })).await?.ok_or(Error::Conflict)?;
        Ok(Response::Mutation {
            receipt: MutationReceipt::Written {
                resource: kind.into(),
                id,
                revision: revision as u64,
            },
        })
    }
    pub(in crate::assets) async fn software_dispatch(
        &self,
        tx: &mut PgTransaction<'_>,
        command: &Command,
        access: &Access,
        cut: Option<&rss_mdm_inventory::AssetCut>,
    ) -> Result<Response> {
        let scope = &access.scope;
        scope.full().map_err(|_| Error::Forbidden)?;
        match command {
            Command::PutStandard { id, change } => {
                self.software_revision(tx, true).await?;
                if let Change::Put(s) = &change.input {
                    filter::validate_standard(s)?;
                    for context in [AssetContext::Endpoint, AssetContext::AssociatedDevice] {
                        if let Some(groups) = &s.assessments.get(context).allowed_groups {
                            for id in groups {
                                let g = self
                                    .software_sources
                                    .groups
                                    .lock_reference_target_in(tx, group_id(*id)?)
                                    .await?
                                    .map_err(|_| Error::Malformed)?;
                                if g.asset_context != context {
                                    return Err(Error::Malformed.into());
                                }
                            }
                        }
                    }
                } else {
                    let tenant = self.tenant.to_string();
                    let id = id.to_string();
                    let referenced: bool = tx.with_connection(move |c| Box::pin(async move {
                        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_assets.software_records WHERE tenant_id=$1::uuid AND kind='mapping' AND document->>'standard'=$2)")
                            .bind(tenant).bind(id).fetch_one(c).await
                    })).await?;
                    if referenced {
                        return Err(Error::Conflict.into());
                    }
                }
                self.software_write(tx, "standard", *id, change).await
            }
            Command::PutMapping { id, change } => {
                self.software_revision(tx, true).await?;
                if let Change::Put(mapping) = &change.input {
                    filter::validate_mapping(mapping)?;
                    if self
                        .software_record::<Standard>(tx, "standard", mapping.standard)
                        .await?
                        .definition
                        .is_none()
                    {
                        return Err(Error::Conflict.into());
                    }
                }
                self.software_write(tx, "mapping", *id, change).await
            }
            Command::Standard { id } => Ok(Response::Standard {
                record: self.software_record(tx, "standard", *id).await?,
            }),
            Command::Mapping { id } => Ok(Response::Mapping {
                record: self.software_record(tx, "mapping", *id).await?,
            }),
            Command::Standards { page } => {
                let (items, next_cursor) =
                    self.software_directory(tx, "standard", scope, page).await?;
                Ok(Response::Standards { items, next_cursor })
            }
            Command::Mappings { page } => {
                let (items, next_cursor) =
                    self.software_directory(tx, "mapping", scope, page).await?;
                Ok(Response::Mappings { items, next_cursor })
            }
            Command::Receipt {
                id,
                actor,
                instance,
            } => {
                let tenant = self.tenant.to_string();
                let actor = actor.clone();
                let instance = instance.clone();
                let operation = *id;
                let response: Option<serde_json::Value> = tx.with_connection(move |c| Box::pin(async move {
                    sqlx::query_scalar("SELECT CASE WHEN response->'asset'->>'kind'='accepted' THEN response->'asset' ELSE response->'asset'->'response'->'receipt' END FROM mdm_assets.operations WHERE tenant_id=$1::uuid AND actor=$2 AND id=$3 AND instance=$4::uuid AND ((response->'asset'->>'kind'='software' AND response->'asset'->'response'->>'kind'='mutation') OR (response->'asset'->>'kind'='accepted' AND response->'asset'->>'statusUrl' LIKE '/api/v1/software-asset-queries/%'))")
                        .bind(tenant).bind(actor).bind(operation).bind(instance).fetch_optional(c).await
                })).await?;
                Ok(Response::Receipt {
                    operation,
                    receipt: response
                        .map(|v| stored(serde_json::from_value(v)))
                        .transpose()?,
                })
            }
            Command::Search { change } => {
                self.software_search(
                    tx,
                    access,
                    change,
                    cut.ok_or(Error::Unavailable(Failure::AssetsStorage))?,
                )
                .await
            }
            Command::Release { id, change } => self.software_release(tx, scope, *id, change).await,
            _ => self.software_read(tx, scope, command).await,
        }
    }
}
pub(super) fn group_id(id: Uuid) -> Result<GroupId> {
    checked_input(GroupId::parse(&id.to_string()))
}
fn decode<T: DeserializeOwned>(row: &sqlx::postgres::PgRow) -> Result<Record<T>> {
    Ok(Record {
        id: row.try_get("id")?,
        revision: row.try_get::<i64, _>("revision")? as u64,
        definition: row
            .try_get::<Option<serde_json::Value>, _>("document")?
            .map(|v| stored(serde_json::from_value(v)))
            .transpose()?,
    })
}
