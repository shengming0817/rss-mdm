use super::*;
use rss_mdm_inventory::{Evidence, SourceFact, State};
use sqlx::Row;
impl AssetService {
    pub(super) async fn assign_asset(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        field: FieldKey,
        change: &Operation<ManualChange>,
        owner: &Owner,
        at: Timepoint,
    ) -> Result<Response> {
        let catalog = catalog_in(tx, self.tenant, i64::MAX).await?;
        let definition = checked_input(catalog.definition(field))?;
        if !definition.manual || change.expected_revision >= i64::MAX as u64 {
            return Err(Error::Malformed.into());
        }
        checked_input(rss_observation::Id::new(device))?;
        let tenant = self.tenant.to_string();
        let id = device.to_owned();
        let exists: bool = tx
            .with_connection(move |c| {
                Box::pin(async move { crate::device::read::exists(c, tenant, id).await })
            })
            .await?;
        if !exists {
            return Err(Error::NotFound.into());
        }
        let tenant = self.tenant;
        let ids = vec![device.to_owned()];
        let prior = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    rss_mdm_inventory_postgres::manual_in(c, tenant, &ids)
                        .await
                        .map_err(|_| sqlx::Error::Protocol("manual read failed".into()))
                })
            })
            .await
            .map_err(|_| Error::Unavailable(Failure::ManualQuery))?;
        let old = prior.into_iter().find(|a| a.field == field);
        let state = match &change.input {
            ManualChange::Set { value } => {
                checked_input(definition.validate_scalar(value))?;
                State::Known(value.clone())
            }
            ManualChange::Null {} => State::Null,
            ManualChange::Delete {} => State::Deleted,
        };
        let evidence = Evidence {
            source: rss_mdm_inventory::Source::Manual,
            dataset: None,
            registration: None,
            registration_generation: None,
            epoch: None,
            snapshot_id: change.operation_id.to_string(),
            observed_at: at.unix_seconds(),
            received_at: at.unix_seconds(),
            actor: Some(format!("{}:{}", owner.instance, owner.principal)),
        };
        let last_known = if let State::Known(v) = &state {
            Some(rss_mdm_inventory::KnownValue {
                value: v.clone(),
                evidence: evidence.clone(),
            })
        } else {
            old.and_then(|a| a.fact.last_known)
        };
        let fact = SourceFact {
            state,
            last_known,
            evidence,
        };
        let tenant = self.tenant;
        let id = device.to_owned();
        let expected = change.expected_revision as i64;
        let revision = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    rss_mdm_inventory_postgres::assign_in(c, tenant, &id, field, expected, &fact)
                        .await
                        .map_err(|error| {
                            error.downcast::<sqlx::Error>().unwrap_or_else(|_| {
                                sqlx::Error::Protocol("manual write failed".into())
                            })
                        })
                })
            })
            .await?
            .ok_or(Error::Conflict)?;
        Ok(Response::Assignment {
            device: device.into(),
            field,
            revision,
        })
    }
    pub(super) async fn saved_read(
        &self,
        tx: &mut PgTransaction<'_>,
        owner: &Owner,
        id: Uuid,
    ) -> Result<SavedView> {
        let tenant = self.tenant.to_string();
        let owner = owner.clone();
        let row=tx.with_connection(move |c|Box::pin(async move {sqlx::query("SELECT revision,document::text FROM mdm_assets.saved_queries WHERE tenant_id=$1::uuid AND instance=$2::uuid AND owner=$3::uuid AND id=$4::uuid").bind(tenant).bind(owner.instance).bind(owner.principal).bind(id.to_string()).fetch_optional(c).await})).await?.ok_or(Error::NotFound)?;
        Ok(SavedView {
            id,
            revision: row.try_get("revision")?,
            definition: row
                .try_get::<Option<String>, _>("document")?
                .map(|s| stored(serde_json::from_str(&s)))
                .transpose()?,
        })
    }
    pub(super) async fn saved_list(
        &self,
        tx: &mut PgTransaction<'_>,
        owner: &Owner,
        after: Option<Uuid>,
    ) -> Result<Response> {
        let tenant = self.tenant.to_string();
        let owner = owner.clone();
        let rows=tx.with_connection(move |c|Box::pin(async move {sqlx::query("SELECT id::text,revision,document::text FROM mdm_assets.saved_queries WHERE tenant_id=$1::uuid AND instance=$2::uuid AND owner=$3::uuid AND ($4::uuid IS NULL OR id>$4::uuid) ORDER BY id LIMIT 101").bind(tenant).bind(owner.instance).bind(owner.principal).bind(after.map(|i|i.to_string())).fetch_all(c).await})).await?;
        let more = rows.len() > 100;
        let items = rows
            .into_iter()
            .take(100)
            .map(|r| {
                Ok(SavedView {
                    id: checked_input(Uuid::parse_str(r.try_get("id")?))?,
                    revision: r.try_get("revision")?,
                    definition: r
                        .try_get::<Option<String>, _>("document")?
                        .map(|s| stored(serde_json::from_str(&s)))
                        .transpose()?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let next = if more {
            items.last().map(|v| v.id)
        } else {
            None
        };
        Ok(Response::SavedList { items, next })
    }
    pub(super) async fn saved_write(
        &self,
        tx: &mut PgTransaction<'_>,
        owner: &Owner,
        id: Uuid,
        change: &Operation<SavedChange>,
    ) -> Result<Response> {
        if id.is_nil() || change.expected_revision >= i64::MAX as u64 {
            return Err(Error::Malformed.into());
        }
        let definition = match &change.input {
            SavedChange::Delete {} => None,
            SavedChange::Put { definition } => {
                crate::authorization::exact_id(&definition.name)?;
                self.validate_query(
                    &definition.query,
                    &catalog_in(tx, self.tenant, i64::MAX).await?,
                )?;
                if checked_input(serde_json::to_vec(definition))?.len() > 16384 {
                    return Err(Error::Malformed.into());
                }
                Some(definition.as_ref().clone())
            }
        };
        let tenant = self.tenant.to_string();
        let owner = owner.clone();
        let expected = change.expected_revision as i64;
        let document = definition
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|_| Error::Malformed)?;
        let revision=tx.with_connection(move |c|Box::pin(async move {
            if expected==0 && document.is_some(){
                sqlx::query_scalar("INSERT INTO mdm_assets.saved_queries VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid,1,$5::jsonb) ON CONFLICT DO NOTHING RETURNING revision").bind(tenant).bind(owner.instance).bind(owner.principal).bind(id.to_string()).bind(document).fetch_optional(c).await
            }else{
                sqlx::query_scalar("UPDATE mdm_assets.saved_queries SET revision=revision+1,document=$6::jsonb WHERE tenant_id=$1::uuid AND instance=$2::uuid AND owner=$3::uuid AND id=$4::uuid AND revision=$5 AND document IS NOT NULL RETURNING revision").bind(tenant).bind(owner.instance).bind(owner.principal).bind(id.to_string()).bind(expected).bind(document).fetch_optional(c).await
            }
        })).await?.ok_or(Error::Conflict)?;
        Ok(Response::Saved {
            query: SavedView {
                id,
                revision,
                definition,
            },
        })
    }
}
