use super::*;
use rss_mdm_inventory::{Evidence, State};
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
        let state = match &change.input {
            ManualChange::Set { value } => {
                checked_input(definition.validate_scalar(value))?;
                State::Known(value.clone())
            }
            ManualChange::Null {} => State::Null,
            ManualChange::Delete {} => State::Deleted,
        };
        let evidence = Evidence {
            scope: rss_mdm_inventory::CollectionScope::Device,
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
        let tenant = self.tenant;
        let id = device.to_owned();
        let expected = change.expected_revision as i64;
        let revision = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    rss_mdm_inventory_postgres::assign_in(
                        c, tenant, &id, field, expected, &state, &evidence,
                    )
                    .await
                    .map_err(|error| {
                        error
                            .downcast::<sqlx::Error>()
                            .unwrap_or_else(|_| sqlx::Error::Protocol("manual write failed".into()))
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
                .map(|s| {
                    stored(serde_json::from_str::<rsql::StoredDefinition>(&s))
                        .and_then(rsql::StoredDefinition::into_view)
                })
                .transpose()?,
        })
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
                let catalog = catalog_in(tx, self.tenant, i64::MAX).await?;
                let compiled = rsql::StoredDefinition::compile(definition, &catalog)?;
                self.validate_query(compiled.query(), &catalog)?;
                // Returned definitions must also fit a subsequent Put request.
                if checked_input(serde_json::to_vec(definition))?.len() > 16384
                    || checked_input(serde_json::to_vec(&compiled.clone().into_view()?))?.len()
                        > 16384
                {
                    return Err(Error::Malformed.into());
                }
                Some(compiled)
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
                definition: definition
                    .map(rsql::StoredDefinition::into_view)
                    .transpose()?,
            },
        })
    }
}
