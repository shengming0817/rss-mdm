use super::*;
use rss_mdm_inventory::{Evidence, SourceFact, State};
use sqlx::Row;
impl Management {
    pub(super) async fn load_assets(
        &self,
        tx: &mut PgTransaction<'_>,
        scope: &ReadScope,
    ) -> Result<Vec<DeviceView>> {
        let tenant = self.tenant.to_string();
        let all = scope.devices.is_none();
        let allowed: Vec<_> = scope
            .devices
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect();
        let ids:Vec<String>=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar("SELECT id FROM mdm_access.devices WHERE tenant_id=$1::uuid AND ($2 OR id=ANY($3)) ORDER BY id COLLATE \"C\" LIMIT 10001")
                .bind(tenant).bind(all).bind(allowed).fetch_all(c).await
        })).await?;
        if ids.len() > rss_mdm_group_postgres::core::limits::OBJECTS {
            return Err(Error::Malformed.into());
        }
        let mut devices: BTreeMap<_, _> = ids
            .iter()
            .map(|id| {
                (
                    id.clone(),
                    DeviceView {
                        device: id.clone(),
                        channels: BTreeSet::new(),
                        fields: BTreeMap::new(),
                        quality: vec![],
                        revisions: BTreeMap::new(),
                    },
                )
            })
            .collect();
        let tenant = self.tenant.to_string();
        let selected = ids.clone();
        let rows=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT r.device,r.id::text AS registration,r.generation,r.channel,s.source,s.epoch::text FROM mdm_access.registrations r JOIN mdm_access.report_sources s ON (s.tenant_id,s.registration)=(r.tenant_id,r.id) JOIN mdm_access.credentials c ON (c.tenant_id,c.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.device=ANY($2) AND r.state='active' AND s.enabled AND c.state='active' ORDER BY r.device,s.source")
                .bind(tenant).bind(selected).fetch_all(c).await
        })).await?;
        if rows.len() > 20_000 {
            return Err(Error::Malformed.into());
        }
        let mut scopes = Vec::new();
        let mut subjects = BTreeMap::new();
        let mut generations = BTreeMap::new();
        for row in rows {
            let device: String = row.try_get("device")?;
            let source = stored(rss_mdm_inventory::ReportSource::parse(
                row.try_get("source")?,
            ))?;
            let channel: &str = row.try_get("channel")?;
            if channel != source.channel().as_str() {
                return Err(Error::Unavailable(Failure::InventoryQuery).into());
            }
            let scope = crate::device::scope(
                self.tenant,
                input(Uuid::parse_str(row.try_get("registration")?))?,
                source.as_str(),
                input(Uuid::parse_str(row.try_get("epoch")?))?,
            )?;
            devices
                .get_mut(&device)
                .ok_or(Error::Malformed)?
                .channels
                .insert(row.try_get("channel")?);
            generations.insert(
                input(scope.encode())?,
                stored(u64::try_from(row.try_get::<i64, _>("generation")?))?,
            );
            subjects.insert(input(scope.encode())?, device);
            scopes.push(scope);
        }
        let tenant = self.tenant;
        let source_facts = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    rss_mdm_inventory_postgres::read_in(c, tenant, &scopes)
                        .await
                        .map_err(|_| sqlx::Error::Protocol("asset facts unavailable".into()))
                })
            })
            .await?;
        let mut facts: BTreeMap<(String, FieldKey), Vec<SourceFact>> = BTreeMap::new();
        for mut row in source_facts {
            row.fact.evidence.registration_generation =
                Some(*generations.get(&row.scope).ok_or(Error::Malformed)?);
            if let Some(last) = &mut row.fact.last_known {
                last.evidence.registration_generation = row.fact.evidence.registration_generation;
            }
            let device = subjects.get(&row.scope).ok_or(Error::Malformed)?;
            facts
                .entry((device.clone(), row.field))
                .or_default()
                .push(row.fact);
        }
        let tenant = self.tenant;
        let selected = ids.clone();
        let assignments = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    rss_mdm_inventory_postgres::manual_in(c, tenant, &selected)
                        .await
                        .map_err(|_| sqlx::Error::Protocol("manual facts unavailable".into()))
                })
            })
            .await?;
        for row in assignments {
            devices
                .get_mut(&row.device)
                .ok_or(Error::Malformed)?
                .revisions
                .insert(row.field, row.revision);
            facts
                .entry((row.device, row.field))
                .or_default()
                .push(row.fact);
        }
        let tenant = self.tenant.to_string();
        let keys: Vec<_> = subjects.keys().cloned().collect();
        let quality=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("SELECT DISTINCT ON(scope) scope,id::text,sequence,result,attempts,delivery_pending FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND scope=ANY($2) ORDER BY scope,sequence DESC")
                .bind(tenant).bind(keys).fetch_all(c).await
        })).await?;
        for row in quality {
            let attempts: crate::collection::Attempts =
                stored(serde_json::from_str(row.try_get("attempts")?))?;
            let fields = FieldKey::observed()
                .zip(attempts.fields)
                .map(|(field, a)| QualityField {
                    field,
                    quality: a.quality,
                    status: a.status,
                    received_at: a.received_at,
                })
                .collect();
            let scope: String = row.try_get("scope")?;
            let device = subjects.get(&scope).ok_or(Error::Malformed)?;
            devices
                .get_mut(device)
                .ok_or(Error::Malformed)?
                .quality
                .push(QualityRun {
                    run_id: stored(Uuid::parse_str(row.try_get("id")?))?,
                    sequence: row.try_get("sequence")?,
                    result: crate::collection::RunResult::parse(row.try_get("result")?)?,
                    delivery_pending: row.try_get("delivery_pending")?,
                    fields,
                });
        }
        for (id, device) in &mut devices {
            for field in FieldKey::ALL {
                device.fields.insert(
                    field,
                    stored(rss_mdm_inventory::resolve(
                        field,
                        facts.remove(&(id.clone(), field)).unwrap_or_default(),
                    ))?,
                );
            }
        }
        let devices: Vec<_> = devices.into_values().collect();
        if input(serde_json::to_vec(&devices))?.len()
            > rss_mdm_group_postgres::core::limits::BATCH_BYTES
        {
            return Err(Error::Malformed.into());
        }
        Ok(devices)
    }
    pub(super) async fn assign_asset(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        field: FieldKey,
        change: &Operation<ManualChange>,
        owner: &Owner,
        at: Timepoint,
    ) -> Result<Response> {
        if !field.definition().manual || change.expected_revision >= i64::MAX as u64 {
            return Err(Error::Malformed.into());
        }
        input(rss_observation::Id::new(device))?;
        let tenant = self.tenant.to_string();
        let id = device.to_owned();
        let exists:bool=tx.with_connection(move |c|Box::pin(async move {sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.devices WHERE tenant_id=$1::uuid AND id=$2)").bind(tenant).bind(id).fetch_one(c).await})).await?;
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
            .await?;
        let old = prior.into_iter().find(|a| a.field == field);
        let state = match &change.input {
            ManualChange::Set { value } => {
                input(field.validate_scalar(value))?;
                State::Known(value.clone())
            }
            ManualChange::Null {} => State::Null,
            ManualChange::Delete {} => State::Deleted,
        };
        let evidence = Evidence {
            source: rss_mdm_inventory::Source::Manual,
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
        let row=tx.with_connection(move |c|Box::pin(async move {sqlx::query("SELECT revision,document::text FROM mdm_management.saved_queries WHERE tenant_id=$1::uuid AND instance=$2::uuid AND owner=$3::uuid AND id=$4::uuid").bind(tenant).bind(owner.instance).bind(owner.principal).bind(id.to_string()).fetch_optional(c).await})).await?.ok_or(Error::NotFound)?;
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
        let rows=tx.with_connection(move |c|Box::pin(async move {sqlx::query("SELECT id::text,revision,document::text FROM mdm_management.saved_queries WHERE tenant_id=$1::uuid AND instance=$2::uuid AND owner=$3::uuid AND ($4::uuid IS NULL OR id>$4::uuid) ORDER BY id LIMIT 101").bind(tenant).bind(owner.instance).bind(owner.principal).bind(after.map(|i|i.to_string())).fetch_all(c).await})).await?;
        let more = rows.len() > 100;
        let items = rows
            .into_iter()
            .take(100)
            .map(|r| {
                Ok(SavedView {
                    id: input(Uuid::parse_str(r.try_get("id")?))?,
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
                self.validate_query(&definition.query)?;
                if input(serde_json::to_vec(definition))?.len() > 16384 {
                    return Err(Error::Malformed.into());
                }
                if definition.query.cursor.is_some() {
                    return Err(Error::Malformed.into());
                }
                Some(definition.clone())
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
                sqlx::query_scalar("INSERT INTO mdm_management.saved_queries VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid,1,$5::jsonb) ON CONFLICT DO NOTHING RETURNING revision").bind(tenant).bind(owner.instance).bind(owner.principal).bind(id.to_string()).bind(document).fetch_optional(c).await
            }else{
                sqlx::query_scalar("UPDATE mdm_management.saved_queries SET revision=revision+1,document=$6::jsonb WHERE tenant_id=$1::uuid AND instance=$2::uuid AND owner=$3::uuid AND id=$4::uuid AND revision=$5 AND document IS NOT NULL RETURNING revision").bind(tenant).bind(owner.instance).bind(owner.principal).bind(id.to_string()).bind(expected).bind(document).fetch_optional(c).await
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
