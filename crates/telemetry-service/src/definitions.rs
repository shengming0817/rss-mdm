//! Bounded catalog projection. Checkpoints advance only after an exact RSS receipt.
use crate::{Error, Service};
use rss_mdm_inventory::{FieldDefinition, FieldKey};
use rss_request_context::{Deadline, TenantId};
use rss_timeseries::*;
use sqlx::{PgConnection, Row};
use std::{num::NonZeroU64, sync::Arc};
struct DefinitionAuthority {
    tenant: TenantId,
    key: String,
}
impl Authority for DefinitionAuthority {
    fn authorize(&self, input: Access<'_>) -> Result<(), rss_timeseries::Error> {
        let (scope, key) = match input {
            Access::Definition(DefinitionMutation::Register { definition, .. }) => {
                (&definition.spec().scope, &definition.spec().key)
            }
            Access::DefinitionRead(id)
            | Access::Definition(DefinitionMutation::Retire { id, .. }) => (&id.scope, &id.key),
            _ => return Err(rss_timeseries::Error::InvalidInput),
        };
        if scope.tenant() == self.tenant
            && scope.namespace().as_str() == "mdm.telemetry"
            && key.as_str() == self.key
        {
            Ok(())
        } else {
            Err(rss_timeseries::Error::InvalidInput)
        }
    }
}
impl Service {
    pub(crate) async fn synchronize(
        self: &Arc<Self>,
        field: FieldDefinition,
        cutoff: Deadline,
    ) -> Result<bool, Error> {
        let service = self.clone();
        self.runtime
            .local_tx(self.tenant, crate::deadline(), move |tx| {
                Box::pin(async move {
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            advance_on(&service, c, &field, cutoff).await.map_err(|_| {
                                sqlx::Error::Protocol("definition projection failed".into())
                            })
                        })
                    })
                    .await
                })
            })
            .await
            .fold(
                Ok,
                |_| Err(Error::Storage),
                |_| Err(Error::Storage),
                |_| Err(Error::Unknown),
                |_| Err(Error::Unknown),
                |_| Err(Error::Storage),
            )
    }
}
async fn advance_on(
    service: &Service,
    c: &mut PgConnection,
    field: &FieldDefinition,
    cutoff: Deadline,
) -> Result<bool, Error> {
    sqlx::query("INSERT INTO mdm_telemetry.definition_progress(tenant_id,field,version,digest) VALUES($1::uuid,$2,0,NULL) ON CONFLICT DO NOTHING")
        .bind(service.tenant.to_string()).bind(field.key.as_str()).execute(&mut *c).await?;
    let row = sqlx::query("SELECT version,digest FROM mdm_telemetry.definition_progress WHERE tenant_id=$1::uuid AND field=$2 FOR UPDATE")
        .bind(service.tenant.to_string()).bind(field.key.as_str()).fetch_one(&mut *c).await?;
    let mut version = row.try_get::<i64, _>("version")? as u64;
    let authority = DefinitionAuthority {
        tenant: service.tenant,
        key: field.key.as_str().into(),
    };
    let scope = Scope::new(service.tenant, Id::new("mdm.telemetry")?);
    let lookup = |version| DefinitionId {
        scope: scope.clone(),
        key: Id::new(field.key.as_str()).expect("validated field key"),
        version: NonZeroU64::new(version).expect("positive field revision"),
    };
    let mut expected = if version == 0 {
        None
    } else {
        let found = service
            .backend
            .definition(
                &Authorized::<DefinitionId>::verify(&authority, lookup(version))?,
                cutoff,
            )
            .await?;
        let Lookup::Found(found) = found else {
            return Err(Error::Storage);
        };
        let digest = found.definition.digest()?;
        if row.try_get::<Option<Vec<u8>>, _>("digest")?.as_deref()
            != Some(digest.as_bytes().as_slice())
        {
            return Err(Error::Storage);
        }
        Some(digest)
    };
    if version >= field.version {
        return match service
            .backend
            .definition(
                &Authorized::<DefinitionId>::verify(&authority, lookup(field.version))?,
                cutoff,
            )
            .await?
        {
            Lookup::Found(record)
                if record.definition
                    == field
                        .time_series_definition(scope)
                        .map_err(|_| Error::Invalid)? =>
            {
                Ok(true)
            }
            _ => Err(Error::Storage),
        };
    }
    let fields = rss_mdm_inventory_postgres::time_series_versions_in(
        c,
        service.tenant,
        FieldKey::parse(field.key.as_str()).map_err(|_| Error::Invalid)?,
        version,
        field.version,
    )
    .await
    .map_err(|_| Error::Storage)?;
    for field in fields {
        let definition = field
            .time_series_definition(scope.clone())
            .map_err(|_| Error::Invalid)?;
        let mutation = Authorized::<DefinitionMutation>::verify(
            &authority,
            DefinitionMutation::Register {
                definition: definition.clone(),
                expected_latest: expected,
            },
        )?;
        let outcome = service.backend.define(&mutation, cutoff).await?;
        let record = match outcome {
            Outcome::Accepted(v) | Outcome::Replay(v) => v,
            Outcome::Unknown => return Ok(false),
        };
        if record.definition != definition {
            return Err(Error::Storage);
        }
        expected = Some(record.definition.digest()?);
        version = field.version;
        sqlx::query("UPDATE mdm_telemetry.definition_progress SET version=$3,digest=$4 WHERE tenant_id=$1::uuid AND field=$2")
            .bind(service.tenant.to_string()).bind(field.key.as_str()).bind(version as i64).bind(expected.as_ref().map(|d| d.as_bytes().to_vec())).execute(&mut *c).await?;
    }
    Ok(version >= field.version)
}

impl Service {
    pub(crate) async fn retire_definitions(self: &Arc<Self>) -> Result<(), Error> {
        let service = self.clone();
        self.runtime
            .local_tx(self.tenant, crate::deadline(), move |tx| {
                Box::pin(async move {
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            retire_on(&service, c).await.map_err(|_| {
                                sqlx::Error::Protocol(
                                    "telemetry definition retirement unconfirmed".into(),
                                )
                            })
                        })
                    })
                    .await
                })
            })
            .await
            .fold(
                Ok,
                |_| Err(Error::Storage),
                |_| Err(Error::Storage),
                |_| Err(Error::Unknown),
                |_| Err(Error::Unknown),
                |_| Err(Error::Storage),
            )
    }
}
async fn retire_on(service: &Service, c: &mut PgConnection) -> Result<(), Error> {
    // A shared catalog fence prevents fresh admission while retirement is decided.
    sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1,2554))")
        .bind(format!("{}:field-catalog", service.tenant))
        .execute(&mut *c)
        .await?;
    let row=sqlx::query("SELECT p.field,p.version,p.retired_through FROM mdm_telemetry.definition_progress p WHERE p.tenant_id=$1::uuid AND p.retired_through<p.version AND (SELECT definition IS NULL FROM mdm.field_versions f WHERE f.tenant_id=p.tenant_id AND f.field=p.field ORDER BY version DESC LIMIT 1) AND NOT EXISTS(SELECT 1 FROM mdm_telemetry.batches b WHERE b.tenant_id=p.tenant_id AND p.field=ANY(b.fields) AND b.delivery<>'published') ORDER BY p.field LIMIT 1 FOR UPDATE OF p")
        .bind(service.tenant.to_string()).fetch_optional(&mut *c).await?;
    let Some(row) = row else {
        return Ok(());
    };
    let field = row.try_get::<String, _>("field")?;
    let through = row.try_get::<i64, _>("version")? as u64;
    let retired = row.try_get::<i64, _>("retired_through")? as u64;
    let versions = rss_mdm_inventory_postgres::time_series_versions_in(
        c,
        service.tenant,
        FieldKey::parse(&field).map_err(|_| Error::Storage)?,
        retired,
        through,
    )
    .await
    .map_err(|_| Error::Storage)?;
    let authority = DefinitionAuthority {
        tenant: service.tenant,
        key: field.clone(),
    };
    let scope = Scope::new(service.tenant, Id::new("mdm.telemetry")?);
    let deadline = Deadline::from_timeout(
        &crate::backend::SystemClock,
        std::time::Duration::from_secs(6),
    )
    .map_err(|_| Error::Storage)?;
    for field in versions.into_iter().take(8) {
        let definition = field
            .time_series_definition(scope.clone())
            .map_err(|_| Error::Storage)?;
        let id = DefinitionId {
            scope: scope.clone(),
            key: Id::new(field.key.as_str())?,
            version: NonZeroU64::new(field.version).ok_or(Error::Storage)?,
        };
        let mutation = DefinitionMutation::Retire {
            id,
            expected: definition.digest()?,
        };
        match service
            .backend
            .define(
                &Authorized::<DefinitionMutation>::verify(&authority, mutation)?,
                deadline,
            )
            .await?
        {
            Outcome::Unknown => return Ok(()),
            Outcome::Accepted(record) | Outcome::Replay(record) => {
                if record.state != DefinitionState::Retired {
                    return Err(Error::Storage);
                }
            }
        }
        sqlx::query("UPDATE mdm_telemetry.definition_progress SET retired_through=$3 WHERE tenant_id=$1::uuid AND field=$2")
            .bind(service.tenant.to_string()).bind(field.key.as_str()).bind(field.version as i64).execute(&mut *c).await?;
    }
    Ok(())
}
