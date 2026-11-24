//! Translate approved product mappings into ordinary versioned inventory definitions.
use super::*;

pub(super) async fn fields(
    c: &mut PgConnection,
    binding: ExecutionBinding,
    providers: &[Uuid],
) -> Result<Vec<Field>> {
    let tenant = binding.tenant();
    rss_mdm_inventory_postgres::lock_catalog_write_in(c, tenant)
        .await
        .map_err(invalid)?;
    let rows=sqlx::query("SELECT DISTINCT ON (field) field,version,definition FROM mdm.field_versions WHERE tenant_id=$1::uuid ORDER BY field,version DESC")
        .bind(tenant.to_string()).fetch_all(&mut *c).await?;
    let mut previous = BTreeMap::new();
    let mut other = Vec::new();
    for row in rows {
        let key = rss_mdm_inventory::FieldKey::parse(row.try_get("field")?).map_err(invalid)?;
        let version: i64 = row.try_get("version")?;
        let value: Option<Value> = row.try_get("definition")?;
        let old: Option<FieldDefinition> = value
            .map(serde_json::from_value)
            .transpose()
            .map_err(invalid)?;
        if DeviceUser::for_key(key).is_some() {
            previous.insert(key, (version, old));
        } else {
            other.extend(old);
        }
    }
    let mut fields = Vec::new();
    let mut add = |attribute, kind: ValueType, profile, after, revision: u64| {
        fields.push(Field {
            attribute,
            profile,
            after,
            fields: DeviceUser::ALL
                .into_iter()
                .map(|role| (role, role.definition(attribute, revision, kind.clone())))
                .collect(),
        });
    };
    add(
        Attribute::Principal,
        ValueType::String {
            max_length: 36,
            allow_empty: false,
        },
        None,
        0,
        1,
    );
    add(Attribute::LocalGroups, personnel::identifiers(), None, 0, 1);
    for id in providers {
        for attr in ProviderAttribute::ALL {
            add(
                Attribute::Provider(*id, attr),
                personnel::identifiers(),
                None,
                0,
                1,
            );
        }
    }
    let definitions=sqlx::query("SELECT field_id,revision,collected_after_micros,value FROM mdm_user_profiles.device_fields ORDER BY field_id LIMIT $1")
        .bind(rss_mdm_inventory::catalog_capacity() as i64 + 1).fetch_all(&mut *c).await?;
    for row in definitions {
        let d: model::DefinitionValue =
            serde_json::from_value(row.try_get("value")?).map_err(invalid)?;
        let kind = match d.value_type {
            model::ValueType::String => ValueType::String {
                max_length: d.max_length.unwrap_or(65536),
                allow_empty: true,
            },
            model::ValueType::Number => ValueType::Number,
            model::ValueType::Integer => ValueType::Integer,
            model::ValueType::Boolean => ValueType::Boolean,
            _ => return Err(invalid("profile type")),
        };
        let version = u64::try_from(row.try_get::<i64, _>("revision")?).map_err(invalid)?;
        add(
            Attribute::Profile(row.try_get("field_id")?),
            kind,
            Some(d),
            row.try_get("collected_after_micros")?,
            version,
        );
    }
    let mut changes = Vec::new();
    for field in &mut fields {
        for (_, d) in &mut field.fields {
            let (version, old) = previous.remove(&d.key).unwrap_or_default();
            let revision = d.version;
            if let Some(old) = old
                && revision <= old.version
            {
                d.version = old.version;
                if *d == old {
                    other.push(old);
                    continue;
                }
            }
            d.version = revision.max((version + 1) as u64);
            other.push(d.clone());
            changes.push((
                d.key,
                d.version,
                Some(serde_json::to_value(d).map_err(invalid)?),
            ));
        }
    }
    for (key, (version, old)) in previous {
        if old.is_some() {
            changes.push((key, (version + 1) as u64, None))
        }
    }
    if !changes.is_empty() {
        rss_mdm_inventory::Catalog::new(other).map_err(invalid)?;
        for (key, version, definition) in changes {
            sqlx::query("SELECT mdm.append_field_version($1::uuid,$2,$3,$4)")
                .bind(tenant.to_string())
                .bind(key.as_str())
                .bind(version as i64)
                .bind(definition)
                .execute(&mut *c)
                .await?;
        }
    }
    Ok(fields)
}
