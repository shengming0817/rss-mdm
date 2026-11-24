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
    let rows=sqlx::query("SELECT DISTINCT ON (field) field,version,definition,coalesce(octet_length(definition::text),0) AS bytes FROM mdm.field_versions WHERE tenant_id=$1::uuid ORDER BY field,version DESC")
        .bind(tenant.to_string()).fetch_all(&mut *c).await?;
    let mut previous = BTreeMap::new();
    let mut count = 0;
    let mut bytes = 0i64;
    for row in rows {
        let key = rss_mdm_inventory::FieldKey::parse(row.try_get("field")?).map_err(invalid)?;
        let size = i64::from(row.try_get::<i32, _>("bytes")?);
        if DeviceUser::for_key(key).is_some() {
            let raw: Option<Value> = row.try_get("definition")?;
            let definition: Option<FieldDefinition> = raw
                .map(serde_json::from_value)
                .transpose()
                .map_err(invalid)?;
            previous.insert(key, (row.try_get::<i64, _>("version")?, definition, size));
        } else if size > 0 {
            count += 1;
            bytes += size;
        }
    }
    let mut fields = desired_fields(c, providers).await?;
    // Keep published attributes first when the shared field catalog is full.
    fields.sort_by_key(|f| {
        !f.fields.iter().any(|(_, d)| {
            previous
                .get(&d.key)
                .is_some_and(|(_, old, _)| old.is_some())
        })
    });
    let mut accepted = Vec::new();
    for mut field in fields {
        if count + field.fields.len() > rss_mdm_inventory::catalog_capacity() {
            continue;
        }
        let mut changed = Vec::new();
        let mut field_bytes = 0i64;
        for (_, definition) in &mut field.fields {
            let old = previous.get(&definition.key);
            let previous_version = old.map_or(0, |(v, _, _)| *v);
            definition.version = definition.version.max(previous_version as u64);
            if let Some((_, Some(published), size)) = old
                && published == definition
            {
                field_bytes += size;
                continue;
            }
            definition.version = definition.version.max((previous_version + 1) as u64);
            let body = serde_json::to_value(&*definition).map_err(invalid)?;
            let size: i32 = sqlx::query_scalar("SELECT octet_length($1::jsonb::text)")
                .bind(&body)
                .fetch_one(&mut *c)
                .await?;
            field_bytes += i64::from(size);
            changed.push((definition.key, definition.version, body));
        }
        if bytes + field_bytes > rss_mdm_inventory::MAX_CATALOG_BYTES as i64 {
            continue;
        }
        for (key, version, body) in changed {
            sqlx::query("SELECT mdm.append_field_version($1::uuid,$2,$3,$4)")
                .bind(tenant.to_string())
                .bind(key.as_str())
                .bind(version as i64)
                .bind(body)
                .execute(&mut *c)
                .await?;
        }
        count += field.fields.len();
        bytes += field_bytes;
        for (_, d) in &field.fields {
            previous.remove(&d.key);
        }
        accepted.push(field);
    }
    for (key, (version, old, _)) in previous {
        if old.is_some() {
            sqlx::query("SELECT mdm.append_field_version($1::uuid,$2,$3,NULL)")
                .bind(tenant.to_string())
                .bind(key.as_str())
                .bind(version + 1)
                .execute(&mut *c)
                .await?;
        }
    }
    Ok(accepted)
}

async fn desired_fields(c: &mut PgConnection, providers: &[Uuid]) -> Result<Vec<Field>> {
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
        if model::device_path(&d.pointer).is_none() {
            continue;
        }
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
    Ok(fields)
}
