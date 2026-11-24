//! Translate approved product mappings into ordinary versioned inventory definitions.
use super::*;

pub(super) async fn next(
    c: &mut PgConnection,
    binding: ExecutionBinding,
    providers: &[Uuid],
    after: Option<&str>,
) -> Result<(Option<Field>, Option<String>)> {
    let tenant = binding.tenant();
    rss_mdm_inventory_postgres::lock_catalog_write_in(c, tenant)
        .await
        .map_err(invalid)?;
    let mut candidates = desired_fields(c, providers, after).await?;
    let rows = sqlx::query("SELECT DISTINCT ON (field) field,version,CASE WHEN field LIKE 'device.%user.%' THEN definition END AS definition,coalesce(octet_length(definition::text),0) AS bytes FROM mdm.field_versions WHERE tenant_id=$1::uuid ORDER BY field,version DESC")
        .bind(tenant.to_string()).fetch_all(&mut *c).await?;
    let mut previous = BTreeMap::new();
    let mut count = 0;
    let mut bytes = 0i64;
    for row in rows {
        let size = i64::from(row.try_get::<i32, _>("bytes")?);
        count += usize::from(size > 0);
        bytes += size;
        let key = rss_mdm_inventory::FieldKey::parse(row.try_get("field")?).map_err(invalid)?;
        if let Some((role, _)) = personnel::attribute(key) {
            let raw: Option<Value> = row.try_get("definition")?;
            let definition: Option<FieldDefinition> = raw
                .map(serde_json::from_value)
                .transpose()
                .map_err(invalid)?;
            if role == DeviceUser::Registration && definition.is_some() {
                candidates.entry(key).or_insert(None);
            }
            previous.insert(key, (row.try_get::<i64, _>("version")?, definition, size));
        }
    }
    let mut candidates = candidates
        .into_iter()
        .filter(|(key, _)| after.is_none_or(|s| key.as_str() > s));
    let Some((key, field)) = candidates.next() else {
        return Ok((None, None));
    };
    let next = candidates.next().map(|_| key.as_str().to_owned());
    let attribute = personnel::attribute(key).expect("server field").1;
    let old: Vec<_> = previous
        .iter()
        .filter(|(key, (_, old, _))| {
            old.is_some() && personnel::attribute(**key).is_some_and(|(_, a)| a == attribute)
        })
        .collect();
    if let Some(mut field) = field {
        let available = rss_mdm_inventory::MAX_CATALOG_BYTES as i64 - bytes
            + old.iter().map(|(_, (_, _, size))| size).sum::<i64>();
        if count - old.len() + field.fields.len() <= rss_mdm_inventory::catalog_capacity()
            && publish(c, binding, &mut field, &previous, available).await?
        {
            return Ok((Some(field), next));
        }
    }
    for (key, (version, _, _)) in old {
        sqlx::query("SELECT mdm.append_field_version($1::uuid,$2,$3,NULL)")
            .bind(tenant.to_string())
            .bind(key.as_str())
            .bind(version + 1)
            .execute(&mut *c)
            .await?;
    }
    Ok((None, next))
}

async fn publish(
    c: &mut PgConnection,
    binding: ExecutionBinding,
    field: &mut Field,
    previous: &BTreeMap<rss_mdm_inventory::FieldKey, (i64, Option<FieldDefinition>, i64)>,
    remaining_bytes: i64,
) -> Result<bool> {
    let tenant = binding.tenant();
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
    if field_bytes > remaining_bytes {
        return Ok(false);
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
    Ok(true)
}

async fn desired_fields(
    c: &mut PgConnection,
    providers: &[Uuid],
    after: Option<&str>,
) -> Result<BTreeMap<rss_mdm_inventory::FieldKey, Option<Field>>> {
    let mut fields = BTreeMap::new();
    let mut invalid_mappings = Vec::new();
    let mut add = |attribute, kind: ValueType, profile, after, revision: u64| {
        fields.insert(
            DeviceUser::Registration.key(attribute),
            Some(Field {
                attribute,
                profile,
                after,
                fields: DeviceUser::ALL
                    .into_iter()
                    .map(|role| (role, role.definition(attribute, revision, kind.clone())))
                    .collect(),
            }),
        );
    };
    for (attribute, kind) in personnel::fixed_attributes() {
        add(attribute, kind, None, 0, 1);
    }
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
    let definitions=sqlx::query("SELECT field_id,revision,collected_after_micros,value FROM mdm_user_profiles.device_fields WHERE $1::text IS NULL OR ('device.registration_user.profile.f_' || replace(field_id::text,'-','')) COLLATE \"C\" > $1 ORDER BY field_id LIMIT 2")
        .bind(after).fetch_all(&mut *c).await?;
    for row in definitions {
        let d: model::DefinitionValue =
            serde_json::from_value(row.try_get("value")?).map_err(invalid)?;
        if model::device_path(&d.pointer).is_none() {
            invalid_mappings
                .push(DeviceUser::Registration.key(Attribute::Profile(row.try_get("field_id")?)));
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
    for key in invalid_mappings {
        fields.insert(key, None);
    }
    Ok(fields)
}
