//! Translate approved product mappings into ordinary versioned inventory definitions.
use super::*;

pub(super) async fn next(
    c: &mut PgConnection,
    binding: ExecutionBinding,
    providers: &[Uuid],
    after: Option<&str>,
) -> Result<(Option<Field>, Option<String>)> {
    let tenant = binding.tenant();
    let mut candidates = desired_fields(c, providers, after).await?;
    // Two indexed seeks also advance through retired keys without loading their history.
    let prefix = "device.registration_user.";
    let mut bound = after.unwrap_or(prefix).to_owned();
    for _ in 0..2 {
        let key: Option<String> = sqlx::query_scalar("SELECT field FROM mdm.field_versions WHERE tenant_id=$1::uuid AND field>$2 ORDER BY field LIMIT 1")
            .bind(tenant.to_string()).bind(&bound).fetch_optional(&mut *c).await?;
        let Some(key) = key.filter(|key| key.starts_with(prefix)) else {
            break;
        };
        let name = rss_mdm_inventory::FieldKey::parse(&key).map_err(invalid)?;
        if personnel::attribute(name).is_some() {
            candidates.entry(name).or_insert(None);
        }
        bound = key;
    }
    let mut candidates = candidates
        .into_iter()
        .filter(|(key, _)| after.is_none_or(|s| key.as_str() > s));
    let Some((key, field)) = candidates.next() else {
        return Ok((None, None));
    };
    let next = candidates.next().map(|_| key.as_str().to_owned());
    let attribute = personnel::attribute(key).expect("server field").1;
    if matches!(
        attribute,
        Attribute::Provider(_, ProviderAttribute::DepartmentAncestors)
    ) {
        return Ok((None, next));
    }
    let field = publish(c, binding, attribute, field).await?;
    Ok((field, next))
}

async fn publish(
    c: &mut PgConnection,
    binding: ExecutionBinding,
    attribute: Attribute,
    mut field: Option<Field>,
) -> Result<Option<Field>> {
    let tenant = binding.tenant();
    let keys: Vec<_> = outputs(attribute)
        .map(|(role, a)| role.key(a).as_str().to_owned())
        .collect();
    let mut writes = Vec::new();
    let mut retire = Vec::new();
    for (index, key) in keys.iter().enumerate() {
        let previous:Option<(i64,Option<Value>)>=sqlx::query_as("SELECT version,definition FROM mdm.field_versions WHERE tenant_id=$1::uuid AND field=$2 ORDER BY version DESC LIMIT 1")
            .bind(tenant.to_string()).bind(key).fetch_optional(&mut *c).await?;
        let (version, old) = previous.unwrap_or((0, None));
        if old.is_some() {
            retire.push((key, version + 1, None));
        }
        let definition = field.as_mut().map(|f| &mut f.fields[index].definition);
        let body = if let Some(def) = definition {
            def.version = def.version.max(version as u64);
            if old.as_ref() == Some(&serde_json::to_value(&*def).map_err(invalid)?) {
                continue;
            }
            def.version = def.version.max((version + 1) as u64);
            Some(serde_json::to_value(&*def).map_err(invalid)?)
        } else {
            if old.is_none() {
                continue;
            }
            None
        };
        let new_version = field
            .as_ref()
            .map_or(version + 1, |f| f.fields[index].definition.version as i64);
        writes.push((key, new_version, body));
    }
    if !writes.is_empty() {
        rss_mdm_inventory_postgres::lock_catalog_write_in(c, tenant)
            .await
            .map_err(invalid)?;
        if let Some(f) = &field {
            let definitions = f
                .fields
                .iter()
                .map(|o| serde_json::to_value(&o.definition))
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(invalid)?;
            // The ordinary catalog capacity only changes on definition publication.
            let fits: bool = sqlx::query_scalar(include_str!("capacity.sql"))
                .bind(tenant.to_string())
                .bind(&keys)
                .bind(Value::Array(definitions))
                .bind(rss_mdm_inventory::catalog_capacity() as i64)
                .bind(rss_mdm_inventory::MAX_CATALOG_BYTES as i64)
                .fetch_one(&mut *c)
                .await?;
            if !fits {
                field = None;
                writes = retire;
            }
        }
        for (key, version, body) in writes {
            sqlx::query("SELECT mdm.append_field_version($1::uuid,$2,$3,$4)")
                .bind(tenant.to_string())
                .bind(key)
                .bind(version)
                .bind(body)
                .execute(&mut *c)
                .await?;
        }
    }
    Ok(field)
}

// The Identity department snapshot supplies both membership views in a single asset revision.
fn outputs(attribute: Attribute) -> impl Iterator<Item = (DeviceUser, Attribute)> {
    let ancestors = match attribute {
        Attribute::Provider(id, ProviderAttribute::Departments) => Some(Attribute::Provider(
            id,
            ProviderAttribute::DepartmentAncestors,
        )),
        _ => None,
    };
    std::iter::once(attribute)
        .chain(ancestors)
        .flat_map(|a| DeviceUser::ALL.map(|role| (role, a)))
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
                fields: outputs(attribute)
                    .map(|(role, attribute)| Output {
                        role,
                        attribute,
                        definition: role.definition(attribute, revision, kind.clone()),
                    })
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
