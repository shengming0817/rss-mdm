//! Adapt existing software facts without rewriting Inventory or inferring physical identity.
use super::*;
use rss_mdm_inventory::{Platform, Scalar};

pub(super) struct Item {
    pub fields: BTreeMap<String, String>,
    pub installed: bool,
    pub installation_known: bool,
}
pub(super) fn item(source: SoftwareSource, platform: Platform, value: &Scalar) -> Result<Item> {
    let Scalar::Object(row) = value else {
        return Err(Error::Unavailable(Failure::AssetsStorage).into());
    };
    let text = |key: &str| match row.get(key) {
        Some(Scalar::String(v)) => Some(v.clone()),
        _ => None,
    };
    let boolean = |key: &str| match row.get(key) {
        Some(Scalar::Boolean(v)) => Some(*v),
        _ => None,
    };
    let mut fields = BTreeMap::new();
    for (out, key) in [
        ("id", "id"),
        ("name", "name"),
        ("version", "version"),
        ("publisher", "publisher"),
        ("origin", "origin"),
    ] {
        if let Some(value) = text(key) {
            fields.insert(out.into(), value);
        }
    }
    if let Some(id) = text(if source == SoftwareSource::Installations {
        "native_id"
    } else {
        "id"
    }) {
        fields.insert("nativeId".into(), id);
    }
    if let Some(location) = text("location")
        .or_else(|| text("path"))
        .or_else(|| text("registry_key"))
    {
        fields.insert("location".into(), location);
    }
    fields.insert("source".into(), source.field().into());
    fields.insert(
        "platform".into(),
        match platform {
            Platform::Windows => "windows",
            Platform::Macos => "macos",
        }
        .into(),
    );
    fields.insert(
        "component".into(),
        text("native_id")
            .or_else(|| text("id"))
            .or_else(|| text("name"))
            .unwrap_or_default(),
    );
    // ref: Microsoft EnterpriseModernAppManagement CSP /AppManagement/*/*/Users.
    // Provisioning and PackageStatus do not establish a user's installation state.
    let installed = match source {
        SoftwareSource::Installations => match text("installation_state").as_deref() {
            Some("installed" | "registered") => Some(true),
            Some("provisioned") => Some(false),
            _ => None,
        },
        SoftwareSource::WindowsWin32 => Some(true),
        SoftwareSource::AppleApplications => Some(boolean("installing") != Some(true)),
        _ => match text("registered_users_native").as_deref().map(str::trim) {
            Some("2") => Some(true),
            Some("0" | "1" | "6") => Some(false),
            _ => None,
        },
    };
    Ok(Item {
        fields,
        installed: installed == Some(true),
        installation_known: installed.is_some(),
    })
}

pub(super) struct Matched {
    pub key: String,
    pub identity: Identity,
    pub standard: Option<Uuid>,
    pub rules: Vec<Uuid>,
}
pub(super) fn resolve(
    configuration: &Configuration,
    predicates: &BTreeMap<Uuid, filter::Predicate>,
    input: &ArrayInput,
    ordinal: usize,
    item: &Item,
) -> Result<Matched> {
    let mut candidates = BTreeSet::new();
    let mut rules = Vec::new();
    for record in &configuration.mappings {
        let Some(mapping) = &record.definition else {
            continue;
        };
        if mapping.enabled
            && mapping.source == input.source
            && mapping.platform == input.platform
            && mapping
                .origin
                .as_ref()
                .is_none_or(|origin| item.fields.get("origin") == Some(origin))
            && filter::matches(
                predicates
                    .get(&record.id)
                    .ok_or(Error::Unavailable(Failure::AssetsStorage))?,
                item,
            )
        {
            candidates.insert(mapping.standard);
            rules.push(record.id);
        }
    }
    let name = item.fields.get("name").cloned().unwrap_or_default();
    let native_id = item.fields.get("nativeId").cloned().unwrap_or_default();
    let publisher = item.fields.get("publisher").cloned().unwrap_or_default();
    let raw = digest(&(
        &input.source,
        input.platform,
        item.fields.get("origin"),
        &native_id,
        &publisher,
        &name,
        if native_id.is_empty() {
            item.fields.get("location")
        } else {
            None
        },
        if native_id.is_empty()
            && (name.is_empty() || publisher.is_empty())
            && !item.fields.get("location").is_some_and(|v| !v.is_empty())
        {
            Some((&input.endpoint, &input.value.version, ordinal))
        } else {
            None
        },
    ))?;
    let (key, identity, standard) = if candidates.len() == 1 {
        let id = *candidates.first().expect("one candidate");
        let definition = configuration
            .standards
            .iter()
            .find(|r| r.id == id)
            .and_then(|r| r.definition.as_ref())
            .ok_or(Error::Unavailable(Failure::AssetsStorage))?;
        (
            format!("standard:{id}"),
            Identity::Standard {
                id,
                name: definition.name.clone(),
                risk: definition.risk,
                tags: definition.tags.clone(),
            },
            Some(id),
        )
    } else if candidates.is_empty() {
        (
            format!("raw:{raw}"),
            Identity::Unmapped {
                name,
                source: input.source,
                native_id,
                publisher,
                platform: input.platform,
            },
            None,
        )
    } else {
        (
            format!("conflict:{raw}"),
            Identity::Conflict {
                name,
                candidates: candidates.into_iter().collect(),
                rules: rules.clone(),
            },
            None,
        )
    };
    Ok(Matched {
        key,
        identity,
        standard,
        rules,
    })
}
pub(super) fn selected(
    query: &SoftwareFilter,
    predicate: Option<&filter::Predicate>,
    matched: &Matched,
    item: &Item,
) -> Result<bool> {
    if !query.standards.is_empty()
        && matched
            .standard
            .is_none_or(|id| !query.standards.contains(&id))
    {
        return Ok(false);
    }
    if !query.risks.is_empty() || !query.tags.is_empty() {
        let Identity::Standard { risk, tags, .. } = &matched.identity else {
            return Ok(false);
        };
        if !query.risks.is_empty() && !query.risks.contains(risk)
            || query.tags.iter().any(|tag| !tags.contains(tag))
        {
            return Ok(false);
        }
    }
    Ok(predicate.is_none_or(|filter| filter::matches(filter, item)))
}
