//! Native asset binding and Legacy Profile composition.
use super::*;
/// Immutable protected Resource selection for one native downloaded asset or legacy Profile.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssetInput {
    pub identifier: String,
    pub resource: String,
    pub version: String,
    pub variant: String,
    pub version_digest: [u8; 32],
    pub content_type: String,
    pub profile_schemas: Vec<String>,
}
/// The content owner resolved these coordinates; native compilation checks real target architecture.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssetBinding {
    pub selection: AssetInput,
    pub reference: String,
    pub length: u64,
    pub sha256: [u8; 32],
    pub apple_silicon: bool,
    pub profile: Option<super::super::profiles::ProfileInput>,
}
/// Bind native HTTPS supply to an exact scope and operation, never an arbitrary authored URL.
pub fn bind_assets(
    inputs: &[DeclarationInput],
    bindings: &[AssetBinding],
    base: &str,
    target: &Target<'_>,
) -> Result<Vec<DeclarationInput>, Error> {
    use super::super::input::{FieldValue, Fields};
    let origin = url::Url::parse(base).map_err(|_| Error::Constraint)?;
    if origin.scheme() != "https"
        || origin.host_str().is_none()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        return Err(Error::Constraint);
    }
    let mut bound = std::collections::BTreeSet::new();
    let mut result = inputs.to_vec();
    for input in &mut result {
        let binding = bindings
            .iter()
            .find(|b| b.selection.identifier == input.identifier);
        let legacy = input.declaration_type == "com.apple.configuration.legacy";
        let reference = input.payload.0.get("Reference");
        let needs = legacy && input.payload.0.contains_key("ProfileURL") || reference.is_some();
        if let Some(binding) = binding {
            if !bound.insert(&input.identifier)
                || Some(binding.apple_silicon) != target.context.apple_silicon
                || binding.length == 0
                || binding.length > 16 * 1024 * 1024
                || binding.selection.content_type.is_empty()
            {
                return Err(Error::Constraint);
            }
            let mut url = origin.clone();
            url.path_segments_mut()
                .map_err(|_| Error::Constraint)?
                .push(&input.identifier);
            if legacy {
                if input.payload.0.contains_key("ProfileAssetReference") {
                    return Err(Error::Constraint);
                }
                input
                    .payload
                    .0
                    .insert("ProfileURL".into(), FieldValue::String(url.to_string()));
            } else if input.declaration_type.starts_with("com.apple.asset.") {
                let mut fields = match reference {
                    Some(FieldValue::Dictionary(fields)) => fields.clone(),
                    None => Fields::default(),
                    _ => return Err(Error::Field),
                };
                // Server-owned values replace these transport fields atomically.
                fields
                    .0
                    .insert("DataURL".into(), FieldValue::String(url.to_string()));
                fields.0.insert(
                    "ContentType".into(),
                    FieldValue::String(binding.selection.content_type.clone()),
                );
                fields.0.insert(
                    "Size".into(),
                    FieldValue::Integer(i64::try_from(binding.length).map_err(|_| Error::Limit)?),
                );
                fields.0.insert(
                    "Hash-SHA-256".into(),
                    FieldValue::String(binding.sha256.iter().map(|b| format!("{b:02x}")).collect()),
                );
                input.payload.0.insert(
                    "Authentication".into(),
                    FieldValue::Dictionary(Fields(std::collections::BTreeMap::from([(
                        "Type".into(),
                        FieldValue::String("MDM".into()),
                    )]))),
                );
                input
                    .payload
                    .0
                    .insert("Reference".into(), FieldValue::Dictionary(fields));
            } else {
                return Err(Error::Constraint);
            }
        } else if needs {
            return Err(Error::Constraint);
        }
    }
    if bound.len() != bindings.len() {
        return Err(Error::Constraint);
    }
    Ok(result)
}

/// Legacy profiles participate in classic native object guards in their original order.
#[derive(Clone, Serialize, Deserialize)]
pub struct LegacyProfile {
    pub declaration: String,
    pub objects: Vec<super::super::profiles::ProfileObject>,
}
pub fn legacy_profiles(
    inputs: &[DeclarationInput],
    assets: &[AssetBinding],
    target: &Target<'_>,
) -> Result<Vec<LegacyProfile>, Error> {
    let mut result = Vec::new();
    for input in inputs
        .iter()
        .filter(|i| i.declaration_type == "com.apple.configuration.legacy")
    {
        let reference = input
            .payload
            .0
            .get("ProfileAssetReference")
            .map(|v| match v {
                super::super::input::FieldValue::String(id) => Ok(id.as_str()),
                _ => Err(Error::Field),
            })
            .transpose()?
            .unwrap_or(&input.identifier);
        let profile = assets
            .iter()
            .find(|a| a.selection.identifier == reference)
            .and_then(|a| a.profile.as_ref())
            .ok_or(Error::Constraint)?;
        let compiled = profile.compile(target)?;
        result.push(LegacyProfile {
            declaration: input.identifier.clone(),
            objects: compiled.objects,
        });
    }
    Ok(result)
}
