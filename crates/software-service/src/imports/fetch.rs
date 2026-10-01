//! Exact finite source reads share the existing content egress/TLS policy.
use super::*;
use crate::publication::ArtifactReader;
fn input_error() -> Error {
    Error::Input
}
fn raw_repository(repository: &str, commit: &str) -> Result<url::Url> {
    let u = url::Url::parse(repository).map_err(|_| input_error())?;
    if u.host_str() != Some("github.com") || u.port().is_some() {
        return Err(Error::Unsupported);
    }
    let path = u.path().trim_matches('/').trim_end_matches(".git");
    if path.split('/').count() != 2
        || path.split('/').any(|s| {
            s.is_empty()
                || s == "."
                || s == ".."
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
    {
        return Err(Error::Input);
    }
    url::Url::parse(&format!(
        "https://raw.githubusercontent.com/{path}/{commit}/"
    ))
    .map_err(|_| input_error())
}
pub async fn fetch(
    tenant: TenantId,
    reader: &ArtifactReader,
    source: &SourceDefinition,
    input: &ImportRequest,
) -> Result<SourceDocuments> {
    source.snapshot()?;
    if source.snapshot()? != input.source {
        return Err(Error::Input);
    }
    let read = |url: String| async move { reader.document(&url).await.map_err(|_| Error::Content) };
    let mut documents = SourceDocuments::new();
    match (&source.protocol, &input.selection) {
        (
            SourceProtocol::WingetRest {
                location,
                identifier,
            },
            ImportSelection::Winget { files, .. },
        ) => {
            if files != &["manifest.json"] {
                return Err(Error::Input);
            }
            let base = url::Url::parse(location).map_err(|_| input_error())?;
            if !base.path().ends_with('/') {
                return Err(Error::Input);
            }
            let info: serde_json::Value = serde_json::from_slice(
                &read(base.join("information").map_err(|_| input_error())?.into()).await?,
            )
            .map_err(|_| input_error())?;
            if info["Data"]["SourceIdentifier"].as_str() != Some(identifier)
                || !info["Data"]["ServerSupportedVersions"]
                    .as_array()
                    .is_some_and(|v| v.iter().any(|v| v == "1.0.0"))
                || info["Data"].get("Authentication").is_some()
            {
                return Err(Error::Unsupported);
            }
            let mut url = base.join("packageManifests/").map_err(|_| input_error())?;
            url.path_segments_mut()
                .map_err(|_| input_error())?
                .pop_if_empty()
                .push(&input.package);
            url.query_pairs_mut()
                .append_pair("Version", &input.package_version);
            documents.insert("manifest.json".into(), read(url.into()).await?);
        }
        (
            SourceProtocol::WingetCommunity { repository, commit },
            ImportSelection::Winget { files, .. },
        ) => {
            query(tenant, source, input)?;
            if files.is_empty() || files.len() > 8 {
                return Err(Error::Input);
            }
            let base = raw_repository(repository, commit)?;
            let prefix = format!(
                "manifests/{}/{}/{}/",
                input.package[..1].to_ascii_lowercase(),
                input.package.replace('.', "/"),
                input.package_version
            );
            for file in files {
                if file.contains('/')
                    || !file.starts_with(&format!("{}.", input.package))
                    || !file.ends_with(".yaml")
                    || file.len() > 255
                    || !file
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                {
                    return Err(Error::Input);
                }
                if documents
                    .insert(
                        file.clone(),
                        read(
                            base.join(&format!("{prefix}{file}"))
                                .map_err(|_| input_error())?
                                .into(),
                        )
                        .await?,
                    )
                    .is_some()
                {
                    return Err(Error::Input);
                }
            }
        }
        (
            SourceProtocol::BrewTap {
                repository, commit, ..
            },
            ImportSelection::Brew { path, .. },
        ) => {
            if (!path.starts_with("Casks/") && !path.starts_with("Formula/"))
                || !path.ends_with(&format!("/{}.rb", input.package))
                || path
                    .split('/')
                    .any(|s| s == "." || s == ".." || s.is_empty())
                || !path
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/._-@+".contains(&b))
            {
                return Err(Error::Input);
            }
            let base = raw_repository(repository, commit)?;
            documents.insert(
                path.clone(),
                read(base.join(path).map_err(|_| input_error())?.into()).await?,
            );
        }
        _ => return Err(Error::Unsupported),
    }
    Ok(documents)
}
