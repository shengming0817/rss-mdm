//! Native package-manager reads over the existing frozen publication authority.
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine;
use rss_mdm_flow_service::software_publication::service::PublicationDirectory;
use rss_mdm_software_release::Ring;
use rss_mdm_software_service::publication::{
    self as p, ExportDocument, PublicationService, PublishedSoftware,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
pub struct StateData {
    pub directory: Arc<PublicationDirectory>,
    pub content: Option<Arc<rss_mdm_content_service::Store>>,
    pub requests: Arc<tokio::sync::Semaphore>,
}
struct Timer;
impl rss_request_context::Clock for Timer {
    #[allow(
        clippy::disallowed_methods,
        reason = "native HTTP ingress owns the monotonic deadline"
    )]
    fn now(&self) -> std::time::Instant {
        std::time::Instant::now()
    }
}
fn cutoff() -> Result<rss_request_context::Deadline, StatusCode> {
    rss_request_context::Deadline::from_timeout(&Timer, Duration::from_secs(6))
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}
fn ring(value: &str) -> Result<Ring, StatusCode> {
    match value {
        "test" => Ok(Ring::Test),
        "pilot" => Ok(Ring::Pilot),
        "production" => Ok(Ring::Production),
        _ => Err(StatusCode::NOT_FOUND),
    }
}
fn digest(value: &str) -> Result<[u8; 32], StatusCode> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut d = [0; 32];
    for (i, b) in d.iter_mut().enumerate() {
        *b = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
    }
    Ok(d)
}
fn failure(e: p::Error) -> StatusCode {
    match e {
        p::Error::CandidateNotFound | p::Error::Content | p::Error::Identity => {
            StatusCode::NOT_FOUND
        }
        p::Error::Input => StatusCode::BAD_REQUEST,
        p::Error::Unsupported => StatusCode::NOT_IMPLEMENTED,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}
fn service<'a>(state: &'a StateData, source: &str) -> Result<&'a PublicationService, StatusCode> {
    state
        .directory
        .services
        .get(source)
        .map(Arc::as_ref)
        .ok_or(StatusCode::NOT_FOUND)
}
fn token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    if let Some(token) = value.strip_prefix("Bearer ") {
        if token.len() <= 512 {
            return Some(token.into());
        }
        return None;
    }
    let encoded = value.strip_prefix("Basic ")?;
    if encoded.len() > 1024 {
        return None;
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let text = std::str::from_utf8(&bytes).ok()?;
    let (user, token) = text.split_once(':')?;
    if user != "rss" || token.len() > 512 {
        return None;
    }
    Some(token.into())
}
fn authenticated(
    service: &PublicationService,
    ring: Ring,
    headers: &HeaderMap,
) -> Result<(), StatusCode> {
    if service.native_read_allowed(ring, token(headers).as_deref()) {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}
fn contract(headers: &HeaderMap) -> Result<(), StatusCode> {
    if headers.get("Version").is_some_and(|v| v != "1.0.0") {
        return Err(StatusCode::NOT_IMPLEMENTED);
    }
    Ok(())
}
pub fn routes() -> Router<Arc<StateData>> {
    Router::new()
      .route("/software/native/sources/{source}/{ring}/information",get(information))
      .route("/software/native/sources/{source}/{ring}/manifestSearch",post(search))
      .route("/software/native/sources/{source}/{ring}/packageManifests/{package}",get(manifest))
      .route("/software/native/sources/{source}/{ring}/exports/{publication}/information",get(frozen_information))
      .route("/software/native/sources/{source}/{ring}/exports/{publication}/manifestSearch",post(frozen_search))
      .route("/software/native/sources/{source}/{ring}/exports/{publication}/packageManifests/{package}",get(frozen_manifest))
      .route("/software/native/sources/{source}/{ring}/exports/{publication}/info/refs",get(refs))
      .route("/software/native/sources/{source}/{ring}/exports/{publication}/git-upload-pack",post(upload_pack))
      .route("/software/native/sources/{source}/artifacts/{resource}/{version}/{digest}/{*file}",get(artifact))
      .layer(axum::extract::DefaultBodyLimit::max(1024*1024))
      .layer(axum::middleware::from_fn(no_store))
}
async fn information(
    State(state): State<Arc<StateData>>,
    Path((source, r)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    let ring = ring(&r)?;
    let s = service(&state, &source)?;
    if !s.native_winget(ring) {
        return Err(StatusCode::NOT_FOUND);
    }
    contract(&headers)?;
    Ok(Json(
        json!({"Data":{"SourceIdentifier":s.native_identifier(ring,None),"ServerSupportedVersions":["1.0.0"]}}),
    ))
}
async fn frozen_information(
    State(state): State<Arc<StateData>>,
    Path((source, r, id)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    let ring = ring(&r)?;
    let id = digest(&id)?;
    let s = service(&state, &source)?;
    if !s.native_winget(ring) {
        return Err(StatusCode::NOT_FOUND);
    }
    contract(&headers)?;
    s.published(ring, id, cutoff()?).await.map_err(failure)?;
    Ok(Json(
        json!({"Data":{"SourceIdentifier":s.native_identifier(ring,Some(id)),"ServerSupportedVersions":["1.0.0"]}}),
    ))
}
#[derive(Clone, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct Match {
    key_word: String,
    match_type: String,
}
#[derive(Clone, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct Filter {
    package_match_field: String,
    request_match: Match,
}
#[derive(Clone, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct Search {
    maximum_results: Option<usize>,
    fetch_all_manifests: Option<bool>,
    query: Option<Match>,
    inclusions: Option<Vec<Filter>>,
    filters: Option<Vec<Filter>>,
}
impl Search {
    fn validate(&self) -> Result<usize, StatusCode> {
        if self.fetch_all_manifests == Some(true) {
            return Err(StatusCode::NOT_IMPLEMENTED);
        }
        let limit = self.maximum_results.unwrap_or(100);
        if limit == 0 || limit > 100 {
            return Err(StatusCode::BAD_REQUEST);
        }
        if self.inclusions.as_ref().is_some_and(|v| v.len() > 16)
            || self.filters.as_ref().is_some_and(|v| v.len() > 16)
        {
            return Err(StatusCode::BAD_REQUEST);
        }
        for f in self.inclusions.iter().chain(self.filters.iter()).flatten() {
            if !matches!(
                f.package_match_field.as_str(),
                "PackageIdentifier" | "PackageName" | "ProductCode"
            ) {
                return Err(StatusCode::NOT_IMPLEMENTED);
            }
        }
        for m in self.query.iter().chain(
            self.inclusions
                .iter()
                .chain(self.filters.iter())
                .flatten()
                .map(|f| &f.request_match),
        ) {
            if m.key_word.len() > 255 || m.key_word.contains(['\0', '\r', '\n']) {
                return Err(StatusCode::BAD_REQUEST);
            }
            if !matches!(
                m.match_type.as_str(),
                "Exact" | "CaseInsensitive" | "StartsWith" | "Substring"
            ) {
                return Err(StatusCode::NOT_IMPLEMENTED);
            }
        }
        Ok(limit)
    }
    fn matches(&self, package: &Value) -> bool {
        let value = |field: &str| match field {
            "ProductCode" => package["Versions"]
                .as_array()
                .into_iter()
                .flatten()
                .flat_map(|v| v["ProductCodes"].as_array().into_iter().flatten())
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>(),
            _ => package[field]
                .as_str()
                .map(|s| vec![s.into()])
                .unwrap_or_default(),
        };
        let matched = |m: &Match, v: &str| match m.match_type.as_str() {
            "Exact" => v == m.key_word,
            "CaseInsensitive" => v.eq_ignore_ascii_case(&m.key_word),
            "StartsWith" => v
                .to_ascii_lowercase()
                .starts_with(&m.key_word.to_ascii_lowercase()),
            "Substring" => v
                .to_ascii_lowercase()
                .contains(&m.key_word.to_ascii_lowercase()),
            _ => false,
        };
        let filter = |f: &Filter| {
            value(&f.package_match_field)
                .iter()
                .any(|v| matched(&f.request_match, v))
        };
        self.query.as_ref().is_none_or(|m| {
            ["PackageIdentifier", "PackageName"]
                .iter()
                .flat_map(|k| value(k))
                .any(|v| matched(m, &v))
        }) && self
            .inclusions
            .as_ref()
            .is_none_or(|fs| fs.is_empty() || fs.iter().any(filter))
            && self.filters.as_ref().is_none_or(|fs| fs.iter().all(filter))
    }
}
fn search_row(document: &ExportDocument) -> Result<Value, StatusCode> {
    let ExportDocument::Winget { manifest } = document else {
        return Err(StatusCode::NOT_FOUND);
    };
    let version = &manifest["Versions"][0];
    let locale = &version["DefaultLocale"];
    let product_codes = version["Installers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|i| i["ProductCode"].as_str())
        .collect::<std::collections::BTreeSet<_>>();
    Ok(
        json!({"PackageIdentifier":manifest["PackageIdentifier"],"PackageName":locale["PackageName"],"Publisher":locale["Publisher"],"Versions":[{"PackageVersion":version["PackageVersion"],"Channel":"","ProductCodes":product_codes}]}),
    )
}
async fn page(
    s: &PublicationService,
    ring: Ring,
    after: &str,
) -> Result<(Vec<(String, PublishedSoftware)>, Option<String>), StatusCode> {
    let cutoff = cutoff()?;
    let candidates = s
        .published_page(ring, after, 100, cutoff)
        .await
        .map_err(failure)?;
    let next =
        (candidates.len() == 100).then(|| candidates.last().expect("page nonempty").0.clone());
    let mut values = Vec::new();
    for (coordinate, id) in candidates {
        match s.published(ring, id, cutoff).await {
            Ok(v) => values.push((coordinate, v)),
            Err(p::Error::Content | p::Error::CandidateNotFound) => {}
            Err(e) => return Err(failure(e)),
        }
    }
    Ok((values, next))
}
async fn search(
    State(state): State<Arc<StateData>>,
    Path((source, r)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<Search>,
) -> Result<Json<Value>, StatusCode> {
    let _permit = state
        .requests
        .clone()
        .try_acquire_owned()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let ring = ring(&r)?;
    let s = service(&state, &source)?;
    if !s.native_winget(ring) {
        return Err(StatusCode::NOT_FOUND);
    }
    contract(&headers)?;
    let limit = input.validate()?;
    let after = headers
        .get("ContinuationToken")
        .map(|v| v.to_str().map_err(|_| StatusCode::BAD_REQUEST))
        .transpose()?
        .unwrap_or("");
    let (values, next) = page(s, ring, after).await?;
    search_results(
        &input,
        limit,
        values.into_iter().map(|(key, value)| (key, value.document)),
        next,
    )
}
fn search_results(
    input: &Search,
    limit: usize,
    values: impl IntoIterator<Item = (String, ExportDocument)>,
    mut next: Option<String>,
) -> Result<Json<Value>, StatusCode> {
    let mut rows = BTreeMap::<String, Value>::new();
    let mut consumed = String::new();
    for (coordinate, document) in values {
        let row = search_row(&document)?;
        if !input.matches(&row) {
            consumed = coordinate;
            continue;
        }
        let id = row["PackageIdentifier"]
            .as_str()
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
            .to_owned();
        if !rows.contains_key(&id) && rows.len() == limit {
            // Resume before the first omitted match, instead of skipping the rest of a DB page.
            next = Some(consumed);
            break;
        }
        consumed = coordinate;
        if let Some(existing) = rows.get_mut(&id) {
            existing["Versions"]
                .as_array_mut()
                .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
                .extend(
                    row["Versions"]
                        .as_array()
                        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
                        .clone(),
                );
        } else {
            rows.insert(id, row);
        }
    }
    let data: Vec<_> = rows.into_values().collect();
    Ok(Json(json!({"Data":data,"ContinuationToken":next})))
}

async fn frozen_search(
    State(state): State<Arc<StateData>>,
    Path((source, r, id)): Path<(String, String, String)>,
    headers: HeaderMap,
    Json(input): Json<Search>,
) -> Result<Json<Value>, StatusCode> {
    let ring = ring(&r)?;
    let s = service(&state, &source)?;
    if !s.native_winget(ring) {
        return Err(StatusCode::NOT_FOUND);
    }
    contract(&headers)?;
    input.validate()?;
    let value = s
        .published(ring, digest(&id)?, cutoff()?)
        .await
        .map_err(failure)?;
    let rows = std::iter::once(&value.document)
        .chain(value.dependencies.iter())
        .map(search_row)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|row| input.matches(row))
        .take(input.maximum_results.unwrap_or(100))
        .collect::<Vec<_>>();
    Ok(Json(json!({"Data":rows})))
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct VersionQuery {
    version: Option<String>,
}
async fn manifest(
    State(state): State<Arc<StateData>>,
    Path((source, r, package)): Path<(String, String, String)>,
    headers: HeaderMap,
    Query(query): Query<VersionQuery>,
) -> Result<Json<Value>, StatusCode> {
    let _permit = state
        .requests
        .clone()
        .try_acquire_owned()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let ring = ring(&r)?;
    let s = service(&state, &source)?;
    if !s.native_winget(ring) {
        return Err(StatusCode::NOT_FOUND);
    }
    contract(&headers)?;
    if package.is_empty()
        || package.len() > 256
        || package.contains('/')
        || query
            .version
            .as_ref()
            .is_some_and(|v| v.is_empty() || v.len() > 256 || v.contains('/'))
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let deadline = cutoff()?;
    let mut documents = Vec::new();
    if let Some(version) = &query.version {
        documents.push(
            s.published_coordinate(ring, &format!("{package}/{version}"), deadline)
                .await
                .map_err(failure)?
                .document,
        );
    } else {
        let prefix = format!("{package}/");
        let mut after = prefix.clone();
        'pages: loop {
            let rows = s
                .published_page(ring, &after, 100, deadline)
                .await
                .map_err(failure)?;
            let full = rows.len() == 100;
            for (coordinate, id) in rows {
                if !coordinate.starts_with(&prefix) {
                    break 'pages;
                }
                after = coordinate;
                let value = match s.published(ring, id, deadline).await {
                    Ok(value) => value,
                    Err(
                        rss_mdm_software_service::publication::Error::CandidateNotFound
                        | rss_mdm_software_service::publication::Error::Blocked,
                    ) => continue,
                    Err(error) => return Err(failure(error)),
                };
                if documents.len() == 128 {
                    return Err(StatusCode::SERVICE_UNAVAILABLE);
                }
                documents.push(value.document);
            }
            if !full {
                break;
            }
        }
    }
    manifest_response(documents, &package, query.version.as_deref())
}
async fn frozen_manifest(
    State(state): State<Arc<StateData>>,
    Path((source, r, id, package)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    Query(query): Query<VersionQuery>,
) -> Result<Json<Value>, StatusCode> {
    let ring = ring(&r)?;
    let s = service(&state, &source)?;
    if !s.native_winget(ring) {
        return Err(StatusCode::NOT_FOUND);
    }
    contract(&headers)?;
    let value = s
        .published(ring, digest(&id)?, cutoff()?)
        .await
        .map_err(failure)?;
    manifest_response(
        std::iter::once(value.document).chain(value.dependencies),
        &package,
        query.version.as_deref(),
    )
}
fn manifest_response(
    documents: impl IntoIterator<Item = ExportDocument>,
    package: &str,
    version: Option<&str>,
) -> Result<Json<Value>, StatusCode> {
    let mut versions = Vec::new();
    for document in documents {
        if let ExportDocument::Winget { manifest } = document
            && manifest["PackageIdentifier"] == package
        {
            for item in manifest["Versions"]
                .as_array()
                .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
            {
                if version.is_none_or(|v| item["PackageVersion"] == v) && !versions.contains(item) {
                    versions.push(item.clone());
                }
            }
        }
    }
    if versions.is_empty() {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(Json(
        json!({"Data":{"PackageIdentifier":package,"Versions":versions}}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GitQuery {
    service: String,
}
enum GitRead<'a> {
    Advertise(&'a str),
    Upload(&'a [u8]),
}
async fn refs(
    State(state): State<Arc<StateData>>,
    Path((source, r, id)): Path<(String, String, String)>,
    Query(query): Query<GitQuery>,
    headers: HeaderMap,
) -> Response {
    git(
        &state,
        &source,
        &r,
        &id,
        &headers,
        GitRead::Advertise(&query.service),
    )
    .await
    .unwrap_or_else(|e| e)
}
async fn upload_pack(
    State(state): State<Arc<StateData>>,
    Path((source, r, id)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    git(&state, &source, &r, &id, &headers, GitRead::Upload(&body))
        .await
        .unwrap_or_else(|e| e)
}
async fn git(
    state: &StateData,
    source: &str,
    r: &str,
    id: &str,
    headers: &HeaderMap,
    read: GitRead<'_>,
) -> Result<Response, Response> {
    let (advertise, body, protocol) = match read {
        GitRead::Advertise(service) => (true, &[][..], Some(service)),
        GitRead::Upload(bytes) => (false, bytes, None),
    };
    let _permit = state
        .requests
        .clone()
        .try_acquire_owned()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE.into_response())?;
    let ring = ring(r).map_err(IntoResponse::into_response)?;
    let s = service(state, source).map_err(IntoResponse::into_response)?;
    if s.native_winget(ring) {
        return Err(StatusCode::NOT_FOUND.into_response());
    }
    authenticated(s, ring, headers).map_err(|status| {
        (
            status,
            [(
                header::WWW_AUTHENTICATE,
                "Basic realm=\"RSS software read\"",
            )],
        )
            .into_response()
    })?;
    if advertise && protocol != Some("git-upload-pack") {
        return Err(StatusCode::FORBIDDEN.into_response());
    }
    if !advertise
        && headers
            .get(header::CONTENT_TYPE)
            .is_none_or(|v| v != "application/x-git-upload-pack-request")
    {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response());
    }
    let v2 = match headers.get("Git-Protocol") {
        None => false,
        Some(v) if v == "version=2" => true,
        Some(v) if v == "version=1" => false,
        _ => return Err(StatusCode::BAD_REQUEST.into_response()),
    };
    let bytes = s
        .upload_pack(
            ring,
            digest(
                id.strip_suffix(".git")
                    .ok_or_else(|| StatusCode::NOT_FOUND.into_response())?,
            )
            .map_err(IntoResponse::into_response)?,
            advertise,
            v2,
            body,
            cutoff().map_err(IntoResponse::into_response)?,
        )
        .await
        .map_err(|e| failure(e).into_response())?;
    let bytes = if advertise {
        [b"001e# service=git-upload-pack\n0000".as_slice(), &bytes].concat()
    } else {
        bytes
    };
    Ok((
        [
            (
                header::CONTENT_TYPE,
                if advertise {
                    "application/x-git-upload-pack-advertisement"
                } else {
                    "application/x-git-upload-pack-result"
                },
            ),
            (header::CACHE_CONTROL, "no-store"),
        ],
        bytes,
    )
        .into_response())
}
async fn artifact(
    State(state): State<Arc<StateData>>,
    Path((source, resource, version, expected, file)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
    headers: HeaderMap,
) -> Response {
    let deadline = match cutoff() {
        Ok(value) => value,
        Err(status) => return status.into_response(),
    };
    let result = async {
        let s = service(&state, &source).map_err(IntoResponse::into_response)?;
        let expected = digest(&expected).map_err(IntoResponse::into_response)?;
        let content = state
            .content
            .as_ref()
            .ok_or_else(|| StatusCode::SERVICE_UNAVAILABLE.into_response())?;
        let credential = token(&headers);
        let mut authorized = false;
        for ring in [Ring::Test, Ring::Pilot, Ring::Production] {
            if !s.native_read_allowed(ring, credential.as_deref()) {
                continue;
            }
            authorized = true;
            let values = s
                .published_resource(ring, &resource, &version, deadline)
                .await
                .map_err(|e| failure(e).into_response())?;
            for value in values {
                if value.resource != resource
                    || value.version != version
                    || value.resource_digest != expected
                {
                    continue;
                }
                for a in &value.artifacts {
                    let url = url::Url::parse(&a.url)
                        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE.into_response())?;
                    let encoded = file
                        .split('/')
                        .map(|s| {
                            url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>()
                        })
                        .collect::<Vec<_>>()
                        .join("/");
                    let suffix =
                        format!("/{resource}/{version}/{}/{encoded}", super_hex(&expected));
                    if !url.path().ends_with(&suffix) {
                        continue;
                    }
                    let descriptor = rss_mdm_resource::Artifact::new(
                        rss_mdm_resource::Id::new(&a.key)
                            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE.into_response())?,
                        a.length,
                        rss_mdm_resource::Digest::from_bytes(a.sha256),
                    )
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE.into_response())?;
                    let verified = content
                        .verify(&descriptor)
                        .await
                        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE.into_response())?;
                    s.published(ring, value.publication, deadline)
                        .await
                        .map_err(|e| failure(e).into_response())?;
                    return crate::content::http::response(verified, &headers)
                        .await
                        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE.into_response());
                }
            }
        }
        if !authorized {
            return Err((
                StatusCode::UNAUTHORIZED,
                [(
                    header::WWW_AUTHENTICATE,
                    "Basic realm=\"RSS software read\"",
                )],
            )
                .into_response());
        }
        Err(StatusCode::NOT_FOUND.into_response())
    };
    let result = match tokio::time::timeout_at(deadline.instant().into(), result).await {
        Ok(result) => result,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    result.unwrap_or_else(|e| e)
}
fn super_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

async fn no_store(request: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn maximum_results_resumes_before_the_first_omitted_package() {
        let request: Search = serde_json::from_value(json!({"MaximumResults":1})).unwrap();
        let document = |name: &str| ExportDocument::Winget {
            manifest: json!({"PackageIdentifier":name,"Versions":[{"PackageVersion":"1","DefaultLocale":{"PackageName":name,"Publisher":"Acme"},"Installers":[]}]}),
        };
        let Json(first) = search_results(
            &request,
            1,
            [
                ("Acme.A/1".into(), document("Acme.A")),
                ("Acme.B/1".into(), document("Acme.B")),
            ],
            None,
        )
        .unwrap();
        assert_eq!(first["Data"][0]["PackageIdentifier"], "Acme.A");
        assert_eq!(first["ContinuationToken"], "Acme.A/1");
        let Json(next) =
            search_results(&request, 1, [("Acme.B/1".into(), document("Acme.B"))], None).unwrap();
        assert_eq!(next["Data"][0]["PackageIdentifier"], "Acme.B");
        assert!(next["ContinuationToken"].is_null());
    }

    #[test]
    fn native_query_never_ignores_unsupported_constraints() {
        let query:Search=serde_json::from_value(json!({"Query":{"KeyWord":"Acme.App","MatchType":"CaseInsensitive"},"MaximumResults":1})).unwrap();
        query.validate().unwrap();
        assert!(
            query.matches(
                &json!({"PackageIdentifier":"acme.app","PackageName":"Acme","Versions":[]})
            )
        );
        for value in [
            json!({"FetchAllManifests":true}),
            json!({"Query":{"KeyWord":"x","MatchType":"Fuzzy"}}),
            json!({"Filters":[{"PackageMatchField":"Command","RequestMatch":{"KeyWord":"x","MatchType":"Exact"}}]}),
        ] {
            let query: Search = serde_json::from_value(value).unwrap();
            assert!(query.validate().is_err());
        }
        assert!(serde_json::from_value::<Search>(json!({"Alias":"other"})).is_err());
    }
    #[test]
    fn brew_credentials_require_the_scoped_username_and_remain_out_of_urls() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            axum::http::HeaderValue::from_static("Basic d3JpdGVyOm5vdC1hLXJlYWQtdG9rZW4="),
        );
        assert!(token(&headers).is_none());
        assert!(digest("../secret").is_err());
        let access = rss_mdm_software_service::BrewReadAccess::new(
            rss_request_context::TenantId::parse("10000000-0000-0000-0000-000000000001").unwrap(),
            "brew",
            "source-read-token-2531-00000000000",
        )
        .unwrap();
        assert!(access.permits(
            rss_request_context::TenantId::parse("10000000-0000-0000-0000-000000000001").unwrap(),
            "brew",
            "source-read-token-2531-00000000000"
        ));
        assert!(!access.permits(
            rss_request_context::TenantId::parse("10000000-0000-0000-0000-000000000001").unwrap(),
            "other",
            "source-read-token-2531-00000000000"
        ));
    }
}
