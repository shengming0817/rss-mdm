//! Restricted RustFS identity preparation and S3 workload qualification.
//! ref: rustfs/rustfs 1.0.0 rustfs/src/admin/handlers/{user,policies}.rs.
use super::super::{Error, Result, local::Journal};
use super::signed_http::Client;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::PathBuf;
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub id: String,
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub namespace: String,
    pub ca_file: PathBuf,
    pub rustfs_administrator: Option<Administrator>,
    pub boundary_verifier: Option<Administrator>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Administrator {
    pub access_key_file: PathBuf,
    pub secret_key_file: PathBuf,
    pub session_token_file: Option<PathBuf>,
}
/// Generated or imported in the encrypted domain owner before any external side effect.
/// This type has no Debug or Serialize implementation.
pub struct Workload {
    pub create_identity: bool,
    pub access: Zeroizing<String>,
    pub secret: Zeroizing<String>,
    pub token: Option<Zeroizing<String>>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Evidence {
    pub operation: uuid::Uuid,
    pub tenant: uuid::Uuid,
    pub endpoint: String,
    pub bucket: String,
    pub namespace: String,
    pub policy_digest: String,
    pub qualified: bool,
    pub qualified_at: i64,
}
fn namespace(profile: &Profile, tenant: uuid::Uuid) -> Result<String> {
    if tenant.is_nil()
        || profile.bucket.len() < 3
        || profile.bucket.len() > 63
        || !profile
            .bucket
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-".contains(&b))
        || profile.namespace.is_empty()
        || profile.namespace.len() > 512
        || !profile
            .namespace
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._/".contains(&b))
        || profile
            .namespace
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(Error::Input);
    }
    Ok(format!("{}/{}", profile.namespace, tenant))
}
fn policy(bucket: &str, namespace: &str) -> Value {
    json!({"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Action":["s3:GetBucketVersioning"],"Resource":[format!("arn:aws:s3:::{bucket}")]},
        {"Effect":"Allow","Action":["s3:ListBucketMultipartUploads"],"Resource":[format!("arn:aws:s3:::{bucket}")],"Condition":{"StringLike":{"s3:prefix":[format!("{namespace}/*")]}}},
        {"Effect":"Allow","Action":["s3:PutObject","s3:GetObject","s3:GetObjectVersion","s3:DeleteObjectVersion","s3:AbortMultipartUpload","s3:ListMultipartUploadParts"],"Resource":[format!("arn:aws:s3:::{bucket}/{namespace}/*")]}
    ]})
}

fn canonical_policy(mut value: Value) -> Value {
    match &mut value {
        Value::Object(values) => {
            for name in ["Id", "Sid"] {
                if values
                    .get(name)
                    .is_some_and(|v| v.is_null() || v.as_str() == Some(""))
                {
                    values.remove(name);
                }
            }
            for (name, value) in values.iter_mut() {
                if matches!(name.as_str(), "Action" | "Resource" | "s3:prefix") && value.is_string()
                {
                    *value = json!([value.clone()]);
                }
                *value = canonical_policy(value.take());
            }
        }
        Value::Array(values) => {
            for value in values.iter_mut() {
                *value = canonical_policy(value.take());
            }
            values.sort_by_key(Value::to_string);
        }
        _ => (),
    }
    value
}
#[derive(Deserialize)]
struct UserInfo {
    status: String,
    #[serde(rename = "policyName")]
    policy: Option<String>,
    #[serde(default, rename = "memberOf")]
    groups: Vec<String>,
    #[serde(rename = "secretKey")]
    _secret: Option<Zeroizing<String>>,
}
async fn user(client: &Client, access: &str) -> Result<Option<UserInfo>> {
    let response = client
        .request(
            Method::GET,
            "/rustfs/admin/v3/user-info",
            &[("accessKey", access)],
            &[],
            "application/json",
        )
        .await?;
    if response.status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !response.status.is_success() {
        return Err(Error::Storage);
    }
    serde_json::from_slice(&response.body)
        .map(Some)
        .map_err(|_| Error::Input)
}
async fn prepare_identity(
    profile: &Profile,
    material: &Workload,
    ca: &[u8],
    tenant: uuid::Uuid,
    expected: &Value,
) -> Result<()> {
    let admin = profile.rustfs_administrator.as_ref().ok_or(Error::Input)?;
    let client = Client::new(
        &profile.endpoint,
        &profile.region,
        ca,
        crate::config::secret(&admin.access_key_file).map_err(|_| Error::Input)?,
        crate::config::secret(&admin.secret_key_file).map_err(|_| Error::Input)?,
        admin
            .session_token_file
            .as_ref()
            .map(|p| crate::config::secret(p).map_err(|_| Error::Input))
            .transpose()?,
    )?;
    let name = format!("rss-mdm-{}", tenant.simple());
    let response = client
        .request(
            Method::GET,
            "/rustfs/admin/v3/list-canned-policies",
            &[],
            &[],
            "application/json",
        )
        .await?;
    if !response.status.is_success() {
        return Err(Error::Storage);
    }
    let policies: std::collections::BTreeMap<String, Value> =
        serde_json::from_slice(&response.body).map_err(|_| Error::Input)?;
    if let Some(policy) = policies.get(&name) {
        if canonical_policy(policy.clone()) != canonical_policy(expected.clone()) {
            return Err(Error::Conflict);
        }
    } else {
        let body = serde_json::to_vec(expected).map_err(|_| Error::Input)?;
        let _ = client
            .request(
                Method::PUT,
                "/rustfs/admin/v3/add-canned-policy",
                &[("name", &name)],
                &body,
                "application/json",
            )
            .await;
    }
    // Readback also resolves a lost create response; never replace a differently configured policy.
    let response = client
        .request(
            Method::GET,
            "/rustfs/admin/v3/info-canned-policy",
            &[("name", &name)],
            &[],
            "application/json",
        )
        .await?;
    if !response.status.is_success() {
        return Err(Error::Storage);
    }
    let actual: Value = serde_json::from_slice(&response.body).map_err(|_| Error::Input)?;
    if actual["policy_name"] != name
        || canonical_policy(actual["policy"].clone()) != canonical_policy(expected.clone())
    {
        return Err(Error::Conflict);
    }
    if user(&client, &material.access).await?.is_none() {
        #[derive(Serialize)]
        struct Create<'a> {
            #[serde(rename = "secretKey")]
            secret: &'a str,
            status: &'static str,
        }
        let body = Zeroizing::new(
            serde_json::to_vec(&Create {
                secret: &material.secret,
                status: "enabled",
            })
            .map_err(|_| Error::Input)?,
        );
        let _ = client
            .request(
                Method::PUT,
                "/rustfs/admin/v3/add-user",
                &[("accessKey", &material.access)],
                &body,
                "application/json",
            )
            .await;
    }
    let state = user(&client, &material.access)
        .await?
        .ok_or(Error::Storage)?;
    if state.status != "enabled" || !state.groups.is_empty() {
        return Err(Error::Conflict);
    }
    match state.policy.as_deref() {
        None | Some("") => {
            let _ = client
                .request(
                    Method::PUT,
                    "/rustfs/admin/v3/set-user-or-group-policy",
                    &[
                        ("policyName", &name),
                        ("userOrGroup", &material.access),
                        ("isGroup", "false"),
                    ],
                    &[],
                    "application/json",
                )
                .await;
        }
        Some(policy) if policy == name => (),
        Some(_) => return Err(Error::Conflict),
    }
    let state = user(&client, &material.access)
        .await?
        .ok_or(Error::Storage)?;
    if state.status != "enabled"
        || state.policy.as_deref() != Some(name.as_str())
        || !state.groups.is_empty()
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
struct Secrets {
    access: Zeroizing<String>,
    secret: Zeroizing<String>,
    token: Option<Zeroizing<String>>,
}
impl rss_mdm_content_s3::Secrets for Secrets {
    fn resolve(
        &self,
        reference: &str,
    ) -> rss_mdm_content_s3::Result<rss_mdm_content_s3::Credentials> {
        if reference != "qualification" {
            return Err(rss_mdm_content_s3::Error::Configuration);
        }
        rss_mdm_content_s3::Credentials::new(
            self.access.to_string(),
            self.secret.to_string(),
            self.token.as_ref().map(|v| v.to_string()),
            None,
        )
    }
}
fn budget() -> Result<rss_mdm_content_s3::Budget> {
    rss_mdm_content_s3::Budget::new(
        std::sync::Arc::new(crate::lifecycle::RuntimeTimer),
        std::time::Duration::from_secs(12),
        std::time::Duration::from_secs(4),
        4096,
        8,
    )
    .map_err(|_| Error::Input)
}
async fn store(
    profile: &Profile,
    namespace: String,
    ca: &[u8],
    material: &Workload,
) -> Result<rss_mdm_content_s3::Store> {
    let config = rss_mdm_content_s3::Config {
        endpoint: profile.endpoint.clone(),
        region: profile.region.clone(),
        bucket: profile.bucket.clone(),
        namespace,
        credentials_reference: "qualification".into(),
        private_ca_pem: Some(ca.to_vec()),
        max_concurrent: 1,
        connect_timeout: std::time::Duration::from_secs(4),
    };
    rss_mdm_content_s3::Store::connect(
        config,
        std::sync::Arc::new(Secrets {
            access: material.access.clone(),
            secret: material.secret.clone(),
            token: material.token.clone(),
        }),
        std::sync::Arc::new(crate::lifecycle::RuntimeTimer),
        budget()?,
    )
    .await
    .map_err(|_| Error::Storage)
}
async fn probe(
    store: &rss_mdm_content_s3::Store,
    journal: &Journal,
    name: &str,
    operation: uuid::Uuid,
    body: &[u8],
) -> Result<rss_mdm_content_s3::Verified> {
    use rss_mdm_content_s3::{Content, Mutation, Recovery, Written};
    use sha2::{Digest, Sha256};
    let content = Content {
        length: body.len() as u64,
        sha256: Sha256::digest(body).into(),
    };
    let write = store
        .write(
            store
                .target(&format!("{name}-{operation}.probe"))
                .map_err(|_| Error::Input)?,
            &operation.to_string(),
            content,
        )
        .map_err(|_| Error::Input)?;
    journal.secret(
        &format!("{name}-intent.json"),
        &serde_json::to_vec(&write).map_err(|_| Error::Input)?,
    )?;
    if let Some(object) = journal.load(&format!("{name}-object.json"))? {
        return store
            .verify(&object, content, budget()?)
            .await
            .map_err(|_| Error::Storage);
    }
    let recovered = store
        .recover(&write, budget()?)
        .await
        .map_err(|_| Error::Storage)?;
    let written = match recovered {
        Recovery::Matched(value) => value,
        Recovery::Unresolved => {
            let bytes = axum::body::Bytes::copy_from_slice(body);
            let stream: rss_mdm_content_s3::ByteStreamInput =
                Box::pin(futures::stream::once(async move { Ok(bytes) }));
            match store
                .put(&write, stream, budget()?)
                .await
                .map_err(|_| Error::Storage)?
            {
                Mutation::Confirmed(value) => value,
                Mutation::Unknown(_) => return Err(Error::Storage),
            }
        }
    };
    let object = match written {
        Written::Verified(value) => value,
        Written::Unverified { .. } => return Err(Error::Storage),
    };
    journal.save(&format!("{name}-object.json"), object.object())?;
    Ok(object)
}
/// Both automatic identity creation and imported credentials must pass real versioned I/O and
/// denial against an independently verified, existing object outside the tenant prefix.
pub async fn prepare(
    directory: &std::path::Path,
    profile: &Profile,
    tenant: uuid::Uuid,
    operation: uuid::Uuid,
    material: &Workload,
) -> Result<Evidence> {
    use sha2::{Digest, Sha256};
    if operation.is_nil() {
        return Err(Error::Input);
    }
    let namespace = namespace(profile, tenant)?;
    let ca = crate::config::read(&profile.ca_file, 1024 * 1024, false).map_err(|_| Error::Input)?;
    let journal = Journal::open(&directory.join(format!("storage-{operation}")))?;
    journal.secret(
        "input.json",
        &serde_json::to_vec(&(
            profile.id.as_str(),
            &profile.endpoint,
            &profile.region,
            &profile.bucket,
            &namespace,
            format!("{:x}", Sha256::digest(&ca)),
            material.access.as_str(),
            material.create_identity,
        ))
        .map_err(|_| Error::Input)?,
    )?;
    let binding = Zeroizing::new(
        serde_json::to_vec(&(
            profile.id.as_str(),
            &namespace,
            material.access.as_str(),
            material.token.as_deref(),
        ))
        .map_err(|_| Error::Input)?,
    );
    let tag = ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, material.secret.as_bytes()),
        &binding,
    );
    journal.secret("credential-binding", tag.as_ref())?;
    if let Some(evidence) = journal.load("qualified.json")? {
        return Ok(evidence);
    }
    let expected = policy(&profile.bucket, &namespace);
    if material.create_identity {
        prepare_identity(profile, material, &ca, tenant, &expected).await?;
    }
    let workload = store(profile, namespace.clone(), &ca, material).await?;
    let verifier = profile
        .boundary_verifier
        .as_ref()
        .or(profile.rustfs_administrator.as_ref())
        .ok_or(Error::Input)?;
    let verifier = Workload {
        create_identity: false,
        access: crate::config::secret(&verifier.access_key_file).map_err(|_| Error::Input)?,
        secret: crate::config::secret(&verifier.secret_key_file).map_err(|_| Error::Input)?,
        token: verifier
            .session_token_file
            .as_ref()
            .map(|p| crate::config::secret(p).map_err(|_| Error::Input))
            .transpose()?,
    };
    let foreign_namespace = format!("{}/.rss-qualification", profile.namespace);
    let boundary = store(profile, foreign_namespace.clone(), &ca, &verifier).await?;
    let body = format!("rss-mdm-storage:{tenant}:{operation}");
    let foreign = probe(&boundary, &journal, "boundary", operation, body.as_bytes()).await?;
    let client = Client::new(
        &profile.endpoint,
        &profile.region,
        &ca,
        material.access.clone(),
        material.secret.clone(),
        material.token.clone(),
    )?;
    let denied = client
        .request(
            Method::HEAD,
            &format!(
                "/{}/{}/boundary-{}.probe",
                profile.bucket, foreign_namespace, operation
            ),
            &[("versionId", foreign.object().version())],
            &[],
            "application/octet-stream",
        )
        .await?;
    if denied.status != reqwest::StatusCode::FORBIDDEN {
        return Err(Error::Conflict);
    }
    qualify_workload(&workload, &journal, operation, body.as_bytes()).await?;
    // Exact probe versions are retained as qualification evidence for recovery/re-observation;
    // they are not inferred from mutable current objects or a successful metadata-only request.
    let evidence = Evidence {
        operation,
        tenant,
        endpoint: profile.endpoint.clone(),
        bucket: profile.bucket.clone(),
        namespace,
        policy_digest: format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&canonical_policy(expected)).map_err(|_| Error::Input)?
            )
        ),
        qualified: true,
        qualified_at: crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)
            .map_err(|_| Error::Storage)?,
    };
    journal.save("qualified.json", &evidence)?;
    Ok(evidence)
}

async fn qualify_workload(
    workload: &rss_mdm_content_s3::Store,
    journal: &Journal,
    operation: uuid::Uuid,
    body: &[u8],
) -> Result<()> {
    use futures::StreamExt;
    let own = probe(workload, journal, "workload", operation, body).await?;
    let mut stream = workload
        .read(&own, 0, body.len() as u64, budget()?)
        .await
        .map_err(|_| Error::Storage)?;
    let mut actual = Vec::new();
    while let Some(bytes) = stream.next().await {
        actual.extend_from_slice(&bytes.map_err(|_| Error::Storage)?);
        if actual.len() > 4096 {
            return Err(Error::Storage);
        }
    }
    if actual != body {
        return Err(Error::Conflict);
    }
    let cleanup_name = "cleanup-object.json";
    let cleanup = if let Some(object) = journal.load::<rss_mdm_content_s3::Object>(cleanup_name)? {
        object
    } else {
        probe(workload, journal, "cleanup", operation, body)
            .await?
            .object()
            .clone()
    };
    match workload
        .delete(&cleanup, budget()?)
        .await
        .map_err(|_| Error::Storage)?
    {
        rss_mdm_content_s3::Mutation::Confirmed(()) => (),
        rss_mdm_content_s3::Mutation::Unknown(_) => return Err(Error::Storage),
    }
    if !matches!(
        workload.inspect(&cleanup, budget()?).await,
        Err(rss_mdm_content_s3::Error::Missing)
    ) {
        return Err(Error::Storage);
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/setup/providers.rs"]
mod tests;
