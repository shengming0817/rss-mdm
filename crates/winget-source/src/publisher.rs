//! Controlled WinGet 1.0 writes. No overwrite/PUT fallback; responses are not publication facts.
use crate::*;
use reqwest::{Method, header::HeaderValue};
/// Service credential for the selected management API header; never a URL query key.
pub struct WriteAccess {
    tenant: TenantId,
    source: String,
    reference: String,
    key: HeaderValue,
}
impl WriteAccess {
    pub fn new(tenant: TenantId, source: &str, reference: &str, key: &str) -> Result<Self, Error> {
        identity(source)?;
        identity(reference)?;
        if key.is_empty()
            || key.len() > 8192
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~+/=".contains(&b))
        {
            return Err(Error::InvalidInput);
        }
        let mut value = HeaderValue::from_str(key).map_err(|_| Error::InvalidInput)?;
        value.set_sensitive(true);
        Ok(Self {
            tenant,
            source: source.into(),
            reference: reference.into(),
            key: value,
        })
    }
}
impl fmt::Debug for WriteAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WriteAccess([redacted])")
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Inspection {
    Matching,
    Absent,
    Different,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteResponse {
    Accepted,
    Conflict,
    Absent,
}
pub struct Publisher {
    client: Client,
}
impl Publisher {
    pub fn new(source: Source) -> Result<Self, Error> {
        Ok(Self {
            client: Client::new(source)?,
        })
    }
    fn check(&self, m: &VersionManifest, a: &WriteAccess) -> Result<(), Error> {
        let s = &self.client.source;
        if m.tenant() != s.tenant || a.tenant != s.tenant {
            return Err(Error::TenantMismatch);
        }
        if m.source() != s.id || a.source != s.id || a.reference != s.credential_ref {
            return Err(Error::IdentityMismatch);
        }
        Ok(())
    }
    pub async fn submit(
        &self,
        m: &VersionManifest,
        a: &WriteAccess,
    ) -> Result<WriteResponse, Error> {
        self.check(m, a)?;
        tokio::time::timeout(self.client.total, async {
            self.information(a).await?;
            let (status, _) = self
                .request(
                    Method::POST,
                    "packageManifests",
                    None,
                    Some(m.bytes()),
                    a,
                    RequestStage::Publish,
                )
                .await?;
            match status {
                201 => Ok(WriteResponse::Accepted),
                409 => Ok(WriteResponse::Conflict),
                _ => Err(Error::HttpStatus {
                    stage: RequestStage::Publish,
                    status,
                }),
            }
        })
        .await
        .map_err(|_| Error::Timeout(RequestStage::Publish))?
    }
    pub async fn inspect(&self, m: &VersionManifest, a: &WriteAccess) -> Result<Inspection, Error> {
        self.check(m, a)?;
        tokio::time::timeout(self.client.total, async {
            self.information(a).await?;
            let (status, bytes) = self
                .request(
                    Method::GET,
                    &format!("packageManifests/{}", m.package()),
                    Some(m.version()),
                    None,
                    a,
                    RequestStage::Reconcile,
                )
                .await?;
            if status == 404 {
                return Ok(Inspection::Absent);
            }
            if status != 200 {
                return Err(Error::HttpStatus {
                    stage: RequestStage::Reconcile,
                    status,
                });
            }
            let actual = VersionManifest::from_response(m.tenant(), m.source(), &bytes)?;
            Ok(if actual == *m {
                Inspection::Matching
            } else {
                Inspection::Different
            })
        })
        .await
        .map_err(|_| Error::Timeout(RequestStage::Reconcile))?
    }
    /// Call only after serialized ownership checks. No package-wide delete is exposed.
    pub async fn withdraw(
        &self,
        m: &VersionManifest,
        a: &WriteAccess,
    ) -> Result<WriteResponse, Error> {
        self.check(m, a)?;
        tokio::time::timeout(self.client.total, async {
            self.information(a).await?;
            let (status, _) = self
                .request(
                    Method::DELETE,
                    &format!("packages/{}/versions/{}", m.package(), m.version()),
                    None,
                    None,
                    a,
                    RequestStage::Withdraw,
                )
                .await?;
            match status {
                204 => Ok(WriteResponse::Accepted),
                404 => Ok(WriteResponse::Absent),
                _ => Err(Error::HttpStatus {
                    stage: RequestStage::Withdraw,
                    status,
                }),
            }
        })
        .await
        .map_err(|_| Error::Timeout(RequestStage::Withdraw))?
    }
    async fn information(&self, a: &WriteAccess) -> Result<(), Error> {
        let (status, bytes) = self
            .request(
                Method::GET,
                "information",
                None,
                None,
                a,
                RequestStage::Information,
            )
            .await?;
        if status != 200 {
            return Err(Error::HttpStatus {
                stage: RequestStage::Information,
                status,
            });
        }
        let v: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| Error::InvalidResponse)?;
        if v["Data"]["SourceIdentifier"].as_str() != Some(&self.client.source.id) {
            return Err(Error::IdentityMismatch);
        }
        if v["Data"].get("Authentication").is_some()
            || !v["Data"]["ServerSupportedVersions"]
                .as_array()
                .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(CONTRACT_VERSION)))
        {
            return Err(Error::Unsupported);
        }
        Ok(())
    }
    async fn request(
        &self,
        method: Method,
        path: &str,
        version: Option<&str>,
        body: Option<&[u8]>,
        a: &WriteAccess,
        stage: RequestStage,
    ) -> Result<(u16, Vec<u8>), Error> {
        let mut url = self.client.source.base.clone();
        {
            let mut segments = url.path_segments_mut().map_err(|_| Error::InvalidInput)?;
            segments.pop_if_empty();
            for p in path.split('/') {
                segments.push(p);
            }
        }
        if let Some(v) = version {
            url.query_pairs_mut().append_pair("Version", v);
        }
        let mut request = self
            .client
            .http
            .request(method, url)
            .header("Version", CONTRACT_VERSION)
            .header("Accept", "application/json")
            .header("x-functions-key", a.key.clone());
        if let Some(body) = body {
            request = request
                .header("Content-Type", "application/json")
                .body(body.to_vec());
        }
        let mut response = request.send().await.map_err(|_| Error::Transport(stage))?;
        let status = response.status().as_u16();
        if response
            .content_length()
            .is_some_and(|n| n > MAX_RESPONSE as u64)
        {
            return Err(Error::BudgetExceeded);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| Error::Transport(stage))?
        {
            if chunk.len() > MAX_RESPONSE - bytes.len() {
                return Err(Error::BudgetExceeded);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok((status, bytes))
    }
}
