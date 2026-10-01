//! Bounded output transport on the existing task event channel, with one immutable manifest.
use crate::{OutputQuality, TaskDiagnostics, TaskResult, WireError};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
/// Maximum canonical structured output per template execution.
pub const OUTPUT_MAX_BYTES: usize = 16 * 1024 * 1024;
/// Raw bytes in every non-final chunk.
pub const OUTPUT_CHUNK_BYTES: usize = 256 * 1024;
/// Immutable output identity; chunk count is derived from byte length.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ManifestInput", into = "ManifestInput")]
pub struct OutputManifest(ManifestInput);
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ManifestInput {
    bytes: u32,
    sha256: [u8; 32],
}
impl From<OutputManifest> for ManifestInput {
    fn from(v: OutputManifest) -> Self {
        v.0
    }
}
impl TryFrom<ManifestInput> for OutputManifest {
    type Error = WireError;
    fn try_from(v: ManifestInput) -> Result<Self, WireError> {
        Self::new(v.bytes, v.sha256)
    }
}
impl OutputManifest {
    /// Validate the total size before allocating or receiving any output.
    pub fn new(bytes: u32, sha256: [u8; 32]) -> Result<Self, WireError> {
        if bytes == 0 || bytes as usize > OUTPUT_MAX_BYTES {
            return Err(WireError::InvalidValue);
        }
        Ok(Self(ManifestInput { bytes, sha256 }))
    }
    /// Canonical JSON byte length.
    pub fn bytes(&self) -> u32 {
        self.0.bytes
    }
    /// SHA-256 of the full canonical JSON output.
    pub fn sha256(&self) -> [u8; 32] {
        self.0.sha256
    }
    /// Exact number of required chunks.
    pub fn count(&self) -> usize {
        (self.0.bytes as usize).div_ceil(OUTPUT_CHUNK_BYTES)
    }
}
/// Exactly one position in a manifest; duplicate positions must contain identical bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ChunkInput", into = "ChunkInput")]
pub struct OutputChunk(ChunkInput);
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChunkInput {
    manifest: OutputManifest,
    index: u16,
    data: String,
}
impl From<OutputChunk> for ChunkInput {
    fn from(v: OutputChunk) -> Self {
        v.0
    }
}
impl TryFrom<ChunkInput> for OutputChunk {
    type Error = WireError;
    fn try_from(v: ChunkInput) -> Result<Self, WireError> {
        if v.data.len() > OUTPUT_CHUNK_BYTES.div_ceil(3) * 4 {
            return Err(WireError::InvalidValue);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(&v.data)
            .map_err(|_| WireError::InvalidValue)?;
        if URL_SAFE_NO_PAD.encode(&bytes) != v.data {
            return Err(WireError::InvalidValue);
        }
        Self::new(v.manifest, v.index, &bytes)
    }
}
impl OutputChunk {
    /// Bind a byte slice to its exact manifest position.
    pub fn new(manifest: OutputManifest, index: u16, bytes: &[u8]) -> Result<Self, WireError> {
        let offset = usize::from(index) * OUTPUT_CHUNK_BYTES;
        if offset >= manifest.bytes() as usize
            || bytes.len() != (manifest.bytes() as usize - offset).min(OUTPUT_CHUNK_BYTES)
        {
            return Err(WireError::InvalidValue);
        }
        Ok(Self(ChunkInput {
            manifest,
            index,
            data: URL_SAFE_NO_PAD.encode(bytes),
        }))
    }
    /// Full output identity shared by all chunks.
    pub fn manifest(&self) -> &OutputManifest {
        &self.0.manifest
    }
    /// Zero-based immutable position.
    pub fn index(&self) -> u16 {
        self.0.index
    }
    /// Recover validated raw bytes.
    pub fn bytes(&self) -> Vec<u8> {
        URL_SAFE_NO_PAD
            .decode(&self.0.data)
            .expect("validated canonical base64")
    }
}
/// Terminal process evidence referencing an assembled output; missing chunks cannot be complete.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ResultInput", into = "ResultInput")]
pub struct ChunkedTaskResult(ResultInput);
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResultInput {
    #[serde(deserialize_with = "crate::tasks::required_option")]
    exit_code: Option<i32>,
    quality: OutputQuality,
    diagnostics: TaskDiagnostics,
    manifest: OutputManifest,
}
impl From<ChunkedTaskResult> for ResultInput {
    fn from(v: ChunkedTaskResult) -> Self {
        v.0
    }
}
impl TryFrom<ResultInput> for ChunkedTaskResult {
    type Error = WireError;
    fn try_from(v: ResultInput) -> Result<Self, WireError> {
        TaskResult::new(
            v.exit_code,
            v.quality,
            serde_json::Value::Null,
            v.diagnostics.clone(),
        )?;
        Ok(Self(v))
    }
}
impl ChunkedTaskResult {
    /// Freeze a validated result into one terminal reference and bounded transport chunks.
    pub fn split(result: TaskResult) -> Result<(Self, Vec<OutputChunk>), WireError> {
        let bytes = serde_json::to_vec(result.output()).map_err(|_| WireError::InvalidValue)?;
        let manifest = OutputManifest::new(
            bytes
                .len()
                .try_into()
                .map_err(|_| WireError::InvalidValue)?,
            Sha256::digest(&bytes).into(),
        )?;
        let chunks = bytes
            .chunks(OUTPUT_CHUNK_BYTES)
            .enumerate()
            .map(|(index, bytes)| OutputChunk::new(manifest.clone(), index as u16, bytes))
            .collect::<Result<_, _>>()?;
        Ok((
            Self(ResultInput {
                exit_code: result.exit_code(),
                quality: result.quality(),
                diagnostics: result.diagnostics().clone(),
                manifest,
            }),
            chunks,
        ))
    }
    /// Full output manifest, independent of HTTP request retry identities.
    pub fn manifest(&self) -> &OutputManifest {
        &self.0.manifest
    }
    /// Verify every position and the full digest before accepting a terminal output.
    pub fn assemble(&self, mut chunks: Vec<OutputChunk>) -> Result<TaskResult, WireError> {
        if chunks.len() != self.0.manifest.count() {
            return Err(WireError::InvalidValue);
        }
        chunks.sort_by_key(OutputChunk::index);
        let mut bytes = Vec::with_capacity(self.0.manifest.bytes() as usize);
        for (index, chunk) in chunks.into_iter().enumerate() {
            if usize::from(chunk.index()) != index || chunk.manifest() != &self.0.manifest {
                return Err(WireError::InvalidValue);
            }
            bytes.extend(chunk.bytes());
        }
        if bytes.len() != self.0.manifest.bytes() as usize
            || <[u8; 32]>::from(Sha256::digest(&bytes)) != self.0.manifest.sha256()
        {
            return Err(WireError::InvalidValue);
        }
        let output: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| WireError::InvalidValue)?;
        if serde_json::to_vec(&output).map_err(|_| WireError::InvalidValue)? != bytes {
            return Err(WireError::InvalidValue);
        }
        TaskResult::new(
            self.0.exit_code,
            self.0.quality,
            output,
            self.0.diagnostics.clone(),
        )
    }
}
