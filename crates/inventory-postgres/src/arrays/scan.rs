//! Resumable validation of canonical array bytes, owned by the PG value carrier.
//! ref: RustCrypto/traits digest/src/buffer_macros/fixed.rs@digest-v0.11.3
use super::*;
use rss_mdm_inventory::{ScalarBudget, ValueType};
use sha2_state::{
    Digest, Sha256,
    digest::common::hazmat::{SerializableState, SerializedState},
};

/// Checkpoint for one immutable array. Persist only inside the owning task transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArrayScanState {
    format: u8,
    tenant: String,
    metadata: Metadata,
    next: usize,
    bytes: usize,
    hash: Vec<u8>,
    budget: ScalarBudget,
    previous_key: Option<Scalar>,
    verified: bool,
}
impl ArrayScanState {
    /// True only after all items and the final canonical digest were checked.
    pub fn verified(&self) -> bool {
        if !self.verified
            || self.format != 1
            || self.next != self.metadata.count
            || self.bytes != self.metadata.bytes
        {
            return false;
        }
        let Ok(serialized): std::result::Result<SerializedState<Sha256>, _> =
            self.hash.as_slice().try_into()
        else {
            return false;
        };
        Sha256::deserialize(&serialized).is_ok_and(|hash| {
            hash.finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
                == self.metadata.digest
        })
    }
    /// Immutable version bound to this checkpoint.
    pub fn version(&self) -> &str {
        &self.metadata.version
    }
    /// Next ordinal, also useful for deterministic progress diagnostics.
    pub fn next_ordinal(&self) -> usize {
        self.next
    }
    /// Metadata whose identity must remain unchanged across recovery.
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }
}
/// One validated chunk; a final chunk still contains items to project before committing.
pub struct ScanChunk {
    /// Complete items in original canonical order.
    pub items: Vec<Scalar>,
    /// Updated checkpoint, including final validation status.
    pub state: ArrayScanState,
}
/// Start a scan without fetching any item payload.
pub async fn start_scan(
    c: &mut PgConnection,
    tenant: TenantId,
    version: &str,
) -> Result<ArrayScanState> {
    let m = metadata(c, tenant, &[version.to_owned()])
        .await?
        .remove(version)
        .ok_or_else(|| anyhow::anyhow!("missing scan version"))?;
    let mut hash = Sha256::new();
    hash.update(PREFIX);
    Ok(ArrayScanState {
        format: 1,
        tenant: tenant.to_string(),
        metadata: m,
        next: 0,
        bytes: PREFIX.len(),
        hash: hash.serialize().to_vec(),
        budget: ScalarBudget::array(),
        previous_key: None,
        verified: false,
    })
}
/// Advance by at most 1,000 items and usually 1 MiB; a larger legal item runs alone.
/// No transaction is committed and no partial validation is claimed as complete.
pub async fn advance_scan(
    c: &mut PgConnection,
    tenant: TenantId,
    mut state: ArrayScanState,
) -> Result<ScanChunk> {
    crate::reader::assert_tenant(c, tenant).await?;
    ensure!(
        state.format == 1 && state.tenant == tenant.to_string(),
        "array scan identity"
    );
    let m = metadata(c, tenant, &[state.metadata.version.clone()])
        .await?
        .remove(&state.metadata.version)
        .ok_or_else(|| anyhow::anyhow!("scan version missing"))?;
    ensure!(
        m == state.metadata && state.next <= m.count && !state.verified,
        "array scan binding"
    );
    let definition: Vec<u8> = sqlx::query_scalar("SELECT definition FROM mdm.array_versions WHERE tenant_id=$1::uuid AND version=$2 AND octet_length(definition)<=65536")
        .bind(tenant.to_string()).bind(&m.version).fetch_one(&mut *c).await?;
    ensure!(
        Sha256::digest(&definition)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
            == m.definition_digest,
        "scan definition digest"
    );
    let definition: FieldDefinition = serde_json::from_slice(&definition)?;
    definition.validate()?;
    let ValueType::Array { max_items, .. } = &definition.value_type else {
        anyhow::bail!("scan non-array definition")
    };
    ensure!(
        definition.key == m.field && m.count <= *max_items as usize,
        "scan field/count"
    );
    // Canonical JSON can escape each text byte sixfold; structural overhead is bounded
    // by the existing 200,000-node scalar contract. This bounds corrupt payload fetches.
    const MAX_CANONICAL_ITEM: usize = 6 * 16 * 1024 * 1024 + 128 * 200_000;
    let index: Vec<(i64,i64,i32)> = sqlx::query_as("SELECT ordinal,prefix_bytes,item_bytes FROM mdm.array_items WHERE tenant_id=$1::uuid AND version=$2 AND ordinal>=$3 ORDER BY ordinal LIMIT 1000")
        .bind(tenant.to_string()).bind(&m.version).bind(i64::try_from(state.next)?).fetch_all(&mut *c).await?;
    let mut selected = Vec::new();
    let mut used = 0usize;
    for (ordinal, prefix, size) in index {
        ensure!(
            usize::try_from(ordinal)? == state.next + selected.len() && size > 0,
            "scan ordinal"
        );
        let size = usize::try_from(size)?;
        ensure!(
            size <= MAX_CANONICAL_ITEM && size <= m.bytes,
            "scan item size"
        );
        if !selected.is_empty() && used.checked_add(size).is_none_or(|n| n > 1024 * 1024) {
            break;
        }
        used = used
            .checked_add(size)
            .ok_or_else(|| anyhow::anyhow!("scan size overflow"))?;
        selected.push((ordinal, prefix, size));
    }
    ensure!(
        state.next == m.count || !selected.is_empty(),
        "scan missing item"
    );
    ensure!(state.next + selected.len() <= m.count, "scan extra item");
    let rows: Vec<(i64,Vec<u8>,Vec<u8>)> = sqlx::query_as("SELECT ordinal,payload,digest FROM mdm.array_items WHERE tenant_id=$1::uuid AND version=$2 AND ordinal=ANY($3) ORDER BY ordinal")
        .bind(tenant.to_string()).bind(&m.version).bind(selected.iter().map(|v|v.0).collect::<Vec<_>>()).fetch_all(&mut *c).await?;
    ensure!(rows.len() == selected.len(), "scan payload count");
    let serialized: SerializedState<Sha256> = state
        .hash
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("scan hash encoding"))?;
    let mut hash =
        Sha256::deserialize(&serialized).map_err(|_| anyhow::anyhow!("scan hash state"))?;
    let mut items = Vec::with_capacity(rows.len());
    for ((ordinal, payload, digest), (expected, prefix, size)) in rows.into_iter().zip(selected) {
        ensure!(
            ordinal == expected
                && payload.len() == size
                && Sha256::digest(&payload).as_slice() == digest,
            "scan item digest/size"
        );
        let item: Scalar = serde_json::from_slice(&payload)?;
        definition.validate_item(&item)?;
        state.budget.observe(&item, 1)?;
        let canonical = serde_json::to_vec(&item)?;
        ensure!(canonical == payload, "scan noncanonical payload");
        if let Some(key) = &definition.item_key {
            let Scalar::Object(properties) = &item else {
                anyhow::bail!("scan keyed item")
            };
            let key = properties
                .get(key)
                .ok_or_else(|| anyhow::anyhow!("scan missing item key"))?;
            ensure!(
                state.previous_key.as_ref().is_none_or(|old| old < key),
                "scan unordered or duplicate item key"
            );
            state.previous_key = Some(key.clone());
        }
        if state.next > 0 {
            hash.update(b",");
            state.bytes += 1;
        }
        hash.update(&canonical);
        state.bytes = state
            .bytes
            .checked_add(canonical.len())
            .ok_or_else(|| anyhow::anyhow!("scan bytes overflow"))?;
        ensure!(
            usize::try_from(prefix)? == state.bytes - PREFIX.len(),
            "scan prefix"
        );
        state.next += 1;
        items.push(item);
    }
    if state.next == m.count {
        let extra: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm.array_items WHERE tenant_id=$1::uuid AND version=$2 AND ordinal >= $3)")
            .bind(tenant.to_string()).bind(&m.version).bind(i64::try_from(m.count)?).fetch_one(c).await?;
        ensure!(!extra, "scan trailing items");
        hash.update(SUFFIX);
        state.bytes += SUFFIX.len();
        ensure!(
            state.bytes == m.bytes
                && hash
                    .clone()
                    .finalize()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
                    == m.digest,
            "scan canonical digest/count"
        );
        state.verified = true;
    }
    state.hash = hash.serialize().to_vec();
    Ok(ScanChunk { items, state })
}
