//! Persist query qualification with exact trust bytes; publication requalifies atomically.
use crate::Error;
use rss_mdm_agent_wire::pki::{Purpose, Trust};
use rss_mdm_device_trust::DeviceTrust;
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};

pub(crate) struct Qualification {
    pub trust: Vec<u8>,
    pub start: Option<i64>,
    pub end: Option<i64>,
}
struct Verifier {
    trust: Vec<u8>,
    verifier: DeviceTrust,
}
impl Verifier {
    fn new(tenant: &str, purpose: &str, bytes: &[u8]) -> Result<Self, Error> {
        let trust: Trust = serde_json::from_slice(bytes).map_err(|_| Error::Storage)?;
        if trust.tenant.to_string() != tenant || crate::registry::purpose(trust.purpose) != purpose
        {
            return Err(Error::Storage);
        }
        let at = crate::maintenance::publication_time(&trust)?;
        let usage = trust.purpose;
        let verifier = DeviceTrust::restore(trust, usage, at).map_err(|_| Error::Storage)?;
        Ok(Self {
            trust: Sha256::digest(bytes).to_vec(),
            verifier,
        })
    }
    fn certificate(&self, bytes: &[u8]) -> Result<Qualification, Error> {
        let window = self
            .verifier
            .certificate_window(bytes)
            .map_err(|_| Error::Request)?;
        Ok(Qualification {
            trust: self.trust.clone(),
            start: window.as_ref().map(|w| w.start()),
            end: window.as_ref().map(|w| w.end()),
        })
    }
}
pub(crate) async fn for_certificate_in(
    c: &mut PgConnection,
    tenant: &str,
    purpose: &str,
    certificate: &[u8],
) -> Result<Qualification, Error> {
    // Same lock order as trust publication: trust, then certificates. A new certificate
    // cannot commit an old-trust proof after the publisher finished its bounded scan.
    let bytes: Vec<u8> = sqlx::query_scalar(
        "SELECT body FROM mdm_pki.trust WHERE tenant_id=$1::uuid AND purpose=$2 FOR SHARE",
    )
    .bind(tenant)
    .bind(purpose)
    .fetch_one(c)
    .await
    .map_err(|_| Error::Storage)?;
    Verifier::new(tenant, purpose, &bytes)?.certificate(certificate)
}
pub(crate) async fn publish_in(
    c: &mut PgConnection,
    tenant: &str,
    purpose: Purpose,
    bytes: &[u8],
) -> Result<(), Error> {
    let purpose = crate::registry::purpose(purpose);
    let verifier = Verifier::new(tenant, purpose, bytes)?;
    let mut after = Vec::<u8>::new();
    loop {
        let rows=sqlx::query("SELECT fingerprint,certificate FROM mdm_pki.certificates WHERE tenant_id=$1::uuid AND purpose=$2 AND fingerprint>$3 AND (verification_trust<>$4 OR verification_version<>$5) ORDER BY fingerprint LIMIT 128")
            .bind(tenant).bind(purpose).bind(&after).bind(&verifier.trust)
            .bind(rss_mdm_device_trust::qualification::VERSION).fetch_all(&mut *c).await.map_err(|_|Error::Storage)?;
        if rows.is_empty() {
            return Ok(());
        }
        let mut fingerprints = Vec::with_capacity(rows.len());
        let mut starts = Vec::with_capacity(rows.len());
        let mut ends = Vec::with_capacity(rows.len());
        for row in rows {
            let fingerprint: Vec<u8> = row.try_get("fingerprint").map_err(|_| Error::Storage)?;
            let certificate: Vec<u8> = row.try_get("certificate").map_err(|_| Error::Storage)?;
            if fingerprint != Sha256::digest(&certificate).to_vec() {
                return Err(Error::Storage);
            }
            let qualification = verifier.certificate(&certificate)?;
            after = fingerprint.clone();
            fingerprints.push(fingerprint);
            starts.push(qualification.start);
            ends.push(qualification.end);
        }
        sqlx::query("UPDATE mdm_pki.certificates c SET verification_version=$3,verification_trust=$4,verification_start=q.start,verification_end=q.finish FROM unnest($5::bytea[],$6::bigint[],$7::bigint[]) q(fingerprint,start,finish) WHERE c.tenant_id=$1::uuid AND c.purpose=$2 AND c.fingerprint=q.fingerprint")
            .bind(tenant).bind(purpose).bind(rss_mdm_device_trust::qualification::VERSION).bind(&verifier.trust)
            .bind(fingerprints).bind(starts).bind(ends).execute(&mut *c).await.map_err(|_|Error::Storage)?;
        tokio::task::yield_now().await;
    }
}
