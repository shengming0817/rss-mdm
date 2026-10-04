//! Approved purpose trust and signed CRLs; all three device channels use this verifier.
//! ref: rustls@0.23.45 src/webpki/client_verifier.rs; RFC 5280 sections 4–6.
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid device trust material")]
    Malformed,
    #[error("device trust rejected")]
    Unauthorized,
    #[error("device trust rollback or conflict")]
    Conflict,
    #[error("device trust expired or not yet valid")]
    Expired,
}
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::signature;
use rss_mdm_agent_wire::pki::{Issuer, Mode, Purpose, Trust};
use sha2::{Digest, Sha256};
use std::{
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio_rustls::rustls::{
    self, DigitallySignedStruct, DistinguishedName, SignatureScheme,
    client::danger::HandshakeSignatureValid,
    pki_types::{CertificateDer, CertificateRevocationListDer, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use x509_cert::{
    Certificate,
    crl::CertificateList,
    der::{Decode, Encode, asn1::ObjectIdentifier},
    ext::pkix::{BasicConstraints, KeyUsage, crl::CrlNumber},
    spki::AlgorithmIdentifierOwned,
};

pub fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn serial(bytes: &[u8]) -> String {
    num_bigint::BigUint::from_bytes_be(bytes).to_str_radix(10)
}
fn invalid(_: impl std::fmt::Debug) -> Error {
    Error::Malformed
}
pub fn decode(value: &str, limit: usize) -> Result<Vec<u8>, Error> {
    if value.len() > limit.saturating_mul(4).div_ceil(3) + 4 {
        return Err(Error::Malformed);
    }
    let der = STANDARD.decode(value).map_err(invalid)?;
    if der.is_empty() || der.len() > limit {
        return Err(Error::Malformed);
    }
    Ok(der)
}
fn signed(
    issuer: &Certificate,
    algorithm: &AlgorithmIdentifierOwned,
    bytes: &[u8],
    sig: &[u8],
) -> Result<(), Error> {
    let algorithm: &dyn signature::VerificationAlgorithm = match algorithm.oid.to_string().as_str()
    {
        "1.2.840.113549.1.1.11" => &signature::RSA_PKCS1_2048_8192_SHA256,
        "1.2.840.113549.1.1.12" => &signature::RSA_PKCS1_2048_8192_SHA384,
        "1.2.840.10045.4.3.2" => &signature::ECDSA_P256_SHA256_ASN1,
        "1.2.840.10045.4.3.3" => &signature::ECDSA_P384_SHA384_ASN1,
        _ => return Err(Error::Malformed),
    };
    let key = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or(Error::Malformed)?;
    signature::UnparsedPublicKey::new(algorithm, key)
        .verify(bytes, sig)
        .map_err(invalid)
}
fn ca_shape(c: &Certificate) -> Result<(), Error> {
    let t = &c.tbs_certificate;
    if t.validity.not_after.to_unix_duration() <= t.validity.not_before.to_unix_duration()
        || t.get::<BasicConstraints>()
            .map_err(invalid)?
            .is_none_or(|(_, v)| !v.ca)
        || t.get::<KeyUsage>()
            .map_err(invalid)?
            .is_none_or(|(_, v)| !v.key_cert_sign() || !v.crl_sign())
    {
        return Err(Error::Malformed);
    }
    Ok(())
}
fn valid_ca(c: &Certificate, now: i64) -> Result<(), Error> {
    ca_shape(c)?;
    let t = &c.tbs_certificate;
    if now <= 0
        || t.validity.not_before.to_unix_duration().as_secs() > now as u64
        || t.validity.not_after.to_unix_duration().as_secs() <= now as u64
    {
        return Err(Error::Expired);
    }
    Ok(())
}
#[derive(Clone)]
pub struct Crl {
    pub number: u64,
    pub this_update: i64,
    pub next_update: i64,
    pub revoked: Vec<String>,
    pub der: Vec<u8>,
}
pub fn crl(der: &[u8], issuer: &Certificate, now: i64) -> Result<Crl, Error> {
    if der.is_empty() || der.len() > 16 * 1024 * 1024 {
        return Err(Error::Malformed);
    }
    let list = CertificateList::from_der(der).map_err(invalid)?;
    let t = &list.tbs_cert_list;
    if list.to_der().map_err(invalid)? != der
        || t.issuer != issuer.tbs_certificate.subject
        || t.signature != list.signature_algorithm
    {
        return Err(Error::Unauthorized);
    }
    signed(
        issuer,
        &list.signature_algorithm,
        &t.to_der().map_err(invalid)?,
        list.signature.as_bytes().ok_or(Error::Malformed)?,
    )?;
    let before = t.this_update.to_unix_duration().as_secs() as i64;
    let after = t
        .next_update
        .ok_or(Error::Malformed)?
        .to_unix_duration()
        .as_secs() as i64;
    if now < before || now >= after || after <= before {
        return Err(Error::Expired);
    }
    let oid = ObjectIdentifier::new_unwrap("2.5.29.20");
    let extensions = t.crl_extensions.as_ref().ok_or(Error::Malformed)?;
    let numbers = extensions
        .iter()
        .filter(|e| e.extn_id == oid)
        .collect::<Vec<_>>();
    if numbers.len() != 1 {
        return Err(Error::Malformed);
    }
    let number = CrlNumber::from_der(numbers[0].extn_value.as_bytes()).map_err(invalid)?;
    let bytes = number.0.as_bytes();
    if bytes.len() > 8 {
        return Err(Error::Malformed);
    }
    let number = bytes.iter().fold(0_u64, |n, b| n * 256 + u64::from(*b));
    let revoked = t
        .revoked_certificates
        .as_ref()
        .map(|rows| {
            rows.iter()
                .map(|r| serial(r.serial_number.as_bytes()))
                .collect()
        })
        .unwrap_or_default();
    Ok(Crl {
        number,
        this_update: before,
        next_update: after,
        revoked,
        der: der.to_vec(),
    })
}
#[derive(Clone)]
struct Generation {
    public: Issuer,
    certificate: Certificate,
    root: Certificate,
    crl: Crl,
    root_crl: Crl,
}
struct Snapshot {
    trust: Trust,
    generations: Vec<Generation>,
    verifier: Arc<dyn ClientCertVerifier>,
}
/// Revisions and CRL numbers only move forward. TLS and request checks share this same snapshot.
#[derive(Clone)]
pub struct DeviceTrust {
    inner: Arc<RwLock<Snapshot>>,
}
impl std::fmt::Debug for DeviceTrust {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceTrust")
    }
}
impl DeviceTrust {
    pub fn new(trust: Trust, purpose: Purpose, now: i64) -> Result<Self, Error> {
        let snapshot = Self::snapshot(trust, purpose, now)?;
        Ok(Self {
            inner: Arc::new(RwLock::new(snapshot)),
        })
    }
    /// Load a previously accepted signed snapshot before the host refreshes its CRLs.
    /// This does not authorize requests: verify() still checks freshness against request time.
    pub fn restore(trust: Trust, purpose: Purpose, now: i64) -> Result<Self, Error> {
        let mut checkpoint = 0;
        for g in &trust.issuers {
            for value in [&g.crl, &g.root_crl] {
                let list = CertificateList::from_der(&decode(value, 16 * 1024 * 1024)?)
                    .map_err(invalid)?;
                checkpoint = checkpoint
                    .max(list.tbs_cert_list.this_update.to_unix_duration().as_secs() as i64);
            }
        }
        if checkpoint <= 0 || checkpoint > now {
            return Err(Error::Expired);
        }
        Self::new(trust, purpose, checkpoint)
    }
    fn snapshot(trust: Trust, purpose: Purpose, now: i64) -> Result<Snapshot, Error> {
        if trust.version != 1
            || trust.purpose != purpose
            || trust.revision == 0
            || trust.revision > i64::MAX as u64
            || trust.tenant.is_nil()
            || trust.issuers.is_empty()
            || trust.issuers.len() > 16
            || trust
                .issuers
                .iter()
                .filter(|g| g.mode == Mode::Active)
                .count()
                != 1
        {
            return Err(Error::Malformed);
        }
        let origin = url::Url::parse(&trust.origin).map_err(invalid)?;
        if origin.scheme() != "https"
            || origin.host_str().is_none()
            || origin.origin().ascii_serialization() != trust.origin
            || !origin.username().is_empty()
            || origin.password().is_some()
        {
            return Err(Error::Malformed);
        }
        let mut roots = rustls::RootCertStore::empty();
        let mut crls = Vec::new();
        let mut generations = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for public in &trust.issuers {
            if public.provisioner.len() > 128
                || public.kid.len() > 128
                || (public.mode != Mode::VerifyOnly && public.provisioner.is_empty())
                || (trust.purpose == Purpose::Agent
                    && (public.provisioner != "rss-agent" || public.kid.is_empty()))
            {
                return Err(Error::Malformed);
            }
            let der = decode(&public.certificate, 32768)?;
            if digest(&der) != public.digest || !seen.insert(public.digest.clone()) {
                return Err(Error::Conflict);
            }
            let certificate = Certificate::from_der(&der).map_err(invalid)?;
            let root_der = decode(&public.root, 32768)?;
            let root = Certificate::from_der(&root_der).map_err(invalid)?;
            ca_shape(&certificate)?;
            ca_shape(&root)?;
            if public.mode != Mode::VerifyOnly {
                valid_ca(&certificate, now)?;
                valid_ca(&root, now)?;
            }
            if certificate.tbs_certificate.issuer != root.tbs_certificate.subject
                || root.tbs_certificate.subject != root.tbs_certificate.issuer
            {
                return Err(Error::Unauthorized);
            }
            signed(
                &root,
                &root.signature_algorithm,
                &root.tbs_certificate.to_der().map_err(invalid)?,
                root.signature.as_bytes().ok_or(Error::Malformed)?,
            )?;
            if certificate.signature_algorithm != certificate.tbs_certificate.signature
                || root.signature_algorithm != root.tbs_certificate.signature
            {
                return Err(Error::Malformed);
            }
            signed(
                &root,
                &certificate.signature_algorithm,
                &certificate.tbs_certificate.to_der().map_err(invalid)?,
                certificate.signature.as_bytes().ok_or(Error::Malformed)?,
            )?;
            let issuer_crl = crl(&decode(&public.crl, 16 * 1024 * 1024)?, &certificate, now)?;
            let root_crl = crl(&decode(&public.root_crl, 16 * 1024 * 1024)?, &root, now)?;
            if certificate != root
                && root_crl.revoked.contains(&serial(
                    certificate.tbs_certificate.serial_number.as_bytes(),
                ))
            {
                return Err(Error::Unauthorized);
            }
            roots.add(CertificateDer::from(root_der)).map_err(invalid)?;
            crls.push(CertificateRevocationListDer::from(issuer_crl.der.clone()));
            if certificate != root {
                crls.push(CertificateRevocationListDer::from(root_crl.der.clone()));
            }
            generations.push(Generation {
                public: public.clone(),
                certificate,
                root,
                crl: issuer_crl,
                root_crl,
            });
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .with_crls(crls)
        .enforce_revocation_expiration()
        .build()
        .map_err(invalid)?;
        Ok(Snapshot {
            trust,
            generations,
            verifier,
        })
    }
    /// The complete approved public root/issuer overlap, deduplicated by exact DER.
    pub fn certificates(&self) -> Result<Vec<(bool, Vec<u8>)>, Error> {
        let public = self.public()?;
        let mut seen = std::collections::BTreeSet::new();
        let mut result = Vec::new();
        for g in public.issuers {
            for (root, encoded) in [(true, g.root), (false, g.certificate)] {
                let der = decode(&encoded, 32768)?;
                if seen.insert(der.clone()) {
                    result.push((root, der));
                }
            }
        }
        Ok(result)
    }
    pub fn public(&self) -> Result<Trust, Error> {
        Ok(self.inner.read().map_err(invalid)?.trust.clone())
    }
    pub fn active(&self) -> Result<Issuer, Error> {
        self.public()?
            .issuers
            .into_iter()
            .find(|g| g.mode == Mode::Active)
            .ok_or(Error::Malformed)
    }
    pub fn update(&self, trust: Trust, now: i64) -> Result<(), Error> {
        let mut old = self.inner.write().map_err(invalid)?;
        if trust.origin != old.trust.origin
            || trust.tenant != old.trust.tenant
            || trust.purpose != old.trust.purpose
            || trust.revision < old.trust.revision
        {
            return Err(Error::Conflict);
        }
        let next = Self::snapshot(trust, old.trust.purpose, now)?;
        if next.trust.revision == old.trust.revision
            && next
                .trust
                .issuers
                .iter()
                .map(|g| (&g.digest, g.mode))
                .ne(old.trust.issuers.iter().map(|g| (&g.digest, g.mode)))
        {
            return Err(Error::Conflict);
        }
        for generation in &next.generations {
            if let Some(previous) = old
                .generations
                .iter()
                .find(|g| g.public.digest == generation.public.digest)
            {
                if generation.public.certificate != previous.public.certificate
                    || generation.public.root != previous.public.root
                    || generation.public.provisioner != previous.public.provisioner
                    || generation.public.kid != previous.public.kid
                {
                    return Err(Error::Conflict);
                }
                for (a, b) in [
                    (&previous.crl, &generation.crl),
                    (&previous.root_crl, &generation.root_crl),
                ] {
                    if b.number < a.number
                        || b.this_update < a.this_update
                        || (b.number == a.number && b.der != a.der)
                    {
                        return Err(Error::Conflict);
                    }
                }
            }
        }
        *old = next;
        Ok(())
    }
    fn leaf_purpose(trust: &Trust, leaf: &Certificate) -> Result<(), Error> {
        use x509_cert::ext::pkix::{
            ExtendedKeyUsage, KeyUsages, SubjectAltName, name::GeneralName,
        };
        let t = &leaf.tbs_certificate;
        if t.get::<BasicConstraints>()
            .map_err(invalid)?
            .is_none_or(|(_, v)| v.ca || v.path_len_constraint.is_some())
            || t.get::<KeyUsage>()
                .map_err(invalid)?
                .is_none_or(|(_, v)| v != KeyUsage(KeyUsages::DigitalSignature.into()))
            || t.get::<ExtendedKeyUsage>()
                .map_err(invalid)?
                .is_none_or(|(_, v)| v.0 != vec![ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2")])
        {
            return Err(Error::Unauthorized);
        }
        match trust.purpose {
            Purpose::Windows => {
                let subject = t.subject.to_string();
                let id = subject
                    .strip_prefix("CN=")
                    .and_then(|s| uuid::Uuid::parse_str(s).ok())
                    .ok_or(Error::Unauthorized)?;
                if id.is_nil()
                    || subject != format!("CN={id}")
                    || t.get::<SubjectAltName>().map_err(invalid)?.is_some()
                {
                    return Err(Error::Unauthorized);
                }
            }
            Purpose::Apple => {
                apple_subject(&t.subject)?;
                if t.get::<SubjectAltName>().map_err(invalid)?.is_some() {
                    return Err(Error::Unauthorized);
                }
            }
            Purpose::Agent => {
                let (_, sans) = t
                    .get::<SubjectAltName>()
                    .map_err(invalid)?
                    .ok_or(Error::Unauthorized)?;
                let [GeneralName::UniformResourceIdentifier(uri)] = sans.0.as_slice() else {
                    return Err(Error::Unauthorized);
                };
                if t.subject.to_string() != "CN=rss-mdm-agent"
                    || !uri
                        .as_str()
                        .starts_with(&format!("urn:rss-mdm:agent:v1:{}:", trust.tenant))
                {
                    return Err(Error::Unauthorized);
                }
            }
        }
        Ok(())
    }
    /// Validate an imported historical certificate record, including expired/revoked records.
    /// This proves its original issuer and purpose; it never authorizes a live connection.
    pub fn verify_history(&self, leaf_der: &[u8], issuer: &str) -> Result<Issuer, Error> {
        if leaf_der.is_empty() || leaf_der.len() > 32768 {
            return Err(Error::Malformed);
        }
        let leaf = Certificate::from_der(leaf_der).map_err(invalid)?;
        let snapshot = self.inner.read().map_err(invalid)?;
        Self::leaf_purpose(&snapshot.trust, &leaf)?;
        let generation = snapshot
            .generations
            .iter()
            .find(|g| g.public.digest == issuer)
            .ok_or(Error::Unauthorized)?;
        let t = &leaf.tbs_certificate;
        if leaf.to_der().map_err(invalid)? != leaf_der
            || leaf.signature_algorithm != t.signature
            || t.issuer != generation.certificate.tbs_certificate.subject
            || t.validity.not_after.to_unix_duration() <= t.validity.not_before.to_unix_duration()
            || t.validity.not_before.to_unix_duration()
                < generation
                    .certificate
                    .tbs_certificate
                    .validity
                    .not_before
                    .to_unix_duration()
            || t.validity.not_after.to_unix_duration()
                > generation
                    .certificate
                    .tbs_certificate
                    .validity
                    .not_after
                    .to_unix_duration()
        {
            return Err(Error::Unauthorized);
        }
        signed(
            &generation.certificate,
            &leaf.signature_algorithm,
            &t.to_der().map_err(invalid)?,
            leaf.signature.as_bytes().ok_or(Error::Malformed)?,
        )?;
        if snapshot.trust.purpose == Purpose::Agent {
            let identity = agent_identity(&leaf, &generation.public)?;
            if !identity.starts_with(&format!("urn:rss-mdm:agent:v1:{}:", snapshot.trust.tenant)) {
                return Err(Error::Unauthorized);
            }
        }
        Ok(generation.public.clone())
    }
    pub fn verify(&self, chain: &[CertificateDer<'_>], now: i64) -> Result<Issuer, Error> {
        if chain.is_empty() || chain.len() > 4 || chain.iter().any(|c| c.len() > 32768) || now <= 0
        {
            return Err(Error::Unauthorized);
        }
        let leaf = Certificate::from_der(&chain[0]).map_err(invalid)?;
        let snapshot = self.inner.read().map_err(invalid)?;
        Self::leaf_purpose(&snapshot.trust, &leaf)?;
        for g in &snapshot.generations {
            if leaf.tbs_certificate.issuer != g.certificate.tbs_certificate.subject {
                continue;
            }
            if signed(
                &g.certificate,
                &leaf.signature_algorithm,
                &leaf.tbs_certificate.to_der().map_err(invalid)?,
                leaf.signature.as_bytes().ok_or(Error::Malformed)?,
            )
            .is_err()
            {
                continue;
            }
            if snapshot.trust.purpose == Purpose::Agent {
                let identity = agent_identity(&leaf, &g.public)?;
                if !identity
                    .starts_with(&format!("urn:rss-mdm:agent:v1:{}:", snapshot.trust.tenant))
                {
                    return Err(Error::Unauthorized);
                }
            }
            valid_ca(&g.certificate, now)?;
            valid_ca(&g.root, now)?;
            if now < g.crl.this_update
                || now >= g.crl.next_update
                || now < g.root_crl.this_update
                || now >= g.root_crl.next_update
            {
                return Err(Error::Expired);
            }
            let issuer = CertificateDer::from(g.certificate.to_der().map_err(invalid)?);
            snapshot
                .verifier
                .verify_client_cert(
                    &chain[0],
                    &[issuer],
                    UnixTime::since_unix_epoch(Duration::from_secs(now as u64)),
                )
                .map_err(invalid)?;
            return Ok(g.public.clone());
        }
        Err(Error::Unauthorized)
    }
    pub fn verifier(&self, anonymous: bool) -> Arc<dyn ClientCertVerifier> {
        Arc::new(Verifier {
            trust: self.clone(),
            anonymous,
        })
    }
}
#[derive(Debug)]
struct Verifier {
    trust: DeviceTrust,
    anonymous: bool,
}
impl ClientCertVerifier for Verifier {
    fn client_auth_mandatory(&self) -> bool {
        !self.anonymous
    }
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        end: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let chain: Vec<_> = std::iter::once(end.clone())
            .chain(intermediates.iter().cloned())
            .collect();
        self.trust
            .verify(&chain, now.as_secs() as i64)
            .map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
            })?;
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.trust
            .inner
            .read()
            .map_err(|_| rustls::Error::General("PKI unavailable".into()))?
            .verifier
            .verify_tls12_signature(message, cert, dss)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.trust
            .inner
            .read()
            .map_err(|_| rustls::Error::General("PKI unavailable".into()))?
            .verifier
            .verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.trust
            .inner
            .read()
            .map(|s| s.verifier.supported_verify_schemes())
            .unwrap_or_default()
    }
}

pub fn agent_identity(
    c: &Certificate,
    generation: &rss_mdm_agent_wire::pki::Issuer,
) -> Result<String, Error> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use uuid::Uuid;
    use x509_cert::{
        der::asn1::{Any, OctetString},
        ext::pkix::{SubjectAltName, name::GeneralName},
    };
    struct Provisioner {
        kind: u8,
        name: OctetString,
        credential: OctetString,
    }
    let t = &c.tbs_certificate;
    if t.subject.to_string() != "CN=rss-mdm-agent"
        || t.subject_public_key_info.algorithm.oid
            != ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1")
    {
        return Err(Error::Unauthorized);
    }
    let (_, san) = t
        .get::<SubjectAltName>()
        .map_err(invalid)?
        .ok_or(Error::Unauthorized)?;
    let identity = match san.0.as_slice() {
        [GeneralName::UniformResourceIdentifier(uri)] => uri.to_string(),
        _ => return Err(Error::Unauthorized),
    };
    let remainder = identity
        .strip_prefix("urn:rss-mdm:agent:v1:")
        .ok_or(Error::Unauthorized)?;
    let (tenant, encoded) = remainder.split_once(':').ok_or(Error::Unauthorized)?;
    let tenant = Uuid::parse_str(tenant).map_err(invalid)?;
    let device = URL_SAFE_NO_PAD.decode(encoded).map_err(invalid)?;
    let device = std::str::from_utf8(&device).map_err(invalid)?;
    if tenant.is_nil()
        || device.is_empty()
        || device.len() > 256
        || device.chars().any(char::is_control)
        || format!(
            "urn:rss-mdm:agent:v1:{tenant}:{}",
            URL_SAFE_NO_PAD.encode(device)
        ) != identity
    {
        return Err(Error::Unauthorized);
    }
    let extensions = t.extensions.as_ref().ok_or(Error::Unauthorized)?;
    let mut seen = std::collections::BTreeSet::new();
    if extensions.iter().any(|ext| !seen.insert(ext.extn_id)) {
        return Err(Error::Unauthorized);
    }
    let marker = extensions
        .iter()
        .find(|ext| ext.extn_id == ObjectIdentifier::new_unwrap("1.3.6.1.4.1.37476.9000.64.1"))
        .ok_or(Error::Unauthorized)?;
    let provisioner = Any::from_der(marker.extn_value.as_bytes())
        .map_err(invalid)?
        .sequence(|reader| {
            Ok(Provisioner {
                kind: u8::decode(reader)?,
                name: OctetString::decode(reader)?,
                credential: OctetString::decode(reader)?,
            })
        })
        .map_err(invalid)?;
    if provisioner.kind != 1
        || provisioner.name.as_bytes() != generation.provisioner.as_bytes()
        || provisioner.credential.as_bytes() != generation.kid.as_bytes()
    {
        return Err(Error::Unauthorized);
    }
    Ok(identity)
}

pub fn apple_subject(name: &x509_cert::name::Name) -> Result<(uuid::Uuid, uuid::Uuid), Error> {
    use x509_cert::der::Tagged;
    if name.0.len() != 1 || name.0[0].0.len() != 1 {
        return Err(Error::Unauthorized);
    }
    let attribute = name.0[0].0.iter().next().ok_or(Error::Unauthorized)?;
    if attribute.oid != ObjectIdentifier::new_unwrap("2.5.4.3")
        || !matches!(
            attribute.value.tag(),
            x509_cert::der::Tag::Utf8String | x509_cert::der::Tag::PrintableString
        )
    {
        return Err(Error::Unauthorized);
    }
    let value = std::str::from_utf8(attribute.value.value()).map_err(invalid)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(Error::Unauthorized);
    }
    let enrollment = uuid::Uuid::parse_str(&value[..32]).map_err(invalid)?;
    let attempt = uuid::Uuid::parse_str(&value[32..]).map_err(invalid)?;
    if enrollment.is_nil() || attempt.is_nil() {
        return Err(Error::Unauthorized);
    }
    Ok((enrollment, attempt))
}
