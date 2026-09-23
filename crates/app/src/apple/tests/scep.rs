//! Independent controlled SCEP peer. OpenSSL handles fixture envelope encryption/decryption.
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use uuid::Uuid;
use x509_cert::der::{
    Decode, Encode,
    asn1::{Any, ObjectIdentifier, OctetString, PrintableString, SetOfVec},
};

pub(super) struct Device {
    pub root: tempfile::TempDir,
    pub csr: Vec<u8>,
    pub self_signed: PathBuf,
    pub key: PathBuf,
    pub pk8: PathBuf,
}
pub(super) fn openssl(args: &[&std::ffi::OsStr]) -> Result<()> {
    let result = std::process::Command::new("openssl").args(args).output()?;
    ensure!(
        result.status.success(),
        "fixture OpenSSL failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(())
}
impl Device {
    pub fn new(enrollment: Uuid, attempt: Uuid, challenge: &str) -> Result<Self> {
        Self::with_key(enrollment, attempt, challenge, None)
    }
    pub fn with_key(
        enrollment: Uuid,
        attempt: Uuid,
        challenge: &str,
        existing: Option<&Path>,
    ) -> Result<Self> {
        let root = tempfile::tempdir()?;
        let key = root.path().join("device.key");
        let csr = root.path().join("device.csr");
        let pk8 = root.path().join("device.pk8");
        let self_signed = root.path().join("self.pem");
        let config = root.path().join("req.conf");
        let subject = super::super::certificate::subject(enrollment, attempt);
        std::fs::write(
            &config,
            format!(
                "[req]\nprompt=no\ndistinguished_name=subject\nattributes=attributes\n[subject]\nCN={subject}\n[attributes]\nchallengePassword={challenge}\n"
            ),
        )?;
        let mut args: Vec<&std::ffi::OsStr> = vec![
            "req".as_ref(),
            "-new".as_ref(),
            "-nodes".as_ref(),
            "-sha256".as_ref(),
            "-config".as_ref(),
            config.as_os_str(),
            "-outform".as_ref(),
            "DER".as_ref(),
            "-out".as_ref(),
            csr.as_os_str(),
        ];
        if let Some(existing) = existing {
            std::fs::copy(existing, &key)?;
            args.extend(["-key".as_ref(), key.as_os_str()]);
        } else {
            args.extend([
                "-newkey".as_ref(),
                "rsa:2048".as_ref(),
                "-keyout".as_ref(),
                key.as_os_str(),
            ]);
        }
        openssl(&args)?;
        openssl(&[
            "x509".as_ref(),
            "-req".as_ref(),
            "-inform".as_ref(),
            "DER".as_ref(),
            "-in".as_ref(),
            csr.as_os_str(),
            "-signkey".as_ref(),
            key.as_os_str(),
            "-days".as_ref(),
            "1".as_ref(),
            "-out".as_ref(),
            self_signed.as_os_str(),
        ])?;
        openssl(&[
            "pkcs8".as_ref(),
            "-topk8".as_ref(),
            "-nocrypt".as_ref(),
            "-in".as_ref(),
            key.as_os_str(),
            "-outform".as_ref(),
            "DER".as_ref(),
            "-out".as_ref(),
            pk8.as_os_str(),
        ])?;
        use std::os::unix::fs::PermissionsExt;
        for path in [&key, &pk8, &config] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(Self {
            csr: std::fs::read(csr)?,
            root,
            self_signed,
            key,
            pk8,
        })
    }
    pub fn request(&self, recipient: &Path, transaction: &str, now: i64) -> Result<Vec<u8>> {
        use cms::{
            content_info::ContentInfo,
            signed_data::{SignedData, SignerInfos},
        };
        use ring::signature::{self, RsaKeyPair};
        let input = self.root.path().join("csr.der");
        let encrypted = self.root.path().join("enveloped.der");
        std::fs::write(&input, &self.csr)?;
        openssl(&[
            "cms".as_ref(),
            "-encrypt".as_ref(),
            "-binary".as_ref(),
            "-aes256".as_ref(),
            "-in".as_ref(),
            input.as_os_str(),
            "-outform".as_ref(),
            "DER".as_ref(),
            "-out".as_ref(),
            encrypted.as_os_str(),
            recipient.as_os_str(),
        ])?;
        let bytes = std::fs::read(encrypted)?;
        let cms = super::super::certificate::Signer::load(&self.self_signed, &self.pk8, now)?
            .sign(&bytes, now)?;
        let mut content = ContentInfo::from_der(&cms)?;
        let mut signed = content.content.decode_as::<SignedData>()?;
        let oid = |s: &str| ObjectIdentifier::new(s).unwrap();
        let attr = |s: &str, value: Any| x509_cert::attr::Attribute {
            oid: oid(s),
            values: SetOfVec::try_from(vec![value]).unwrap(),
        };
        let attrs = SetOfVec::try_from(vec![
            attr(
                "1.2.840.113549.1.9.3",
                Any::encode_from(&oid("1.2.840.113549.1.7.1"))?,
            ),
            attr(
                "1.2.840.113549.1.9.4",
                Any::encode_from(&OctetString::new(Sha256::digest(&bytes).to_vec())?)?,
            ),
            attr(
                "2.16.840.1.113733.1.9.2",
                Any::encode_from(&PrintableString::new("19")?)?,
            ),
            attr(
                "2.16.840.1.113733.1.9.5",
                Any::encode_from(&OctetString::new(Uuid::new_v4().as_bytes())?)?,
            ),
            attr(
                "2.16.840.1.113733.1.9.7",
                Any::encode_from(&PrintableString::new(transaction)?)?,
            ),
        ])?;
        let key = RsaKeyPair::from_pkcs8(&std::fs::read(&self.pk8)?)
            .map_err(|_| anyhow::anyhow!("fixture key"))?;
        let mut signature = vec![0; key.public().modulus_len()];
        key.sign(
            &signature::RSA_PKCS1_SHA256,
            &ring::rand::SystemRandom::new(),
            &attrs.to_der()?,
            &mut signature,
        )
        .map_err(|_| anyhow::anyhow!("fixture signature"))?;
        let mut info = signed.signer_infos.0.iter().next().unwrap().clone();
        info.signed_attrs = Some(attrs);
        info.signature = OctetString::new(signature)?;
        signed.signer_infos = SignerInfos::try_from(vec![info])?;
        content.content = Any::encode_from(&signed)?;
        Ok(content.to_der()?)
    }
    pub async fn enroll(
        &self,
        client: &reqwest::Client,
        url: &str,
        request: &[u8],
    ) -> Result<Vec<u8>> {
        let response = client
            .post(url)
            .query(&[("operation", "PKIOperation")])
            .header("content-type", "application/x-pki-message")
            .body(request.to_vec())
            .send()
            .await?;
        ensure!(
            response.status().is_success(),
            "SCEP HTTP failure {}",
            response.status()
        );
        let reply = self.root.path().join("reply.der");
        let encrypted = self.root.path().join("reply-encrypted.der");
        let certificates = self.root.path().join("certificates.der");
        let pem = self.root.path().join("issued.pem");
        std::fs::write(&reply, response.bytes().await?)?;
        openssl(&[
            "cms".as_ref(),
            "-verify".as_ref(),
            "-binary".as_ref(),
            "-noverify".as_ref(),
            "-inform".as_ref(),
            "DER".as_ref(),
            "-in".as_ref(),
            reply.as_os_str(),
            "-out".as_ref(),
            encrypted.as_os_str(),
        ])?;
        openssl(&[
            "cms".as_ref(),
            "-decrypt".as_ref(),
            "-binary".as_ref(),
            "-inform".as_ref(),
            "DER".as_ref(),
            "-in".as_ref(),
            encrypted.as_os_str(),
            "-recip".as_ref(),
            self.self_signed.as_os_str(),
            "-inkey".as_ref(),
            self.key.as_os_str(),
            "-out".as_ref(),
            certificates.as_os_str(),
        ])?;
        openssl(&[
            "pkcs7".as_ref(),
            "-inform".as_ref(),
            "DER".as_ref(),
            "-in".as_ref(),
            certificates.as_os_str(),
            "-print_certs".as_ref(),
            "-out".as_ref(),
            pem.as_os_str(),
        ])?;
        use tokio_rustls::rustls::pki_types::{CertificateDer, pem::PemObject};
        Ok(CertificateDer::pem_slice_iter(&std::fs::read(pem)?)
            .next()
            .ok_or_else(|| anyhow::anyhow!("SCEP omitted leaf"))??
            .to_vec())
    }
    pub fn identity(&self, der: &[u8]) -> Result<reqwest::Identity> {
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            STANDARD.encode(der)
        );
        let mut bytes = pem.into_bytes();
        bytes.extend(std::fs::read(&self.key)?);
        Ok(reqwest::Identity::from_pem(&bytes)?)
    }
}
