//! Current trust and real signed credentials for tests of downstream business behavior.
use anyhow::{Result, ensure};
use rss_mdm_agent_wire::pki::Trust;
use std::path::{Path, PathBuf};
use x509_cert::der::Decode;

/// Seed the existing persistence owner, without replaying online startup admission.
/// Rotation and admission specialties continue to call Registry::admit themselves.
pub(crate) async fn seed_trust(
    pool: &sqlx::PgPool,
    trusts: &[rss_mdm_device_trust::DeviceTrust],
) -> Result<()> {
    for binding in trusts {
        let trust: Trust = binding.public()?;
        use crate::clock::Clock;
        rss_mdm_device_trust::DeviceTrust::new(
            trust.clone(),
            trust.purpose,
            crate::clock::SystemClock.unix_seconds()?,
        )?;
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(trust.tenant.to_string())
            .execute(&mut *tx)
            .await?;
        // Serialize only this tenant/purpose's preparation, never unrelated resources.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("t2-trust:{}:{:?}", trust.tenant, trust.purpose))
            .execute(&mut *tx)
            .await?;
        let stored: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT body FROM mdm_pki.trust WHERE tenant_id=$1 AND purpose=$2")
                .bind(trust.tenant)
                .bind(rss_mdm_pki_service::registry::purpose(trust.purpose))
                .fetch_optional(&mut *tx)
                .await?;
        if let Some(bytes) = stored {
            let current: Trust = serde_json::from_slice(&bytes)?;
            ensure!(
                current.tenant == trust.tenant
                    && current.purpose == trust.purpose
                    && current.origin == trust.origin
                    && trust
                        .issuers
                        .iter()
                        .all(|g| current.issuers.iter().any(|c| c.digest == g.digest
                            && c.certificate == g.certificate
                            && c.root == g.root
                            && c.provisioner == g.provisioner
                            && c.kid == g.kid)),
                "fixture trust changed within a shared environment"
            );
        } else {
            rss_mdm_pki_service::registry::persist(&mut tx, &trust).await?;
        }
        tx.commit().await?;
    }
    Ok(())
}

#[derive(serde::Deserialize)]
struct Issuer {
    certificate: PathBuf,
    key: PathBuf,
    password: Option<PathBuf>,
}

/// OpenSSL signs a real leaf. The consumer still validates its signature and identity.
/// ref: openssl/openssl apps/ca.c@openssl-3.0.15.
pub(crate) fn leaf(
    root: &Path,
    csr: &[u8],
    subject: &str,
    sans: &[String],
    start: i64,
    end: i64,
) -> Result<Vec<Vec<u8>>> {
    let issuer: Issuer = serde_json::from_slice(&std::fs::read(root.join("leaf-issuer.json"))?)?;
    ensure!(
        !subject.contains(['\n', '\r', '/']),
        "invalid fixture subject"
    );
    ensure!(
        sans.iter().all(|s| !s.contains(['\n', '\r', ','])),
        "invalid fixture SAN"
    );
    let temp = tempfile::tempdir()?;
    let dir = temp.path();
    std::fs::write(dir.join("index"), "")?;
    std::fs::write(
        dir.join("serial"),
        format!("{}\n", uuid::Uuid::new_v4().simple()),
    )?;
    std::fs::write(dir.join("csr.der"), csr)?;
    let mut extra = if sans.is_empty() {
        String::new()
    } else {
        format!(
            "subjectAltName={}\n",
            sans.iter()
                .map(|s| format!("URI:{s}"))
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    if subject == "rss-mdm-agent" {
        let trust: Trust = serde_json::from_slice(&std::fs::read(root.join("agent-trust.json"))?)?;
        let generation = trust
            .issuers
            .iter()
            .find(|issuer| issuer.mode == rss_mdm_agent_wire::pki::Mode::Active)
            .ok_or_else(|| anyhow::anyhow!("fixture Agent issuer missing"))?;
        let hex = |value: &str| {
            value
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        extra.push_str(&format!("1.3.6.1.4.1.37476.9000.64.1=ASN1:SEQUENCE:provisioner\n[provisioner]\nkind=INTEGER:1\nname=FORMAT:HEX,OCTETSTRING:{}\ncredential=FORMAT:HEX,OCTETSTRING:{}\n", hex(&generation.provisioner), hex(&generation.kid)));
    }
    std::fs::write(
        dir.join("ca.conf"),
        format!(
            "[ca]\ndefault_ca=CA\n[CA]\ndatabase={0}/index\nserial={0}/serial\nnew_certs_dir={0}\ncertificate={1}\nprivate_key={2}\ndefault_md=sha256\npolicy=policy\nx509_extensions=leaf\n[policy]\ncommonName=supplied\n[leaf]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n{extra}",
            dir.display(),
            issuer.certificate.display(),
            issuer.key.display()
        ),
    )?;
    let run = |command: &mut std::process::Command| -> Result<()> {
        let output = command.output()?;
        ensure!(
            output.status.success(),
            "fixture certificate: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    };
    run(std::process::Command::new("openssl")
        .args(["req", "-inform", "DER", "-in"])
        .arg(dir.join("csr.der"))
        .arg("-out")
        .arg(dir.join("csr.pem")))?;
    let date = |at| -> Result<String> {
        Ok(time::OffsetDateTime::from_unix_timestamp(at)?.format(
            &time::format_description::parse_borrowed::<2>(
                "[year][month][day][hour][minute][second]Z",
            )?,
        )?)
    };
    let mut command = std::process::Command::new("openssl");
    command
        .args(["ca", "-batch", "-notext", "-config"])
        .arg(dir.join("ca.conf"))
        .arg("-in")
        .arg(dir.join("csr.pem"))
        .arg("-subj")
        .arg(format!("/CN={subject}"))
        .arg("-startdate")
        .arg(date(start)?)
        .arg("-enddate")
        .arg(date(end)?)
        .arg("-out")
        .arg(dir.join("leaf.pem"));
    if let Some(password) = issuer.password {
        command
            .arg("-passin")
            .arg(format!("file:{}", password.display()));
    }
    run(&mut command)?;
    run(std::process::Command::new("openssl")
        .args(["x509", "-in"])
        .arg(dir.join("leaf.pem"))
        .args(["-outform", "DER", "-out"])
        .arg(dir.join("leaf.der")))?;
    use x509_cert::der::{DecodePem, Encode};
    Ok(vec![
        std::fs::read(dir.join("leaf.der"))?,
        x509_cert::Certificate::from_pem(&std::fs::read(issuer.certificate)?)?.to_der()?,
    ])
}

pub(crate) fn validity(leaf: &[u8]) -> Result<std::ops::Range<i64>> {
    let validity = x509_cert::Certificate::from_der(leaf)?
        .tbs_certificate
        .validity;
    Ok(validity.not_before.to_unix_duration().as_secs() as i64
        ..validity.not_after.to_unix_duration().as_secs() as i64)
}
