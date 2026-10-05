use rss_mdm_certificate::apple::ProfileSigner;
#[test]
#[ignore = "Apple T2: disposable real keys and independent OpenSSL CMS verifier"]
fn cms_is_attached_and_independently_verified() -> anyhow::Result<()> {
    let root = std::path::PathBuf::from(std::env::var("MDM_APPLE_FIXTURES")?);
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    let signer = ProfileSigner::from_bytes(
        &std::fs::read(root.join("apple-profile.pem"))?,
        &std::fs::read(root.join("apple-profile.pk8"))?,
        now,
    )?;
    let bytes = b"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict/></plist>".to_vec();
    let cms = signer.sign(&bytes, now)?;
    let work = tempfile::tempdir()?;
    let input = work.path().join("profile.cms");
    let output = work.path().join("profile.plist");
    std::fs::write(&input, &cms)?;
    let status = std::process::Command::new("openssl")
        .args(["cms", "-verify", "-inform", "DER", "-in"])
        .arg(&input)
        .arg("-CAfile")
        .arg(root.join("apple-root.pem"))
        .arg("-out")
        .arg(&output)
        .output()?;
    anyhow::ensure!(
        status.status.success(),
        "independent CMS verification failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    anyhow::ensure!(std::fs::read(&output)? == bytes);
    let mut changed = cms;
    let i = changed.len() - 1;
    changed[i] ^= 1;
    std::fs::write(&input, changed)?;
    anyhow::ensure!(
        !std::process::Command::new("openssl")
            .args(["cms", "-verify", "-inform", "DER", "-in"])
            .arg(&input)
            .arg("-CAfile")
            .arg(root.join("apple-root.pem"))
            .arg("-out")
            .arg(&output)
            .output()?
            .status
            .success()
    );
    Ok(())
}

#[test]
#[ignore = "MODULE=apple.cms: independent CMS signed attributes and ECDSA bootstrap integrity"]
fn account_bootstrap_integrity_is_not_apple_attestation() -> anyhow::Result<()> {
    let work = tempfile::tempdir()?;
    let key = work.path().join("ec.key");
    let certificate = work.path().join("ec.pem");
    let input = work.path().join("request.plist");
    let output = work.path().join("request.cms");
    let payload=b"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>PRODUCT</key><string>Mac14,2</string></dict></plist>";
    std::fs::write(&input, payload)?;
    let generated = std::process::Command::new("openssl")
        .args([
            "req",
            "-new",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=Untrusted bootstrap signer",
            "-keyout",
        ])
        .arg(&key)
        .arg("-out")
        .arg(&certificate)
        .output()?;
    anyhow::ensure!(generated.status.success());
    let signed = std::process::Command::new("openssl")
        .args([
            "cms",
            "-sign",
            "-binary",
            "-nodetach",
            "-md",
            "sha256",
            "-in",
        ])
        .arg(&input)
        .arg("-signer")
        .arg(&certificate)
        .arg("-inkey")
        .arg(&key)
        .args(["-outform", "DER", "-out"])
        .arg(&output)
        .output()?;
    anyhow::ensure!(signed.status.success());
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    let bytes = std::fs::read(output)?;
    let request = rss_mdm_certificate::apple::enrollment_request(&bytes, now)?;
    anyhow::ensure!(request.payload == payload);
    anyhow::ensure!(
        rss_mdm_certificate::apple::enrollment_request(&bytes, now + 2 * 86400).is_err()
    );
    let mut changed = bytes;
    let index = changed
        .windows(payload.len())
        .position(|s| s == payload)
        .unwrap();
    changed[index + 4] ^= 1;
    anyhow::ensure!(
        rss_mdm_certificate::apple::enrollment_request(&changed, now).is_err(),
        "tampered CMS accepted"
    );
    Ok(())
}
