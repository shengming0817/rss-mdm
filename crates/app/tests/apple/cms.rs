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
