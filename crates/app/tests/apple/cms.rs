use super::*;
#[test]
fn subject_preserves_two_complete_ids_within_common_name_limit() {
    let enrollment = Uuid::new_v4();
    let attempt = Uuid::new_v4();
    let encoded = subject(enrollment, attempt);
    assert_eq!(encoded.len(), 64);
    let name = format!("CN={encoded}").parse().unwrap();
    assert_eq!(subject_ids(&name).unwrap(), (enrollment, attempt));
    assert!(subject_ids(&format!("CN={enrollment}:{attempt}").parse().unwrap()).is_err());
    assert!(subject_ids(&format!("CN={encoded},O=extra").parse().unwrap()).is_err());
    assert!(
        subject_ids(
            &format!("CN={}", subject(Uuid::nil(), attempt))
                .parse()
                .unwrap()
        )
        .is_err()
    );
}
#[test]
#[ignore = "Apple T2: disposable real keys and independent OpenSSL CMS verifier"]
fn cms_is_attached_and_independently_verified() -> anyhow::Result<()> {
    let root = std::path::PathBuf::from(std::env::var("MDM_APPLE_FIXTURES")?);
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    let signer = Signer::load(
        &root.join("apple-profile.pem"),
        &root.join("apple-profile.pk8"),
        now,
    )?;
    let bytes = super::super::profile::firewall("com.rss.test", Uuid::new_v4(), true)?;
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
