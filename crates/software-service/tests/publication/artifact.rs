use super::*;

#[tokio::test]
#[ignore = "real HTTPS: make t2 MODULE=publication.artifact"]
async fn public_artifact_digest_length_tls_redirect_and_timeout_fail_closed() {
    let server = Server::new().await;
    let url = format!("{}artifacts/x64.msi", server.base);
    let digest = rel::Digest::of(b"abc").bytes();
    let reader = server.artifacts();
    reader.verify(&url, 3, digest).await.unwrap();
    assert!(matches!(
        reader.verify(&url, 2, digest).await,
        Err(Error::ArtifactDigest)
    ));
    assert!(matches!(
        reader.verify(&url, 3, [0; 32]).await,
        Err(Error::ArtifactDigest)
    ));
    assert!(matches!(
        reader.verify(&url, 1024 * 1024 + 1, digest).await,
        Err(Error::ArtifactBudget)
    ));
    assert!(matches!(
        reader
            .verify(&format!("{}artifacts/redirect", server.base), 3, digest)
            .await,
        Err(Error::ArtifactTransport)
    ));
    let untrusted = ArtifactReader::new(
        vec![ArtifactOrigin {
            base: format!("{}artifacts/", server.base),
            addresses: vec![server.address],
            private_ca: None,
        }],
        1024,
        std::time::Duration::from_secs(2),
    )
    .unwrap();
    assert!(matches!(
        untrusted.verify(&url, 3, digest).await,
        Err(Error::Diagnostic { stage: "artifact::verify", category, .. }) if matches!(*category, Error::ArtifactTransport)
    ));
    let bounded = ArtifactReader::new(
        vec![ArtifactOrigin {
            base: format!("{}artifacts/", server.base),
            addresses: vec![server.address],
            private_ca: Some(server.ca.clone()),
        }],
        1024,
        std::time::Duration::from_millis(100),
    )
    .unwrap();
    assert!(matches!(
        bounded
            .verify(&format!("{}artifacts/timeout", server.base), 3, digest)
            .await,
        Err(Error::Diagnostic { stage: "artifact::verify", category, .. }) if matches!(*category, Error::ArtifactTimeout)
    ));
    assert!(!server.state.lock().unwrap().artifact_auth_leaked);
}
