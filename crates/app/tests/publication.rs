use rss_mdm_app::software_publication::{ArtifactOrigin, ArtifactReader};
#[test]
fn artifact_reader_rejects_credentials_redirectable_urls_and_unbounded_budgets() {
    let origin = |base: &str| ArtifactOrigin {
        base: base.into(),
        addresses: vec!["8.8.8.8".parse().unwrap()],
        private_ca: None,
    };
    for url in [
        "http://cdn.example/",
        "https://user:secret@cdn.example/",
        "https://cdn.example/?signature=secret",
        "https://cdn.example/#fragment",
    ] {
        assert!(
            ArtifactReader::new(vec![origin(url)], 1024, std::time::Duration::from_secs(1))
                .is_err()
        );
    }
    assert!(
        ArtifactReader::new(
            vec![origin("https://cdn.example/")],
            0,
            std::time::Duration::from_secs(1)
        )
        .is_err()
    );
}
