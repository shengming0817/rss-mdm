use rss_mdm_software_release::*;

fn variant(architecture: &str, byte: u8) -> VariantContent {
    VariantContent::new(
        architecture,
        "msi",
        vec![Artifact::new(architecture, Digest::from_bytes([byte; 32])).unwrap()],
    )
    .unwrap()
}
fn content(variants: Vec<VariantContent>) -> Result<Content, Error> {
    Content::new(
        SoftwareIdentity::new(SoftwareIdentityFields {
            source: "private".into(),
            package: "Acme.App".into(),
            version: "1".into(),
            platform: "windows".into(),
        })
        .unwrap(),
        Digest::from_bytes([1; 32]),
        Digest::from_bytes([2; 32]),
        Digest::from_bytes([3; 32]),
        variants,
    )
}
#[test]
fn complete_version_binds_every_variant_and_canonical_order() {
    let first = content(vec![variant("x64", 4), variant("arm64", 5)]).unwrap();
    assert_eq!(
        first,
        content(vec![variant("arm64", 5), variant("x64", 4)]).unwrap()
    );
    assert_ne!(
        first.digest(),
        content(vec![variant("x64", 4)]).unwrap().digest()
    );
    assert_ne!(
        first.digest(),
        content(vec![variant("x64", 4), variant("arm64", 6)])
            .unwrap()
            .digest()
    );
    assert!(content(vec![]).is_err());
    assert!(content(vec![variant("x64", 4), variant("x64", 4)]).is_err());
    assert!(VariantContent::new("x64", "msi", vec![]).is_err());
}
