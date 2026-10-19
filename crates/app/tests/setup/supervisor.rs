use super::*;
#[test]
fn supervisor_accepts_only_literal_absolute_paths() {
    let generated = unit(
        Path::new("/opt/rss-mdm/bin/rss-mdm"),
        Path::new("/var/lib/rss-mdm/deployer-input.json"),
        "test",
    )
    .unwrap();
    assert!(generated.contains("provision-hosts --config /var/lib/rss-mdm/deployer-input.json"));
    assert!(generated.contains("UMask=0077"));
    for path in [
        "relative",
        "/tmp/$HOME",
        "/tmp/%n",
        "/tmp/a\nExecStart=/other",
        "/tmp/a b",
    ] {
        assert!(unit(Path::new(path), Path::new("/var/lib/input.json"), "test").is_err());
    }
}
