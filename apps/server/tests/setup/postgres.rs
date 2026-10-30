use super::*;
#[test]
fn database_identifiers_cannot_change_the_bootstrap_statement() {
    assert_eq!(identifier("rss_mdm_01").unwrap(), "\"rss_mdm_01\"");
    for name in [
        "",
        "postgres;DROP DATABASE prod",
        "a\"",
        "a.b",
        "a b",
        "_mdm",
        "1mdm",
        "A",
        "a\n",
    ] {
        assert!(identifier(name).is_err());
    }
    assert!(identifier(&"a".repeat(64)).is_err());
}
