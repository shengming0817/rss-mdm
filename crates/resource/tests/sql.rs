use rss_mdm_resource::{Platform, SqlTemplate};
use serde_json::json;
#[test]
fn sql_template_binds_literals_without_turning_parameters_into_syntax() {
    let t = SqlTemplate::new("SELECT name, version FROM programs WHERE publisher = :publisher")
        .unwrap();
    let sql = t.render(&json!({"publisher":"x' OR 1=1; --"}), 50).unwrap();
    assert!(sql.contains("'x'' OR 1=1; --'"));
    assert!(SqlTemplate::validate_rendered(&sql, 50, Platform::Windows).is_ok());
    assert!(SqlTemplate::validate_rendered(&sql, 50, Platform::MacOS).is_err());
    assert!(t.render(&json!({"publisher":"x","extra":1}), 50).is_err());
    assert!(t.render(&json!({}), 50).is_err());
}
#[test]
fn sql_guard_rejects_mutations_extensions_unlisted_data_and_unbounded_query_shapes() {
    for query in [
        "DELETE FROM programs",
        "SELECT version FROM osquery_info; SELECT version FROM osquery_info",
        "SELECT load_extension('x') FROM osquery_info",
        "SELECT content FROM file",
        "SELECT * FROM programs",
        "SELECT uninstall_string FROM programs",
        "SELECT version FROM osquery_info LIMIT 1",
        "WITH x AS (SELECT version FROM osquery_info) SELECT version FROM x",
        "SELECT version FROM osquery_info UNION SELECT version FROM os_version",
        "SELECT a.version FROM osquery_info a JOIN osquery_info b ON 1=1",
        "PRAGMA journal_mode",
        "SELECT version FROM osquery_info ORDER BY version",
    ] {
        assert!(SqlTemplate::new(query).is_err(), "{query}");
    }
}
#[test]
fn version_is_an_ordinary_bounded_sql_template() {
    let t = SqlTemplate::new("select version from osquery_info;").unwrap();
    assert_eq!(
        t.render(&json!({}), 1).unwrap(),
        "SELECT version FROM osquery_info LIMIT 2"
    );
}
