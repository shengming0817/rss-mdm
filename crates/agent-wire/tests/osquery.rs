use rss_mdm_agent_wire::{osquery::SqlTemplate, runtime::TaskPlatform as Platform};
use serde_json::json;
#[test]
fn sql_template_binds_literals_without_turning_parameters_into_syntax() {
    let t = SqlTemplate::new("SELECT name, version FROM programs WHERE publisher = :publisher")
        .unwrap();
    let sql = t.render(&json!({"publisher":"x' OR 1=1; --"}), 50).unwrap();
    assert!(sql.contains("'x'' OR 1=1; --'"));
    assert!(t.validate_platform(Platform::Windows).is_ok());
    assert!(t.validate_platform(Platform::Macos).is_err());
    assert!(t.render(&json!({"publisher":"x","extra":1}), 50).is_err());
    assert!(t.render(&json!({}), 50).is_err());
}
#[test]
fn sql_guard_rejects_mutations_extensions_unlisted_data_and_unbounded_query_shapes() {
    for query in [
        "DELETE FROM programs",
        "SELECT version FROM osquery_info; SELECT version FROM osquery_info",
        "SELECT load_extension('x') FROM osquery_info",
        "SELECT sleep(1) FROM osquery_info",
        "SELECT carve('x') FROM osquery_info",
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

#[test]
fn platform_tables_share_the_published_template_contract() {
    for sql in [
        "SELECT device_id FROM bitlocker_info",
        "SELECT free_space FROM logical_drives",
        "SELECT firewall FROM windows_security_center",
        "SELECT name FROM programs",
    ] {
        let template = SqlTemplate::new(sql).unwrap();
        template.validate_platform(Platform::Windows).unwrap();
        assert!(template.validate_platform(Platform::Macos).is_err());
    }
    let template = SqlTemplate::new("SELECT path FROM apps").unwrap();
    template.validate_platform(Platform::Macos).unwrap();
    assert!(template.validate_platform(Platform::Windows).is_err());
}

#[test]
fn parameters_and_overflow_sentinel_keep_their_bounds() {
    let template = SqlTemplate::new("SELECT name FROM programs WHERE name = :name").unwrap();
    assert_eq!(template.parameters().unwrap(), ["name".to_owned()].into());
    for values in [
        json!({"name": null}),
        json!({"name": []}),
        json!({"name": 1.5}),
    ] {
        assert!(template.render(&values, 1).is_err());
    }
    for rows in [0, 100_001] {
        assert!(template.render(&json!({"name": "x"}), rows).is_err());
    }
    assert!(
        template
            .render(&json!({"name": "x"}), 100_000)
            .unwrap()
            .ends_with("LIMIT 100001")
    );
}
