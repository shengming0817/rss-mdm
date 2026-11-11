use rss_mdm_query::directory::{Position, Schema};
use serde_json::json;
use sqlx::QueryBuilder;
pub static SCHEMA: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
    Schema::derived::<Row>("test", &["id"], 2, 3, &[]).expect("Public directory model")
});
#[test]
fn user_values_are_bound_and_null_seek_matches_nulls_last() {
    let q = SCHEMA
        .parse("filter=name==%22x%27%20OR%201%3D1--%22&sort=-name&limit=1")
        .unwrap();
    let mut sql = QueryBuilder::new("SELECT id FROM owned WHERE TRUE");
    rss_mdm_query_postgres::append(
        &mut sql,
        &q,
        Some(&Position(vec![json!(null), json!(4)])),
        &*BINDINGS,
    )
    .unwrap();
    let statement = sql.sql();
    let text = statement.as_str();
    assert!(!text.contains("OR 1=1"));
    assert!(text.contains("name COLLATE \"C\" IS NULL AND"));
    assert!(text.contains("FALSE"));
    assert!(text.contains("DESC NULLS LAST,id ASC NULLS LAST LIMIT"));
}

#[test]
fn prefilter_preserves_mixed_or_and_binds_only_available_atoms() {
    let q = SCHEMA
        .parse("filter=(id==1,name==blocked);id=gt=0")
        .unwrap();
    let mut sql = QueryBuilder::new("SELECT id FROM owned WHERE TRUE");
    rss_mdm_query_postgres::prefilter(&mut sql, &q, &*BINDINGS, |name| name != "name").unwrap();
    let statement = sql.sql();
    assert!(
        statement
            .as_str()
            .contains("((id = $1) OR TRUE) AND (id > $2)")
    );
    assert!(!statement.as_str().contains("name COLLATE"));
}

#[test]
fn sql_page_budget_uses_the_declared_query_owner() {
    pub static FIELDS: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
        Schema::derived::<IdRow>("field_metadata", &["id"], 100, 1024, &[])
            .expect("Public directory model")
    });
    let bindings = rss_mdm_query_postgres::Bindings::new(
        &FIELDS,
        &[rss_mdm_query_postgres::Source::column("id", "id")],
    )
    .unwrap();
    let query = FIELDS.parse("limit=1024").unwrap();
    let mut sql = QueryBuilder::new("SELECT id FROM owned WHERE TRUE");
    rss_mdm_query_postgres::append(&mut sql, &query, None, &bindings).unwrap();
    assert!(sql.sql().as_str().ends_with(" LIMIT $1"));
    let mut sql = QueryBuilder::new("SELECT id FROM owned WHERE TRUE");
    assert_eq!(
        rss_mdm_query_postgres::page_limit(&mut sql, &query, None, &bindings, 1026),
        Err(rss_mdm_query::Error::Budget)
    );
    let mut sql = QueryBuilder::new("SELECT id FROM owned WHERE TRUE");
    assert_eq!(
        rss_mdm_query_postgres::page_limit(
            &mut sql,
            &SCHEMA.parse("").unwrap(),
            None,
            &*BINDINGS,
            5
        ),
        Err(rss_mdm_query::Error::Budget)
    );
}

#[derive(schemars::JsonSchema)]
#[allow(dead_code)]
struct Row {
    id: i64,
    #[schemars(length(max = 64))]
    name: Option<String>,
}
#[derive(schemars::JsonSchema)]
#[allow(dead_code)]
struct IdRow {
    id: i64,
}

pub static BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> =
    std::sync::LazyLock::new(|| {
        rss_mdm_query_postgres::Bindings::new(
            &SCHEMA,
            &[
                rss_mdm_query_postgres::Source::column("id", "id"),
                rss_mdm_query_postgres::Source::column("name", "name COLLATE \"C\""),
            ],
        )
        .expect("Complete public model storage binding")
    });
