use rss_mdm_query::directory::{Field, Kind, Position, Schema};
use serde_json::json;
use sqlx::QueryBuilder;
static SCHEMA: Schema = Schema {
    id: "test",
    keys: &["id"],
    default_limit: 2,
    max_limit: 3,
    fields: &[
        Field::scalar("id", Kind::Integer),
        Field::scalar("name", Kind::Text),
    ],
};
fn column(name: &str) -> &'static str {
    match name {
        "id" => "id",
        "name" => "name COLLATE \"C\"",
        _ => panic!("unexpected field"),
    }
}
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
        column,
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
    rss_mdm_query_postgres::prefilter(&mut sql, &q, column, |name| name != "name").unwrap();
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
    static FIELDS: Schema = Schema {
        id: "field_metadata",
        keys: &["id"],
        default_limit: 100,
        max_limit: 1024,
        fields: &[Field::scalar("id", Kind::Integer)],
    };
    let query = FIELDS.parse("limit=1024").unwrap();
    let mut sql = QueryBuilder::new("SELECT id FROM owned WHERE TRUE");
    rss_mdm_query_postgres::append(&mut sql, &query, None, column).unwrap();
    assert!(sql.sql().as_str().ends_with(" LIMIT $1"));
    let mut sql = QueryBuilder::new("SELECT id FROM owned WHERE TRUE");
    assert_eq!(
        rss_mdm_query_postgres::page_limit(&mut sql, &query, None, column, 1026),
        Err(rss_mdm_query::Error::Budget)
    );
    let mut sql = QueryBuilder::new("SELECT id FROM owned WHERE TRUE");
    assert_eq!(
        rss_mdm_query_postgres::page_limit(&mut sql, &SCHEMA.parse("").unwrap(), None, column, 5),
        Err(rss_mdm_query::Error::Budget)
    );
}
