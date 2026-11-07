use rss_mdm_query::directory::{Exclusion, Schema};
use rss_mdm_query_postgres::{Bindings, Source};
use schemars::JsonSchema;

#[derive(JsonSchema, serde::Serialize, serde::Deserialize)]
struct Metadata {
    name: String,
    added: Option<String>,
    labels: Vec<String>,
}
#[derive(JsonSchema, serde::Serialize, serde::Deserialize)]
struct Row {
    id: i64,
    metadata: Metadata,
    secret: String,
}
static SCHEMA: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
    Schema::derived::<Row>(
        "bound",
        &["id"],
        10,
        20,
        &[Exclusion {
            path: "secret",
            reason: "Credential",
        }],
    )
    .unwrap()
});
#[test]
fn a_trusted_json_root_binds_new_model_fields_but_missing_storage_fails_closed() {
    assert!(Bindings::new(&SCHEMA, &[Source::column("id", "id")]).is_err());
    let binding = Bindings::new(
        &SCHEMA,
        &[
            Source::column("id", "id"),
            Source::json("metadata", "document"),
        ],
    )
    .unwrap();
    let query = SCHEMA.parse("filter=metadata.added=icontains=%22x%27%20OR%20TRUE--%22;metadata.labels=containsall=(a,b)&sort=metadata.added").unwrap();
    let mut sql = sqlx::QueryBuilder::new("SELECT id FROM objects WHERE true");
    rss_mdm_query_postgres::append(&mut sql, &query, None, &binding).unwrap();
    let statement = sql.sql();
    assert!(!statement.as_str().contains("OR TRUE"));
    assert!(statement.as_str().contains("pg_c_utf8"));
    assert!(statement.as_str().contains("ARRAY['added']"));
    assert!(statement.as_str().contains("jsonb_array_elements_text"));
    assert!(statement.as_str().contains("NULLS LAST"));
    assert!(
        Bindings::new(
            &SCHEMA,
            &[Source::json("", "row"), Source::column("unknown", "secret")]
        )
        .is_err()
    );
}
