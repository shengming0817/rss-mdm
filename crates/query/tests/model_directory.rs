use rss_mdm_query::{
    Operator,
    directory::{Exclusion, Schema},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(JsonSchema, Serialize, Deserialize)]
struct Metadata {
    #[schemars(length(max = 128))]
    name: String,
    category: Option<String>,
    labels: Vec<String>,
}
#[derive(JsonSchema, Serialize, Deserialize)]
struct Row {
    id: i64,
    metadata: Metadata,
    secret: String,
}
static MODEL: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
    Schema::derived::<Row>(
        "model",
        &["id"],
        2,
        10,
        &[Exclusion {
            path: "secret",
            reason: "Credential value; never a filter or sort key",
        }],
    )
    .unwrap()
});

#[test]
fn model_is_the_field_authority_and_capabilities_are_executable() {
    let name = MODEL.field("metadata.name").unwrap();
    assert!(name.filter && name.sort && !name.output);
    assert!(name.operations().contains(&Operator::Icontains));
    assert!(MODEL.field("metadata.category").unwrap().nullable);
    assert!(!MODEL.field("metadata.labels").unwrap().sort);
    assert!(MODEL.parse("filter=metadata.name=icontains=É;metadata.labels=containsall=(a,b)&sort=metadata.name").is_ok());
    assert!(MODEL.parse("filter=metadata.category=isnull=true").is_ok());
    for query in [
        "filter=secret==x",
        "sort=secret",
        "filter=metadata.arbitrary==x",
        "fields=metadata.name",
        "filter=metadata.category=isnull=false",
        "filter=metadata.labels=gt=x",
    ] {
        assert!(MODEL.parse(query).is_err(), "{query}");
    }
    let descriptor = serde_json::to_value(&*MODEL).unwrap();
    let secret = descriptor["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == "secret")
        .unwrap();
    assert_eq!(secret["operators"], serde_json::json!([]));
    assert!(
        secret["limitation"]
            .as_str()
            .unwrap()
            .contains("Credential")
    );
}

#[derive(JsonSchema, serde::Serialize, serde::Deserialize)]
struct ExtendedMetadata {
    #[schemars(length(max = 128))]
    name: String,
    category: Option<String>,
    labels: Vec<String>,
    publisher: String,
}
#[derive(JsonSchema, serde::Serialize, serde::Deserialize)]
struct Extended {
    id: i64,
    metadata: ExtendedMetadata,
}
#[test]
fn a_new_nested_property_needs_no_parallel_query_field_list() {
    let schema = Box::leak(Box::new(
        Schema::derived::<Extended>("extended", &["id"], 2, 10, &[]).unwrap(),
    ));
    assert!(
        schema
            .parse("filter=metadata.publisher=icontains=Acme")
            .is_ok()
    );
}

#[derive(JsonSchema, serde::Serialize, serde::Deserialize)]
struct Complex {
    id: i64,
    objects: Vec<Metadata>,
}
#[test]
fn unsupported_collections_and_misspelled_exclusions_fail_at_construction() {
    assert!(Schema::derived::<Complex>("complex", &["id"], 2, 10, &[]).is_err());
    assert!(
        Schema::derived::<Complex>(
            "complex",
            &["id"],
            2,
            10,
            &[Exclusion {
                path: "objects",
                reason: "Same-element semantics required"
            }]
        )
        .is_ok()
    );
    assert!(
        Schema::derived::<Complex>(
            "complex",
            &["id"],
            2,
            10,
            &[Exclusion {
                path: "typo",
                reason: "Wrong property"
            }]
        )
        .is_err()
    );
}

#[derive(JsonSchema, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Selection {
    All,
    Names { values: Vec<String> },
    Ids { values: Vec<uuid::Uuid> },
}
#[derive(JsonSchema, serde::Serialize, serde::Deserialize)]
struct Tagged {
    id: i64,
    selection: Selection,
}
#[test]
fn tagged_variants_merge_vocabularies_and_missing_properties_without_cross_element_expansion() {
    let schema = Box::leak(Box::new(
        Schema::derived::<Tagged>("tagged", &["id"], 2, 10, &[]).unwrap(),
    ));
    assert!(!schema.field("selection.kind").unwrap().nullable);
    assert!(schema.field("selection.values").unwrap().nullable);
    assert!(
        schema
            .parse("filter=selection.kind==names;selection.values=containsany=(a,b)")
            .is_ok()
    );
    assert!(schema.parse("filter=selection.kind==other").is_err());
}

#[test]
fn directory_rejects_paths_outside_the_query_grammar_budget() {
    let child = "c".repeat(100);
    let parent = "p".repeat(50);
    let model = serde_json::json!({"type":"object","required":["id"],"properties":{"id":{"type":"integer"},parent:{"type":"object","properties":{child:{"type":"string"}}}}});
    assert!(Schema::from_model("long_path", &["id"], 1, 10, &model, &[]).is_err());
}

#[test]
fn unbounded_text_filters_but_sort_combinations_must_fit_the_cursor() {
    assert!(MODEL.field("metadata.category").unwrap().filter);
    assert!(!MODEL.field("metadata.category").unwrap().sort);
    assert!(MODEL.parse("sort=metadata.category").is_err());
    #[derive(JsonSchema, serde::Serialize, serde::Deserialize)]
    struct Bounded {
        id: i64,
        #[schemars(length(max = 256))]
        a: String,
        #[schemars(length(max = 256))]
        b: String,
    }
    let model = Box::leak(Box::new(
        Schema::derived::<Bounded>("bounded", &["id"], 1, 2, &[]).unwrap(),
    ));
    assert!(model.parse("sort=a,b").is_err());
    let query = model.parse("sort=a").unwrap();
    let row = serde_json::json!({"id":1,"a":"合法\n多行","b":""});
    let position = query.position(&row).unwrap();
    let codec = rss_mdm_query::cursor::CursorCodec::new(&[1; 32]).unwrap();
    assert!(codec.encode("bounded", &position).is_ok());
}

#[test]
fn documented_closed_map_keys_keep_their_declared_types() {
    let model = serde_json::json!({"type":"object","required":["id"],"properties":{
        "id":{"type":"string","format":"uuid"},
        "packages":{"type":"object","propertyNames":{"oneOf":[
            {"type":"string","const":"windows","description":"Windows"},
            {"type":"string","const":"macos","description":"macOS"}
        ]},"additionalProperties":{"type":"string","format":"uuid"}}
    }});
    let schema = Box::leak(Box::new(
        Schema::from_model("closed_map", &["id"], 1, 10, &model, &[]).unwrap(),
    ));
    assert_eq!(
        schema.field("packages.windows").unwrap().kind,
        rss_mdm_query::directory::Kind::Uuid
    );
    assert!(
        schema
            .parse("filter=packages.linux==00000000-0000-0000-0000-000000000001")
            .is_err()
    );
    assert!(
        schema
            .parse("filter=id=gt=00000000-0000-0000-0000-000000000001")
            .is_ok()
    );
}

#[test]
fn text_range_boundaries_are_not_stored_values_or_seek_positions() {
    #[derive(JsonSchema, serde::Serialize)]
    struct Address {
        id: i64,
        #[schemars(length(min = 39, max = 39))]
        tool: String,
    }
    let model = Box::leak(Box::new(
        Schema::derived::<Address>("address", &["id"], 1, 2, &[]).unwrap(),
    ));
    for op in ["lt", "le", "gt", "ge"] {
        for boundary in ["policy_7".to_owned(), "z".repeat(64)] {
            assert!(
                model
                    .parse(&format!("filter=tool={op}={boundary}&sort=tool"))
                    .is_ok()
            );
        }
    }
    assert!(
        model
            .parse(&format!("filter=tool=gt={}", "a".repeat(4097)))
            .is_err()
    );
    assert!(model.parse("filter=tool=gt=%0A").is_err());
    assert!(
        model
            .parse("sort=tool")
            .unwrap()
            .position(&serde_json::json!({"id":1,"tool":"policy_7"}))
            .is_err()
    );
}
