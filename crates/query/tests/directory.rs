use rss_mdm_query::{
    Error,
    cursor::CursorCodec,
    directory::{Field, Kind, Schema},
};
use serde_json::{Value, json};
static SCHEMA: Schema = Schema {
    id: "example",
    keys: &["id"],
    default_limit: 2,
    max_limit: 3,
    fields: &[
        Field::scalar("id", Kind::Integer),
        Field::scalar("name", Kind::Text),
        Field::scalar("enabled", Kind::Boolean),
        Field::output("detail"),
    ],
};
#[test]
fn projection_does_not_change_authenticated_seek_and_context_is_bound() {
    let q = SCHEMA.parse("sort=name&fields=name&limit=1").unwrap();
    let codec = CursorCodec::new(&[3; 32]).unwrap();
    let binding = q.binding(&("tenant", "principal", "authority")).unwrap();
    let page = q
        .page(
            vec![json!({"id":1,"name":"same"}), json!({"id":2,"name":"same"})],
            &codec,
            &binding,
        )
        .unwrap();
    assert_eq!(page.items, vec![json!({"name":"same"})]);
    let token = page.next_cursor.unwrap();
    let next = SCHEMA
        .parse(&format!("sort=name&fields=name&limit=3&cursor={token}"))
        .unwrap();
    assert_eq!(
        next.binding(&("tenant", "principal", "authority")).unwrap(),
        binding
    );
    assert_eq!(
        next.after(&codec, &binding).unwrap().unwrap().0,
        vec![json!("same"), json!(1)]
    );
    assert!(matches!(
        next.after(
            &codec,
            &next.binding(&("other", "principal", "authority")).unwrap()
        ),
        Err(Error::CursorInvalidated)
    ));
    let changed = SCHEMA
        .parse(&format!("sort=name&fields=id&cursor={token}"))
        .unwrap();
    assert!(
        changed
            .after(
                &codec,
                &changed
                    .binding(&("tenant", "principal", "authority"))
                    .unwrap()
            )
            .is_err()
    );
}
#[test]
fn declared_capabilities_reject_invalid_queries_and_old_parameters() {
    for raw in [
        "after=1",
        "descending=true",
        "filter=secret==x",
        "fields=secret",
        "sort=detail",
        "filter=detail==x",
        "filter=enabled==yes",
        "filter=enabled=gt=true",
        "filter=id==1.5",
        "limit=0",
        "limit=4",
        "fields=",
        "sort=id,-id",
    ] {
        assert!(SCHEMA.parse(raw).is_err(), "{raw}");
    }
    assert!(
        SCHEMA
            .parse("filter=name=icontains=ab;enabled==true&sort=-name")
            .is_ok()
    );
}
#[test]
fn nullable_positions_keep_unique_identity_and_terminal_pages_have_no_cursor() {
    let q = SCHEMA.parse("sort=name&fields=id").unwrap();
    let codec = CursorCodec::new(&[4; 32]).unwrap();
    let row = json!({"id":2,"name":null});
    assert_eq!(q.position(&row).unwrap().0, vec![json!(null), json!(2)]);
    let page = q.page(vec![row], &codec, "scope").unwrap();
    assert_eq!(page.items, vec![json!({"id":2})]);
    assert!(page.next_cursor.is_none());
    assert!(q.page(vec![], &codec, "scope").unwrap().items.is_empty());
}
#[test]
fn context_parameters_use_the_same_strict_decoder() {
    use rss_mdm_query::Parameters;
    for raw in [
        "referenceableFor=a&referenceableFor=b",
        "referenceableFor=",
        "referenceableFor=%ff",
        "unknown=a",
    ] {
        assert!(Parameters::parse_with_context(raw, &["referenceableFor"]).is_err());
    }
    assert_eq!(
        Parameters::parse_with_context("referenceableFor=a%2Bb&limit=1", &["referenceableFor"])
            .unwrap()
            .1["referenceableFor"],
        "a+b"
    );
}

#[test]
fn bounded_product_continuations_keep_authentication_and_strict_query_admission() {
    static WINDOW: rss_mdm_query::window::Schema = rss_mdm_query::window::Schema {
        id: "fixed_input",
        default_limit: 1,
        max_limit: 10,
        order: "ordinal",
        context: &[],
    };
    let codec = CursorCodec::new(&[9; 32]).unwrap();
    let input = json!({"snapshot": "1".repeat(65_536), "after": "x".repeat(48_000)});
    let token = codec.encode_bounded("assets", &input, 256 * 1024).unwrap();
    assert!(codec.encode("assets", &input).is_err());
    let raw = format!("cursor={token}&limit=1");
    assert!(WINDOW.parse(&raw).is_err());
    let (parsed, _) = WINDOW
        .parse_with_budgets(&raw, 384 * 1024, 256 * 1024)
        .unwrap();
    let actual: Value = codec
        .decode_bounded(parsed.cursor().as_deref().unwrap(), "assets", 256 * 1024)
        .unwrap();
    assert_eq!(actual, input);
    assert!(
        codec
            .decode_bounded::<Value>(&token, "other", 256 * 1024)
            .is_err()
    );
    assert!(
        codec
            .decode_bounded::<Value>(&token, "assets", token.len() - 1)
            .is_err()
    );
    for raw in [
        format!("{raw}&cursor={token}"),
        format!("{raw}&unknown=x"),
        "cursor=AAAA=".into(),
        "cursor=AB".into(),
    ] {
        assert!(
            WINDOW
                .parse_with_budgets(&raw, 384 * 1024, 256 * 1024)
                .is_err()
        );
    }
    let forged = format!(
        "{}{}",
        if token.starts_with('A') { "B" } else { "A" },
        &token[1..]
    );
    assert!(
        codec
            .decode_bounded::<Value>(&forged, "assets", 256 * 1024)
            .is_err()
    );
}
