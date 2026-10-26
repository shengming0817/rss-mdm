use rss_mdm_query::{Error, Expression, Operator, Parameters, cursor::CursorCodec, parse_filter};
#[test]
fn precedence_quotes_and_sets_are_explicit() {
    let e = parse_filter("id=='a';revision=ge=2,kind=in=(script,software)").unwrap();
    let Expression::Or(parts) = e else {
        panic!("OR root")
    };
    assert!(matches!(&parts[0], Expression::And(v) if v.len()==2));
    assert!(
        matches!(&parts[1], Expression::Compare{operator:Operator::In,values,..} if values==&["script","software"])
    );
    assert!(
        matches!(parse_filter(r#"id=="a\"b""#).unwrap(),Expression::Compare{values,..} if values==["a\"b"])
    );
    for s in [
        "",
        "id==",
        "id==a;",
        "(id==a",
        "id=in=()",
        "id=in=(a,)",
        "id=='a",
        "id==a*",
        "id==a b",
        "id==a=gt=b",
        "id==a\\q",
    ] {
        assert!(parse_filter(s).is_err(), "{s}");
    }
}
#[test]
fn budgets_reject_before_unbounded_structure() {
    assert!(parse_filter(&format!("{}id==a{}", "(".repeat(16), ")".repeat(16))).is_ok());
    assert_eq!(
        parse_filter(&format!("{}id==a{}", "(".repeat(17), ")".repeat(17))),
        Err(Error::Budget)
    );
    assert!(parse_filter(&format!("id=in=({})", vec!["a"; 64].join(","))).is_ok());
    assert_eq!(
        parse_filter(&format!("id=in=({})", vec!["a"; 65].join(","))),
        Err(Error::Budget)
    );
    assert_eq!(
        parse_filter(&vec!["id==a"; 128].join(";")),
        Err(Error::Budget)
    );
    assert_eq!(
        parse_filter(&format!("id=='{}'", "a".repeat(1025))),
        Err(Error::Budget)
    );
    let set = format!("id=in=({})", vec!["a"; 64].join(","));
    assert_eq!(parse_filter(&vec![set; 5].join(";")), Err(Error::Budget));
    assert_eq!(parse_filter(&"a".repeat(8193)), Err(Error::Budget));
}
#[test]
fn parameters_are_single_decoded_strict_and_bounded() {
    let p = Parameters::parse("filter=id%3D%3D%27a%2Fb%27&sort=-revision,id&fields=id&limit=10")
        .unwrap();
    assert_eq!(p.filter.as_deref(), Some("id=='a/b'"));
    assert!(p.sort[0].descending);
    assert_eq!(p.limit, Some(10));
    for p in [
        "filter=",
        "limit=1&limit=2",
        "limit=1&%6cimit=2",
        "fields=",
        "cursor=",
        "unknown=1",
        "filter=%",
        "filter=%GG",
        "filter=%ff",
        "sort=id,,kind",
        "sort=id,id",
        "limit=-1",
        "filter=id==a&&sort=id",
    ] {
        assert!(Parameters::parse(p).is_err(), "{p}");
    }
    assert!(Parameters::parse(&format!("filter={}", "a".repeat(16385))).is_err());
}
#[test]
fn cursor_authenticates_context_and_position() {
    let codec = CursorCodec::new(&[7; 32]).unwrap();
    let token = codec
        .encode("context-a", &vec!["script", "resource-1"])
        .unwrap();
    assert_eq!(
        codec.decode::<Vec<String>>(&token, "context-a").unwrap(),
        ["script", "resource-1"]
    );
    assert_eq!(
        codec.decode::<Vec<String>>(&token, "context-b"),
        Err(Error::CursorInvalidated)
    );
    assert_eq!(
        CursorCodec::new(&[8; 32])
            .unwrap()
            .decode::<Vec<String>>(&token, "context-a"),
        Err(Error::CursorInvalidated)
    );
    let mut changed = token.as_str().as_bytes().to_vec();
    changed[20] = if changed[20] == b'A' { b'B' } else { b'A' };
    let changed = rss_contract::PageCursor::parse(std::str::from_utf8(&changed).unwrap()).unwrap();
    assert_eq!(
        codec.decode::<Vec<String>>(&changed, "context-a"),
        Err(Error::CursorInvalidated)
    );
}

#[test]
fn fixed_windows_reject_reinterpretation_and_keep_context_strict() {
    static SCHEMA: rss_mdm_query::window::Schema = rss_mdm_query::window::Schema {
        id: "test",
        default_limit: 10,
        max_limit: 100,
        order: "frozen source ordinal",
        context: &["scope"],
    };
    let (q, context) = SCHEMA.parse("limit=2&scope=device").unwrap();
    assert_eq!(q.limit(), 2);
    assert_eq!(context["scope"], "device");
    for raw in [
        "offset=0",
        "after=x",
        "sort=id",
        "filter=id==x",
        "fields=id",
        "limit=101",
        "scope=x&scope=y",
    ] {
        assert!(SCHEMA.parse(raw).is_err(), "{raw}");
    }
}

#[test]
fn windows_use_thousand_row_budget_and_reject_foreign_schemas() {
    use rss_mdm_query::{DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, window::Schema};
    static FIRST: Schema = Schema {
        id: "first",
        default_limit: DEFAULT_PAGE_LIMIT,
        max_limit: MAX_PAGE_LIMIT,
        order: "id",
        context: &[],
    };
    static SECOND: Schema = Schema {
        id: "second",
        default_limit: DEFAULT_PAGE_LIMIT,
        max_limit: MAX_PAGE_LIMIT,
        order: "id",
        context: &[],
    };
    let (query, _) = FIRST.parse("").unwrap();
    assert_eq!(query.limit(), 1000);
    assert!(query.require_schema(&FIRST).is_ok());
    assert!(query.require_schema(&SECOND).is_err());
    assert_eq!(FIRST.parse("limit=1000").unwrap().0.limit(), 1000);
    for raw in ["limit=0", "limit=1001", "afterAt=0", "afterId=123"] {
        assert!(FIRST.parse(raw).is_err(), "{raw}");
    }
}
