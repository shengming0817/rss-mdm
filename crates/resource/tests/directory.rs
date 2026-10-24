use rss_mdm_resource::{
    Id, Kind,
    directory::{Field, Position, Query, Record, Scalar},
};
#[test]
fn typed_binding_rejects_unsupported_values_and_capabilities() {
    for input in [
        "filter=kind==unknown",
        "filter=active==1",
        "filter=revision==-1",
        "filter=revision==9223372036854775808",
        "filter=kind=lt=script",
        "filter=presentation==x",
        "filter=id==a%27OR%271%27",
        "sort=active",
        "fields=active",
    ] {
        assert!(Query::parse(input).is_err(), "{input}");
    }
    let q =
        Query::parse("filter=kind=in=(script,software);active==true&sort=kind,-revision").unwrap();
    assert_eq!(
        q.sort().iter().map(|v| v.field).collect::<Vec<_>>(),
        [Field::Kind, Field::Revision, Field::Id]
    );
    assert_eq!(q.limit(), 64);
}
#[test]
fn projection_cannot_remove_seek_position_or_extension_keys() {
    let row = Record {
        id: Id::new("a").unwrap(),
        revision: 3,
        kind: Kind::Script,
        active_version: None,
        presentation: serde_json::from_value(serde_json::json!({"custom":{"label":7}})).unwrap(),
    };
    let q = Query::parse("fields=presentation&sort=-revision").unwrap();
    let position = q.position(&row);
    assert!(q.validate_position(&position).is_ok());
    assert_eq!(position.0, [Scalar::Integer(3), Scalar::Text("a".into())]);
    assert_eq!(
        serde_json::Value::Object(q.project(row)),
        serde_json::json!({"presentation":{"custom":{"label":7}}})
    );
    assert!(
        q.validate_position(&Position(vec![
            Scalar::Integer(-1),
            Scalar::Text("a".into())
        ]))
        .is_err()
    );
}
#[test]
fn context_changes_invalidate_but_page_size_and_projection_order_do_not() {
    let binding =
        |q: &str, t: &str, a: &str| Query::parse(q).unwrap().binding(t, "instance", a).unwrap();
    let first = binding("fields=kind,id&limit=1", "tenant", "authority");
    assert_eq!(
        first,
        binding("fields=id,kind&limit=9", "tenant", "authority")
    );
    for (q, t, a) in [
        ("fields=id", "tenant", "authority"),
        ("fields=id,kind&sort=-id", "tenant", "authority"),
        ("fields=id,kind", "other", "authority"),
        ("fields=id,kind", "tenant", "changed"),
    ] {
        assert_ne!(first, binding(q, t, a));
    }
}
