use rss_mdm_resource::{
    Id, Kind,
    directory::{Record, SCHEMA},
};
use serde_json::json;
#[test]
fn shared_binding_preserves_resource_invariants_and_includes_metadata() {
    for input in [
        "filter=kind==unknown",
        "filter=active==1",
        "filter=revision==-1",
        "filter=kind=lt=script",
        "filter=presentation==x",
        "filter=id==a%27OR%271%27",
        "filter=presentation.custom.secret==x",
    ] {
        assert!(SCHEMA.parse(input).is_err(), "{input}");
    }
    let q = SCHEMA
        .parse(
            "filter=kind=in=(script,software);presentation.name=icontains=工具&sort=kind,-revision",
        )
        .unwrap();
    assert_eq!(
        q.sort()
            .iter()
            .map(|v| v.field.as_str())
            .collect::<Vec<_>>(),
        ["kind", "revision", "id"]
    );
    for key in [
        "presentation.name",
        "presentation.category",
        "presentation.publisher",
        "presentation.description",
        "activeVersion",
    ] {
        assert!(SCHEMA.field(key).unwrap().filter, "{key}");
    }
}
#[test]
fn projection_retains_extensions_and_nested_seek_is_independent_of_output() {
    let row = Record {
        id: Id::new("a").unwrap(),
        revision: 3,
        kind: Kind::Script,
        active: false,
        active_version: None,
        presentation: serde_json::from_value(json!({"name":"Éclair","custom":{"label":7}}))
            .unwrap(),
    };
    let q = SCHEMA
        .parse("fields=presentation&sort=presentation.name,-revision")
        .unwrap();
    let value = serde_json::to_value(&row).unwrap();
    assert_eq!(
        q.position(&value).unwrap().0,
        vec![json!("Éclair"), json!(3), json!("a")]
    );
    assert_eq!(
        serde_json::to_value(q.project_typed(row).unwrap()).unwrap(),
        json!({"presentation":{"name":"Éclair","custom":{"label":7}}})
    );
}
#[test]
fn query_and_authority_changes_invalidate_continuations() {
    let binding = |q: &str, tenant: &str| {
        SCHEMA
            .parse(q)
            .unwrap()
            .binding(&(tenant, "instance", "authority"))
            .unwrap()
    };
    assert_eq!(
        binding("fields=id,kind&limit=1", "a"),
        binding("fields=kind,id&limit=9", "a")
    );
    assert_ne!(
        binding("fields=id,kind", "a"),
        binding("fields=id,kind", "b")
    );
    assert_ne!(
        binding("fields=id,kind", "a"),
        binding("fields=id,kind&filter=active==true", "a")
    );
}
