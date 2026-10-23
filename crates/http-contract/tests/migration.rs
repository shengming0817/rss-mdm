//! Migration exceptions are an exact, shrinking baseline, not a capability-off switch.
use rss_mdm_http_contract::{QueryPolicy, catalog};
use std::collections::BTreeSet;
use std::process::Command;
use syn::{Expr, Item, Member};
fn unwrap_ref(expr: &Expr) -> &Expr {
    if let Expr::Reference(r) = expr {
        unwrap_ref(&r.expr)
    } else {
        expr
    }
}
fn text(expr: &Expr) -> String {
    match expr {
        Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(s),
            ..
        }) => s.value(),
        Expr::Path(p) => p.path.segments.last().unwrap().ident.to_string(),
        _ => panic!("unexpected migration identity"),
    }
}
fn number(expr: &Expr) -> u32 {
    let Expr::Lit(syn::ExprLit {
        lit: syn::Lit::Int(n),
        ..
    }) = expr
    else {
        panic!("explicit issue required")
    };
    n.base10_parse().unwrap()
}
fn prior(source: &str) -> (BTreeSet<(String, String, u32)>, BTreeSet<(String, u32)>) {
    let file = syn::parse_file(source).unwrap();
    let mut gaps = BTreeSet::new();
    let mut pending = BTreeSet::new();
    for item in file.items {
        let Item::Static(item) = item else { continue };
        if item.ident == "GAPS" {
            let Expr::Array(a) = unwrap_ref(&item.expr) else {
                panic!("explicit gaps required")
            };
            for entry in &a.elems {
                let Expr::Struct(e) = entry else {
                    panic!("explicit gap required")
                };
                let field = |name: &str| {
                    &e.fields
                        .iter()
                        .find(|f| matches!(&f.member,Member::Named(n) if n==name))
                        .unwrap()
                        .expr
                };
                gaps.insert((
                    text(field("resource")),
                    text(field("operation")),
                    number(field("issue")),
                ));
            }
        } else if let Expr::Struct(e) = unwrap_ref(&item.expr) {
            let field = |name: &str| {
                e.fields
                    .iter()
                    .find(|f| matches!(&f.member,Member::Named(n) if n==name))
                    .map(|f| &f.expr)
            };
            if let (Some(id), Some(Expr::Call(q))) = (field("id"), field("query")) {
                if text(&q.func) == "Pending" {
                    pending.insert((text(id), number(&q.args[0])));
                }
            }
        }
    }
    (gaps, pending)
}
#[test]
fn migration_baseline_only_shrinks_and_all_gaps_have_existing_owners() {
    let gaps = catalog::GAPS
        .iter()
        .map(|g| {
            assert!([2902, 2904, 2906].contains(&g.issue) && !g.reason.is_empty());
            let resource = catalog::ALL
                .iter()
                .find(|r| r.id == g.resource)
                .expect("gap resource exists");
            assert!(resource.category.required().contains(&g.operation));
            (g.resource.to_owned(), format!("{:?}", g.operation), g.issue)
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(gaps.len(), catalog::GAPS.len(), "duplicate migration gap");
    let pending = catalog::ALL
        .iter()
        .filter_map(|r| match r.query {
            QueryPolicy::Pending(issue) => {
                assert!([2902, 2904, 2906].contains(&issue));
                Some((r.id.to_owned(), issue))
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let base = std::env::var("CI_BASE").unwrap_or_else(|_| "origin/develop".into());
    let merged = Command::new("/usr/bin/git")
        .args(["merge-base", &base, "HEAD"])
        .current_dir(&root)
        .output()
        .unwrap();
    assert!(merged.status.success(), "cannot resolve migration baseline");
    let base = String::from_utf8(merged.stdout).unwrap();
    let path = format!("{}:crates/http-contract/src/catalog.rs", base.trim());
    let exists = Command::new("/usr/bin/git")
        .args(["cat-file", "-e", &path])
        .current_dir(&root)
        .output()
        .unwrap();
    // Initial #2900 adds this owner. Subsequent changes compare against the actual shared base.
    if !exists.status.success() {
        return;
    }
    let old = Command::new("/usr/bin/git")
        .args(["show", &path])
        .current_dir(&root)
        .output()
        .unwrap();
    assert!(old.status.success());
    let (old_gaps, old_pending) = prior(&String::from_utf8(old.stdout).unwrap());
    assert!(
        gaps.is_subset(&old_gaps),
        "operation migration gaps expanded"
    );
    assert!(
        pending.is_subset(&old_pending),
        "query migration gaps expanded"
    );
}
#[test]
fn expanded_gap_is_not_an_acceptable_baseline_subset() {
    let (gaps, pending) = prior(
        r#"static GAPS:&[Gap]=&[Gap{resource:"a",operation:Op::List,issue:2902,reason:"missing"}]; static A:Resource=Resource{id:"a",query:QueryPolicy::Pending(2902)};"#,
    );
    assert!(gaps.contains(&("a".into(), "List".into(), 2902)));
    assert!(pending.contains(&("a".into(), 2902)));
    let mut expanded = gaps.clone();
    expanded.insert(("b".into(), "List".into(), 2902));
    assert!(!expanded.is_subset(&gaps));
}
