//! Declared gaps must identify current resources and required operations.
use rss_mdm_http_contract::{QueryPolicy, catalog};
use std::collections::BTreeSet;

#[test]
fn current_gaps_have_resource_and_operation_owners() {
    let gaps = catalog::GAPS
        .iter()
        .map(|g| {
            assert!(g.issue > 0 && !g.reason.is_empty());
            let resource = catalog::ALL
                .iter()
                .find(|r| r.id == g.resource)
                .expect("gap resource exists");
            assert!(resource.category.required().contains(&g.operation));
            (g.resource, format!("{:?}", g.operation), g.issue)
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(gaps.len(), catalog::GAPS.len(), "duplicate migration gap");
    for resource in catalog::ALL {
        if let QueryPolicy::Pending(issue) = resource.query {
            assert!(issue > 0);
        }
    }
}
