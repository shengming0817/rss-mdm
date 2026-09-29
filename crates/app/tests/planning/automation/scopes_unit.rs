#[test]
fn scope_page_budget_is_inclusive_and_rejects_overflow() {
    assert!(check_scope_page(999_999, 1).is_ok());
    for (processed, added) in [(1_000_000, 1), (usize::MAX, 1)] {
        assert!(matches!(
            check_scope_page(processed, added),
            Err(Error::Unavailable(Failure::AssetObjectLimit))
        ));
    }
}
