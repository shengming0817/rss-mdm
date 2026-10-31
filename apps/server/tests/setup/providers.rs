use super::*;
#[test]
fn equivalent_policy_order_is_stable_but_broader_scope_is_rejected() {
    let expected = policy("content", "content/tenant");
    let mut reordered = expected.clone();
    reordered["Statement"].as_array_mut().unwrap().reverse();
    assert_eq!(
        canonical_policy(expected.clone()),
        canonical_policy(reordered.clone())
    );
    reordered["Statement"][0]["Resource"] = json!(["arn:aws:s3:::content/content/*"]);
    assert_ne!(canonical_policy(expected), canonical_policy(reordered));
}
