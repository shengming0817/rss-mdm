//! Regenerate fixture coverage from the current public collection definition.
fn main() {
    let mut value: serde_json::Value =
        serde_json::from_str(include_str!("../../../fixtures/snapshot.json")).expect("fixture");
    value["coverage"] = serde_json::to_value(
        rss_mdm_examples::fixture::definition()
            .coverage()
            .expect("coverage"),
    )
    .expect("coverage JSON");
    println!(
        "{}",
        serde_json::to_string_pretty(&value).expect("fixture JSON")
    );
}
