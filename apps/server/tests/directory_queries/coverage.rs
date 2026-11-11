//! Test coverage follows actual composed owners, including conditional routes and every listener.
use super::*;
pub(super) fn check(cases: &[(String, String, Value)]) -> Result<()> {
    let contract = crate::http_contract_document().map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let mut mounted = std::collections::BTreeSet::new();
    let mut exercised = std::collections::BTreeSet::from(["devices".to_owned()]); // history::exercise, on this HTTP host
    // These execute through their original listener/realm fixture, with real PostgreSQL rows.
    // Keeping the proof location here makes a newly mounted owner fail until it has a consumer.
    exercised.extend(
        [
            "executions", // execution_owners::directory::recurring_owners_share_http_pagination_statistics_and_redacted_evidence
            "self_service", // execution_owners::self_service_directory::authenticated_self_service_filters_typed_fields_and_business_search
            "tenants",
            "provisionings", // operation_diagnostics::installation::original_tenant_result_and_missing_result_have_independent_evidence
            "device_access",
            "enterprise_configuration", // device_access foundation::business::verify
            "da_configurations", // device_access foundation::configuration::concurrent_export
        ]
        .into_iter()
        .map(str::to_owned),
    );
    for endpoint in contract["endpoints"]
        .as_array()
        .context("mounted endpoints")?
    {
        let owner = &endpoint["request"]["query_owner"];
        if owner["kind"] != "directory" || owner["schema"]["role"] != "list" {
            continue;
        }
        let id = owner["schema"]["id"]
            .as_str()
            .context("directory identity")?;
        mounted.insert(id.to_owned());
        let path = endpoint["path"].as_str().context("mounted path")?;
        if cases.iter().any(|(actual, _, _)| matches(path, actual)) {
            exercised.insert(id.into());
        }
    }
    assert_eq!(
        mounted, exercised,
        "each actual directory owner needs a nonempty discriminating HTTP/PostgreSQL proof"
    );
    Ok(())
}
fn matches(pattern: &str, path: &str) -> bool {
    let a = pattern.split('/').collect::<Vec<_>>();
    let b = path.split('/').collect::<Vec<_>>();
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(a, b)| a == &b || (a.starts_with('{') && a.ends_with('}') && !b.is_empty()))
}
