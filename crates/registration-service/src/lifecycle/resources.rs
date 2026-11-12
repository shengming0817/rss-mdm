//! Product conflict declarations, independent of registration generations and
//! reconciliation scopes. RSS owns admission and claim lifetime.
//! ref: Tokio tokio-1.48.0 tokio/src/sync/batch_semaphore.rs (admission vs execution).
use rss_reconcile::ResourceSet;
use rss_request_context::TenantId;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy)]
pub enum Work {
    ScriptRecovery,
    AgentCollectionRecovery,
    Exclusive,
}

fn keys(device: &str, work: Work) -> Vec<String> {
    let endpoint = format!("{:x}", Sha256::digest(device.as_bytes()));
    match work {
        Work::ScriptRecovery => vec![format!("endpoint.{endpoint}.script")],
        Work::AgentCollectionRecovery => vec![format!("endpoint.{endpoint}.collection")],
        Work::Exclusive => vec![
            format!("endpoint.{endpoint}.script"),
            format!("endpoint.{endpoint}.collection"),
        ],
    }
}

pub fn device(tenant: TenantId, device: &str, work: Work) -> ResourceSet {
    ResourceSet::new(tenant, keys(device, work)).expect("two fixed bounded resource keys")
}

/// Current complete association/retirement membership, not just the initiating
/// endpoint. Existing product bounds keep this within RSS's resource-set budget.
pub fn devices(tenant: TenantId, devices: &[String]) -> Result<ResourceSet, crate::Error> {
    ResourceSet::new(
        tenant,
        devices.iter().flat_map(|d| keys(d, Work::Exclusive)),
    )
    .map_err(|_| crate::Error::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_script_and_agent_collection_have_disjoint_endpoint_resources() {
        let tenant = TenantId::parse("00000000-0000-0000-0000-000000000001").unwrap();
        let script = device(tenant, "device-a", Work::ScriptRecovery);
        let collection = device(tenant, "device-a", Work::AgentCollectionRecovery);
        let exclusive = device(tenant, "device-a", Work::Exclusive);
        assert!(script.keys().iter().all(|k| !collection.keys().contains(k)));
        assert!(
            script
                .keys()
                .iter()
                .chain(collection.keys())
                .all(|k| exclusive.keys().contains(k))
        );
        let other = device(tenant, "device-b", Work::Exclusive);
        assert!(exclusive.keys().iter().all(|k| !other.keys().contains(k)));
        let members = devices(
            tenant,
            &["device-b".into(), "device-a".into(), "device-a".into()],
        )
        .unwrap();
        assert_eq!(members.keys().len(), 4);
        assert!(
            exclusive
                .keys()
                .iter()
                .chain(other.keys())
                .all(|k| members.keys().contains(k))
        );
    }
}
