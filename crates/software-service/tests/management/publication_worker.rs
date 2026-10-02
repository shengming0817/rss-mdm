use super::*;
use crate::publication::{ArtifactOrigin, ArtifactReader, PublicationWork};
use rss_mdm_software_release::{Digest, PublicationId};
#[test]
fn recovery_failure_records_safe_category_and_original_identity() {
    let tenant =
        rss_request_context::TenantId::parse("10000000-0000-0000-0000-000000000001").unwrap();
    let error = ArtifactReader::new(
        vec![ArtifactOrigin {
            base: "https://provider.test/".into(),
            addresses: vec!["8.8.8.8".parse().unwrap()],
            private_ca: Some(
                b"-----BEGIN CERTIFICATE-----\nsecret-provider-token\n-----END CERTIFICATE-----"
                    .to_vec(),
            ),
        }],
        1024,
        std::time::Duration::from_secs(1),
    )
    .err()
    .expect("invalid CA");
    let scan = failure_event("private-source", tenant, &error, None);
    assert_eq!(scan["tenant"], tenant.to_string());
    assert_eq!(scan["phase"], "scan");
    assert_eq!(scan["category"], "input");
    assert_eq!(scan["stage"], "artifact::new");
    let work = PublicationWork {
        cursor: "original-cursor".into(),
        publication: PublicationId::from_digest(Digest::from_bytes([7; 32])),
        attempt: 3,
        withdrawal: true,
    };
    let event = failure_event("private-source", tenant, &error, Some(&work));
    assert_eq!(event["publication"], "07".repeat(32));
    assert_eq!(event["attempt"], 3);
    assert_eq!(event["withdrawal"], true);
    assert!(!event.to_string().contains("secret-provider-token"));
    assert!(!event.to_string().contains("credential@"));
}
