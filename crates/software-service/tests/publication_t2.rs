use rss_mdm_software_release as rel;
use rss_mdm_software_service::publication::*;
use tracing::instrument::WithSubscriber;
#[path = "../../../tests/support/software/mod.rs"]
mod publication_support;
use publication_support::pg::*;
use publication_support::*;
fn assert_publication_audit(p: &rel::Publication, candidate: &rel::CandidateId, outcome: &str) {
    let digest: String = p
        .id()
        .digest()
        .bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let rows = audit_records()
        .iter()
        .map(audit_payload)
        .filter(|p| {
            p["software"]["publication"] == digest
                && p["software"]["stage"] == "record_result"
                && p["software"]["outcome"] == outcome
        })
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 1);
    let fact = &rows[0]["software"];
    let request_hash = sql(&format!(
        "SELECT encode(sha256(convert_to(id,'UTF8')),'hex') FROM mdm_software_release.requests WHERE tenant_id='{}' AND owner='{}' AND id LIKE 'record/%'",
        candidate.tenant(),
        candidate.value()
    ));
    assert_eq!(request_hash.lines().count(), 1);
    assert_eq!(fact["operation"], request_hash);
    assert_eq!(fact["publication"], digest);
    assert_eq!(fact["attempt"], p.attempt);
    assert_eq!(fact["ring"], 0);
    assert_eq!(fact["binding"].as_str().unwrap().len(), 64);
    assert_eq!(fact["outcome"], outcome);
    assert_eq!(
        rows[0]["result"],
        if outcome == "unknown" {
            "unknown"
        } else {
            "success"
        }
    );
    assert_eq!(
        rows[0]["status"],
        if outcome == "unknown" { 202 } else { 200 }
    );
    assert_eq!(fact.as_object().unwrap().len(), 7);
}
#[derive(Clone)]
struct AuditLog(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
impl std::io::Write for AuditLog {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[path = "publication/artifact.rs"]
mod artifact;
#[path = "publication/brew.rs"]
mod brew;
#[path = "publication/mapping.rs"]
mod mapping;
#[path = "publication/recovery.rs"]
mod recovery;
#[path = "publication/winget.rs"]
mod winget;
#[path = "publication/withdrawal.rs"]
mod withdrawal;
