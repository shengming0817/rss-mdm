use crate::BackendStorage;
use rss_transactional_messaging_postgres::PgError;
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

/// Maximum encoded JSON document size, inclusive.
pub const MAX_DOCUMENT: usize = 64 * 1024 * 1024;
#[derive(Debug, thiserror::Error)]
#[error("{domain} {stage}: {kind}: {reason}")]
struct Diagnostic {
    domain: &'static str,
    stage: &'static str,
    kind: &'static str,
    reason: String,
}
impl BackendStorage {
    /// Reject a storage invariant without disclosing stored values.
    pub fn fault(self, stage: &'static str) -> PgError {
        tracing::error!(
            domain = self.kind.domain(),
            stage,
            reason = "storage-invariant",
            "adapter data rejected"
        );
        sqlx::Error::Protocol(format!("{} storage invariant", self.kind.schema())).into()
    }
    fn diagnostic(self, stage: &'static str, kind: &'static str, reason: String) -> PgError {
        self.classify(stage, kind, reason).into_error()
    }
    fn classify(self, stage: &'static str, kind: &'static str, reason: String) -> Diagnostic {
        Diagnostic {
            domain: self.kind.domain(),
            stage,
            kind,
            reason,
        }
    }
}
impl Diagnostic {
    fn into_error(self) -> PgError {
        let Self {
            domain,
            stage,
            kind,
            ref reason,
            ..
        } = self;
        tracing::error!(domain, stage, kind, %reason, "adapter data rejected");
        sqlx::Error::Decode(Box::new(self)).into()
    }
}
impl BackendStorage {
    /// A static domain category; the adapter must not pass request/error contents.
    pub fn domain_error(
        self,
        stage: &'static str,
        kind: &'static str,
        category: &'static str,
    ) -> PgError {
        self.diagnostic(stage, kind, category.to_owned())
    }
    /// Canonical parser failures retain type and stage, never arbitrary error text.
    pub fn invalid<T, E>(self, stage: &'static str, result: Result<T, E>) -> Result<T, PgError> {
        result.map_err(|_| self.domain_error(stage, std::any::type_name::<E>(), "invalid-value"))
    }
    /// Keep only JSON error category and input position.
    pub fn json<T>(
        self,
        stage: &'static str,
        result: Result<T, serde_json::Error>,
    ) -> Result<T, PgError> {
        result.map_err(|e| {
            self.diagnostic(
                stage,
                std::any::type_name::<serde_json::Error>(),
                json_reason(&e),
            )
        })
    }
    /// Report integer range failure with a static reason.
    pub fn integer<T>(
        self,
        stage: &'static str,
        result: Result<T, std::num::TryFromIntError>,
    ) -> Result<T, PgError> {
        result.map_err(|_| {
            self.domain_error(
                stage,
                std::any::type_name::<std::num::TryFromIntError>(),
                "integer-out-of-range",
            )
        })
    }
    /// Encode bounded JSON with the existing wire representation.
    pub fn encode(self, value: &impl Serialize) -> Result<Vec<u8>, PgError> {
        let bytes = self.json("db::encode", serde_json::to_vec(value))?;
        if bytes.len() > MAX_DOCUMENT {
            return Err(self.fault("db::encode"));
        }
        Ok(bytes)
    }
    /// Decode bounded JSON; domain validation remains with the adapter.
    pub fn decode<T: DeserializeOwned>(self, bytes: &[u8]) -> Result<T, PgError> {
        if bytes.len() > MAX_DOCUMENT {
            return Err(self.fault("db::decode"));
        }
        self.json("db::decode", serde_json::from_slice(bytes))
    }
    /// Verify SHA-256 before returning persisted bytes.
    pub fn checked(self, bytes: Vec<u8>, hash: Vec<u8>) -> Result<Vec<u8>, PgError> {
        if digest(&bytes) == hash {
            Ok(bytes)
        } else {
            Err(self.fault("db::checked"))
        }
    }
}
fn json_reason(error: &serde_json::Error) -> String {
    format!(
        "{:?} at {}:{}",
        error.classify(),
        error.line(),
        error.column()
    )
}
/// Existing SHA-256 representation used for documents and receipts.
pub fn digest(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BackendKind;
    const STORAGE: BackendStorage = BackendStorage::new(BackendKind::Resource);
    #[test]
    fn corruption_and_diagnostics_do_not_expose_inputs() {
        let bytes = STORAGE
            .encode(&serde_json::json!({"secret":"private-token"}))
            .unwrap();
        assert!(STORAGE.checked(bytes.clone(), vec![0; 32]).is_err());
        assert_eq!(
            STORAGE.checked(bytes.clone(), digest(&bytes)).unwrap(),
            bytes
        );
        let error = STORAGE
            .json(
                "receipt-decode",
                serde_json::from_str::<u64>("\"private-token\""),
            )
            .unwrap_err();
        let message = format!("{error:?}");
        let error = serde_json::from_str::<u64>("\"private-token\"").unwrap_err();
        let diagnostic = STORAGE.classify(
            "receipt-decode",
            std::any::type_name::<serde_json::Error>(),
            json_reason(&error),
        );
        let detail = format!("{diagnostic:?}");
        assert!(detail.contains("receipt-decode") && detail.contains("Data"));
        assert!(!detail.contains("private-token"));
        assert!(!message.contains("private-token"));
        let error = STORAGE
            .integer("revision", u64::try_from(-1_i64))
            .unwrap_err();
        assert!(!format!("{error:?}").contains("private-token"));
        assert!(STORAGE.decode::<serde_json::Value>(b"{").is_err());
    }
    #[test]
    fn document_limit_is_inclusive_for_encode_and_decode() {
        // JSON string framing consumes two bytes.
        let text = "x".repeat(MAX_DOCUMENT - 2);
        let bytes = STORAGE.encode(&text).unwrap();
        assert_eq!(bytes.len(), MAX_DOCUMENT);
        assert_eq!(STORAGE.decode::<String>(&bytes).unwrap(), text);
        assert!(STORAGE.encode(&(text + "x")).is_err());
        let oversized = vec![b' '; MAX_DOCUMENT + 1];
        assert!(STORAGE.decode::<serde_json::Value>(&oversized).is_err());
    }
}

#[cfg(test)]
mod logging_tests {
    use super::*;
    use crate::BackendKind;
    use std::sync::{Arc, Mutex};
    struct Capture(Arc<Mutex<Vec<String>>>, std::thread::ThreadId);
    struct Domains<'a>(&'a mut Vec<String>);
    impl tracing::field::Visit for Domains<'_> {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            if field.name() == "domain" {
                self.0.push(value.to_owned());
            }
        }
        fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
    }
    impl tracing::Subscriber for Capture {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            if std::thread::current().id() == self.1 {
                event.record(&mut Domains(&mut self.0.lock().unwrap()));
            }
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }
    #[test]
    fn both_error_paths_identify_the_backend_in_logs() {
        let domains = Arc::new(Mutex::new(Vec::new()));
        // One global subscriber for this test binary avoids callsite-interest races
        // with other parallel tests using the same diagnostic callsites. Record only
        // this test thread, while keeping every callsite enabled on all threads.
        tracing::subscriber::set_global_default(Capture(
            domains.clone(),
            std::thread::current().id(),
        ))
        .unwrap();
        {
            for kind in [
                BackendKind::Policy,
                BackendKind::Resource,
                BackendKind::SoftwareRelease,
            ] {
                let storage = BackendStorage::new(kind);
                let _ = storage.fault("db::checked");
                let _ = storage.decode::<serde_json::Value>(b"{");
            }
        }
        assert_eq!(
            *domains.lock().unwrap(),
            [
                "policy",
                "policy",
                "resource",
                "resource",
                "software-release",
                "software-release"
            ]
        );
    }
}
