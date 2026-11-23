//! The host selects finite listener, request and process-drain budgets.
use super::{ConfigIssue, Error};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Http {
    pub da_listener: DaListener,
    pub request_slots: usize,
    pub buffered_body_bytes: usize,
    pub connections: usize,
    pub prepare_seconds: u64,
    pub first_request_seconds: u64,
    pub connection_drain_seconds: u64,
    pub header_seconds: u64,
    pub max_headers: usize,
    pub buffer_bytes: usize,
    pub request_seconds: u64,
    pub total_drain_seconds: u64,
    pub admission_drain_seconds: u64,
}
#[derive(Clone, Copy)]
pub(crate) struct Compiled {
    pub da_listener: rss_axum::Http1ServePolicy,
    pub da_requests: usize,
    pub request_slots: usize,
    pub buffered_body_bytes: usize,
    pub listener: rss_axum::Http1ServePolicy,
    pub request: rss_axum::RequestBudget,
    pub total_drain: Duration,
    pub admission_drain: Duration,
}
impl Http {
    pub(crate) fn installation(request_slots: usize, buffered_body_bytes: usize) -> Self {
        Self {
            request_slots,
            buffered_body_bytes,
            da_listener: DaListener {
                connections: 16,
                prepare_seconds: 5,
                first_request_seconds: 3,
                drain_seconds: 12,
                header_seconds: 3,
                max_headers: 64,
                buffer_bytes: 32768,
            },
            connections: 128,
            prepare_seconds: 8,
            first_request_seconds: 10,
            connection_drain_seconds: 10,
            header_seconds: 10,
            max_headers: 64,
            buffer_bytes: 32768,
            request_seconds: 8,
            total_drain_seconds: 60,
            admission_drain_seconds: 35,
        }
    }
    pub(crate) fn compile(
        &self,
        identity: &crate::identity::policy::RuntimePolicy,
    ) -> Result<Compiled, Error> {
        let bad = || Error::Configuration(ConfigIssue::Budget);
        let seconds = crate::identity::policy::seconds;
        let total_drain = seconds(self.total_drain_seconds)?;
        if self.request_slots == 0 || self.request_slots > tokio::sync::Semaphore::MAX_PERMITS
            || self.buffered_body_bytes < rss_mdm_management_http::body_limits().largest_buffer()
            || self.buffered_body_bytes > tokio::sync::Semaphore::MAX_PERMITS
            || self.request_seconds.max(identity.request_seconds) > self.admission_drain_seconds
            || self.admission_drain_seconds > self.total_drain_seconds
            || self.connection_drain_seconds > self.total_drain_seconds
            || identity.kdf_drain_seconds > self.total_drain_seconds
        {
            return Err(bad());
        }
        let listener = rss_axum::Http1ServePolicy::new(
            rss_axum::ServePolicy::new(
                self.connections,
                seconds(self.prepare_seconds)?,
                seconds(self.first_request_seconds)?,
                seconds(self.connection_drain_seconds)?,
            )
            .map_err(|_| bad())?,
            seconds(self.header_seconds)?,
            self.max_headers,
            self.buffer_bytes,
        )
        .map_err(|_| bad())?;
        let da_listener = self.da_listener.compile()?;
        if self.da_listener.drain_seconds > self.total_drain_seconds {
            return Err(bad());
        }
        Ok(Compiled {
            request_slots: self.request_slots,
            buffered_body_bytes: self.buffered_body_bytes,
            da_listener,
            da_requests: self.da_listener.connections,
            listener,
            request: rss_axum::RequestBudget::new(seconds(self.request_seconds)?)
                .map_err(|_| bad())?,
            total_drain,
            admission_drain: seconds(self.admission_drain_seconds)?,
        })
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DaListener {
    pub connections: usize,
    pub prepare_seconds: u64,
    pub first_request_seconds: u64,
    pub drain_seconds: u64,
    pub header_seconds: u64,
    pub max_headers: usize,
    pub buffer_bytes: usize,
}
impl DaListener {
    fn compile(&self) -> Result<rss_axum::Http1ServePolicy, Error> {
        let seconds = crate::identity::policy::seconds;
        let bad = |_| Error::Configuration(ConfigIssue::Budget);
        rss_axum::Http1ServePolicy::new(
            rss_axum::ServePolicy::new(
                self.connections,
                seconds(self.prepare_seconds)?,
                seconds(self.first_request_seconds)?,
                seconds(self.drain_seconds)?,
            )
            .map_err(bad)?,
            seconds(self.header_seconds)?,
            self.max_headers,
            self.buffer_bytes,
        )
        .map_err(bad)
    }
}
