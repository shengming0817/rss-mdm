//! Internal request budgets use the attested client source; Nginx owns public transport limits.
//! ref: Axum serve/listener.rs keeps accepted IO and its address together; Tokio owned permits.
use axum::{
    Extension, Json,
    extract::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
mod windows;
pub(crate) use windows::admit_windows;

struct Bucket {
    tokens: f64,
    at: Instant,
    capacity: f64,
    rate: f64,
}
impl Bucket {
    fn new(now: Instant, capacity: f64, rate: f64) -> Self {
        Self {
            tokens: capacity,
            at: now,
            capacity,
            rate,
        }
    }
    fn take(&mut self, now: Instant) -> bool {
        if now < self.at {
            return false;
        }
        self.tokens = self
            .capacity
            .min(self.tokens + now.saturating_duration_since(self.at).as_secs_f64() * self.rate);
        self.at = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
    fn wait(&mut self, now: Instant) -> Duration {
        if now < self.at {
            return Duration::from_secs(1);
        }
        self.tokens = self
            .capacity
            .min(self.tokens + now.saturating_duration_since(self.at).as_secs_f64() * self.rate);
        self.at = now;
        Duration::from_secs_f64(((1.0 - self.tokens) / self.rate).max(0.0))
    }
    fn refund(&mut self, now: Instant) {
        self.wait(now);
        self.tokens = (self.tokens + 1.0).min(self.capacity);
    }
}
struct Peer {
    requests: Arc<Semaphore>,
    request_rate: Bucket,
    seen: Instant,
}
impl Peer {
    fn new(now: Instant) -> Self {
        Self {
            requests: Arc::new(Semaphore::new(2)),
            request_rate: Bucket::new(now, 64.0, 4.0),
            seen: now,
        }
    }
}
struct State {
    peers: BTreeMap<IpAddr, Peer>,
    devices: BTreeMap<(uuid::Uuid, String), Peer>,
    requests: Bucket,
}
pub(crate) struct Admission {
    clock: Arc<dyn rss_observation::Clock>,
    state: Mutex<State>,
    requests: Arc<Semaphore>,
    name: &'static str,
    refused: [AtomicU64; 2],
}
#[derive(Clone)]
pub(crate) struct RequestGate {
    owner: Arc<Admission>,
    peer: IpAddr,
}
impl Admission {
    pub(crate) fn new(
        clock: Arc<dyn rss_observation::Clock>,
        requests: Arc<Semaphore>,
        name: &'static str,
    ) -> Arc<Self> {
        let now = clock.now();
        Arc::new(Self {
            clock,
            requests,
            name,
            refused: [AtomicU64::new(0), AtomicU64::new(0)],
            state: Mutex::new(State {
                peers: BTreeMap::new(),
                devices: BTreeMap::new(),
                requests: Bucket::new(now, 256.0, 64.0),
            }),
        })
    }
    fn refused(&self, kind: usize) {
        let count = self.refused[kind].fetch_add(1, Ordering::Relaxed) + 1;
        // Low-cost counters with logarithmic diagnostics; no per-denial PG writes or peer values.
        if count.is_power_of_two() {
            eprintln!(
                "{}",
                serde_json::json!({"event":"mdm_ingress_limited","listener":self.name,"kind":if kind==0 { "connection" } else { "request" },"count":count})
            );
        }
    }
    pub(crate) fn gate(self: &Arc<Self>, address: IpAddr) -> Option<RequestGate> {
        let now = self.clock.now();
        let mut state = self.state.lock().ok()?;
        state.peers.retain(|_, peer| {
            now.saturating_duration_since(peer.seen) < Duration::from_secs(300)
                || peer.requests.available_permits() < 2
        });
        if !state.peers.contains_key(&address) && state.peers.len() >= 4096 {
            return None;
        }
        state
            .peers
            .entry(address)
            .or_insert_with(|| Peer::new(now))
            .seen = now;
        Some(RequestGate {
            owner: self.clone(),
            peer: address,
        })
    }
    fn peer_request(&self, address: IpAddr) -> Option<OwnedSemaphorePermit> {
        let now = self.clock.now();
        let mut state = self.state.lock().ok()?;
        let peer = state.peers.get_mut(&address)?;
        peer.seen = now;
        let slot = peer.requests.clone().try_acquire_owned().ok()?;
        if !peer.request_rate.take(now) || !state.requests.take(now) {
            return None;
        }
        Some(slot)
    }
    fn request(&self, address: IpAddr) -> Option<(OwnedSemaphorePermit, OwnedSemaphorePermit)> {
        let peer = self.peer_request(address)?;
        Some((peer, self.requests.clone().try_acquire_owned().ok()?))
    }
}
pub(crate) async fn admit(
    Extension(gate): Extension<RequestGate>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(slots) = gate.owner.request(gate.peer) else {
        gate.owner.refused(1);
        return limited(Duration::from_secs(1));
    };
    let lease = Arc::new(vec![slots.0, slots.1]);
    request.extensions_mut().insert(lease.clone());
    let response = next.run(request).await;
    drop(lease);
    response
}
pub(crate) fn limited(delay: Duration) -> Response {
    let mut response = crate::http_host::secure_response(
        (
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"code":"request_limited"})),
        )
            .into_response(),
        uuid::Uuid::new_v4(),
    );
    response.headers_mut().insert(
        axum::http::header::RETRY_AFTER,
        axum::http::HeaderValue::from_str(&delay.as_secs_f64().ceil().max(1.0).to_string())
            .expect("seconds"),
    );
    response
}

pub(crate) async fn admit_agent(
    Extension(gate): Extension<RequestGate>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(peer_slot) = gate.owner.peer_request(gate.peer) else {
        gate.owner.refused(1);
        use axum::http::{HeaderValue, StatusCode, header};
        let body = if request.uri().path().starts_with("/api/v1/agent/enroll/") {
            serde_json::to_value(rss_mdm_agent_wire::enroll::ErrorBody {
                code: rss_mdm_agent_wire::enroll::ErrorCode::ServiceUnavailable,
                issuance_id: None,
            })
            .expect("closed error")
        } else {
            serde_json::to_value(rss_mdm_agent_wire::runtime::ErrorBody {
                code: rss_mdm_agent_wire::runtime::ErrorCode::ServiceUnavailable,
            })
            .expect("closed error")
        };
        let mut response = crate::http_host::secure_response(
            (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response(),
            uuid::Uuid::new_v4(),
        );
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return response;
    };
    let lease = Arc::new(vec![peer_slot]);
    request.extensions_mut().insert(lease.clone());
    let response = next.run(request).await;
    drop(lease);
    response
}

#[cfg(test)]
#[path = "../../tests/native/admission_unit.rs"]
mod tests;

/// App binds the single RSS lifecycle gate after launch has registered all dependencies.
pub(crate) async fn lifecycle(
    axum::extract::State(gate): axum::extract::State<
        Arc<std::sync::OnceLock<rss_runtime::AdmissionGate>>,
    >,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(gate) = gate.get() else {
        return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    request.extensions_mut().insert(gate.clone());
    next.run(request).await
}
