//! Product ingress budgets use the accepted TCP peer, before costly TLS or audit work.
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
}
struct Peer {
    connections: Arc<Semaphore>,
    requests: Arc<Semaphore>,
    connection_rate: Bucket,
    request_rate: Bucket,
    seen: Instant,
}
impl Peer {
    fn new(now: Instant) -> Self {
        Self {
            connections: Arc::new(Semaphore::new(4)),
            requests: Arc::new(Semaphore::new(2)),
            connection_rate: Bucket::new(now, 16.0, 1.0),
            request_rate: Bucket::new(now, 64.0, 4.0),
            seen: now,
        }
    }
}
struct State {
    peers: BTreeMap<IpAddr, Peer>,
    connections: Bucket,
    requests: Bucket,
    pruned: Instant,
}
pub(super) struct Admission {
    clock: Arc<dyn rss_observation::Clock>,
    state: Mutex<State>,
    requests: Arc<Semaphore>,
    name: &'static str,
    refused: [AtomicU64; 2],
}
pub(super) struct ConnectionPermit {
    _slot: OwnedSemaphorePermit,
    gate: RequestGate,
}
impl ConnectionPermit {
    pub(super) fn gate(&self) -> RequestGate {
        self.gate.clone()
    }
}
#[derive(Clone)]
pub(super) struct RequestGate {
    owner: Arc<Admission>,
    peer: IpAddr,
}
impl Admission {
    pub(super) fn new(
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
                connections: Bucket::new(now, 128.0, 32.0),
                requests: Bucket::new(now, 256.0, 64.0),
                pruned: now,
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
    pub(super) fn connection(self: &Arc<Self>, peer: IpAddr) -> Option<ConnectionPermit> {
        let result = self.connection_slot(peer).map(|slot| ConnectionPermit {
            _slot: slot,
            gate: RequestGate {
                owner: self.clone(),
                peer,
            },
        });
        if result.is_none() {
            self.refused(0);
        }
        result
    }
    fn connection_slot(&self, address: IpAddr) -> Option<OwnedSemaphorePermit> {
        let now = self.clock.now();
        let mut state = self.state.lock().ok()?;
        if now.saturating_duration_since(state.pruned) >= Duration::from_secs(30) {
            state.peers.retain(|_, p| {
                p.connections.available_permits() < 4
                    || p.requests.available_permits() < 2
                    || now.saturating_duration_since(p.seen) < Duration::from_secs(300)
            });
            state.pruned = now;
        }
        if !state.peers.contains_key(&address) && state.peers.len() >= 4096 {
            return None;
        }
        let peer = state.peers.entry(address).or_insert_with(|| Peer::new(now));
        peer.seen = now;
        let slot = peer.connections.clone().try_acquire_owned().ok()?;
        if !peer.connection_rate.take(now) || !state.connections.take(now) {
            return None;
        }
        Some(slot)
    }
    fn request(&self, address: IpAddr) -> Option<(OwnedSemaphorePermit, OwnedSemaphorePermit)> {
        let now = self.clock.now();
        let mut state = self.state.lock().ok()?;
        let peer = state.peers.get_mut(&address)?;
        peer.seen = now;
        let slot = peer.requests.clone().try_acquire_owned().ok()?;
        if !peer.request_rate.take(now) || !state.requests.take(now) {
            return None;
        }
        Some((slot, self.requests.clone().try_acquire_owned().ok()?))
    }
}
pub(super) async fn admit(
    Extension(gate): Extension<RequestGate>,
    request: Request,
    next: Next,
) -> Response {
    let Some(_slots) = gate.owner.request(gate.peer) else {
        gate.owner.refused(1);
        return crate::api::secure_response(
            (
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({"code":"request_limited"})),
            )
                .into_response(),
            uuid::Uuid::new_v4(),
        );
    };
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Clock(Mutex<Instant>);
    impl rss_observation::Clock for Clock {
        fn now(&self) -> Instant {
            *self.0.lock().unwrap()
        }
    }
    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "test composition root supplies a controllable monotonic clock"
    )]
    fn peer_bursts_are_bounded_and_other_peers_recover() {
        let clock = Arc::new(Clock(Mutex::new(Instant::now())));
        let admission = Admission::new(
            clock.clone(),
            Arc::new(Semaphore::new(4)),
            "mdm-enrollment-tls",
        );
        let noisy = "127.0.0.2".parse().unwrap();
        let healthy = "127.0.0.1".parse().unwrap();
        let busy = (0..4)
            .map(|_| admission.connection(noisy).unwrap())
            .collect::<Vec<_>>();
        assert!(admission.connection(noisy).is_none());
        let healthy_connection = admission.connection(healthy).unwrap();
        let one = admission.request(noisy).unwrap();
        let two = admission.request(noisy).unwrap();
        assert!(admission.request(noisy).is_none());
        assert!(admission.request(healthy).is_some());
        drop((one, two, busy));
        let successes = (0..1000)
            .filter(|_| admission.request(healthy).is_some())
            .count();
        assert!(successes < 64);
        let connections = (0..1000)
            .filter(|_| admission.connection(noisy).is_some())
            .count();
        assert!(connections <= 12);
        *clock.0.lock().unwrap() += Duration::from_secs(60);
        assert!(admission.connection(noisy).is_some());
        assert!(admission.request(healthy).is_some());
        drop(healthy_connection);
    }
}
