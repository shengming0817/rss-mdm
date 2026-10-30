//! Windows authentication releases the NAT budget, while device work stays bounded.
use super::*;
use rss_mdm_execution_service::channels::ManagementIngress;

const RETRY: Duration = Duration::from_secs(1);
struct Phase {
    ip: Option<OwnedSemaphorePermit>,
    device: Option<OwnedSemaphorePermit>,
    result: Option<((uuid::Uuid, String), Result<(), Duration>)>,
}
struct Lease {
    owner: Arc<Admission>,
    peer: IpAddr,
    phase: Mutex<Phase>,
    _request: OwnedSemaphorePermit,
}
impl Lease {
    fn begin(gate: &RequestGate) -> Result<Self, Duration> {
        let request = gate
            .owner
            .requests
            .clone()
            .try_acquire_owned()
            .map_err(|_| RETRY)?;
        let now = gate.owner.clock.now();
        let mut state = gate.owner.state.lock().map_err(|_| RETRY)?;
        let global_wait = state.requests.wait(now);
        let peer = state.peers.get_mut(&gate.peer).ok_or(RETRY)?;
        let ip_wait = peer.request_rate.wait(now);
        let delay = global_wait.max(ip_wait);
        if !delay.is_zero() {
            return Err(delay);
        }
        let ip = peer
            .requests
            .clone()
            .try_acquire_owned()
            .map_err(|_| RETRY)?;
        peer.seen = now;
        peer.request_rate.tokens -= 1.0;
        state.requests.tokens -= 1.0;
        Ok(Self {
            owner: gate.owner.clone(),
            peer: gate.peer,
            phase: Mutex::new(Phase {
                ip: Some(ip),
                device: None,
                result: None,
            }),
            _request: request,
        })
    }
    fn transition(&self, key: (uuid::Uuid, String)) -> Result<(), Duration> {
        let mut phase = self.phase.lock().map_err(|_| RETRY)?;
        if let Some((prior, result)) = &phase.result {
            return if prior == &key { *result } else { Err(RETRY) };
        }
        let now = self.owner.clock.now();
        let mut state = self.owner.state.lock().map_err(|_| RETRY)?;
        // In-flight IP entries cannot be evicted. Refund before checking device
        // budgets: a throttled legitimate device must not penalize its neighbours.
        if let Some(peer) = state.peers.get_mut(&self.peer) {
            peer.request_rate.refund(now);
        }
        drop(phase.ip.take());
        state.devices.retain(|_, device| {
            now.saturating_duration_since(device.seen) < Duration::from_secs(300)
                || device.requests.available_permits() < 2
        });
        let admitted = (|| {
            if !state.devices.contains_key(&key) && state.devices.len() >= 4096 {
                return Err(RETRY);
            }
            let device = state
                .devices
                .entry(key.clone())
                .or_insert_with(|| Peer::new(now));
            device.seen = now;
            let delay = device.request_rate.wait(now);
            if !delay.is_zero() {
                return Err(delay);
            }
            let permit = device
                .requests
                .clone()
                .try_acquire_owned()
                .map_err(|_| RETRY)?;
            device.request_rate.tokens -= 1.0;
            phase.device = Some(permit);
            Ok(())
        })();
        phase.result = Some((key, admitted));
        if admitted.is_err() {
            self.owner.refused(1);
        }
        admitted
    }
}
impl ManagementIngress for Lease {
    fn authenticated(
        &self,
        p: &rss_mdm_registration_service::DevicePrincipal,
    ) -> Result<(), Duration> {
        let tenant = uuid::Uuid::parse_str(&p.tenant().to_string()).map_err(|_| RETRY)?;
        self.transition((tenant, p.device().to_owned()))
    }
}
pub(crate) async fn admit_windows(
    Extension(gate): Extension<RequestGate>,
    mut request: Request,
    next: Next,
) -> Response {
    if !matches!(
        request.uri().path(),
        "/ManagementServer/MDM.svc" | "/ManagementServer/Declared.svc"
    ) {
        return super::admit(Extension(gate), request, next).await;
    }
    let lease = match Lease::begin(&gate) {
        Ok(lease) => lease,
        Err(delay) => {
            gate.owner.refused(1);
            return limited(delay);
        }
    };
    let lease: Arc<dyn ManagementIngress> = Arc::new(lease);
    request.extensions_mut().insert(lease);
    next.run(request).await
}

#[cfg(all(test, feature = "integration"))]
#[derive(Debug)]
pub(crate) struct BudgetProbe {
    pub ip_tokens: f64,
    pub ip_in_flight: usize,
    pub device_in_flight: usize,
    pub request_available: usize,
}
#[cfg(all(test, feature = "integration"))]
impl Admission {
    /// Read counters without retaining a request lease or changing refill time.
    pub(crate) fn windows_budget(&self, tenant: uuid::Uuid, device: &str) -> BudgetProbe {
        let state = self.state.lock().unwrap();
        BudgetProbe {
            ip_tokens: state.peers.values().map(|p| p.request_rate.tokens).sum(),
            ip_in_flight: state
                .peers
                .values()
                .map(|p| 2 - p.requests.available_permits())
                .sum(),
            device_in_flight: state
                .devices
                .get(&(tenant, device.into()))
                .map_or(0, |p| 2 - p.requests.available_permits()),
            request_available: self.requests.available_permits(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixed(Instant);
    impl rss_observation::Clock for Fixed {
        fn now(&self) -> Instant {
            self.0
        }
    }
    fn owner() -> Arc<Admission> {
        Admission::new(
            Arc::new(Fixed(rss_request_context::Clock::now(
                &crate::lifecycle::RuntimeTimer,
            ))),
            Arc::new(Semaphore::new(8)),
            "windows",
        )
    }
    #[test]
    fn device_rejection_refunds_nat_once_and_keeps_global_charge() {
        let owner = owner();
        let gate = owner.gate("192.0.2.1".parse().unwrap()).unwrap();
        let key = (uuid::Uuid::new_v4(), "device-a".to_owned());
        let first = Lease::begin(&gate).unwrap();
        first.transition(key.clone()).unwrap();
        let second = Lease::begin(&gate).unwrap();
        second.transition(key.clone()).unwrap();
        let third = Lease::begin(&gate).unwrap();
        assert_eq!(third.transition(key.clone()), Err(RETRY));
        {
            let state = owner.state.lock().unwrap();
            assert_eq!(state.peers[&gate.peer].requests.available_permits(), 2);
            assert_eq!(state.peers[&gate.peer].request_rate.tokens, 64.0);
            assert_eq!(state.requests.tokens, 253.0);
        }
        let pending = Lease::begin(&gate).unwrap();
        assert_eq!(third.transition(key), Err(RETRY));
        assert_eq!(
            owner.state.lock().unwrap().peers[&gate.peer]
                .request_rate
                .tokens,
            63.0
        );
        pending
            .transition((uuid::Uuid::new_v4(), "device-b".into()))
            .unwrap();
    }
    #[test]
    fn successful_conversion_is_single_use_and_cannot_change_device() {
        let owner = owner();
        let gate = owner.gate("192.0.2.1".parse().unwrap()).unwrap();
        let key = (uuid::Uuid::new_v4(), "first".to_owned());
        let lease = Lease::begin(&gate).unwrap();
        lease.transition(key.clone()).unwrap();
        let pending = Lease::begin(&gate).unwrap();
        lease.transition(key.clone()).unwrap();
        assert_eq!(lease.transition((key.0, "second".into())), Err(RETRY));
        let state = owner.state.lock().unwrap();
        assert_eq!(state.peers[&gate.peer].request_rate.tokens, 63.0);
        assert_eq!(state.devices[&key].request_rate.tokens, 63.0);
        assert_eq!(state.devices[&key].requests.available_permits(), 1);
        assert_eq!(state.devices.len(), 1);
        drop(state);
        drop(pending);
    }
    #[test]
    fn preauth_failure_spends_ip_and_actual_work_retains_concurrency() {
        let owner = owner();
        let gate = owner.gate("192.0.2.1".parse().unwrap()).unwrap();
        drop(Lease::begin(&gate).unwrap());
        assert_eq!(
            owner.state.lock().unwrap().peers[&gate.peer]
                .request_rate
                .tokens,
            63.0
        );
        let key = (uuid::Uuid::new_v4(), "device".to_owned());
        let outer = Arc::new(Lease::begin(&gate).unwrap());
        outer.transition(key.clone()).unwrap();
        let work = outer.clone();
        drop(outer);
        assert_eq!(owner.requests.available_permits(), 7);
        assert_eq!(
            owner.state.lock().unwrap().devices[&key]
                .requests
                .available_permits(),
            1
        );
        drop(work);
        assert_eq!(owner.requests.available_permits(), 8);
        assert_eq!(
            owner.state.lock().unwrap().devices[&key]
                .requests
                .available_permits(),
            2
        );
    }
}
