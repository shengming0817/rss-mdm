//! Observe actual provider cells, before business decoding; never record values.
#[derive(Clone)]
pub(crate) struct QueryReadCounts {
    prefix: &'static str,
    pub calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    pub rows: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    pub bytes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}
impl QueryReadCounts {
    pub fn reset(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        self.calls.store(0, Relaxed);
        self.rows.store(0, Relaxed);
        self.bytes.store(0, Relaxed);
    }
    pub fn new(prefix: &'static str) -> Self {
        Self {
            prefix,
            calls: Default::default(),
            rows: Default::default(),
            bytes: Default::default(),
        }
    }
}
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for QueryReadCounts {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if event.metadata().target() != "rss_mdm.query_read" {
            return;
        }
        #[derive(Default)]
        struct Measurement {
            stage: String,
            rows: u64,
            bytes: u64,
        }
        impl tracing::field::Visit for Measurement {
            fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
            fn record_str(&mut self, f: &tracing::field::Field, v: &str) {
                if f.name() == "stage" {
                    self.stage = v.into();
                }
            }
            fn record_u64(&mut self, f: &tracing::field::Field, v: u64) {
                match f.name() {
                    "rows" => self.rows = v,
                    "payload_bytes" => self.bytes = v,
                    _ => {}
                }
            }
        }
        let mut m = Measurement::default();
        event.record(&mut m);
        if m.stage.starts_with(self.prefix) {
            use std::sync::atomic::Ordering::Relaxed;
            self.calls.fetch_add(1, Relaxed);
            self.rows.fetch_add(m.rows as usize, Relaxed);
            self.bytes.fetch_add(m.bytes as usize, Relaxed);
        }
    }
}
