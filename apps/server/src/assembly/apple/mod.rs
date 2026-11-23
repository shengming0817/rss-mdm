//! Apple material consumption, TLS listener configuration and channel construction.
pub(crate) mod config;
use crate::Error;
use std::sync::Arc;

pub(crate) struct Apple {
    pub(crate) channel: Arc<rss_mdm_apple_channel::runtime_materials::runtime::Runtime>,
    pub(crate) config: config::Config,
}
impl Apple {
    pub(crate) fn load(config: config::Config) -> Result<Self, Error> {
        let webhooks = if config.webhooks.is_empty() {
            None
        } else {
            Some(Arc::new(crate::ca_webhooks::load(&config.webhooks)?))
        };
        let channel = Arc::new(
            rss_mdm_apple_channel::runtime_materials::runtime::Runtime::new(
                config.management.origin.clone(),
                webhooks,
            ),
        );
        Ok(Self { config, channel })
    }
}
pub(crate) fn router(
    apple: Option<&Apple>,
    app: Arc<rss_mdm_apple_channel::HttpState>,
    clock: Arc<dyn rss_observation::Clock>,
    request_budget: rss_axum::RequestBudget,
) -> Option<crate::native::ChannelRouter> {
    use crate::native::{ChannelRouter, admission};
    use axum::middleware;
    use rss_mdm_apple_channel::boundary::Envelope;
    let apple = apple?;
    let router = rss_mdm_apple_channel::router(
        app.clone(),
        Envelope {
            request_budget,
            host: apple
                .config
                .management
                .origin
                .trim_start_matches("https://")
                .into(),
            clock: clock.clone(),
            audit_store: app.audit_store.clone(),
            buffered_bytes: app.buffered_bytes.clone(),
        },
    )
    .layer(middleware::from_fn(admission::admit));
    Some(ChannelRouter {
        admission: admission::Admission::new(clock, "apple-management-tls"),
        origins: vec![apple.config.management.origin.clone()],
        router: router.into_checked_axum(rss_mdm_http_contract::module::Listener::Apple),
    })
}
