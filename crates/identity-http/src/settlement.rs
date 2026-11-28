//! A transaction owner receives the request cutoff and reports its own bounded settlement.
use axum::{extract::Request, http::Extensions, middleware::Next, response::Response};
use rss_request_context::{CancellationFuture, CancellationObserver, Deadline};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
struct OwnerLifetime(CancellationToken);

impl CancellationObserver for OwnerLifetime {
    fn is_cancelled(&self) -> bool {
        self.0.is_cancelled()
    }
    fn cancelled(&self) -> CancellationFuture<'_> {
        Box::pin(self.0.cancelled())
    }
}

pub fn lifetime(ext: &Extensions) -> Option<(Deadline, Arc<dyn CancellationObserver>)> {
    if let Some(owner) = ext.get::<OwnerLifetime>() {
        return Some((*ext.get::<Deadline>()?, Arc::new(owner.clone())));
    }
    let control = ext.get::<rss_axum::RequestControl>()?;
    Some((control.deadline(), Arc::new(control.clone())))
}

pub fn owner_settles(ext: &Extensions) -> bool {
    ext.get::<OwnerLifetime>().is_some()
}

pub async fn dispatch(mut request: Request, next: Next, deadline: Deadline) -> Response {
    let inherited = request.extensions().get::<Deadline>().copied();
    let deadline = inherited.map_or(deadline, |d| deadline.shortened_to(d.instant()));
    let token = CancellationToken::new();
    let _guard = token.clone().drop_guard();
    request.extensions_mut().insert(OwnerLifetime(token));
    request.extensions_mut().insert(deadline);
    next.run(request).await
}
