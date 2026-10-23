use crate::{Endpoint, routing::MethodRouter};
#[derive(Clone)]
pub struct Router<S = ()> {
    inner: axum::Router<S>,
    endpoints: Vec<Endpoint>,
}
impl<S: Clone + Send + Sync + 'static> Default for Router<S> {
    fn default() -> Self {
        Self::new()
    }
}
impl<S: Clone + Send + Sync + 'static> Router<S> {
    pub fn new() -> Self {
        Self {
            inner: axum::Router::new(),
            endpoints: Vec::new(),
        }
    }
    pub fn route(mut self, path: &str, method: MethodRouter<S>) -> Self {
        self.endpoints.extend(method.endpoints(path));
        self.inner = self.inner.route(path, method.inner);
        self
    }
    pub fn merge(mut self, other: Self) -> Self {
        self.inner = self.inner.merge(other.inner);
        self.endpoints.extend(other.endpoints);
        self
    }
    pub fn nest(mut self, path: &str, mut other: Self) -> Self {
        for endpoint in &mut other.endpoints {
            endpoint.path = format!("{}{}", path.trim_end_matches('/'), endpoint.path);
        }
        self.inner = self.inner.nest(path, other.inner);
        self.endpoints.extend(other.endpoints);
        self
    }
    pub fn with_state<S2>(self, state: S) -> Router<S2> {
        Router {
            inner: self.inner.with_state(state),
            endpoints: self.endpoints,
        }
    }
    pub fn endpoints(&self) -> &[Endpoint] {
        &self.endpoints
    }
    /// Exit at the product's final transport boundary after validating its mounted inventory.
    pub fn into_axum(self) -> axum::Router<S> {
        self.inner
    }
    /// External Identity owns its own contract and router. No product route is admitted here.
    pub fn identity(router: axum::Router<S>) -> Self {
        Self {
            inner: router,
            endpoints: Vec::new(),
        }
    }
    pub fn fallback<H, T>(mut self, handler: H) -> Self
    where
        H: axum::handler::Handler<T, S>,
        T: 'static,
    {
        self.inner = self.inner.fallback(handler);
        self
    }
    pub fn layer<L>(self, layer: L) -> Self
    where
        L: tower::Layer<axum::routing::Route> + Clone + Send + Sync + 'static,
        L::Service: tower::Service<axum::extract::Request> + Clone + Send + Sync + 'static,
        <L::Service as tower::Service<axum::extract::Request>>::Response:
            axum::response::IntoResponse + 'static,
        <L::Service as tower::Service<axum::extract::Request>>::Error:
            Into<std::convert::Infallible> + 'static,
        <L::Service as tower::Service<axum::extract::Request>>::Future: Send + 'static,
    {
        Self {
            inner: self.inner.layer(layer),
            endpoints: self.endpoints,
        }
    }
    pub fn route_layer<L>(self, layer: L) -> Self
    where
        L: tower::Layer<axum::routing::Route> + Clone + Send + Sync + 'static,
        L::Service: tower::Service<axum::extract::Request> + Clone + Send + Sync + 'static,
        <L::Service as tower::Service<axum::extract::Request>>::Response:
            axum::response::IntoResponse + 'static,
        <L::Service as tower::Service<axum::extract::Request>>::Error:
            Into<std::convert::Infallible> + 'static,
        <L::Service as tower::Service<axum::extract::Request>>::Future: Send + 'static,
    {
        Self {
            inner: self.inner.route_layer(layer),
            endpoints: self.endpoints,
        }
    }
}
impl tower::Service<axum::extract::Request> for Router {
    type Response = axum::response::Response;
    type Error = std::convert::Infallible;
    type Future = <axum::Router as tower::Service<axum::extract::Request>>::Future;
    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        tower::Service::<axum::extract::Request>::poll_ready(&mut self.inner, cx)
    }
    fn call(&mut self, request: axum::extract::Request) -> Self::Future {
        tower::Service::call(&mut self.inner, request)
    }
}
