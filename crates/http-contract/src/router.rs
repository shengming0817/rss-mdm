use crate::{Endpoint, routing::MethodRouter};
#[derive(Clone)]
pub struct Router<S = ()> {
    inner: Option<axum::Router<S>>,
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
            inner: Some(axum::Router::new()),
            endpoints: Vec::new(),
        }
    }
    pub fn route(mut self, path: &str, method: MethodRouter<S>) -> Self {
        self.endpoints.extend(method.endpoints(path));
        self.inner = self.inner.map(|inner| inner.route(path, method.inner));
        self
    }
    /// Register a static route whose single UUID segment comes from deployment configuration.
    /// Offline mode retains the template and cannot construct a serving router.
    pub fn configured_route(
        mut self,
        template: &str,
        binding: crate::ConfiguredSegment,
        resolved: Option<&str>,
        method: MethodRouter<S>,
    ) -> Self {
        assert!(
            !binding.name.is_empty() && !binding.source.is_empty(),
            "configuration binding is required"
        );
        let capture = binding.capture();
        assert_eq!(
            template.split('/').filter(|s| *s == capture).count(),
            1,
            "configuration slot must occupy one whole segment"
        );
        let mut endpoints = method.endpoints(template);
        for endpoint in &mut endpoints {
            endpoint.configured_path = Some(binding.clone());
        }
        self.endpoints.extend(endpoints);
        self.inner = match (self.inner, resolved) {
            (Some(inner), Some(value)) => {
                let id =
                    uuid::Uuid::parse_str(value).expect("configured route segment must be a UUID");
                assert!(
                    !id.is_nil() && !value.contains('/'),
                    "invalid configured route UUID"
                );
                Some(inner.route(&template.replace(&capture, value), method.inner))
            }
            _ => None,
        };
        self
    }
    pub fn merge(mut self, other: Self) -> Self {
        self.inner = self
            .inner
            .zip(other.inner)
            .map(|(inner, other)| inner.merge(other));
        self.endpoints.extend(other.endpoints);
        self
    }
    pub fn nest(mut self, path: &str, mut other: Self) -> Self {
        for endpoint in &mut other.endpoints {
            endpoint.path = format!("{}{}", path.trim_end_matches('/'), endpoint.path);
        }
        self.inner = self
            .inner
            .zip(other.inner)
            .map(|(inner, other)| inner.nest(path, other));
        self.endpoints.extend(other.endpoints);
        self
    }
    pub fn with_state<S2>(self, state: S) -> Router<S2> {
        Router {
            inner: self.inner.map(|inner| inner.with_state(state)),
            endpoints: self.endpoints,
        }
    }
    /// Bind real state only for runtime composition. Offline composition executes the same
    /// registration and mounting calls without evaluating any service construction closure.
    /// A description-only router cannot be converted to a serving Axum router.
    pub fn bind_with<C, S2>(
        self,
        context: Option<&C>,
        make_state: impl FnOnce(&C) -> S,
    ) -> Router<S2> {
        Router {
            inner: match (self.inner, context) {
                (Some(inner), Some(context)) => Some(inner.with_state(make_state(context))),
                _ => None,
            },
            endpoints: self.endpoints,
        }
    }
    pub fn into_endpoints(self) -> Vec<Endpoint> {
        self.endpoints
    }
    /// The same explicit product condition controls mounting and its offline description.
    pub fn when(mut self, condition: &'static str, enabled: bool) -> Self {
        if !enabled {
            return Self::new();
        }
        assert!(!condition.is_empty(), "empty product mount condition");
        for endpoint in &mut self.endpoints {
            endpoint.conditions.push(condition);
            endpoint.conditions.sort_unstable();
            endpoint.conditions.dedup();
        }
        self
    }
    /// Attach the mounted authentication owner; final paths are resolved during projection.
    pub fn authentication(
        mut self,
        describe: fn(&str, &str) -> crate::authentication::Description,
    ) -> Self {
        for endpoint in &mut self.endpoints {
            assert!(
                endpoint.authentication.is_none(),
                "duplicate authentication owner"
            );
            endpoint.authentication = Some(describe);
        }
        self
    }
    pub fn endpoints(&self) -> &[Endpoint] {
        &self.endpoints
    }
    /// Exit at the product's final transport boundary after validating its mounted inventory.
    pub fn into_axum(self) -> axum::Router<S> {
        self.inner.expect("contract descriptions cannot serve HTTP")
    }
    /// Validate an independently declared listener inventory before erasing its descriptors.
    pub fn into_checked_axum(self, expected: &[&crate::Resource]) -> axum::Router<S> {
        let violations = crate::validate(&self.endpoints, expected);
        assert!(
            violations.is_empty(),
            "invalid listener route assembly: {violations:?}"
        );
        self.inner.expect("contract descriptions cannot serve HTTP")
    }
    /// External Identity owns its own contract and router. No product route is admitted here.
    pub fn from_identity_router(router: axum::Router<S>) -> Self {
        Self {
            inner: Some(router),
            endpoints: Vec::new(),
        }
    }
    pub fn fallback<H, T>(mut self, handler: H) -> Self
    where
        H: axum::handler::Handler<T, S>,
        T: 'static,
    {
        self.inner = self.inner.map(|inner| inner.fallback(handler));
        self
    }
    /// Apply fixed response headers through Axum and describe those same values on every response.
    pub fn fixed_response_headers(
        mut self,
        headers: &'static [(&'static str, &'static str)],
    ) -> Self {
        let parsed = headers
            .iter()
            .map(|(name, value)| {
                (
                    axum::http::HeaderName::from_static(name),
                    axum::http::HeaderValue::from_static(value),
                )
            })
            .collect::<Vec<_>>();
        for endpoint in &mut self.endpoints {
            if let crate::EndpointContract::Product(signature) = &mut endpoint.contract {
                for response in signature
                    .responses
                    .iter_mut()
                    .chain(signature.request.rejections.iter_mut())
                {
                    for (name, value) in headers {
                        let mut schema = crate::signature::Schema::response::<String>();
                        schema.value["const"] = (*value).into();
                        response.headers.insert((*name).into(), schema);
                    }
                }
            }
        }
        self.inner = self.inner.map(|inner| {
            inner.layer(axum::middleware::map_response(
                move |mut response: axum::response::Response| {
                    let headers = parsed.clone();
                    async move {
                        for (name, value) in headers {
                            response.headers_mut().insert(name, value);
                        }
                        response
                    }
                },
            ))
        });
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
            inner: self.inner.map(|inner| inner.layer(layer)),
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
            inner: self.inner.map(|inner| inner.route_layer(layer)),
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
        tower::Service::<axum::extract::Request>::poll_ready(
            self.inner
                .as_mut()
                .expect("contract descriptions cannot serve HTTP"),
            cx,
        )
    }
    fn call(&mut self, request: axum::extract::Request) -> Self::Future {
        tower::Service::call(
            self.inner
                .as_mut()
                .expect("contract descriptions cannot serve HTTP"),
            request,
        )
    }
}
