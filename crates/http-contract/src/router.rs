use crate::{
    Endpoint,
    module::{Declaration, Key, Presence},
};
#[must_use]
pub struct Router<S, M> {
    pub(crate) inner: Option<axum::Router<S>>,
    pub(crate) endpoints: Vec<Endpoint>,
    pub(crate) expected: Vec<Key>,
    pub(crate) observed: Vec<Key>,
    pub(crate) modules: Vec<Presence>,
    pub(crate) resources: Vec<&'static crate::Resource>,
    pub(crate) activation: Option<bool>,
    pub(crate) marker: std::marker::PhantomData<fn() -> M>,
}
// Cloning a completed module preserves its entire frozen declaration and receipts.
impl<S: Clone, M> Clone for Router<S, M> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            endpoints: self.endpoints.clone(),
            expected: self.expected.clone(),
            observed: self.observed.clone(),
            modules: self.modules.clone(),
            resources: self.resources.clone(),
            activation: self.activation,
            marker: std::marker::PhantomData,
        }
    }
}
impl<S: Clone + Send + Sync + 'static, M: Declaration> Router<S, M> {
    pub fn with_state<S2>(self, state: S) -> Router<S2, M> {
        Router {
            inner: self.inner.map(|inner| inner.with_state(state)),
            endpoints: self.endpoints,
            expected: self.expected,
            observed: self.observed,
            modules: self.modules,
            resources: self.resources,
            activation: self.activation,
            marker: std::marker::PhantomData,
        }
    }
    /// Bind real state only for runtime composition. Offline composition executes the same
    /// registration and mounting calls without evaluating any service construction closure.
    /// A description-only router cannot be converted to a serving Axum router.
    pub fn bind_with<C, S2>(
        self,
        context: Option<&C>,
        make_state: impl FnOnce(&C) -> S,
    ) -> Router<S2, M> {
        Router {
            inner: match (self.inner, context) {
                (Some(inner), Some(context)) => Some(inner.with_state(make_state(context))),
                _ => None,
            },
            endpoints: self.endpoints,
            expected: self.expected,
            observed: self.observed,
            modules: self.modules,
            resources: self.resources,
            activation: self.activation,
            marker: std::marker::PhantomData,
        }
    }
    pub fn into_endpoints(self) -> Vec<Endpoint> {
        self.endpoints
    }
    /// The same explicit product condition controls mounting and its offline description.
    pub fn when(mut self, condition: &'static str, enabled: bool) -> Self {
        assert!(
            self.activation.is_none(),
            "module already has a configuration decision"
        );
        self.activation = Some(enabled);
        if !enabled {
            self.inner = Some(axum::Router::new());
            self.endpoints.clear();
            self.expected.clear();
            self.observed.clear();
            self.resources.clear();
            return self;
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
    /// Only a complete, correctly placed production declaration may erase its descriptors.
    pub fn into_checked_axum(self, listener: crate::module::Listener) -> axum::Router<S> {
        self.check(Some(listener));
        self.inner.expect("contract descriptions cannot serve HTTP")
    }
    pub fn into_axum(self) -> axum::Router<S> {
        self.check(None);
        self.inner.expect("contract descriptions cannot serve HTTP")
    }
    pub fn validate(&self, listener: crate::module::Listener) -> Vec<String> {
        let mut failures = Vec::new();
        let mut expected = self.expected.clone();
        expected.sort();
        let mut observed = self.observed.clone();
        observed.sort();
        if expected != observed {
            failures.push("incomplete endpoint assembly".into());
        }
        for module in &self.modules {
            if !module.allowed.contains(&listener) {
                failures.push(format!(
                    "module {} is not allowed on {listener:?}",
                    module.id
                ));
            }
        }
        let resources = self
            .resources
            .iter()
            .map(|r| (r.id, *r))
            .collect::<std::collections::BTreeMap<_, _>>();
        failures.extend(
            crate::validate(
                &self.endpoints,
                &resources.values().copied().collect::<Vec<_>>(),
            )
            .into_iter()
            .map(|v| format!("{v:?}")),
        );
        failures
    }
    fn check(&self, listener: Option<crate::module::Listener>) {
        assert!(
            self.activation != Some(false),
            "disabled module cannot serve as a listener"
        );
        let mut expected = self.expected.clone();
        expected.sort();
        let mut observed = self.observed.clone();
        observed.sort();
        assert_eq!(expected, observed, "incomplete declared module assembly");
        if let Some(listener) = listener {
            let errors = self.validate(listener);
            assert!(
                errors.is_empty(),
                "invalid listener route assembly: {errors:?}"
            );
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
            expected: self.expected,
            observed: self.observed,
            modules: self.modules,
            resources: self.resources,
            activation: self.activation,
            marker: std::marker::PhantomData,
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
            expected: self.expected,
            observed: self.observed,
            modules: self.modules,
            resources: self.resources,
            activation: self.activation,
            marker: std::marker::PhantomData,
        }
    }
}
impl<M: Declaration> tower::Service<axum::extract::Request> for Router<(), M> {
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
