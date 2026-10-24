use crate::{Endpoint, Operation, Resource};
type Ownership = (&'static Resource, &'static [Operation]);
type MethodBinding = (
    &'static str,
    Option<Ownership>,
    Option<&'static rss_mdm_query::directory::Schema>,
);
#[derive(Clone)]
pub struct MethodRouter<S = ()> {
    pub(crate) inner: axum::routing::MethodRouter<S>,
    pub(crate) bindings: Vec<MethodBinding>,
}
impl<S: Clone + Send + Sync + 'static> MethodRouter<S> {
    /// Bind the last added method to its semantic owner. Missing bindings fail at registration.
    pub fn owned(mut self, resource: &'static Resource, operations: &'static [Operation]) -> Self {
        assert!(!operations.is_empty(), "empty route operation ownership");
        let last = self.bindings.last_mut().expect("method exists");
        assert!(
            last.1.replace((resource, operations)).is_none(),
            "method already has an owner"
        );
        self
    }
    /// Bind a List method to the same field authority consumed by its handler and repository.
    pub fn queried(mut self, schema: &'static rss_mdm_query::directory::Schema) -> Self {
        let last = self.bindings.last_mut().expect("method exists");
        let (resource, operations) = last.1.expect("query follows ownership");
        assert!(
            operations.contains(&Operation::List) && resource.id == schema.id,
            "query owner mismatch"
        );
        assert!(last.2.replace(schema).is_none(), "duplicate query owner");
        self
    }
    pub fn patch<H, T>(mut self, handler: H) -> Self
    where
        H: axum::handler::Handler<T, S>,
        T: 'static,
    {
        self.inner = self.inner.patch(handler);
        self.bindings.push(("PATCH", None, None));
        self
    }
    pub fn with_state<S2>(self, state: S) -> MethodRouter<S2> {
        MethodRouter {
            inner: self.inner.with_state(state),
            bindings: self.bindings,
        }
    }
    pub(crate) fn endpoints(&self, path: &str) -> Vec<Endpoint> {
        self.bindings
            .iter()
            .map(|(method, binding, query)| {
                let (resource, operations) =
                    binding.expect("every method requires a resource and semantic operation");
                Endpoint {
                    path: path.into(),
                    method,
                    resource,
                    operations,
                    query: *query,
                }
            })
            .collect()
    }
    pub fn get<H, T>(mut self, handler: H) -> Self
    where
        H: axum::handler::Handler<T, S>,
        T: 'static,
    {
        self.inner = self.inner.get(handler);
        self.bindings.push(("GET", None, None));
        self
    }
    pub fn post<H, T>(mut self, handler: H) -> Self
    where
        H: axum::handler::Handler<T, S>,
        T: 'static,
    {
        self.inner = self.inner.post(handler);
        self.bindings.push(("POST", None, None));
        self
    }
    pub fn put<H, T>(mut self, handler: H) -> Self
    where
        H: axum::handler::Handler<T, S>,
        T: 'static,
    {
        self.inner = self.inner.put(handler);
        self.bindings.push(("PUT", None, None));
        self
    }
    pub fn delete<H, T>(mut self, handler: H) -> Self
    where
        H: axum::handler::Handler<T, S>,
        T: 'static,
    {
        self.inner = self.inner.delete(handler);
        self.bindings.push(("DELETE", None, None));
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
            bindings: self.bindings,
        }
    }
    pub fn route_layer<L>(self, layer: L) -> Self
    where
        L: tower::Layer<axum::routing::Route> + Clone + Send + Sync + 'static,
        L::Service: tower::Service<axum::extract::Request, Error = std::convert::Infallible>
            + Clone
            + Send
            + Sync
            + 'static,
        <L::Service as tower::Service<axum::extract::Request>>::Response:
            axum::response::IntoResponse + 'static,
        <L::Service as tower::Service<axum::extract::Request>>::Error:
            Into<std::convert::Infallible> + 'static,
        <L::Service as tower::Service<axum::extract::Request>>::Future: Send + 'static,
    {
        Self {
            inner: self.inner.route_layer(layer),
            bindings: self.bindings,
        }
    }
}
pub fn get<H, T, S>(handler: H) -> MethodRouter<S>
where
    H: axum::handler::Handler<T, S>,
    T: 'static,
    S: Clone + Send + Sync + 'static,
{
    MethodRouter {
        inner: axum::routing::get(handler),
        bindings: vec![("GET", None, None)],
    }
}
pub fn post<H, T, S>(handler: H) -> MethodRouter<S>
where
    H: axum::handler::Handler<T, S>,
    T: 'static,
    S: Clone + Send + Sync + 'static,
{
    MethodRouter {
        inner: axum::routing::post(handler),
        bindings: vec![("POST", None, None)],
    }
}
pub fn put<H, T, S>(handler: H) -> MethodRouter<S>
where
    H: axum::handler::Handler<T, S>,
    T: 'static,
    S: Clone + Send + Sync + 'static,
{
    MethodRouter {
        inner: axum::routing::put(handler),
        bindings: vec![("PUT", None, None)],
    }
}
pub fn delete<H, T, S>(handler: H) -> MethodRouter<S>
where
    H: axum::handler::Handler<T, S>,
    T: 'static,
    S: Clone + Send + Sync + 'static,
{
    MethodRouter {
        inner: axum::routing::delete(handler),
        bindings: vec![("DELETE", None, None)],
    }
}
