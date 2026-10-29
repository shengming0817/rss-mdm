//! A handler cannot be registered without its resource and semantic operation.
//! ref: axum axum/src/routing/method_routing.rs@axum-v0.8.9
use crate::{
    Endpoint, EndpointContract, ExternalProtocol, Operation, Resource, signature::ContractHandler,
};
type MethodBinding = (
    &'static str,
    &'static Resource,
    &'static [Operation],
    EndpointContract,
    &'static str,
);
#[must_use]
pub struct MethodRouter<S = ()> {
    pub(crate) inner: axum::routing::MethodRouter<S>,
    pub(crate) binding: MethodBinding,
}
fn binding(
    method: &'static str,
    resource: &'static Resource,
    operations: &'static [Operation],
    contract: EndpointContract,
    handler: &'static str,
) -> MethodBinding {
    assert!(!operations.is_empty(), "empty route operation ownership");
    if let EndpointContract::External(protocol) = &contract {
        assert!(
            protocol.accepts(resource),
            "external protocol does not own this resource"
        );
    }
    (method, resource, operations, contract, handler)
}
impl<S: Clone + Send + Sync + 'static> MethodRouter<S> {
    pub fn with_state<S2>(self, state: S) -> MethodRouter<S2> {
        MethodRouter {
            inner: self.inner.with_state(state),
            binding: self.binding,
        }
    }
    pub(crate) fn endpoint(&self, path: &str) -> Endpoint {
        let (method, resource, operations, signature, handler) = &self.binding;
        Endpoint {
            path: path.into(),
            method,
            resource,
            operations,
            query: match signature {
                EndpointContract::Product(signature) => signature.request.query_owner,
                EndpointContract::External(_) => None,
            },
            contract: signature.clone(),
            operation_id: (*handler).into(),
            conditions: Vec::new(),
            configured_path: None,
            authentication: None,
        }
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
            binding: self.binding,
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
            binding: self.binding,
        }
    }
}

macro_rules! product_methods {
    ($($method:ident => $name:literal),* $(,)?) => { $(
        pub fn $method<H,T,S>(handler:H, resource:&'static Resource, operations:&'static [Operation]) -> MethodRouter<S>
        where H:axum::handler::Handler<T,S> + ContractHandler<T,S>, T:'static, S:Clone+Send+Sync+'static {
            MethodRouter { inner:axum::routing::$method(handler), binding: binding($name,resource,operations,EndpointContract::Product(Box::new(H::signature())),std::any::type_name::<H>()) }
        }

    )* };
}
product_methods!(get=>"GET",post=>"POST",put=>"PUT",patch=>"PATCH",delete=>"DELETE");
macro_rules! external_methods {
    ($($method:ident => ($function:ident,$name:literal)),* $(,)?) => { $(
        pub fn $function<H,T,S>(handler:H,protocol:ExternalProtocol,resource:&'static Resource,operations:&'static [Operation])->MethodRouter<S>
        where H:axum::handler::Handler<T,S>,T:'static,S:Clone+Send+Sync+'static {
            MethodRouter { inner:axum::routing::$method(handler),binding: binding($name,resource,operations,EndpointContract::External(protocol),std::any::type_name::<H>()) }
        }

    )* };
}
external_methods!(get=>(external_get,"GET"),post=>(external_post,"POST"),put=>(external_put,"PUT"),delete=>(external_delete,"DELETE"));
