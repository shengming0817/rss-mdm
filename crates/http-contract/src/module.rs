//! Closed product route declarations, lowered through Axum's own router.
//! INVARIANT: HTTP-MODULE-COMPLETENESS-01
//! Required fields are compiled into production constructors and their only lowering path.
//! ref: axum axum/src/routing/mod.rs@axum-v0.8.9
use crate::{Endpoint, Router, routing::MethodRouter};
use std::marker::PhantomData;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Listener {
    Browser,
    Agent,
    WindowsEnrollment,
    WindowsManagement,
    Apple,
}

pub trait Declaration: 'static {
    const ID: &'static str;
}

#[must_use]
pub struct Route<S> {
    path: String,
    method: MethodRouter<S>,
    configured: Option<(crate::ConfiguredSegment, Option<String>)>,
}
impl<S: Clone + Send + Sync + 'static> Route<S> {
    pub fn new(path: &str, method: MethodRouter<S>) -> Self {
        Self {
            path: path.into(),
            method,
            configured: None,
        }
    }
    pub fn configured(
        template: &str,
        binding: crate::ConfiguredSegment,
        resolved: Option<&str>,
        method: MethodRouter<S>,
    ) -> Self {
        let mut route = Self::new(template, method);
        route.configured = Some((binding, resolved.map(str::to_owned)));
        route
    }
}

mod sealed {
    pub trait Node {}
}
/// Only complete declared modules or bound endpoints can fill a module field.
#[doc(hidden)]
pub trait Node<S>: sealed::Node + 'static {
    fn enabled(&self) -> bool {
        true
    }
    fn append(self, name: &'static str, prefix: &'static str, assembly: &mut Assembly<S>);
}
impl<S> sealed::Node for Route<S> {}
impl<S, M> sealed::Node for Router<S, M> {}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Key {
    pub id: String,
    pub method: &'static str,
    pub path: String,
}
#[derive(Clone)]
pub(crate) struct Presence {
    pub id: &'static str,
    pub allowed: &'static [Listener],
}

/// Macro expansion access only. The field declaration supplies the slots before lowering.
#[doc(hidden)]
pub struct Assembly<S> {
    pub(crate) inner: Option<axum::Router<S>>,
    pub(crate) endpoints: Vec<Endpoint>,
    pub(crate) expected: Vec<Key>,
    pub(crate) observed: Vec<Key>,
    pub(crate) modules: Vec<Presence>,
    pub(crate) resources: Vec<&'static crate::Resource>,
    slots: &'static [&'static str],
    consumed: Vec<&'static str>,
}
impl<S: Clone + Send + Sync + 'static> Assembly<S> {
    pub fn new(
        id: &'static str,
        allowed: &'static [Listener],
        slots: &'static [&'static str],
    ) -> Self {
        assert!(
            !slots.is_empty() && !allowed.is_empty(),
            "a module requires fields and listener ownership"
        );
        Self {
            inner: Some(axum::Router::new()),
            endpoints: Vec::new(),
            expected: Vec::new(),
            observed: Vec::new(),
            modules: vec![Presence { id, allowed }],
            resources: Vec::new(),
            slots,
            consumed: Vec::new(),
        }
    }
    pub fn field<N: Node<S>>(
        &mut self,
        name: &'static str,
        prefix: &'static str,
        required: bool,
        node: N,
    ) {
        assert!(
            self.slots.contains(&name) && !self.consumed.contains(&name),
            "unknown or repeated module field"
        );
        // Validate even when an offline child has no serving router to nest.
        if !prefix.is_empty() {
            let _ = axum::Router::<()>::new().nest(prefix, axum::Router::new());
        }
        assert!(
            !required || node.enabled(),
            "required module field is disabled"
        );
        self.consumed.push(name);
        node.append(name, prefix, self);
    }
    pub fn finish<M: Declaration>(self) -> Router<S, M> {
        assert_eq!(
            self.slots.len(),
            self.consumed.len(),
            "required module field was not mounted"
        );
        Router {
            inner: self.inner,
            endpoints: self.endpoints,
            expected: self.expected,
            observed: self.observed,
            modules: self.modules,
            resources: self.resources,
            activation: None,
            marker: PhantomData,
        }
    }
}
fn path(prefix: &str, path: &str) -> String {
    if prefix.is_empty() {
        path.into()
    } else if prefix.ends_with('/') {
        format!("{prefix}{}", path.trim_start_matches('/'))
    } else if path == "/" {
        prefix.into()
    } else {
        format!("{prefix}{path}")
    }
}

impl<S: Clone + Send + Sync + 'static> Node<S> for Route<S> {
    fn append(self, name: &'static str, prefix: &'static str, a: &mut Assembly<S>) {
        assert!(
            prefix.is_empty(),
            "endpoint paths are declared at their leaf owner"
        );
        let mut endpoints = vec![self.method.endpoint(&self.path)];
        let mut resolved = Some(self.path.clone());
        if let Some((binding, value)) = self.configured {
            assert!(
                !binding.name.is_empty() && !binding.source.is_empty(),
                "configuration binding required"
            );
            let capture = binding.capture();
            assert_eq!(
                self.path.split('/').filter(|s| *s == capture).count(),
                1,
                "whole configuration segment required"
            );
            resolved = value.map(|value| {
                let id = uuid::Uuid::parse_str(&value).expect("configured route UUID");
                assert!(
                    !id.is_nil() && !value.contains('/'),
                    "configured route UUID"
                );
                self.path.replace(&capture, &value)
            });
            for e in &mut endpoints {
                e.configured_path = Some(binding.clone());
            }
        }
        let id = format!("{}::{name}", a.modules[0].id);
        let keys = endpoints
            .iter()
            .map(|e| Key {
                id: id.clone(),
                method: e.method,
                path: e.path.clone(),
            })
            .collect::<Vec<_>>();
        a.resources.extend(endpoints.iter().map(|e| e.resource));
        a.expected.extend(keys.iter().cloned());
        a.inner = a
            .inner
            .take()
            .zip(resolved)
            .map(|(inner, path)| inner.route(&path, self.method.inner));
        a.observed.extend(keys);
        a.endpoints.extend(endpoints);
    }
}
impl<S: Clone + Send + Sync + 'static, M: Declaration> Node<S> for Router<S, M> {
    fn enabled(&self) -> bool {
        self.activation != Some(false)
    }
    fn append(self, _name: &'static str, prefix: &'static str, a: &mut Assembly<S>) {
        let mut child = self;
        for e in &mut child.endpoints {
            e.path = path(prefix, &e.path);
        }
        for key in child.expected.iter_mut().chain(&mut child.observed) {
            key.path = path(prefix, &key.path);
        }
        a.inner = a.inner.take().zip(child.inner).map(|(inner, child)| {
            if prefix.is_empty() {
                inner.merge(child)
            } else {
                inner.nest(prefix, child)
            }
        });
        a.expected.extend(child.expected);
        a.observed.extend(child.observed);
        a.endpoints.extend(child.endpoints);
        a.modules.extend(child.modules);
        a.resources.extend(child.resources);
    }
}

/// Declare required, named endpoint/module fields and their sole lowering implementation.
/// Each field's concrete node type is retained until the complete constructor is consumed.
/// A constructor cannot omit a declared endpoint or subtree:
/// ```compile_fail
/// use rss_mdm_http_contract::{route_module,module::Route,routing::get,catalog::HEALTH,Operation};
/// route_module! { struct Health for [Browser] { live, ready } }
/// let _ = Health { live:Route::new("/livez",get(||async{},&HEALTH,&[Operation::Action])) }.assemble::<()>();
/// ```
/// Unclassified handlers cannot fill an endpoint field:
/// ```compile_fail
/// use rss_mdm_http_contract::{module::Route,routing::get,catalog::HEALTH,Operation};
/// async fn erased()->axum::response::Response { unimplemented!() }
/// let _ = Route::<()>::new("/livez",get(erased,&HEALTH,&[Operation::Action]));
/// ```
#[macro_export]
macro_rules! route_module {
    ($vis:vis struct $name:ident for [$($listener:ident),+ $(,)?] { $($field:ident $([$optional:ident])? $(at $prefix:literal)?),+ $(,)? }) => {
        #[must_use]
        #[allow(non_camel_case_types)]
        $vis struct $name<$($field),+> { $(pub $field:$field),+ }
        #[allow(non_camel_case_types)]
        impl<$($field:'static),+> $crate::module::Declaration for $name<$($field),+> {
            const ID:&'static str=concat!(module_path!(),"::",stringify!($name));
        }
        #[allow(non_camel_case_types)]
        impl<$($field),+> $name<$($field),+> {
            pub fn assemble<S:Clone+Send+Sync+'static>(self)->$crate::Router<S,Self>
            where $($field:$crate::module::Node<S>),+ {
                let mut assembly=$crate::module::Assembly::new(
                    <Self as $crate::module::Declaration>::ID,
                    &[$($crate::module::Listener::$listener),+], &[$(stringify!($field)),+]);
                $(assembly.field(stringify!($field),$crate::route_module!(@prefix $($prefix)?),$crate::route_module!(@required $($optional)?),self.$field);)+
                assembly.finish()
            }
        }
    };
    (@required optional)=>{false};
    (@required)=>{true};
    (@prefix $prefix:literal)=>{$prefix};
    (@prefix)=>{""};
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Operation, catalog::HEALTH, routing::get};
    crate::route_module! { struct Health for [Browser] { live,ready } }
    fn health() -> Router<(), impl Declaration> {
        Health {
            live: Route::new("/livez", get(|| async {}, &HEALTH, &[Operation::Action])),
            ready: Route::new("/readyz", get(|| async {}, &HEALTH, &[Operation::Action])),
        }
        .assemble()
    }
    #[test]
    fn missing_endpoint_receipt_is_rejected_even_with_the_same_resource() {
        let mut routes = health();
        routes.observed.pop();
        routes.endpoints.pop();
        assert!(
            routes
                .validate(Listener::Browser)
                .iter()
                .any(|v| v.contains("incomplete"))
        );
    }
    #[test]
    fn missing_whole_required_module_is_rejected_before_erasure() {
        let mut assembly =
            Assembly::<()>::new("browser", &[Listener::Browser], &["host", "management"]);
        assembly.field("host", "", true, health());
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || assembly.finish::<Health<Route<()>, Route<()>>>()
            ))
            .is_err()
        );
    }
    #[test]
    fn only_declared_optional_slots_accept_disabled_modules() {
        crate::route_module! { struct Required for [Browser] { host } }
        assert!(
            std::panic::catch_unwind(|| Required {
                host: health().when("host", false)
            }
            .assemble())
            .is_err()
        );
        crate::route_module! { struct Optional for [Browser] { host [optional] } }
        let routes = Optional {
            host: health().when("host", false),
        }
        .assemble();
        assert!(routes.endpoints().is_empty());
        assert!(routes.validate(Listener::Browser).is_empty());
    }
    #[tokio::test]
    async fn declared_prefix_matches_axum_root_nesting_and_implicit_head() {
        use tower::ServiceExt;
        crate::route_module! { struct Leaf for [Browser] { root } }
        crate::route_module! { struct Root for [Browser] { leaf at "/health" } }
        let routes = Root {
            leaf: Leaf {
                root: Route::new("/", get(|| async {}, &HEALTH, &[Operation::Action])),
            }
            .assemble::<()>(),
        }
        .assemble();
        assert_eq!(routes.endpoints()[0].path, "/health");
        let response = routes
            .into_checked_axum(Listener::Browser)
            .oneshot(
                axum::http::Request::builder()
                    .method("HEAD")
                    .uri("/health")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }
}
