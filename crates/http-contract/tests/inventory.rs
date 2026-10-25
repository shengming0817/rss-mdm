//! The source check finds unowned registration; mounted-router checks own composition behavior.
use rss_mdm_http_contract::{Endpoint, Operation, catalog, validate_ownership};
use std::path::{Path, PathBuf};
use syn::visit::{self, Visit};
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn files(path: &Path, output: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(path).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files(&path, output)
        } else if path.extension().is_some_and(|s| s == "rs") {
            output.push(path)
        }
    }
}
fn path_name(expr: &syn::Expr) -> String {
    match expr {
        syn::Expr::Reference(r) => path_name(&r.expr),
        syn::Expr::Path(p) => p.path.segments.last().unwrap().ident.to_string(),
        _ => panic!("route ownership must name a static product resource"),
    }
}
fn operations(expr: &syn::Expr) -> Vec<Operation> {
    let syn::Expr::Reference(r) = expr else {
        panic!("static operations required")
    };
    let syn::Expr::Array(a) = r.expr.as_ref() else {
        panic!("operation array required")
    };
    a.elems
        .iter()
        .map(|e| match path_name(e).as_str() {
            "List" => Operation::List,
            "Get" => Operation::Get,
            "Create" => Operation::Create,
            "Update" => Operation::Update,
            "Delete" => Operation::Delete,
            "Lifecycle" => Operation::Lifecycle,
            "Action" => Operation::Action,
            "Query" => Operation::Query,
            _ => panic!("unknown operation"),
        })
        .collect()
}
struct Bindings {
    path: String,
    endpoints: Vec<Endpoint>,
    queried: std::collections::BTreeSet<String>,
}
impl<'ast> Visit<'ast> for Bindings {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if matches!(
            node.method.to_string().as_str(),
            "queried" | "windowed" | "catalog_queried"
        ) {
            let syn::Expr::MethodCall(owner) = node.receiver.as_ref() else {
                panic!("query must bind owned List")
            };
            assert_eq!(owner.method, "owned");
            assert!(operations(&owner.args[1]).iter().any(|op| matches!(
                op,
                Operation::List | Operation::Action | Operation::Query | Operation::Create
            )));
            self.queried
                .insert(path_name(&owner.args[0]).to_lowercase());
        }
        if node.method == "owned" {
            let name = path_name(&node.args[0]).to_lowercase();
            let resource = catalog::ALL
                .iter()
                .find(|r| r.id == name)
                .unwrap_or_else(|| panic!("unknown resource {name}"));
            let method = match node.receiver.as_ref() {
                syn::Expr::Call(c) => path_name(&c.func),
                syn::Expr::MethodCall(c) => c.method.to_string(),
                _ => panic!("ownership must immediately bind an HTTP method"),
            };
            let method = match method.as_str() {
                "get" => "GET",
                "post" => "POST",
                "put" => "PUT",
                "delete" => "DELETE",
                "patch" => "PATCH",
                "head" => "HEAD",
                "options" => "OPTIONS",
                _ => panic!("invalid bound method {method}"),
            };
            let ops = operations(&node.args[1]);
            // Test-owned descriptors live only for this process, just like parsed source strings.
            let ops = Box::leak(ops.into_boxed_slice());
            self.endpoints.push(Endpoint {
                path: self.path.clone(),
                method,
                resource,
                operations: ops,
                query: None,
            });
        }
        visit::visit_expr_method_call(self, node);
    }
}
struct Inventory {
    file: String,
    endpoints: Vec<Endpoint>,
    registrations: usize,
}
impl<'ast> Visit<'ast> for Inventory {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(p) = node.func.as_ref()
            && p.path
                .segments
                .last()
                .is_some_and(|s| s.ident == "from_identity_router")
        {
            assert_eq!(
                self.file, "crates/app/src/api.rs",
                "external router admission escaped the Identity composition"
            );
            assert_eq!(node.args.len(), 1);
            assert_eq!(
                path_name(&node.args[0]),
                "authentication",
                "only the actual Identity router is external"
            );
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if node.attrs.iter().any(|a| {
            a.path().is_ident("cfg")
                && matches!(&a.meta,syn::Meta::List(l) if l.tokens.to_string()=="test")
        }) {
            return;
        }
        visit::visit_item_mod(self, node);
    }
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        assert!(
            !matches!(
                node.method.to_string().as_str(),
                "route_service" | "nest_service"
            ),
            "unclassified service mount: {}",
            self.file
        );
        if node.method == "route" {
            self.registrations += 1;
            assert_eq!(node.args.len(), 2, "unsupported registration {}", self.file);
            let path = match &node.args[0] {
                syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(s),
                    ..
                }) => s.value(),
                syn::Expr::Reference(r) => match r.expr.as_ref() {
                    syn::Expr::Macro(m) if m.mac.path.is_ident("format") => format!(
                        "dynamic:{}",
                        syn::parse2::<syn::LitStr>(m.mac.tokens.clone())
                            .expect("literal format route")
                            .value()
                    ),
                    _ => panic!("unsupported route expression {}", self.file),
                },
                _ => panic!("literal route required: {}", self.file),
            };
            let mut bindings = Bindings {
                queried: Default::default(),
                path: format!("{}:{}", self.file, path),
                endpoints: Vec::new(),
            };
            bindings.visit_expr(&node.args[1]);
            assert!(
                !bindings.endpoints.is_empty(),
                "unowned route {}:{}",
                self.file,
                path
            );
            for endpoint in &bindings.endpoints {
                if endpoint.resource.query == rss_mdm_http_contract::QueryPolicy::Unified
                    && (endpoint.operations.contains(&Operation::List)
                        || (endpoint.resource.collection.is_none()
                            && endpoint.operations.contains(&Operation::Create)))
                {
                    assert!(
                        bindings.queried.contains(endpoint.resource.id),
                        "unbound query field owner: {}",
                        endpoint.resource.id
                    );
                }
            }
            self.endpoints.extend(bindings.endpoints);
        }
        visit::visit_expr_method_call(self, node);
    }
}
#[test]
fn all_ingress_registrations_have_resource_and_real_method_owners() {
    let mut paths = Vec::new();
    for owner in [
        "management-http",
        "apple-channel",
        "windows-channel",
        "agent-channel",
        "app",
    ] {
        files(&root().join(format!("crates/{owner}/src")), &mut paths);
    }
    let mut endpoints = Vec::new();
    let mut count = 0;
    for path in paths {
        let source = std::fs::read_to_string(&path).unwrap();
        let syntax = syn::parse_file(&source).unwrap();
        let mut inventory = Inventory {
            file: path.strip_prefix(root()).unwrap().display().to_string(),
            endpoints: Vec::new(),
            registrations: 0,
        };
        inventory.visit_file(&syntax);
        endpoints.extend(inventory.endpoints);
        count += inventory.registrations;
    }
    assert!(count > 0, "no production registration was examined");
    let violations = validate_ownership(&endpoints, catalog::ALL, catalog::GAPS);
    assert!(
        violations.is_empty(),
        "resource inventory violations: {violations:?}"
    );
}
#[test]
fn bare_registration_is_rejected() {
    let syntax =
        syn::parse_file("fn routes(){ Router::new().route(\"/unowned\",get(handler)); }").unwrap();
    let rejected = std::panic::catch_unwind(|| {
        let mut i = Inventory {
            file: "synthetic.rs".into(),
            endpoints: Vec::new(),
            registrations: 0,
        };
        i.visit_file(&syntax);
    });
    assert!(rejected.is_err());
}
