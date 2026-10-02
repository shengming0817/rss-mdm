//! Resource content owns immutable native desired inputs; no parallel Boolean configuration store.
use crate::{Create, Error, NativeTarget, Task};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Configuration {
    pub target: NativeTarget,
    pub apply: Task,
    pub remove: Option<Task>,
}
impl Configuration {
    pub fn read(verified: &rss_mdm_content_service::Verified) -> Result<Self, Error> {
        let bytes = verified
            .read_plaintext(16 * 1024 * 1024)
            .map_err(|_| Error::Malformed)?;
        let value: Self = serde_json::from_slice(&bytes).map_err(|_| Error::Malformed)?;
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), Error> {
        use rss_mdm_apple_mdm::native::request::Request as A;
        use rss_mdm_windows_mdm::native::Execution as W;
        self.target.validate()?;
        if matches!(self.apply, Task::Windows { .. })
            && !matches!(self.target, crate::NativeTarget::Device)
        {
            // No current Windows user binding is supplied by the registration/channel owner.
            // Reject at publication rather than poisoning device-wide reconciliation.
            return Err(Error::Unsupported);
        }
        let owned = self.objects()?;
        if self
            .apply
            .permissions()?
            .contains(&crate::authorization::Permission::SoftwareDeploy)
        {
            return Err(Error::Unsupported);
        }
        if let Task::Windows {
            request: W::SyncMl { request },
        } = &self.apply
        {
            mutations(request)?;
        }
        let Some(remove) = &self.remove else {
            return Ok(());
        };
        if remove
            .permissions()?
            .contains(&crate::authorization::Permission::SoftwareDeploy)
        {
            return Err(Error::Unsupported);
        }
        match (&self.apply, remove) {
            (
                Task::Windows { .. },
                Task::Windows {
                    request: W::SyncMl { request },
                },
            ) => {
                mutations(request)?;
                for object in request.objects().map_err(|_| Error::Malformed)? {
                    if !owned
                        .iter()
                        .any(|o| o.platform == "windows" && o.kind == "csp" && o.key == object.uri)
                    {
                        return Err(Error::Malformed);
                    }
                }
            }
            (
                Task::Macos {
                    request: A::InstallProfile { profile },
                },
                Task::Macos {
                    request: A::RemoveProfile { identifier, uuid },
                },
            ) if identifier == &profile.identifier && uuid == &profile.uuid => {}
            (
                Task::Macos {
                    request: A::Declarations { .. },
                },
                Task::Macos {
                    request: A::Declarations { declarations },
                },
            ) if declarations.is_empty() => {}
            _ => return Err(Error::Malformed),
        }
        Ok(())
    }
    pub fn request(
        &self,
        id: uuid::Uuid,
        input_version: String,
        deadline: i64,
        remove: bool,
    ) -> Result<Create, Error> {
        Ok(Create {
            operation_id: id,
            input_version,
            target: self.target.clone(),
            task: if remove {
                self.remove.clone().ok_or(Error::Unsupported)?
            } else {
                self.apply.clone()
            },
            deadline,
        })
    }
}

/// Product claim identity; protocol-specific values remain in their native content owner.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Object {
    pub platform: String,
    pub kind: String,
    pub key: String,
    pub user: String,
}
impl Object {
    /// Windows native object ownership includes ancestor/descendant scopes, on URI segment boundaries.
    /// Other platforms retain their own exact native object identities.
    pub fn overlaps(&self, other: &Self) -> bool {
        if self.platform != other.platform || self.kind != other.kind || self.user != other.user {
            return false;
        }
        self.key == other.key
            || (self.platform == "windows"
                && self.kind == "csp"
                && (self
                    .key
                    .strip_prefix(&other.key)
                    .is_some_and(|rest| rest.starts_with('/'))
                    || other
                        .key
                        .strip_prefix(&self.key)
                        .is_some_and(|rest| rest.starts_with('/'))))
    }
}
impl Configuration {
    pub fn objects(&self) -> Result<Vec<Object>, Error> {
        use rss_mdm_apple_mdm::native::request::Request as A;
        use rss_mdm_windows_mdm::native::{Execution as W, Scope};
        let mut objects = std::collections::BTreeSet::new();
        let user = self.target.user_key().to_owned();
        match &self.apply {
            Task::Windows {
                request: W::SyncMl { request },
            } => {
                for object in request.objects().map_err(|_| Error::Malformed)? {
                    if (object.scope == Scope::User)
                        != matches!(self.target, NativeTarget::User { .. })
                    {
                        return Err(Error::Malformed);
                    }
                    objects.insert(Object {
                        platform: "windows".into(),
                        kind: "csp".into(),
                        key: object.uri,
                        user: user.clone(),
                    });
                }
            }
            Task::Macos {
                request: A::InstallProfile { profile },
            } => {
                objects.insert(Object {
                    platform: "macos".into(),
                    kind: "profile".into(),
                    key: profile.identifier.clone(),
                    user: user.clone(),
                });
                for payload in &profile.payloads {
                    objects.insert(Object {
                        platform: "macos".into(),
                        kind: "payload".into(),
                        key: payload.identifier.clone(),
                        user: user.clone(),
                    });
                }
            }
            Task::Macos {
                request: A::Declarations { declarations },
            } => {
                for declaration in declarations {
                    objects.insert(Object {
                        platform: "macos".into(),
                        kind: "declaration".into(),
                        key: declaration.identifier.clone(),
                        user: user.clone(),
                    });
                }
            }
            _ => return Err(Error::Unsupported),
        }
        if objects.is_empty() {
            return Err(Error::Malformed);
        }
        Ok(objects.into_iter().collect())
    }
}

// Desired configuration owns state mutations. Queries and Exec retain their separate native lifecycles.
fn mutations(request: &rss_mdm_windows_mdm::native::Request) -> Result<(), Error> {
    use rss_mdm_windows_mdm::native::{Request, Verb};
    request.command_count().map_err(|_| Error::Malformed)?;
    let mut pending = vec![request];
    while let Some(request) = pending.pop() {
        match request {
            Request::Node {
                operation: Verb::Get | Verb::Exec,
                ..
            } => return Err(Error::Unsupported),
            Request::Node { .. } => {}
            Request::Atomic { operations } | Request::Sequence { operations } => {
                pending.extend(operations)
            }
        }
    }
    Ok(())
}

/// Immutable publication identity supplied by the owner, never by sealed content.
#[derive(Clone, Copy, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Owner {
    Policy {
        policy: uuid::Uuid,
        version: uuid::Uuid,
    },
    Remote {
        operation: uuid::Uuid,
    },
}
/// Frozen publications retain protected native content; readers open it only for execution.
#[derive(Clone, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Protected(String);
impl std::fmt::Debug for Protected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProtectedConfiguration([redacted])")
    }
}
impl Protected {
    pub fn seal(
        key: &rss_mdm_native_protection::Protector,
        tenant: rss_request_context::TenantId,
        owner: Owner,
        native: &Configuration,
    ) -> Result<Self, Error> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let plain =
            zeroize::Zeroizing::new(serde_json::to_vec(native).map_err(|_| Error::Malformed)?);
        if plain.len() > 16 * 1024 * 1024 {
            return Err(Error::Malformed);
        }
        let aad = crate::protection::aad(tenant, "configuration.publication", &owner)?;
        let sealed = key
            .seal_bytes(&plain, &aad)
            .map_err(|_| Error::Unavailable(crate::Failure::NativeProtection))?;
        Ok(Self(STANDARD.encode(sealed)))
    }
    pub fn open(
        &self,
        key: &rss_mdm_native_protection::Protector,
        tenant: rss_request_context::TenantId,
        owner: Owner,
    ) -> Result<Configuration, Error> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        if self.0.len() > (16_usize * 1024 * 1024 + 68).div_ceil(3) * 4 {
            return Err(Error::Malformed);
        }
        let sealed = STANDARD.decode(&self.0).map_err(|_| Error::Malformed)?;
        let aad = crate::protection::aad(tenant, "configuration.publication", &owner)?;
        let plain = key
            .open_bytes(&sealed, &aad)
            .map_err(|_| Error::Unavailable(crate::Failure::NativeProtection))?;
        let native: Configuration =
            serde_json::from_slice(plain.expose()).map_err(|_| Error::Malformed)?;
        native.validate()?;
        Ok(native)
    }
}

#[cfg(test)]
mod protected_tests {
    use super::*;
    use rss_mdm_native_protection::Protector;
    use rss_request_context::TenantId;
    use uuid::Uuid;
    #[test]
    fn frozen_native_requires_its_exact_publication_and_never_decodes_plaintext() {
        let key = Protector::new(&[17; 32]).unwrap();
        let tenant = TenantId::parse("11111111-1111-1111-1111-111111111111").unwrap();
        let policy = Uuid::new_v4();
        let version = Uuid::new_v4();
        let owner = Owner::Policy { policy, version };
        let native: Configuration = serde_json::from_value(serde_json::json!({
            "target":{"kind":"device"},
            "apply":{"platform":"windows","request":{"kind":"sync_ml","request":{
                "kind":"node","node":"./Device/Vendor/MSFT/Policy/Config/Experience/AllowCortana",
                "instance":[],"operation":"replace","value":{"type":"integer","value":"1"}
            }}},"remove":null
        }))
        .unwrap();
        native.validate().unwrap();
        let sealed = Protected::seal(&key, tenant, owner, &native).unwrap();
        let stored = serde_json::to_value(&sealed).unwrap();
        assert!(!stored.to_string().contains("AllowCortana"));
        let recovered: Protected = serde_json::from_value(stored.clone()).unwrap();
        assert_eq!(
            serde_json::to_value(recovered.open(&key, tenant, owner).unwrap()).unwrap(),
            serde_json::to_value(&native).unwrap()
        );
        for wrong in [
            Owner::Policy {
                policy: Uuid::new_v4(),
                version,
            },
            Owner::Policy {
                policy,
                version: Uuid::new_v4(),
            },
            Owner::Remote { operation: version },
        ] {
            assert!(recovered.open(&key, tenant, wrong).is_err());
        }
        assert!(
            recovered
                .open(
                    &key,
                    TenantId::parse("22222222-2222-2222-2222-222222222222").unwrap(),
                    owner
                )
                .is_err()
        );
        assert!(
            recovered
                .open(&Protector::new(&[18; 32]).unwrap(), tenant, owner)
                .is_err()
        );
        assert!(
            serde_json::from_value::<Protected>(serde_json::to_value(&native).unwrap()).is_err()
        );
        let old = serde_json::json!({"kind":"configuration","native":native,"grants":{},"platform":"windows","exit":"retain","resource_digest":vec![0;32]});
        assert!(serde_json::from_value::<crate::planning::policies::Frozen>(old).is_err());
        let mut tampered = recovered.0.into_bytes();
        tampered[100] = if tampered[100] == b'A' { b'B' } else { b'A' };
        assert!(
            Protected(String::from_utf8(tampered).unwrap())
                .open(&key, tenant, owner)
                .is_err()
        );
    }
}

impl Configuration {
    /// Per-object native input comparison. These values are transient; only keyed digests persist.
    /// A compound dispatch's identity remains separate and never permits clipping its children.
    pub fn object_digests(
        &self,
        key: &rss_mdm_native_protection::Protector,
        tenant: rss_request_context::TenantId,
        device: &str,
    ) -> Result<std::collections::BTreeMap<Object, Vec<u8>>, Error> {
        use rss_mdm_apple_mdm::native::request::Request as A;
        use rss_mdm_windows_mdm::native::{Execution as W, Request};
        use serde_json::{Value, json};
        let mut content: std::collections::BTreeMap<Object, Value> =
            std::collections::BTreeMap::new();
        let identity = |platform: &str, kind: &str, value: &str| Object {
            platform: platform.into(),
            kind: kind.into(),
            key: value.into(),
            user: self.target.user_key().into(),
        };
        match &self.apply {
            Task::Windows {
                request: W::SyncMl { request },
            } => {
                let mut pending = vec![request];
                while let Some(request) = pending.pop() {
                    match request {
                        Request::Node {
                            operation, value, ..
                        } => {
                            let objects = request.objects().map_err(|_| Error::Malformed)?;
                            for object in objects {
                                let values = content
                                    .entry(identity("windows", "csp", &object.uri))
                                    .or_insert_with(|| json!([]));
                                values
                                    .as_array_mut()
                                    .ok_or(Error::Malformed)?
                                    .push(json!([operation, value]));
                            }
                        }
                        Request::Atomic { operations } | Request::Sequence { operations } => {
                            pending.extend(operations.iter().rev())
                        }
                    }
                }
            }
            Task::Macos {
                request: A::InstallProfile { profile },
            } => {
                content.insert(
                    identity("macos", "profile", &profile.identifier),
                    serde_json::to_value(profile).map_err(|_| Error::Malformed)?,
                );
                for (position, payload) in profile.payloads.iter().enumerate() {
                    content.insert(
                        identity("macos", "payload", &payload.identifier),
                        json!([profile.identifier, profile.uuid, position, payload]),
                    );
                }
            }
            Task::Macos {
                request: A::Declarations { declarations },
            } => {
                for declaration in declarations {
                    content.insert(
                        identity("macos", "declaration", &declaration.identifier),
                        serde_json::to_value(declaration).map_err(|_| Error::Malformed)?,
                    );
                }
            }
            _ => return Err(Error::Unsupported),
        }
        content
            .into_iter()
            .map(|(object, value)| {
                let digest = crate::protection::fingerprint(
                    key,
                    tenant,
                    device,
                    "native-configuration/object/v1",
                    &(&self.target, &object, value),
                )?;
                Ok((object, digest))
            })
            .collect()
    }
}

#[cfg(test)]
mod object_tests {
    use super::*;
    use serde_json::{Value, json};
    #[test]
    fn object_content_is_independent_of_sibling_sets_but_preserves_order_and_container() {
        let key = rss_mdm_native_protection::Protector::new(&[27; 32]).unwrap();
        let tenant =
            rss_request_context::TenantId::parse("11111111-1111-1111-1111-111111111111").unwrap();
        let config = |task: Value| {
            serde_json::from_value::<Configuration>(
                json!({"target":{"kind":"device"},"apply":task,"remove":null}),
            )
            .unwrap()
        };
        let node = |node: &str, value: &str| json!({"kind":"node","node":node,"instance":[],"operation":"replace","value":{"type":"integer","value":value}});
        let x = "./Device/Vendor/MSFT/Policy/Config/Experience/AllowCortana";
        let y = "./Device/Vendor/MSFT/Policy/Config/Privacy/LetAppsAccessCamera";
        let windows = |request| {
            config(json!({"platform":"windows","request":{"kind":"sync_ml","request":request}}))
        };
        let digest = |input: &Configuration| {
            let content = input.object_digests(&key, tenant, "device").unwrap();
            assert_eq!(
                content.keys().cloned().collect::<Vec<_>>(),
                input.objects().unwrap()
            );
            content
        };
        let single = windows(node(x, "1"));
        let pair = windows(json!({"kind":"sequence","operations":[node(x,"1"),node(y,"1")]}));
        let one = digest(&single);
        let shared = digest(&pair);
        for (object, hash) in &one {
            assert_eq!(shared.get(object), Some(hash));
        }
        let a = windows(json!({"kind":"sequence","operations":[node(x,"1"),node(x,"0")]}));
        let b = windows(json!({"kind":"sequence","operations":[node(x,"0"),node(x,"1")]}));
        assert_ne!(digest(&a), digest(&b));
        assert_ne!(
            one,
            single
                .object_digests(&key, tenant, "another-device")
                .unwrap()
        );
        let declaration = |id: &str| json!({"identifier":id,"declarationType":"com.apple.asset.data","payload":{"Reference":{"type":"dictionary","value":{"DataURL":{"type":"string","value":"https://example.test/profile.mobileconfig"},"ContentType":{"type":"string","value":"application/plist"}}}}});
        let ddm = |ids: &[&str]| {
            config(
                json!({"platform":"macos","request":{"kind":"declarations","declarations":ids.iter().map(|id|declaration(id)).collect::<Vec<_>>()}}),
            )
        };
        let a = digest(&ddm(&["X", "Y"]));
        let b = digest(&ddm(&["X", "Z"]));
        let shared = a.keys().find(|o| o.key == "X").unwrap();
        assert_eq!(a.get(shared), b.get(shared));
        let profile = |identifier: &str| {
            config(
                json!({"platform":"macos","request":{"kind":"install_profile","profile":{"identifier":identifier,"uuid":"33333333-3333-4333-8333-333333333333","metadata":{},"payloads":[{"schema":"mdm/profiles/com.apple.security.firewall.yaml","identifier":"shared-payload","uuid":"44444444-4444-4444-8444-444444444444","metadata":{},"fields":{"EnableFirewall":{"type":"boolean","value":true}}}]}}}),
            )
        };
        let a = digest(&profile("org.example.a"));
        let b = digest(&profile("org.example.b"));
        let guard = a.keys().find(|o| o.kind == "payload").unwrap();
        assert_ne!(a.get(guard), b.get(guard));
    }
}
