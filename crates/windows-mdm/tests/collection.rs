use rss_mdm_windows_mdm::native::{
    Context, Enrollment, Scope,
    collection::{Inventory, Outcome, Plan, Read, State},
};
use std::collections::BTreeMap;
fn plan(inventory: Inventory) -> Plan {
    BTreeMap::from([("field".into(), Read::Inventory { inventory })])
        .try_into()
        .unwrap()
}
fn context() -> Context {
    Context {
        build: Some([10, 0, 22621, 0]),
        edition: Some(48),
        scope: Scope::Device,
        enrollment: Enrollment::Primary,
    }
}
fn round(state: &mut State, plan: &Plan, message: u32, reply: impl Fn(&str) -> (u16, &str)) {
    let mut sent = Vec::new();
    let mut command = 1024;
    while let Some((step, q)) = state.next().unwrap() {
        let compiled = q.compile(context(), command).unwrap();
        let uri = compiled.objects[0].key().to_owned();
        state.sent(step, message, command).unwrap();
        sent.push((command, uri));
        command += 1;
    }
    // Reverse command order and Results before Status are legitimate.
    for (command, uri) in sent.into_iter().rev() {
        let (status, value) = reply(&uri);
        if status == 200 {
            state.value(message, command, &uri, value.into()).unwrap();
            state.value(message, command, &uri, value.into()).unwrap();
        }
        state.status(message, command, status).unwrap();
        state.status(message, command, status).unwrap();
    }
    state.advance(plan, 1048576).unwrap();
}
#[test]
fn all_fixed_recipes_resolve_and_bind_actual_platform() {
    for kind in [
        Inventory::Win32,
        Inventory::Store,
        Inventory::NonStore,
        Inventory::System,
        Inventory::Network,
        Inventory::InstalledUpdates,
        Inventory::InstallableUpdates,
        Inventory::FailedUpdates,
        Inventory::PendingRebootUpdates,
    ] {
        let plan = plan(kind);
        plan.applicable(context()).unwrap();
        if kind == Inventory::Win32 {
            assert!(
                plan.applicable(Context {
                    edition: Some(101),
                    ..context()
                })
                .is_err()
            );
        }
    }
}
#[test]
fn modern_package_settings_are_not_software_instances() {
    for inventory in [Inventory::Store, Inventory::NonStore, Inventory::System] {
        let plan = plan(inventory);
        let mut state = plan.start("RSS").unwrap();
        round(&mut state, &plan, 1, |_| (200, "Example_publisher"));
        let packages = "AppSettingPolicy/AppUpdateSettings/DoNotUpdate/MaintainProcessorArchitectureOnUpdate/NonRemovable/Example_1.0.0.0_arm64__publisher";
        round(&mut state, &plan, 2, |_| (200, packages));
        round(&mut state, &plan, 3, |uri| {
            assert!(!uri.contains("/AppSettingPolicy/"));
            assert!(!uri.contains("/AppUpdateSettings/"));
            assert!(!uri.contains("/DoNotUpdate/"));
            assert!(!uri.contains("/MaintainProcessorArchitectureOnUpdate/"));
            assert!(!uri.contains("/NonRemovable/"));
            (200, "value")
        });
        round(&mut state, &plan, 4, |uri| {
            (
                200,
                if uri.ends_with("/Example_publisher") {
                    packages
                } else {
                    "Example_publisher"
                },
            )
        });
        let Outcome::Value(value) = state.outcomes(&plan).unwrap().remove("field").unwrap() else {
            panic!("settings container invalidated software inventory")
        };
        assert_eq!(value.as_array().unwrap().len(), 1);
        assert_eq!(value[0]["Name"], "value");
    }
}
#[test]
fn inventory_is_not_complete_until_verified_and_survives_restart() {
    let plan = plan(Inventory::Win32);
    let mut state = plan.start("RSS").unwrap();
    round(&mut state, &plan, 1, |_| (200, "program"));
    assert!(state.outcomes(&plan).unwrap().is_empty());
    state = serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    round(&mut state, &plan, 2, |uri| {
        (
            200,
            if uri.ends_with("/Name") {
                "Example"
            } else {
                "1"
            },
        )
    });
    assert!(state.outcomes(&plan).unwrap().is_empty());
    round(&mut state, &plan, 3, |_| (200, "program"));
    let Outcome::Value(value) = state.outcomes(&plan).unwrap().remove("field").unwrap() else {
        panic!()
    };
    assert_eq!(value[0]["Name"], "Example");
    assert_eq!(value[0]["installation_scope"], "unknown");
    assert!(state.outcomes(&plan).unwrap().is_empty());
}
#[test]
fn empty_requires_a_successful_second_enumeration() {
    let plan = plan(Inventory::Win32);
    let mut state = plan.start("RSS").unwrap();
    round(&mut state, &plan, 1, |_| (200, ""));
    assert!(state.outcomes(&plan).unwrap().is_empty());
    round(&mut state, &plan, 2, |_| (200, ""));
    assert!(
        matches!(state.outcomes(&plan).unwrap().remove("field"),Some(Outcome::Value(v)) if v == serde_json::json!([]))
    );
}
#[test]
fn missing_denied_or_changed_tree_is_never_an_empty_success() {
    for code in [404, 403, 500, 501] {
        let plan = plan(Inventory::Win32);
        let mut state = plan.start("RSS").unwrap();
        round(&mut state, &plan, 1, |_| (200, "program"));
        round(&mut state, &plan, 2, |_| (code, ""));
        assert!(
            matches!(state.outcomes(&plan).unwrap().remove("field"),Some(Outcome::Status(c)) if c == code)
        );
    }
    let plan = plan(Inventory::Win32);
    let mut state = plan.start("RSS").unwrap();
    round(&mut state, &plan, 1, |_| (200, ""));
    round(&mut state, &plan, 2, |_| (200, "new-program"));
    assert!(matches!(
        state.outcomes(&plan).unwrap().remove("field"),
        Some(Outcome::Status(500))
    ));
}
#[test]
fn hostile_or_duplicate_child_id_is_not_traversed() {
    for raw in [
        "..",
        "%2e%2e",
        "%2Fother",
        "%252Fother",
        "one/one",
        "one//two",
        "%00",
    ] {
        let plan = plan(Inventory::Win32);
        let mut state = plan.start("RSS").unwrap();
        round(&mut state, &plan, 1, |_| (200, raw));
        assert!(matches!(
            state.outcomes(&plan).unwrap().remove("field"),
            Some(Outcome::Status(500))
        ));
        assert_eq!(state.unsent(), 0);
    }
}
#[test]
fn scalar_uses_same_engine_and_rejects_conflicting_results() {
    let plan: Plan = BTreeMap::from([(
        "model".into(),
        Read::Scalar {
            uri: "./DevInfo/Mod".into(),
        },
    )])
    .try_into()
    .unwrap();
    let mut state = plan.start("RSS").unwrap();
    let (step, q) = state.next().unwrap().unwrap();
    let uri = q.compile(context(), 1024).unwrap().objects[0]
        .key()
        .to_owned();
    state.sent(step, 1, 1024).unwrap();
    state.value(1, 1024, &uri, "Model".into()).unwrap();
    assert!(state.value(1, 1024, &uri, "other".into()).is_err());
    assert!(state.value(2, 1024, &uri, "Model".into()).is_err());
    state.status(1, 1024, 200).unwrap();
    state.advance(&plan, 100).unwrap();
    assert!(
        matches!(state.outcomes(&plan).unwrap().remove("model"),Some(Outcome::Value(v)) if v == "Model")
    );
}
#[test]
fn enrollment_queries_bind_only_the_current_provider() {
    let plan: Plan = BTreeMap::from([("enrollment".into(), Read::EnrollmentId)])
        .try_into()
        .unwrap();
    let state = plan.start("RSS-A").unwrap();
    let (_, q) = state.next().unwrap().unwrap();
    q.validate_provider("RSS-A").unwrap();
    assert!(q.validate_provider("RSS-B").is_err());
    let direct = BTreeMap::from([(
        "enrollment".into(),
        Read::Scalar {
            uri: "./Device/Vendor/MSFT/DMClient/Provider/RSS-B/EntDMID".into(),
        },
    )]);
    assert!(Plan::try_from(direct).is_err());
}

#[test]
fn omitted_results_and_output_budget_never_form_a_snapshot() {
    let plan = plan(Inventory::Win32);
    let mut state = plan.start("RSS").unwrap();
    let (step, _) = state.next().unwrap().unwrap();
    state.sent(step, 1, 1024).unwrap();
    state.status(1, 1024, 200).unwrap();
    state.advance(&plan, 100).unwrap();
    assert!(state.pending());
    assert!(state.outcomes(&plan).unwrap().is_empty());
    let mut state = plan.start("RSS").unwrap();
    round(&mut state, &plan, 1, |_| (200, "program"));
    round(&mut state, &plan, 2, |_| (200, "value"));
    state.advance(&plan, 1).unwrap();
    assert!(matches!(
        state.outcomes(&plan).unwrap().remove("field"),
        Some(Outcome::Status(500))
    ));
}
