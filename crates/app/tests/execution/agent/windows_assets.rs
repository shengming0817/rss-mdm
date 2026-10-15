//! Synthetic Windows source evidence; device API behavior requires separate T3 evidence.
use crate::test_support::*;
use std::collections::BTreeMap;

pub(super) fn rows(query: &str, stage: i32) -> Option<Vec<BTreeMap<String, Value>>> {
    let rows = match query {
        "system" => json!([{"Model":"Native Model","Manufacturer":"Native Vendor"}]),
        "os" => json!([{"Caption":"Windows 11","Version":"10.0","BuildNumber":"26100"}]),
        "edition" => json!([{"EditionID":"Professional"}]),
        "architecture" => {
            json!([{"PROCESSOR_ARCHITECTURE":if stage == 0 {"AMD64"} else if stage == 1 {"ARM64"} else {"unknown"}}])
        }
        "bios" => {
            json!([{"SerialNumber":if stage == 0 {" sn-2741 "} else {"To Be Filled By O.E.M."}}])
        }
        "product" => {
            json!([{"UUID":if stage == 0 {"12345678-ABCD-4234-ABCD-123456789ABC"} else {"00000000-0000-0000-0000-000000000000"}}])
        }
        "software" if stage == 2 => json!([]),
        "software" => {
            let sid1 = "S-1-5-21-1-2-3-1001";
            let sid2 = "S-1-5-21-1-2-3-1002";
            let items: Vec<Value> = [
                ("win32.uninstall.32", "device", ""),
                ("win32.uninstall.64", "user", sid1),
                ("msix.registered", "user", sid1),
                ("msix.registered", "user", sid2),
                ("msix.provisioned", if stage == 5 { "user" } else { "device" }, if stage == 5 { sid1 } else { "" }),
            ].into_iter().map(|(origin, scope, owner)| {
                json!({"id":format!("{origin}:{owner}"),"native_id":"same-package","name":"private-software","version":"1.0","publisher":"Acme","scope":scope,"owner":owner,"origin":if stage == 4 {"msix.unknown"} else {origin},"location":"C:\\Apps"})
            }).collect();
            json!(items)
        }
        _ => return None,
    };
    Some(serde_json::from_value(rows).expect("synthetic native rows"))
}

pub(super) fn verify_identity(registration: Uuid, attempt: Uuid, stage: i32) -> Result<()> {
    for (key, expected) in [
        ("device.os.edition", "Professional"),
        (
            "device.architecture",
            if stage == 0 { "x86_64" } else { "aarch64" },
        ),
        ("device.serial_number", "SN-2741"),
        (
            "device.hardware_uuid",
            "12345678-abcd-4234-abcd-123456789abc",
        ),
    ] {
        let actual = pg(&format!(
            "SELECT value::jsonb->>'value' FROM mdm.inventory WHERE tenant_id='{}' AND registration='{registration}' AND source='agent.native' AND field='{key}'",
            case_tenant()
        ))?;
        ensure!(actual.trim() == expected, "{key}: {actual}");
        if stage != 0 && key != "device.os.edition" && !(stage == 1 && key == "device.architecture")
        {
            let quality = pg(&format!(
                "SELECT attempts::jsonb#>>'{{fields,{key},quality}}' FROM mdm_access.collection_runs WHERE tenant_id='{}' AND id='{attempt}'",
                case_tenant()
            ))?;
            ensure!(quality.trim() == "invalid", "{key}: {quality}");
        }
    }
    Ok(())
}

pub(super) fn verify_software(value: &Value) -> Result<()> {
    let rows = value["value"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("software array"))?;
    ensure!(rows.len() == 5);
    let mut states = std::collections::BTreeMap::<String, usize>::new();
    let mut ids = std::collections::BTreeSet::new();
    for row in rows {
        let item = &row["value"];
        *states
            .entry(item["installation_state"]["value"].as_str().unwrap().into())
            .or_default() += 1;
        ensure!(ids.insert(item["id"]["value"].as_str().unwrap()));
        ensure!(item["native_id"]["value"] == "same-package");
    }
    ensure!(
        states
            == [
                ("installed".into(), 2),
                ("registered".into(), 2),
                ("provisioned".into(), 1)
            ]
            .into()
    );
    Ok(())
}
