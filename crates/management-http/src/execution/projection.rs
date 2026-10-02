//! Transport addresses are owned by management HTTP, not execution storage.
use rss_mdm_execution_service::queries::records::{
    ExecutionDirectory, ExecutionKind, RemoteDirectory,
};
use serde_json::{Value, json};
pub fn directory(facts: ExecutionDirectory) -> Value {
    let urls = facts
        .items
        .iter()
        .map(|item| match item.kind {
            ExecutionKind::Command => {
                let device = url::form_urlencoded::byte_serialize(item.device.as_bytes())
                    .collect::<String>()
                    .replace('+', "%20");
                format!("/api/v3/devices/{device}/operations/{}", item.id)
            }
            ExecutionKind::ActionRun => {
                if let Some(policy) = item.policy {
                    format!("/api/v2/policies/{policy}/runs/{}", item.id)
                } else {
                    format!(
                        "/api/v3/remote-operations/{}/runs/{}",
                        item.remote_operation.expect("stored run source"),
                        item.id
                    )
                }
            }
        })
        .collect::<Vec<_>>();
    let mut value = serde_json::to_value(facts).expect("directory facts serialize");
    for (item, url) in value["items"]
        .as_array_mut()
        .expect("typed page")
        .iter_mut()
        .zip(urls)
    {
        item["detailUrl"] = json!(url);
    }
    value
}
pub fn remote_directory(facts: RemoteDirectory) -> Value {
    let urls = facts
        .items
        .iter()
        .map(|item| format!("/api/v3/remote-operations/{}", item.id))
        .collect::<Vec<_>>();
    let mut value = serde_json::to_value(facts).expect("directory facts serialize");
    for (item, url) in value["items"]
        .as_array_mut()
        .expect("typed page")
        .iter_mut()
        .zip(urls)
    {
        item["detailUrl"] = json!(url);
    }
    value
}
