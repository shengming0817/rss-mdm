mod gc;
mod http;
mod mirror;

fn upload_metadata(
    directory: &std::path::Path,
    id: uuid::Uuid,
) -> anyhow::Result<std::path::PathBuf> {
    let mut found = None;
    for entry in std::fs::read_dir(directory)? {
        let path = entry?.path();
        if path.extension().and_then(|v| v.to_str()) != Some("json") {
            continue;
        }
        let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        if value["id"] == id.to_string() {
            anyhow::ensure!(found.is_none(), "fixture operation must have one actor");
            found = Some(path);
        }
    }
    found.ok_or_else(|| anyhow::anyhow!("fixture upload metadata missing"))
}
