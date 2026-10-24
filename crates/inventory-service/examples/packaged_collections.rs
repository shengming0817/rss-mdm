//! Regenerate the package data from the actual producer owners, without database access.
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args != ["--write"] && args != ["--check"] {
        return Err("usage: packaged_collections --write|--check".into());
    }
    let definitions = rss_mdm_inventory_service::collection::packaged::definitions()?;
    let expected = format!("{}\n", serde_json::to_string(&definitions)?);
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../agent-wire/src/packaged_collections.json");
    if args == ["--write"] {
        std::fs::write(path, expected)?;
    } else if std::fs::read_to_string(path)? != expected {
        return Err("packaged collection data differs from producer declarations".into());
    }
    println!(
        "verified {} packaged native collection definitions",
        definitions.len()
    );
    Ok(())
}
