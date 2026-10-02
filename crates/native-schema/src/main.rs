//! Offline compiler for pinned Apple and Windows native schema sources.
//! ref: apple/device-management docs/schema.md; yaml-rust2 src/parser.rs.
mod admx;
mod apple;
mod sources;
mod windows;
mod xml;
mod yaml;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if let [mode, manifest, output] = args.as_slice()
        && mode == "--import-admx"
    {
        return admx::import(std::path::Path::new(manifest), std::path::Path::new(output));
    }
    if let [mode, manifest] = args.as_slice()
        && mode == "--import-admx"
    {
        return admx::import(
            std::path::Path::new(manifest),
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../windows-mdm/schema/upstream/admx"),
        );
    }
    if args == ["--check"] || args == ["--write"] || args == ["--check-windows-sources"] {
        let status = std::process::Command::new("python3")
            .arg(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../hack/native_sources.py"),
            )
            .arg("prepare")
            .status()?;
        if !status.success() {
            return Err("native schema ZIP preparation failed".into());
        }
    }
    if args == ["--check-windows-sources"] {
        let sources = windows::Sources::read(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../windows-mdm"),
        )?;
        let missing = sources.unresolved_admx();
        println!(
            "verified {} DDF files and {} ADMX filenames",
            sources.ddf.len(),
            sources.admx.len()
        );
        if !missing.is_empty() {
            for reference in &missing {
                eprintln!("unresolved ADMX: {reference}");
            }
            return Err(format!(
                "{} ADMX references require official source resolution",
                missing.len()
            )
            .into());
        }
        return Ok(());
    }
    if args != ["--check"] && args != ["--write"] {
        return Err("usage: native_schema --check|--write|--check-windows-sources".into());
    }
    let windows_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../windows-mdm");
    let windows = windows::generate(&windows_root)?;
    let windows_path = windows_root.join("src/native/generated.rs");
    if args == ["--check"] {
        if std::fs::read_to_string(&windows_path)? != windows {
            return Err("generated Windows schema is stale".into());
        }
    } else {
        std::fs::create_dir_all(windows_path.parent().ok_or("generated Windows path")?)?;
        std::fs::write(windows_path, windows)?;
    }
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../apple-mdm/schema/upstream");
    let (sources, documents) = sources::read_apple(&root)?;
    for release in &sources.releases {
        apple::version(&release.release)?;
    }
    let generated = apple::generate(&sources, &documents)?;
    let destination = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../apple-mdm/src/native/generated.rs");
    let check = std::env::args().skip(1).collect::<Vec<_>>();
    if check == ["--check"] {
        if std::fs::read_to_string(&destination)? != generated {
            return Err("generated Apple schema is stale".into());
        }
    } else if check == ["--write"] {
        std::fs::create_dir_all(destination.parent().ok_or("generated path")?)?;
        std::fs::write(destination, generated)?;
    } else {
        return Err("usage: native_schema --check|--write".into());
    }
    println!(
        "verified {} releases and {} distinct schemas",
        sources.releases.len(),
        documents.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::yaml::Document;

    #[test]
    fn recursive_schema_alias_is_a_reference_not_unbounded_expansion() {
        let document = Document::parse("node: &node\n  key: Payload\n  children: [*node]\n")
            .expect("official recursive schemas must be representable");
        let root = document.get(document.root(), "node").unwrap();
        let children = document.get(root, "children").unwrap();
        assert_eq!(document.sequence(children).unwrap(), &[root]);
        assert_eq!(document.len(), 7);
    }

    #[test]
    fn duplicate_keys_and_unresolved_aliases_are_rejected() {
        assert!(Document::parse("key: one\nkey: two\n").is_err());
        assert!(Document::parse("key: *missing\n").is_err());
    }

    #[test]
    fn distinct_yaml_scalars_and_multiline_content_are_preserved() {
        let document =
            Document::parse("version: '15.0'\nenabled: false\nnotes: |-\n  one\n  two\n").unwrap();
        assert_eq!(
            document
                .text(document.get(document.root(), "version").unwrap())
                .unwrap(),
            "15.0"
        );
        assert_eq!(
            document
                .text(document.get(document.root(), "enabled").unwrap())
                .unwrap(),
            "false"
        );
        assert_eq!(
            document
                .text(document.get(document.root(), "notes").unwrap())
                .unwrap(),
            "one\ntwo"
        );
    }
}
