//! Materialize fixed command lanes and their common fresh-install grants from one catalog.
use std::{collections::BTreeSet, env, fmt::Write as _, fs, path::PathBuf};

fn main() {
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo output directory"));
    let catalog = "schema/command-lanes.csv";
    println!("cargo:rerun-if-changed={catalog}");
    let rows = fs::read_to_string(catalog).expect("command lane catalog");
    let mut constants = String::new();
    let mut names = Vec::new();
    let mut roles = Vec::new();
    let mut domains = BTreeSet::new();
    for line in rows.lines().skip(1) {
        let fields: Vec<_> = line.split(',').collect();
        let [name, owner, domain] = fields[..] else {
            panic!("invalid command lane: {line}");
        };
        assert!(owner.bytes().all(|c| c.is_ascii_lowercase() || c == b'_'));
        let role = format!("mdm_dispatch_{owner}");
        assert!(!roles.contains(&role) && domains.insert(domain));
        writeln!(constants,"pub(crate) const {name}: Lane = Lane {{ role: {role:?}, domain: {domain:?}, owner: {owner:?} }};").unwrap();
        names.push(name);
        roles.push(role);
    }
    writeln!(
        constants,
        "pub(crate) const LANES: &[Lane] = &[{}];",
        names.join(",")
    )
    .unwrap();
    fs::write(output.join("command_lanes.rs"), constants).unwrap();
    let grants = roles.join(",");
    for name in [
        "business-roles",
        "audit-runtime",
        "audit-ledger-runtime",
        "command-projections",
    ] {
        let sql = format!("schema/{name}.sql");
        println!("cargo:rerun-if-changed={sql}");
        let template = fs::read_to_string(sql).unwrap();
        fs::write(
            output.join(format!("{name}.sql")),
            template.replace("{command_roles}", &grants),
        )
        .unwrap();
    }
}
