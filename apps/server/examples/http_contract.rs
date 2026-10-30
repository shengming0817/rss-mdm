//! Product-owned offline projection; no config, service instance, socket or database is opened.
fn main() {
    match rss_mdm_app::http_contract_document() {
        Ok(document) => println!(
            "{}",
            serde_json::to_string_pretty(&document).expect("HTTP contract JSON")
        ),
        Err(errors) => {
            for error in errors {
                eprintln!("{error}");
            }
            std::process::exit(1);
        }
    }
}
