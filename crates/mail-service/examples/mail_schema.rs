use rss_mdm_mail_service::store::*;
fn main() {
    println!("{}",serde_json::to_string_pretty(&serde_json::json!({"Qualification":schemars::schema_for!(Request),"Operation":schemars::schema_for!(Receipt),"Directory":schemars::schema_for!(Directory)})).unwrap());
}
