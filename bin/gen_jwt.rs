use rand::{distr::Alphanumeric, Rng};
use std::env;
use indexmap::IndexMap;

/// Generates a random string
pub fn random_jwt() -> String {
    rand::rng().sample_iter(&Alphanumeric).take(32).map(char::from).collect()
}

fn format_comma_separated(map: &IndexMap<String, String>) -> String {
    map.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join(",")
}

fn main() {
    let key = "CB_MODULE_ID";
    let module_id = match env::var(key) {
        Ok(value) => value,
        Err(e) => {
            println!("Err: Couldn't read {}: {}", key, e);
            return;
        },
    };
    let mut jwts = IndexMap::new();
    let mut envs = IndexMap::new();
    let jwt = random_jwt();
    let jwt_name = format!("CB_JWT_{}", module_id.to_uppercase());

    envs.insert(jwt_name.clone(), jwt.clone());
    jwts.insert(module_id.clone(), jwt.clone());
    envs.insert("CB_JWTS".to_string(), format_comma_separated(&jwts));
    envs.insert("CB_SIGNER_JWT".to_string(), jwt.clone());
    let envs_str = {
        let mut envs_str = String::new();
        for (k, v) in envs {
            envs_str.push_str(&format!("{}={}\n", k, v));
        }
        envs_str
    };
    std::fs::write(".cb.env", envs_str)
        .expect("Failed to write environment variables to .cb.env file");
}