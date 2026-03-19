use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use alloy::sol;

#[derive(Debug, Deserialize)]
pub struct KeystoreConfig {
    pub keystore_path: PathBuf,
    pub password_path: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageDvt {
    pub user_id: String,
    pub user_address: String,
    pub verify_type: String,
}

#[derive(Debug, Deserialize)]
pub struct Eip712MessageDvt {
    pub message: MessageDvt,
    pub domain: crate::login_types::Domain,
}

sol! {
    #[allow(missing_docs)]
    #[derive(Serialize)]
    struct data {
        string userId;
        string userAddress;
        string verifyType;
    }
}