use serde::{Deserialize, Serialize};
use std::{path::PathBuf};

#[derive(Debug, Deserialize)]
pub struct KeystoreConfig {
    pub keystore_path: PathBuf,
    pub password_path: PathBuf,
}