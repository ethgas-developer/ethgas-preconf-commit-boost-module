use eyre::Result;
use reqwest::{Client, Url};
use serde::Deserialize;
use std::{collections::HashMap, error::Error};
use tracing::{error, info};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct APIValidatorUpdateOfacResponse {
    pub success: bool,
    pub error_msg_key: Option<String>,
}

pub async fn update_ofac(
    client: &Client,
    registration_mode: &str,
    exchange_api_base: &str,
    access_jwt: &str,
    enable_ofac: bool,
    pubkeys_str: &str,
) -> Result<(), Box<dyn Error>> {
    let api_endpoint: &str;
    if registration_mode == "ssv" {
        api_endpoint = "/api/v1/user/ssv/operator/validator/update/ofac";
    } else if registration_mode == "obol" {
        api_endpoint = "/api/v1/user/obol/operator/validator/update/ofac";
    } else {
        api_endpoint = "/api/v1/validator/update/ofac";
    }
    let exchange_api_url = Url::parse(&format!("{}{}", exchange_api_base, api_endpoint))?;

    if pubkeys_str.is_empty() {
        return Ok(());
    }

    let pubkeys: Vec<&str> = pubkeys_str.split(',').collect();

    for (_i, chunk) in pubkeys.chunks(100).enumerate() {
        let chunk_str = chunk.join(",");
        let mut form_data = HashMap::new();
        form_data.insert("publicKeys".to_string(), chunk_str);
        form_data.insert("ofac".to_string(), if enable_ofac { "true".to_string() } else { "false".to_string() });

        let res = client
            .post(exchange_api_url.to_string())
            .header("Authorization", format!("Bearer {}", access_jwt))
            .header("content-type", "application/x-www-form-urlencoded")
            .form(&form_data)
            .send()
            .await?;

        match res.json::<APIValidatorUpdateOfacResponse>().await {
            Ok(res_json) => {
                if res_json.success {
                    if enable_ofac {
                        info!("successfully enabled ofac for the above registered validators");
                    } else {
                        info!("successfully disabled ofac for the above registered validators");
                    }
                } else if enable_ofac {
                    error!(
                        "failed to enable ofac: {}",
                        res_json.error_msg_key.unwrap_or_default()
                    );
                } else {
                    error!(
                        "failed to disable ofac: {}",
                        res_json.error_msg_key.unwrap_or_default()
                    );
                }
            }
            Err(err) => {
                error!(?err, "Failed to call update ofac API");
            }
        }
    }

    Ok(())
}
