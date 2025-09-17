use eyre::Result;
use reqwest::{Client, Url};
use std::{fs::File, error::Error, io::Write};
use tracing::{error, info, warn};
use serde::Deserialize;
use chrono::Local;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct APIGetValidatorsResponse {
    pub success: bool,
    pub data: APIGetValidatorsResponseData,
    pub error_msg_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct APIGetValidatorsResponseData {
    pub validators: Option<Vec<APIGetValidatorsResponseDataValidators>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct APIGetValidatorsResponseDataValidators {
    pub public_key: String
}

#[derive(Debug, Deserialize)]
pub struct APIGetSsvOperatorsResponse {
    pub success: bool,
    pub data: APIGetSsvOperatorsResponseData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct APIGetSsvOperatorsResponseData {
    pub ssv_operators: Vec<APIGetSsvOperatorsResponseDataOperators>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct APIGetSsvOperatorsResponseDataOperators {
    pub owner_address: String
}

#[derive(Debug, Deserialize)]
pub struct APIGetSsvOperatorValidatorsResponse {
    pub success: bool,
    pub data: APIGetSsvOperatorValidatorsResponseData,
}

#[derive(Debug, Deserialize)]
pub struct APIGetSsvOperatorValidatorsResponseData {
    pub validators: Vec<String>,
}

pub async fn get_registered_all_pubkeys(
    client: &Client,
    exchange_api_base: String,
    access_jwt: &str,
) -> Result<(), Box<dyn Error>> {
    let exchange_api_url = Url::parse(&format!(
        "{}{}",
        exchange_api_base,
        "/api/v1/user/validators"
    ))?;

    let res = client
        .get(exchange_api_url.to_string())
        .header("Authorization", format!("Bearer {}", access_jwt))
        .send()
        .await?;

    match res.json::<APIGetValidatorsResponse>().await {
        Ok(res_json) => {
            if res_json.success {
                let validators = res_json.data.validators.unwrap_or_default();
                if validators.len() > 0 {
                    let pubkeys: Vec<String> = validators
                        .into_iter()
                        .map(|v| v.public_key)
                        .collect();
                    let now = Local::now();
                    let timestamp = now.format("%Y%m%d_%H%M%S").to_string();
                    let filename = format!("registered_all_pubkeys_{}.txt", timestamp);
                    let mut file = File::create(&filename)?;
                    for key in pubkeys {
                        writeln!(file, "{}", key)?;
                    }

                    info!("Records are saved in {}", filename);
                } else {
                    warn!("No registered pubkeys can be found");
                }
            } else {
                error!(
                    "Failed to get validators: {}",
                    res_json.error_msg_key.unwrap_or_default()
                );
            }
        }
        Err(err) => {
            error!(?err, "Failed to call get validators API");
        }
    }

    Ok(())
}

pub async fn get_registered_ssv_pubkeys(
    client: &Client,
    exchange_api_base: String,
    access_jwt: &str,
) -> Result<(), Box<dyn Error>> {
    let mut exchange_api_url = Url::parse(&format!(
        "{}{}",
        exchange_api_base,
        "/api/v1/user/ssv/operators"
    ))?;

    let mut res = client
        .get(exchange_api_url.to_string())
        .header("Authorization", format!("Bearer {}", access_jwt))
        .send()
        .await?;

    match res.json::<APIGetSsvOperatorsResponse>().await {
        Ok(res_json) => {
            if res_json.success {
                if res_json.data.ssv_operators.len() > 0 {
                    let owner_addresses: Vec<String> = res_json
                        .data
                        .ssv_operators
                        .into_iter()
                        .map(|v| v.owner_address)
                        .collect();
                    for owner_address in &owner_addresses {
                        exchange_api_url = Url::parse(&format!(
                            "{}{}",
                            exchange_api_base,
                            "/api/v1/user/ssv/operator/validators"
                        ))?;
                        res = client
                            .get(exchange_api_url.to_string())
                            .header("Authorization", format!("Bearer {}", access_jwt))
                            .query(&[("ownerAddress", owner_address)])
                            .send()
                            .await?;
                        match res.json::<APIGetSsvOperatorValidatorsResponse>().await {
                            Ok(res_json) => {
                                if res_json.success {
                                    if res_json.data.validators.len() > 0 {
                                        let now = Local::now();
                                        let timestamp = now.format("%Y%m%d_%H%M%S").to_string();
                                        let filename = format!("registered_ssv_owner_{}_ssv_pubkeys_{}.txt", owner_address, timestamp);
                                        let mut file = File::create(&filename)?;
                                        for key in res_json.data.validators {
                                            writeln!(file, "{}", key)?;
                                        }

                                        info!("Records are saved in {}", filename);
                                    } else {
                                        warn!("No registered ssv pubkeys for ssv owner {} can be found", owner_address);
                                    }
                                }
                            }
                            Err(err) => {
                                error!(?err, "Failed to call get ssv operator validators API");
                            }
                        }
                    }

                } else {
                    warn!("No registered ssv operator owner can be found");
                }
            }
        }
        Err(err) => {
            error!(?err, "Failed to call get ssv operator owner API");
        }
    }

    Ok(())
}