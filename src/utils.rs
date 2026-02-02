use eyre::Result;
use reqwest::{Client, Url};
use serde::Deserialize;
use std::error::Error;
use tracing::{error, info};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct APIUpdatePayoutAddrResponse {
    pub success: bool,
    pub error_msg_key: Option<String>,
}

pub async fn update_payout_address(
    client: &Client,
    exchange_api_base: &str,
    access_jwt: &str,
    payout_address: alloy::primitives::Address,
) -> Result<(), Box<dyn Error>> {
    let api_endpoint: &str = "/api/v1/user/payoutAddress";
    let exchange_api_url = Url::parse(&format!("{}{}", exchange_api_base, api_endpoint))?;

    let res = client
        .post(exchange_api_url.to_string())
        .header("Authorization", format!("Bearer {}", access_jwt))
        .query(&[("payoutAddress", payout_address)])
        .send()
        .await?;

    match res.json::<APIUpdatePayoutAddrResponse>().await {
        Ok(res_json) => {
            if res_json.success {
                info!("successfully updated payout address as {}", payout_address);
            } else {
                error!(
                    "failed to update payout address: {}",
                    res_json.error_msg_key.unwrap_or_default()
                );
            }
        }
        Err(err) => {
            error!(?err, "Failed to call update payout address API");
        }
    }

    Ok(())
}
