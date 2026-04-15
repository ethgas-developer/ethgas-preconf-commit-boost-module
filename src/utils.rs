use eyre::Result;
use reqwest::{Client, Url};
use serde::Deserialize;
use std::{error::Error, collections::HashMap};
use tracing::{error, info};
use alloy::{
    hex::encode,
    sol_types::eip712_domain
};
use crate::{
    login_types::{EoaSigner, Eip712Message}, 
    dvt_types::Eip712MessageDvt
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct APIUpdatePayoutAddrResponse {
    pub success: bool,
    pub error_msg_key: Option<String>,
}

pub async fn update_payout_address(
    client: &Client,
    registration_mode: &str,
    exchange_api_base: &str,
    access_jwt: &str,
    payout_address: alloy::primitives::Address,
    pubkeys_str: &str,
) -> Result<(), Box<dyn Error>> {
    let api_endpoint = if registration_mode == "ssv" {
        "/api/v1/user/ssv/operator/validator/update/validatorPayoutAddress"
    } else if registration_mode == "obol" {
        "/api/v1/user/obol/operator/validator/update/validatorPayoutAddress"
    } else {
        "/api/v1/validator/update/validatorPayoutAddress"
    };
    let exchange_api_url = Url::parse(&format!("{}{}", exchange_api_base, api_endpoint))?;
    let payout_address_str = payout_address.to_string();

    if pubkeys_str.is_empty() {
        return Ok(());
    }

    let pubkeys: Vec<&str> = pubkeys_str.split(',').collect();

    for (_i, chunk) in pubkeys.chunks(100).enumerate() {
        let chunk_str = chunk.join(",");
        let mut form_data = HashMap::new();
        form_data.insert("publicKeys".to_string(), chunk_str);
        form_data.insert("validatorPayoutAddress".to_string(), payout_address_str.clone());

        let res = client
            .post(exchange_api_url.to_string())
            .header("Authorization", format!("Bearer {}", access_jwt))
            .header("content-type", "application/x-www-form-urlencoded")
            .form(&form_data)
            .send()
            .await?;

        match res.json::<APIUpdatePayoutAddrResponse>().await {
            Ok(res_json) => {
                if res_json.success {
                    info!("successfully updated payout address to {} for the above registered validators", payout_address);
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
    }

    Ok(())
}

pub async fn generate_eip712_signature(
    eip712_message_str: &str, 
    signer: &EoaSigner
) -> Result<String> {

    let eip712_message: Eip712Message = serde_json::from_str(eip712_message_str)
        .map_err(|e| eyre::eyre!("Failed to parse EIP712 message: {}", e))?;

    let domain = eip712_domain! {
        name: eip712_message.domain.name,
        version: eip712_message.domain.version,
        chain_id: eip712_message.domain.chain_id,
        verifying_contract: eip712_message.domain.verifying_contract,
    };

    let message = crate::login_types::data {
        hash: eip712_message.message.hash.clone(),
        message: eip712_message.message.message,
        domain: eip712_message.message.domain,
    };

    // let hash = message.eip712_signing_hash(&domain);
    // let signature = signer.sign_hash(&hash).await?;
    let signature = signer.sign_typed_data(&message, &domain).await?;
    Ok(encode(signature.as_bytes()))
}

pub async fn generate_eip712_signature_for_dvt(
    eip712_message_str: &str,
    signer: &EoaSigner,
) -> Result<String> {
    let eip712_message: Eip712MessageDvt = serde_json::from_str(eip712_message_str)
        .map_err(|e| eyre::eyre!("Failed to parse EIP712 message: {}", e))?;

    let domain = eip712_domain! {
        name: eip712_message.domain.name,
        version: eip712_message.domain.version,
        chain_id: eip712_message.domain.chain_id,
        verifying_contract: eip712_message.domain.verifying_contract,
    };

    let message = crate::dvt_types::data {
        userId: eip712_message.message.user_id,
        userAddress: eip712_message.message.user_address,
        verifyType: eip712_message.message.verify_type,
    };

    // let hash = message.eip712_signing_hash(&domain);
    // let signature = signer.sign_hash(&hash).await?;
    let signature = signer.sign_typed_data(&message, &domain).await?;
    Ok(encode(signature.as_bytes()))
}
