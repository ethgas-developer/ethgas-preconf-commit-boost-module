use alloy::{
    hex::encode,
    primitives::{FixedBytes, B256, PrimitiveSignature},
    signers::{local::PrivateKeySigner, Signer, ledger::{HDPath, LedgerSigner}, Error as SignerError},
    sol,
    sol_types::{eip712_domain, Eip712Domain, SolStruct},
};
use commit_boost::prelude::BlsPublicKey;
use eyre::Result;
use reqwest::{Client, Url};
use std::{fs::File, error::Error, io::Write, env, str::FromStr, path::PathBuf};
use tracing::{error, info, warn};
use serde::{Deserialize, Serialize};
use chrono::Local;
use crate::{ofac::update_ofac, models::KeystoreConfig};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MessageObol {
    user_id: String,
    user_address: String,
    verify_type: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Domain {
    name: String,
    version: String,
    chain_id: u64,
    verifying_contract: alloy::primitives::Address,
}

#[derive(Debug, Deserialize)]
struct Eip712MessageObol {
    message: MessageObol,
    domain: Domain,
}


#[derive(Debug, Deserialize)]
struct APIObolNodeOperatorRegisterResponse {
    success: bool,
    data: APIObolNodeOperatorRegisterResponseData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct APIObolNodeOperatorRegisterResponseData {
    available: bool,
    message_to_sign: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct APIObolNodeOperatorVerifyResponse {
    success: bool,
    error_msg_key: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct APIObolNodeOperatorRefreshResponse {
    success: bool,
    error_msg_key: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct APIObolValidatorRegisterResponse {
    success: bool,
    error_msg_key: Option<String>,
    data: APIObolValidatorRegisterResponseData,
}

#[derive(Debug, Deserialize)]
struct APIObolValidatorRegisterResponseData {
    added: Option<Vec<BlsPublicKey>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct APIObolValidatorDeregisterResponse {
    success: bool,
    error_msg_key: Option<String>,
    data: APIObolValidatorDeregisterResponseData,
}

#[derive(Debug, Deserialize)]
struct APIObolValidatorDeregisterResponseData {
    removed: Vec<BlsPublicKey>,
}

enum ObolSigner {
    PrivateKey(PrivateKeySigner),
    Ledger(LedgerSigner),
}

impl ObolSigner {
    pub fn address(&self) -> alloy::primitives::Address {
        match self {
            ObolSigner::Ledger(signer) => signer.address(),
            ObolSigner::PrivateKey(signer) => signer.address(),
        }
    }

    pub async fn sign_typed_data(&self, message: &data, domain: &Eip712Domain) -> Result<PrimitiveSignature, SignerError> {
        match self {
            ObolSigner::Ledger(signer) => signer.sign_typed_data(message, domain).await,
            ObolSigner::PrivateKey(signer) => signer.sign_typed_data(message, domain).await,
        }
    }
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

async fn generate_eip712_signature_for_obol(
    eip712_message_str: &str,
    signer: &ObolSigner,
) -> Result<String> {

    let eip712_message: Eip712MessageObol = serde_json::from_str(eip712_message_str)
        .map_err(|e| eyre::eyre!("Failed to parse EIP712 message: {}", e))?;

    let domain = eip712_domain! {
        name: eip712_message.domain.name,
        version: eip712_message.domain.version,
        chain_id: eip712_message.domain.chain_id,
        verifying_contract: eip712_message.domain.verifying_contract,
    };

    let message = data {
        userId: eip712_message.message.user_id,
        userAddress: eip712_message.message.user_address,
        verifyType: eip712_message.message.verify_type,
    };

    let signature = signer.sign_typed_data(&message, &domain).await?;
    Ok(encode(signature.as_bytes()))
}

pub async fn register_obol_keys(
    client: &Client,
    access_jwt: &str,
    config_extra_exchange_api_base: &str,
    config_extra_enable_registration: bool,
    config_extra_registration_mode: &str,
    config_extra_enable_pricer: bool,
    config_extra_enable_ofac: bool,
    config_extra_obol_node_operator_owner_mode: &Option<String>,
    config_extra_obol_node_operator_owner_signing_keys: &Option<Vec<B256>>,
    config_extra_obol_node_operator_owner_keystores: &Option<Vec<KeystoreConfig>>,
    config_extra_obol_node_operator_owner_ledger_paths: &Option<Vec<String>>,
    config_extra_obol_node_operator_owner_validator_pubkeys: &Option<Vec<Vec<BlsPublicKey>>>,
) -> Result<(), Box<dyn Error>> {
    let obol_node_operator_owner_validator_pubkeys = match config_extra_obol_node_operator_owner_validator_pubkeys {
        Some(validator_pubkeys) => validator_pubkeys.clone(),
        None => {
            return Err(std::io::Error::other(
                "obol_node_operator_owner_validator_pubkeys cannot be empty",
            )
            .into())
        }
    };
    let obol_node_operator_signers: Vec<ObolSigner> = match config_extra_obol_node_operator_owner_mode {
        Some(mode) => match mode.as_str() {
            "key" => {
                let obol_node_operator_owner_signing_keys = match config_extra_obol_node_operator_owner_signing_keys {
                    Some(signing_keys) => signing_keys.clone(),
                    None => match env::var("OBOL_NODE_OPERATOR_OWNER_SIGNING_KEYS") {
                        Ok(signing_keys_str) => signing_keys_str
                            .split(',')
                            .filter(|s| !s.trim().is_empty())
                            .map(|key| {
                                B256::from_str(key.trim()).map_err(|_| {
                                    std::io::Error::new(
                                        std::io::ErrorKind::InvalidData,
                                        "Invalid signing key format".to_string(),
                                    )
                                })
                            })
                            .collect::<Result<Vec<B256>, _>>()?,
                        Err(_) => {
                            return Err(std::io::Error::other(
                                "obol_node_operator_owner_signing_keys cannot be empty",
                            )
                            .into());
                        }
                    },
                };
                if obol_node_operator_owner_signing_keys.is_empty() {
                        return Err(std::io::Error::other(
                            "obol_node_operator_owner_signing_keys cannot be empty",
                    )
                    .into());
                };

                let mut operator_signers = Vec::new();
                for key_byte in obol_node_operator_owner_signing_keys {
                    let signer = PrivateKeySigner::from_bytes(&key_byte)
                        .map_err(|e| eyre::eyre!("Failed to create signer: {}", e))?;
                    operator_signers.push(ObolSigner::PrivateKey(signer));
                }
                operator_signers
            }
            "keystore" => {
                let operator_signers: Vec<ObolSigner> = match config_extra_obol_node_operator_owner_keystores {
                    Some(keystores) => {
                        let mut operator_signers = Vec::new();
                        for keystore in keystores {
                            let password = std::fs::read_to_string(&keystore.password_path)?;
                            let signer = PrivateKeySigner::decrypt_keystore(&keystore.keystore_path, password.trim())
                                .map_err(|e| eyre::eyre!("Failed to create signer: {}", e))?;
                            operator_signers.push(ObolSigner::PrivateKey(signer));
                        }
                        operator_signers

                    }
                    None => {
                        let keystore_paths = env::var("OBOL_NODE_OPERATOR_OWNER_KEYSTORES");
                        let password_paths = env::var("OBOL_NODE_OPERATOR_OWNER_PASSOWRDS");

                        match (keystore_paths, password_paths) {
                            (Ok(keystore_paths), Ok(password_paths)) => {
                                let keystore_paths = keystore_paths
                                    .split(',')
                                    .filter(|s| !s.trim().is_empty())
                                    .collect::<Vec<_>>();
                                let password_paths = password_paths
                                    .split(',')
                                    .filter(|s| !s.trim().is_empty())
                                    .collect::<Vec<_>>();

                                if keystore_paths.len() != password_paths.len() {
                                    return Err(std::io::Error::other("OBOL_NODE_OPERATOR_OWNER_KEYSTORES & OBOL_NODE_OPERATOR_OWNER_PASSWORDS should have the same array length").into());
                                }

                                let mut operator_signers = Vec::new();
                                for (keystore_path, password_path) in keystore_paths.iter().zip(password_paths.iter()) {
                                    let password = std::fs::read_to_string(password_path)?;
                                    let signer = PrivateKeySigner::decrypt_keystore(keystore_path, password.trim())
                                        .map_err(|e| eyre::eyre!("Failed to create signer: {}", e))?;
                                    operator_signers.push(ObolSigner::PrivateKey(signer));
                                }
                                operator_signers

                            }
                            _ => {
                                return Err(std::io::Error::other(
                                    "obol_node_operator_owner_keystores cannot be empty",
                                )
                                .into());
                            }
                        }
                    }
                };
                operator_signers

            }
            "ledger" => {
                let obol_node_operator_owner_ledger_paths = match config_extra_obol_node_operator_owner_ledger_paths {
                    Some(paths) => paths.clone(),
                    None => return Err(std::io::Error::other(
                        "obol_node_operator_owner_ledger_paths cannot be empty",
                    )
                    .into()),
                };
                if obol_node_operator_owner_ledger_paths.len() != 1 {
                    return Err(std::io::Error::other(
                        "obol_node_operator_owner_ledger_paths cannot be empty or more than 1 path",
                    )
                    .into());
                };

                let mut operator_signers = Vec::new();
                for path in obol_node_operator_owner_ledger_paths {
                    let signer = LedgerSigner::new(HDPath::Other(path.to_string()), Some(1)).await?;
                    operator_signers.push(ObolSigner::Ledger(signer));
                }
                operator_signers
            }
            _ => {
                return Err(std::io::Error::other("Unsupported obol_node_operator_owner_mode").into());
            }
        }
        None => {
            return Err(std::io::Error::other("obol_node_operator_owner_mode cannot be empty").into());
        }
    };

    if obol_node_operator_signers.len() != obol_node_operator_owner_validator_pubkeys.len() {
        return Err(std::io::Error::other("obol_node_operator_owner_signing_keys & obol_node_operator_owner_validator_pubkeys should have same array length").into());
    }

    for i in 0..obol_node_operator_signers.len() {
        let signer = obol_node_operator_signers.get(i).unwrap();
        // let obol_node_operator_owner_address = signer.address();
        let obol_node_operator_owner_address = "0xbc29BAC9815b5Ee2D161BcFC385B83D1dcf06924";
        info!(
            "Obol node operator owner address: {}",
            obol_node_operator_owner_address
        );

        let mut exchange_api_url = Url::parse(&format!(
            "{}{}",
            config_extra_exchange_api_base, "/api/v1/user/obol/operator/register"
        ))?;
        let mut res = client
            .post(exchange_api_url.to_string())
            .header("Authorization", format!("Bearer {}", access_jwt))
            .query(&[("operatorAddress", obol_node_operator_owner_address)])
            .send()
            .await?;

        // println!("{}", res.text().await?);
        let res_json_obol_node_operator_register = match res
            .json::<APIObolNodeOperatorRegisterResponse>()
            .await
        {
            Ok(result) => match result.success {
                true => {
                    if !result.data.available {
                        warn!("obol node operator owner address has been registered");
                    }
                    result
                }
                false => {
                    return Err(std::io::Error::other("failed to get the Obol node operator registration message for signing").into());
                }
            },
            Err(err) => {
                return Err(std::io::Error::other(format!("failed to call the API to get the Obol node operator registration message for signing: {}", err)).into());
            }
        };
        if res_json_obol_node_operator_register.data.available {
            let signature_hex = generate_eip712_signature_for_obol(
                &res_json_obol_node_operator_register
                    .data
                    .message_to_sign
                    .unwrap_or_default(),
                signer,
            )
            .await?;
            exchange_api_url = Url::parse(&format!(
                "{}{}",
                config_extra_exchange_api_base, "/api/v1/user/obol/operator/verify"
            ))?;
            res = client
                .post(exchange_api_url.to_string())
                .header("User-Agent", "cb_ethgas_commit")
                .header("Authorization", format!("Bearer {}", access_jwt))
                .query(&[("operatorAddress", obol_node_operator_owner_address)])
                .query(&[("signature", signature_hex)])
                .query(&[("autoImport", false)])
                .query(&[("sync", false)])
                .send()
                .await?;

            match res.json::<APIObolNodeOperatorVerifyResponse>().await {
                Ok(result) => match result.success {
                    true => {
                        info!("successfully registered obol node operator owner address");
                    }
                    false => {
                        error!(
                            "failed to register obol node operator owner address: {}",
                            result.error_msg_key.unwrap_or_default()
                        );
                    }
                },
                Err(err) => {
                    error!(?err, "failed to call obol operator verify API");
                }
            }
        }

        exchange_api_url = Url::parse(&format!(
            "{}{}",
            config_extra_exchange_api_base, "/api/v1/user/obol/operator/refresh"
        ))?;
        warn!("it may take up to 30 seconds to get the latest obol cluster info");
        res = client
            .post(exchange_api_url.to_string())
            .header("User-Agent", "cb_ethgas_commit")
            .header("Authorization", format!("Bearer {}", access_jwt))
            .query(&[("operatorAddress", obol_node_operator_owner_address)])
            .send()
            .await?;
        match res.json::<APIObolNodeOperatorRefreshResponse>().await {
            Ok(result) => match result.success {
                true => {
                    info!("successfully refresh obol cluster info");
                }
                false => {
                    error!(
                        "failed to refresh obol cluster info: {}",
                        result.error_msg_key.unwrap_or_default()
                    );
                }
            },
            Err(err) => {
                error!(?err, "failed to call obol refresh API");
            }
        }

        let pubkeys_str_list = obol_node_operator_owner_validator_pubkeys[i]
            .iter()
            .map(|key| key.to_string())
            .collect::<Vec<String>>()
            .join(",");
        if config_extra_enable_registration {
            warn!("it may take up to 30 seconds to register all Obol validator pubkeys if there are many pubkeys");
            exchange_api_url = Url::parse(&format!(
                "{}{}",
                config_extra_exchange_api_base,
                "/api/v1/user/obol/operator/validator/register"
            ))?;
            res = if obol_node_operator_owner_validator_pubkeys[i].is_empty() {
                client
                    .post(exchange_api_url.to_string())
                    .header("User-Agent", "cb_ethgas_commit")
                    .header("Authorization", format!("Bearer {}", access_jwt))
                    .query(&[("operatorAddress", obol_node_operator_owner_address)])
                    .send()
                    .await?
            } else {
                client
                    .post(exchange_api_url.to_string())
                    .header("User-Agent", "cb_ethgas_commit")
                    .header("Authorization", format!("Bearer {}", access_jwt))
                    .query(&[("operatorAddress", obol_node_operator_owner_address)])
                    .query(&[("publicKeys", pubkeys_str_list.clone())])
                    .send()
                    .await?
            };

            // println!("{}", res.text().await?);
            match res.json::<APIObolValidatorRegisterResponse>().await {
                Ok(result) => {
                    match result.success {
                        true => {
                            match result.data.added.clone() {
                                None => warn!("no pubkey was registered. those pubkeys may not be found in any obol cluster"),
                                Some(ref vec) if vec.is_empty() => warn!("no pubkey was registered. those pubkeys may not be found in any obol cluster"),
                                Some(_) => {
                                    if config_extra_enable_pricer {
                                        info!("successful registration, the default pricer can now sell preconfs on ETHGas on behalf of you");
                                    } else {
                                        info!("successful registration, you can now sell preconfs on ETHGas");
                                    }
                                    let result_data_validators = result.data.added.unwrap_or_default();
                                    info!(number = result_data_validators.len(), registered_validators = ?result_data_validators);

                                    update_ofac(
                                        &client,
                                        config_extra_registration_mode,
                                        config_extra_exchange_api_base,
                                        access_jwt,
                                        config_extra_enable_ofac,
                                        pubkeys_str_list,
                                    ).await?;
                                }
                            }
                        },
                        false => {
                            error!("failed to register obol validator pubkeys: {}", result.error_msg_key.unwrap_or_default());
                        }
                    }
                },
                Err(err) => {
                    error!(?err, "failed to call obol validator register API");
                }
            }
        } else {
            exchange_api_url = Url::parse(&format!(
                "{}{}",
                config_extra_exchange_api_base,
                "/api/v1/user/obol/operator/validator/deregister"
            ))?;
            res = if obol_node_operator_owner_validator_pubkeys[i].is_empty() {
                client
                    .post(exchange_api_url.to_string())
                    .header("User-Agent", "cb_ethgas_commit")
                    .header("Authorization", format!("Bearer {}", access_jwt))
                    .query(&[("operatorAddress", obol_node_operator_owner_address)])
                    .send()
                    .await?
            } else {
                client
                    .post(exchange_api_url.to_string())
                    .header("User-Agent", "cb_ethgas_commit")
                    .header("Authorization", format!("Bearer {}", access_jwt))
                    .query(&[("operatorAddress", obol_node_operator_owner_address)])
                    .query(&[("publicKeys", pubkeys_str_list)])
                    .send()
                    .await?
            };

            // println!("{}", res.text().await?);
            match res.json::<APIObolValidatorDeregisterResponse>().await {
                Ok(result) => match result.success {
                    true => {
                        if result.data.removed.is_empty() {
                            warn!("no pubkey was deregistered. those pubkeys maybe deregistered already previously");
                        } else {
                            info!("successful deregistration");
                            info!(number = result.data.removed.len(), deregistered_validators = ?result.data.removed);
                        }
                    }
                    false => {
                        error!(
                            "failed to deregister obol validator pubkeys: {}",
                            result.error_msg_key.unwrap_or_default()
                        );
                    }
                },
                Err(err) => {
                    error!(?err, "failed to call obol validator deregister API");
                }
            }
        }
    }

    Ok(())
}