use commit_boost::prelude::*;
use alloy::{
    primitives::B256, signers::{local::PrivateKeySigner, Signer}, sol, sol_types::{eip712_domain, SolStruct}
};
use eyre::Result;
use lazy_static::lazy_static;
use prometheus::{IntCounter, Registry};
use serde::{Deserialize, Serialize};
use tracing::{error, info};
use std::{time::Duration, error::Error};
use reqwest::Client;
use tokio::time::sleep;
use hex::encode;
// use tracing_subscriber::FmtSubscriber;

// You can define custom metrics and a custom registry for the business logic of
// your module. These will be automatically scaped by the Prometheus server
lazy_static! {
    pub static ref MY_CUSTOM_REGISTRY: prometheus::Registry =
        Registry::new_custom(Some("ethgas_commit".to_string()), None).unwrap();
    pub static ref SIG_RECEIVED_COUNTER: IntCounter =
        IntCounter::new("signature_received", "successful signatures requests received").unwrap();
}

struct EthgasExchangeService {
    exchange_api_base: String,
    chain_id: String,
    entity_name: String,
    eoa_signing_key: B256
}

struct EthgasCommitService {
    config: StartCommitModuleConfig<ExtraConfig>,
    exchange_jwt: String
}

// Extra configurations parameters can be set here and will be automatically
// parsed from the .self.config.toml file These parameters will be in the .extra
// field of the StartModuleConfig<ExtraConfig> struct you get after calling
// `load_commit_module_config::<ExtraConfig>()`
#[derive(Debug, Deserialize)]
struct ExtraConfig {
    exchange_api_base: String,
    chain_id: String,
    entity_name: String,
    is_all_pubkey: bool,
    pubkey_id: usize,
    pubkey_end_id: usize,
    is_jwt_provided: bool,
    eoa_signing_key: B256,
    exchange_jwt: String,
}

#[derive(Debug, TreeHash, Deserialize)]
struct RegisteredInfo {
    address: alloy::primitives::Address,
}

#[derive(Debug, TreeHash, Deserialize)]
struct SigningData {
    object_root: [u8; 32],
    signing_domain: [u8; 32],
}

#[derive(Debug, Deserialize)]
struct Domain {
    name: String,
    version: String,
    chainId: u64,
    verifyingContract: alloy::primitives::Address
}

#[derive(Debug, Deserialize)]
struct Message {
    hash: String,
    message: String,
    domain: String
}

sol! {
    #[allow(missing_docs)]
    #[derive(Serialize)]
    struct data {
        string hash;
        string message;
        string domain;
    }
}

#[derive(Debug, Deserialize)]
struct Eip712Message {
    message: Message,
    domain: Domain
}

#[derive(Debug, Deserialize)]
struct APILoginResponse {
    success: bool,
    data: APILoginResponseData
}

#[derive(Debug, Deserialize)]
struct APILoginResponseData {
    eip712Message: String,
}

#[derive(Debug, Deserialize)]
struct APILoginVerifyResponse {
    success: bool,
    data: APILoginVerifyResponseData
}

#[derive(Debug, Deserialize)]
struct APILoginVerifyResponseData {
    accessToken: AccessToken
}

#[derive(Debug, Deserialize)]
struct AccessToken {
    token: String
}

#[derive(Debug, Deserialize)]
struct APIValidatorRequestResponse {
    success: bool,
    data: APIValidatorRequestResponseData
}

#[derive(Debug, Deserialize)]
struct APIValidatorRequestResponseData {
    available: bool,
    message: Option<RegisteredInfo>
}

#[derive(Debug, Deserialize)]
struct APIValidatorVerifyResponse {
    success: bool,
    data: APIValidatorVerifyResponseData
}

#[derive(Debug, Deserialize)]
struct APIValidatorVerifyResponseData {
    result: usize,
    description: String
}

impl EthgasExchangeService {
    pub async fn login(self) -> Result<String> {
        let client = Client::new();
        let signer = PrivateKeySigner::from_bytes(&self.eoa_signing_key).unwrap();
        let mut exchange_api_url = format!("{}{}", self.exchange_api_base, "/api/user/login");
        let mut res = client.post(exchange_api_url.to_string())
                .query(&[("addr", signer.clone().address())])
                .query(&[("chainId", self.chain_id.clone())])
                .query(&[("name", self.entity_name.clone())])
                .send()
                .await.unwrap();
        let res_json_login = res.json::<APILoginResponse>().await.unwrap();
        info!(exchange_login_eip712_message = ?res_json_login);
        let eip712_message: Eip712Message = serde_json::from_str(&res_json_login.data.eip712Message).unwrap();
        let eip712_domain_from_api = eip712_message.domain;
        let eip712_sub_message = eip712_message.message;
        let domain = eip712_domain! {
            name: eip712_domain_from_api.name,
            version: eip712_domain_from_api.version,
            chain_id: eip712_domain_from_api.chainId,
            verifying_contract: eip712_domain_from_api.verifyingContract,
        };
        let message = data {
            hash: eip712_sub_message.hash.clone(),
            message: eip712_sub_message.message,
            domain: eip712_sub_message.domain
        };
        let hash = message.eip712_signing_hash(&domain);
        let signature = signer.clone().sign_hash(&hash).await?;
        let signature_hex = encode(signature.as_bytes());
        exchange_api_url = format!("{}{}", self.exchange_api_base, "/api/user/login/verify");
        res = client.post(exchange_api_url.to_string())
                .query(&[("addr", signer.clone().address())])
                .query(&[("nonceHash", eip712_sub_message.hash)])
                .query(&[("signature", signature_hex)])
                .send()
                .await.unwrap();
        let res_text_login_verify = res.text().await.unwrap();
        let res_json_verify: APILoginVerifyResponse = serde_json::from_str(&res_text_login_verify).unwrap();
        info!(exchange_jwt = ?res_json_verify);
        Ok(res_json_verify.data.accessToken.token)
    }
}

impl EthgasCommitService {
    pub async fn run(self) -> Result<(), Box<dyn Error>> {
        let client = Client::new();
        info!(chain = ?self.config.chain); // Debug: chain

        let pubkeys = self.config.signer_client.get_pubkeys().await.unwrap();

        let pubkey_id: usize = self.config.extra.pubkey_id;
        let mut pubkey_end_id: usize = self.config.extra.pubkey_end_id;
        if pubkey_end_id == 0 {
            pubkey_end_id = pubkeys.keys.len() - 1;
        }
        if pubkey_id >= pubkeys.keys.len() || pubkey_end_id >= pubkeys.keys.len() || pubkey_id > pubkey_end_id {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "wrong pubkey_id/pubkey_end_id")));
        }
        for i in pubkey_id..=pubkey_end_id {
            let pubkey = pubkeys.keys[i].consensus;
            info!(pubkey_id = i, ?pubkey);

            let mut exchange_api_url = format!("{}{}", self.config.extra.exchange_api_base, "/api/validator/verification/request");
            let mut res = client.post(exchange_api_url.to_string())
                .header("Authorization", format!("Bearer {}", self.exchange_jwt))
                .header("content-type", "application/json")
                .query(&[("publicKey", pubkey.to_string())])
                .send()
                .await.unwrap();
            match res.json::<APIValidatorRequestResponse>().await {
                Ok(res_json_request) => {
                    info!(exchange_signing_data = ?res_json_request);

                    match res_json_request.data.message {
                        Some(api_validator_request_response_data_message) => {
                            let info = RegisteredInfo { 
                                address: api_validator_request_response_data_message.address
                            };
                            let request = SignConsensusRequest::builder(pubkey).with_msg(&info);
                            exchange_api_url = format!("{}{}", self.config.extra.exchange_api_base, "/api/validator/verification/verify");

                            // Request the signature from the signer client
                            let signature = self.config
                                .signer_client
                                .request_consensus_signature(request)
                                .await
                                .unwrap();

                            res = client.post(exchange_api_url.to_string())
                                .header("Authorization", format!("Bearer {}", self.exchange_jwt))
                                .header("content-type", "application/json")
                                .query(&[("publicKey", pubkey.to_string())])
                                .query(&[("signature", signature.to_string())])
                                .send()
                                .await.unwrap();

                            let res_json_verify = res.json::<APIValidatorVerifyResponse>().await.unwrap();
                            info!(exchange_registration_response = ?res_json_verify);

                            if res_json_verify.data.result == 0 {
                                info!("successful registration, you can now sell preconfs on ETHGas!");
                            } else {
                                error!("fail to register");
                            }
                        },
                        None => error!("this pubkey has been registered already"),
                    }
                },
                Err(err) => {
                    error!(?err, "fail to request for signing data");
                }
            }
            if self.config.extra.is_all_pubkey == false {
                break;
            }
            sleep(Duration::from_millis(500)).await;
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    // Remember to register all your metrics before starting the process
    MY_CUSTOM_REGISTRY.register(Box::new(SIG_RECEIVED_COUNTER.clone()))?;
    // Spin up a server that exposes the /metrics endpoint to Prometheus
    MetricsProvider::load_and_run(MY_CUSTOM_REGISTRY.clone())?;

    match load_commit_module_config::<ExtraConfig>() {
        Ok(config) => {
            let _guard = initialize_tracing_log(&config.id)?;
            // let subscriber = FmtSubscriber::builder().finish();
            // tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

            info!(
                module_id = %config.id,
                "Starting module with custom data"
            );

            let exchange_jwt: String;
            if config.extra.is_jwt_provided == false {
                let exchange_service = EthgasExchangeService { 
                    exchange_api_base: config.extra.exchange_api_base.clone(),
                    chain_id: config.extra.chain_id.clone(),
                    entity_name: config.extra.entity_name.clone(),
                    eoa_signing_key: config.extra.eoa_signing_key
                };
                
                exchange_jwt = match exchange_service.login().await {
                    Ok(value) => value,
                    Err(err) => {
                        error!(?err, "Service failed");
                        return Err(err);
                    }
                };
            } else {
                exchange_jwt = config.extra.exchange_jwt.clone();
            }
            let commit_service = EthgasCommitService { config, exchange_jwt };
            if let Err(err) = commit_service.run().await {
                error!(?err);
            }
        }
        Err(err) => {
            eprintln!("Failed to load module config: {err:?}");
        }
    }
    Ok(())
}
