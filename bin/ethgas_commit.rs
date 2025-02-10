use commit_boost::prelude::*;
use alloy::{
    primitives::B256, signers::{local::PrivateKeySigner, Signer}, sol, sol_types::{eip712_domain, SolStruct}
};
use eyre::Result;
use lazy_static::lazy_static;
use prometheus::{IntCounter, Registry};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};
use std::{
    time::Duration, error::Error, env, str::FromStr
};
use reqwest::Client;
use tokio::time::sleep;
use hex::encode;
// use tracing_subscriber::FmtSubscriber;

// You can define custom metrics and a custom registry for the business logic of
// your module. These will be automatically scaped by the Prometheus server
lazy_static! {
    pub static ref MY_CUSTOM_REGISTRY: prometheus::Registry =
        Registry::new_custom(Some("ethgas_commit".to_string()), None)
            .expect("Failed to create metrics registry");
    pub static ref SIG_RECEIVED_COUNTER: IntCounter =
        IntCounter::new("signature_received", "successful signatures requests received")
            .expect("Failed to create signature counter");
}

struct EthgasExchangeService {
    exchange_api_base: String,
    chain_id: String,
    entity_name: String,
    eoa_signing_key: B256,
}

struct EthgasCommitService {
    config: StartCommitModuleConfig<ExtraConfig>,
    exchange_jwt: String,
    mux_pubkeys: Vec<BlsPublicKey>
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
    enable_pricer: bool,
    is_jwt_provided: bool,
    eoa_signing_key: Option<B256>,
    exchange_jwt: Option<String>,
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

#[derive(Debug, Deserialize)]
struct APIEnablePricerResponse {
    success: bool
}

impl EthgasExchangeService {
    pub async fn login(self) -> Result<String> {
        let client = Client::new();
        let signer = PrivateKeySigner::from_bytes(&self.eoa_signing_key)
            .expect("Failed to create signer from private key");
        let mut exchange_api_url = format!("{}{}", self.exchange_api_base, "/api/user/login");
        let mut res = client.post(exchange_api_url.to_string())
                .query(&[("addr", signer.clone().address())])
                .query(&[("chainId", self.chain_id.clone())])
                .query(&[("name", self.entity_name.clone())])
                .send()
                .await?;
        let res_json_login = res.json::<APILoginResponse>().await?;
        info!(exchange_login_eip712_message = ?res_json_login);
        let eip712_message: Eip712Message = serde_json::from_str(&res_json_login.data.eip712Message)
            .expect("Failed to parse EIP712 message");
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
                .await?;
        let res_text_login_verify = res.text().await?;
        let res_json_verify: APILoginVerifyResponse = serde_json::from_str(&res_text_login_verify)
            .expect("Failed to parse login verification response");
        info!(exchange_jwt = ?res_json_verify);
        Ok(res_json_verify.data.accessToken.token)
    }
}

impl EthgasCommitService {
    pub async fn run(self) -> Result<(), Box<dyn Error>> {
        let client = Client::new();
        info!(chain = ?self.config.chain); // Debug: chain

        let mut exchange_api_url = format!("{}{}{}", self.config.extra.exchange_api_base, "/api/user/pricer?enable=", self.config.extra.enable_pricer);
        let mut res = client.post(exchange_api_url.to_string())
                .header("Authorization", format!("Bearer {}", self.exchange_jwt))
                .header("content-type", "application/json")
                .send()
                .await?;
        match res.json::<APIEnablePricerResponse>().await {
            Ok(result) => {
                match result.success {
                    true => {
                        if self.config.extra.enable_pricer == true {
                            info!("successfully enable pricer");
                        } else {
                            info!("successfully disable pricer");
                        }
                    },
                    false => {
                        if self.config.extra.enable_pricer == true {
                            error!("fail to enable pricer");
                        } else {
                            error!("fail to disable pricer");
                        }
                    }
                }
            },
            Err(err) => {
                error!(?err, "fail to call pricer API");
            }
        }

        let pubkeys = self.config.signer_client.get_pubkeys().await?;

        for i in 0..pubkeys.keys.len() {
            let pubkey = pubkeys.keys[i].consensus;
            info!(pubkey_id = i, ?pubkey);

            if !self.mux_pubkeys.contains(&pubkey) {
                info!("this pubkey is skipped for registration");
                continue;
            }

            exchange_api_url = format!("{}{}", self.config.extra.exchange_api_base, "/api/validator/verification/request");
            res = client.post(exchange_api_url.to_string())
                .header("Authorization", format!("Bearer {}", self.exchange_jwt))
                .header("content-type", "application/json")
                .query(&[("publicKey", pubkey.to_string())])
                .send()
                .await?;
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
                                .await?;

                            res = client.post(exchange_api_url.to_string())
                                .header("Authorization", format!("Bearer {}", self.exchange_jwt))
                                .header("content-type", "application/json")
                                .query(&[("publicKey", pubkey.to_string())])
                                .query(&[("signature", signature.to_string())])
                                .send()
                                .await?;

                            let res_json_verify = res.json::<APIValidatorVerifyResponse>()
                                .await
                                .expect("Failed to parse validator verification response");
                            info!(exchange_registration_response = ?res_json_verify);

                            if res_json_verify.data.result == 0 {
                                if self.config.extra.enable_pricer == true {
                                    info!("successful registration, the default pricer can now sell preconfs on ETHGas on behalf of you!");
                                } else {
                                    info!("successful registration, you can now sell preconfs on ETHGas!");
                                }
                            } else {
                                error!("fail to register");
                            }
                        },
                        None => warn!("this pubkey has been registered already"),
                    }
                },
                Err(err) => {
                    error!(?err, "fail to request for signing data");
                }
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

            let pbs_config = match load_pbs_config() {
                Ok(config) => config,
                Err(err) => {
                    error!("Failed to load pbs config: {err:?}");
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, "Failed to load pbs config").into());
                }
            };

            let mux_pubkeys = match pbs_config.muxes {
                Some(mux_map) => {
                    let mut vec = Vec::new();
                    for (key, value) in mux_map.iter() {
                        for relay in value.relays.iter() {
                            if relay.id.contains("ethgas") {
                                vec.push(BlsPublicKey::from(*key));
                                break;
                            }
                        }
                    }
                    vec
                },
                None => Vec::new()
            };
            info!("mux_pubkeys: {:?}", mux_pubkeys);

            let exchange_jwt: String;
            if config.extra.is_jwt_provided == false {
                let exchange_service = EthgasExchangeService {
                    exchange_api_base: config.extra.exchange_api_base.clone(),
                    chain_id: config.extra.chain_id.clone(),
                    entity_name: config.extra.entity_name.clone(),
                    eoa_signing_key: match config.extra.eoa_signing_key.clone() {
                        Some(eoa) => eoa,
                        None => {
                            match env::var("EOA_SIGNING_KEY") {
                                Ok(eoa) => {
                                    match B256::from_str(&eoa) {
                                        Ok(key) => key,
                                        Err(_) => {
                                            error!("EOA_SIGNING_KEY environment variable is not a valid 32-byte hex string");
                                            return Err(std::io::Error::new(std::io::ErrorKind::Other, "Invalid EOA_SIGNING_KEY").into());
                                        }
                                    }
                                },
                                Err(_) => {
                                    error!("Config eoa_signing_key is required. Please set EOA_SIGNING_KEY environment variable or provide it in the config file");
                                    return Err(std::io::Error::new(std::io::ErrorKind::Other,
                                    "eoa_signing_key missing").into());
                                }
                            }
                        }
                    }
                };
                exchange_jwt = match exchange_service.login().await {
                    Ok(value) => value,
                    Err(err) => {
                        error!(?err, "Service failed");
                        return Err(err);
                    }
                };
            } else {
                exchange_jwt = match config.extra.exchange_jwt.clone() {
                    Some(jwt) => jwt,
                    None => {
                        match env::var("EXCHANGE_JWT") {
                            Ok(jwt) => jwt,
                            Err(_) => {
                                error!("Config exchange_jwt is required. Please set EXCHANGE_JWT environment variable or provide it in the config file");
                                return Err(std::io::Error::new(std::io::ErrorKind::Other,
                                "exchange_jwt missing").into());
                            }
                        }
                    }
                };
            }
            if !exchange_jwt.is_empty() {
                let commit_service = EthgasCommitService { config, exchange_jwt, mux_pubkeys };
                if let Err(err) = commit_service.run().await {
                    error!(?err);
                }
            } else { error!("JWT invalid") }


        }
        Err(err) => {
            eprintln!("Failed to load module config: {err:?}");
        }
    }
    Ok(())
}
