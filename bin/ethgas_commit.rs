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
use reqwest::{Client, Url};
use tokio::time::sleep;
use tokio_retry::{Retry, strategy::FixedInterval};
use hex::encode;
use rust_decimal::Decimal;
// use tracing_subscriber::FmtSubscriber;
// use serde_json::Value;

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
    chain_id: Option<String>, // not required, only for backward compatibility 
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
    chain_id: Option<String>, // not required, only for backward compatibility 
    entity_name: String,
    wait_interval_in_second: u32,
    enable_pricer: bool,
    enable_registration: bool,
    enable_builder: bool,
    collateral_per_slot: String,
    builder_pubkey: BlsPublicKey,
    is_jwt_provided: bool,
    eoa_signing_key: Option<B256>,
    exchange_jwt: Option<String>,
}

#[derive(Debug, TreeHash, Deserialize)]
struct RegisteredInfo {
    eoaAddress: alloy::primitives::Address,
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
struct APIValidatorRegisterResponse {
    success: bool,
    data: APIValidatorRegisterResponseData
}

#[derive(Debug, Deserialize)]
struct APIValidatorRegisterResponseData {
    available: bool,
    verified: bool,
    message: Option<RegisteredInfo>
}

#[derive(Debug, Deserialize)]
struct APIValidatorDeregisterResponse {
    success: bool,
    data: APIValidatorDeregisterResponseData
}

#[derive(Debug, Deserialize)]
struct APIValidatorDeregisterResponseData {
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

#[derive(Debug, Deserialize)]
struct APIEnableBuilderResponse {
    success: bool
}

#[derive(Debug, Deserialize)]
struct APIValidatorSettingsResponse {
    success: bool
}

impl EthgasExchangeService {
    pub async fn login(self) -> Result<String> {
        let client = Client::new();
        let signer = PrivateKeySigner::from_bytes(&self.eoa_signing_key)
            .map_err(|e| eyre::eyre!("Failed to create signer: {}", e))?;
        
        let mut exchange_api_url = Url::parse(&format!("{}{}", self.exchange_api_base, "/api/v1/user/login"))?;
        let mut res = client.post(exchange_api_url.to_string())
                .query(&[("addr", signer.clone().address())])
                .query(&[("chainId", self.chain_id.clone())])
                .query(&[("name", self.entity_name.clone())])
                .send()
                .await?;
                
        let res_json_login = res.json::<APILoginResponse>().await?;
        info!(exchange_login_eip712_message = ?res_json_login);
        
        let eip712_message: Eip712Message = serde_json::from_str(&res_json_login.data.eip712Message)
            .map_err(|e| eyre::eyre!("Failed to parse EIP712 message: {}", e))?;
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
        exchange_api_url = Url::parse(&format!("{}{}", self.exchange_api_base, "/api/v1/user/login/verify"))?;
        res = client.post(exchange_api_url.to_string())
                .header("User-Agent", "cb_ethgas_commit")
                .query(&[("addr", signer.clone().address())])
                .query(&[("nonceHash", eip712_sub_message.hash)])
                .query(&[("signature", signature_hex)])
                .send()
                .await?;
        let res_text_login_verify = res.text().await?;
        let res_json_verify: APILoginVerifyResponse = serde_json::from_str(&res_text_login_verify)
            .expect("Failed to parse login verification response");
        info!("successfully obtain JWT from the exchange");
        Ok(res_json_verify.data.accessToken.token)
        // println!("API Response as JSON: {}", res.json::<Value>().await?);
        // Ok(String::from("test"))
    }
}

impl EthgasCommitService {
    pub async fn run(self) -> Result<(), Box<dyn Error>> {
        let client = Client::new();
        info!(chain = ?self.config.chain); // Debug: chain

        let mut exchange_api_url = Url::parse(&format!("{}{}{}", self.config.extra.exchange_api_base, "/api/v1/user/delegate/pricer?enable=", self.config.extra.enable_pricer))?;
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

        exchange_api_url = Url::parse(&format!("{}{}{}{}{}", self.config.extra.exchange_api_base, "/api/v1/user/delegate/builder?enable=", self.config.extra.enable_builder, "&publicKey=", self.config.extra.builder_pubkey))?;
        res = client.post(exchange_api_url.to_string())
                .header("Authorization", format!("Bearer {}", self.exchange_jwt))
                .header("content-type", "application/json")
                .send()
                .await?;
        match res.json::<APIEnableBuilderResponse>().await {
            Ok(result) => {
                match result.success {
                    true => {
                        if self.config.extra.enable_builder == true {
                            info!("successfully delegate to builder {}", self.config.extra.builder_pubkey);
                        } else {
                            info!("successfully disable builder delegation");
                        }
                    },
                    false => {
                        if self.config.extra.enable_builder == true {
                            error!("fail to enable builder delegation");
                        } else {
                            error!("fail to disable builder delegation");
                        }
                    }
                }
            },
            Err(err) => {
                error!(?err, "fail to call builder delegation API");
            }
        }

        exchange_api_url = Url::parse(&format!("{}{}{}", self.config.extra.exchange_api_base, "/api/v1/validator/settings?collateralPerSlot=", self.config.extra.collateral_per_slot))?;
        res = client.post(exchange_api_url.to_string())
                .header("Authorization", format!("Bearer {}", self.exchange_jwt))
                .header("content-type", "application/json")
                .send()
                .await?;
        match res.json::<APIValidatorSettingsResponse>().await {
            Ok(result) => {
                match result.success {
                    true => {
                        info!("successfully set collateral per slot to {} ETH", self.config.extra.collateral_per_slot);
                    },
                    false => {
                        error!("fail to set collateral per slot");
                    }
                }
            },
            Err(err) => {
                error!(?err, "fail to call validator collateral setting API");
            }
        }

        let pubkeys = if !self.mux_pubkeys.is_empty() {
            self.mux_pubkeys
        } else {
            let client_pubkeys_response = self.config.signer_client.get_pubkeys().await?;
            let mut client_pubkeys = Vec::new();
            for proxy_map in client_pubkeys_response.keys {
                client_pubkeys.push(proxy_map.consensus);
            }
            client_pubkeys
        };

        for i in 0..pubkeys.len() {
            let pubkey = pubkeys[i];
            info!(pubkey_counter = i, ?pubkey);

            if !self.config.extra.enable_registration == false {
                exchange_api_url = Url::parse(&format!("{}{}", self.config.extra.exchange_api_base, "/api/v1/validator/register"))?;
                res = client.post(exchange_api_url.to_string())
                    .header("Authorization", format!("Bearer {}", self.exchange_jwt))
                    .header("content-type", "application/json")
                    .query(&[("publicKey", pubkey.to_string())])
                    .send()
                    .await?;
                match res.json::<APIValidatorRegisterResponse>().await {
                    Ok(res_json_request) => {
                        info!(exchange_signing_data = ?res_json_request);

                        match res_json_request.data.message {
                            Some(api_validator_request_response_data_message) => {
                                let info = RegisteredInfo {
                                    eoaAddress: api_validator_request_response_data_message.eoaAddress
                                };
                                let request = SignConsensusRequest::builder(pubkey).with_msg(&info);
                                exchange_api_url = Url::parse(&format!("{}{}", self.config.extra.exchange_api_base, "/api/v1/validator/verify"))?;

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

                                // println!("API Response as JSON: {}", res.json::<Value>().await?);
                                match res.json::<APIValidatorVerifyResponse>().await {
                                    Ok(res_json_verify) => {
                                        info!(exchange_registration_response = ?res_json_verify);
                                        
                                        if res_json_verify.data.result == 0 {
                                            if self.config.extra.enable_pricer {
                                                info!("successful registration, the default pricer can now sell preconfs on ETHGas on behalf of you!");
                                            } else {
                                                info!("successful registration, you can now sell preconfs on ETHGas!");
                                            }
                                        } else {
                                            error!("fail to register");
                                        }
                                    },
                                    Err(e) => error!("Failed to parse validator verification response: {}", e)
                                }
                            },
                            None => warn!("this pubkey has been registered already"),
                        }
                    },
                    Err(err) => {
                        error!(?err, "fail to request for signing data");
                    }
                }
            } else {
                exchange_api_url = Url::parse(&format!("{}{}", self.config.extra.exchange_api_base, "/api/v1/validator/deregister"))?;
                res = client.post(exchange_api_url.to_string())
                    .header("Authorization", format!("Bearer {}", self.exchange_jwt))
                    .header("content-type", "application/json")
                    .query(&[("publicKey", pubkey.to_string())])
                    .send()
                    .await?;
                match res.json::<APIValidatorDeregisterResponse>().await {
                    Ok(res_json_request) => {
                        info!(exchange_signing_data = ?res_json_request);
                        if res_json_request.success {
                            info!("successful de-registration!");
                        } else {
                            info!("fail to de-register");
                        }
                    },
                    Err(err) => {
                        error!(?err, "fail to request for signing data");
                    }
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

    let _guard = initialize_tracing_log("ETHGAS_COMMIT")?;
    // let subscriber = FmtSubscriber::builder().finish();
    // tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let mut wait_interval_in_second: u32 = 0;

    loop {
        match load_commit_module_config::<ExtraConfig>() {
            Ok(config) => {
                wait_interval_in_second = config.extra.wait_interval_in_second;

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

                let collateral_per_slot: Decimal = Decimal::from_str(&config.extra.collateral_per_slot)?;
                if collateral_per_slot < Decimal::new(1, 1) || collateral_per_slot.scale() > 1 {
                    error!("collateral_per_slot must be >= 0.1 ETH & no more than 1 decimal place");
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, "collateral_per_slot must be >= 0.1 ETH & no more than 1 decimal place").into());
                }

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
                                        B256::from_str(&eoa).map_err(|_| {
                                            error!("Invalid EOA_SIGNING_KEY format"); 
                                            std::io::Error::new(std::io::ErrorKind::InvalidData, "EOA_SIGNING_KEY format error")
                                        })?
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
                    exchange_jwt = Retry::spawn(FixedInterval::from_millis(500).take(5), || async { 
                        let service = EthgasExchangeService {
                            exchange_api_base: exchange_service.exchange_api_base.clone(),
                            chain_id: exchange_service.chain_id.clone(),
                            entity_name: exchange_service.entity_name.clone(),
                            eoa_signing_key: exchange_service.eoa_signing_key.clone(),
                        };
                        service.login().await.map_err(|err| {
                            error!(?err, "Service failed");
                            err
                        })
                    }).await?;
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
                error!("Failed to load module config: {:?}", err);
                return Err(err);
            }
        }
        if wait_interval_in_second == 0 {
            break;
        }
        info!("waiting for {} seconds to start again...", wait_interval_in_second);
        sleep(Duration::from_millis((wait_interval_in_second as u64) * 1000)).await;
    }
    Ok(())
}
