use commit_boost::prelude::*;
use alloy::{
    primitives::B256, signers::{local::PrivateKeySigner, Signer}, sol, sol_types::{eip712_domain, SolStruct}, hex::encode
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
use rust_decimal::Decimal;
use cookie::Cookie;
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
    access_jwt: String,
    refresh_jwt: String,
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
    overall_wait_interval_in_second: u32,
    api_wait_interval_in_ms: Option<u32>,
    enable_pricer: bool,
    registration_mode: String,
    enable_registration: bool,
    enable_builder: bool,
    collateral_per_slot: String,
    builder_pubkey: BlsPublicKey,
    is_jwt_provided: bool,
    eoa_signing_key: Option<B256>,
    access_jwt: Option<String>,
    refresh_jwt: Option<String>,
    ssv_node_operator_owner_signing_keys: Option<Vec<B256>>,
    ssv_node_operator_owner_validator_pubkeys: Option<Vec<Vec<BlsPublicKey>>>
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

#[derive(Debug, Deserialize)]
struct Eip712Message {
    message: Message,
    domain: Domain
}

#[derive(Debug, Deserialize)]
struct MessageSsv {
    userId: String,
    userAddress: String,
    verifyType: String
}

#[derive(Debug, Deserialize)]
struct Eip712MessageSsv {
    message: MessageSsv,
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
    data: APIValidatorVerifyResponseData,
    errorMsgKey: Option<String>
}

#[derive(Debug, Deserialize)]
struct APIValidatorVerifyResponseData {}

#[derive(Debug, Deserialize)]
struct APISsvNodeOperatorRegisterResponse {
    success: bool,
    data: APISsvNodeOperatorRegisterResponseData
}

#[derive(Debug, Deserialize)]
struct APISsvNodeOperatorRegisterResponseData {
    available: bool,
    messageToSign: Option<String>,
}

#[derive(Debug, Deserialize)]
struct APISsvNodeOperatorVerifyResponse {
    success: bool,
    errorMsgKey: Option<String>
}

#[derive(Debug, Deserialize)]
struct APISsvValidatorRegisterResponse  {
    success: bool,
    errorMsgKey: Option<String>,
    data: APISsvValidatorRegisterResponseData
}

#[derive(Debug, Deserialize)]
struct APISsvValidatorRegisterResponseData {
    validators: Option<Vec<BlsPublicKey>>
}

#[derive(Debug, Deserialize)]
struct APISsvValidatorDeregisterResponse  {
    success: bool,
    errorMsgKey: Option<String>,
    data: APISsvValidatorDeregisterResponseData
}

#[derive(Debug, Deserialize)]
struct APISsvValidatorDeregisterResponseData {
    removed: Vec<BlsPublicKey>
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
struct APICollateralPerSlotResponse {
    success: bool
}

async fn generate_eip712_signature(eip712_message_str: &str, signer: &PrivateKeySigner) -> Result<String> {
    sol! {
        #[allow(missing_docs)]
        #[derive(Serialize)]
        struct data {
            string hash;
            string message;
            string domain;
        }
    }

    let eip712_message: Eip712Message = serde_json::from_str(eip712_message_str)
        .map_err(|e| eyre::eyre!("Failed to parse EIP712 message: {}", e))?;
    
    let domain = eip712_domain! {
        name: eip712_message.domain.name,
        version: eip712_message.domain.version,
        chain_id: eip712_message.domain.chainId,
        verifying_contract: eip712_message.domain.verifyingContract,
    };

    let message = data {
        hash: eip712_message.message.hash.clone(),
        message: eip712_message.message.message,
        domain: eip712_message.message.domain
    };

    let hash = message.eip712_signing_hash(&domain);
    let signature = signer.sign_hash(&hash).await?;
    Ok(encode(signature.as_bytes()))
}

async fn generate_eip712_signature_for_ssv(eip712_message_str: &str, signer: &PrivateKeySigner) -> Result<String> {
    sol! {
        #[allow(missing_docs)]
        #[derive(Serialize)]
        struct data {
            string userId;
            string userAddress;
            string verifyType;
        }
    }

    let eip712_message: Eip712MessageSsv = serde_json::from_str(eip712_message_str)
        .map_err(|e| eyre::eyre!("Failed to parse EIP712 message: {}", e))?;
    
    let domain = eip712_domain! {
        name: eip712_message.domain.name,
        version: eip712_message.domain.version,
        chain_id: eip712_message.domain.chainId,
        verifying_contract: eip712_message.domain.verifyingContract,
    };

    let message = data {
        userId: eip712_message.message.userId,
        userAddress: eip712_message.message.userAddress,
        verifyType: eip712_message.message.verifyType
    };

    let hash = message.eip712_signing_hash(&domain);
    let signature = signer.sign_hash(&hash).await?;
    Ok(encode(signature.as_bytes()))
}

impl EthgasExchangeService {
    pub async fn login(self) -> Result<(String, String)> {
        let client = Client::new();
        let signer = PrivateKeySigner::from_bytes(&self.eoa_signing_key)
            .map_err(|e| eyre::eyre!("Failed to create signer: {}", e))?;
        info!("your EOA address: {}", signer.clone().address());
        let mut exchange_api_url = Url::parse(&format!("{}{}", self.exchange_api_base, "/api/v1/user/login"))?;
        let mut res = client.post(exchange_api_url.to_string())
                .query(&[("addr", signer.clone().address())])
                .query(&[("chainId", self.chain_id.clone())])
                .query(&[("name", self.entity_name.clone())])
                .send()
                .await?;
                
        let res_json_login = res.json::<APILoginResponse>().await?;
        
        let eip712_message: Eip712Message = serde_json::from_str(&res_json_login.data.eip712Message)
            .map_err(|e| eyre::eyre!("Failed to parse EIP712 message: {}", e))?;
        let signature_hex = generate_eip712_signature(&res_json_login.data.eip712Message, &signer).await?;
        exchange_api_url = Url::parse(&format!("{}{}", self.exchange_api_base, "/api/v1/user/login/verify"))?;
        res = client.post(exchange_api_url.to_string())
                .header("User-Agent", "cb_ethgas_commit")
                .query(&[("addr", signer.clone().address())])
                .query(&[("nonceHash", eip712_message.message.hash)])
                .query(&[("signature", signature_hex)])
                .send()
                .await?;
        let refresh_jwt: String;
        if let Some(set_cookie) = res.headers().get("Set-Cookie") {
            let cookie_str = set_cookie.to_str().expect("cannot parse cookie");
            let cookie = Cookie::parse(cookie_str)?;
            info!("successfully obtained refresh jwt from the exchange");
            refresh_jwt = cookie.value().to_string();
        } else {
            return Err(std::io::Error::new(std::io::ErrorKind::Other,
                "Set-Cookie header not found").into());
        }
        let res_text_login_verify = res.text().await?;
        let res_json_verify: APILoginVerifyResponse = serde_json::from_str(&res_text_login_verify)
            .expect("Failed to parse login verification response");
        info!("successfully obtained access jwt from the exchange");
        Ok((res_json_verify.data.accessToken.token, refresh_jwt))
        // println!("API Response as JSON: {}", res.json::<Value>().await?);
        // Ok(String::from("test"))
    }
}

impl EthgasCommitService {
    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        let client = Client::new();

        let mut exchange_api_url = Url::parse(&format!("{}{}{}", self.config.extra.exchange_api_base, "/api/v1/user/delegate/pricer?enable=", self.config.extra.enable_pricer))?;
        let mut res = client.post(exchange_api_url.to_string())
                .header("Authorization", format!("Bearer {}", self.access_jwt))
                .header("content-type", "application/json")
                .send()
                .await?;
        match res.json::<APIEnablePricerResponse>().await {
            Ok(result) => {
                match result.success {
                    true => {
                        if self.config.extra.enable_pricer == true {
                            info!("successfully enabled pricer");
                        } else {
                            info!("successfully disabled pricer");
                        }
                    },
                    false => {
                        if self.config.extra.enable_pricer == true {
                            error!("failed to enable pricer");
                        } else {
                            error!("failed to disable pricer");
                        }
                    }
                }
            },
            Err(err) => {
                error!(?err, "failed to call pricer API");
            }
        }

        exchange_api_url = Url::parse(&format!("{}{}{}{}{}", self.config.extra.exchange_api_base, "/api/v1/user/delegate/builder?enable=", self.config.extra.enable_builder, "&publicKeys=", self.config.extra.builder_pubkey))?;
        res = client.post(exchange_api_url.to_string())
                .header("Authorization", format!("Bearer {}", self.access_jwt))
                .header("content-type", "application/json")
                .send()
                .await?;
        match res.json::<APIEnableBuilderResponse>().await {
            Ok(result) => {
                match result.success {
                    true => {
                        if self.config.extra.enable_builder == true {
                            info!("successfully delegated to builder {}", self.config.extra.builder_pubkey);
                        } else {
                            info!("successfully disabled builder delegation");
                        }
                    },
                    false => {
                        if self.config.extra.enable_builder == true {
                            error!("failed to enable builder delegation");
                        } else {
                            error!("failed to disable builder delegation");
                        }
                    }
                }
            },
            Err(err) => {
                error!(?err, "failed to call builder delegation API");
            }
        }

        let mut access_jwt = self.access_jwt.clone();

        exchange_api_url = Url::parse(&format!("{}{}{}", self.config.extra.exchange_api_base, "/api/v1/user/collateralPerSlot?collateralPerSlot=", self.config.extra.collateral_per_slot))?;
        res = client.post(exchange_api_url.to_string())
                .header("Authorization", format!("Bearer {}", access_jwt))
                .header("content-type", "application/json")
                .send()
                .await?;
        match res.json::<APICollateralPerSlotResponse>().await {
            Ok(result) => {
                match result.success {
                    true => {
                        info!("successfully set collateral per slot to {} ETH", self.config.extra.collateral_per_slot);
                    },
                    false => {
                        error!("failed to set collateral per slot");
                    }
                }
            },
            Err(err) => {
                error!(?err, "failed to call validator collateral setting API");
            }
        }

        if self.config.extra.registration_mode == "ssv" {
            let ssv_node_operator_owner_signing_keys = match &self.config.extra.ssv_node_operator_owner_signing_keys {
                Some(signing_keys) => signing_keys.clone(),
                None => match env::var("SSV_NODE_OPERATOR_OWNER_SIGNING_KEYS") {
                    Ok(signing_keys_str) => {
                        signing_keys_str.split(',')
                            .filter(|s| !s.trim().is_empty())
                            .map(|key| B256::from_str(key.trim()).map_err(|_| {
                                std::io::Error::new(std::io::ErrorKind::InvalidData, 
                                    format!("Invalid signing key format"))
                            }))
                            .collect::<Result<Vec<B256>, _>>()?
                    },
                    Err(_) => {
                        return Err(std::io::Error::new(std::io::ErrorKind::Other,
                            "ssv_node_operator_owner_signing_keys cannot be empty").into());
                    }
                }
            };
            if ssv_node_operator_owner_signing_keys.is_empty() {
                return Err(std::io::Error::new(std::io::ErrorKind::Other,
                    "ssv_node_operator_owner_signing_keys cannot be empty").into());
            };
            let ssv_node_operator_owner_validator_pubkeys = match &self.config.extra.ssv_node_operator_owner_validator_pubkeys {
                Some(validator_pubkeys) => validator_pubkeys.clone(),
                None => return Err(std::io::Error::new(std::io::ErrorKind::Other,
                    "ssv_node_operator_owner_validator_pubkeys cannot be empty").into())
            };
            if ssv_node_operator_owner_signing_keys.len() != ssv_node_operator_owner_validator_pubkeys.len() {
                return Err(std::io::Error::new(std::io::ErrorKind::Other,
                    "ssv_node_operator_owner_signing_keys & ssv_node_operator_owner_validator_pubkeys should have same array length").into());
            }

            for i in 0..ssv_node_operator_owner_signing_keys.len() {
                let signer = PrivateKeySigner::from_bytes(&ssv_node_operator_owner_signing_keys[i])
                    .map_err(|e| eyre::eyre!("Failed to create signer: {}", e))?;
                let ssv_node_operator_owner_address = signer.clone().address();
                info!("SSV node operator owner address: {}", ssv_node_operator_owner_address);

                exchange_api_url = Url::parse(&format!("{}{}", self.config.extra.exchange_api_base, "/api/v1/user/ssv/operator/register"))?;
                res = client.post(exchange_api_url.to_string())
                    .header("Authorization", format!("Bearer {}", access_jwt))
                    .query(&[("ownerAddress", ssv_node_operator_owner_address)]) 
                    .send()
                    .await?;

                let res_json_ssv_node_operator_register = match res.json::<APISsvNodeOperatorRegisterResponse>().await {
                    Ok(result) => {
                        match result.success {
                            true => {
                                if result.data.available == false {
                                    warn!("ssv node operator owner address has been registered");
                                }
                                result
                            },
                            false => {
                                return Err(std::io::Error::new(std::io::ErrorKind::Other,
                                    "failed to get the SSV node operator registration message for signing").into());
                            }
                        }
                    },
                    Err(err) => {
                        return Err(std::io::Error::new(std::io::ErrorKind::Other,
                            format!("failed to call the API to get the SSV node operator registration message for signing: {}", err)).into());
                    }
                };
                if res_json_ssv_node_operator_register.data.available {
                    let signature_hex = generate_eip712_signature_for_ssv(&res_json_ssv_node_operator_register.data.messageToSign.unwrap_or_default(), &signer).await?;
                    exchange_api_url = Url::parse(&format!("{}{}", self.config.extra.exchange_api_base, "/api/v1/user/ssv/operator/verify"))?;
                    res = client.post(exchange_api_url.to_string())
                            .header("User-Agent", "cb_ethgas_commit")
                            .header("Authorization", format!("Bearer {}", access_jwt))
                            .query(&[("ownerAddress", ssv_node_operator_owner_address)])
                            .query(&[("signature", signature_hex)])
                            .query(&[("autoImport", false)])
                            .query(&[("sync", false)])
                            .send()
                            .await?;

                    match res.json::<APISsvNodeOperatorVerifyResponse>().await {
                        Ok(result) => {
                            match result.success {
                                true => {
                                    info!("successfully registered ssv node operator owner address");
                                },
                                false => {
                                    error!("failed to register ssv node operator owner address: {}", result.errorMsgKey.unwrap_or_default());
                                }
                            }
                        },
                        Err(err) => {
                            error!(?err, "failed to call ssv operator verify API");
                        }
                    }
                }

                let pubkeys_str_list = ssv_node_operator_owner_validator_pubkeys[i].iter()
                        .map(|key| key.to_string())
                        .collect::<Vec<String>>()
                        .join(",");
                if self.config.extra.enable_registration {
                    warn!("it may take up to 30 seconds to register all SSV validator pubkeys if there are many pubkeys");
                    exchange_api_url = Url::parse(&format!("{}{}", self.config.extra.exchange_api_base, "/api/v1/user/ssv/operator/validator/register"))?;
                    res = if ssv_node_operator_owner_validator_pubkeys[i].is_empty() {
                        client.post(exchange_api_url.to_string())
                            .header("User-Agent", "cb_ethgas_commit")
                            .header("Authorization", format!("Bearer {}", access_jwt))
                            .query(&[("ownerAddress", ssv_node_operator_owner_address)])
                            .send()
                            .await?
                    } else {
                        client.post(exchange_api_url.to_string())
                            .header("User-Agent", "cb_ethgas_commit")
                            .header("Authorization", format!("Bearer {}", access_jwt))
                            .query(&[("ownerAddress", ssv_node_operator_owner_address)])
                            .query(&[("publicKeys", pubkeys_str_list)])
                            .send()
                            .await?
                    };

                    match res.json::<APISsvValidatorRegisterResponse>().await {
                        Ok(result) => {
                            match result.success {
                                true => {
                                    match result.data.validators.clone() {
                                        None => warn!("no pubkey was registered. those pubkeys may not be found in any ssv cluster"),
                                        Some(ref vec) if vec.is_empty() => warn!("no pubkey was registered. those pubkeys may not be found in any ssv cluster"),
                                        Some(vec) => {
                                            if self.config.extra.enable_pricer {
                                                info!("successful registration, the default pricer can now sell preconfs on ETHGas on behalf of you!");
                                            } else {
                                                info!("successful registration, you can now sell preconfs on ETHGas!");
                                            }
                                            let result_data_validators = result.data.validators.unwrap_or_default();
                                            info!(number = result_data_validators.len(), registered_validators = ?result_data_validators);
                                        }
                                    }
                                },
                                false => {
                                    error!("failed to register ssv validator pubkeys: {}", result.errorMsgKey.unwrap_or_default());
                                }
                            }
                        },
                        Err(err) => {
                            error!(?err, "failed to call ssv validator register API");
                        }
                    }
                } else {
                    exchange_api_url = Url::parse(&format!("{}{}", self.config.extra.exchange_api_base, "/api/v1/user/ssv/operator/validator/deregister"))?;
                    res = if ssv_node_operator_owner_validator_pubkeys[i].is_empty() {
                        client.post(exchange_api_url.to_string())
                            .header("User-Agent", "cb_ethgas_commit")
                            .header("Authorization", format!("Bearer {}", access_jwt))
                            .query(&[("ownerAddress", ssv_node_operator_owner_address)])
                            .send()
                            .await?
                    } else {
                        client.post(exchange_api_url.to_string())
                            .header("User-Agent", "cb_ethgas_commit")
                            .header("Authorization", format!("Bearer {}", access_jwt))
                            .query(&[("ownerAddress", ssv_node_operator_owner_address)])
                            .query(&[("publicKeys", pubkeys_str_list)])
                            .send()
                            .await?
                    };

                    match res.json::<APISsvValidatorDeregisterResponse>().await {
                        Ok(result) => {
                            match result.success {
                                true => {
                                    if result.data.removed.is_empty() {
                                        warn!("no pubkey was deregistered. those pubkeys maybe deregistered already previously");
                                    } else {
                                        info!("successful deregistration!");
                                        info!(number = result.data.removed.len(), deregistered_validators = ?result.data.removed);
                                    }
                                },
                                false => {
                                    error!("failed to deregister ssv validator pubkeys: {}", result.errorMsgKey.unwrap_or_default());
                                }
                            }
                        },
                        Err(err) => {
                            error!(?err, "failed to call ssv validator deregister API");
                        }
                    }

                }
                
            }

        } else if self.config.extra.registration_mode == "standard" || self.config.extra.registration_mode == "standard-mux" {

            let pubkeys = if !self.mux_pubkeys.is_empty() && self.config.extra.registration_mode == "standard-mux" {
                self.mux_pubkeys.clone()
            } else if self.mux_pubkeys.is_empty() && self.config.extra.registration_mode == "standard" {
                let client_pubkeys_response = self.config.signer_client.get_pubkeys().await?;
                let mut client_pubkeys = Vec::new();
                for proxy_map in client_pubkeys_response.keys {
                    client_pubkeys.push(proxy_map.consensus);
                }
                client_pubkeys
            } else {
                warn!("ensure to specify list of pubkeys under mux config for standard-mux flag or comment out the mux config for standard flag");
                Vec::new()
            };

            let api_wait_interval_in_ms = match self.config.extra.api_wait_interval_in_ms {
                Some(wait_interval) => wait_interval,
                None => 0
            };
            for i in 0..pubkeys.len() {
                let pubkey = pubkeys[i];
                info!(pubkey_counter = i, ?pubkey);
                if i % 10000 == 0 && i != 0 {
                    exchange_api_url = Url::parse(&format!("{}{}{}", self.config.extra.exchange_api_base, "/api/v1/user/login/refresh?refreshToken=", self.refresh_jwt))?;
                    res = client.post(exchange_api_url.to_string())
                        .header("User-Agent", "cb_ethgas_commit")
                        .header("Authorization", format!("Bearer {}", access_jwt))
                        .header("content-type", "application/json")
                        .send()
                        .await?;
                    match res.json::<APILoginVerifyResponse>().await {
                        Ok(res_json) => {
                            if res_json.success {
                                info!("successfully refreshed access jwt!");
                                access_jwt = res_json.data.accessToken.token;
                            } else {
                                error!("failed to refresh access jwt");
                            }
                        },
                        Err(err) => {
                            error!(?err, "failed to call jwt refresh API");
                        }
                    }
                }
                if self.config.extra.enable_registration {
                    exchange_api_url = Url::parse(&format!("{}{}", self.config.extra.exchange_api_base, "/api/v1/validator/register"))?;
                    res = client.post(exchange_api_url.to_string())
                        .header("Authorization", format!("Bearer {}", access_jwt))
                        .header("content-type", "application/json")
                        .query(&[("publicKey", pubkey.to_string())])
                        .send()
                        .await?;
                    match res.json::<APIValidatorRegisterResponse>().await {
                        Ok(res_json) => {
                            match res_json.data.message {
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
                                        .header("Authorization", format!("Bearer {}", access_jwt))
                                        .header("content-type", "application/json")
                                        .query(&[("publicKey", pubkey.to_string())])
                                        .query(&[("signature", signature.to_string())])
                                        .send()
                                        .await?;

                                    match res.json::<APIValidatorVerifyResponse>().await {
                                        Ok(res_json_verify) => {
                                            if res_json_verify.success {
                                                if self.config.extra.enable_pricer {
                                                    info!("successful registration, the default pricer can now sell preconfs on ETHGas on behalf of you!");
                                                } else {
                                                    info!("successful registration, you can now sell preconfs on ETHGas!");
                                                }
                                            } else {
                                                let err_msg = res_json_verify.errorMsgKey.unwrap_or_default();
                                                if err_msg == "error.validator.registered" {
                                                    warn!("this pubkey has been registered already");
                                                } else {
                                                    error!("failed to register: {err_msg}");
                                                }
                                            }
                                            
                                        },
                                        Err(e) => error!("Failed to parse validator verification response: {}", e)
                                    }
                                },
                                None => warn!("this pubkey has been registered already"),
                            }
                        },
                        Err(err) => {
                            error!(?err, "failed to call validator register API");
                        }
                    }
                } else {
                    exchange_api_url = Url::parse(&format!("{}{}", self.config.extra.exchange_api_base, "/api/v1/validator/deregister"))?;
                    res = client.post(exchange_api_url.to_string())
                        .header("Authorization", format!("Bearer {}", access_jwt))
                        .header("content-type", "application/json")
                        .query(&[("publicKeys", pubkey.to_string())])
                        .send()
                        .await?;
                    match res.json::<APIValidatorDeregisterResponse>().await {
                        Ok(res_json) => {
                            if res_json.success {
                                info!("successful deregistration!");
                            } else {
                                error!("failed to deregister");
                            }
                        },
                        Err(err) => {
                            error!(?err, "failed to call validator deregister API");
                        }
                    }
                }
                sleep(Duration::from_millis(api_wait_interval_in_ms.into())).await;
            }
        } else if self.config.extra.registration_mode == "skipped" {
            info!("skipped registration or deregistration");
        } else {
            error!("invalid registration mode");
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    // Remember to register all your metrics before starting the process
    MY_CUSTOM_REGISTRY.register(Box::new(SIG_RECEIVED_COUNTER.clone()))?;

    let _guard = initialize_tracing_log("ETHGAS_COMMIT", LogsSettings::from_env_config()?);

    let mut overall_wait_interval_in_second: u32 = 0;
    let mut counter: u32 = 0;

    loop {
        match load_commit_module_config::<ExtraConfig>() {
            Ok(config) => {
                if counter == 0 {
                    // Spin up a server that exposes the /metrics endpoint to Prometheus
                    MetricsProvider::load_and_run(config.chain, MY_CUSTOM_REGISTRY.clone())?;
                }

                overall_wait_interval_in_second = config.extra.overall_wait_interval_in_second;

                info!(
                    module_id = %config.id,
                    "Starting module with custom data"
                );
                info!("chain: {:?}", config.chain);

                let pbs_config = match load_pbs_config().await {
                    Ok(config) => config,
                    Err(err) => {
                        error!("Failed to load pbs config: {err:?}");
                        return Err(std::io::Error::new(std::io::ErrorKind::Other, "Failed to load pbs config").into());
                    }
                };

                let collateral_per_slot: Decimal = Decimal::from_str(&config.extra.collateral_per_slot)?;
                if collateral_per_slot != Decimal::new(0, 0) && (collateral_per_slot > Decimal::new(1000, 0) || collateral_per_slot < Decimal::new(1, 2) || collateral_per_slot.scale() > 2) {
                    error!("collateral_per_slot must be 0 or between 0.01 to 1000 ETH inclusive & no more than 2 decimal place");
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, "invalid collateral_per_slot").into());
                }

                let access_jwt: String;
                let refresh_jwt: String;
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
                    (access_jwt, refresh_jwt) = Retry::spawn(FixedInterval::from_millis(500).take(5), || async { 
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
                    access_jwt = match config.extra.access_jwt.clone() {
                        Some(jwt) => jwt,
                        None => {
                            match env::var("ACCESS_JWT") {
                                Ok(jwt) => jwt,
                                Err(_) => {
                                    error!("Config access_jwt is required. Please set ACCESS_JWT environment variable or provide it in the config file");
                                    return Err(std::io::Error::new(std::io::ErrorKind::Other,
                                    "access_jwt missing").into());
                                }
                            }
                        }
                    };
                    refresh_jwt = match config.extra.refresh_jwt.clone() {
                        Some(jwt) => jwt,
                        None => {
                            match env::var("REFRESH_JWT") {
                                Ok(jwt) => jwt,
                                Err(_) => {
                                    error!("Config refresh_jwt is required. Please set REFRESH_JWT environment variable or provide it in the config file");
                                    return Err(std::io::Error::new(std::io::ErrorKind::Other,
                                    "refresh_jwt missing").into());
                                }
                            }
                        }
                    };
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

                if !access_jwt.is_empty() && !refresh_jwt.is_empty() {
                    let mut commit_service = EthgasCommitService { config, access_jwt, refresh_jwt, mux_pubkeys };
                    if let Err(err) = commit_service.run().await {
                        error!(?err);
                    }
                } else { 
                    return Err(std::io::Error::new(std::io::ErrorKind::Other,
                        "access_jwt or refresh_jwt missing").into());
                }


            }
            Err(err) => {
                error!("Failed to load module config: {:?}", err);
                return Err(err);
            }
        }
        if overall_wait_interval_in_second == 0 {
            break;
        }
        info!("waiting for {} seconds to start again...", overall_wait_interval_in_second);
        sleep(Duration::from_millis((overall_wait_interval_in_second as u64) * 1000)).await;
        counter += 1;
    }
    Ok(())
}
