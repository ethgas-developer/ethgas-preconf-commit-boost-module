use alloy::{
    hex::encode,
    primitives::{FixedBytes, Signature, B256},
    signers::{
        ledger::{HDPath, LedgerSigner},
        local::PrivateKeySigner,
        Error as SignerError, Signer,
    },
    sol,
    sol_types::{eip712_domain, Eip712Domain, SolStruct},
};
use commit_boost::prelude::*;
use cookie::Cookie;
use ethgas_commit::{
    models::KeystoreConfig,
    obol_registry::register_obol_keys,
    ofac::update_ofac,
    query_pubkey::{
        get_registered_all_pubkeys, get_registered_obol_pubkeys, get_registered_ssv_pubkeys,
    },
};
use eyre::Result;
use lazy_static::lazy_static;
use prometheus::{IntCounter, Registry};
use reqwest::{Client, Response, Url};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, env, error::Error, str::FromStr, time::Duration};
use tokio::time::sleep;
use tokio_retry::{strategy::FixedInterval, Retry};
use tracing::{error, info, warn};

// You can define custom metrics and a custom registry for the business logic of
// your module. These will be automatically scaped by the Prometheus server
lazy_static! {
    pub static ref MY_CUSTOM_REGISTRY: prometheus::Registry =
        Registry::new_custom(Some("ethgas_commit".to_string()), None)
            .expect("Failed to create metrics registry");
    pub static ref SIG_RECEIVED_COUNTER: IntCounter = IntCounter::new(
        "signature_received",
        "successful signatures requests received"
    )
    .expect("Failed to create signature counter");
}

struct EthgasExchangeService {
    exchange_api_base: String,
    entity_name: String,
    eoa_signing_key: B256,
}

struct EthgasCommitService {
    config: StartCommitModuleConfig<ExtraConfig>,
    access_jwt: String,
    refresh_jwt: String,
    mux_pubkeys: Vec<BlsPublicKey>,
}

// Extra configurations parameters can be set here and will be automatically
// parsed from the .self.config.toml file These parameters will be in the .extra
// field of the StartModuleConfig<ExtraConfig> struct you get after calling
// `load_commit_module_config::<ExtraConfig>()`
#[derive(Debug, Deserialize)]
struct ExtraConfig {
    exchange_api_base: String,
    entity_name: String,
    overall_wait_interval_in_second: u32,
    enable_pricer: bool,
    registration_mode: String,
    enable_registration: bool,
    enable_builder: bool,
    enable_ofac: bool,
    collateral_per_slot: String,
    builder_pubkey: BlsPublicKey,
    is_jwt_provided: bool,
    query_pubkey: bool,
    eoa_signing_key: Option<B256>,
    access_jwt: Option<String>,
    refresh_jwt: Option<String>,
    ssv_node_operator_owner_mode: Option<String>,
    ssv_node_operator_owner_signing_keys: Option<Vec<B256>>,
    ssv_node_operator_owner_keystores: Option<Vec<KeystoreConfig>>,
    ssv_node_operator_owner_ledger_paths: Option<Vec<String>>,
    ssv_node_operator_owner_validator_pubkeys: Option<Vec<Vec<BlsPublicKey>>>,
    obol_node_operator_owner_mode: Option<String>,
    obol_node_operator_owner_signing_keys: Option<Vec<B256>>,
    obol_node_operator_owner_keystores: Option<Vec<KeystoreConfig>>,
    obol_node_operator_owner_ledger_paths: Option<Vec<String>>,
    obol_node_operator_owner_validator_pubkeys: Option<Vec<Vec<BlsPublicKey>>>,
}

#[derive(Debug, TreeHash, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisteredInfo {
    eoa_address: alloy::primitives::Address,
}

#[derive(Debug, TreeHash, Deserialize)]
struct SigningData {
    object_root: [u8; 32],
    signing_domain: [u8; 32],
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
struct Message {
    hash: String,
    message: String,
    domain: String,
}

#[derive(Debug, Deserialize)]
struct Eip712Message {
    message: Message,
    domain: Domain,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MessageSsv {
    user_id: String,
    user_address: String,
    verify_type: String,
}

#[derive(Debug, Deserialize)]
struct Eip712MessageSsv {
    message: MessageSsv,
    domain: Domain,
}

#[derive(Debug, Deserialize)]
struct APILoginResponse {
    success: bool,
    data: APILoginResponseData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct APILoginResponseData {
    eip712_message: String,
}

#[derive(Debug, Deserialize)]
struct APILoginVerifyResponse {
    success: bool,
    data: APILoginVerifyResponseData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct APILoginVerifyResponseData {
    access_token: AccessToken,
}

#[derive(Debug, Deserialize)]
struct APIUserUpdateResponse {
    success: bool,
    data: APIUserUpdateResponseData,
}

#[derive(Debug, Deserialize)]
struct APIUserUpdateResponseData {
    user: APIUserUpdateResponseDataUser,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct APIUserUpdateResponseDataUser {
    display_name: String,
}

#[derive(Debug, Deserialize)]
struct AccessToken {
    token: String,
}

#[derive(Debug, Deserialize)]
struct APIValidatorRegisterResponse {
    success: bool,
    data: APIValidatorRegisterResponseData,
}

#[derive(Debug, Deserialize)]
struct APIValidatorRegisterResponseData {
    message: Option<RegisteredInfo>,
}

#[derive(Debug, Deserialize)]
struct APIValidatorDeregisterResponse {
    success: bool,
    data: APIValidatorDeregisterResponseData,
}

#[derive(Debug, Deserialize)]
struct APIValidatorDeregisterResponseData {
    deleted: Vec<BlsPublicKey>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct APIValidatorVerifyBatchResponse {
    success: bool,
    data: HashMap<BlsPublicKey, ValidatorVerifyResult>,
    error_msg_key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ValidatorVerifyResult {
    result: u8,
    description: String,
}

#[derive(Debug, Deserialize)]
struct APISsvNodeOperatorRegisterResponse {
    success: bool,
    data: APISsvNodeOperatorRegisterResponseData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct APISsvNodeOperatorRegisterResponseData {
    available: bool,
    message_to_sign: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct APISsvNodeOperatorVerifyResponse {
    success: bool,
    error_msg_key: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct APISsvValidatorRegisterResponse {
    success: bool,
    error_msg_key: Option<String>,
    data: APISsvValidatorRegisterResponseData,
}

#[derive(Debug, Deserialize)]
struct APISsvValidatorRegisterResponseData {
    validators: Option<Vec<BlsPublicKey>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct APISsvValidatorDeregisterResponse {
    success: bool,
    error_msg_key: Option<String>,
    data: APISsvValidatorDeregisterResponseData,
}

#[derive(Debug, Deserialize)]
struct APISsvValidatorDeregisterResponseData {
    removed: Vec<BlsPublicKey>,
}

#[derive(Debug, Deserialize)]
struct APIEnablePricerResponse {
    success: bool,
}

#[derive(Debug, Deserialize)]
struct APIEnableBuilderResponse {
    success: bool,
}

#[derive(Debug, Deserialize)]
struct APICollateralPerSlotResponse {
    success: bool,
}

async fn generate_eip712_signature(
    eip712_message_str: &str,
    signer: &PrivateKeySigner,
) -> Result<String> {
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
        chain_id: eip712_message.domain.chain_id,
        verifying_contract: eip712_message.domain.verifying_contract,
    };

    let message = data {
        hash: eip712_message.message.hash.clone(),
        message: eip712_message.message.message,
        domain: eip712_message.message.domain,
    };

    let hash = message.eip712_signing_hash(&domain);
    let signature = signer.sign_hash(&hash).await?;
    Ok(encode(signature.as_bytes()))
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
enum SSVSigner {
    PrivateKey(PrivateKeySigner),
    Ledger(LedgerSigner),
}

impl SSVSigner {
    pub fn address(&self) -> alloy::primitives::Address {
        match self {
            SSVSigner::Ledger(signer) => signer.address(),
            SSVSigner::PrivateKey(signer) => signer.address(),
        }
    }

    pub async fn sign_typed_data(
        &self,
        message: &data,
        domain: &Eip712Domain,
    ) -> Result<Signature, SignerError> {
        match self {
            SSVSigner::Ledger(signer) => signer.sign_typed_data(message, domain).await,
            SSVSigner::PrivateKey(signer) => signer.sign_typed_data(message, domain).await,
        }
    }
}

async fn generate_eip712_signature_for_ssv(
    eip712_message_str: &str,
    signer: &SSVSigner,
) -> Result<String> {
    let eip712_message: Eip712MessageSsv = serde_json::from_str(eip712_message_str)
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

    // let hash = message.eip712_signing_hash(&domain);
    // let signature = signer.sign_hash(&hash).await?;
    let signature = signer.sign_typed_data(&message, &domain).await?;
    Ok(encode(signature.as_bytes()))
}

impl EthgasExchangeService {
    pub async fn login(self) -> Result<(String, String)> {
        let client = Client::new();
        let signer = PrivateKeySigner::from_bytes(&self.eoa_signing_key)
            .map_err(|e| eyre::eyre!("Failed to create signer: {}", e))?;
        info!("your EOA address: {}", signer.clone().address());
        let mut exchange_api_url = Url::parse(&format!(
            "{}{}",
            self.exchange_api_base, "/api/v1/user/login"
        ))?;
        let mut res = client
            .post(exchange_api_url.to_string())
            .query(&[("addr", signer.clone().address())])
            .send()
            .await?;

        let res_json_login = res.json::<APILoginResponse>().await?;

        let eip712_message: Eip712Message =
            serde_json::from_str(&res_json_login.data.eip712_message)
                .map_err(|e| eyre::eyre!("Failed to parse EIP712 message: {}", e))?;
        let signature_hex =
            generate_eip712_signature(&res_json_login.data.eip712_message, &signer).await?;
        exchange_api_url = Url::parse(&format!(
            "{}{}",
            self.exchange_api_base, "/api/v1/user/login/verify"
        ))?;
        res = client
            .post(exchange_api_url.to_string())
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
            return Err(std::io::Error::other("Set-Cookie header not found").into());
        }
        let res_text_login_verify = res.text().await?;
        let res_json_verify: APILoginVerifyResponse = serde_json::from_str(&res_text_login_verify)
            .expect("Failed to parse login verification response");
        info!("successfully obtained access jwt from the exchange");
        exchange_api_url = Url::parse(&format!(
            "{}{}",
            self.exchange_api_base, "/api/v1/user/update"
        ))?;
        res = client
            .post(exchange_api_url.to_string())
            .header(
                "Authorization",
                format!("Bearer {}", res_json_verify.data.access_token.token),
            )
            .query(&[("displayName", self.entity_name.clone())])
            .send()
            .await?;
        match res.json::<APIUserUpdateResponse>().await {
            Ok(res_json) => {
                if res_json.data.user.display_name != self.entity_name.clone() {
                    warn!("failed to set the user name")
                }
            }
            Err(e) => warn!("failed to set the user name: {e}"),
        }
        Ok((res_json_verify.data.access_token.token, refresh_jwt))
        // println!("API status: {}", res.status());
        // println!("API Response as raw data: {}", res.text().await?);
        // Ok((String::from("test"), String::from("test")))
    }
}

impl EthgasCommitService {
    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        let client = Client::new();

        let mut exchange_api_url = Url::parse(&format!(
            "{}{}{}",
            self.config.extra.exchange_api_base,
            "/api/v1/user/delegate/pricer?enable=",
            self.config.extra.enable_pricer
        ))?;
        let mut res = client
            .post(exchange_api_url.to_string())
            .header("Authorization", format!("Bearer {}", self.access_jwt))
            .header("content-type", "application/json")
            .send()
            .await?;
        match res.json::<APIEnablePricerResponse>().await {
            Ok(result) => match result.success {
                true => {
                    if self.config.extra.enable_pricer {
                        info!("successfully enabled pricer");
                    } else {
                        info!("successfully disabled pricer");
                    }
                }
                false => {
                    if self.config.extra.enable_pricer {
                        error!("failed to enable pricer");
                    } else {
                        error!("failed to disable pricer");
                    }
                }
            },
            Err(err) => {
                error!(?err, "failed to call pricer API");
            }
        }

        exchange_api_url = Url::parse(&format!(
            "{}{}{}{}{}",
            self.config.extra.exchange_api_base,
            "/api/v1/user/delegate/builder?enable=",
            self.config.extra.enable_builder,
            "&publicKeys=",
            self.config.extra.builder_pubkey
        ))?;
        res = client
            .post(exchange_api_url.to_string())
            .header("Authorization", format!("Bearer {}", self.access_jwt))
            .header("content-type", "application/json")
            .send()
            .await?;
        match res.json::<APIEnableBuilderResponse>().await {
            Ok(result) => match result.success {
                true => {
                    if self.config.extra.enable_builder {
                        info!(
                            "successfully delegated to builder {}",
                            self.config.extra.builder_pubkey
                        );
                    } else {
                        info!("successfully disabled builder delegation");
                    }
                }
                false => {
                    if self.config.extra.enable_builder {
                        error!("failed to enable builder delegation");
                    } else {
                        error!("failed to disable builder delegation");
                    }
                }
            },
            Err(err) => {
                error!(?err, "failed to call builder delegation API");
            }
        }

        let mut access_jwt = self.access_jwt.clone();

        exchange_api_url = Url::parse(&format!(
            "{}{}{}",
            self.config.extra.exchange_api_base,
            "/api/v1/user/collateralPerSlot?collateralPerSlot=",
            self.config.extra.collateral_per_slot
        ))?;
        res = client
            .post(exchange_api_url.to_string())
            .header("Authorization", format!("Bearer {}", access_jwt))
            .header("content-type", "application/json")
            .send()
            .await?;
        match res.json::<APICollateralPerSlotResponse>().await {
            Ok(result) => match result.success {
                true => {
                    info!(
                        "successfully set collateral per slot to {} ETH",
                        self.config.extra.collateral_per_slot
                    );
                }
                false => {
                    error!("failed to set collateral per slot");
                }
            },
            Err(err) => {
                error!(?err, "failed to call validator collateral setting API");
            }
        }

        if self.config.extra.registration_mode == "ssv" {
            let ssv_node_operator_owner_validator_pubkeys =
                match &self.config.extra.ssv_node_operator_owner_validator_pubkeys {
                    Some(validator_pubkeys) => validator_pubkeys.clone(),
                    None => {
                        return Err(std::io::Error::other(
                            "ssv_node_operator_owner_validator_pubkeys cannot be empty",
                        )
                        .into())
                    }
                };
            let ssv_node_operator_signers: Vec<SSVSigner> = match &self
                .config
                .extra
                .ssv_node_operator_owner_mode
            {
                Some(mode) => match mode.as_str() {
                    "key" => {
                        let ssv_node_operator_owner_signing_keys =
                            match &self.config.extra.ssv_node_operator_owner_signing_keys {
                                Some(signing_keys) => signing_keys.clone(),
                                None => match env::var("SSV_NODE_OPERATOR_OWNER_SIGNING_KEYS") {
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
                                            "ssv_node_operator_owner_signing_keys cannot be empty",
                                        )
                                        .into());
                                    }
                                },
                            };
                        if ssv_node_operator_owner_signing_keys.is_empty() {
                            return Err(std::io::Error::other(
                                "ssv_node_operator_owner_signing_keys cannot be empty",
                            )
                            .into());
                        };

                        let mut operator_signers = Vec::new();
                        for key_byte in ssv_node_operator_owner_signing_keys {
                            let signer = PrivateKeySigner::from_bytes(&key_byte)
                                .map_err(|e| eyre::eyre!("Failed to create signer: {}", e))?;
                            operator_signers.push(SSVSigner::PrivateKey(signer));
                        }
                        operator_signers
                    }
                    "keystore" => {
                        let operator_signers: Vec<SSVSigner> = match &self
                            .config
                            .extra
                            .ssv_node_operator_owner_keystores
                        {
                            Some(keystores) => {
                                let mut operator_signers = Vec::new();
                                for keystore in keystores {
                                    let password =
                                        std::fs::read_to_string(&keystore.password_path)?;
                                    let private_key = eth_keystore::decrypt_key(
                                        &keystore.keystore_path,
                                        password.trim(),
                                    )
                                    .map_err(|e| eyre::eyre!("Failed to read keystore: {}", e))?;
                                    let signer = PrivateKeySigner::from_slice(&private_key)
                                        .map_err(|e| {
                                            eyre::eyre!("Failed to create signer: {}", e)
                                        })?;
                                    operator_signers.push(SSVSigner::PrivateKey(signer));
                                }
                                operator_signers
                            }
                            None => {
                                let keystore_paths = env::var("SSV_NODE_OPERATOR_OWNER_KEYSTORES");
                                let password_paths = env::var("SSV_NODE_OPERATOR_OWNER_PASSOWRDS");

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
                                            return Err(std::io::Error::other("SSV_NODE_OPERATOR_OWNER_KEYSTORES & SSV_NODE_OPERATOR_OWNER_PASSWORDS should have the same array length").into());
                                        }

                                        let mut operator_signers = Vec::new();
                                        for (keystore_path, password_path) in
                                            keystore_paths.iter().zip(password_paths.iter())
                                        {
                                            let password = std::fs::read_to_string(password_path)?;
                                            let signer = PrivateKeySigner::decrypt_keystore(
                                                keystore_path,
                                                password.trim(),
                                            )
                                            .map_err(|e| {
                                                eyre::eyre!("Failed to create signer: {}", e)
                                            })?;
                                            operator_signers.push(SSVSigner::PrivateKey(signer));
                                        }
                                        operator_signers
                                    }
                                    _ => {
                                        return Err(std::io::Error::other(
                                            "ssv_node_operator_owner_keystores cannot be empty",
                                        )
                                        .into());
                                    }
                                }
                            }
                        };
                        operator_signers
                    }
                    "ledger" => {
                        let ssv_node_operator_owner_ledger_paths =
                            match &self.config.extra.ssv_node_operator_owner_ledger_paths {
                                Some(paths) => paths.clone(),
                                None => {
                                    return Err(std::io::Error::other(
                                        "ssv_node_operator_owner_ledger_paths cannot be empty",
                                    )
                                    .into())
                                }
                            };
                        if ssv_node_operator_owner_ledger_paths.len() != 1 {
                            return Err(std::io::Error::other(
                                "ssv_node_operator_owner_ledger_paths cannot be empty or more than 1 path",
                            )
                            .into());
                        };

                        let mut operator_signers = Vec::new();
                        for path in ssv_node_operator_owner_ledger_paths {
                            let signer =
                                LedgerSigner::new(HDPath::Other(path.to_string()), Some(1)).await?;
                            operator_signers.push(SSVSigner::Ledger(signer));
                        }
                        operator_signers
                    }
                    _ => {
                        return Err(std::io::Error::other(
                            "Unsupported ssv_node_operator_owner_mode",
                        )
                        .into());
                    }
                },
                None => {
                    return Err(std::io::Error::other(
                        "ssv_node_operator_owner_mode cannot be empty",
                    )
                    .into());
                }
            };

            if ssv_node_operator_signers.len() != ssv_node_operator_owner_validator_pubkeys.len() {
                return Err(std::io::Error::other("ssv_node_operator_owner_signing_keys & ssv_node_operator_owner_validator_pubkeys should have same array length").into());
            }

            for i in 0..ssv_node_operator_signers.len() {
                let signer = &ssv_node_operator_signers[i];
                let ssv_node_operator_owner_address = signer.address();
                info!(
                    "SSV node operator owner address: {}",
                    ssv_node_operator_owner_address
                );

                exchange_api_url = Url::parse(&format!(
                    "{}{}",
                    self.config.extra.exchange_api_base, "/api/v1/user/ssv/operator/register"
                ))?;
                res = client
                    .post(exchange_api_url.to_string())
                    .header("Authorization", format!("Bearer {}", access_jwt))
                    .query(&[("ownerAddress", ssv_node_operator_owner_address)])
                    .send()
                    .await?;

                let res_json_ssv_node_operator_register = match res
                    .json::<APISsvNodeOperatorRegisterResponse>()
                    .await
                {
                    Ok(result) => match result.success {
                        true => {
                            if !result.data.available {
                                warn!("ssv node operator owner address has been registered");
                            }
                            result
                        }
                        false => {
                            return Err(std::io::Error::other("failed to get the SSV node operator registration message for signing").into());
                        }
                    },
                    Err(err) => {
                        return Err(std::io::Error::other(format!("failed to call the API to get the SSV node operator registration message for signing: {}", err)).into());
                    }
                };
                if res_json_ssv_node_operator_register.data.available {
                    let signature_hex = generate_eip712_signature_for_ssv(
                        &res_json_ssv_node_operator_register
                            .data
                            .message_to_sign
                            .unwrap_or_default(),
                        signer,
                    )
                    .await?;
                    exchange_api_url = Url::parse(&format!(
                        "{}{}",
                        self.config.extra.exchange_api_base, "/api/v1/user/ssv/operator/verify"
                    ))?;
                    res = client
                        .post(exchange_api_url.to_string())
                        .header("User-Agent", "cb_ethgas_commit")
                        .header("Authorization", format!("Bearer {}", access_jwt))
                        .query(&[("ownerAddress", ssv_node_operator_owner_address)])
                        .query(&[("signature", signature_hex)])
                        .query(&[("autoImport", false)])
                        .query(&[("sync", false)])
                        .send()
                        .await?;

                    match res.json::<APISsvNodeOperatorVerifyResponse>().await {
                        Ok(result) => match result.success {
                            true => {
                                info!("successfully registered ssv node operator owner address");
                            }
                            false => {
                                error!(
                                    "failed to register ssv node operator owner address: {}",
                                    result.error_msg_key.unwrap_or_default()
                                );
                            }
                        },
                        Err(err) => {
                            error!(?err, "failed to call ssv operator verify API");
                        }
                    }
                }

                if self.config.extra.enable_registration {
                    warn!("it may take up to 30 seconds to register all SSV validator pubkeys if there are many pubkeys");
                    exchange_api_url = Url::parse(&format!(
                        "{}{}",
                        self.config.extra.exchange_api_base,
                        "/api/v1/user/ssv/operator/validator/register"
                    ))?;
                    if ssv_node_operator_owner_validator_pubkeys[i].is_empty() {
                        res = client
                            .post(exchange_api_url.to_string())
                            .header("User-Agent", "cb_ethgas_commit")
                            .header("Authorization", format!("Bearer {}", access_jwt))
                            .query(&[("ownerAddress", ssv_node_operator_owner_address)])
                            .send()
                            .await?;

                        let pubkeys_str_list = ssv_node_operator_owner_validator_pubkeys[i]
                            .iter()
                            .map(|key| key.to_string())
                            .collect::<Vec<String>>()
                            .join(",");

                        self.ssv_validator_register_response(
                            res,
                            &client,
                            &access_jwt,
                            pubkeys_str_list,
                        )
                        .await?;
                    } else {
                        for pubkey_chunk in ssv_node_operator_owner_validator_pubkeys[i].chunks(35)
                        {
                            let pubkeys_chunk_list = pubkey_chunk
                                .iter()
                                .map(|key| key.to_string())
                                .collect::<Vec<String>>()
                                .join(",");

                            res = client
                                .post(exchange_api_url.to_string())
                                .header("User-Agent", "cb_ethgas_commit")
                                .header("Authorization", format!("Bearer {}", access_jwt))
                                .query(&[("ownerAddress", ssv_node_operator_owner_address)])
                                .query(&[("publicKeys", pubkeys_chunk_list.clone())])
                                .send()
                                .await?;

                            self.ssv_validator_register_response(
                                res,
                                &client,
                                &access_jwt,
                                pubkeys_chunk_list,
                            )
                            .await?;
                        }
                    };
                } else {
                    exchange_api_url = Url::parse(&format!(
                        "{}{}",
                        self.config.extra.exchange_api_base,
                        "/api/v1/user/ssv/operator/validator/deregister"
                    ))?;
                    if ssv_node_operator_owner_validator_pubkeys[i].is_empty() {
                        res = client
                            .post(exchange_api_url.to_string())
                            .header("User-Agent", "cb_ethgas_commit")
                            .header("Authorization", format!("Bearer {}", access_jwt))
                            .query(&[("ownerAddress", ssv_node_operator_owner_address)])
                            .send()
                            .await?;

                        self.ssv_validator_deregister_response(res).await?;
                    } else {
                        for pubkey_chunk in ssv_node_operator_owner_validator_pubkeys[i].chunks(35)
                        {
                            let pubkeys_chunk_list = pubkey_chunk
                                .iter()
                                .map(|key| key.to_string())
                                .collect::<Vec<String>>()
                                .join(",");

                            res = client
                                .post(exchange_api_url.to_string())
                                .header("User-Agent", "cb_ethgas_commit")
                                .header("Authorization", format!("Bearer {}", access_jwt))
                                .query(&[("ownerAddress", ssv_node_operator_owner_address)])
                                .query(&[("publicKeys", pubkeys_chunk_list)])
                                .send()
                                .await?;

                            self.ssv_validator_deregister_response(res).await?;
                        }
                    };
                }
            }
        } else if self.config.extra.registration_mode == "obol" {
            register_obol_keys(
                &client,
                &access_jwt,
                &self.config.extra.exchange_api_base,
                self.config.extra.enable_registration,
                &self.config.extra.registration_mode,
                self.config.extra.enable_pricer,
                self.config.extra.enable_ofac,
                &self.config.extra.obol_node_operator_owner_mode,
                &self.config.extra.obol_node_operator_owner_signing_keys,
                &self.config.extra.obol_node_operator_owner_keystores,
                &self.config.extra.obol_node_operator_owner_ledger_paths,
                &self.config.extra.obol_node_operator_owner_validator_pubkeys,
            )
            .await?;
        } else if self.config.extra.registration_mode == "standard"
            || self.config.extra.registration_mode == "standard-mux"
        {
            let pubkeys = if !self.mux_pubkeys.is_empty()
                && self.config.extra.registration_mode == "standard-mux"
            {
                self.mux_pubkeys.clone()
            } else if self.mux_pubkeys.is_empty()
                && self.config.extra.registration_mode == "standard"
            {
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

            exchange_api_url = Url::parse(&format!(
                "{}{}",
                self.config.extra.exchange_api_base, "/api/v1/validator/register"
            ))?;
            res = client
                .post(exchange_api_url.to_string())
                .header("Authorization", format!("Bearer {}", access_jwt))
                .header("content-type", "application/json")
                .query(&[("publicKey", FixedBytes::<48>::from([0u8; 48]))])
                .send()
                .await?;
            match res.json::<APIValidatorRegisterResponse>().await {
                Ok(res_json) => {
                    match res_json.data.message {
                        Some(api_validator_request_response_data_message) => {
                            let mut signatures = Vec::new();
                            if self.config.extra.enable_registration {
                                if !pubkeys.is_empty() {
                                    info!("generating signatures for pubkeys...");
                                }
                                for pubkey in &pubkeys {
                                    let info = RegisteredInfo {
                                        eoa_address: api_validator_request_response_data_message
                                            .eoa_address,
                                    };
                                    let request = SignConsensusRequest::builder(pubkey.clone())
                                        .with_msg(&info);
                                    // Request the signature from the signer client
                                    let signature = self
                                        .config
                                        .signer_client
                                        .request_consensus_signature(request)
                                        .await?;

                                    signatures.push(signature.to_string());
                                }

                                let mut newly_registered_key_num = 0;
                                for (counter, (pubkey_chunk, sig_chunk)) in
                                    pubkeys.chunks(100).zip(signatures.chunks(100)).enumerate()
                                {
                                    if counter % 1000 == 0 && counter != 0 {
                                        exchange_api_url = Url::parse(&format!(
                                            "{}{}{}",
                                            self.config.extra.exchange_api_base,
                                            "/api/v1/user/login/refresh?refreshToken=",
                                            self.refresh_jwt
                                        ))?;
                                        res = client
                                            .post(exchange_api_url.to_string())
                                            .header("User-Agent", "cb_ethgas_commit")
                                            .header(
                                                "Authorization",
                                                format!("Bearer {}", access_jwt),
                                            )
                                            .header("content-type", "application/json")
                                            .send()
                                            .await?;
                                        match res.json::<APILoginVerifyResponse>().await {
                                            Ok(res_json) => {
                                                if res_json.success {
                                                    info!("successfully refreshed access jwt");
                                                    access_jwt = res_json.data.access_token.token;
                                                } else {
                                                    error!("failed to refresh access jwt");
                                                }
                                            }
                                            Err(err) => {
                                                error!(?err, "failed to call jwt refresh API");
                                            }
                                        }
                                    }

                                    let pubkeys_str = pubkey_chunk
                                        .iter()
                                        .map(|key| key.to_string())
                                        .collect::<Vec<String>>()
                                        .join(",");

                                    let signatures_str = sig_chunk
                                        .iter()
                                        .map(|sig| sig.to_string())
                                        .collect::<Vec<String>>()
                                        .join(",");

                                    let mut form_data = HashMap::new();
                                    form_data.insert("publicKeys", pubkeys_str.clone());
                                    form_data.insert("signatures", signatures_str);
                                    exchange_api_url = Url::parse(&format!(
                                        "{}{}",
                                        self.config.extra.exchange_api_base,
                                        "/api/v1/validator/verify/batch"
                                    ))?;
                                    res = client
                                        .post(exchange_api_url.to_string())
                                        .header("Authorization", format!("Bearer {}", access_jwt))
                                        .header("content-type", "application/x-www-form-urlencoded")
                                        .form(&form_data)
                                        .send()
                                        .await?;

                                    match res.json::<APIValidatorVerifyBatchResponse>().await {
                                        Ok(res_json_verify) => {
                                            let registered_keys: Vec<BlsPublicKey> =
                                                res_json_verify
                                                    .data
                                                    .iter()
                                                    .filter_map(|(key, verify_result)| {
                                                        if verify_result.result == 0 {
                                                            Some(key.to_owned())
                                                        } else {
                                                            None
                                                        }
                                                    })
                                                    .collect();
                                            let previously_registered_keys: Vec<BlsPublicKey> =
                                                res_json_verify
                                                    .data
                                                    .iter()
                                                    .filter_map(|(key, verify_result)| {
                                                        if verify_result.result == 3 {
                                                            Some(key.to_owned())
                                                        } else {
                                                            None
                                                        }
                                                    })
                                                    .collect();
                                            let keys_with_invalid_signature: Vec<BlsPublicKey> =
                                                res_json_verify
                                                    .data
                                                    .iter()
                                                    .filter_map(|(key, verify_result)| {
                                                        if verify_result.result == 2 {
                                                            Some(key.to_owned())
                                                        } else {
                                                            None
                                                        }
                                                    })
                                                    .collect();
                                            if res_json_verify.success {
                                                if !registered_keys.is_empty() {
                                                    if self.config.extra.enable_pricer {
                                                        info!("successful registration, the default pricer can now sell preconfs on ETHGas on behalf of you");
                                                    } else {
                                                        info!("successful registration, you can now sell preconfs on ETHGas");
                                                    }
                                                    info!(number = registered_keys.len(), registered_validators = ?registered_keys);
                                                    newly_registered_key_num +=
                                                        registered_keys.len();
                                                }
                                                if !previously_registered_keys.is_empty() {
                                                    warn!(number = previously_registered_keys.len(), previously_registered_validators = ?previously_registered_keys);
                                                }
                                                if !keys_with_invalid_signature.is_empty() {
                                                    error!(number = keys_with_invalid_signature.len(), invalid_signature = ?keys_with_invalid_signature);
                                                }

                                                update_ofac(
                                                    &client,
                                                    &self.config.extra.registration_mode,
                                                    &self.config.extra.exchange_api_base,
                                                    &access_jwt,
                                                    self.config.extra.enable_ofac,
                                                    pubkeys_str,
                                                )
                                                .await?;
                                            } else {
                                                let err_msg = res_json_verify
                                                    .error_msg_key
                                                    .unwrap_or_default();
                                                error!("failed to register: {err_msg}");
                                            }
                                        }
                                        Err(e) => error!(
                                            "Failed to parse validator verification response: {}",
                                            e
                                        ),
                                    }
                                }
                                info!(?newly_registered_key_num);
                            } else {
                                let mut deregistered_key_num = 0;
                                for pubkey_chunk in pubkeys.chunks(100) {
                                    let pubkeys_str = pubkey_chunk
                                        .iter()
                                        .map(|key| key.to_string())
                                        .collect::<Vec<String>>()
                                        .join(",");

                                    let mut form_data = HashMap::new();
                                    form_data.insert("publicKeys", pubkeys_str);
                                    exchange_api_url = Url::parse(&format!(
                                        "{}{}",
                                        self.config.extra.exchange_api_base,
                                        "/api/v1/validator/deregister"
                                    ))?;
                                    res = client
                                        .post(exchange_api_url.to_string())
                                        .header("Authorization", format!("Bearer {}", access_jwt))
                                        .header("content-type", "application/x-www-form-urlencoded")
                                        .form(&form_data)
                                        .send()
                                        .await?;
                                    match res.json::<APIValidatorDeregisterResponse>().await {
                                        Ok(res_json) => {
                                            if res_json.success {
                                                info!("successful deregistration");
                                                info!(number = res_json.data.deleted.len(), deregistered_validators = ?res_json.data.deleted);
                                                deregistered_key_num += res_json.data.deleted.len();
                                            } else {
                                                error!("failed to deregister");
                                            }
                                        }
                                        Err(err) => {
                                            error!(?err, "failed to call validator deregister API");
                                        }
                                    }
                                }
                                info!(?deregistered_key_num);
                            }
                        }
                        None => error!("failed to get user EOA address from the exchange"),
                    }
                }
                Err(err) => {
                    error!(?err, "failed to get user EOA address from the exchange");
                }
            }
        } else if self.config.extra.registration_mode == "skipped" {
            info!("skipped registration or deregistration");
        } else {
            error!("invalid registration mode");
        }

        if self.config.extra.query_pubkey {
            info!("querying all your registered pubkeys...");
            get_registered_all_pubkeys(
                &client,
                self.config.extra.exchange_api_base.clone(),
                &access_jwt,
            )
            .await?;

            get_registered_ssv_pubkeys(
                &client,
                self.config.extra.exchange_api_base.clone(),
                &access_jwt,
            )
            .await?;

            get_registered_obol_pubkeys(
                &client,
                self.config.extra.exchange_api_base.clone(),
                &access_jwt,
            )
            .await?;
        }

        Ok(())
    }

    async fn ssv_validator_register_response(
        &self,
        res: Response,
        client: &Client,
        access_jwt: &str,
        pubkeys_str_list: String,
    ) -> Result<()> {
        match res.json::<APISsvValidatorRegisterResponse>().await {
            Ok(result) => {
                match result.success {
                    true => {
                        match result.data.validators.clone() {
                            None => warn!("no pubkey was registered. those pubkeys may not be found in any ssv cluster"),
                            Some(ref vec) if vec.is_empty() => warn!("no pubkey was registered. those pubkeys may not be found in any ssv cluster"),
                            Some(_) => {
                                if self.config.extra.enable_pricer {
                                    info!("successful registration, the default pricer can now sell preconfs on ETHGas on behalf of you");
                                } else {
                                    info!("successful registration, you can now sell preconfs on ETHGas");
                                }
                                let result_data_validators = result.data.validators.unwrap_or_default();
                                info!(number = result_data_validators.len(), registered_validators = ?result_data_validators);

                                update_ofac(
                                    client,
                                    &self.config.extra.registration_mode,
                                    &self.config.extra.exchange_api_base,
                                    access_jwt,
                                    self.config.extra.enable_ofac,
                                    pubkeys_str_list,
                                ).await.map_err(|err| eyre::eyre!("failed to update OFAC status: {}", err))?;
                            }
                        }
                    },
                    false => {
                        error!("failed to register ssv validator pubkeys: {}", result.error_msg_key.unwrap_or_default());
                    }
                }
            },
            Err(err) => {
                error!(?err, "failed to call ssv validator register API");
            }
        }
        Ok(())
    }

    async fn ssv_validator_deregister_response(&self, res: Response) -> Result<()> {
        match res.json::<APISsvValidatorDeregisterResponse>().await {
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
                        "failed to deregister ssv validator pubkeys: {}",
                        result.error_msg_key.unwrap_or_default()
                    );
                }
            },
            Err(err) => {
                error!(?err, "failed to call ssv validator deregister API");
            }
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

    let mut overall_wait_interval_in_second: u32;
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
                        return Err(std::io::Error::other("Failed to load pbs config").into());
                    }
                };

                let collateral_per_slot: Decimal =
                    Decimal::from_str(&config.extra.collateral_per_slot)?;
                if collateral_per_slot != Decimal::new(0, 0)
                    && (collateral_per_slot > Decimal::new(1000, 0)
                        || collateral_per_slot < Decimal::new(1, 2)
                        || collateral_per_slot.scale() > 2)
                {
                    error!("collateral_per_slot must be 0 or between 0.01 to 1000 ETH inclusive & no more than 2 decimal place");
                    return Err(std::io::Error::other("invalid collateral_per_slot").into());
                }

                let access_jwt: String;
                let refresh_jwt: String;
                if !config.extra.is_jwt_provided {
                    let exchange_service = EthgasExchangeService {
                        exchange_api_base: config.extra.exchange_api_base.clone(),
                        entity_name: config.extra.entity_name.clone(),
                        eoa_signing_key: match config.extra.eoa_signing_key {
                            Some(eoa) => eoa,
                            None => match env::var("EOA_SIGNING_KEY") {
                                Ok(eoa) => B256::from_str(&eoa).map_err(|_| {
                                    error!("Invalid EOA_SIGNING_KEY format");
                                    std::io::Error::new(
                                        std::io::ErrorKind::InvalidData,
                                        "EOA_SIGNING_KEY format error",
                                    )
                                })?,
                                Err(_) => {
                                    error!("Config eoa_signing_key is required. Please set EOA_SIGNING_KEY environment variable or provide it in the config file");
                                    return Err(
                                        std::io::Error::other("eoa_signing_key missing").into()
                                    );
                                }
                            },
                        },
                    };
                    (access_jwt, refresh_jwt) =
                        Retry::spawn(FixedInterval::from_millis(500).take(5), || async {
                            let service = EthgasExchangeService {
                                exchange_api_base: exchange_service.exchange_api_base.clone(),
                                entity_name: exchange_service.entity_name.clone(),
                                eoa_signing_key: exchange_service.eoa_signing_key,
                            };
                            service.login().await.map_err(|err| {
                                error!(?err, "Service failed");
                                err
                            })
                        })
                        .await?;
                } else {
                    access_jwt = match config.extra.access_jwt.clone() {
                        Some(jwt) => jwt,
                        None => match env::var("ACCESS_JWT") {
                            Ok(jwt) => jwt,
                            Err(_) => {
                                error!("Config access_jwt is required. Please set ACCESS_JWT environment variable or provide it in the config file");
                                return Err(std::io::Error::other("access_jwt missing").into());
                            }
                        },
                    };
                    refresh_jwt = match config.extra.refresh_jwt.clone() {
                        Some(jwt) => jwt,
                        None => match env::var("REFRESH_JWT") {
                            Ok(jwt) => jwt,
                            Err(_) => {
                                error!("Config refresh_jwt is required. Please set REFRESH_JWT environment variable or provide it in the config file");
                                return Err(std::io::Error::other("refresh_jwt missing").into());
                            }
                        },
                    };
                }

                let mux_pubkeys = match pbs_config.mux_lookup {
                    Some(mux_map) => {
                        let mut vec = Vec::new();
                        for (key, value) in mux_map.iter() {
                            for relay in value.relays.iter() {
                                if relay.id.contains("ethgas") {
                                    vec.push(BlsPublicKey::from(key.to_owned()));
                                    break;
                                }
                            }
                        }
                        vec
                    }
                    None => Vec::new(),
                };

                if !access_jwt.is_empty() && !refresh_jwt.is_empty() {
                    let mut commit_service = EthgasCommitService {
                        config,
                        access_jwt,
                        refresh_jwt,
                        mux_pubkeys,
                    };
                    if let Err(err) = commit_service.run().await {
                        error!(?err);
                    }
                } else {
                    return Err(std::io::Error::other("access_jwt or refresh_jwt missing").into());
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
        info!(
            "waiting for {} seconds to start again...",
            overall_wait_interval_in_second
        );
        sleep(Duration::from_millis(
            (overall_wait_interval_in_second as u64) * 1000,
        ))
        .await;
        counter += 1;
    }
    Ok(())
}
