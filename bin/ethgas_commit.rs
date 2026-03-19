use alloy::{
    primitives::{FixedBytes, B256},
    signers::{
        ledger::{HDPath, LedgerSigner},
        local::PrivateKeySigner,
    },
};
use commit_boost::prelude::*;
use cookie::Cookie;
use ethgas_commit::{
    login_types::{EoaSigner, Eip712Message},
    dvt_types::KeystoreConfig,
    obol_registry::register_obol_keys,
    ofac::update_ofac,
    query_pubkey::{
        get_registered_all_pubkeys, get_registered_obol_pubkeys, get_registered_ssv_pubkeys,
    },
    utils::{generate_eip712_signature, generate_eip712_signature_for_dvt, update_payout_address}
};
use eyre::Result;
use lazy_static::lazy_static;
use prometheus::{IntCounter, Registry};
use reqwest::{Client, Response, Url};
use rust_decimal::Decimal;
use serde::Deserialize;
use std::{collections::{HashMap, HashSet}, env, error::Error, str::FromStr, time::Duration};
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
    eoa_signer_config: EoaSignerConfig,
}

#[derive(Clone)]
enum EoaSignerConfig {
    PrivateKey(B256),
    LedgerPath(String),
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
    payout_address: Option<alloy::primitives::Address>,
    builder_pubkey: BlsPublicKey,
    is_jwt_provided: bool,
    query_pubkey: bool,
    eoa_signing_key: Option<B256>,
    eoa_ledger_path: Option<String>,
    access_jwt: Option<String>,
    refresh_jwt: Option<String>,
    ssv_node_operator_owner_mode: Option<String>,
    ssv_node_operator_owner_signing_keys: Option<Vec<B256>>,
    ssv_node_operator_owner_keystores: Option<Vec<KeystoreConfig>>,
    ssv_node_operator_owner_ledger_paths: Option<Vec<String>>,
    ssv_node_operator_owner_tx_hashes: Option<Vec<String>>,
    ssv_node_operator_owner_tx_from_addr: Option<Vec<alloy::primitives::Address>>,
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
struct APISsvNodeOperatorVerifyByTxResponse {
    success: bool,
    error_msg_key: Option<String>,
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
    removed: Option<Vec<BlsPublicKey>>,
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

impl EthgasExchangeService {
    pub async fn login(self) -> Result<(String, String)> {
        let client = Client::new();
        let signer = match &self.eoa_signer_config {
            EoaSignerConfig::PrivateKey(signing_key) => EoaSigner::PrivateKey(
                PrivateKeySigner::from_bytes(signing_key)
                    .map_err(|e| eyre::eyre!("Failed to create signer: {}", e))?,
            ),
            EoaSignerConfig::LedgerPath(path) => EoaSigner::Ledger(
                LedgerSigner::new(HDPath::Other(path.to_string()), Some(1)).await?,
            ),
        };
        let signer_address = signer.address();
        info!("your EOA address: {}", signer_address);
        let mut exchange_api_url = Url::parse(&format!(
            "{}{}",
            self.exchange_api_base, "/api/v1/user/login"
        ))?;
        let mut res = client
            .post(exchange_api_url.to_string())
            .query(&[("addr", signer_address)])
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
            .query(&[("addr", signer_address)])
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

        if let Some(payout_address) = self.config.extra.payout_address {
            update_payout_address(
                &client,
                &self.config.extra.exchange_api_base,
                &access_jwt,
                payout_address,
            )
            .await?;
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
            let mut ssv_node_operator_owner_tx_hashes: Vec<String> = Vec::new();
            let mut ssv_node_operator_owner_tx_from_addr: Vec<alloy::primitives::Address> = Vec::new();
            let ssv_node_operator_signers: Vec<EoaSigner> = match &self
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
                            operator_signers.push(EoaSigner::PrivateKey(signer));
                        }
                        operator_signers
                    }
                    "keystore" => {
                        let operator_signers: Vec<EoaSigner> = match &self
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
                                    operator_signers.push(EoaSigner::PrivateKey(signer));
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
                                            let private_key = eth_keystore::decrypt_key(
                                                keystore_path,
                                                password.trim(),
                                            )
                                            .map_err(|e| eyre::eyre!("Failed to read keystore: {}", e))?;
                                            let signer = PrivateKeySigner::from_slice(&private_key)
                                                .map_err(|e| {
                                                    eyre::eyre!("Failed to create signer: {}", e)
                                                })?;
                                            operator_signers.push(EoaSigner::PrivateKey(signer));
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
                            operator_signers.push(EoaSigner::Ledger(signer));
                        }
                        operator_signers
                    }
                    "tx" => {
                        ssv_node_operator_owner_tx_hashes =
                            match &self.config.extra.ssv_node_operator_owner_tx_hashes {
                                Some(tx_hashes) => tx_hashes.clone(),
                                None => {
                                    return Err(std::io::Error::other(
                                        "ssv_node_operator_owner_tx_hashes cannot be empty",
                                    )
                                    .into())
                                }
                            };
                        if ssv_node_operator_owner_tx_hashes.is_empty() {
                            return Err(std::io::Error::other(
                                "ssv_node_operator_owner_tx_hashes cannot be empty",
                            )
                            .into());
                        };
                        ssv_node_operator_owner_tx_from_addr =
                            match &self.config.extra.ssv_node_operator_owner_tx_from_addr {
                                Some(from_addr) => from_addr.clone(),
                                None => {
                                    return Err(std::io::Error::other(
                                        "ssv_node_operator_owner_tx_from_addr cannot be empty",
                                    )
                                    .into())
                                }
                            };
                        if ssv_node_operator_owner_tx_from_addr.is_empty() {
                            return Err(std::io::Error::other(
                                "ssv_node_operator_owner_tx_from_addr cannot be empty",
                            )
                            .into());
                        };

                        if ssv_node_operator_owner_tx_hashes.len() != ssv_node_operator_owner_tx_from_addr.len() {
                            return Err(std::io::Error::other("ssv_node_operator_owner_tx_hashes & ssv_node_operator_owner_tx_from_addr should have the same array length").into());
                        }

                        let mut operator_signers = Vec::new();
                        for _tx_hash in &ssv_node_operator_owner_tx_hashes {
                            // as placeholder signers
                            let signer = PrivateKeySigner::from_bytes(&FixedBytes::<32>::from([1u8; 32]))
                                    .map_err(|e| eyre::eyre!("Failed to create signer: {}", e))?;
                            operator_signers.push(EoaSigner::PrivateKey(signer));
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
                let ssv_node_operator_owner_address: alloy::primitives::Address;

                if self.config.extra.ssv_node_operator_owner_mode.clone().unwrap_or_default() == "tx" {
                    ssv_node_operator_owner_address = ssv_node_operator_owner_tx_from_addr[i];
                    info!(
                        "SSV node operator owner address: {}",
                        ssv_node_operator_owner_address
                    );
                    exchange_api_url = Url::parse(&format!(
                        "{}{}",
                        self.config.extra.exchange_api_base, "/api/v1/user/ssv/operator/verifyByTx"
                    ))?;
                    res = client
                        .post(exchange_api_url.to_string())
                        .header("User-Agent", "cb_ethgas_commit")
                        .header("Authorization", format!("Bearer {}", access_jwt))
                        .query(&[("ownerAddress", ssv_node_operator_owner_address)])
                        .query(&[("txHash", ssv_node_operator_owner_tx_hashes[i].clone())])
                        .query(&[("autoImport", false)])
                        .query(&[("sync", false)])
                        .send()
                        .await?;

                    match res.json::<APISsvNodeOperatorVerifyByTxResponse>().await {
                        Ok(result) => match result.success {
                            true => {
                                info!("successfully registered ssv node operator owner address");
                            }
                            false => {
                                if result.error_msg_key.clone().unwrap_or_default() == "error.ssv.operator.registered" {
                                    warn!("ssv node operator owner address has been registered");
                                } else {
                                    error!(
                                        "failed to register ssv node operator owner address: {}",
                                        result.error_msg_key.unwrap_or_default()
                                    );
                                }
                            }
                        },
                        Err(err) => {
                            error!(?err, "failed to call ssv operator verify by tx API");
                        }
                    }
                } else {
                    let signer = &ssv_node_operator_signers[i];
                    ssv_node_operator_owner_address = signer.address();
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
                        let signature_hex = generate_eip712_signature_for_dvt(
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
                                }
                            Err(err) => {
                                error!(?err, "failed to call ssv operator verify API");
                            }
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

                        let pubkeys_str_list = String::new();

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
                    let result_data_removed = result.data.removed.unwrap_or_default();
                    if result_data_removed.is_empty() {
                        warn!("no pubkey was deregistered. those pubkeys maybe deregistered already previously");
                    } else {
                        info!("successful deregistration");
                        info!(number = result_data_removed.len(), deregistered_validators = ?result_data_removed);
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
                    let eoa_signer_config = match (
                        config.extra.eoa_signing_key,
                        config.extra.eoa_ledger_path.clone(),
                    ) {
                        (Some(_), Some(_)) => {
                            error!(
                                "Config eoa_signing_key and eoa_ledger_path are mutually exclusive"
                            );
                            return Err(
                                std::io::Error::other("conflicting eoa signer config").into()
                            );
                        }
                        (Some(eoa_signing_key), None) => EoaSignerConfig::PrivateKey(eoa_signing_key),
                        (None, Some(eoa_ledger_path)) => EoaSignerConfig::LedgerPath(eoa_ledger_path),
                        (None, None) => match env::var("EOA_SIGNING_KEY") {
                            Ok(eoa_signing_key) => {
                                EoaSignerConfig::PrivateKey(B256::from_str(&eoa_signing_key).map_err(|_| {
                                    error!("Invalid EOA_SIGNING_KEY format");
                                    std::io::Error::new(
                                        std::io::ErrorKind::InvalidData,
                                        "EOA_SIGNING_KEY format error",
                                    )
                                })?)
                            }
                            Err(_) => {
                                error!("Please set EOA_SIGNING_KEY environment variable or provide eoa_signing_key or eoa_ledger_path in the config file");
                                return Err(
                                    std::io::Error::other("EOA_SIGNING_KEY/eoa_signing_key or eoa_ledger_path is missing").into()
                                );
                            }
                        },
                    };
                    let exchange_service = EthgasExchangeService {
                        exchange_api_base: config.extra.exchange_api_base.clone(),
                        entity_name: config.extra.entity_name.clone(),
                        eoa_signer_config,
                    };
                    (access_jwt, refresh_jwt) =
                        Retry::spawn(FixedInterval::from_millis(500).take(5), || async {
                            let service = EthgasExchangeService {
                                exchange_api_base: exchange_service.exchange_api_base.clone(),
                                entity_name: exchange_service.entity_name.clone(),
                                eoa_signer_config: exchange_service.eoa_signer_config.clone(),
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
                        let mut seen = HashSet::new();
                        mux_map
                            .iter()
                            .filter_map(|(key, value)| {
                                let matches = value.id.contains("ethgas") || value.relays.iter().any(|relay| relay.id.contains("ethgas"));

                                if matches {
                                    let pk = BlsPublicKey::from(key.to_owned());
                                    seen.insert(pk.clone()).then_some(pk)
                                } else {
                                    None
                                }
                            })
                            .collect::<Vec<_>>()
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
