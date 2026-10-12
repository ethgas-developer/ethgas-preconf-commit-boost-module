use alloy::{
    contract::{ContractInstance, Interface},
    dyn_abi::DynSolValue,
    network::EthereumWallet,
    primitives::{B256, U256},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
};
use chrono::DateTime;
use commit_boost::prelude::*;
use ethgas_commit::{login_types::EoaSigner, utils::{generate_eip712_signature, parse_sensitive_json}};
use eyre::Result;
use lazy_static::lazy_static;
use prometheus::{IntCounter, Registry};
use reqwest::{Client, Url};
use rust_decimal::Decimal;
use serde::Deserialize;
use std::{env, error::Error, str::FromStr, sync::Arc, time::Duration};
use tokio::time::{sleep, timeout};
use tokio_retry::{strategy::FixedInterval, Retry};
use tracing::{error, info};
// use serde_json::Value;

// You can define custom metrics and a custom registry for the business logic of
// your module. These will be automatically scaped by the Prometheus server
lazy_static! {
    pub static ref MY_CUSTOM_REGISTRY: prometheus::Registry =
        Registry::new_custom(Some("ethgas_deposit".to_string()), None)
            .expect("Failed to create metrics registry");
    pub static ref SIG_RECEIVED_COUNTER: IntCounter = IntCounter::new(
        "signature_received",
        "successful signatures requests received"
    )
    .expect("Failed to create signature counter");
}

struct EthgasExchangeService {
    exchange_api_base: String,
    eoa_signing_key: B256,
    chain_id: u64,
}

struct EthgasDepositService {
    exchange_api_base: String,
    block_confirmation: u64,
    rpc_url: Url,
    collateral_to_be_deposited: Decimal,
    collateral_contract: alloy::primitives::Address,
    eoa_signing_key: B256,
    access_jwt: String,
}

// Extra configurations parameters can be set here and will be automatically
// parsed from the .self.config.toml file These parameters will be in the .extra
// field of the StartModuleConfig<ExtraConfig> struct you get after calling
// `load_commit_module_config::<ExtraConfig>()`
#[derive(Debug, Deserialize)]
struct ExtraConfig {
    exchange_api_base: String,
    block_confirmation: u64,
    collateral_to_be_deposited: String,
    collateral_contract: alloy::primitives::Address,
    eoa_signing_key: Option<B256>,
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
struct AccessToken {
    token: String,
}

#[derive(Debug, Deserialize)]
struct APICollateralContractResponse {
    success: bool,
    data: APICollateralAddressResponseData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct APICollateralAddressResponseData {
    contract_address: alloy::primitives::Address,
}

#[derive(Debug, Deserialize)]
struct APIDepositsHistoryResponse {
    success: bool,
    data: APIDepositsHistoryResponseData,
}

#[derive(Debug, Deserialize)]
struct APIDepositsHistoryResponseData {
    deposits: Vec<Deposit>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Deposit {
    event_id: u32,
    create_date: i64,
    deposits: Vec<DepositQuantity>,
}

#[derive(Debug, Deserialize)]
struct DepositQuantity {
    // a: alloy::primitives::Address,
    q: i128,
}

#[derive(Debug, Deserialize)]
struct APIAccountsResponse {
    success: bool,
    data: APIAccountsResponseData,
}

#[derive(Debug, Deserialize)]
struct APIAccountsResponseData {
    accounts: Vec<Account>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Account {
    account_id: u32,
    r#type: u8,
}

#[derive(Debug, Deserialize)]
struct APIAccountTokenTransferResponse {
    success: bool,
}

impl EthgasExchangeService {
    pub async fn login(self) -> Result<String> {
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

        if !res_json_login.success {
            return Err(eyre::eyre!("login challenge was rejected"));
        }
        let eip712_message: ethgas_commit::login_types::Eip712Message =
            serde_json::from_str(&res_json_login.data.eip712_message)?;
        let signature_hex = generate_eip712_signature(
            &res_json_login.data.eip712_message,
            &EoaSigner::PrivateKey(signer.clone()),
            self.chain_id,
        ).await?;
        exchange_api_url = Url::parse(&format!(
            "{}{}",
            self.exchange_api_base, "/api/v1/user/login/verify"
        ))?;
        res = client
            .post(exchange_api_url.to_string())
            .header("User-Agent", "cb_ethgas_deposit")
            .query(&[("addr", signer.clone().address())])
            .query(&[("nonceHash", eip712_message.message.hash)])
            .query(&[("signature", signature_hex)])
            .send()
            .await
            .map_err(|err| err.without_url())?;
        let res_json_verify: APILoginVerifyResponse =
            parse_sensitive_json(res, "login verification").await?;
        if !res_json_verify.success || res_json_verify.data.access_token.token.is_empty() {
            return Err(eyre::eyre!("login verification failed or returned an empty access token"));
        }
        info!("successfully obtained access jwt from the exchange");
        Ok(res_json_verify.data.access_token.token)
        // info!("API Response as JSON: {}", res.json::<Value>().await?);
        // Ok(String::from("test"))
    }
}

impl EthgasDepositService {
    pub async fn deposit(
        &self,
        amount: Decimal,
        ethgas_pool_addr: alloy::primitives::Address,
    ) -> Result<(), Box<dyn Error>> {
        let signer = PrivateKeySigner::from_bytes(&self.eoa_signing_key)
            .map_err(|e| eyre::eyre!("Failed to create signer: {}", e))?;
        let wallet = EthereumWallet::from(signer);
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(self.rpc_url.clone());
        const ABI: &str = r#"[{
            "inputs": [{
                "components": [
                    {"name": "token", "type": "address"},
                    {"name": "amount", "type": "uint256"}
                ],
                "name": "tokenTransfers",
                "type": "tuple[]"
            }],
            "name": "deposit",
            "outputs": [],
            "stateMutability": "payable",
            "type": "function"
        }]"#;

        let abi = serde_json::from_str(ABI)?;
        let contract = ContractInstance::new(ethgas_pool_addr, provider, Interface::new(abi));
        let token_transfers_value = DynSolValue::Array(Vec::new());
        let wei_amount_decimal = amount.checked_mul(Decimal::from_str("1000000000000000000")?)
            .ok_or_else(|| std::io::Error::other("deposit amount is too large"))?.round_dp(0);
        let pending_transaction_builder = contract
            .function("deposit", &[token_transfers_value])?
            .value(U256::from_str(&wei_amount_decimal.to_string())?)
            .send()
            .await?;
        info!(
            "Pending transaction hash: {:?}",
            pending_transaction_builder.tx_hash()
        );
        confirm_deposit_receipt(pending_transaction_builder.get_receipt()).await?;
        info!(
            "{} ETH deposit transaction is successfully included in the block",
            amount
        );
        Ok(())
    }

    pub async fn run(self) -> Result<(), Box<dyn Error>> {
        let client = Client::new();

        let mut exchange_api_url = Url::parse(&format!(
            "{}{}",
            self.exchange_api_base, "/api/v1/p/funding/contractAddress"
        ))?;
        let mut res = client
            .get(exchange_api_url.to_string())
            .header("Authorization", format!("Bearer {}", self.access_jwt))
            .send()
            .await?;
        let ethgas_pool_addr = match res.json::<APICollateralContractResponse>().await {
            Ok(result) => match result.success {
                true => result.data.contract_address,
                false => {
                    return Err(std::io::Error::other(
                        "failed to get collateral contract address from exchange",
                    )
                    .into());
                }
            },
            Err(err) => {
                error!(?err, "failed to call contract address API");
                return Err(std::io::Error::other("failed to call contract address API").into());
            }
        };
        if ethgas_pool_addr == self.collateral_contract {
            info!("collaterl contract address: {}", ethgas_pool_addr);
        } else {
            error!("collateral contract address from exchange and the config are different");
            return Err(std::io::Error::other(
                "collateral contract address from exchange and the config are different",
            )
            .into());
        }
        self.deposit(self.collateral_to_be_deposited, ethgas_pool_addr)
            .await?;
        let waiting_time = self.block_confirmation * 12;
        info!(
            "waiting for {} seconds to confirm the deposit in the exchange...",
            waiting_time
        );
        sleep(Duration::from_secs(waiting_time)).await;
        exchange_api_url = Url::parse(&format!(
            "{}{}",
            self.exchange_api_base, "/api/v1/user/funding/deposits"
        ))?;
        res = client
            .get(exchange_api_url.to_string())
            .header("Authorization", format!("Bearer {}", self.access_jwt))
            .send()
            .await?;
        match res.json::<APIDepositsHistoryResponse>().await {
            Ok(result) => match result.success {
                true => {
                    if let Some(latest_deposit) =
                        result.data.deposits.iter().max_by_key(|obj| obj.event_id)
                    {
                        let datetime =
                            DateTime::from_timestamp(latest_deposit.create_date / 1000, 0)
                                .ok_or_else(|| std::io::Error::other("invalid deposit timestamp"))?;
                        let latest_deposit_datetime =
                            datetime.format("%Y-%m-%d %H:%M:%S").to_string();
                        let deposit_in_eth =
                            Decimal::try_from_i128_with_scale(latest_deposit.deposits.first()
                                .ok_or_else(|| std::io::Error::other("deposit quantities are empty"))?.q, 0)?
                                / Decimal::from_str("1000000000000000000")?;
                        info!(
                            "latest deposit found at {}UTC with {:?} ETH",
                            latest_deposit_datetime,
                            deposit_in_eth.to_string()
                        );
                    } else {
                        error!("No deposit found!");
                    }
                }
                false => {
                    error!("failed to get deposits history");
                }
            },
            Err(err) => {
                error!(?err, "failed to call deposits history API");
            }
        }
        let current_ac_id: u32;
        let trading_ac_id: u32;
        exchange_api_url = Url::parse(&format!(
            "{}{}",
            self.exchange_api_base, "/api/v1/user/accounts"
        ))?;
        res = client
            .get(exchange_api_url.to_string())
            .header("Authorization", format!("Bearer {}", self.access_jwt))
            .send()
            .await?;
        match res.json::<APIAccountsResponse>().await {
            Ok(result) => match result.success {
                true => {
                    if let Some(_current_ac_id) = result
                        .data
                        .accounts
                        .iter()
                        .find(|obj| obj.r#type == 1)
                        .map(|obj| obj.account_id)
                    {
                        current_ac_id = _current_ac_id;
                    } else {
                        return Err(std::io::Error::other("No type 1 account found").into());
                    }
                    if let Some(_trading_ac_id) = result
                        .data
                        .accounts
                        .iter()
                        .find(|obj| obj.r#type == 2)
                        .map(|obj| obj.account_id)
                    {
                        trading_ac_id = _trading_ac_id;
                    } else {
                        return Err(std::io::Error::other("No type 2 account found").into());
                    }
                }
                false => {
                    return Err(std::io::Error::other("failed to get user accounts").into());
                }
            },
            Err(_) => {
                return Err(std::io::Error::other("failed to call user accounts API").into());
            }
        }

        exchange_api_url = Url::parse(&format!(
            "{}{}{}{}{}{}{}",
            self.exchange_api_base,
            "/api/v1/user/account/transfer/token?fromAccountId=",
            current_ac_id,
            "&toAccountId=",
            trading_ac_id,
            "&tokenId=1&quantity=",
            self.collateral_to_be_deposited
        ))?;
        res = client
            .post(exchange_api_url.to_string())
            .header("Authorization", format!("Bearer {}", self.access_jwt))
            .send()
            .await?;
        match res.json::<APIAccountTokenTransferResponse>().await {
            Ok(result) => match result.success {
                true => {
                    info!("successfully transferred ETH from current account to trading account")
                }
                false => {
                    error!("failed to transfer ETH from current account to trading account");
                }
            },
            Err(err) => {
                error!(?err, "failed to call account token transfer API");
            }
        }

        Ok(())
    }
}

async fn confirm_deposit_receipt(
    receipt: impl std::future::Future<Output = Result<alloy::rpc::types::TransactionReceipt, alloy::providers::PendingTransactionError>>,
) -> Result<(), Box<dyn Error>> {
    let receipt = timeout(Duration::from_secs(60), receipt)
        .await
        .map_err(|_| std::io::Error::other("On-chain deposit timeout"))??;
    if !receipt.status() {
        return Err(std::io::Error::other("On-chain deposit reverted").into());
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    // Remember to register all your metrics before starting the process
    MY_CUSTOM_REGISTRY.register(Box::new(SIG_RECEIVED_COUNTER.clone()))?;

    let _guard = initialize_tracing_log("ETHGAS_DEPOSIT", LogsSettings::from_env_config()?);

    match load_commit_module_config::<ExtraConfig>() {
        Ok(config) => {
            // Spin up a server that exposes the /metrics endpoint to Prometheus
            MetricsProvider::load_and_run(config.chain, MY_CUSTOM_REGISTRY.clone())?;

            info!(
                module_id = %config.id,
                "Starting module with custom data"
            );
            info!("chain: {:?}", config.chain);

            let pbs_config = match load_pbs_config(None).await {
                Ok(config) => config,
                Err(err) => {
                    error!("Failed to load pbs config: {err:?}");
                    return Err(std::io::Error::other("Failed to load pbs config").into());
                }
            };

            let rpc_url = match Arc::try_unwrap(pbs_config.0.pbs_config) {
                Ok(pbs_config) => pbs_config.rpc_url.ok_or_else(|| eyre::eyre!("Failed to get RPC URL"))?,
                Err(_arc) => {
                    error!("Failed to get RPC URL");
                    return Err(std::io::Error::other("Failed to get RPC URL").into());
                }
            };

            let collateral_to_be_deposited: Decimal =
                Decimal::from_str(&config.extra.collateral_to_be_deposited)?;
            if collateral_to_be_deposited < Decimal::new(1, 2)
                || collateral_to_be_deposited.scale() > 2
            {
                error!("collateral_to_be_deposited must be >= 0.01 & no more than 2 decimal place");
                return Err(std::io::Error::other("invalid collateral_to_be_deposited").into());
            }

            let exchange_service = EthgasExchangeService {
                chain_id: config.chain.id().to::<u64>(),
                exchange_api_base: config.extra.exchange_api_base.clone(),
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
                            return Err(std::io::Error::other("eoa_signing_key missing").into());
                        }
                    },
                },
            };
            let access_jwt = Retry::spawn(FixedInterval::from_millis(500).take(5), || async {
                let service = EthgasExchangeService {
                    exchange_api_base: exchange_service.exchange_api_base.clone(),
                    eoa_signing_key: exchange_service.eoa_signing_key,
                    chain_id: exchange_service.chain_id,
                };
                service.login().await.map_err(|err| {
                    error!(?err, "Service failed");
                    err
                })
            })
            .await?;

            if !access_jwt.is_empty() {
                let commit_service = EthgasDepositService {
                    exchange_api_base: exchange_service.exchange_api_base.clone(),
                    block_confirmation: config.extra.block_confirmation,
                    rpc_url,
                    collateral_to_be_deposited,
                    collateral_contract: config.extra.collateral_contract,
                    eoa_signing_key: exchange_service.eoa_signing_key,
                    access_jwt,
                };
                if let Err(err) = commit_service.run().await {
                    error!(?err);
                }
            } else {
                error!("JWT invalid")
            }
        }
        Err(err) => {
            error!("Failed to load module config: {:?}", err);
            return Err(err);
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/deposit.rs"]
mod tests;
