use commit_boost::prelude::*;
use alloy::{
    primitives::{B256, U256}, signers::{local::PrivateKeySigner, Signer}, sol, sol_types::{eip712_domain, SolStruct},
    providers::ProviderBuilder,
    network::EthereumWallet,
    contract::{Interface, ContractInstance},
    dyn_abi::DynSolValue,
};
use eyre::Result;
use lazy_static::lazy_static;
use prometheus::{IntCounter, Registry};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};
use std::{
    time::Duration, error::Error, env, str::FromStr, sync::Arc
};
use reqwest::{Client, Url};
use tokio::time::{timeout, sleep};
use tokio_retry::{Retry, strategy::FixedInterval};
use hex::encode;
use rust_decimal::Decimal;
use chrono::DateTime;
// use tracing_subscriber::FmtSubscriber;
// use serde_json::Value;

// You can define custom metrics and a custom registry for the business logic of
// your module. These will be automatically scaped by the Prometheus server
lazy_static! {
    pub static ref MY_CUSTOM_REGISTRY: prometheus::Registry =
        Registry::new_custom(Some("ethgas_deposit".to_string()), None)
            .expect("Failed to create metrics registry");
    pub static ref SIG_RECEIVED_COUNTER: IntCounter =
        IntCounter::new("signature_received", "successful signatures requests received")
            .expect("Failed to create signature counter");
}

struct EthgasExchangeService {
    exchange_api_base: String,
    eoa_signing_key: B256,
}

struct EthgasDepositService {
    exchange_api_base: String,
    block_confirmation: u64,
    rpc_url: Url,
    collateral_to_be_deposited: Decimal,
    collateral_contract: alloy::primitives::Address,
    eoa_signing_key: B256,
    access_jwt: String
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
struct APICollateralContractResponse {
    success: bool,
    data: APICollateralAddressResponseData
}

#[derive(Debug, Deserialize)]
struct APICollateralAddressResponseData {
    contractAddress: alloy::primitives::Address
}

#[derive(Debug, Deserialize)]
struct APIDepositsHistoryResponse {
    success: bool,
    data: APIDepositsHistoryResponseData
}

#[derive(Debug, Deserialize)]
struct APIDepositsHistoryResponseData {
    deposits: Vec<Deposit>
}

#[derive(Debug, Deserialize)]
struct Deposit {
    eventId: u32,
    createDate: i64,
    deposits: Vec<DepositQuantity>
}

#[derive(Debug, Deserialize)]
struct DepositQuantity {
    a: alloy::primitives::Address,
    q: i128
}

#[derive(Debug, Deserialize)]
struct APIAccountsResponse {
    success: bool,
    data: APIAccountsResponseData
}

#[derive(Debug, Deserialize)]
struct APIAccountsResponseData {
    accounts: Vec<Account>
}

#[derive(Debug, Deserialize)]
struct Account {
    accountId: u32,
    r#type: u8
}

#[derive(Debug, Deserialize)]
struct APIAccountTokenTransferResponse {
    success: bool
}

impl EthgasExchangeService {
    pub async fn login(self) -> Result<String> {
        let client = Client::new();
        let signer = PrivateKeySigner::from_bytes(&self.eoa_signing_key)
            .map_err(|e| eyre::eyre!("Failed to create signer: {}", e))?;
        info!("your EOA address: {}", signer.clone().address());
        let mut exchange_api_url = Url::parse(&format!("{}{}", self.exchange_api_base, "/api/v1/user/login"))?;
        let mut res = client.post(exchange_api_url.to_string())
                .query(&[("addr", signer.clone().address())])
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
                .header("User-Agent", "cb_ethgas_deposit")
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
        // info!("API Response as JSON: {}", res.json::<Value>().await?);
        // Ok(String::from("test"))
    }
}

impl EthgasDepositService {
    pub async fn deposit(&self, amount: Decimal, ethgas_pool_addr: alloy::primitives::Address) -> Result<(), Box<dyn Error>> {
        let signer = PrivateKeySigner::from_bytes(&self.eoa_signing_key).map_err(|e| eyre::eyre!("Failed to create signer: {}", e))?;
        let wallet = EthereumWallet::from(signer);
        let provider = ProviderBuilder::new().with_recommended_fillers().wallet(wallet).on_http(self.rpc_url.clone());
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

        let abi = serde_json::from_str(&ABI)?;
        let contract = ContractInstance::new(ethgas_pool_addr, provider, Interface::new(abi));
        let token_transfers_value = DynSolValue::Array(Vec::new());
        let wei_amount_decimal = (amount * Decimal::from_str("1000000000000000000")?).round_dp(0);
        let pending_transaction_builder = contract
            .function("deposit", &[token_transfers_value])?
            .value(U256::from_str(&wei_amount_decimal.to_string())?)
            .send()
            .await?;
        info!("Pending transaction hash: {:?}", pending_transaction_builder.tx_hash());
        match timeout(Duration::from_secs(60), pending_transaction_builder.watch()).await {
            Ok(inner_result) => {},
            Err(_) => {
                error!("Please check the status of the on-chain deposit by searching the pending transaction hash on Etherscan and then visit https://app.ethgas.com/my-portfolio/accounts to transfer your fund from current account to trading account");
                return Err(std::io::Error::new(std::io::ErrorKind::Other, "On-chain deposit timeout").into());
            }
        }
        info!("{} ETH deposit transaction is successfully included in the block", amount);
        Ok(())
    }

    pub async fn run(self) -> Result<(), Box<dyn Error>> {
        let client = Client::new();

        let mut exchange_api_url = Url::parse(&format!("{}{}", self.exchange_api_base, "/api/v1/p/funding/contractAddress"))?;
        let mut res = client.get(exchange_api_url.to_string())
                .header("Authorization", format!("Bearer {}", self.access_jwt))
                .send()
                .await?;
        let ethgas_pool_addr = match res.json::<APICollateralContractResponse>().await {
            Ok(result) => {
                match result.success {
                    true => {
                        result.data.contractAddress
                    },
                    false => {
                        return Err(std::io::Error::new(std::io::ErrorKind::Other,
                            "failed to get collateral contract address from exchange").into());
                    }
                }
            },
            Err(err) => {
                error!(?err, "failed to call contract address API");
                return Err(std::io::Error::new(std::io::ErrorKind::Other,
                    "failed to call contract address API").into());
            }
        };
        if ethgas_pool_addr == self.collateral_contract {
            info!("collaterl contract address: {}", ethgas_pool_addr);
        } else {
            error!("collateral contract address from exchange and the config are different");
                return Err(std::io::Error::new(std::io::ErrorKind::Other,
                    "collateral contract address from exchange and the config are different").into());
        }
        self.deposit(self.collateral_to_be_deposited, ethgas_pool_addr).await?;
        let waiting_time = self.block_confirmation * 12;
        info!("waiting for {} seconds to confirm the deposit in the exchange...", waiting_time);
        sleep(Duration::from_secs(waiting_time)).await;
        exchange_api_url = Url::parse(&format!("{}{}", self.exchange_api_base, "/api/v1/user/funding/deposits"))?;
        res = client.get(exchange_api_url.to_string())
                .header("Authorization", format!("Bearer {}", self.access_jwt))
                .send()
                .await?;
        match res.json::<APIDepositsHistoryResponse>().await {
            Ok(result) => {
                match result.success {
                    true => {
                        if let Some(latest_deposit) = result.data.deposits.iter().max_by_key(|obj| obj.eventId) {
                            let datetime = DateTime::from_timestamp(latest_deposit.createDate / 1000, 0).expect("invalid timestamp");
                            let latest_deposit_datetime = datetime.format("%Y-%m-%d %H:%M:%S").to_string();
                            let deposit_in_eth = Decimal::from_i128_with_scale(latest_deposit.deposits[0].q, 0) / Decimal::from_str("1000000000000000000")?;
                            info!("latest deposit found at {}UTC with {:?} ETH", latest_deposit_datetime, deposit_in_eth.to_string());
                        } else {
                            error!("No deposit found!");
                        }
                    },
                    false => {
                        error!("failed to get deposits history");
                    }
                }
            },
            Err(err) => {
                error!(?err, "failed to call deposits history API");
            }
        }
        let mut current_ac_id: u32 = 0;
        let mut trading_ac_id: u32 = 0;
        exchange_api_url = Url::parse(&format!("{}{}", self.exchange_api_base, "/api/v1/user/accounts"))?;
        res = client.get(exchange_api_url.to_string())
                .header("Authorization", format!("Bearer {}", self.access_jwt))
                .send()
                .await?;
        match res.json::<APIAccountsResponse>().await {
            Ok(result) => {
                match result.success {
                    true => {
                        if let Some(_current_ac_id) = result.data.accounts.iter().find(|obj| obj.r#type == 1).map(|obj| obj.accountId) {
                            current_ac_id = _current_ac_id;
                        } else {
                            error!("No type 1 account found!");
                        }
                        if let Some(_trading_ac_id) = result.data.accounts.iter().find(|obj| obj.r#type == 2).map(|obj| obj.accountId) {
                            trading_ac_id = _trading_ac_id;
                        } else {
                            error!("No type 2 account found!");
                        }
                    },
                    false => {
                        return Err(std::io::Error::new(std::io::ErrorKind::Other,
                            "failed to get user accounts").into());
                    }
                }
            },
            Err(err) => {
                return Err(std::io::Error::new(std::io::ErrorKind::Other,
                    "failed to call user accounts API").into());
            }
        }

        exchange_api_url = Url::parse(&format!(
            "{}{}{}{}{}{}{}", 
            self.exchange_api_base, 
            "/api/v1/user/account/transfer/token?fromAccountId=", current_ac_id,
            "&toAccountId=", trading_ac_id,
            "&tokenId=1&quantity=", self.collateral_to_be_deposited.to_string()
        ))?;
        res = client.post(exchange_api_url.to_string())
                .header("Authorization", format!("Bearer {}", self.access_jwt))
                .send()
                .await?;
        match res.json::<APIAccountTokenTransferResponse>().await {
            Ok(result) => {
                match result.success {
                    true => {
                        info!("successfully transfer ETH from current account to trading account")
                    },
                    false => {
                        error!("failed to transfer ETH from current account to trading account");
                    }
                }
            },
            Err(err) => {
                error!(?err, "failed to call account token transfer API");
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
    // Spin up a server that exposes the /metrics endpoint to Prometheus
    MetricsProvider::load_and_run(MY_CUSTOM_REGISTRY.clone())?;

    let _guard = initialize_tracing_log("ETHGAS_DEPOSIT")?;
    // let subscriber = FmtSubscriber::builder().finish();
    // tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    match load_commit_module_config::<ExtraConfig>() {
        Ok(config) => {

            info!(
                module_id = %config.id,
                "Starting module with custom data"
            );
            info!("chain: {:?}", config.chain);

            let pbs_config = match load_pbs_config() {
                Ok(config) => config,
                Err(err) => {
                    error!("Failed to load pbs config: {err:?}");
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, "Failed to load pbs config").into());
                }
            };

            let rpc_url = match Arc::try_unwrap(pbs_config.pbs_config) {
                Ok(pbs_config) => {
                    pbs_config.rpc_url.expect("Failed to get RPC URL")
                },
                Err(_arc) => {
                    error!("Failed to get RPC URL");
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, "Failed to get RPC URL").into());
                }
            };

            let collateral_to_be_deposited: Decimal = Decimal::from_str(&config.extra.collateral_to_be_deposited)?;
                if collateral_to_be_deposited < Decimal::new(1, 2) || collateral_to_be_deposited.scale() > 2 {
                    error!("collateral_to_be_deposited must be >= 0.01 & no more than 2 decimal place");
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, "invalid collateral_to_be_deposited").into());
                }

            let exchange_service = EthgasExchangeService {
                exchange_api_base: config.extra.exchange_api_base.clone(),
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
            let access_jwt = Retry::spawn(FixedInterval::from_millis(500).take(5), || async { 
                let service = EthgasExchangeService {
                    exchange_api_base: exchange_service.exchange_api_base.clone(),
                    eoa_signing_key: exchange_service.eoa_signing_key.clone(),
                };
                service.login().await.map_err(|err| {
                    error!(?err, "Service failed");
                    err
                })
            }).await?;

            if !access_jwt.is_empty() {
                let commit_service = EthgasDepositService { 
                    exchange_api_base: exchange_service.exchange_api_base.clone(),
                    block_confirmation: config.extra.block_confirmation,
                    rpc_url,
                    collateral_to_be_deposited,
                    collateral_contract: config.extra.collateral_contract,
                    eoa_signing_key: exchange_service.eoa_signing_key.clone(),
                    access_jwt 
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
