## Overview
First and foremost, we would like to give a big shout out to the Commit-Boost team for making Ethereum a more open and cooperative environment! This repo allows you to run all Commit-Boost components related to ETHGas in Docker. There are 3 main components, i.e.
* `cb_pbs`: It serves a similar purpose as MEV-Boost. To avoid validators being slashed because of signing a block without preconf, please only set relays that are approved by ETHGas.
* `cb_signer`: It securely generates signatures from the validator BLS private keys. If you use remote signer or want to onboard DVT validators, you don't need this component.
* `cb_ethgas_commit`: It requests signatures for ETHGas registration from `cb_signer` where the signatures are then sent to the ETHGas Exchange via REST API
![Architecture](./architecture.png)
* For more details on ETHGas architecture, please refer to [here](https://docs.ethgas.com/our-technology/the-ethgas-architecture)

## Build docker images
* For `cb_ethgas_commit` and `cb_gen_jwt`, you can either use our pre-built linux/amd64 or linux/arm64 docker image or run `./scripts/build.sh` to build it locally
* For `cb_signer` and `cb_pbs`, you can either use the official image from Commit Boost team or use Dockerfile [here](https://github.com/Commit-Boost/commit-boost-client/tree/main/provisioning) to build it locally

## Config Setup
* Copy one of the `config.example.<env>.toml` as `config.toml`
* Copy `docker-compose-example.yml` as `docker-compose.yml`
* Create an empty `.cb.env` file and run `docker compose -f docker-compose.yml up cb_gen_jwt` to generate new jwt for the signer module
* Do not use any other relay than the one listed in the `config.example.<env>.toml`, otherwise you will get slashed
* Registration of SSV or Obol validators can skip signer-related setup below
* For local signer module, Commit Boost supports various consensus client. Please refer to [here](https://commit-boost.github.io/commit-boost-client/get_started/configuration#local-signer) for more details
    * `format`, `keys_path` and `secrets_path` are used together and cannot be used together with `key_path` (key without s)
* For remote signer module, Commit Boost supports Web3Signer and Dirk. Please refer to [here](https://commit-boost.github.io/commit-boost-client/get_started/configuration#remote-signer) for more details. You also need to update `CB_SIGNER_URL` to the remote signer URL in `docker-compose.yml`
    * for Web3Signer, set `--commit-boost-api-enabled=true`, a placeholder dir for `--proxy-keystores-path` and a placeholder file for `--proxy-keystores-password-file` when you run the `web3signer` command
* Set ETHGas Commit module config in `config.toml`
    * under `[[modules]]` section where `id = ETHGAS_COMMIT`,
    * set your `entity_name`
    * set `registration_mode` to be either `standard` for the most typical validators, `ssv` for SSV validators, `obol` for Obol validators or `skipped` to skip registration
    * set `enable_registration = true` to register validators in ETHGas, set `enable_registration = false` to de-register validators
    * When `registration_mode = standard`, all validator public keys inside keys directory or file will be registered in ETHGas Exchange. To enable PBS multiplexer, set `registration_mode = standard-mux` and set the `id` of `[[mux.relays]]` to contain `ethgas` wording under `[[mux]]` section, then only validator public keys of `validator_pubkeys` or `loader` will be registered.
    * for SSV validators, you need to prove your ownership to any one of the SSV node operator. 
        * set `ssv_node_operator_owner_mode` to be either `key`, `keystore` or `ledger`
        * For the `key` mode, set one or multiple private keys under `ssv_node_operator_owner_signing_keys` array 
            * Alternatively, you can set `SSV_NODE_OPERATOR_OWNER_SIGNING_KEYS` as an env variable in `.cb.env`
        * For the `keystore` mode, set keystore configurations under `ssv_node_operator_owner_keystores` array where each entry contains both `keystore_path` and `password_path`
            * Alternatively, you can set `SSV_NODE_OPERATOR_OWNER_KEYSTORE_PATHS` and `SSV_NODE_OPERATOR_OWNER_PASSWORD_PATHS` as env variables in `.cb.env`
        * For the `ledger` mode, only set one derivation path in `ssv_node_operator_owner_ledger_paths` array 
            * if you are using Linux, identify the correct ledger device path and add `devices` section under `cb_ethgas_commit` service of `docker-compose.yml`
            * if you are using Mac, you can only run the program in native rust as Docker cannot support native ledger connection in Mac
                * export all env variables of `.cb.env` in the terminal
                * run `export CB_MODULE_ID=ETHGAS_COMMIT && export CB_SIGNER_JWT=??? && export CB_SIGNER_URL="http://localhost:20000" && export CB_CONFIG="./config.toml" && cargo run --bin ethgas_commit`
        * specify validator public keys under `ssv_node_operator_owner_validator_pubkeys` or set it as `[]` to indicate the registration of all associated validator public keys obtained via SSV official API
        * if node operators within a cluster are associated with different owner addresses which are all owned by you, please put all signing keys of those owner addresses under the `ssv_node_operator_owner_signing_keys` array. This can ensure our exchange will open markets for your ssv validators even when the leading node operator rotates within the cluster.
    * for Obol validators, the onboarding instruction is the same as the ssv one above but with `obol_` as prefix.
    * since your EOA address is required to be registered in ETHGas Exchange by generating a EIP712 signature first, then your validator public key can be binded to your EOA address by generating a BLS signature. You will need to either set `is_jwt_provided = false` and `eoa_signing_key` in `config.toml` or you can refer to our API doc [this part](https://developers.ethgas.com/?http#post-api-v1-user-login) and [this part](https://developers.ethgas.com/?http#post-api-v1-user-login-refresh) to get access & refresh jwt and set `is_jwt_provided = true` and `access_jwt` & `refresh_jwt` in `config.toml`
        * if you are a node operator with validators from multiple pools, please use a different `eoa_signing_key` for validators from different pools.
        * Alternatively, you can set `EOA_SIGNING_KEY` or `ACCESS_JWT` & `REFRESH_JWT` as env variables in `.cb.env`
    * set `enable_pricer = true` if you want to delegate to our default pricer to help you to sell preconfs
    * set `enable_builder = true` and `builder_pubkey` if you want to delegate to a specific external builder to build the block. Regardless of whether the builder delegation is enabled or not, our fallback builder will always build a backup block which can fulfill all the preconf commitments
    * set `enable_ofac = true` if your validators only accept ofac-compliant blocks. This is a pubkey-specific setting so you could specify list of pubkeys in `[[mux]].validator_pubkeys` or `ssv_node_operator_owner_validator_pubkeys`.
    * `collateral_per_slot` indicates how much ETH is allocated to secure a single slot. It is in the unit of ETH and can either be 0 or between 0.01 to 1000 inclusive and no more than 2 decimal place
    * `overall_wait_interval_in_second` indicates the waiting time before re-running the module, set it as `0` to stop re-running the module
    * set `query_pubkey = true` if you want to query all your validator pubkeys regardless of standard or dvt type that have been registered on the ETHGas Exchange. A txt file will be created in `./records` folder
    * The config is reloaded before every re-run of the module so you could update the `[[modules]]` config directly that will be effective in the next run of the module
* For non-DVT validators, set validator BLS key directory or file in `docker-compose.yml`
    * under `cb_signer` section
    * if `key_path` is set in `config.toml`, then set `CB_SIGNER_LOADER_FILE: /keys.json`
    * if `keys_path` and `secrets_path` are set in `config.toml`, then set `CB_SIGNER_LOADER_KEYS_DIR: /keys` and `CB_SIGNER_LOADER_SECRETS_DIR: /secrets`
    * mount the correct validator keystore directories from the host machine to the container `/keys` and `/secrets` directory

## Start the Signer module
* For registration of non-DVT validators, run `docker compose -f docker-compose.yml up cb_signer`. For DVT validators or remote signer, you don't need to run this module
    * if your signer starts successfully, you should see the log similar to `INFO Starting signing service version="0.8.0" commit_hash="f51f5bd61831fde943057b29ffd6e26e7eb23765" modules=["ETHGAS_COMMIT"] endpoint=0.0.0.0:20000 loaded_consensus=100 loaded_proxies=0` where `loaded_consensus` indicates the total number of loaded keys

## Start the ETHGas Commit module
* You are advised to run this module at or after the 2nd slot of the current epoch so you could have more time to configure the PBS module
* Run `docker compose -f docker-compose.yml up cb_ethgas_commit` to register in ETHGas Exchange
    * you will see the log `INFO successful registration, you can now sell preconfs on ETHGas!` or `INFO successful registration, the default pricer can now sell preconfs on ETHGas on behalf of you!` if all goes well
    * if the module encounters `ConnectionRefused` error when it tries to connect to `http://cb_signer:20000/signer/v1/get_pubkeys`, please wait for 20 minutes to retry

## Start the PBS module
* Start the PBS module by running `docker compose -f docker-compose.yml up cb_pbs`
* update builder/relay config of your beacon node from pointing towards MEV-Boost to `cb_pbs` endpoint where the port is `18550` by default
    * you will see the log `DEBUG register_validators{req_id=...}:handler{relay_id="ethgas"}: registration successful code=200 latency=...ms` if all goes well
* Once the ETHGas Commit module has completed the registration process and right before the start of the next epoch, please stop the MEV-Boost, restart the beacon node with new builder endpoint and immediately start the PBS module.
* To hot reload the config without restarting the module, run `docker compose -f docker-compose.yml exec cb_pbs curl -X POST http://localhost:18550/reload`. You will see the log `INFO : config reload successful` if the config reloads successfully. Please refer to [here](https://commit-boost.github.io/commit-boost-client/get_started/configuration/#hot-reload) for more details.

## Deposit ETH to our collateral contract
* You can either deposit ETH/WETH via our [website](https://app.ethgas.com/my-portfolio/accounts), docker or direct contract interaction. After deposit, please transfer ETH from current account to trading account

### Through docker
* Set ETHGas Deposit module config in `config.toml`
    * under `[[modules]]` section where `id = ETHGAS_DEPOSIT`,
    * set `collateral_to_be_deposited` to be >= `collateral_per_slot` of ETHGas Commit module
    * set `eoa_signing_key` which should equal to the one in ETHGas Commit module above
    * Run ETHGas Deposit module by `docker compose -f docker-compose-example-deposit.yml up`

### Through direct contract interaction
* Collateral contract (EthgasPool) on mainnet: [0x3314Fb492a5d205A601f2A0521fAFbD039502Fc3](https://etherscan.io/address/0x3314Fb492a5d205A601f2A0521fAFbD039502Fc3#writeContract)
    * on hoodi: [0x104Ef4192a97E0A93aBe8893c8A2d2484DFCBAF1](https://hoodi.etherscan.io/address/0x104Ef4192a97E0A93aBe8893c8A2d2484DFCBAF1#writeContract)
* Call deposit function of the EthgasPool contract which can accept both WETH and native ETH. Below are the ABI details.
```
struct TokenTransfer {
    address token;
    uint256 amount;
}
function deposit(TokenTransfer[] memory tokenTransfers) external payable;
```
* For WETH, put the WETH address of the respective network in the `token` field and specify the `amount` inside the `TokenTransfer` struct. For native ETH, put an empty struct and specify the amount in the value field

## Debug cb_ethgas_commit locally
* To debug without building docker image, expose 20000 port for `cb_signer` in `docker-compose.yml`
* Then run `docker compose -f docker-compose.yml up cb_signer` and separately run `export CB_MODULE_ID=ETHGAS_COMMIT && export CB_SIGNER_JWT=??? && export CB_SIGNER_URL="http://localhost:20000" && export CB_CONFIG="./config.toml" && cargo run --bin ethgas_commit`

## Audit
* The module has been audited by [Sigma Prime](https://sigmaprime.io/). Find the report [here](https://github.com/ethgas-developer/ethgas-audit)

## Acknowledgements
* [Commit-Boost](https://github.com/Commit-Boost/commit-boost-client)

## If you need help...
* [ETHGas Doc](https://docs.ethgas.com/)
* [ETHGas API Doc](https://developers.ethgas.com/)
* [ETHGas X / Twitter](https://x.com/ETHGASofficial)
* [Commit-Boost Doc](https://commit-boost.github.io/commit-boost-client/)
