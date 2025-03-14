## Overview
First and foremost, we would like to give a big shout out to the Commit-Boost team for making Ethereum a more open and cooperative environment! This repo allows you to run all Commit-Boost components related to ETHGas in Docker. There are 3 main components, i.e.
* `cb_pbs`: It serves a similar purpose as MEV-Boost. To avoid validators being slashed because of signing a block without preconf, please only set relays that are approved by ETHGas.
* `cb_signer`: It securely generates signatures from the validator BLS private keys
* `cb_ethgas_commit`: It requests signatures for ETHGas registration from `cb_signer` which are then sent to the ETHGas Exchange via REST API

## Config Setup
* Copy one of the `config.example.xxx.toml` as `config.toml`
* Copy `docker-compose-example.yml` as `docker-compose.yml`
* Create an empty `.cb.env` file and run `docker-compose -f docker-compose.yml up cb_gen_jwt` to generate new jwt for the signer module
* For local signer module, Commit Boost supports Lighthouse, Prysm, Teku and Lodestar's keystores. Please refer to [here](https://commit-boost.github.io/commit-boost-client/get_started/configuration#local-signer) for more details
    * `format`, `keys_path` and `secrets_path` are used together and cannot be used together with `key_path` (key without s)
* For remote signer module, Commit Boost supports Web3Signer. Please refer to [here](https://commit-boost.github.io/commit-boost-client/get_started/configuration#remote-signer) for more details
* Set ETHGas Commit module config in `config.toml`
    * under `[[modules]]` section,
    * set your `entity_name`
    * set `enable_registration = true` to register validators in ETHGas, set `enable_registration = false` to de-register validators
    * By default, all validator public keys inside keys directory or file will be registered in ETHGas Exchange. If `[[mux]]` section with `id` under `[[mux.relays]]` contains `ethgas` wording in the config, then only those `validator_pubkeys` will be registered.
    * since your EOA address is required to be registered in ETHGas Exchange by generating a EIP712 signature first, then your validator public key can be binded to your EOA address by generating a BLS signature. You will need to either set `is_jwt_provided = false` and `eoa_signing_key` in `config.toml` or you can refer to [our API doc](https://developers.ethgas.com/?python#post-api-user-login) to get jwt and set `is_jwt_provided = true` and `exchange_jwt` in `config.toml` 
        * Alternatively, you can set `EOA_SIGNING_KEY` or `EXCHANGE_JWT` as env variables in `.cb.env`
    * set `enable_pricer = true` if you want to delegate the default pricer to help you to sell preconfs
    * set `enable_builder = true` and `builder_pubkey` if you want to delegate to a specific external builder to build the block. Regardless of whether the builder delegation is enabled or not, our fallback builder will always build a backup block which can fulfill all the preconf commitments
    * `wait_interval_in_second` indicates the waiting time before re-running the module, set it as `0` to stop re-running the module
    * The config is reloaded before every re-run of the module
* Set validator BLS key directory or file in `docker-compose.yml`
    * under `cb_signer` section
    * if `key_path` is set in `config.toml`, then set `CB_SIGNER_LOADER_FILE: /keys.json`
    * if `keys_path` and `secrets_path` are set in `config.toml`, then set `CB_SIGNER_LOADER_KEYS_DIR: /keys` and `CB_SIGNER_LOADER_SECRETS_DIR: /secrets`
    * mount the correct validator keystore directories from the host machine to the container `/keys` and `/secrets` directory

## Build docker images
* For `cb_ethgas_commit` and `cb_gen_jwt`, you can either use our pre-built linux/amd64 or linux/arm64 docker image or run `./scripts/build.sh` to build it locally
* For `cb_signer` and `cb_pbs`, you can either use the official image from Commit Boost team or run [this script](https://github.com/Commit-Boost/commit-boost-client/blob/main/scripts/build_local_images.sh) to build it locally

## Start the Signer module
* Run `docker-compose -f docker-compose.yml up cb_signer`

## Start the ETHGas Commit module
* Run `docker-compose -f docker-compose.yml up cb_ethgas_commit` to register in ETHGas Exchange
    * you will see the log `INFO successful registration, you can now sell preconfs on ETHGas!` or `INFO successful registration, the default pricer can now sell preconfs on ETHGas on behalf of you!` if all goes well
    * if the module encounters `ConnectionRefused` error when it tries to connect to `http://cb_signer:20000/signer/v1/get_pubkeys`, please wait for 20 minutes to retry

## Start the PBS module
* Start the PBS module by running `docker-compose -f docker-compose.yml up cb_pbs`
* update builder/relay config of your beacon node from pointing towards MEV-Boost to `cb_pbs` endpoint where the port is `18550` by default
    * you will see the log `DEBUG register_validators{req_id=...}:handler{relay_id="ethgas"}: registration successful code=200 latency=...ms` if all goes well

## Debug cb_ethgas_commit locally
* To debug without building docker image, expose 20000 port for `cb_signer` in `docker-compose.yml`, uncomment `tracing-subscriber = "0.2"` in `Cargo.toml` and comment/uncomment relevant code in `bin/ethgas_commit.rs` according to the example below
```
use tracing_subscriber::FmtSubscriber;
...
// let _guard = initialize_tracing_log(&config.id)?;
let subscriber = FmtSubscriber::builder().finish();
tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
```
* Then run `docker-compose -f docker-compose.yml up cb_signer` and separately run `export CB_MODULE_ID=ETHGAS_COMMIT && export CB_SIGNER_JWT=??? && export CB_SIGNER_URL="http://localhost:20000" && export CB_CONFIG="./config.toml" && cargo run --bin ethgas_commit`


## If you need help...
* [ETHGas Doc](https://docs.ethgas.com/)
* [ETHGas X / Twitter](https://x.com/ETHGASofficial)
* [Commit-Boost Doc](https://commit-boost.github.io/commit-boost-client/)