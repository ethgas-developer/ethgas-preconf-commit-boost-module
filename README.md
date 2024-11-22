## Overview
First and foremost, we would like to give a big shout out to the Commit-Boost team for making Ethereum a more open and cooperative environment! This repo allows you to run all Commit-Boost components related to ETHGas in Docker. There are 3 main components, i.e.
* `cb_pbs`: It serves a similar purpose as MEV-Boost. To avoid validators being slashed because of signing a block without preconf, please only set relays that are approved by ETHGas.
* `cb_signer`: It securely generates signatures from the validator BLS private keys
* `cb_ethgas_commit`: It requests signatures for ETHGas registration from `cb_signer` which are then sent to the ETHGas Exchange via REST API

## Config Setup
* Copy `config.example.toml` as `config.toml`
* Ensure some public values in `config.toml` are correct
    * `chain = Holesky` and `preconf_mode = true`
    * under `[[relays]]` section, `url` of `id = "ethgas"` is `https://0xb20c3fe59db9c3655088839ef3d972878d182eb745afd8abb1dd2abf6c14f93cd5934ed4446a5fe1ba039e2bc0cf1011@testnet-relay.ethgas.com`
* Set validator BLS key directory or file in `config.toml`
    * under `[signer.loader]` section
    * if you use Lighthouse consensus client, set `keys_path = "/path/to/data_validator/validators"` and `secrets_path = "/path/to/data_validator/secrets"`
        * ensure the name of all keystore files under `/path/to/data_validator/validators/0x...` are `voting-keystore.json`
    * if you use other consensus client, copy `keys.example.json` as `keys.json` and put your validator BLS private keys inside, then set `key_path = "./keys.json"` in `config.toml`
    * remember `keys_path` and `secrets_path` are used together and cannot be used together with `key_path` (key without s)
* Set ETHGas Commit module config in `config.toml`
    * under `[[modules]]` section,
    * ensure `exchange_api_base = "https://testnetapp.ethgas.com"`
    * set your `entity_name`
    * if `is_all_pubkey = true`, then all validator public keys inside keys directory or file will be registered in ETHGas Exchange. if `is_all_pubkey = false`, only the validator public key of `pubkey_id` will be registered
    * `pubkey_id` indicates either the start id or the specific id depending on `is_all_pubkey`
    * `pubkey_end_id` indicates the end id if you only want to register some of the validator public keys
    * since your EOA address is required to be registered in ETHGas Exchange by generating a EIP712 signature first, then your validator public key can be binded to your EOA address by generating a BLS signature. You will need to either set `eoa_signing_key` or you can refer to [our API doc](https://developers.ethgas.com/?python#post-api-user-login) to get jwt and set `is_jwt_provided = true` and `exchange_jwt`
* Set validator BLS key directory or file in `docker-compose.yml`
    * under `cb_signer` section
    * if `key_path` is set in `config.toml`, then set `CB_SIGNER_LOADER_FILE: /keys.json`
    * if `keys_path` and `secrets_path` are set in `config.toml`, then set `CB_SIGNER_LOADER_KEYS_DIR: /keys` and `CB_SIGNER_LOADER_SECRETS_DIR: /secrets`

## Build docker images
* For `cb_ethgas_commit` and `cb_gen_jwt`, you can either use our pre-built linux/amd64 or linux/arm64 docker image or run `./scripts/build.sh` to build it locally
* For `cb_signer` and `cb_pbs`, you can either use the official image from Commit Boost team or run [this script](https://github.com/Commit-Boost/commit-boost-client/blob/main/scripts/build_local_images.sh) to build it locally

## Start the Signer module
* Create an empty `.cb.env` file and run `docker-compose -f docker-compose.yml up cb_gen_jwt` to generate new jwt for the signer module
* Run `docker-compose -f docker-compose.yml up cb_signer`

## Start the ETHGas Commit module
* Run `docker-compose -f docker-compose.yml up cb_ethgas_commit` to register in ETHGas Exchange
    * you will see the log `INFO successful registration, you can now sell preconfs on ETHGas!` if all goes well
    * if the module encounters `ConnectionRefused` error when it tries to connect to `http://cb_signer:20000/signer/v1/get_pubkeys`, please wait for 20 minutes to retry

## Start the PBS module
* Start the PBS module by running `docker-compose -f docker-compose.yml up cb_pbs`
* update builder/relay config of your beacon node from pointing towards MEV-Boost to `cb_pbs` endpoint where the port is `18550` by default

## If you need help...
* [ETHGas Doc](https://docs.ethgas.com/)
* [ETHGas X / Twitter](https://x.com/ETHGASofficial)
* [Commit-Boost Doc](https://commit-boost.github.io/commit-boost-client/)