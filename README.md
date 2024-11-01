## Overview
First and foremost, we would like to give a big shout out to the Commit-Boost team for making Ethereum a more open and cooperative environment! This repo allows you to run all Commit-Boost components related to ETHGas in Docker. There are 3 main components, i.e.
* `cb_pbs`: It serves a similar purpose as MEV-Boost. We slightly modify the original code to set ETHGas Relay as the default when multiple relays are available. This can avoid the situation that validators will be slashed because of signing a block without preconf. If ETHGas Relay is out of service, it will select the block from other relays.
* `cb_signer`: It securely generates signatures from the validator BLS private keys
* `cb_ethgas_commit`: It requests signatures for ETHGas registration from `cb_signer` which are then sent to the ETHGas Exchange via REST API

## Init
* install Rust
* run `cargo build`

## Config Setup
* Copy `config.example.toml` as `config.toml`
* Ensure some public values in `config.toml` are correct
    * `chain = Holesky` and `preconf_mode = true`
    * under `[[relays]]` section, `url` of `id = "ethgas"` is `http://0x...@relay.ethgas.com`
* Set validator BLS key directory or file in `config.toml`
    * under `[signer.loader]` section
    * if you use Lighthouse consensus client, set `keys_path = "/path/to/data_validator/validators"` and `secrets_path = "/path/to/data_validator/secrets"`
    * if you use other consensus client, copy `keys.example.json` as `keys.json` and put your validator BLS private keys inside, then set `key_path = "./keys.json"` in `config.toml`
    * remember `keys_path` and `secrets_path` are used together and cannot be used together with `key_path` (key without s)
* Set ETHGas Commit module config in `config.toml`
    * under `[[modules]]` section,
    * ensure `exchange_api_base = "https://uatapp.ethgas.com"`
    * set your `entity_name`
    * if `is_all_pubkey = true`, then all validator public keys inside keys directory or file will be registered in ETHGas Exchange. if `is_all_pubkey = false`, only the validator public key of `pubkey_id` will be registered
    * `pubkey_id` indicates either the starting id or the specific id depending on `is_all_pubkey`
    * since your EOA address is required to be registered in ETHGas Exchange by generating a EIP712 signature first, then your validator public key can be binded to your EOA address by generating a BLS signature. You will need to either set `eoa_signing_key` or you can refer to [our API doc](https://developers.ethgas.com/?python#post-api-user-login) to get jwt and set `is_jwt_provided = true` and `exchange_jwt`
* Set validator BLS key directory or file in `docker-compose.yml`
    * under `cb_signer` section
    * if `key_path` is set in `config.toml`, then set `CB_SIGNER_LOADER_FILE: /keys.json`
    * if `keys_path` and `secrets_path` are set in `config.toml`, then set `CB_SIGNER_LOADER_KEYS_DIR: /keys` and `CB_SIGNER_LOADER_SECRETS_DIR: /secrets`
* Run `export CB_MODULE_ID=ETHGAS_COMMIT && cargo run --bin gen_jwt` to generate new jwt for Commit-Boost signer module

## Start the ETHGas Commit module
* You can either use our pre-built docker image or run `docker build -t ghcr.io/ethgas-developer/commitboost_ethgas_commit:latest .` to build it locally
* Start the signer module first by running `docker-compose -f docker-compose.yml up cb_signer`
* Run `docker-compose -f docker-compose.yml up cb_ethgas_commit` to register in ETHGas Exchange
    * you will see the log `INFO successful registration, ETHGas Pricer will start to sell your block` if all goes well

## Start the modified PBS module
* You can either use our pre-built docker image or clone our forked version of [commit-boost-client](https://github.com/ethgas-developer/commit-boost-client.git) and run `./scripts/build_modified_pbs.sh` to build it locally
* Start the PBS module by running `docker-compose -f docker-compose.yml up cb_pbs`

## If you need help...
* [ETHGas Doc](https://docs.ethgas.com/)
* [ETHGas X / Twitter](https://x.com/ETHGASofficial)
* [Commit-Boost Doc](https://commit-boost.github.io/commit-boost-client/)