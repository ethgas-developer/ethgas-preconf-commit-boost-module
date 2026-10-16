mod support;
use serde_json::{Value, json};
use std::{path::Path, process::Stdio, time::Duration};
use support::*;
use tokio::process::Command;

fn module(base: &str) -> Value {
    json!({"id": "ETHGAS_COMMIT", "type": "commit", "docker_image": "test", "signing_id": format!("0x{}", "09".repeat(32)),
        "exchange_api_base": format!("{base}/mainnet"), "entity_name": "test", "registration_mode": "skipped",
        "enable_registration": true, "enable_ofac": true, "is_jwt_provided": true,
        "eoa_address": address().to_string(), "access_jwt": ACCESS, "refresh_jwt": REFRESH, "query_pubkey": false})
}

fn write_config(dir: &Path, base: &str, value: Value) -> std::path::PathBuf {
    let config = json!({"chain": "Mainnet", "signer": {"remote": {"url": base}}, "pbs": {"rpc_url": base},
        "relays": [{"id": "test", "url": format!("http://{}@127.0.0.1:1", pubkeys(1)[0])}], "modules": [value]});
    let path = dir.join("config.toml");
    std::fs::write(
        &path,
        toml::to_string(&toml::Value::try_from(config).unwrap()).unwrap(),
    )
    .unwrap();
    path
}

fn command(binary: &str, dir: &Path, config: &Path) -> Command {
    let mut command = Command::new(binary);
    command
        .current_dir(dir)
        .kill_on_drop(true)
        .env("CB_CONFIG", config)
        .env("CB_MODULE_ID", "ETHGAS_COMMIT")
        .env("CB_SIGNER_URL", "http://127.0.0.1:1")
        .env("CB_SIGNER_JWT", "test-signer-secret")
        .env("CB_LOGS_LEVEL", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in [
        "EOA_SIGNING_KEY",
        "ACCESS_JWT",
        "REFRESH_JWT",
        "CB_METRICS_PORT",
        "SSV_NODE_OPERATOR_OWNER_SIGNING_KEYS",
        "SSV_NODE_OPERATOR_OWNER_KEYSTORE_PATHS",
        "SSV_NODE_OPERATOR_OWNER_PASSWORD_PATHS",
        "OBOL_NODE_OPERATOR_OWNER_SIGNING_KEYS",
        "OBOL_NODE_OPERATOR_OWNER_KEYSTORE_PATHS",
        "OBOL_NODE_OPERATOR_OWNER_PASSWORD_PATHS",
    ] {
        command.env_remove(name);
    }
    command
}

async fn output(command: &mut Command) -> std::process::Output {
    tokio::time::timeout(Duration::from_secs(15), command.output())
        .await
        .expect("CLI timed out")
        .unwrap()
}

#[tokio::test]
async fn generated_secrets_have_expected_mapping_and_io_errors_are_visible() {
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_gen_jwt"));
    cmd.current_dir(dir.path())
        .env("CB_MODULE_ID", "ETHGAS_COMMIT");
    assert!(output(&mut cmd).await.status.success());
    let text = std::fs::read_to_string(dir.path().join(".cb.env")).unwrap();
    let values: std::collections::HashMap<_, _> = text
        .lines()
        .map(|line| line.split_once('=').unwrap())
        .collect();
    assert_eq!(values.len(), 3);
    assert_eq!(
        values["CB_JWTS"],
        format!("ETHGAS_COMMIT={}", values["CB_SIGNER_JWT"])
    );
    for key in ["CB_SIGNER_JWT", "CB_SIGNER_ADMIN_JWT"] {
        assert_eq!(values[key].len(), 32);
        assert!(values[key].bytes().all(|b| b.is_ascii_alphanumeric()));
    }
    let empty = tempfile::tempdir().unwrap();
    let mut missing = Command::new(env!("CARGO_BIN_EXE_gen_jwt"));
    missing.current_dir(empty.path()).env_remove("CB_MODULE_ID");
    let result = output(&mut missing).await;
    assert!(String::from_utf8_lossy(&result.stdout).contains("CB_MODULE_ID"));
    assert!(!empty.path().join(".cb.env").exists());
    std::fs::remove_file(dir.path().join(".cb.env")).unwrap();
    std::fs::create_dir(dir.path().join(".cb.env")).unwrap();
    assert!(!output(&mut cmd).await.status.success());
}

#[tokio::test]
async fn commit_cli_loads_config_login_or_supplied_tokens_and_runs_once() {
    let server = Server::new().await;
    for provided in [true, false] {
        for from_env in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let mut value = module(&server.url);
            value["is_jwt_provided"] = json!(provided);
            if !provided && !from_env {
                value["eoa_signing_key"] = json!(format!("0x{KEY}"));
            }
            if from_env {
                for field in ["access_jwt", "refresh_jwt"] {
                    value.as_object_mut().unwrap().remove(field);
                }
            }
            let config = write_config(dir.path(), &server.url, value);
            let mut cmd = command(env!("CARGO_BIN_EXE_ethgas_commit"), dir.path(), &config);
            if from_env {
                cmd.env("EOA_SIGNING_KEY", KEY)
                    .env("ACCESS_JWT", ACCESS)
                    .env("REFRESH_JWT", REFRESH);
            }
            let result = output(&mut cmd).await;
            assert!(
                result.status.success(),
                "stdout: {} stderr: {}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            assert!(!String::from_utf8_lossy(&result.stdout).contains(ACCESS));
        }
    }
    assert_eq!(server.calls("/api/v1/user/login/verify").len(), 2);
}

#[tokio::test]
async fn commit_cli_rejects_invalid_credentials_config_and_collateral() {
    let server = Server::new().await;
    let mut cases = Vec::new();
    for field in ["eoa_address", "access_jwt", "refresh_jwt"] {
        let mut value = module(&server.url);
        value.as_object_mut().unwrap().remove(field);
        cases.push(value);
    }
    for token in ["access_jwt", "refresh_jwt"] {
        let mut value = module(&server.url);
        value[token] = json!("");
        cases.push(value);
    }
    for amount in ["invalid", "0.001", "1001"] {
        let mut value = module(&server.url);
        value["collateral_per_slot"] = json!(amount);
        cases.push(value);
    }
    let mut value = module(&server.url);
    value["exchange_api_base"] = json!(&server.url);
    cases.push(value);
    let mut value = module(&server.url);
    value["is_jwt_provided"] = json!(false);
    cases.push(value.clone());
    value["eoa_signing_key"] = json!(format!("0x{KEY}"));
    value["eoa_ledger_path"] = json!("m/44'/60'/0'/0/0");
    cases.push(value);
    for value in cases {
        let dir = tempfile::tempdir().unwrap();
        let config = write_config(dir.path(), &server.url, value);
        let result = output(&mut command(
            env!("CARGO_BIN_EXE_ethgas_commit"),
            dir.path(),
            &config,
        ))
        .await;
        assert!(!result.status.success(), "invalid configuration accepted");
        assert!(
            !String::from_utf8_lossy(&result.stderr).contains("invalid key"),
            "fixture is not a TOML document"
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let mut value = module(&server.url);
    value["is_jwt_provided"] = json!(false);
    let config = write_config(dir.path(), &server.url, value);
    let mut cmd = command(env!("CARGO_BIN_EXE_ethgas_commit"), dir.path(), &config);
    cmd.env("EOA_SIGNING_KEY", "invalid");
    assert!(!output(&mut cmd).await.status.success());
    let mut cmd = command(env!("CARGO_BIN_EXE_ethgas_commit"), dir.path(), &config);
    cmd.env_remove("CB_MODULE_ID");
    assert!(!output(&mut cmd).await.status.success());
    std::fs::write(&config, "invalid toml").unwrap();
    assert!(
        !output(&mut command(
            env!("CARGO_BIN_EXE_ethgas_commit"),
            dir.path(),
            &config
        ))
        .await
        .status
        .success()
    );
    std::fs::remove_file(&config).unwrap();
    assert!(
        !output(&mut command(
            env!("CARGO_BIN_EXE_ethgas_commit"),
            dir.path(),
            &config
        ))
        .await
        .status
        .success()
    );
    assert!(server.calls("/api/v1/validator/register").is_empty());
}

#[tokio::test]
async fn repeated_runs_reload_config_without_reinitializing_metrics() {
    let server = Server::new().await;
    let dir = tempfile::tempdir().unwrap();
    let mut value = module(&server.url);
    value["overall_wait_interval_in_second"] = json!(1);
    value["enable_pricer"] = json!(true);
    let config = write_config(dir.path(), &server.url, value.clone());
    let child = command(env!("CARGO_BIN_EXE_ethgas_commit"), dir.path(), &config)
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while server.calls("/api/v1/user/delegate/pricer").is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    value["overall_wait_interval_in_second"] = json!(0);
    value["enable_pricer"] = json!(false);
    write_config(dir.path(), &server.url, value);
    let result = tokio::time::timeout(Duration::from_secs(10), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        result.status.success(),
        "stdout: {} stderr: {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let calls = server.calls("/api/v1/user/delegate/pricer");
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].query["enable"], "true");
    assert_eq!(calls[1].query["enable"], "false");
}

#[tokio::test]
async fn operator_environment_keys_and_keystores_validate_and_register() {
    let server = Server::new().await;
    let dir = tempfile::tempdir().unwrap();
    eth_keystore::encrypt_key(
        dir.path(),
        &mut rand::rng(),
        alloy::hex::decode(KEY).unwrap(),
        "password",
        Some("key.json"),
    )
    .unwrap();
    let password = dir.path().join("password.txt");
    std::fs::write(&password, "password\n").unwrap();
    for mode in ["ssv", "obol"] {
        let prefix = format!("{}_NODE_OPERATOR_OWNER_", mode.to_uppercase());
        let mut value = module(&server.url);
        value["registration_mode"] = json!(mode);
        value[format!("{mode}_node_operator_owner_validator_pubkeys")] = json!([pubkeys(1)]);
        for (key, expected) in [
            (format!(" {KEY}, "), true),
            ("invalid".into(), false),
            (" , ".into(), false),
        ] {
            value[format!("{mode}_node_operator_owner_mode")] = json!("key");
            let config = write_config(dir.path(), &server.url, value.clone());
            let mut cmd = command(env!("CARGO_BIN_EXE_ethgas_commit"), dir.path(), &config);
            cmd.env(format!("{prefix}SIGNING_KEYS"), key);
            let before = server
                .calls(&format!("/api/v1/user/{mode}/operator/register"))
                .len();
            let result = output(&mut cmd).await;
            assert!(
                result.status.success(),
                "stdout: {} stderr: {}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            // Service errors are currently logged by the outer CLI; verify side effects.
            assert_eq!(
                server
                    .calls(&format!("/api/v1/user/{mode}/operator/register"))
                    .len()
                    - before,
                usize::from(expected)
            );
        }
        value[format!("{mode}_node_operator_owner_mode")] = json!("keystore");
        for (paths, passwords, expected) in [
            (
                dir.path().join("key.json").to_string_lossy().into_owned(),
                password.to_string_lossy().into_owned(),
                true,
            ),
            ("one,two".into(), "one".into(), false),
            ("".into(), "".into(), false),
            (
                "missing".into(),
                password.to_string_lossy().into_owned(),
                false,
            ),
        ] {
            let config = write_config(dir.path(), &server.url, value.clone());
            let mut cmd = command(env!("CARGO_BIN_EXE_ethgas_commit"), dir.path(), &config);
            cmd.env(format!("{prefix}KEYSTORE_PATHS"), paths)
                .env(format!("{prefix}PASSWORD_PATHS"), passwords);
            let before = server
                .calls(&format!("/api/v1/user/{mode}/operator/register"))
                .len();
            let result = output(&mut cmd).await;
            assert!(
                result.status.success(),
                "stdout: {} stderr: {}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(
                server
                    .calls(&format!("/api/v1/user/{mode}/operator/register"))
                    .len()
                    - before,
                usize::from(expected)
            );
        }
    }
}

#[tokio::test]
async fn deposit_cli_completes_with_config_or_environment_key_and_rejects_bad_inputs() {
    let exchange = Server::with_responder(funding_reply).await;
    let rpc = Server::with_responder(rpc_reply).await;
    let base = json!({"id": "ETHGAS_COMMIT", "type": "commit", "docker_image": "test", "signing_id": format!("0x{}", "09".repeat(32)),
        "exchange_api_base": exchange.url, "block_confirmation": 0, "collateral_to_be_deposited": "0.01",
        "collateral_contract": alloy::primitives::Address::ZERO});
    for from_env in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut value = base.clone();
        if !from_env {
            value["eoa_signing_key"] = json!(format!("0x{KEY}"));
        }
        let config = write_config(dir.path(), &rpc.url, value);
        let mut cmd = command(env!("CARGO_BIN_EXE_ethgas_deposit"), dir.path(), &config);
        if from_env {
            cmd.env("EOA_SIGNING_KEY", KEY);
        }
        let result = output(&mut cmd).await;
        assert!(
            result.status.success(),
            "{} {}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    }
    assert_eq!(
        exchange.calls("/api/v1/user/account/transfer/token").len(),
        2
    );
    for amount in ["invalid", "0.001", "-1"] {
        let dir = tempfile::tempdir().unwrap();
        let mut value = base.clone();
        value["eoa_signing_key"] = json!(format!("0x{KEY}"));
        value["collateral_to_be_deposited"] = json!(amount);
        let config = write_config(dir.path(), &rpc.url, value);
        assert!(
            !output(&mut command(
                env!("CARGO_BIN_EXE_ethgas_deposit"),
                dir.path(),
                &config
            ))
            .await
            .status
            .success()
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), &rpc.url, base);
    assert!(
        !output(&mut command(
            env!("CARGO_BIN_EXE_ethgas_deposit"),
            dir.path(),
            &config
        ))
        .await
        .status
        .success()
    );
    let mut cmd = command(env!("CARGO_BIN_EXE_ethgas_deposit"), dir.path(), &config);
    cmd.env("EOA_SIGNING_KEY", "invalid");
    assert!(!output(&mut cmd).await.status.success());
    std::fs::write(&config, "invalid toml").unwrap();
    assert!(
        !output(&mut command(
            env!("CARGO_BIN_EXE_ethgas_deposit"),
            dir.path(),
            &config
        ))
        .await
        .status
        .success()
    );
    assert_eq!(
        exchange.calls("/api/v1/user/account/transfer/token").len(),
        2
    );
}

#[tokio::test]
async fn environment_keystores_reject_invalid_scalars_and_corrupt_files() {
    let server = Server::new().await;
    let dir = tempfile::tempdir().unwrap();
    eth_keystore::encrypt_key(
        dir.path(),
        &mut rand::rng(),
        [0u8; 32],
        "password",
        Some("zero.json"),
    )
    .unwrap();
    let password = dir.path().join("password.txt");
    std::fs::write(&password, "password").unwrap();
    for mode in ["ssv", "obol"] {
        let prefix = format!("{}_NODE_OPERATOR_OWNER_", mode.to_uppercase());
        let mut value = module(&server.url);
        value["registration_mode"] = json!(mode);
        value[format!("{mode}_node_operator_owner_mode")] = json!("keystore");
        value[format!("{mode}_node_operator_owner_validator_pubkeys")] = json!([pubkeys(1)]);
        let config = write_config(dir.path(), &server.url, value);
        let mut cmd = command(env!("CARGO_BIN_EXE_ethgas_commit"), dir.path(), &config);
        cmd.env(
            format!("{prefix}KEYSTORE_PATHS"),
            dir.path().join("zero.json"),
        )
        .env(format!("{prefix}PASSWORD_PATHS"), &password);
        let result = output(&mut cmd).await;
        assert!(String::from_utf8_lossy(&result.stdout).contains("Failed to create signer"));
        std::fs::write(dir.path().join("corrupt.json"), "not a keystore").unwrap();
        cmd.env(
            format!("{prefix}KEYSTORE_PATHS"),
            dir.path().join("corrupt.json"),
        );
        let result = output(&mut cmd).await;
        assert!(String::from_utf8_lossy(&result.stdout).contains("Failed to read keystore"));
        assert!(
            server
                .calls(&format!("/api/v1/user/{mode}/operator/register"))
                .is_empty()
        );
    }
}

#[tokio::test]
async fn cli_retries_login_failures_and_rejects_invalid_pbs_configuration() {
    for binary in [
        env!("CARGO_BIN_EXE_ethgas_commit"),
        env!("CARGO_BIN_EXE_ethgas_deposit"),
    ] {
        let server = Server::new().await;
        let dir = tempfile::tempdir().unwrap();
        let value = if binary.ends_with("ethgas_commit") {
            let mut value = module(&server.url);
            value["is_jwt_provided"] = json!(false);
            value["eoa_signing_key"] = json!(format!("0x{KEY}"));
            value
        } else {
            json!({"id": "ETHGAS_COMMIT", "type": "commit", "docker_image": "test", "signing_id": format!("0x{}", "09".repeat(32)),
            "exchange_api_base": server.url, "block_confirmation": 0, "collateral_to_be_deposited": "0.01", "collateral_contract": alloy::primitives::Address::ZERO, "eoa_signing_key": format!("0x{KEY}")})
        };
        server.reply("/api/v1/user/login", Reply::json(json!({"success": false, "data": {"eip712Message": challenge("Ethgas Login", false)}})));
        let config = write_config(dir.path(), &server.url, value);
        let result = output(&mut command(binary, dir.path(), &config)).await;
        assert!(!result.status.success());
        assert_eq!(server.calls("/api/v1/user/login").len(), 6);
        let mut document: toml::Value = std::fs::read_to_string(&config).unwrap().parse().unwrap();
        document["pbs"]["rpc_url"] = toml::Value::String("http://127.0.0.1:0".into());
        std::fs::write(&config, toml::to_string(&document).unwrap()).unwrap();
        let result = output(&mut command(binary, dir.path(), &config)).await;
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stdout).contains("Failed to load pbs config"));
    }
}

#[tokio::test]
async fn mux_registration_selects_only_ethgas_mux_keys() {
    for register in [true, false] {
        let server = Server::new().await;
        let dir = tempfile::tempdir().unwrap();
        let keys = pubkeys(5);
        let mut value = module(&server.url);
        value["registration_mode"] = json!("standard-mux");
        value["enable_registration"] = json!(register);
        let config = write_config(dir.path(), &server.url, value);
        let mut document: toml::Value = std::fs::read_to_string(&config).unwrap().parse().unwrap();
        let muxes = json!([
            {"id": "ethgas_mux", "validator_pubkeys": [keys[0]], "relays": [{"id": "other", "url": format!("http://{}@127.0.0.1:1", keys[0])}]},
            {"id": "other_mux", "validator_pubkeys": [keys[1]], "relays": [{"id": "ethgas_relay", "url": format!("http://{}@127.0.0.1:1", keys[0])}]},
            {"id": "unrelated", "validator_pubkeys": [keys[2]], "relays": [{"id": "other", "url": format!("http://{}@127.0.0.1:1", keys[0])}]},
            {"id": "ETHGAS_MUX", "validator_pubkeys": [keys[3]], "relays": [{"id": "other", "url": format!("http://{}@127.0.0.1:1", keys[0])}]},
            {"id": "custom_EtHgAs_mux", "validator_pubkeys": [keys[4]], "relays": [{"id": "other", "url": format!("http://{}@127.0.0.1:1", keys[0])}]}
        ]);
        document
            .as_table_mut()
            .unwrap()
            .insert("mux".into(), toml::Value::try_from(muxes).unwrap());
        std::fs::write(&config, toml::to_string(&document).unwrap()).unwrap();
        let mut cmd = command(env!("CARGO_BIN_EXE_ethgas_commit"), dir.path(), &config);
        cmd.env("CB_SIGNER_URL", &server.url);
        let result = output(&mut cmd).await;
        assert!(
            result.status.success(),
            "{} {}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        let path = if register {
            "/api/v1/validator/verify/batch2"
        } else {
            "/api/v1/validator/deregister"
        };
        let calls = server.calls(path);
        assert_eq!(calls.len(), 1);
        let selected: std::collections::HashSet<_> = calls[0].form()["publicKeys"]
            .split(',')
            .map(str::to_owned)
            .collect();
        assert_eq!(
            selected,
            [0, 3, 4].iter().map(|&index| keys[index].to_string()).collect()
        );
        let signatures = server.calls("/signer/v1/request_signature/bls");
        assert_eq!(signatures.len(), if register { selected.len() } else { 0 });
        if register {
            let signed: std::collections::HashSet<_> = signatures
                .iter()
                .map(|request| {
                    let body: Value = serde_json::from_str(&request.body).unwrap();
                    body["pubkey"].as_str().unwrap().to_owned()
                })
                .collect();
            assert_eq!(signed, selected);
        }
    }
}

#[tokio::test]
async fn missing_password_and_deposit_rpc_configuration_are_visible_errors() {
    let server = Server::new().await;
    let dir = tempfile::tempdir().unwrap();
    for mode in ["ssv", "obol"] {
        let mut value = module(&server.url);
        value["registration_mode"] = json!(mode);
        value[format!("{mode}_node_operator_owner_mode")] = json!("keystore");
        value[format!("{mode}_node_operator_owner_validator_pubkeys")] = json!([pubkeys(1)]);
        let config = write_config(dir.path(), &server.url, value);
        let mut cmd = command(env!("CARGO_BIN_EXE_ethgas_commit"), dir.path(), &config);
        let prefix = format!("{}_NODE_OPERATOR_OWNER_", mode.to_uppercase());
        cmd.env(format!("{prefix}KEYSTORE_PATHS"), "unused").env(
            format!("{prefix}PASSWORD_PATHS"),
            dir.path().join("missing-password"),
        );
        let result = output(&mut cmd).await;
        assert!(String::from_utf8_lossy(&result.stdout).contains("No such file"));
        assert!(
            server
                .calls(&format!("/api/v1/user/{mode}/operator/register"))
                .is_empty()
        );
    }
    let value = json!({"id": "ETHGAS_COMMIT", "type": "commit", "docker_image": "test", "signing_id": format!("0x{}", "09".repeat(32)),
        "exchange_api_base": server.url, "block_confirmation": 0, "collateral_to_be_deposited": "0.01", "collateral_contract": alloy::primitives::Address::ZERO, "eoa_signing_key": format!("0x{KEY}")});
    let config = write_config(dir.path(), &server.url, value);
    let mut document: toml::Value = std::fs::read_to_string(&config).unwrap().parse().unwrap();
    document["pbs"].as_table_mut().unwrap().remove("rpc_url");
    std::fs::write(&config, toml::to_string(&document).unwrap()).unwrap();
    let result = output(&mut command(
        env!("CARGO_BIN_EXE_ethgas_deposit"),
        dir.path(),
        &config,
    ))
    .await;
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("Failed to get RPC URL"));
}
