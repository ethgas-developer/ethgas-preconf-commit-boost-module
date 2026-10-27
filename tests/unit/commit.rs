use super::*;
use commit_boost::prelude::commit::client::SignerClient;
use serde_json::{Value, json};

#[path = "../support/mod.rs"]
mod support;
use support::*;

fn extra(base: &str, mode: &str) -> Value {
    json!({"exchange_api_base": base, "entity_name": "test", "registration_mode": mode,
        "enable_registration": true, "enable_ofac": true, "is_jwt_provided": true, "query_pubkey": false, "enable_pricer": false, "enable_builder": false, "overall_wait_interval_in_second": 0, "collateral_per_slot": "0"})
}

fn service(server: &Server, value: Value) -> EthgasCommitService {
    EthgasCommitService {
        config: StartCommitModuleConfig {
            id: serde_json::from_value(json!("ETHGAS_COMMIT")).unwrap(),
            chain: Chain::Mainnet,
            signer_client: SignerClient::new(
                server.url.parse().unwrap(),
                serde_json::from_value(json!("test-signer-secret")).unwrap(),
                serde_json::from_value(json!("ETHGAS_COMMIT")).unwrap(),
            )
            .unwrap(),
            extra: serde_json::from_value(value).unwrap(),
        },
        access_jwt: ACCESS.into(),
        refresh_jwt: REFRESH.into(),
        mux_pubkeys: Vec::new(),
    }
}

fn operator_extra(server: &Server, mode: &str, count: usize) -> Value {
    let mut value = extra(&server.url, mode);
    value[format!("{mode}_node_operator_owner_mode")] = json!("key");
    value[format!("{mode}_node_operator_owner_signing_keys")] = json!([format!("0x{KEY}")]);
    value[format!("{mode}_node_operator_owner_validator_pubkeys")] = json!([pubkeys(count)]);
    value
}

#[tokio::test]
async fn encrypted_keystores_and_invalid_passwords_are_handled() {
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
    std::fs::write(&password, "password").unwrap();
    for mode in ["ssv", "obol"] {
        let server = Server::new().await;
        let mut value = operator_extra(&server, mode, 1);
        value[format!("{mode}_node_operator_owner_mode")] = json!("keystore");
        value[format!("{mode}_node_operator_owner_keystores")] =
            json!([{"keystore_path": dir.path().join("key.json"), "password_path": password}]);
        service(&server, value.clone()).run().await.unwrap();
        assert_eq!(
            server
                .calls(&format!("/api/v1/user/{mode}/operator/register"))
                .len(),
            1
        );
        std::fs::write(&password, "wrong").unwrap();
        let before = server.requests().len();
        assert!(service(&server, value.clone()).run().await.is_err());
        assert_eq!(server.requests().len(), before + 2);
        std::fs::write(&password, "password").unwrap();
        value[format!("{mode}_node_operator_owner_keystores")][0]["keystore_path"] =
            json!(dir.path().join("missing"));
        assert!(service(&server, value).run().await.is_err());
    }
}

#[tokio::test]
async fn operator_registration_and_deregistration_cover_empty_and_chunked_keys() {
    for mode in ["ssv", "obol"] {
        for register in [true, false] {
            for count in [0usize, 1, 35, 36] {
                let server = Server::new().await;
                let mut value = operator_extra(&server, mode, count);
                value["enable_registration"] = json!(register);
                value["enable_light_mode"] = json!(true);
                value[format!("{mode}_node_operator_owner_payout_addresses")] = json!([address()]);
                service(&server, value).run().await.unwrap();
                let operation = if register { "register" } else { "deregister" };
                let calls = server.calls(&format!(
                    "/api/v1/user/{mode}/operator/validator/{operation}"
                ));
                assert_eq!(
                    calls.len(),
                    if mode == "ssv" {
                        count.div_ceil(35).max(1)
                    } else {
                        1
                    }
                );
                if count == 0 {
                    assert!(!calls[0].query.contains_key("publicKeys"));
                }
                for r in &calls {
                    assert_eq!(r.headers["authorization"], format!("Bearer {ACCESS}"));
                }
                assert_eq!(
                    server
                        .calls(&format!("/api/v1/user/{mode}/operator/verify"))
                        .len(),
                    1
                );
                let payout = server.calls(&format!(
                    "/api/v1/user/{mode}/operator/validator/update/validatorPayoutAddress"
                ));
                if register {
                    assert_eq!(payout.len(), calls.len());
                } else {
                    assert!(payout.is_empty());
                }
            }
        }
    }
}

#[tokio::test]
async fn operator_configuration_errors_and_failed_verification_stop_registration() {
    for mode in ["ssv", "obol"] {
        let server = Server::new().await;
        let prefix = format!("{mode}_node_operator_owner_");
        let mut cases = Vec::new();
        for field in ["validator_pubkeys", "mode", "signing_keys"] {
            let mut value = operator_extra(&server, mode, 1);
            value
                .as_object_mut()
                .unwrap()
                .remove(&format!("{prefix}{field}"));
            cases.push(value);
        }
        for field in ["signing_keys", "validator_pubkeys", "payout_addresses"] {
            let mut value = operator_extra(&server, mode, 1);
            value[format!("{prefix}{field}")] = json!([]);
            cases.push(value);
        }
        let mut invalid = operator_extra(&server, mode, 1);
        invalid[format!("{prefix}signing_keys")] = json!([format!("{:#x}", B256::ZERO)]);
        cases.push(invalid);
        for owner_mode in ["invalid", "keystore", "ledger"] {
            let mut value = operator_extra(&server, mode, 1);
            value[format!("{prefix}mode")] = json!(owner_mode);
            cases.push(value);
        }
        for paths in [json!([]), json!(["one", "two"])] {
            let mut value = operator_extra(&server, mode, 1);
            value[format!("{prefix}mode")] = json!("ledger");
            value[format!("{prefix}ledger_paths")] = paths;
            cases.push(value);
        }
        for value in cases {
            assert!(
                service(&server, value).run().await.is_err(),
                "accepted invalid {mode} config"
            );
        }
        for suffix in ["register", "verify"] {
            for response in [
                Reply::json(
                    json!({"success": false, "data": {"available": true}, "errorMsgKey": "rejected"}),
                ),
                Reply::invalid(),
            ] {
                let server = Server::new().await;
                server.reply(&format!("/api/v1/user/{mode}/operator/{suffix}"), response);
                let failed = service(&server, operator_extra(&server, mode, 1))
                    .run()
                    .await
                    .is_err();
                assert_eq!(failed, suffix == "register");
                assert_eq!(
                    server
                        .calls(&format!("/api/v1/user/{mode}/operator/validator/register"))
                        .len(),
                    usize::from(suffix == "verify")
                );
            }
        }
    }
}

#[tokio::test]
async fn operator_response_variants_and_transaction_verification() {
    for mode in ["ssv", "obol"] {
        for register in [true, false] {
            for response in [
                json!({"success": true, "data": {"added": null, "validators": null, "removed": null}}),
                json!({"success": true, "data": {"added": [], "validators": [], "removed": []}}),
                json!({"success": false, "data": {}, "errorMsgKey": "rejected"}),
                json!(null),
            ] {
                let server = Server::new().await;
                server.reply(
                    &format!("/api/v1/user/{mode}/operator/register"),
                    Reply::json(json!({"success": true, "data": {"available": false}})),
                );
                let op = if register { "register" } else { "deregister" };
                server.reply(
                    &format!("/api/v1/user/{mode}/operator/validator/{op}"),
                    Reply::json(response),
                );
                if mode == "obol" {
                    server.reply(
                        "/api/v1/user/obol/operator/refresh",
                        Reply::json(json!({"success": false})),
                    );
                }
                let mut value = operator_extra(&server, mode, 1);
                value["enable_registration"] = json!(register);
                service(&server, value).run().await.unwrap();
                assert!(
                    server
                        .calls(&format!("/api/v1/user/{mode}/operator/verify"))
                        .is_empty()
                );
                assert!(
                    server
                        .calls(&format!(
                            "/api/v1/user/{mode}/operator/validator/update/ofac"
                        ))
                        .is_empty()
                );
            }
        }
    }
    for reply in [
        Reply::json(json!({"success": true})),
        Reply::json(json!({"success": false, "errorMsgKey": "error.ssv.operator.registered"})),
        Reply::json(json!({"success": false, "errorMsgKey": "rejected"})),
        Reply::invalid(),
    ] {
        let server = Server::new().await;
        server.reply("/api/v1/user/ssv/operator/verifyByTx", reply.clone());
        let mut value = operator_extra(&server, "ssv", 1);
        value["ssv_node_operator_owner_mode"] = json!("tx");
        value["ssv_node_operator_owner_tx_hashes"] = json!(["0x123"]);
        value["ssv_node_operator_owner_tx_from_addr"] = json!([address()]);
        service(&server, value.clone()).run().await.unwrap();
        for field in [
            "ssv_node_operator_owner_tx_hashes",
            "ssv_node_operator_owner_tx_from_addr",
        ] {
            let mut bad = value.clone();
            bad.as_object_mut().unwrap().remove(field);
            assert!(service(&server, bad).run().await.is_err());
            let mut bad = value.clone();
            bad[field] = json!([]);
            assert!(service(&server, bad).run().await.is_err());
        }
        value["ssv_node_operator_owner_tx_from_addr"] = json!([address(), address()]);
        assert!(service(&server, value).run().await.is_err());
    }
}

#[tokio::test]
async fn keystores_with_invalid_scalar_cannot_register_operators() {
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
        let server = Server::new().await;
        let mut value = operator_extra(&server, mode, 1);
        value[format!("{mode}_node_operator_owner_mode")] = json!("keystore");
        value[format!("{mode}_node_operator_owner_keystores")] =
            json!([{"keystore_path": dir.path().join("zero.json"), "password_path": password}]);
        assert!(
            service(&server, value)
                .run()
                .await
                .unwrap_err()
                .to_string()
                .contains("signer")
        );
        assert!(
            server
                .calls(&format!("/api/v1/user/{mode}/operator/register"))
                .is_empty()
        );
    }
}

#[test]
fn legacy_required_settings_remain_required() {
    let value = extra("http://localhost", "skipped");
    let config: ExtraConfig = serde_json::from_value(value.clone()).unwrap();
    assert!(!config.enable_pricer && !config.enable_builder && !config.query_pubkey);
    for field in [
        "enable_pricer",
        "enable_builder",
        "query_pubkey",
        "collateral_per_slot",
        "overall_wait_interval_in_second",
    ] {
        let mut invalid = value.clone();
        invalid.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<ExtraConfig>(invalid).is_err(),
            "{field}"
        );
    }
}

#[tokio::test]
async fn builder_and_settings_preserve_required_update_behavior() {
    for enabled in [false, true] {
        for key in [false, true] {
            for reply in [
                Reply::json(json!({"success": true})),
                Reply::json(json!({"success": false})),
                Reply::invalid(),
            ] {
                let server = Server::with_responder(move |_| reply.clone()).await;
                let mut value = extra(&server.url, "skipped");
                value["enable_builder"] = json!(enabled);
                value["enable_pricer"] = json!(enabled);
                if key {
                    value["builder_pubkey"] = json!(pubkeys(1)[0]);
                }
                assert_eq!(
                    service(&server, value).run().await.is_err(),
                    enabled && !key
                );
                assert_eq!(
                    server.calls("/api/v1/user/delegate/builder").len(),
                    usize::from(key)
                );
                assert_eq!(
                    server.calls("/api/v1/user/delegate/pricer").len(),
                    usize::from(!enabled || key)
                );
            }
        }
    }
}

#[tokio::test]
async fn standard_registration_uses_legacy_signing_and_batch_api() {
    for mode in ["standard", "standard-mux"] {
        for register in [true, false] {
            for count in [0usize, 1, 99, 100, 101, 201] {
                let keys = pubkeys(count);
                let server = Server::new().await;
                server.reply("/signer/v1/get_pubkeys", Reply::json(json!({"keys": keys.iter().map(|key| json!({"consensus": key, "proxy_bls": [], "proxy_ecdsa": []})).collect::<Vec<_>>()})));
                let mut value = extra(&server.url, mode);
                value["enable_registration"] = json!(register);
                value["payout_address"] = json!(address());
                let mut module = service(&server, value);
                if mode == "standard-mux" {
                    module.mux_pubkeys = keys.clone();
                }
                module.run().await.unwrap();
                let path = if register {
                    "/api/v1/validator/verify/batch"
                } else {
                    "/api/v1/validator/deregister"
                };
                let batches = server.calls(path);
                assert_eq!(batches.len(), count.div_ceil(100));
                let submitted = batches
                    .iter()
                    .flat_map(|r| {
                        r.form()["publicKeys"]
                            .split(',')
                            .map(str::to_string)
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();
                assert_eq!(
                    submitted,
                    keys.iter().map(ToString::to_string).collect::<Vec<_>>()
                );
                let signatures = server.calls("/signer/v1/request_signature");
                assert_eq!(signatures.len(), if register { count } else { 0 });
                for (index, request) in signatures.iter().enumerate() {
                    let body: Value = serde_json::from_str(&request.body).unwrap();
                    assert_eq!(body["pubkey"], json!(keys[index]));
                    assert_eq!(body["type"], "consensus");
                    let mut root = [0u8; 32];
                    root[..20].copy_from_slice(address().as_slice());
                    assert_eq!(body["object_root"], json!(B256::from(root)));
                }
                for batch in batches {
                    let form = batch.form();
                    if register {
                        assert_eq!(
                            form["publicKeys"].split(',').count(),
                            form["signatures"].split(',').count()
                        );
                    }
                    assert!(!form.contains_key("signingId") && !form.contains_key("chainId"));
                }
            }
        }
    }
}

#[tokio::test]
async fn login_uses_legacy_challenge_and_cookie_contract() {
    let server = Server::new().await;
    let (access, refresh) = EthgasExchangeService {
        exchange_api_base: server.url.clone(),
        entity_name: "test".into(),
        eoa_signer_config: EoaSignerConfig::PrivateKey(KEY.parse().unwrap()),
    }
    .login()
    .await
    .unwrap();
    assert_eq!((access.as_str(), refresh.as_str()), (ACCESS, REFRESH));
    for path in [
        "/api/v1/user/login",
        "/api/v1/user/login/verify",
        "/api/v1/user/update",
    ] {
        let server = Server::new().await;
        server.reply(path, Reply::disconnected());
        assert!(
            EthgasExchangeService {
                exchange_api_base: server.url.clone(),
                entity_name: "test".into(),
                eoa_signer_config: EoaSignerConfig::PrivateKey(KEY.parse().unwrap())
            }
            .login()
            .await
            .is_err()
        );
    }
    let server = Server::new().await;
    server.reply(
        "/api/v1/user/login/verify",
        Reply::json(json!({"data": {"accessToken": {"token": ACCESS}}})),
    );
    assert!(
        EthgasExchangeService {
            exchange_api_base: server.url.clone(),
            entity_name: "test".into(),
            eoa_signer_config: EoaSignerConfig::PrivateKey(KEY.parse().unwrap())
        }
        .login()
        .await
        .is_err()
    );
}

#[test]
fn legacy_logging_preserves_safe_registration_diagnostics() {
    verify_legacy_logging();
}

#[tokio::test]
async fn standard_registration_response_variants_preserve_legacy_contract() {
    for response in [json!({"data": {"message": null}}), json!(null)] {
        let server = Server::new().await;
        server.reply("/api/v1/validator/register", Reply::json(response));
        service(&server, extra(&server.url, "standard"))
            .run()
            .await
            .unwrap();
        assert!(server.calls("/signer/v1/request_signature").is_empty());
    }
    for mode in ["standard", "standard-mux", "skipped"] {
        let server = Server::new().await;
        let mut value = extra(&server.url, mode);
        value["query_pubkey"] = json!(true);
        let mut module = service(&server, value);
        if mode == "standard" {
            module.mux_pubkeys = pubkeys(1);
        }
        module.run().await.unwrap();
        assert_eq!(server.calls("/api/v1/user/validators").len(), 1);
    }
    for register in [true, false] {
        for enabled in [true, false] {
            for response in [
                json!(null),
                json!({"success": false, "data": {}, "errorMsgKey": "rejected"}),
                json!({"success": true, "data": {"deleted": []}}),
            ] {
                let server = Server::new().await;
                let path = if register {
                    "/api/v1/validator/verify/batch"
                } else {
                    "/api/v1/validator/deregister"
                };
                server.reply(path, Reply::json(response));
                let mut value = extra(&server.url, "standard-mux");
                value["enable_registration"] = json!(register);
                value["enable_pricer"] = json!(enabled);
                let mut module = service(&server, value);
                module.mux_pubkeys = pubkeys(4);
                module.run().await.unwrap();
                assert_eq!(server.calls(path).len(), 1);
            }
        }
    }
    for success in [true, false] {
        let server = Server::new().await;
        let keys = pubkeys(4);
        let results: serde_json::Map<String, Value> = keys
            .iter()
            .zip([0, 2, 3, 9])
            .map(|(key, result)| (key.to_string(), json!({"result":result})))
            .collect();
        server.reply(
            "/api/v1/validator/verify/batch",
            Reply::json(json!({"success":success,"data":results,"errorMsgKey":"rejected"})),
        );
        let mut value = extra(&server.url, "standard-mux");
        value["enable_pricer"] = json!(true);
        let mut module = service(&server, value);
        module.mux_pubkeys = keys;
        module.run().await.unwrap();
        assert_eq!(
            server.calls("/api/v1/validator/update/ofac").len(),
            usize::from(success)
        );
    }
}

#[tokio::test]
async fn response_helpers_reject_transport_errors_and_process_empty_results() {
    let server = Server::new().await;
    let client = Client::new();
    let module = service(&server, extra(&server.url, "ssv"));
    for response in [
        json!({"success":false,"data":{},"errorMsgKey":"rejected"}),
        json!({"success":true,"data":{"validators":null,"removed":null}}),
        json!({"success":true,"data":{"validators":[],"removed":[]}}),
        json!(null),
    ] {
        server.reply("/response", Reply::json(response));
        module
            .ssv_validator_register_response(
                server.response("/response").await,
                &client,
                ACCESS,
                None,
            )
            .await
            .unwrap();
        module
            .ssv_validator_deregister_response(server.response("/response").await)
            .await
            .unwrap();
    }
    for path in [
        "/api/v1/user/ssv/operator/validator/update/ofac",
        "/api/v1/user/ssv/operator/validator/update/validatorPayoutAddress",
    ] {
        let server = Server::new().await;
        let mut value = operator_extra(&server, "ssv", 1);
        value["enable_pricer"] = json!(true);
        value["ssv_node_operator_owner_payout_addresses"] = json!([address()]);
        server.reply(path, Reply::disconnected());
        assert!(service(&server, value).run().await.is_err());
        assert_eq!(server.calls(path).len(), 1);
    }
    for path in [
        "/api/v1/user/delegate/pricer",
        "/api/v1/user/delegate/builder",
        "/api/v1/user/collateralPerSlot",
        "/api/v1/validator/register",
        "/signer/v1/get_pubkeys",
        "/signer/v1/request_signature",
        "/api/v1/validator/verify/batch",
        "/api/v1/validator/update/ofac",
        "/api/v1/validator/update/validatorPayoutAddress",
    ] {
        let server = Server::new().await;
        server.reply(path, Reply::disconnected());
        let mut value = extra(&server.url, "standard");
        value["builder_pubkey"] = json!(pubkeys(1)[0]);
        value["payout_address"] = json!(address());
        assert!(service(&server, value).run().await.is_err(), "{path}");
        assert_eq!(server.calls(path).len(), 1);
    }
    for mode in ["ssv", "obol"] {
        for suffix in [
            "register",
            "verify",
            "validator/register",
            "validator/deregister",
        ] {
            let server = Server::new().await;
            let path = format!("/api/v1/user/{mode}/operator/{suffix}");
            server.reply(&path, Reply::disconnected());
            let mut value = operator_extra(&server, mode, 1);
            value["enable_registration"] = json!(suffix != "validator/deregister");
            assert!(service(&server, value).run().await.is_err());
            assert_eq!(server.calls(&path).len(), 1);
        }
    }
}

#[tokio::test]
async fn registration_refreshes_access_token_after_one_thousand_batches() {
    let server = Server::new().await;
    let key = pubkeys(1)[0].clone();
    let mut root = [0u8; 32];
    root[..20].copy_from_slice(address().as_slice());
    let signature = reference_bls_signature(&json!({"pubkey":key,"object_root":B256::from(root)}));
    server.reply(
        "/signer/v1/request_signature",
        Reply::json(json!(format!(
            "0x{}",
            alloy::hex::encode(signature.to_bytes())
        ))),
    );
    server.sequence(
        "/api/v1/user/login/refresh",
        vec![
            Reply::json(json!({"success":true,"data":{"accessToken":{"token":"test-refreshed"}}})),
            Reply::json(json!({"success":false,"data":{"accessToken":{"token":"ignored"}}})),
            Reply::invalid(),
            Reply::disconnected(),
        ],
    );
    let mut module = service(&server, extra(&server.url, "standard-mux"));
    module.mux_pubkeys = vec![key; 400_001];
    assert!(module.run().await.is_err());
    let batches = server.calls("/api/v1/validator/verify/batch");
    assert_eq!(batches.len(), 4000);
    assert_eq!(
        batches[999].headers["authorization"],
        format!("Bearer {ACCESS}")
    );
    assert_eq!(
        batches[1000].headers["authorization"],
        "Bearer test-refreshed"
    );
    let refresh = server.calls("/api/v1/user/login/refresh");
    assert_eq!(refresh.len(), 4);
    assert_eq!(refresh[0].query["refreshToken"], REFRESH);
    assert_eq!(
        batches[2000].headers["authorization"],
        "Bearer test-refreshed"
    );
    assert_eq!(
        batches[3000].headers["authorization"],
        "Bearer test-refreshed"
    );
}

#[tokio::test]
async fn remaining_legacy_io_and_response_errors_are_observable() {
    for mode in ["ssv", "obol"] {
        let server = Server::new().await;
        let mut value = operator_extra(&server, mode, 1);
        value[format!("{mode}_node_operator_owner_mode")] = json!("keystore");
        value[format!("{mode}_node_operator_owner_keystores")] =
            json!([{"keystore_path":"unused","password_path":"missing-test-password"}]);
        assert!(service(&server, value).run().await.is_err());
        for register in [true, false] {
            let server = Server::new().await;
            let suffix = if register { "register" } else { "deregister" };
            let path = format!("/api/v1/user/{mode}/operator/validator/{suffix}");
            server.reply(&path, Reply::disconnected());
            let mut value = operator_extra(&server, mode, 0);
            value["enable_registration"] = json!(register);
            assert!(service(&server, value).run().await.is_err());
            assert_eq!(server.calls(&path).len(), 1);
        }
    }
    let server = Server::new().await;
    server.reply("/api/v1/user/obol/operator/refresh", Reply::invalid());
    let mut value = operator_extra(&server, "obol", 1);
    value["enable_pricer"] = json!(true);
    service(&server, value).run().await.unwrap();
    let server = Server::new().await;
    server.reply(
        "/api/v1/user/obol/operator/validator/deregister",
        Reply::json(json!({"success":false,"data":{"removed":[]},"errorMsgKey":"rejected"})),
    );
    let mut value = operator_extra(&server, "obol", 1);
    value["enable_registration"] = json!(false);
    service(&server, value).run().await.unwrap();
    let server = Server::new().await;
    service(&server, extra(&server.url, "invalid"))
        .run()
        .await
        .unwrap();
    for response in [
        json!({"data":{"user":{"displayName":"test"}}}),
        json!({"data":{"user":{"displayName":"different"}}}),
        json!(null),
    ] {
        let server = Server::new().await;
        server.reply("/api/v1/user/update", Reply::json(response));
        EthgasExchangeService {
            exchange_api_base: server.url.clone(),
            entity_name: "test".into(),
            eoa_signer_config: EoaSignerConfig::PrivateKey(KEY.parse().unwrap()),
        }
        .login()
        .await
        .unwrap();
    }
    for body in [json!(null), json!({"data":{"eip712Message":"{"}})] {
        let server = Server::new().await;
        server.reply("/api/v1/user/login", Reply::json(body));
        assert!(
            EthgasExchangeService {
                exchange_api_base: server.url.clone(),
                entity_name: "test".into(),
                eoa_signer_config: EoaSignerConfig::PrivateKey(KEY.parse().unwrap())
            }
            .login()
            .await
            .is_err()
        );
    }
    let server = Server::new().await;
    server.reply(
        "/api/v1/user/login/verify",
        Reply::json(json!({"data":{"accessToken":{"token":ACCESS}}})).cookie(""),
    );
    assert!(
        EthgasExchangeService {
            exchange_api_base: server.url.clone(),
            entity_name: "test".into(),
            eoa_signer_config: EoaSignerConfig::PrivateKey(KEY.parse().unwrap())
        }
        .login()
        .await
        .is_err()
    );
    for path in [
        "/api/v1/user/validators",
        "/api/v1/user/ssv/operators",
        "/api/v1/user/obol/operators",
    ] {
        let server = Server::new().await;
        server.reply(path, Reply::disconnected());
        let mut value = extra(&server.url, "skipped");
        value["query_pubkey"] = json!(true);
        assert!(service(&server, value).run().await.is_err());
    }
}

#[tokio::test]
async fn tx_transport_and_deregistration_failures_are_reported() {
    let server = Server::new().await;
    let mut value = operator_extra(&server, "ssv", 1);
    value["ssv_node_operator_owner_mode"] = json!("tx");
    value["ssv_node_operator_owner_tx_hashes"] = json!(["0x123"]);
    value["ssv_node_operator_owner_tx_from_addr"] = json!([address()]);
    server.reply(
        "/api/v1/user/ssv/operator/verifyByTx",
        Reply::disconnected(),
    );
    assert!(service(&server, value).run().await.is_err());
    for mode in ["standard-mux", "ssv"] {
        let server = Server::new().await;
        let path = if mode == "ssv" {
            "/api/v1/user/ssv/operator/validator/deregister"
        } else {
            "/api/v1/validator/deregister"
        };
        server.reply(path,Reply::json(json!({"success":false,"data":{"deleted":[],"removed":[]},"errorMsgKey":"rejected"})));
        let mut value = if mode == "ssv" {
            operator_extra(&server, mode, 1)
        } else {
            extra(&server.url, mode)
        };
        value["enable_registration"] = json!(false);
        let mut module = service(&server, value);
        if mode == "standard-mux" {
            module.mux_pubkeys = pubkeys(1);
        }
        module.run().await.unwrap();
    }
}

#[tokio::test]
async fn ledger_connection_errors_stop_before_authentication_or_registration() {
    if !no_ledger_device() {
        return;
    }
    let server = Server::new().await;
    assert!(
        EthgasExchangeService {
            exchange_api_base: server.url.clone(),
            entity_name: "test".into(),
            eoa_signer_config: EoaSignerConfig::LedgerPath("m/44'/60'/0'/0/0".into())
        }
        .login()
        .await
        .is_err()
    );
    assert!(server.requests().is_empty());
    for mode in ["ssv", "obol"] {
        let mut value = operator_extra(&server, mode, 1);
        value[format!("{mode}_node_operator_owner_mode")] = json!("ledger");
        value[format!("{mode}_node_operator_owner_ledger_paths")] = json!(["m/44'/60'/0'/0/0"]);
        assert!(service(&server, value).run().await.is_err());
        assert!(
            server
                .calls(&format!("/api/v1/user/{mode}/operator/register"))
                .is_empty()
        );
    }
}

#[tokio::test]
async fn invalid_base_urls_and_truncated_verification_responses_return_errors() {
    let server = Server::new().await;
    let mut value = extra("invalid", "skipped");
    assert!(service(&server, value.clone()).run().await.is_err());
    assert!(
        EthgasExchangeService {
            exchange_api_base: "invalid".into(),
            entity_name: "test".into(),
            eoa_signer_config: EoaSignerConfig::PrivateKey(KEY.parse().unwrap())
        }
        .login()
        .await
        .is_err()
    );
    let url = truncated_http_response().await;
    server.reply(
        "/api/v1/user/login/verify",
        Reply {
            status: 307,
            body: String::new(),
            headers: vec![("location".into(), url)],
        },
    );
    assert!(
        EthgasExchangeService {
            exchange_api_base: server.url.clone(),
            entity_name: "test".into(),
            eoa_signer_config: EoaSignerConfig::PrivateKey(KEY.parse().unwrap())
        }
        .login()
        .await
        .is_err()
    );
    value["exchange_api_base"] = json!(&server.url);
    value["query_pubkey"] = json!(true);
    server.reply(
        "/api/v1/user/validators",
        Reply::json(json!({"success":false,"data":{"validators":[]}})),
    );
    service(&server, value).run().await.unwrap();
}
