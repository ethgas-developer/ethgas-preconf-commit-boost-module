use super::*;
use alloy::primitives::Address;
use commit_boost::prelude::commit::client::SignerClient;
use serde_json::{Value, json};

#[path = "../support/mod.rs"]
mod support;
use support::*;

fn extra(base: &str, mode: &str) -> Value {
    json!({"exchange_api_base": base, "entity_name": "test", "registration_mode": mode,
        "enable_registration": true, "enable_ofac": true, "is_jwt_provided": true, "query_pubkey": false})
}

fn service(server: &Server, value: Value) -> EthgasCommitService {
    EthgasCommitService {
        config: StartCommitModuleConfig {
            id: serde_json::from_value(json!("ETHGAS_COMMIT")).unwrap(),
            chain: Chain::Mainnet,
            signer_client: SignerClient::new(
                server.url.parse().unwrap(),
                None,
                serde_json::from_value(json!("test-signer-secret")).unwrap(),
                serde_json::from_value(json!("ETHGAS_COMMIT")).unwrap(),
            )
            .unwrap(),
            extra: serde_json::from_value(value).unwrap(),
        },
        signing_id: B256::repeat_byte(9),
        access_jwt: ACCESS.into(),
        refresh_jwt: REFRESH.into(),
        signer_address: Some(address()),
        mux_pubkeys: Vec::new(),
        chain_id: 1,
    }
}

fn operator_extra(server: &Server, mode: &str, count: usize) -> Value {
    let mut value = extra(&server.url, mode);
    value[format!("{mode}_node_operator_owner_mode")] = json!("key");
    value[format!("{mode}_node_operator_owner_signing_keys")] = json!([format!("0x{KEY}")]);
    value[format!("{mode}_node_operator_owner_validator_pubkeys")] = json!([pubkeys(count)]);
    value
}

#[test]
fn signing_id_selects_exact_module_and_rejects_invalid_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let text = format!(
        "[[modules]]\nid = \"OTHER\"\nsigning_id = \"{:#x}\"\n[[modules]]\nid = \"ETHGAS_COMMIT\"\nsigning_id = \"{:#x}\"\n",
        B256::repeat_byte(1),
        B256::repeat_byte(9)
    );
    std::fs::write(&path, text).unwrap();
    assert_eq!(
        read_module_signing_id(path.to_str().unwrap(), "ETHGAS_COMMIT").unwrap(),
        B256::repeat_byte(9)
    );
    assert!(read_module_signing_id(path.to_str().unwrap(), "missing").is_err());
    std::fs::write(
        &path,
        "[[modules]]\nid = 'ETHGAS_COMMIT'\nsigning_id = 'invalid'",
    )
    .unwrap();
    assert!(read_module_signing_id(path.to_str().unwrap(), "ETHGAS_COMMIT").is_err());
    std::fs::remove_file(&path).unwrap();
    assert!(read_module_signing_id(path.to_str().unwrap(), "ETHGAS_COMMIT").is_err());
}

#[tokio::test]
async fn encrypted_keystores_trim_password_files_and_fail_closed() {
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
        assert_eq!(server.requests().len(), before);
        std::fs::write(&password, "password\n").unwrap();
        value[format!("{mode}_node_operator_owner_keystores")][0]["keystore_path"] =
            json!(dir.path().join("missing"));
        assert!(service(&server, value).run().await.is_err());
    }
}

#[test]
fn optional_settings_deserialize_without_resetting_values() {
    let mut value = extra("http://localhost", "skipped");
    value.as_object_mut().unwrap().remove("query_pubkey");
    let config: ExtraConfig = serde_json::from_value(value.clone()).unwrap();
    assert!(config.enable_pricer.is_none() && config.enable_builder.is_none());
    assert!(config.collateral_per_slot.is_none() && config.payout_address.is_none());
    assert_eq!(config.overall_wait_interval_in_second.unwrap_or(0), 0);
    assert!(config.query_pubkey.unwrap_or(true));
    for field in [
        "exchange_api_base",
        "entity_name",
        "registration_mode",
        "enable_registration",
        "enable_ofac",
        "is_jwt_provided",
    ] {
        let mut incomplete = value.clone();
        incomplete.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<ExtraConfig>(incomplete).is_err(),
            "missing {field}"
        );
    }
    for field in ["enable_pricer", "enable_builder", "query_pubkey"] {
        let mut invalid = value.clone();
        invalid[field] = json!("true");
        assert!(serde_json::from_value::<ExtraConfig>(invalid).is_err());
    }
}

#[test]
fn collateral_validation_covers_bounds_precision_and_malformed_values() {
    validate_collateral_per_slot(None).unwrap();
    for amount in ["0", "0.00", "0.01", "1", "1000", "999.99"] {
        validate_collateral_per_slot(Some(amount)).unwrap();
    }
    for amount in ["", "NaN", "-1", "0.001", "1000.01", "1.001"] {
        assert!(
            validate_collateral_per_slot(Some(amount)).is_err(),
            "{amount}"
        );
    }
}

#[tokio::test]
async fn omitted_updates_send_no_requests_and_query_defaults_to_enabled() {
    let server = Server::new().await;
    service(&server, extra(&server.url, "skipped"))
        .run()
        .await
        .unwrap();
    assert!(server.requests().is_empty());
    let mut value = extra(&server.url, "skipped");
    value.as_object_mut().unwrap().remove("query_pubkey");
    service(&server, value).run().await.unwrap();
    assert_eq!(
        server
            .requests()
            .iter()
            .map(|r| r.path.as_str())
            .collect::<Vec<_>>(),
        [
            "/api/v1/user/validators",
            "/api/v1/user/ssv/operators",
            "/api/v1/user/obol/operators"
        ]
    );
}

#[tokio::test]
async fn builder_configuration_matrix_and_explicit_updates() {
    for flag in [None, Some(false), Some(true)] {
        for has_key in [false, true] {
            for response in [
                json!({"success": true}),
                json!({"success": false}),
                json!(null),
            ] {
                let server = Server::new().await;
                server.reply("/api/v1/user/delegate/builder", Reply::json(response));
                let mut value = extra(&server.url, "skipped");
                if let Some(flag) = flag {
                    value["enable_builder"] = json!(flag);
                }
                if has_key {
                    value["builder_pubkey"] = json!(pubkeys(1)[0]);
                }
                let result = service(&server, value).run().await;
                assert_eq!(result.is_err(), flag == Some(true) && !has_key);
                let expected = usize::from(flag.is_some() && has_key);
                assert_eq!(
                    server.calls("/api/v1/user/delegate/builder").len(),
                    expected
                );
                if expected == 1 {
                    assert_eq!(
                        server.requests()[0].query["enable"],
                        flag.unwrap().to_string()
                    );
                }
                if result.is_err() {
                    assert!(server.requests().is_empty());
                }
            }
        }
    }
    for enabled in [false, true] {
        for reply in [
            Reply::json(json!({"success": true})),
            Reply::json(json!({"success": false})),
            Reply::invalid(),
        ] {
            let server = Server::with_responder(move |_| reply.clone()).await;
            let mut value = extra(&server.url, "skipped");
            value["enable_pricer"] = json!(enabled);
            value["collateral_per_slot"] = json!("0");
            service(&server, value).run().await.unwrap();
            let calls = server.requests();
            assert_eq!(calls.len(), 2);
            assert_eq!(calls[0].query["enable"], enabled.to_string());
            assert_eq!(calls[1].query["collateralPerSlot"], "0");
            assert_eq!(
                calls[0].headers["authorization"],
                format!("Bearer {ACCESS}")
            );
        }
    }
}

#[tokio::test]
async fn standard_registration_batches_and_signer_requests_match() {
    for mode in ["standard", "standard-mux"] {
        for register in [true, false] {
            for count in [0usize, 1, 99, 100, 101, 201] {
                let keys = pubkeys(count);
                let server = Server::new().await;
                server.reply("/signer/v1/get_pubkeys", Reply::json(json!({"keys": keys.iter().map(|key| json!({"consensus": key, "proxy_bls": [], "proxy_ecdsa": []})).collect::<Vec<_>>()})));
                let mut value = extra(&server.url, mode);
                value["enable_registration"] = json!(register);
                value["payout_address"] = json!(address());
                value["enable_light_mode"] = json!(true);
                let mut module = service(&server, value);
                if mode == "standard-mux" {
                    module.mux_pubkeys = keys.clone();
                }
                module.run().await.unwrap();
                let path = if register {
                    "/api/v1/validator/verify/batch2"
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
                let signatures = server.calls("/signer/v1/request_signature/bls");
                assert_eq!(signatures.len(), if register { count } else { 0 });
                for (index, request) in signatures.iter().enumerate() {
                    let body: Value = serde_json::from_str(&request.body).unwrap();
                    assert_eq!(body["pubkey"], json!(keys[index]));
                    assert_eq!(body["nonce"], 0);
                    // SSZ container with one address: the 20 bytes followed by 12 zero bytes.
                    let mut root = [0u8; 32];
                    root[..20].copy_from_slice(address().as_slice());
                    assert_eq!(body["object_root"], json!(B256::from(root)));
                    assert!(request.headers["authorization"].starts_with("Bearer "));
                }
                if register {
                    for batch in &batches {
                        let form = batch.form();
                        assert_eq!(form["signingId"], format!("{:#x}", module.signing_id));
                        assert_eq!(form["chainId"], "1");
                        assert_eq!(
                            form["publicKeys"].split(',').count(),
                            form["signatures"].split(',').count()
                        );
                        for (key, signature) in form["publicKeys"]
                            .split(',')
                            .zip(form["signatures"].split(','))
                        {
                            let key: BlsPublicKey = key.parse().unwrap();
                            let signature: BlsSignature = signature.parse().unwrap();
                            let message = RegisteredInfo {
                                eoa_address: address(),
                            };
                            assert!(verify_proposer_commitment_signature_bls(
                                Chain::Mainnet,
                                &key,
                                &message,
                                &signature,
                                &module.signing_id,
                                0
                            ));
                            assert!(!verify_proposer_commitment_signature_bls(
                                Chain::Mainnet,
                                &key,
                                &message,
                                &signature,
                                &B256::ZERO,
                                0
                            ));
                            assert!(!verify_proposer_commitment_signature_bls(
                                Chain::Mainnet,
                                &key,
                                &message,
                                &signature,
                                &module.signing_id,
                                1
                            ));
                            assert!(!verify_proposer_commitment_signature_bls(
                                Chain::Hoodi,
                                &key,
                                &message,
                                &signature,
                                &module.signing_id,
                                0
                            ));
                            assert!(!verify_proposer_commitment_signature_bls(
                                Chain::Mainnet,
                                &key,
                                &RegisteredInfo {
                                    eoa_address: Address::ZERO
                                },
                                &signature,
                                &module.signing_id,
                                0
                            ));
                        }
                    }
                    assert_eq!(
                        server
                            .calls("/api/v1/validator/update/validatorPayoutAddress")
                            .len(),
                        count.div_ceil(100)
                    );
                }
            }
        }
    }
}

#[tokio::test]
async fn standard_registration_handles_rejection_mismatch_and_mixed_results() {
    for response in [
        json!({"data": {"message": null}}),
        json!(null),
        json!({"data": {"message": {"eoaAddress": Address::ZERO}}}),
    ] {
        let server = Server::new().await;
        server.reply("/api/v1/validator/register", Reply::json(response.clone()));
        let result = service(&server, extra(&server.url, "standard")).run().await;
        assert_eq!(
            result.is_err(),
            response["data"]["message"]["eoaAddress"].is_string()
        );
        assert!(server.calls("/signer/v1/request_signature/bls").is_empty());
    }
    for success in [true, false] {
        let server = Server::new().await;
        let keys = pubkeys(4);
        let data: serde_json::Map<String, Value> = keys
            .iter()
            .zip([0, 2, 3, 9])
            .map(|(key, result)| (key.to_string(), json!({"result": result})))
            .collect();
        server.reply(
            "/api/v1/validator/verify/batch2",
            Reply::json(json!({"success": success, "data": data, "errorMsgKey": "rejected"})),
        );
        let mut module = service(&server, extra(&server.url, "standard-mux"));
        module.mux_pubkeys = keys;
        module.run().await.unwrap();
        assert_eq!(
            server.calls("/api/v1/validator/update/ofac").len(),
            usize::from(success)
        );
        assert!(
            server
                .calls("/api/v1/validator/update/validatorPayoutAddress")
                .is_empty()
        );
    }
    for mode in ["standard", "standard-mux", "invalid"] {
        let server = Server::new().await;
        let mut module = service(&server, extra(&server.url, mode));
        if mode == "standard" {
            module.mux_pubkeys = pubkeys(1);
        }
        module.run().await.unwrap();
        assert!(server.calls("/signer/v1/get_pubkeys").is_empty());
    }
    for register in [true, false] {
        let server = Server::new().await;
        server.reply(
            if register {
                "/api/v1/validator/verify/batch2"
            } else {
                "/api/v1/validator/deregister"
            },
            Reply::invalid(),
        );
        let mut value = extra(&server.url, "standard-mux");
        value["enable_registration"] = json!(register);
        let mut module = service(&server, value);
        module.mux_pubkeys = pubkeys(1);
        module.run().await.unwrap();
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
                assert!(
                    service(&server, operator_extra(&server, mode, 1))
                        .run()
                        .await
                        .is_err()
                );
                assert!(
                    server
                        .calls(&format!("/api/v1/user/{mode}/operator/validator/register"))
                        .is_empty()
                );
            }
        }
        let mut module = service(&server, operator_extra(&server, mode, 1));
        module.signer_address = None;
        assert!(module.run().await.is_err());
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
        let error = reply.body.contains("rejected");
        assert_eq!(service(&server, value.clone()).run().await.is_err(), error);
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
async fn refresh_boundary_and_new_token_usage() {
    let server = Server::new().await;
    let module = service(&server, extra(&server.url, "skipped"));
    let client = Client::new();
    for index in [0, 999, 1000, 1001, 2000] {
        let mut token = "old".to_string();
        module
            .refresh_access_jwt(&client, &mut token, index)
            .await
            .unwrap();
        assert_eq!(
            token,
            if index != 0 && index % 1000 == 0 {
                ACCESS
            } else {
                "old"
            }
        );
    }
    assert_eq!(server.calls("/api/v1/user/login/refresh").len(), 2);
    for reply in [
        Reply::json(json!({"success": false, "data": {"accessToken": {"token": "unused"}}})),
        Reply::json(json!({"success": true, "data": {"accessToken": {"token": ""}}})),
        Reply::invalid(),
    ] {
        server.reply("/api/v1/user/login/refresh", reply);
        let mut token = "old".to_string();
        module
            .refresh_access_jwt(&client, &mut token, 1000)
            .await
            .unwrap();
        assert_eq!(token, "old");
    }
    for r in server.calls("/api/v1/user/login/refresh") {
        assert_eq!(r.query["refreshToken"], REFRESH);
    }
}

#[tokio::test]
async fn login_rejects_failed_verification_and_invalid_cookies() {
    for reply in [
        Reply::json(json!({"success": false, "data": {"accessToken": {"token": ACCESS}}}))
            .cookie("refreshToken=test"),
        Reply::json(json!({"success": true, "data": {"accessToken": {"token": ""}}}))
            .cookie("refreshToken=test"),
        Reply::json(json!({"success": true, "data": {"accessToken": {"token": ACCESS}}})),
        Reply::json(json!({"success": true, "data": {"accessToken": {"token": ACCESS}}}))
            .cookie("invalid"),
        Reply::json(json!({"success": true, "data": {"accessToken": {"token": ACCESS}}}))
            .cookie(";"),
        Reply::json(json!({"success": true, "data": {"accessToken": {"token": ACCESS}}}))
            .cookie("refreshToken="),
        Reply::invalid().cookie("refreshToken=test"),
    ] {
        let server = Server::new().await;
        server.reply("/api/v1/user/login/verify", reply);
        let login = EthgasExchangeService {
            exchange_api_base: server.url.clone(),
            entity_name: "test".into(),
            eoa_signer_config: EoaSignerConfig::PrivateKey(KEY.parse().unwrap()),
            chain_id: 1,
        };
        assert!(login.login().await.is_err());
        assert!(server.calls("/api/v1/user/update").is_empty());
    }
    for reply in [
        Reply::json(json!({"success": true})),
        Reply::json(json!({"success": false})),
        Reply::invalid(),
    ] {
        let server = Server::new().await;
        server.reply("/api/v1/user/update", reply);
        let login = EthgasExchangeService {
            exchange_api_base: server.url.clone(),
            entity_name: "test name".into(),
            eoa_signer_config: EoaSignerConfig::PrivateKey(KEY.parse().unwrap()),
            chain_id: 1,
        };
        let (access, refresh, signer) = login.login().await.unwrap();
        assert_eq!(
            (access.as_str(), refresh.as_str(), signer),
            (ACCESS, REFRESH, address())
        );
        assert_eq!(
            server.calls("/api/v1/user/login/verify")[0].query["nonceHash"],
            "nonce"
        );
        assert_eq!(
            server.calls("/api/v1/user/update")[0].query["displayName"],
            "test name"
        );
    }
}

#[tokio::test]
async fn authentication_transport_errors_are_redacted_and_stop_follow_up_calls() {
    for path in [
        "/api/v1/user/login/verify",
        "/api/v1/user/login/refresh",
        "/api/v1/user/ssv/operator/verify",
        "/api/v1/user/obol/operator/verify",
    ] {
        let server = Server::new().await;
        server.reply(path, Reply::disconnected());
        let diagnostic = if path.ends_with("refresh") {
            let module = service(&server, extra(&server.url, "skipped"));
            format!(
                "{:?}",
                module
                    .refresh_access_jwt(&Client::new(), &mut ACCESS.to_string(), 1000)
                    .await
                    .unwrap_err()
            )
        } else if path.contains("operator") {
            let mode = if path.contains("ssv") { "ssv" } else { "obol" };
            format!(
                "{:?}",
                service(&server, operator_extra(&server, mode, 1))
                    .run()
                    .await
                    .unwrap_err()
            )
        } else {
            format!(
                "{:?}",
                EthgasExchangeService {
                    exchange_api_base: server.url.clone(),
                    entity_name: "test".into(),
                    eoa_signer_config: EoaSignerConfig::PrivateKey(KEY.parse().unwrap()),
                    chain_id: 1
                }
                .login()
                .await
                .unwrap_err()
            )
        };
        for secret in [ACCESS, REFRESH, "signature=", "nonceHash=", "refreshToken="] {
            assert!(!diagnostic.contains(secret), "{diagnostic}");
        }
        assert!(server.calls("/api/v1/user/update").is_empty());
        assert!(
            server
                .calls("/api/v1/user/ssv/operator/validator/register")
                .is_empty()
        );
        assert!(
            server
                .calls("/api/v1/user/obol/operator/validator/register")
                .is_empty()
        );
    }
    let server = Server::new().await;
    let login = |key| EthgasExchangeService {
        exchange_api_base: server.url.clone(),
        entity_name: "test".into(),
        eoa_signer_config: EoaSignerConfig::PrivateKey(key),
        chain_id: 1,
    };
    assert!(
        login(B256::ZERO)
            .login()
            .await
            .unwrap_err()
            .to_string()
            .contains("signer")
    );
    for response in [
        json!({"success": false, "data": {"eip712Message": challenge("Ethgas Login", false)}}),
        json!({"success": true, "data": {"eip712Message": "{"}}),
    ] {
        server.reply("/api/v1/user/login", Reply::json(response));
        assert!(login(KEY.parse().unwrap()).login().await.is_err());
    }
    assert!(server.calls("/api/v1/user/login/verify").is_empty());
}

#[tokio::test]
async fn failed_registration_settings_propagate_and_stop_later_updates() {
    for setting in ["ofac", "mode/enable", "validatorPayoutAddress"] {
        let server = Server::new().await;
        let path = if setting == "mode/enable" {
            "/api/v1/ssv/validator/mode/enable".into()
        } else {
            format!("/api/v1/user/ssv/operator/validator/update/{setting}")
        };
        server.reply(&path, Reply::disconnected());
        let mut value = operator_extra(&server, "ssv", 1);
        value["enable_light_mode"] = json!(true);
        value["ssv_node_operator_owner_payout_addresses"] = json!([address()]);
        assert!(service(&server, value).run().await.is_err(), "{path}");
        assert_eq!(server.calls(&path).len(), 1);
        if setting == "ofac" {
            assert!(server.calls("/api/v1/ssv/validator/mode/enable").is_empty());
        }
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
        assert!(server.requests().is_empty());
    }
}

#[test]
fn signing_id_environment_errors_do_not_mutate_the_parent_environment() {
    if std::env::var("ETHGAS_TEST_SIGNING_ID_CHILD").is_ok() {
        let error = load_module_signing_id().unwrap_err().to_string();
        if std::env::var("CB_MODULE_ID").is_err() {
            assert!(error.contains("CB_MODULE_ID"));
        } else {
            assert!(error.contains("cb-config.toml"));
        }
        return;
    }
    for module_id in [None, Some("ETHGAS_COMMIT")] {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child
            .args([
                "--exact",
                "tests::signing_id_environment_errors_do_not_mutate_the_parent_environment",
            ])
            .env("ETHGAS_TEST_SIGNING_ID_CHILD", "1")
            .env_remove("CB_CONFIG")
            .env_remove("CB_MODULE_ID");
        if let Some(id) = module_id {
            child.env("CB_MODULE_ID", id);
        }
        let output = child.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

#[tokio::test]
async fn transport_errors_stop_each_registration_and_settings_phase() {
    for mode in ["standard", "standard-mux", "ssv", "obol"] {
        for count in [0, 1] {
            for register in [true, false] {
                let mut paths = if mode.starts_with("standard") {
                    vec![
                        "/api/v1/validator/register".to_string(),
                        if register {
                            "/api/v1/validator/verify/batch2"
                        } else {
                            "/api/v1/validator/deregister"
                        }
                        .into(),
                    ]
                } else {
                    vec![
                        format!("/api/v1/user/{mode}/operator/register"),
                        format!("/api/v1/user/{mode}/operator/verify"),
                        format!(
                            "/api/v1/user/{mode}/operator/validator/{}",
                            if register { "register" } else { "deregister" }
                        ),
                    ]
                };
                if register {
                    if mode.starts_with("standard") {
                        paths.extend(
                            [
                                "/signer/v1/get_pubkeys",
                                "/signer/v1/request_signature/bls",
                                "/api/v1/validator/update/ofac",
                                "/api/v1/validator/mode/enable",
                                "/api/v1/validator/update/validatorPayoutAddress",
                            ]
                            .map(str::to_string),
                        );
                    } else {
                        paths.extend([format!("/api/v1/user/{mode}/operator/validator/update/ofac"), format!("/api/v1/{mode}/validator/mode/enable"), format!("/api/v1/user/{mode}/operator/validator/update/validatorPayoutAddress")]);
                    }
                }
                if mode == "obol" {
                    paths.push("/api/v1/user/obol/operator/refresh".into());
                }
                for path in paths {
                    // Empty explicit mux lists cannot reach signing or batch submission.
                    if mode == "standard-mux" && count == 0 && !path.ends_with("/register") {
                        continue;
                    }
                    if mode == "standard-mux" && path.ends_with("get_pubkeys") {
                        continue;
                    }
                    let server = Server::new().await;
                    server.reply(&path, Reply::disconnected());
                    let mut value = if mode.starts_with("standard") {
                        extra(&server.url, mode)
                    } else {
                        operator_extra(&server, mode, count)
                    };
                    value["enable_registration"] = json!(register);
                    value["enable_light_mode"] = json!(true);
                    value["payout_address"] = json!(address());
                    value[format!("{mode}_node_operator_owner_payout_addresses")] =
                        json!([address()]);
                    let mut module = service(&server, value);
                    if mode == "standard-mux" {
                        module.mux_pubkeys = pubkeys(count);
                    }
                    assert!(
                        module.run().await.is_err(),
                        "accepted failed {mode} {register} {count} {path}"
                    );
                    assert_eq!(server.calls(&path).len(), 1, "{path}");
                    assert_eq!(server.requests().last().unwrap().path, path);
                }
            }
        }
    }
    for (flag, path) in [
        ("enable_pricer", "/api/v1/user/delegate/pricer"),
        ("enable_builder", "/api/v1/user/delegate/builder"),
        ("collateral_per_slot", "/api/v1/user/collateralPerSlot"),
        ("enable_user_lock", "/api/v1/user/lock"),
    ] {
        let server = Server::new().await;
        server.reply(path, Reply::disconnected());
        let mut value = extra(&server.url, "skipped");
        value[flag] = if flag == "collateral_per_slot" {
            json!("0.01")
        } else {
            json!(true)
        };
        if flag == "enable_builder" {
            value["builder_pubkey"] = json!(pubkeys(1)[0]);
        }
        assert!(service(&server, value).run().await.is_err(), "{path}");
        assert_eq!(server.calls(path).len(), 1);
    }
    let server = Server::new().await;
    let mut value = extra(&server.url, "skipped");
    value["enable_user_lock"] = json!(true);
    service(&server, value).run().await.unwrap();
    assert_eq!(server.calls("/api/v1/user/lock").len(), 1);
    for path in [
        "/api/v1/user/validators",
        "/api/v1/user/ssv/operators",
        "/api/v1/user/obol/operators",
    ] {
        let server = Server::new().await;
        server.reply(path, Reply::disconnected());
        let mut value = extra(&server.url, "skipped");
        value["query_pubkey"] = json!(true);
        assert!(service(&server, value).run().await.is_err(), "{path}");
    }
}

#[test]
fn legacy_logging_preserves_safe_registration_diagnostics() {
    verify_legacy_logging();
}

#[tokio::test]
async fn malformed_login_and_operator_challenges_fail_before_verification() {
    for base in ["invalid", "http://127.0.0.1:0"] {
        assert!(
            EthgasExchangeService {
                exchange_api_base: base.into(),
                entity_name: "test".into(),
                eoa_signer_config: EoaSignerConfig::PrivateKey(KEY.parse().unwrap()),
                chain_id: 1
            }
            .login()
            .await
            .is_err()
        );
    }
    for reply in [
        Reply::invalid(),
        Reply::json(
            json!({"success": true, "data": {"eip712Message": challenge("malicious", false)}}),
        ),
    ] {
        let server = Server::new().await;
        server.reply("/api/v1/user/login", reply);
        assert!(
            EthgasExchangeService {
                exchange_api_base: server.url.clone(),
                entity_name: "test".into(),
                eoa_signer_config: EoaSignerConfig::PrivateKey(KEY.parse().unwrap()),
                chain_id: 1
            }
            .login()
            .await
            .is_err()
        );
        assert!(server.calls("/api/v1/user/login/verify").is_empty());
    }
    for mode in ["ssv", "obol"] {
        let server = Server::new().await;
        server.reply(&format!("/api/v1/user/{mode}/operator/register"), Reply::json(json!({"success": true, "data": {"available": true, "messageToSign": challenge("malicious", true)}})));
        assert!(
            service(&server, operator_extra(&server, mode, 1))
                .run()
                .await
                .is_err()
        );
        assert!(
            server
                .calls(&format!("/api/v1/user/{mode}/operator/verify"))
                .is_empty()
        );
        let mut value = operator_extra(&server, mode, 1);
        value["exchange_api_base"] = json!("invalid");
        assert!(service(&server, value).run().await.is_err());
    }
    let server = Server::new().await;
    for flag in ["enable_pricer", "enable_builder", "collateral_per_slot"] {
        let mut value = extra("invalid", "skipped");
        value[flag] = if flag == "collateral_per_slot" {
            json!("1")
        } else {
            json!(true)
        };
        value["builder_pubkey"] = json!(pubkeys(1)[0]);
        assert!(service(&server, value).run().await.is_err());
    }
    assert!(
        service(&server, extra("invalid", "standard-mux"))
            .run()
            .await
            .is_err()
    );
    let module = service(&server, extra("invalid", "skipped"));
    assert!(
        module
            .refresh_access_jwt(&Client::new(), &mut ACCESS.to_string(), 1000)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn response_rejections_and_missing_password_files_are_handled() {
    let server = Server::new().await;
    server.reply(
        "/api/v1/user/login/verify",
        Reply::json(json!({"success": true, "data": {"accessToken": {"token": ACCESS}}}))
            .cookie(""),
    );
    assert!(
        EthgasExchangeService {
            exchange_api_base: server.url.clone(),
            entity_name: "test".into(),
            eoa_signer_config: EoaSignerConfig::PrivateKey(KEY.parse().unwrap()),
            chain_id: 1
        }
        .login()
        .await
        .unwrap_err()
        .to_string()
        .contains("cookie")
    );
    server.reply(
        "/api/v1/user/login/verify",
        default_reply(&Recorded {
            method: String::new(),
            path: "/api/v1/user/login/verify".into(),
            query: Default::default(),
            headers: Default::default(),
            body: String::new(),
        }),
    );
    server.reply("/api/v1/user/update", Reply::disconnected());
    assert!(
        EthgasExchangeService {
            exchange_api_base: server.url.clone(),
            entity_name: "test".into(),
            eoa_signer_config: EoaSignerConfig::PrivateKey(KEY.parse().unwrap()),
            chain_id: 1
        }
        .login()
        .await
        .is_err()
    );
    for mode in ["standard-mux", "obol"] {
        let server = Server::new().await;
        let path = if mode == "obol" {
            "/api/v1/user/obol/operator/validator/deregister"
        } else {
            "/api/v1/validator/deregister"
        };
        server.reply(path, Reply::json(json!({"success": false, "data": {"deleted": [], "removed": []}, "errorMsgKey": "rejected"})));
        let mut value = if mode == "obol" {
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
        assert_eq!(server.calls(path).len(), 1);
        assert!(server.calls("/api/v1/validator/update/ofac").is_empty());
    }
    let server = Server::new().await;
    server.reply("/api/v1/user/obol/operator/refresh", Reply::invalid());
    service(&server, operator_extra(&server, "obol", 1))
        .run()
        .await
        .unwrap();
    for mode in ["ssv", "obol"] {
        let server = Server::new().await;
        let mut value = operator_extra(&server, mode, 1);
        value[format!("{mode}_node_operator_owner_mode")] = json!("keystore");
        value[format!("{mode}_node_operator_owner_keystores")] =
            json!([{"keystore_path": "unused", "password_path": "missing-test-password"}]);
        assert!(service(&server, value).run().await.is_err());
        assert!(server.requests().is_empty());
    }
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
}
