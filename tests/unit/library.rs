use crate::{login_types::EoaSigner, ofac::update_ofac, query_pubkey::*, utils::*};
use alloy::{
    primitives::{Address, B256, Signature, keccak256},
    signers::local::PrivateKeySigner,
};
use reqwest::Client;
use serde_json::{Value, json};

#[path = "../support/mod.rs"]
mod support;
use support::*;

fn signer() -> EoaSigner {
    EoaSigner::PrivateKey(PrivateKeySigner::from_bytes(&KEY.parse().unwrap()).unwrap())
}

// Independent EIP-712 encoding: each field is a 32-byte ABI word, then 0x1901.
fn reference_hash(name: &str, fields: &[(&str, &str)]) -> B256 {
    let mut domain = Vec::new();
    domain.extend_from_slice(
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        )
        .as_slice(),
    );
    domain.extend_from_slice(keccak256(name).as_slice());
    domain.extend_from_slice(keccak256("1").as_slice());
    let mut chain = [0u8; 32];
    chain[31] = 1;
    domain.extend_from_slice(&chain);
    domain.extend_from_slice(&[0u8; 32]);
    let types = fields
        .iter()
        .map(|(key, _)| format!("string {key}"))
        .collect::<Vec<_>>()
        .join(",");
    let mut message = keccak256(format!("data({types})")).to_vec();
    for (_, value) in fields {
        message.extend_from_slice(keccak256(value).as_slice());
    }
    let mut encoded = vec![0x19, 0x01];
    encoded.extend_from_slice(keccak256(domain).as_slice());
    encoded.extend_from_slice(keccak256(message).as_slice());
    keccak256(encoded)
}

#[tokio::test]
async fn signatures_recover_against_independent_eip712_encoding() {
    let signer = signer();
    assert_eq!(signer.address(), address());
    let signature: Signature =
        generate_eip712_signature(&challenge("Ethgas Login", false), &signer, 1)
            .await
            .unwrap()
            .parse()
            .unwrap();
    let hash = reference_hash(
        "Ethgas Login",
        &[
            ("hash", "nonce"),
            ("message", "Sign in"),
            ("domain", "ethgas.com"),
        ],
    );
    assert_eq!(
        signature.recover_address_from_prehash(&hash).unwrap(),
        address()
    );
    assert_ne!(
        signature.recover_address_from_prehash(&B256::ZERO).unwrap(),
        address()
    );
    for name in [
        "Ethgas SSV operator verification",
        "Ethgas Obol operator verification",
    ] {
        let signature: Signature =
            generate_eip712_signature_for_dvt(&challenge(name, true), &signer, 1, name, address())
                .await
                .unwrap()
                .parse()
                .unwrap();
        let addr = format!("{:#x}", address());
        let hash = reference_hash(
            name,
            &[
                ("userId", "42"),
                ("userAddress", &addr),
                ("verifyType", "operator"),
            ],
        );
        assert_eq!(
            signature.recover_address_from_prehash(&hash).unwrap(),
            address()
        );
    }
}

#[tokio::test]
async fn signing_rejects_every_untrusted_domain_field_and_dvt_user() {
    for dvt in [false, true] {
        let name = if dvt {
            "Ethgas SSV operator verification"
        } else {
            "Ethgas Login"
        };
        for (field, value) in [
            ("name", json!("malicious")),
            ("version", json!("2")),
            ("chainId", json!(560048)),
            ("verifyingContract", json!(address())),
        ] {
            let mut message: Value = serde_json::from_str(&challenge(name, dvt)).unwrap();
            message["domain"][field] = value;
            let result = if dvt {
                generate_eip712_signature_for_dvt(
                    &message.to_string(),
                    &signer(),
                    1,
                    name,
                    address(),
                )
                .await
            } else {
                generate_eip712_signature(&message.to_string(), &signer(), 1).await
            };
            assert!(result.is_err(), "accepted {field}");
        }
        for invalid in ["", "{", "{}", "null", r#"{"domain":{}}"#] {
            let result = if dvt {
                generate_eip712_signature_for_dvt(invalid, &signer(), 1, name, address()).await
            } else {
                generate_eip712_signature(invalid, &signer(), 1).await
            };
            assert!(result.is_err());
        }
    }
    for user in ["invalid".to_string(), Address::ZERO.to_string()] {
        let name = "Ethgas Obol operator verification";
        let mut message: Value = serde_json::from_str(&challenge(name, true)).unwrap();
        message["message"]["userAddress"] = json!(user);
        assert!(
            generate_eip712_signature_for_dvt(&message.to_string(), &signer(), 1, name, address())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn sensitive_response_errors_do_not_disclose_secrets() {
    let server = Server::new().await;
    server.reply("/bad", Reply::invalid());
    let error = parse_sensitive_json::<Value>(server.response("/bad").await, "verification")
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("verification") && error.contains("500") && error.contains("body length")
    );
    assert!(!error.contains(ACCESS));
    server.reply("/good", Reply::json(json!({"token": ACCESS})));
    assert_eq!(
        parse_sensitive_json::<Value>(server.response("/good").await, "verification")
            .await
            .unwrap()["token"],
        ACCESS
    );
}

#[tokio::test]
async fn batched_settings_route_and_encode_every_mode_and_boundary() {
    let client = Client::new();
    for mode in ["standard", "ssv", "obol"] {
        for count in [0usize, 1, 99, 100, 101, 201] {
            let keys = (0..count)
                .map(|i| format!("key{i}"))
                .collect::<Vec<_>>()
                .join(",");
            for enabled in [true, false] {
                let server = Server::new().await;
                update_ofac(&client, mode, &server.url, ACCESS, enabled, &keys)
                    .await
                    .unwrap();
                enable_light_mode(&client, mode, &server.url, ACCESS, &keys)
                    .await
                    .unwrap();
                update_payout_address(&client, mode, &server.url, ACCESS, address(), &keys)
                    .await
                    .unwrap();
                let requests = server.requests();
                let batches = count.div_ceil(100);
                assert_eq!(requests.len(), batches * 3);
                for request in &requests {
                    assert_eq!(request.method, "POST");
                    assert_eq!(request.headers["authorization"], format!("Bearer {ACCESS}"));
                    assert!(
                        request.headers["content-type"]
                            .starts_with("application/x-www-form-urlencoded")
                    );
                    assert!(!request.form()["publicKeys"].is_empty());
                    assert!(request.form()["publicKeys"].split(',').count() <= 100);
                    if mode != "standard" {
                        assert!(request.path.contains(&format!("/{mode}/")));
                    }
                }
                let sent: Vec<_> = requests
                    .iter()
                    .filter(|r| r.path.ends_with("/ofac"))
                    .flat_map(|r| {
                        r.form()["publicKeys"]
                            .split(',')
                            .map(str::to_string)
                            .collect::<Vec<_>>()
                    })
                    .collect();
                assert_eq!(sent.join(","), keys);
                for r in requests.iter().filter(|r| r.path.ends_with("/ofac")) {
                    assert_eq!(r.form()["ofac"], enabled.to_string());
                }
                for r in requests
                    .iter()
                    .filter(|r| r.path.ends_with("/validatorPayoutAddress"))
                {
                    assert_eq!(r.form()["validatorPayoutAddress"], address().to_string());
                }
            }
        }
    }
}

#[tokio::test]
async fn api_helpers_preserve_their_error_policies() {
    let client = Client::new();
    for reply in [
        Reply::json(json!({"success": false, "errorMsgKey": "rejected"})),
        Reply::json(json!({"success": false})),
        Reply::invalid(),
    ] {
        let server = Server::with_responder(move |_| reply.clone()).await;
        assert!(
            update_ofac(&client, "standard", &server.url, ACCESS, true, "key")
                .await
                .is_err()
        );
        assert!(
            lock_user_account(&client, &server.url, ACCESS)
                .await
                .is_err()
        );
        assert!(
            read_validator_mode(&client, &server.url, ACCESS)
                .await
                .is_err()
        );
        // These helpers intentionally log API rejections; transport failures propagate.
        update_payout_address(&client, "standard", &server.url, ACCESS, address(), "key")
            .await
            .unwrap();
        enable_light_mode(&client, "standard", &server.url, ACCESS, "key")
            .await
            .unwrap();
        update_validator_mode(&client, &server.url, ACCESS, Some(1))
            .await
            .unwrap();
    }
    let server = Server::new().await;
    server.reply(
        "/api/v1/validator/update/ofac",
        Reply::json(json!({"success": false})),
    );
    update_ofac(&client, "standard", &server.url, ACCESS, false, "key")
        .await
        .unwrap();
    lock_user_account(&client, &server.url, ACCESS)
        .await
        .unwrap();
    for mode in [0, 1, 2] {
        server.reply(
            "/api/v1/validator/mode",
            Reply::json(json!({"success": true, "data": {"mode": mode}})),
        );
        assert_eq!(
            read_validator_mode(&client, &server.url, ACCESS)
                .await
                .unwrap(),
            mode
        );
        update_validator_mode(&client, &server.url, ACCESS, Some(mode))
            .await
            .unwrap();
    }
    let before = server.requests().len();
    update_validator_mode(&client, &server.url, ACCESS, None)
        .await
        .unwrap();
    assert_eq!(server.requests().len(), before);
    for base in ["invalid-url", "http://127.0.0.1:0"] {
        assert!(lock_user_account(&client, base, ACCESS).await.is_err());
        assert!(read_validator_mode(&client, base, ACCESS).await.is_err());
        assert!(
            update_validator_mode(&client, base, ACCESS, Some(0))
                .await
                .is_err()
        );
        assert!(
            update_ofac(&client, "standard", base, ACCESS, true, "key")
                .await
                .is_err()
        );
        assert!(
            enable_light_mode(&client, "standard", base, ACCESS, "key")
                .await
                .is_err()
        );
        assert!(
            update_payout_address(&client, "standard", base, ACCESS, address(), "key")
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn exports_write_exact_keys_for_each_operator_and_propagate_io_failures() {
    let server = Server::new().await;
    let client = Client::new();
    server.reply("/api/v1/user/validators", Reply::json(json!({"success": true, "data": {"validators": [{"publicKey": "key1"}, {"publicKey": "key2"}]}})));
    server.reply("/api/v1/user/ssv/operators", Reply::json(json!({"success": true, "data": {"ssvOperators": [{"ownerAddress": "owner1"}, {"ownerAddress": "owner2"}]}})));
    server.reply("/api/v1/user/obol/operators", Reply::json(json!({"success": true, "data": {"operators": [{"address": "owner1"}, {"address": "owner2"}]}})));
    for path in [
        "/api/v1/user/ssv/operator/validators",
        "/api/v1/user/obol/operator/validators",
    ] {
        server.reply(
            path,
            Reply::json(json!({"success": true, "data": {"validators": ["key1", "key2"]}})),
        );
    }
    let dir = tempfile::tempdir().unwrap();
    get_registered_all_pubkeys_to(&client, server.url.clone(), ACCESS, dir.path())
        .await
        .unwrap();
    get_registered_ssv_pubkeys_to(&client, server.url.clone(), ACCESS, dir.path())
        .await
        .unwrap();
    get_registered_obol_pubkeys_to(&client, server.url.clone(), ACCESS, dir.path())
        .await
        .unwrap();
    let files = std::fs::read_dir(dir.path())
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(files.len(), 5);
    for file in files {
        assert_eq!(
            std::fs::read_to_string(file.path()).unwrap(),
            "key1\nkey2\n"
        );
    }
    let missing = dir.path().join("missing");
    assert!(
        get_registered_all_pubkeys_to(&client, server.url.clone(), ACCESS, &missing)
            .await
            .is_err()
    );
    assert!(
        get_registered_ssv_pubkeys_to(&client, server.url.clone(), ACCESS, &missing)
            .await
            .is_err()
    );
    assert!(
        get_registered_obol_pubkeys_to(&client, server.url.clone(), ACCESS, &missing)
            .await
            .is_err()
    );
    for request in server.requests() {
        assert_eq!(request.method, "GET");
        assert_eq!(request.headers["authorization"], format!("Bearer {ACCESS}"));
        if request.path.ends_with("/operator/validators") {
            let field = if request.path.contains("/ssv/") {
                "ownerAddress"
            } else {
                "operatorAddress"
            };
            assert!(request.query[field].starts_with("owner"));
        }
    }
}

#[tokio::test]
async fn exports_handle_empty_failed_and_malformed_responses() {
    let client = Client::new();
    for reply in [
        Reply::invalid(),
        Reply::json(
            json!({"success": false, "data": {"validators": [], "ssvOperators": [], "operators": []}}),
        ),
        Reply::json(
            json!({"success": true, "data": {"validators": null, "ssvOperators": [], "operators": []}}),
        ),
    ] {
        let server = Server::with_responder(move |_| reply.clone()).await;
        let dir = tempfile::tempdir().unwrap();
        get_registered_all_pubkeys_to(&client, server.url.clone(), ACCESS, dir.path())
            .await
            .unwrap();
        get_registered_ssv_pubkeys_to(&client, server.url.clone(), ACCESS, dir.path())
            .await
            .unwrap();
        get_registered_obol_pubkeys_to(&client, server.url.clone(), ACCESS, dir.path())
            .await
            .unwrap();
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
    for response in [
        json!({"success": false, "data": {"validators": []}}),
        json!({"success": true, "data": {"validators": []}}),
        json!(null),
    ] {
        let server = Server::new().await;
        server.reply(
            "/api/v1/user/ssv/operators",
            Reply::json(
                json!({"success": true, "data": {"ssvOperators": [{"ownerAddress": "owner"}]}}),
            ),
        );
        server.reply(
            "/api/v1/user/obol/operators",
            Reply::json(json!({"success": true, "data": {"operators": [{"address": "owner"}]}})),
        );
        for path in [
            "/api/v1/user/ssv/operator/validators",
            "/api/v1/user/obol/operator/validators",
        ] {
            server.reply(path, Reply::json(response.clone()));
        }
        let dir = tempfile::tempdir().unwrap();
        get_registered_ssv_pubkeys_to(&client, server.url.clone(), ACCESS, dir.path())
            .await
            .unwrap();
        get_registered_obol_pubkeys_to(&client, server.url.clone(), ACCESS, dir.path())
            .await
            .unwrap();
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
    for base in ["invalid", "http://127.0.0.1:0"] {
        assert!(
            get_registered_all_pubkeys(&client, base.into(), ACCESS)
                .await
                .is_err()
        );
        assert!(
            get_registered_ssv_pubkeys(&client, base.into(), ACCESS)
                .await
                .is_err()
        );
        assert!(
            get_registered_obol_pubkeys(&client, base.into(), ACCESS)
                .await
                .is_err()
        );
    }
}

proptest::proptest! {
    #[test]
    fn arbitrary_messages_cannot_bypass_the_required_schema(input in ".{0,256}") {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let result = runtime.block_on(generate_eip712_signature(&input, &signer(), 1));
        proptest::prop_assert!(result.is_err());
    }
}

#[tokio::test]
async fn truncated_sensitive_body_has_safe_diagnostics() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = [0u8; 1024];
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            let count = stream.read(&mut buffer).await.unwrap();
            assert!(count > 0);
            headers.extend_from_slice(&buffer[..count]);
        }
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: close\r\n\r\ntest-access-secret").await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let response = reqwest::get(&url).await.unwrap();
    let error = parse_sensitive_json::<Value>(response, "login verification")
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("failed to read login verification response")
    );
    assert!(!format!("{error:?}").contains(ACCESS));
    server.await.unwrap();
}

#[tokio::test]
async fn mode_api_rejection_with_valid_schema_is_distinct_from_bad_json() {
    let server = Server::new().await;
    let client = Client::new();
    server.reply(
        "/api/v1/validator/mode",
        Reply::json(json!({"success": false, "data": {"mode": 1}})),
    );
    assert!(
        read_validator_mode(&client, &server.url, ACCESS)
            .await
            .unwrap_err()
            .to_string()
            .contains("failed to read validator mode")
    );
    update_validator_mode(&client, &server.url, ACCESS, Some(1))
        .await
        .unwrap();
}

#[test]
fn legacy_logging_preserves_safe_library_diagnostics() {
    verify_legacy_logging();
}

#[tokio::test]
async fn export_requests_reject_bad_urls_and_operator_transport_failures() {
    let client = Client::new();
    let dir = tempfile::tempdir().unwrap();
    assert!(
        get_registered_all_pubkeys_to(&client, "invalid".into(), ACCESS, dir.path())
            .await
            .is_err()
    );
    assert!(
        get_registered_ssv_pubkeys_to(&client, "invalid".into(), ACCESS, dir.path())
            .await
            .is_err()
    );
    assert!(
        get_registered_obol_pubkeys_to(&client, "invalid".into(), ACCESS, dir.path())
            .await
            .is_err()
    );
    let server = Server::new().await;
    server.reply(
        "/api/v1/user/ssv/operators",
        Reply::json(
            json!({"success": true, "data": {"ssvOperators": [{"ownerAddress": "owner"}]}}),
        ),
    );
    server.reply(
        "/api/v1/user/obol/operators",
        Reply::json(json!({"success": true, "data": {"operators": [{"address": "owner"}]}})),
    );
    server.reply(
        "/api/v1/user/ssv/operator/validators",
        Reply::disconnected(),
    );
    server.reply(
        "/api/v1/user/obol/operator/validators",
        Reply::disconnected(),
    );
    assert!(
        get_registered_ssv_pubkeys_to(&client, server.url.clone(), ACCESS, dir.path())
            .await
            .is_err()
    );
    assert!(
        get_registered_obol_pubkeys_to(&client, server.url.clone(), ACCESS, dir.path())
            .await
            .is_err()
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}
