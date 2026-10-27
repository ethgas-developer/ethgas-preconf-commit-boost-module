use crate::{login_types::EoaSigner, ofac::update_ofac, query_pubkey::*, utils::*};
use alloy::{
    primitives::{B256, Signature, keccak256},
    signers::local::PrivateKeySigner,
};
use reqwest::Client;
use serde_json::json;

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
        generate_eip712_signature(&challenge("Ethgas Login", false), &signer)
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
            generate_eip712_signature_for_dvt(&challenge(name, true), &signer)
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
                update_payout_address(&client, mode, &server.url, ACCESS, address(), &keys)
                    .await
                    .unwrap();
                let requests = server.requests();
                let batches = count.div_ceil(100);
                assert_eq!(requests.len(), batches * 2);
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
    let missing = dir.path().join("read-only");
    std::fs::create_dir(&missing).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&missing, std::fs::Permissions::from_mode(0o555)).unwrap();
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
    std::fs::set_permissions(&missing, std::fs::Permissions::from_mode(0o755)).unwrap();
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
        let result = runtime.block_on(generate_eip712_signature(&input, &signer()));
        proptest::prop_assert!(result.is_err());
    }
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

// v1.0.7 exports to its working directory. Run each export in a child process
// so parallel tests never change the parent working directory or environment.
async fn export_to(mode: &str, base: String, dir: &std::path::Path) -> eyre::Result<()> {
    let output = tokio::process::Command::new(std::env::current_exe()?)
        .args(["--exact", "tests::export_child", "--nocapture"])
        .current_dir(dir)
        .env("ETHGAS_TEST_EXPORT_MODE", mode)
        .env("ETHGAS_TEST_EXPORT_BASE", base)
        .output()
        .await?;
    if !output.status.success() {
        eyre::bail!(
            "export child failed: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
    Ok(())
}
async fn get_registered_all_pubkeys_to(
    _: &Client,
    base: String,
    _: &str,
    dir: &std::path::Path,
) -> eyre::Result<()> {
    export_to("all", base, dir).await
}
async fn get_registered_ssv_pubkeys_to(
    _: &Client,
    base: String,
    _: &str,
    dir: &std::path::Path,
) -> eyre::Result<()> {
    export_to("ssv", base, dir).await
}
async fn get_registered_obol_pubkeys_to(
    _: &Client,
    base: String,
    _: &str,
    dir: &std::path::Path,
) -> eyre::Result<()> {
    export_to("obol", base, dir).await
}

#[tokio::test]
async fn export_child() {
    let Ok(mode) = std::env::var("ETHGAS_TEST_EXPORT_MODE") else {
        return;
    };
    let base = std::env::var("ETHGAS_TEST_EXPORT_BASE").unwrap();
    let client = Client::new();
    let result = match mode.as_str() {
        "all" => get_registered_all_pubkeys(&client, base, ACCESS).await,
        "ssv" => get_registered_ssv_pubkeys(&client, base, ACCESS).await,
        "obol" => get_registered_obol_pubkeys(&client, base, ACCESS).await,
        _ => panic!("invalid fixture mode"),
    };
    result.unwrap();
}

#[tokio::test]
async fn malformed_signing_messages_and_setting_responses_follow_legacy_policies() {
    for input in ["", "{", "{}", "null"] {
        assert!(generate_eip712_signature(input, &signer()).await.is_err());
        assert!(
            generate_eip712_signature_for_dvt(input, &signer())
                .await
                .is_err()
        );
    }
    let client = Client::new();
    for enabled in [false, true] {
        for reply in [
            Reply::invalid(),
            Reply::json(json!({"success": false, "errorMsgKey": "rejected"})),
        ] {
            let server = Server::with_responder(move |_| reply.clone()).await;
            update_ofac(&client, "standard", &server.url, ACCESS, enabled, "key")
                .await
                .unwrap();
            update_payout_address(&client, "standard", &server.url, ACCESS, address(), "key")
                .await
                .unwrap();
            assert_eq!(server.requests().len(), 2);
        }
    }
    for base in ["invalid", "http://127.0.0.1:0"] {
        assert!(
            update_ofac(&client, "standard", base, ACCESS, true, "key")
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

#[test]
fn legacy_logging_preserves_safe_library_diagnostics() {
    verify_legacy_logging();
}
