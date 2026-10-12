use super::*;
use alloy::primitives::Address;
use serde_json::{Value, json};

#[path = "../support/mod.rs"]
mod support;
use support::*;

fn deposit_service(exchange: &Server, rpc: &Server) -> EthgasDepositService {
    EthgasDepositService {
        exchange_api_base: exchange.url.clone(),
        block_confirmation: 0,
        rpc_url: rpc.url.parse().unwrap(),
        collateral_to_be_deposited: Decimal::from_str("0.01").unwrap(),
        collateral_contract: Address::ZERO,
        eoa_signing_key: KEY.parse().unwrap(),
        access_jwt: ACCESS.into(),
    }
}

#[tokio::test]
async fn deposit_submits_exact_value_and_transfers_between_expected_accounts() {
    let rpc = Server::with_responder(rpc_reply).await;
    let exchange = Server::with_responder(funding_reply).await;
    deposit_service(&exchange, &rpc).run().await.unwrap();
    let requests = rpc.requests();
    let send = requests
        .iter()
        .find(|r| r.body.contains("eth_sendRawTransaction"))
        .unwrap();
    let transaction: Value = serde_json::from_str(&send.body).unwrap();
    let encoded = alloy::hex::decode(transaction["params"][0].as_str().unwrap()).unwrap();
    use alloy::consensus::Transaction;
    use alloy::eips::Decodable2718;
    let envelope = alloy::consensus::TxEnvelope::decode_2718(&mut encoded.as_slice()).unwrap();
    assert_eq!(envelope.value(), U256::from(10000000000000000u64));
    assert_eq!(envelope.to(), Some(Address::ZERO));
    assert_eq!(envelope.input().len(), 68);
    assert_eq!(
        &envelope.input()[..4],
        &alloy::primitives::keccak256("deposit((address,uint256)[])")[..4]
    );
    assert_eq!(&envelope.input()[36..], &[0u8; 32]);
    let transfer = exchange.calls("/api/v1/user/account/transfer/token");
    assert_eq!(transfer.len(), 1);
    assert_eq!(transfer[0].query["fromAccountId"], "10");
    assert_eq!(transfer[0].query["toAccountId"], "20");
    assert_eq!(transfer[0].query["quantity"], "0.01");
    assert_eq!(transfer[0].query["tokenId"], "1");
    for request in exchange.requests() {
        assert_eq!(request.headers["authorization"], format!("Bearer {ACCESS}"));
    }
}

#[tokio::test(start_paused = true)]
async fn confirmation_timeout_and_revert_are_errors() {
    let result = confirm_deposit_receipt(std::future::pending()).await;
    assert!(result.unwrap_err().to_string().contains("timeout"));
    let reverted = serde_json::from_value(receipt(false)).unwrap();
    assert!(
        confirm_deposit_receipt(async { Ok(reverted) })
            .await
            .unwrap_err()
            .to_string()
            .contains("reverted")
    );
    let success = serde_json::from_value(receipt(true)).unwrap();
    confirm_deposit_receipt(async { Ok(success) })
        .await
        .unwrap();
}

#[tokio::test]
async fn contract_mismatch_and_malformed_contract_response_prevent_submission() {
    for response in [
        json!({"success": true, "data": {"contractAddress": address()}}),
        json!({"success": false, "data": {"contractAddress": Address::ZERO}}),
        json!(null),
    ] {
        let exchange = Server::new().await;
        let rpc = Server::with_responder(rpc_reply).await;
        exchange.reply("/api/v1/p/funding/contractAddress", Reply::json(response));
        assert!(deposit_service(&exchange, &rpc).run().await.is_err());
        assert!(rpc.requests().is_empty());
        assert!(
            exchange
                .calls("/api/v1/user/account/transfer/token")
                .is_empty()
        );
    }
}

#[tokio::test]
async fn malformed_history_and_missing_accounts_prevent_transfer() {
    for (path, response) in [
        (
            "/api/v1/user/funding/deposits",
            json!({"success": true, "data": {"deposits": [{"eventId": 1, "createDate": i64::MAX, "deposits": [{"q": 1}]}]}}),
        ),
        (
            "/api/v1/user/funding/deposits",
            json!({"success": true, "data": {"deposits": [{"eventId": 1, "createDate": 0, "deposits": []}]}}),
        ),
        (
            "/api/v1/user/accounts",
            json!({"success": true, "data": {"accounts": []}}),
        ),
        (
            "/api/v1/user/accounts",
            json!({"success": true, "data": {"accounts": [{"accountId": 10, "type": 1}]}}),
        ),
        (
            "/api/v1/user/accounts",
            json!({"success": false, "data": {"accounts": []}}),
        ),
        ("/api/v1/user/accounts", json!(null)),
    ] {
        let exchange = Server::with_responder(funding_reply).await;
        let rpc = Server::with_responder(rpc_reply).await;
        exchange.reply(path, Reply::json(response));
        assert!(
            deposit_service(&exchange, &rpc).run().await.is_err(),
            "accepted {path}"
        );
        assert!(
            exchange
                .calls("/api/v1/user/account/transfer/token")
                .is_empty()
        );
    }
}

#[tokio::test]
async fn history_and_transfer_response_variants_are_handled() {
    for history in [
        json!({"success": true, "data": {"deposits": []}}),
        json!({"success": false, "data": {"deposits": []}}),
        json!(null),
    ] {
        for transfer in [
            json!({"success": true}),
            json!({"success": false}),
            json!(null),
        ] {
            let exchange = Server::with_responder(funding_reply).await;
            let rpc = Server::with_responder(rpc_reply).await;
            exchange.reply(
                "/api/v1/user/funding/deposits",
                Reply::json(history.clone()),
            );
            exchange.reply("/api/v1/user/account/transfer/token", Reply::json(transfer));
            deposit_service(&exchange, &rpc).run().await.unwrap();
            assert_eq!(
                exchange.calls("/api/v1/user/account/transfer/token").len(),
                1
            );
        }
    }
}

#[tokio::test]
async fn login_validates_domains_and_verification_results() {
    for response in [
        Reply::json(json!({"success": true, "data": {"accessToken": {"token": ACCESS}}})),
        Reply::json(json!({"success": false, "data": {"accessToken": {"token": ACCESS}}})),
        Reply::json(json!({"success": true, "data": {"accessToken": {"token": ""}}})),
        Reply::invalid(),
    ] {
        let server = Server::new().await;
        server.reply("/api/v1/user/login/verify", response.clone());
        let login = EthgasExchangeService {
            exchange_api_base: server.url.clone(),
            eoa_signing_key: KEY.parse().unwrap(),
            chain_id: 1,
        };
        let result = login.login().await;
        assert_eq!(
            result.is_ok(),
            response.body.contains(ACCESS) && response.body.contains("true")
        );
        assert_eq!(
            server.calls("/api/v1/user/login/verify")[0].query["nonceHash"],
            "nonce"
        );
    }
    for challenge in [
        json!({"success": false, "data": {"eip712Message": challenge("Ethgas Login", false)}}),
        json!({"success": true, "data": {"eip712Message": challenge("malicious", false)}}),
        json!({"success": true, "data": {"eip712Message": "{"}}),
        json!(null),
    ] {
        let server = Server::new().await;
        server.reply("/api/v1/user/login", Reply::json(challenge));
        let login = EthgasExchangeService {
            exchange_api_base: server.url.clone(),
            eoa_signing_key: KEY.parse().unwrap(),
            chain_id: 1,
        };
        assert!(login.login().await.is_err());
        assert!(server.calls("/api/v1/user/login/verify").is_empty());
    }
}

#[tokio::test]
async fn invalid_signers_transport_and_pending_errors_are_reported() {
    let exchange = Server::new().await;
    let rpc = Server::with_responder(rpc_reply).await;
    assert!(
        EthgasExchangeService {
            exchange_api_base: exchange.url.clone(),
            eoa_signing_key: B256::ZERO,
            chain_id: 1
        }
        .login()
        .await
        .is_err()
    );
    let mut deposit = deposit_service(&exchange, &rpc);
    deposit.eoa_signing_key = B256::ZERO;
    assert!(deposit.deposit(Decimal::ONE, Address::ZERO).await.is_err());
    assert!(rpc.requests().is_empty());
    exchange.reply("/api/v1/user/login/verify", Reply::disconnected());
    let error = EthgasExchangeService {
        exchange_api_base: exchange.url.clone(),
        eoa_signing_key: KEY.parse().unwrap(),
        chain_id: 1,
    }
    .login()
    .await
    .unwrap_err();
    let diagnostic = format!("{error:?}");
    assert!(!diagnostic.contains("signature="));
    assert!(!diagnostic.contains("nonceHash="));
    let result = confirm_deposit_receipt(async {
        Err(alloy::providers::PendingTransactionError::FailedToRegister)
    })
    .await;
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("failed to register")
    );
}

#[tokio::test]
async fn local_evm_receives_exact_deposit_and_rejects_reverting_contract() {
    use alloy::{
        network::TransactionBuilder, primitives::Bytes, providers::Provider,
        rpc::types::TransactionRequest,
    };
    use std::process::{Child, Command, Stdio};
    struct Anvil(Child);
    impl Drop for Anvil {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let executable = std::env::var("ANVIL_BIN").unwrap_or_else(|_| "anvil".into());
    let _anvil = Anvil(
        Command::new(executable)
            .args([
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--chain-id",
                "1",
                "--silent",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("install Anvil or set ANVIL_BIN for the local EVM test"),
    );
    let rpc_url: Url = format!("http://127.0.0.1:{port}").parse().unwrap();
    let signer = PrivateKeySigner::from_bytes(&KEY.parse().unwrap()).unwrap();
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect_http(rpc_url.clone());
    tokio::time::timeout(Duration::from_secs(10), async {
        while provider.get_chain_id().await.is_err() {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let _: Value = provider
        .raw_request(
            "anvil_setBalance".into(),
            (address(), "0x3635c9adc5dea00000"),
        )
        .await
        .unwrap();
    assert_eq!(
        provider.get_balance(address()).await.unwrap(),
        U256::from(1000) * U256::from(10).pow(U256::from(18))
    );
    // Payable runtime stores CALLVALUE in slot zero; the second runtime always reverts.
    for (runtime, accepts) in [("3460005500", true), ("60006000fd", false)] {
        let deployment: Bytes = format!("0x6005600c60003960056000f3{runtime}")
            .parse()
            .unwrap();
        let deployed = provider
            .send_transaction(
                TransactionRequest::default()
                    .with_deploy_code(deployment)
                    .with_nonce(provider.get_transaction_count(address()).await.unwrap()),
            )
            .await
            .unwrap()
            .get_receipt()
            .await
            .unwrap();
        let contract = deployed.contract_address.unwrap();
        let exchange = Server::with_responder(funding_reply).await;
        exchange.reply(
            "/api/v1/p/funding/contractAddress",
            Reply::json(json!({"success": true, "data": {"contractAddress": contract}})),
        );
        let service = EthgasDepositService {
            exchange_api_base: exchange.url.clone(),
            block_confirmation: 0,
            rpc_url: rpc_url.clone(),
            collateral_to_be_deposited: Decimal::from_str("0.01").unwrap(),
            collateral_contract: contract,
            eoa_signing_key: KEY.parse().unwrap(),
            access_jwt: ACCESS.into(),
        };
        if !accepts {
            // Force submission past gas estimation to verify an actually mined reverted receipt.
            let transaction = TransactionRequest::default()
                .with_to(contract)
                .with_value(U256::from(10000000000000000u64))
                .with_gas_limit(100000)
                .with_nonce(provider.get_transaction_count(address()).await.unwrap());
            let receipt = provider
                .send_transaction(transaction)
                .await
                .unwrap()
                .get_receipt()
                .await
                .unwrap();
            assert!(
                confirm_deposit_receipt(async { Ok(receipt) })
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("reverted")
            );
        }
        assert_eq!(service.run().await.is_ok(), accepts);
        assert_eq!(
            exchange.calls("/api/v1/user/account/transfer/token").len(),
            usize::from(accepts)
        );
        let expected = if accepts {
            U256::from(10000000000000000u64)
        } else {
            U256::ZERO
        };
        assert_eq!(provider.get_balance(contract).await.unwrap(), expected);
        if accepts {
            assert_eq!(
                provider.get_storage_at(contract, U256::ZERO).await.unwrap(),
                expected
            );
        }
    }
}

#[tokio::test]
async fn exchange_transport_failures_stop_deposit_and_transfer() {
    for path in [
        "/api/v1/p/funding/contractAddress",
        "/api/v1/user/funding/deposits",
        "/api/v1/user/accounts",
        "/api/v1/user/account/transfer/token",
    ] {
        let exchange = Server::with_responder(funding_reply).await;
        let rpc = Server::with_responder(rpc_reply).await;
        exchange.reply(path, Reply::disconnected());
        assert!(
            deposit_service(&exchange, &rpc).run().await.is_err(),
            "{path}"
        );
        assert_eq!(exchange.requests().last().unwrap().path, path);
    }
    let exchange = Server::new().await;
    let rpc = Server::with_responder(rpc_reply).await;
    let mut service = deposit_service(&exchange, &rpc);
    service.exchange_api_base = "invalid".into();
    assert!(service.run().await.is_err());
    assert!(
        deposit_service(&exchange, &rpc)
            .deposit(Decimal::NEGATIVE_ONE, Address::ZERO)
            .await
            .is_err()
    );
    assert!(rpc.requests().is_empty());
    for base in ["invalid", "http://127.0.0.1:0"] {
        assert!(
            EthgasExchangeService {
                exchange_api_base: base.into(),
                eoa_signing_key: KEY.parse().unwrap(),
                chain_id: 1
            }
            .login()
            .await
            .is_err()
        );
    }
}

#[test]
fn legacy_logging_preserves_safe_deposit_diagnostics() {
    verify_legacy_logging();
}

#[tokio::test]
async fn reverted_rpc_receipt_prevents_off_chain_transfer() {
    let rpc = Server::with_responder(|request| {
        let body: Value = serde_json::from_str(&request.body).unwrap();
        if body["method"] == "eth_getTransactionReceipt" {
            Reply::json(json!({"jsonrpc": "2.0", "id": body["id"], "result": receipt(false)}))
        } else {
            rpc_reply(request)
        }
    })
    .await;
    let exchange = Server::with_responder(funding_reply).await;
    assert!(
        deposit_service(&exchange, &rpc)
            .run()
            .await
            .unwrap_err()
            .to_string()
            .contains("reverted")
    );
    assert!(
        exchange
            .calls("/api/v1/user/account/transfer/token")
            .is_empty()
    );
}

#[tokio::test]
async fn oversized_amounts_and_history_quantities_return_errors_without_panics() {
    let exchange = Server::with_responder(funding_reply).await;
    let rpc = Server::with_responder(rpc_reply).await;
    assert!(
        deposit_service(&exchange, &rpc)
            .deposit(Decimal::MAX, Address::ZERO)
            .await
            .unwrap_err()
            .to_string()
            .contains("too large")
    );
    assert!(rpc.requests().is_empty());
    exchange.reply("/api/v1/user/funding/deposits", Reply { status: 200, headers: Vec::new(),
        body: format!(r#"{{"success":true,"data":{{"deposits":[{{"eventId":1,"createDate":0,"deposits":[{{"q":{}}}]}}]}}}}"#, i128::MAX) });
    assert!(deposit_service(&exchange, &rpc).run().await.is_err());
    assert!(
        exchange
            .calls("/api/v1/user/account/transfer/token")
            .is_empty()
    );
}
