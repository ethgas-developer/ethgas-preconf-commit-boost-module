#![allow(dead_code)]

use alloy::primitives::{Address, B256};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{Request, Response},
};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};

pub const KEY: &str = "0101010101010101010101010101010101010101010101010101010101010101";
pub const ACCESS: &str = "test-access-secret";
pub const REFRESH: &str = "test-refresh-secret";

#[derive(Clone, Debug)]
pub struct Recorded {
    pub method: String,
    pub path: String,
    pub query: HashMap<String, String>,
    pub headers: HashMap<String, String>,
    pub body: String,
}

impl Recorded {
    pub fn form(&self) -> HashMap<String, String> {
        reqwest::Url::parse(&format!("http://test/?{}", self.body))
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect()
    }
}

#[derive(Clone)]
pub struct Reply {
    pub status: u16,
    pub body: String,
    pub headers: Vec<(String, String)>,
}

impl Reply {
    pub fn json(value: Value) -> Self {
        Self {
            status: 200,
            body: value.to_string(),
            headers: Vec::new(),
        }
    }

    pub fn invalid() -> Self {
        Self {
            status: 500,
            body: "not-json test-access-secret".into(),
            headers: Vec::new(),
        }
    }

    pub fn cookie(mut self, value: &str) -> Self {
        self.headers.push(("set-cookie".into(), value.into()));
        self
    }

    pub fn disconnected() -> Self {
        Self {
            status: 307,
            body: String::new(),
            headers: vec![("location".into(), "http://127.0.0.1:0/disconnected".into())],
        }
    }
}

type Responder = dyn Fn(&Recorded) -> Reply + Send + Sync;

#[derive(Clone)]
struct ServerState {
    requests: Arc<Mutex<Vec<Recorded>>>,
    replies: Arc<Mutex<HashMap<String, VecDeque<Reply>>>>,
    responder: Arc<Responder>,
}

pub struct Server {
    pub url: String,
    state: ServerState,
    task: tokio::task::JoinHandle<()>,
}

async fn handle(State(state): State<ServerState>, request: Request<Body>) -> Response<Body> {
    let (parts, body) = request.into_parts();
    let parsed = reqwest::Url::parse(&format!("http://test{}", parts.uri)).unwrap();
    let record = Recorded {
        method: parts.method.to_string(),
        path: parts
            .uri
            .path()
            .strip_prefix("/mainnet")
            .unwrap_or(parts.uri.path())
            .to_string(),
        query: parsed.query_pairs().into_owned().collect(),
        headers: parts
            .headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").into()))
            .collect(),
        body: String::from_utf8(to_bytes(body, 16 * 1024 * 1024).await.unwrap().to_vec()).unwrap(),
    };
    state.requests.lock().unwrap().push(record.clone());
    let scripted = {
        let mut replies = state.replies.lock().unwrap();
        replies.get_mut(&record.path).and_then(|queue| {
            if queue.len() > 1 {
                queue.pop_front()
            } else {
                queue.front().cloned()
            }
        })
    };
    let reply = scripted.unwrap_or_else(|| (state.responder)(&record));
    let mut response = Response::builder()
        .status(reply.status)
        .header("content-type", "application/json");
    for (key, value) in reply.headers {
        response = response.header(key, value);
    }
    response.body(Body::from(reply.body)).unwrap()
}

impl Server {
    pub async fn new() -> Self {
        Self::with_responder(default_reply).await
    }

    pub async fn with_responder(
        responder: impl Fn(&Recorded) -> Reply + Send + Sync + 'static,
    ) -> Self {
        static LOGS: std::sync::Once = std::sync::Once::new();
        LOGS.call_once(|| {
            if std::env::var("ETHGAS_TEST_LEGACY_LOG").is_ok() {
                struct Legacy;
                impl log::Log for Legacy {
                    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
                        metadata.target().starts_with("ethgas_commit")
                            || metadata.target().starts_with("ethgas_deposit")
                    }
                    fn log(&self, record: &log::Record<'_>) {
                        if self.enabled(record.metadata()) {
                            println!("{}", record.args());
                        }
                    }
                    fn flush(&self) {}
                }
                static LOGGER: Legacy = Legacy;
                log::set_logger(&LOGGER).unwrap();
                log::set_max_level(log::LevelFilter::Info);
            } else {
                let _ = tracing_subscriber::fmt()
                    .with_test_writer()
                    .with_max_level(tracing::Level::INFO)
                    .try_init();
            }
        });
        let state = ServerState {
            requests: Arc::new(Mutex::new(Vec::new())),
            replies: Arc::new(Mutex::new(HashMap::new())),
            responder: Arc::new(responder),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().fallback(handle).with_state(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { url, state, task }
    }

    pub fn reply(&self, path: &str, reply: Reply) {
        self.state
            .replies
            .lock()
            .unwrap()
            .insert(path.into(), VecDeque::from([reply]));
    }

    pub fn sequence(&self, path: &str, replies: Vec<Reply>) {
        self.state
            .replies
            .lock()
            .unwrap()
            .insert(path.into(), replies.into());
    }

    pub fn requests(&self) -> Vec<Recorded> {
        self.state.requests.lock().unwrap().clone()
    }

    pub fn calls(&self, path: &str) -> Vec<Recorded> {
        self.requests()
            .into_iter()
            .filter(|r| r.path == path)
            .collect()
    }

    pub async fn response(&self, path: &str) -> reqwest::Response {
        reqwest::get(format!("{}{}", self.url, path)).await.unwrap()
    }
}

pub fn verify_legacy_logging() {
    if std::env::var("ETHGAS_TEST_LEGACY_LOG").is_ok() {
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["tests::", "--nocapture"])
        .env("ETHGAS_TEST_LEGACY_LOG", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let logs = String::from_utf8_lossy(&output.stdout);
    assert!(logs.contains("successful") || logs.contains("failed to"));
    // The v1.0.7 transport diagnostics retain request URLs; URL redaction was
    // added in v1.1 and is outside this behavior-preserving backport.
    for secret in [ACCESS] {
        assert!(!logs.contains(secret), "legacy logger disclosed {secret}");
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub fn address() -> alloy::primitives::Address {
    alloy::signers::local::PrivateKeySigner::from_bytes(&KEY.parse().unwrap())
        .unwrap()
        .address()
}

pub fn pubkeys(count: usize) -> Vec<commit_boost::prelude::BlsPublicKey> {
    (0..count)
        .map(|index| {
            let mut ikm = [1u8; 32];
            ikm[..8].copy_from_slice(&(index as u64 + 1).to_le_bytes());
            let key = blst::min_pk::SecretKey::key_gen(&ikm, &[]).unwrap();
            format!("0x{}", alloy::hex::encode(key.sk_to_pk().to_bytes()))
                .parse()
                .unwrap()
        })
        .collect()
}

pub fn challenge(name: &str, dvt: bool) -> String {
    json!({
        "domain": {"name": name, "version": "1", "chainId": 1,
            "verifyingContract": alloy::primitives::Address::ZERO},
        "message": if dvt { json!({"userId": "42", "userAddress": address(), "verifyType": "operator"}) }
            else { json!({"hash": "nonce", "message": "Sign in", "domain": "ethgas.com"}) }
    }).to_string()
}

pub fn default_reply(request: &Recorded) -> Reply {
    let path = request.path.as_str();
    match path {
        "/" if request.method == "POST" => {
            let rpc: Value = serde_json::from_str(&request.body).unwrap();
            assert_eq!(rpc["method"], "eth_chainId");
            Reply::json(json!({"jsonrpc": "2.0", "id": rpc["id"], "result": "0x1"}))
        }
        "/api/v1/user/login" => Reply::json(
            json!({"success": true, "data": {"eip712Message": challenge("Ethgas Login", false)}}),
        ),
        "/api/v1/user/login/verify" | "/api/v1/user/login/refresh" => {
            Reply::json(json!({"success": true, "data": {"accessToken": {"token": ACCESS}}}))
                .cookie(&format!("refreshToken={REFRESH}; HttpOnly"))
        }
        "/api/v1/validator/register" => {
            Reply::json(json!({"data": {"message": {"eoaAddress": address()}}}))
        }
        "/api/v1/validator/verify/batch" => {
            let form = request.form();
            let results: serde_json::Map<String, Value> = form["publicKeys"]
                .split(',')
                .map(|key| (key.into(), json!({"result": 0})))
                .collect();
            Reply::json(json!({"success": true, "data": results}))
        }
        "/api/v1/validator/deregister" => Reply::json(
            json!({"success": true, "data": {"deleted": request.form()["publicKeys"].split(',').collect::<Vec<_>>()}}),
        ),
        "/signer/v1/get_pubkeys" => Reply::json(
            json!({"keys": pubkeys(3).iter().map(|key| json!({"consensus": key, "proxy_bls": [], "proxy_ecdsa": []})).collect::<Vec<_>>()}),
        ),
        "/signer/v1/request_signature" => {
            let body: Value = serde_json::from_str(&request.body).unwrap();
            let signature = reference_bls_signature(&body);
            Reply::json(json!(format!(
                "0x{}",
                alloy::hex::encode(signature.to_bytes())
            )))
        }
        "/api/v1/user/ssv/operator/register" | "/api/v1/user/obol/operator/register" => {
            let name = if path.contains("/ssv/") {
                "Ethgas SSV operator verification"
            } else {
                "Ethgas Obol operator verification"
            };
            Reply::json(
                json!({"success": true, "data": {"available": true, "messageToSign": challenge(name, true)}}),
            )
        }
        "/api/v1/user/ssv/operator/validator/register" => {
            Reply::json(json!({"success": true, "data": {"validators": pubkeys(2)}}))
        }
        "/api/v1/user/obol/operator/validator/register" => {
            Reply::json(json!({"success": true, "data": {"added": pubkeys(2)}}))
        }
        "/api/v1/user/ssv/operator/validator/deregister"
        | "/api/v1/user/obol/operator/validator/deregister" => {
            Reply::json(json!({"success": true, "data": {"removed": pubkeys(2)}}))
        }
        "/api/v1/user/validators" => {
            Reply::json(json!({"success": true, "data": {"validators": []}}))
        }
        "/api/v1/user/ssv/operators" => {
            Reply::json(json!({"success": true, "data": {"ssvOperators": []}}))
        }
        "/api/v1/user/obol/operators" => {
            Reply::json(json!({"success": true, "data": {"operators": []}}))
        }
        "/api/v1/validator/mode" => Reply::json(json!({"success": true, "data": {"mode": 0}})),
        _ if path.starts_with("/api/") => Reply::json(json!({"success": true})),
        _ => Reply {
            status: 404,
            body: "unexpected test request".into(),
            headers: Vec::new(),
        },
    }
}

// Encode the SSZ signing container independently of Commit-Boost's signer.
pub fn reference_bls_signature(body: &Value) -> blst::min_pk::Signature {
    use sha2::{Digest, Sha256};
    use std::sync::OnceLock;
    static KEYS: OnceLock<HashMap<String, blst::min_pk::SecretKey>> = OnceLock::new();
    let keys = KEYS.get_or_init(|| {
        (0..201)
            .map(|index| {
                let mut ikm = [1u8; 32];
                ikm[..8].copy_from_slice(&(index as u64 + 1).to_le_bytes());
                let key = blst::min_pk::SecretKey::key_gen(&ikm, &[]).unwrap();
                (
                    format!("0x{}", alloy::hex::encode(key.sk_to_pk().to_bytes())),
                    key,
                )
            })
            .collect()
    });
    let hash_pair = |left: &[u8], right: &[u8]| -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(left);
        hash.update(right);
        hash.finalize().into()
    };
    let data: B256 = serde_json::from_value(body["object_root"].clone()).unwrap();
    let fork = hash_pair(&[0u8; 32], &[0u8; 32]);
    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(&[109, 109, 111, 67]);
    domain[4..].copy_from_slice(&fork[..28]);
    keys[body["pubkey"].as_str().unwrap()].sign(
        &hash_pair(data.as_slice(), &domain),
        b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
        &[],
    )
}

pub fn receipt(status: bool) -> Value {
    json!({"transactionHash": B256::repeat_byte(7), "transactionIndex": "0x0",
        "blockHash": B256::repeat_byte(8), "blockNumber": "0x1", "from": address(), "to": Address::ZERO,
        "cumulativeGasUsed": "0x5208", "gasUsed": "0x5208", "contractAddress": null,
        "logs": [], "logsBloom": format!("0x{}", "00".repeat(256)), "status": if status { "0x1" } else { "0x0" },
        "effectiveGasPrice": "0x1", "type": "0x2"})
}

pub fn rpc_reply(request: &Recorded) -> Reply {
    let value: Value = serde_json::from_str(&request.body).unwrap();
    let result = match value["method"].as_str().unwrap() {
        "eth_chainId" => json!("0x1"),
        "eth_getTransactionCount" => json!("0x0"),
        "eth_estimateGas" => json!("0x5208"),
        "eth_gasPrice" | "eth_maxPriorityFeePerGas" => json!("0x1"),
        "eth_feeHistory" => {
            json!({"oldestBlock": "0x0", "baseFeePerGas": ["0x1", "0x1"], "gasUsedRatio": [0.5], "reward": [["0x1"]]})
        }
        "eth_sendRawTransaction" => json!(B256::repeat_byte(7)),
        "eth_getTransactionReceipt" => receipt(true),
        "eth_blockNumber" => json!("0x1"),
        "eth_getBlockByNumber" => {
            let block: alloy::rpc::types::Block = Default::default();
            let mut block = serde_json::to_value(block).unwrap();
            block["number"] = json!("0x1");
            block["hash"] = json!(B256::repeat_byte(8));
            block["baseFeePerGas"] = json!("0x1");
            block
        }
        other => panic!("unexpected RPC method {other}"),
    };
    Reply::json(json!({"jsonrpc": "2.0", "id": value["id"], "result": result}))
}

pub fn funding_reply(request: &Recorded) -> Reply {
    match request.path.as_str() {
        "/api/v1/p/funding/contractAddress" => {
            Reply::json(json!({"success": true, "data": {"contractAddress": Address::ZERO}}))
        }
        "/api/v1/user/funding/deposits" => {
            Reply::json(json!({"success": true, "data": {"deposits": [
            {"eventId": 2, "createDate": 1700000000000i64, "deposits": [{"q": 10000000000000000i128}]},
            {"eventId": 1, "createDate": i64::MAX, "deposits": []}]}}))
        }
        "/api/v1/user/accounts" => Reply::json(
            json!({"success": true, "data": {"accounts": [{"accountId": 10, "type": 1}, {"accountId": 20, "type": 2}]}}),
        ),
        _ => default_reply(request),
    }
}

// Exercise connection failures only when no matching hardware is attached.
// Unknown platforms or failed inventory reads fail closed and skip this fixture.
pub fn no_ledger_device() -> bool {
    #[cfg(target_os = "macos")]
    {
        let Ok(output) = std::process::Command::new("/usr/sbin/ioreg")
            .args(["-r", "-c", "IOUSBHostDevice", "-l"])
            .output()
        else {
            return false;
        };
        return output.status.success()
            && !String::from_utf8_lossy(&output.stdout)
                .lines()
                .any(|line| line.contains("\"idVendor\" = 11415"));
    }
    #[cfg(target_os = "linux")]
    {
        let Ok(devices) = std::fs::read_dir("/sys/bus/usb/devices") else {
            return false;
        };
        return !devices.flatten().any(|device| {
            std::fs::read_to_string(device.path().join("idVendor"))
                .is_ok_and(|vendor| vendor.trim().eq_ignore_ascii_case("2c97"))
        });
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    false
}

pub async fn truncated_http_response() -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 4096];
        socket.read(&mut request).await.unwrap();
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nSet-Cookie: refreshToken=test-refresh-secret\r\nConnection: close\r\n\r\n{").await.unwrap();
        socket.shutdown().await.unwrap();
    });
    url
}
