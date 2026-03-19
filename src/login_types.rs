use serde::{Serialize, Deserialize};
use alloy::{
    primitives::Signature,
    signers::{
        Signer,
        ledger::LedgerSigner,
        local::PrivateKeySigner,
        Error as SignerError,
    },
    sol_types::{Eip712Domain, SolStruct},
    sol
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Domain {
    pub name: String,
    pub version: String,
    pub chain_id: u64,
    pub verifying_contract: alloy::primitives::Address,
}

#[derive(Debug, Deserialize)]
pub struct Message {
    pub hash: String,
    pub message: String,
    pub domain: String,
}

#[derive(Debug, Deserialize)]
pub struct Eip712Message {
    pub message: Message,
    pub domain: Domain,
}

sol! {
    #[allow(missing_docs)]
    #[derive(Serialize)]
    struct data {
        string hash;
        string message;
        string domain;
    }
}

pub enum EoaSigner {
    PrivateKey(PrivateKeySigner),
    Ledger(LedgerSigner),
}

impl EoaSigner {
    pub fn address(&self) -> alloy::primitives::Address {
        match self {
            EoaSigner::PrivateKey(signer) => signer.address(),
            EoaSigner::Ledger(signer) => signer.address(),
        }
    }

    pub async fn sign_typed_data<T>(
        &self,
        message: &T,
        domain: &Eip712Domain,
    ) -> Result<Signature, SignerError>
    where
        T: SolStruct + Send + Sync,
    {
        match self {
            EoaSigner::Ledger(signer) => signer.sign_typed_data(message, domain).await,
            EoaSigner::PrivateKey(signer) => signer.sign_typed_data(message, domain).await,
        }
    }
}
