/*
 * For more information visit https://github.com/pi-apps/pi-python
 * Rust equivalent implementation
 */

#![allow(dead_code)] // Temporarily allows unused code during development

// use std::str::FromStr;
use stellar_base::{
    claim::ClaimableBalanceId,
    operations::ClaimClaimableBalanceOperation,
    xdr::{
        ClaimClaimableBalanceOp,
        // ClaimableBalanceId,
        // Memo,
        MuxedAccount,
        //  Operation
    }, // PublicKey,
};

use anyhow::{self, Context};
use bip39::{Language, Mnemonic};
use regex::Regex;
use reqwest::{Client, Error as ReqwestError};
use std::error::Error as StdError;
use stellar_sdk::Keypair;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use stellar_sdk::{types::Account, Server};

use hmac::{Hmac, Mac};
use sha2::Sha512;

use serde_json::Value;
use std::str::FromStr;

type HmacSha512 = Hmac<Sha512>;
use stellar_base::asset::Asset;
use stellar_base::crypto::{
    hash,
    //  MuxedAccount,
    PublicKey,
};
use stellar_base::memo::Memo;
use stellar_base::network::Network;
use stellar_base::operations::Operation;
use stellar_base::transaction::{Transaction as Trans, MIN_BASE_FEE};
use stellar_base::xdr::{Hash, XDRSerialize};
use thiserror::Error;

// Define custom error type for PiNetwork
#[derive(Error, Debug)]
pub enum PiNetworkError {
    #[error("Network request failed: {0}")]
    RequestError(#[from] ReqwestError),

    #[error("Stellar SDK error: {0}")]
    StellarError(#[from] anyhow::Error),

    #[error("Invalid private key format")]
    InvalidPrivateKey,

    #[error("Account not initialized")]
    AccountNotInitialized,

    #[error("Invalid network: {0}")]
    InvalidNetwork(String),

    #[error("JSON parsing error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Other error: {0}")]
    Other(String),
}

// Payment information structure
#[derive(Debug, Serialize, Deserialize)]
pub struct PaymentInfo {
    pub identifier: String,
    pub user_uid: String,
    pub amount: f64,
    pub memo: String,
    pub metadata: Option<serde_json::Value>,
}

// Payment response structure
#[derive(Debug, Serialize, Deserialize)]
pub struct PaymentResponse {
    pub payment_id: String,
    pub tx_id: Option<String>,
    pub status: String,
}

// Define a struct for fee stats that matches the actual structure
#[derive(Debug, Deserialize)]
struct FeeStats {
    fee_charged: FeeCharged,
}

#[derive(Debug, Deserialize)]
struct FeeCharged {
    mode: u32,
}

// Main PiNetwork struct
pub struct PiNetwork {
    api_key: String,
    client: Client,
    account: Option<Account>,
    base_url: String,
    from_address: String,
    open_payments: HashMap<String, serde_json::Value>,
    network: String,
    server: Option<Server>,
    keypair: Option<stellar_base::crypto::KeyPair>, // Use the correct type
    fee: String,
    derived_keypair: Keypair,
    sequence_value: i64, // Use i64 for sequence value
}

impl PiNetwork {
    /// Creates a new PiNetwork instance
    pub fn new(mnemonic_phrase: &str) -> Self {
        Self {
            api_key: String::new(),
            client: Client::new(),
            account: None,
            base_url: String::new(),
            from_address: String::new(),
            open_payments: HashMap::new(),
            network: String::new(),
            server: None, // We'll initialize this properly in load_account
            keypair: None,
            fee: String::from("100"), // Default fee
            derived_keypair: get_pi_network_keypair(mnemonic_phrase).unwrap().clone(),
            sequence_value: 0, // Initialize sequence_value to 0
        }
    }

    /// Initializes the PiNetwork client with the provided API key, wallet private key, and network
    pub async fn initialize(
        &mut self,
        api_key: &str,
        network: &str,
    ) -> Result<bool, PiNetworkError> {
        self.api_key = api_key.to_string();
        let secret_key = self.derived_keypair.secret_key().unwrap().to_string();
        if !self.validate_private_seed_format(&secret_key) {
            println!("No valid private seed!");
            return Ok(false);
        }
        self.load_account(&secret_key, network)?;

        // Set base_url based on network
        self.base_url = if network == "Pi Network" {
            "https://api.mainnet.minepi.com".to_string()
        } else {
            "https://api.testnet.minepi.com".to_string()
        };

        println!("BASE URL: {}", self.base_url);

        self.open_payments = HashMap::new();
        self.network = network.to_string();

        // Fetch base fee from the network
        self.fee = self.fetch_base_fee().await?;
        println!("SOMEThING H ERE");

        let client = reqwest::Client::new();
        // Step 2: Get the FRESH account information and sequence number
        let account_url = format!(
            "{}/accounts/{}",
            &self.base_url,
            self.keypair.as_ref().unwrap().public_key()
        );

        let resp = client.get(&account_url).send().await?;

        let account_json: Value = resp.json().await?;
        let sequence_str = account_json["sequence"]
            .as_str()
            .ok_or("No sequence in response");

        println!("Current sequence number: {}", sequence_str.unwrap());
        let sequence_value: i64 = sequence_str
            .unwrap()
            .parse()
            .map_err(|_| PiNetworkError::Other("Failed to parse sequence number".to_string()))?;
        self.sequence_value = sequence_value.clone();

        Ok(true)
    }

    // Fixed PiNetwork implementation

    pub async fn send_transaction(
        &mut self,
        recp_public_key: String,
        amount: String,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        // --- User inputs / configuration ---
        let recipient_public_key = recp_public_key.clone();
        let recipient_public_key = recipient_public_key.trim();

        // Parse the recipient public key
        let recipient_pk = PublicKey::from_account_id(recipient_public_key)?;

        // --- Retrieve sender's account sequence from Horizon ---
        let horizon_url = if self.network == "Pi Network" {
            "https://api.mainnet.minepi.com".to_string()
        } else {
            "https://api.testnet.minepi.com".to_string()
        };

        let client = reqwest::Client::new();

        // IMPORTANT: Add 1 to the sequence number

        // // Step 2: Get the FRESH account information and sequence number
        // let account_url = format!(
        //     "{}/accounts/{}",
        //     &self.base_url,
        //     self.keypair.as_ref().unwrap().public_key()
        // );

        // let resp = client.get(&account_url).send().await?;

        // let account_json: Value = resp.json().await?;
        // println!("Account JSON: {:?}", &self.base_url);
        // let sequence_str = account_json["sequence"]
        //     .as_str()
        //     .ok_or("No sequence in response");

        // println!("Current sequence number: {}", sequence_str.unwrap());
        // let sequence_value: i64 = sequence_str
        //     .unwrap()
        //     .parse()
        //     .map_err(|_| PiNetworkError::Other("Failed to parse sequence number".to_string()))?;
        // The Stellar network expects the next transaction to use sequence+1
        // Step 2: Get the FRESH account information and sequence number
        let account_url = format!(
            "{}/accounts/{}",
            &self.base_url,
            self.keypair.as_ref().unwrap().public_key()
        );

        let resp = client.get(&account_url).send().await?;

        let account_json: Value = resp.json().await?;
        let sequence_str = account_json["sequence"]
            .as_str()
            .ok_or("No sequence in response");

        println!("Current sequence number: {}", sequence_str.unwrap());
        let sequence_value: i64 = sequence_str
            .unwrap()
            .parse()
            .map_err(|_| PiNetworkError::Other("Failed to parse sequence number".to_string()))?;
        let sequence_value = sequence_value + 1; // Increment the sequence value for the next transaction
        println!("Using next sequence number: {}", sequence_value);

        // --- Build the payment operation and transaction ---
        let amount = stellar_base::amount::Amount::from_str(&amount)?;
        let payment_op = Operation::new_payment()
            .with_destination(recipient_pk)
            .with_amount(amount)?
            .with_asset(Asset::new_native())
            .build()?;

        // let balance_id_xdr =
        //     "00000000750a37e604268cacfd28466b7e730828242e4a808fe93cbe92eb196b37a2f190"; // Example XDR string

        // // The XDR is in hex format, not base64, so convert from hex to bytes
        // let raw: Vec<u8> = hex::decode(balance_id_xdr)?;

        // // Create a ClaimableBalanceId from the XDR bytes
        // // Note: We're using the correct method and error handling
        // let raw_bytes =
        //     hex::decode(balance_id_hex).context("decoding hex for ClaimableBalanceId")?; // hex::decode returns Vec<u8> of length 32

        // // Create the claim operation
        // // Use the Operation builder pattern that matches your other code style
        // let claim_operation = Operation::new_claim_claimable_balance()
        //     .with_claimable_balance_id(balance_id)
        //     .build()?;

        // Determine the correct network passphrase based on network
        println!("Using network passphrase: {}", self.network);
        let network = Network::new(self.network.to_string());

        // let base_fee: u32 = self.fee.parse()?;
        // // Use at least double the last ledger base fee to have a better chance of acceptance
        // let fee_value = std::cmp::max(base_fee * 2, 1000); // Use at least 1000 stroops (0.0001 XLM)

        let stats: &str = &self.fetch_base_fee().await?;
        println!("Fee stats: {:?}", stats);
        // 2. Determine my fee
        let target: u32 = stats.parse()?;
        let per_op = target + 1; // outbid by 1 stroop
        let op_count = 1; // e.g., one payment op
        let transaction_fee = stellar_base::amount::Stroops::new((per_op * op_count) as i64);

        // Convert to Stroops type that the SDK expects
        // Build the transaction with our higher fee and operations
        let mut tx = Trans::builder::<PublicKey>(
            self.keypair.as_ref().unwrap().public_key().clone(),
            sequence_value, // Use the incremented sequence number
            transaction_fee,
        )
        .with_memo(Memo::new_text("Testnet XLM transfer")?)
        // .add_operation(claim_operation)
        .add_operation(payment_op)
        .into_transaction()?;

        // Sign the transaction with the network passphrase
        let result = tx.sign(&self.keypair.as_ref().unwrap(), &network);
        println!("Transaction signing result: {:?}", result);

        // Convert the signed transaction to base64 XDR
        let envelope_xdr = tx.into_envelope().xdr_base64()?;
        println!("XDR: {}", envelope_xdr);

        // --- Submit the transaction to Horizon ---
        let params = [("tx", envelope_xdr.clone())];
        let submit_resp = client
            .post(&format!("{}/transactions", horizon_url))
            .form(&params)
            .send()
            .await?;

        if submit_resp.status().is_success() {
            let submit_json: Value = submit_resp.json().await?;

            println!("Raw transaction response: {:?}", submit_json);

            // Check if the hash exists in the response
            if let Some(hash) = submit_json.get("hash") {
                if hash.is_null() {
                    println!("Warning: Transaction successful but hash is null");
                    return Ok(serde_json::json!("transaction_submitted_but_hash_null"));
                } else {
                    let hash_str = hash.as_str().unwrap_or("unknown");
                    println!("Transaction successful! Hash: {}", hash_str);
                    return Ok(serde_json::json!(hash_str));
                }
            } else {
                println!("Transaction successful but no hash field found in response");
                return Ok(submit_json);
            }
        } else {
            // Capture and inspect the error properly
            let err_status = submit_resp.status();
            let err_text = submit_resp.text().await?;
            println!(
                "Transaction submission failed with status {}: {}",
                err_status, err_text
            );

            // Try to parse the error response as JSON for better error reporting
            let err_json: Result<Value, _> = serde_json::from_str(&err_text);
            if let Ok(json) = err_json {
                if let Some(extras) = json.get("extras") {
                    if let Some(result_codes) = extras.get("result_codes") {
                        println!("Error result codes: {:?}", result_codes);
                    }
                }
                return Err(format!("Transaction submission failed: {}", json).into());
            }

            Err(format!("Transaction submission failed: {}", err_text).into())
        }
    }

    /// Validates the format of a Stellar private key
    fn validate_private_seed_format(&self, private_key: &str) -> bool {
        // Validate that the private key matches the expected format
        // Typically a Stellar private key starts with 'S' and is followed by a Base32-encoded string
        let re = Regex::new(r"^S[0-9A-Z]{55}$").unwrap();
        re.is_match(private_key)
    }

    /// Loads the Stellar account using the provided private key and network
    fn load_account(&mut self, private_key: &str, network: &str) -> Result<(), PiNetworkError> {
        // Create keypair from private key
        self.keypair = Some(
            stellar_base::crypto::KeyPair::from_secret_seed(private_key)
                .map_err(|e| PiNetworkError::StellarError(anyhow::anyhow!("{}", e)))?,
        );

        // Get public key and set from_address
        let public_key = self
            .keypair
            .as_ref()
            .expect("Keypair should be initialized")
            .public_key()
            .to_string();
        self.from_address = public_key.clone();

        // Set the network and horizon server based on network parameter
        let horizon = if network == "Pi Network" {
            "https://api.mainnet.minepi.com".to_string()
        } else {
            "https://api.testnet.minepi.com".to_string()
        };

        println!("HORIZON: {horizon}");

        // Create server with the proper arguments according to the error
        self.server = Some(
            Server::new(horizon, None)
                .map_err(|e| PiNetworkError::StellarError(anyhow::anyhow!("{}", e)))?,
        );

        // Load account information from the network
        let server = self.server.as_ref().expect("Server should be initialized");

        // Using load_account synchronously
        self.account = Some(
            server
                .load_account(&public_key)
                .map_err(|e| PiNetworkError::StellarError(anyhow::anyhow!("{}", e)))?,
        );

        // println!("{:?}", self.account);
        Ok(())
    }

    pub fn get_balance(&self) -> f64 {
        if self.server.is_none() || self.keypair.is_none() {
            return 0.0;
        }

        let server = self.server.as_ref().unwrap();
        let public_key = self.from_address.clone();

        println!("LULA \nQuerying account: {} ACCOUNTS", public_key);

        // Try to get the account data
        match server.load_account(&public_key) {
            Ok(account) => {
                // Convert the account to a serde_json::Value to handle unknown structure
                if let Ok(account_json) = serde_json::to_value(&account) {
                    // Try to extract balances as a JSON array
                    if let Some(balances) = account_json.get("balances").and_then(|b| b.as_array())
                    {
                        // Look for the native asset balance
                        for balance in balances {
                            if let Some("native") =
                                balance.get("asset_type").and_then(|a| a.as_str())
                            {
                                if let Some(balance_str) =
                                    balance.get("balance").and_then(|b| b.as_str())
                                {
                                    if let Ok(amount) = balance_str.parse::<f64>() {
                                        return amount;
                                    }
                                }
                            }
                        }
                    }
                }

                0.0
            }
            Err(err) => {
                println!("Error getting account balance: {:?}", err);
                0.0
            }
        }
    }

    /// Fetches the current base fee from the Stellar network
    async fn fetch_base_fee(&self) -> Result<String, PiNetworkError> {
        if let Some(server) = &self.server {
            // Fee stats is not an async method according to the error, so we remove .await
            let fee_stats = server
                .fee_stats()
                .map_err(|e| PiNetworkError::StellarError(anyhow::anyhow!("{}", e)))?;

            // Access fee based on actual structure
            Ok(fee_stats.fee_charged.max)
        } else {
            Err(PiNetworkError::Other("Server not initialized".to_string()))
        }
    }

    /// Creates a new payment request
    pub async fn create_payment(
        &mut self,
        payment_info: PaymentInfo,
    ) -> Result<PaymentResponse, PiNetworkError> {
        let url = format!("{}/v2/payments", self.base_url);

        let payload = serde_json::json!({
            "payment": {
                "amount": payment_info.amount,
                "memo": payment_info.memo,
                "metadata": payment_info.metadata,
                "uid": payment_info.user_uid,
            },
            "identifier": payment_info.identifier,
        });

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Key {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(PiNetworkError::Other(format!("API error: {}", error_text)));
        }

        let payment_response: PaymentResponse = response.json().await?;

        // Store the payment info for later use
        self.open_payments.insert(
            payment_response.payment_id.clone(),
            serde_json::to_value(&payment_info).map_err(|e| PiNetworkError::JsonError(e))?,
        );

        Ok(payment_response)
    }

    /// Gets the status of a payment
    pub async fn get_payment_status(
        &self,
        payment_id: &str,
    ) -> Result<PaymentResponse, PiNetworkError> {
        let url = format!("{}/v2/payments/{}", self.base_url, payment_id);

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Key {}", self.api_key))
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(PiNetworkError::Other(format!("API error: {}", error_text)));
        }

        let payment_response: PaymentResponse = response.json().await?;
        Ok(payment_response)
    }

    /// Gets the current network
    pub fn get_network(&self) -> &str {
        &self.network
    }

    /// Gets the current account address
    pub fn get_address(&self) -> &str {
        &self.from_address
    }
}
pub fn get_pi_network_keypair(
    mnemonic_phrase: &str,
) -> Result<Keypair, Box<dyn StdError + Send + Sync>> {
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_phrase)?;
    let seed = mnemonic.to_seed("");

    let hmac_key = b"ed25519 seed";
    let mut mac = HmacSha512::new_from_slice(hmac_key)?;
    mac.update(&seed);
    let i = mac.finalize().into_bytes();

    let master_private_key = &i[0..32];
    let master_chain_code = &i[32..64];

    // Purpose level: m/44'
    let purpose_index: u32 = 0x8000002C; // 44 + hardened bit
    let mut data = vec![0u8];
    data.extend_from_slice(master_private_key);
    data.extend_from_slice(&purpose_index.to_be_bytes());

    let mut mac = HmacSha512::new_from_slice(master_chain_code)?;
    mac.update(&data);
    let i = mac.finalize().into_bytes();

    let purpose_private_key = &i[0..32];
    let purpose_chain_code = &i[32..64];

    // Coin type level: m/44'/314159'
    let coin_type_index: u32 = 0x80000000 + 314159; // Pi Network coin type + hardened bit
    let mut data = vec![0u8];
    data.extend_from_slice(purpose_private_key);
    data.extend_from_slice(&coin_type_index.to_be_bytes());

    let mut mac = HmacSha512::new_from_slice(purpose_chain_code)?;
    mac.update(&data);
    let i = mac.finalize().into_bytes();

    let coin_type_private_key = &i[0..32];
    let coin_type_chain_code = &i[32..64];

    // Account level: m/44'/314159'/0'
    let account_index: u32 = 0x80000000; // 0 + hardened bit
    let mut data = vec![0u8];
    data.extend_from_slice(coin_type_private_key);
    data.extend_from_slice(&account_index.to_be_bytes());

    let mut mac = HmacSha512::new_from_slice(coin_type_chain_code)?;
    mac.update(&data);
    let i = mac.finalize().into_bytes();

    let account_private_key = &i[0..32];

    // Create Stellar keypair from the derived private key
    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(account_private_key);

    let keypair = Keypair::from_raw_ed25519_seed(&seed_array)?;

    Ok(keypair)
}
// Implement Default trait for easier instantiation
// impl Default for PiNetwork {
//     fn default() -> Self {
//         Self::new()
//     }
// }
