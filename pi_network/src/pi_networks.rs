/*
 * For more information visit https://github.com/pi-apps/pi-python
 * Rust equivalent implementation
 */

#![allow(dead_code)] // Temporarily allows unused code during development

use anyhow;
use regex::Regex;
use reqwest::{Client, Error as ReqwestError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net;
use stellar_sdk::{types::Account, Server};

use serde_json::Value;
use std::str::FromStr;
use stellar_base::asset::Asset;
use stellar_base::crypto::PublicKey;
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
}

impl PiNetwork {
    /// Creates a new PiNetwork instance
    pub fn new() -> Self {
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
        }
    }

    /// Initializes the PiNetwork client with the provided API key, wallet private key, and network
    pub async fn initialize(
        &mut self,
        api_key: &str,
        wallet_private_key: &str,
        network: &str,
    ) -> Result<bool, PiNetworkError> {
        if !self.validate_private_seed_format(wallet_private_key) {
            println!("No valid private seed!");
            return Ok(false);
        }

        self.api_key = api_key.to_string();
        self.load_account(wallet_private_key, network)?;

        // Set base_url based on network
        self.base_url = if network == "Pi Network" {
            "https://api.mainnet.minepi.com".to_string()
        } else {
            "https://api.testnet.minepi.com".to_string()
        };

        self.open_payments = HashMap::new();
        self.network = network.to_string();
        
        // Fetch base fee from the network
        self.fee = self.fetch_base_fee().await?;
        println!("SOMEThING H ERE");

        Ok(true)
    }

    // Fixed PiNetwork implementation

    pub async fn send_transaction(&mut self) -> Result<Value, Box<dyn std::error::Error>> {
        // --- User inputs / configuration ---
        let recipient_public_key = "GCR5CBW2Q3FD6V72UKPXEXTG6TZVBOQVBGVPXICBTVBLCBV3YY5YDZUC";
    
        // Parse the recipient public key
        let recipient_pk = PublicKey::from_account_id(recipient_public_key)?;
    
        // --- Retrieve sender's account sequence from Horizon ---
        let horizon_url = if self.network == "Pi Mainnet" {
            "https://api.mainnet.minepi.com".to_string()
        } else {
            "https://api.testnet.minepi.com".to_string()
        };
    
        let client = reqwest::Client::new();
    
        // Step 1: Fetch the current fee stats to get a reasonable fee
        let fee_stats_url = format!("{}/fee_stats", horizon_url);
        let fee_resp = client.get(&fee_stats_url).send().await?;
        if !fee_resp.status().is_success() {
            return Err(format!("Failed to fetch fee stats: {}", fee_resp.status()).into());
        }
    
        let fee_json: Value = fee_resp.json().await?;
        // Get the max fee from the p90 accepted fee for better chances of acceptance
        let fee_str = fee_json["last_ledger_base_fee"].as_str().unwrap_or("100"); // Default higher than MIN_BASE_FEE if we can't get it
    
        let base_fee: u32 = fee_str.parse().unwrap_or(200);
        // Use at least double the last ledger base fee to have a better chance of acceptance
        let fee_value = std::cmp::max(base_fee * 2, 1000); // Use at least 1000 stroops (0.0001 XLM)
    
        // Convert to Stroops type that the SDK expects
        let transaction_fee = stellar_base::amount::Stroops::new(fee_value as i64);
    
        println!("Using transaction fee: {} stroops", fee_value);
    
        // Step 2: Get the FRESH account information and sequence number
        let account_url = format!(
            "{}/accounts/{}",
            horizon_url,
            self.keypair.as_ref().unwrap().public_key()
        );
    
        let resp = client.get(&account_url).send().await?;
        if !resp.status().is_success() {
            return Err(format!("Failed to fetch account from Horizon: {}", resp.status()).into());
        }
    
        let account_json: Value = resp.json().await?;
        let sequence_str = account_json["sequence"]
            .as_str()
            .ok_or("No sequence in response")?;
    
        println!("Current sequence number: {}", sequence_str);
        let sequence_value: i64 = sequence_str.parse()?;
        
        // IMPORTANT: Add 1 to the sequence number
        // The Stellar network expects the next transaction to use sequence+1
        let next_sequence = sequence_value + 1;
        println!("Using next sequence number: {}", next_sequence);
    
        // --- Build the payment operation and transaction ---
        let amount = stellar_base::amount::Amount::from_str("90")?;
        let payment_op = Operation::new_payment()
            .with_destination(recipient_pk)
            .with_amount(amount)?
            .with_asset(Asset::new_native())
            .build()?;
    
        // Determine the correct network passphrase based on network
        let network_passphrase = if self.network == "Pi Mainnet" {
            "Pi Mainnet"
        } else {
            "Pi Testnet"
        };
        println!("Using network passphrase: {}", network_passphrase);
        let network = Network::new(network_passphrase.to_string());
    
        // Build the transaction with our higher fee and operations
        let mut tx = Trans::builder::<PublicKey>(
            self.keypair.as_ref().unwrap().public_key().clone(),
            next_sequence, // Use the incremented sequence number
            transaction_fee,
        )
        .with_memo(Memo::new_text("Testnet XLM transfer")?)
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
        let horizon = if network == "Pi Mainnet" {
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
            Ok(fee_stats.fee_charged.mode)
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

// Implement Default trait for easier instantiation
impl Default for PiNetwork {
    fn default() -> Self {
        Self::new()
    }
}
