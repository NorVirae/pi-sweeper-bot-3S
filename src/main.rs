use bip39::{Language, Mnemonic};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::error::Error as StdError;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use stellar_sdk::Keypair;
use tokio::sync::{Mutex, mpsc};
use tokio::{self, time};

use pi_network::PiNetwork;

const API_KEY: &str = "b36ty496dx4sprsn7yavxatzm4bone3uj3uzvcazc2ltfidlnsmmfstmfzuxdsqk";
const NETWORK_PASSPHRASE: &str = "Pi Network";
const TARGET_ADDRESS: &str = "GCR5CBW2Q3FD6V72UKPXEXTG6TZVBOQVBGVPXICBTVBLCBV3YY5YDZUC";

const MNEMONIC_PHRASE: &str = "ask cute gospel weapon faith exclude beach salon session twelve stove deposit sword pill emotion senior lobster case zone genius change tragic stuff confirm";

// Aggressive sweep parameters
const MAX_ATTEMPTS: usize = 1000; // Increased from 600
const RETRY_INTERVAL_MS: u64 = 1; // Reduced from 10ms to 1ms
const NUM_PARALLEL_WORKERS: usize = 10; // Increased from 3 to 10
const CONNECTION_POOL_SIZE: usize = 20; // Pre-initialize this many connections

#[derive(Debug, Clone)]
struct TransactionResult {
    success: bool,
    hash: Option<String>,
    error: Option<String>,
    latency_ms: u64,
    attempt: usize,
    worker_id: usize,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError + Send + Sync>> {
    // Run the sweeper directly without any time-based waiting

    let pi_network = Arc::new(Mutex::new(PiNetwork::new(MNEMONIC_PHRASE)));
    pi_network
        .lock()
        .await
        .initialize(API_KEY, NETWORK_PASSPHRASE)
        .await?;

    let mut handles = Vec::new();

    for attempt_id in 0..MAX_ATTEMPTS {
        let pi_network = Arc::clone(&pi_network);
        let handle = tokio::spawn(async move {
            let _ = pi_network
                .lock()
                .await
                .send_transaction(TARGET_ADDRESS.to_string(), "200".to_string())
                .await;
        });

        handles.push(handle);
        println!("Attempt {}", attempt_id);
        time::sleep(time::Duration::from_millis(3)).await;
    }

    for handle in handles {
        let _ = handle.await;
    }
    Ok(())
}
