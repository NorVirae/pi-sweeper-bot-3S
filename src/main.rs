use bip39::{Language, Mnemonic};
use hmac::{Hmac, Mac};
use lazy_static::lazy_static;
use pi_network::PiNetwork;
use sha2::Sha512;
use std::error::Error as StdError;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use stellar_sdk::Keypair;
use tokio::sync::{Mutex, mpsc};
use tokio::{self, time};

type HmacSha512 = Hmac<Sha512>;

const API_KEY: &str = "b36ty496dx4sprsn7yavxatzm4bone3uj3uzvcazc2ltfidlnsmmfstmfzuxdsqk";
const NETWORK_PASSPHRASE: &str = "Pi Testnet";
const TARGET_ADDRESS: &str = "GASNNSRM25MPYGQ5YU2CHMCSNJKN6OAIGKVK73WX6FGUYYSFVNEEIUP6";
const MNEMONIC_PHRASE: &str = "survey company follow govern replace theory carbon goat rail abandon carry timber sister sword mandate chest village gaze absorb vibrant loud orchard cluster october";

const UNLOCK_TIMESTAMP: u64 = 1719795600;

const MAX_ATTEMPTS: usize = 600;
const RETRY_INTERVAL_MS: u64 = 10;

lazy_static! {
    static ref DERIVED_KEYPAIR: Result<Keypair, Box<dyn StdError + Send + Sync>> =
        { get_pi_network_keypair(MNEMONIC_PHRASE) };
}

#[derive(Debug, Clone)]
struct TransactionResult {
    success: bool,
    hash: Option<String>,
    error: Option<String>,
    latency_ms: u64,
    attempt: usize,
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

/// Pre-initialize network client before the actual transaction time
async fn prepare_network_client() -> Result<PiNetwork, Box<dyn StdError + Send + Sync>> {
    // Get keypair from lazy_static or pre-computed source
    let keypair = DERIVED_KEYPAIR.as_ref().map_err(|e| {
        let err_msg = format!("Failed to get keypair: {}", e);
        Box::<dyn StdError + Send + Sync>::from(err_msg)
    })?;

    // Clone the keypair for secret key extraction - fixed to avoid mutable borrow
    let mut keypair_clone = keypair.clone();
    let secret_key = keypair_clone.secret_key().map_err(|e| {
        let err_msg = format!("Failed to get secret key: {}", e);
        Box::<dyn StdError + Send + Sync>::from(err_msg)
    })?;

    let mut pi_network = PiNetwork::new();
    match pi_network
        .initialize(API_KEY, &secret_key, NETWORK_PASSPHRASE)
        .await
    {
        Ok(_) => {
            let balance = pi_network.get_balance();

            println!("{}", balance);
            Ok(pi_network)
        }
        Err(e) => {
            let err_msg = format!("Failed to initialize PI network: {:?}", e);
            Err(Box::<dyn StdError + Send + Sync>::from(err_msg))
        }
    }
}

async fn execute_sweep_transaction(
    pi_network: &mut PiNetwork,
    attempt: usize,
) -> Result<TransactionResult, Box<dyn StdError + Send + Sync>> {
    let start_time = Instant::now();

    match pi_network.send_transaction().await {
        Ok(hash) => {
            let elapsed = start_time.elapsed().as_millis() as u64;
            Ok(TransactionResult {
                success: true,
                hash: None,
                error: None,
                latency_ms: elapsed,
                attempt,
            })
        }
        Err(e) => {
            let elapsed = start_time.elapsed().as_millis() as u64;
            Ok(TransactionResult {
                success: false,
                hash: None,
                error: Some(format!("{:?}", e)),
                latency_ms: elapsed,
                attempt,
            })
        }
    }
}

/// Get current timestamp in seconds
fn get_current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

/// Calculates the time remaining until unlock
fn time_until_unlock() -> i64 {
    UNLOCK_TIMESTAMP as i64 - get_current_timestamp() as i64
}

/// Shared status for tracking successful transfers
struct TransferStatus {
    successful: bool,
    successful_attempt: Option<usize>,
    transaction_hash: Option<String>,
}

/// Continuous sweeping attempts at regular intervals
async fn continuous_sweep_attempts(
    stop_signal: Arc<Mutex<bool>>,
    status: Arc<Mutex<TransferStatus>>,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let mut attempt_count = 1;

    while attempt_count <= MAX_ATTEMPTS {
        // Check if we should stop (because another task succeeded)
        if *stop_signal.lock().await {
            println!("🛑 Stopping attempts - transfer already successful");
            break;
        }

        // Prepare a fresh network client for each attempt
        match prepare_network_client().await {
            Ok(mut network) => {
                let result = execute_sweep_transaction(&mut network, attempt_count).await?;

                if result.success {
                    println!(
                        "✅ Attempt #{} SUCCEEDED in {}ms with hash: {}",
                        attempt_count,
                        result.latency_ms,
                        result.hash.as_ref().unwrap_or(&"unknown".to_string())
                    );

                    // Update shared status
                    let mut status = status.lock().await;
                    status.successful = true;
                    status.successful_attempt = Some(attempt_count);
                    status.transaction_hash = result.hash.clone();

                    // Signal other tasks to stop
                    let mut stop = stop_signal.lock().await;
                    *stop = true;

                    return Ok(());
                } else {
                    println!(
                        "❌ Attempt #{} failed in {}ms: {}",
                        attempt_count,
                        result.latency_ms,
                        result
                            .error
                            .as_ref()
                            .unwrap_or(&"unknown error".to_string())
                    );
                }
            }
            Err(e) => {
                println!(
                    "❌ Attempt #{} failed to initialize client: {}",
                    attempt_count, e
                );
            }
        }

        attempt_count += 1;

        // Wait before the next attempt
        time::sleep(Duration::from_millis(RETRY_INTERVAL_MS)).await;
    }

    Ok(())
}

/// Main sweeper logic with precise timing
async fn run_sweeper() -> Result<(), Box<dyn StdError + Send + Sync>> {
    println!("🚀 Pi Network Sweeper Bot starting up");
    println!(
        "🔒 Target wallet will unlock at timestamp: {}",
        UNLOCK_TIMESTAMP
    );

    // Pre-warm & validate keypair derivation
    println!("🔑 Pre-validating keypair...");
    let keypair = DERIVED_KEYPAIR.as_ref().map_err(|e| {
        println!("❌ Keypair validation failed: {}", e);
        e.to_string()
    })?;
    println!("✅ Keypair validated. Public key: {}", keypair.public_key());

    // Pre-initialize network connections - but don't store in Arc<Mutex<>> to avoid get_mut() issues
    println!("🌐 Pre-initializing network client...");
    let _pi_network = prepare_network_client().await?;
    println!("✅ Network client initialized and ready");

    // Check time until wallet unlocks
    let seconds_until_unlock = time_until_unlock();

    if seconds_until_unlock > 0 {
        println!(
            "⏳ Waiting for {} seconds until wallet unlocks",
            seconds_until_unlock
        );

        // If we have more than a minute, check balance periodically
        if seconds_until_unlock > 60 {
            let check_interval = Duration::from_secs(30);

            // Spawn background task to periodically check balance and network status
            tokio::spawn(async move {
                let mut interval = time::interval(check_interval);
                loop {
                    interval.tick().await;
                    let remaining = time_until_unlock();

                    if remaining <= 0 {
                        break;
                    }

                    // Create a fresh client for each balance check to avoid mutex issues
                    if let Ok(client) = prepare_network_client().await {
                        let balance = client.get_balance();
                        println!(
                            "💰 Current balance: {}, Time remaining: {}s",
                            balance, remaining
                        );
                    }
                }
            });
        }

        // Wait until just before the unlock time
        let wait_until = seconds_until_unlock.saturating_sub(1);
        time::sleep(Duration::from_secs(wait_until as u64)).await;

        // Fine-grained waiting for the last second
        let remaining_ms = (time_until_unlock() * 1000) as u64;
        if remaining_ms > 0 {
            // Leave 100ms buffer before the exact unlock time
            let wait_ms = remaining_ms.saturating_sub(100);
            if wait_ms > 0 {
                time::sleep(Duration::from_millis(wait_ms)).await;
            }
        }
    }

    // High precision timer spin-wait for the exact moment
    println!("⚡ Ready to execute sweep - entering high-precision wait...");
    loop {
        let now = get_current_timestamp();
        if now >= UNLOCK_TIMESTAMP {
            break;
        }

        // Yield to scheduler for a very short time if we're not extremely close
        if UNLOCK_TIMESTAMP - now > 1 {
            time::sleep(Duration::from_millis(1)).await;
        }
    }

    println!("🔓 Wallet unlock time reached! Starting continuous transfer attempts...");

    // Shared state for coordination between workers
    let stop_signal = Arc::new(Mutex::new(false));
    let transfer_status = Arc::new(Mutex::new(TransferStatus {
        successful: false,
        successful_attempt: None,
        transaction_hash: None,
    }));

    // Start multiple workers that will continuously attempt transfers until one succeeds
    let mut handles = Vec::new();
    for worker_id in 1..=3 {
        // 3 parallel workers
        let stop_signal_clone = stop_signal.clone();
        let status_clone = transfer_status.clone();

        let handle = tokio::spawn(async move {
            println!(
                "🔄 Worker #{} starting continuous transfer attempts",
                worker_id
            );
            if let Err(e) = continuous_sweep_attempts(stop_signal_clone, status_clone).await {
                println!("⚠️ Worker #{} error: {}", worker_id, e);
            }
        });

        handles.push(handle);
    }

    // Wait for all workers to complete
    for handle in handles {
        let _ = handle.await;
    }

    // Check final status
    let status = transfer_status.lock().await;
    if status.successful {
        println!(
            "🎉 Sweeping operation completed successfully on attempt #{}!",
            status.successful_attempt.unwrap_or(0)
        );
        println!(
            "📝 Transaction hash: {}",
            status
                .transaction_hash
                .as_ref()
                .unwrap_or(&"unknown".to_string())
        );
    } else {
        println!(
            "⚠️ All sweeping attempts failed after {} tries. The wallet may not have unlocked correctly or another error occurred.",
            MAX_ATTEMPTS
        );
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError + Send + Sync>> {
    // Run the sweeper directly
    run_sweeper().await
}
