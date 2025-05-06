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
const TARGET_ADDRESS: &str = "GCR5CBW2Q3FD6V72UKPXEXTG6TZVBOQVBGVPXICBTVBLCBV3YY5YDZUC";
const MNEMONIC_PHRASE: &str = "ask cute gospel weapon faith exclude beach salon session twelve stove deposit sword pill emotion senior lobster case zone genius change tragic stuff confirm";

// Aggressive sweep parameters
const MAX_ATTEMPTS: usize = 2000; // Increased from 600
const RETRY_INTERVAL_MS: u64 = 1; // Reduced from 10ms to 1ms
const NUM_PARALLEL_WORKERS: usize = 10; // Increased from 3 to 10
const CONNECTION_POOL_SIZE: usize = 20; // Pre-initialize this many connections

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
    worker_id: usize,
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

    // Clone the keypair for secret key extraction
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
        Ok(_) => Ok(pi_network),
        Err(e) => {
            let err_msg = format!("Failed to initialize PI network: {:?}", e);
            Err(Box::<dyn StdError + Send + Sync>::from(err_msg))
        }
    }
}

async fn execute_sweep_transaction(
    pi_network: &mut PiNetwork,
    attempt: usize,
    worker_id: usize,
) -> Result<TransactionResult, Box<dyn StdError + Send + Sync>> {
    let start_time = Instant::now();

    match pi_network.send_transaction().await {
        Ok(hash) => {
            let elapsed = start_time.elapsed().as_millis() as u64;

            // Debug the hash response
            println!(
                "DEBUG - Worker #{} - Hash response type: {:?}",
                worker_id, hash
            );

            // Extract hash properly based on response type
            let hash_str = match hash.as_str() {
                Some(s) => Some(s.to_string()),
                None => {
                    if hash.is_object() {
                        println!(
                            "DEBUG - Worker #{} - Hash is an object: {:?}",
                            worker_id, hash
                        );
                        // Try to extract hash from response object
                        hash.get("hash")
                            .and_then(|h| h.as_str())
                            .map(|s| s.to_string())
                    } else {
                        println!(
                            "DEBUG - Worker #{} - Unknown hash format: {:?}",
                            worker_id, hash
                        );
                        Some(format!("{:?}", hash))
                    }
                }
            };

            Ok(TransactionResult {
                success: true,
                hash: hash_str,
                error: None,
                latency_ms: elapsed,
                attempt,
                worker_id,
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
                worker_id,
            })
        }
    }
}

/// Shared status for tracking successful transfers
struct TransferStatus {
    successful: bool,
    successful_attempt: Option<usize>,
    successful_worker: Option<usize>,
    transaction_hash: Option<String>,
    total_attempts: usize,
}

/// Continuous sweeping attempts at regular intervals
async fn continuous_sweep_attempts(
    worker_id: usize,
    stop_signal: Arc<Mutex<bool>>,
    status: Arc<Mutex<TransferStatus>>,
    client_pool: Arc<Mutex<Vec<PiNetwork>>>,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let mut attempt_count = 1;

    while attempt_count <= MAX_ATTEMPTS {
        // Check if we should stop (because another task succeeded)
        if *stop_signal.lock().await {
            println!(
                "🛑 Worker #{} stopping - transfer already successful",
                worker_id
            );
            break;
        }

        // Get a client from the pool or create a new one if none available
        let mut network_client = {
            let mut pool = client_pool.lock().await;
            if pool.is_empty() {
                drop(pool); // Release the lock before the async operation
                match prepare_network_client().await {
                    Ok(client) => client,
                    Err(e) => {
                        if attempt_count % 50 == 0 {
                            // Reduce logging frequency
                            println!("⚠️ Worker #{} failed to create client: {}", worker_id, e);
                        }
                        // Retry after a very short delay
                        time::sleep(Duration::from_millis(5)).await;
                        attempt_count += 1;
                        continue;
                    }
                }
            } else {
                pool.pop().unwrap()
            }
        };

        // Execute transaction attempt
        let result =
            match execute_sweep_transaction(&mut network_client, attempt_count, worker_id).await {
                Ok(res) => res,
                Err(e) => {
                    // Return client to the pool if it's still usable
                    {
                        let mut pool = client_pool.lock().await;
                        pool.push(network_client);
                    }

                    if attempt_count % 50 == 0 {
                        // Reduce logging frequency
                        println!(
                            "⚠️ Worker #{} attempt #{} error: {}",
                            worker_id, attempt_count, e
                        );
                    }
                    attempt_count += 1;
                    time::sleep(Duration::from_millis(5)).await;
                    continue;
                }
            };

        // Return client to the pool if transaction failed (client is still usable)
        if !result.success {
            let mut pool = client_pool.lock().await;
            pool.push(network_client);
        }

        // Update status
        {
            let mut status_guard = status.lock().await;
            status_guard.total_attempts += 1;

            // Only log every 50 attempts to reduce console spam
            if attempt_count % 50 == 0 && !result.success {
                println!(
                    "Worker #{} - Attempt #{} failed in {}ms: {}",
                    worker_id,
                    attempt_count,
                    result.latency_ms,
                    result
                        .error
                        .as_ref()
                        .unwrap_or(&"unknown error".to_string())
                );
            }
        }

        if result.success {
            println!(
                "✅ SUCCESSFUL TRANSFER! Worker #{}, Attempt #{} in {}ms with hash: {}",
                worker_id,
                attempt_count,
                result.latency_ms,
                result.hash.as_ref().unwrap_or(&"unknown".to_string())
            );

            // Update shared status
            let mut status_guard = status.lock().await;
            status_guard.successful = true;
            status_guard.successful_attempt = Some(attempt_count);
            status_guard.successful_worker = Some(worker_id);
            status_guard.transaction_hash = result.hash.clone();

            // Signal other tasks to stop
            let mut stop = stop_signal.lock().await;
            *stop = true;

            return Ok(());
        }

        attempt_count += 1;

        // Only add minimal delay between attempts for rate limiting
        if RETRY_INTERVAL_MS > 0 {
            time::sleep(Duration::from_millis(RETRY_INTERVAL_MS)).await;
        }
    }

    Ok(())
}

/// Pre-initialize a pool of network clients
async fn initialize_client_pool(size: usize) -> Vec<PiNetwork> {
    let mut pool = Vec::with_capacity(size);

    println!("🌐 Pre-initializing pool of {} network clients...", size);

    let (tx, mut rx) = mpsc::channel(size);

    // Spawn multiple tasks to initialize clients in parallel
    for i in 0..size {
        let tx = tx.clone();
        tokio::spawn(async move {
            match prepare_network_client().await {
                Ok(client) => {
                    let _ = tx.send((i, Ok(client))).await;
                }
                Err(e) => {
                    let _ = tx.send((i, Err(e.to_string()))).await;
                }
            }
        });
    }
    drop(tx); // Drop the original sender

    // Collect results
    let mut successful = 0;
    while let Some((i, result)) = rx.recv().await {
        match result {
            Ok(client) => {
                pool.push(client);
                successful += 1;
                if successful % 5 == 0 || successful == size {
                    println!("✅ Initialized {}/{} network clients", successful, size);
                }
            }
            Err(e) => {
                println!("⚠️ Failed to initialize client #{}: {}", i, e);
            }
        }
    }

    println!(
        "✅ Client pool initialization complete: {}/{} successful",
        pool.len(),
        size
    );
    pool
}

async fn run_sweeper() -> Result<(), Box<dyn StdError + Send + Sync>> {
    println!("🚀 Pi Network Sweeper Bot starting up");
    println!(
        "⚡ FLOOD MODE ACTIVATED - Will attempt immediate sweep with {} parallel workers",
        NUM_PARALLEL_WORKERS
    );

    // Pre-warm & validate keypair derivation
    println!("🔑 Pre-validating keypair...");
    let keypair = DERIVED_KEYPAIR.as_ref().map_err(|e| {
        println!("❌ Keypair validation failed: {}", e);
        e.to_string()
    })?;
    println!("✅ Keypair validated. Public key: {}", keypair.public_key());

    // Pre-initialize a pool of network connections
    let client_pool = initialize_client_pool(CONNECTION_POOL_SIZE).await;
    let client_pool = Arc::new(Mutex::new(client_pool));

    // Shared state for coordination between workers
    let stop_signal = Arc::new(Mutex::new(false));
    let transfer_status = Arc::new(Mutex::new(TransferStatus {
        successful: false,
        successful_attempt: None,
        successful_worker: None,
        transaction_hash: None,
        total_attempts: 0,
    }));

    println!(
        "🔥 Starting flood sweep with {} workers!",
        NUM_PARALLEL_WORKERS
    );

    // Start multiple workers that will continuously attempt transfers until one succeeds
    let start_time = Instant::now();
    let mut handles = Vec::new();

    for worker_id in 1..=NUM_PARALLEL_WORKERS {
        let stop_signal_clone = stop_signal.clone();
        let status_clone = transfer_status.clone();
        let client_pool_clone = client_pool.clone();

        let handle = tokio::spawn(async move {
            if let Err(e) = continuous_sweep_attempts(
                worker_id,
                stop_signal_clone,
                status_clone,
                client_pool_clone,
            )
            .await
            {
                println!("⚠️ Worker #{} error: {}", worker_id, e);
            }
        });

        handles.push(handle);
    }

    // Progress reporting task
    let status_clone = transfer_status.clone();
    let stop_signal_clone = stop_signal.clone();
    let progress_handle = tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_millis(500));
        loop {
            interval.tick().await;

            // Check if we should stop
            if *stop_signal_clone.lock().await {
                break;
            }

            let status = status_clone.lock().await;
            let elapsed = start_time.elapsed().as_secs();

            if elapsed > 0 {
                println!(
                    "🔄 Progress: {} attempts in {}s ({}/s)",
                    status.total_attempts,
                    elapsed,
                    status.total_attempts / elapsed as usize
                );
            }
        }
    });

    // Wait for success or all workers to complete
    for handle in handles {
        let _ = handle.await;
    }

    // Check final status
    let status = transfer_status.lock().await;
    let elapsed = start_time.elapsed();

    if status.successful {
        println!(
            "🎉 SWEEP SUCCESSFUL! Worker #{} succeeded on attempt #{}!",
            status.successful_worker.unwrap_or(0),
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
            "⚠️ All sweeping attempts failed after {} tries in {:?}. The wallet may not be ready for sweeping or another error occurred.",
            status.total_attempts, elapsed
        );
    }

    println!(
        "📊 Summary: {} attempts in {:?} ({:.2} attempts/sec)",
        status.total_attempts,
        elapsed,
        status.total_attempts as f64 / elapsed.as_secs_f64()
    );

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError + Send + Sync>> {
    // Run the sweeper directly without any time-based waiting
    run_sweeper().await
}
