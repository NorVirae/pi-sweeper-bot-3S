use clap::Parser;
use std::error::Error as StdError;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::{self, time};

use pi_network::PiNetwork;

const API_KEY: &str = "b36ty496dx4sprsn7yavxatzm4bone3uj3uzvcazc2ltfidlnsmmfstmfzuxdsqk";
const NETWORK_PASSPHRASE: &str = "Pi Network"; //Pi Testnet Pi Network
// const TARGET_ADDRESS: &str = "GCR5CBW2Q3FD6V72UKPXEXTG6TZVBOQVBGVPXICBTVBLCBV3YY5YDZUC";

// const MNEMONIC_PHRASE: &str = "wasp vehicle census boil funny clean bacon census destroy high tower chronic pool exotic chuckle derive melody pave carbon salon easy wink park call";

// // Aggressive sweep parameters
// const MAX_ATTEMPTS: usize = 1000; // Increased from 600
// const AMOUNT: f64 = 0.0001; // Amount to send in each transaction

// const RETRY_INTERVAL_MS: u64 = 1; // Reduced from 10ms to 1ms

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Wallet mnemonic phrase
    #[arg(short, long)]
    mnemonic: String,

    /// Target address to send to
    #[arg(short, long)]
    target: String,

    /// Wallet balance (in Pi)
    #[arg(short, long)]
    balance: f64,

    /// Number of transactions to send
    #[arg(short, long, default_value_t = 10000)]
    count: usize,

    /// Interval between transactions in ms
    #[arg(short, long, default_value_t = 10)]
    interval: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError + Send + Sync>> {
    // Run the sweeper directly without any time-based waiting
    let args = Args::parse();
    let target_address = args.target.clone();
    let pi_network = Arc::new(Mutex::new(PiNetwork::new(&args.mnemonic)));
    pi_network
        .lock()
        .await
        .initialize(API_KEY, NETWORK_PASSPHRASE)
        .await?;

    let mut handles = Vec::new();

    for attempt_id in 0..args.count {
        let target = target_address.clone(); 
        let pi_network = Arc::clone(&pi_network);
        let handle = tokio::spawn(async move {
            let _ = pi_network
                .lock()
                .await
                .send_transaction(target.to_string(), args.balance.clone().to_string())
                .await;
        });

        handles.push(handle);
        println!("Attempt {}", attempt_id);
        time::sleep(time::Duration::from_millis(args.interval)).await;
    }

    for handle in handles {
        let _ = handle.await;
    }
    Ok(())
}
