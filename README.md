# 🦀 PI Sweeper Bot 3S Project

1. A Rust-based Pi Sweeper Bot project. This README provides instructions for setting up, running, and working with the codebase.

---

## ✅ Prerequisites

2. Make sure you have the following installed:

- [Rust](https://www.rust-lang.org/tools/install) (includes `cargo`)
- Git (to clone the repository)

3. Check installation:

```bash
rustc --version
cargo --version
```

## ✅ clone
4. Check installation:
git clone https://github.com/NorVirae/pi-sweeper-bot-3S.git
cd your-project


## ✅ build
4. Check installation:
cargo build

## ✅ run
4. Check installation:
cargo run


## ✅ running
5.  Run this command
```bash 
cargo run -- \
  --mnemonic "your mnemonic phrase here" \
  --target "TARGET_ADDRESS" \
  --balance 3.1415 \
  --count 10000 \
  --interval 10
  ```
5. afer pasting run, Once project starts up:
- you will update for wallet passphrase copy and paste in
- you will update Target Account copy and paste in Account you want to send pi to
- you will update for pi wallet balance.
- you will update for transaction flood count default = 10000
- you will update for the intervals to wait before sending transactions in ms default = 10ms

Bot should run smoothly from here

