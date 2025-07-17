# FROST Threshold Signing (FROST-secp256k1-tr)

This Rust project demonstrates how to perform a distributed key generation (DKG) and threshold signature using the FROST (Flexible Round-Optimized Schnorr Threshold) protocol over `secp256k1` with Taproot (`frost_secp256k1_tr`).

## ⚙️ Features

- Configurable threshold signing (`t-of-n`)
- DKG implementation in 3 rounds
- Signing with `t` participants
- Aggregation of partial signature shares
- Taproot-compatible `secp256k1` signatures

## 🛠 How to Use

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/your-repo-name
cd your-repo-name
```

### 2. Set Threshold Parameters

Edit the following section in `main.rs` to set the threshold and number of total participants:

```rust
let threshold = 2;
let max_signers = 5;
```

- `threshold`: minimum number of parties required to sign.
- `max_signers`: total number of parties participating in DKG.

For example, `threshold = 3` and `max_signers = 5` sets up a 3-of-5 FROST configuration.

### 3. Build & Run

Ensure you have Rust installed. Then run:

```bash
cargo run
```

This will generate keys, perform DKG, sign the message `"Hello, FROST!"` with `threshold` participants, and print the aggregated signature.

## 📦 Dependencies

Make sure your `Cargo.toml` includes:

```toml
frost-secp256k1-tr = "0.9"
bitcoin = "0.30"
rand = "0.8"
```

## 📄 License

MIT or Apache 2.0
