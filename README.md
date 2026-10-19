# iGoSpiral Crypto WASM Bridge

This repository contains the WebAssembly (WASM) wrapper for iGoSpiral. 
It bridges the browser and the core cryptographic library MRS-AUTH-PQC.

The wrapper exposes cryptographic primitives compiled from Rust to WASM, enabling local-first encryption directly in the browser.

## Core Technologies

* ML-KEM-1024 (FIPS 203)
* Clock KDF (19, 9 Diophantine system)
* AES-256-GCM
* MRS-AUTH framework

## Exposed Functions

* `keygen()`: Generates a new ML-KEM-1024 keypair.
* `encrypt(public_key, session_id, associated_data, plaintext)`: Encrypts data using the public key.
* `decrypt(secret_key, envelope, session_id, associated_data)`: Decrypts data using the secret key.
* `clock_audit(seed)`: Returns a string representation of the Clock KDF process (N, tuple, R(N), k, A_k/B_k).

## Building from Source

Requirements: Rust and wasm-pack.

1. Clone the repository.
2. Build the WASM module:
   ```bash
   cargo install wasm-pack
   wasm-pack build --release --target web
