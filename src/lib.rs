//! WASM wrapper around MrsAuthFramework (ML-KEM-1024 + Clock KDF + AES-256-GCM).
//! Format: every part gets a length prefix (u32, little-endian).
//!   keygen()  -> [pk_len][pk][sk_len][sk]
//!   encrypt() -> [nonce_len][nonce][ct_len][kyber_ct][payload_len][aes_payload]

use mrs_auth_pqc::{
    derive_key_from_clock, ClockCiphertextPacket, MrsAuthFramework, SecureEnvelope,
};
use wasm_bindgen::prelude::*;

// Helper to safely send Rust errors to JavaScript.
fn err<E: core::fmt::Debug>(e: E) -> JsValue {
    JsValue::from_str(&format!("{:?}", e))
}

// Helper to safely enforce an exact array length.
fn arr<const N: usize>(b: &[u8]) -> Result<[u8; N], JsValue> {
    b.try_into()
        .map_err(|_| JsValue::from_str("invalid length"))
}

// Helper to pack data with a length prefix (u32 LE).
fn put(out: &mut Vec<u8>, part: &[u8]) {
    out.extend_from_slice(&(part.len() as u32).to_le_bytes());
    out.extend_from_slice(part);
}

// Helper to safely unpack data with a length prefix.
fn take<'a>(b: &'a [u8], pos: &mut usize) -> Result<&'a [u8], JsValue> {
    let start = *pos;
    let end = start.checked_add(4).ok_or_else(|| JsValue::from_str("overflow"))?;
    let head = b.get(start..end).ok_or_else(|| JsValue::from_str("truncated data"))?;
    let len = u32::from_le_bytes([head[0], head[1], head[2], head[3]]) as usize;
    
    let data_end = end.checked_add(len).ok_or_else(|| JsValue::from_str("overflow"))?;
    let part = b.get(end..data_end).ok_or_else(|| JsValue::from_str("truncated data"))?;
    *pos = data_end;
    Ok(part)
}

// Helper to securely wipe memory (zeroing) after use.
fn zeroize(data: &mut [u8]) {
    for byte in data.iter_mut() {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// New ML-KEM-1024 keypair.
#[wasm_bindgen]
pub fn keygen() -> Result<Vec<u8>, JsValue> {
    let mut k = MrsAuthFramework::keygen().map_err(err)?;
    let mut out = Vec::with_capacity(4 + k.public_key.len() + 4 + k.secret_key.len());
    
    put(&mut out, &k.public_key);
    put(&mut out, &k.secret_key);
    
    // Wipe the temporary variable from memory immediately.
    zeroize(&mut k.secret_key);
    Ok(out)
}

/// Encrypt with the public key (no unlock required).
#[wasm_bindgen]
pub fn encrypt(
    public_key: &[u8],
    session_id: &[u8],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(err)?;
    
    // The public key must be the exact required length (ML-KEM-1024 = 1568 bytes).
    let pk = arr(public_key)?;
    
    let env = MrsAuthFramework::full_encrypt(
        &pk,
        session_id,
        &nonce,
        associated_data,
        plaintext,
    )
    .map_err(err)?;
    
    let mut out = Vec::new();
    put(&mut out, &nonce);
    put(&mut out, env.packet.kyber_ciphertext.as_ref());
    put(&mut out, env.packet.aes_payload.as_ref());
    Ok(out)
}

/// Decrypt with the secret key.
#[wasm_bindgen]
pub fn decrypt(
    secret_key: &[u8],
    envelope: &[u8],
    session_id: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let mut pos = 0usize;
    let nonce: [u8; 12] = arr(take(envelope, &mut pos)?)?;
    let kyber_ct = take(envelope, &mut pos)?;
    let payload = take(envelope, &mut pos)?;
    
    // Ensure we do not crash on a malformed envelope.
    if pos != envelope.len() {
        return Err(JsValue::from_str("envelope contains extra data"));
    }

    let env = SecureEnvelope {
        packet: ClockCiphertextPacket {
            kyber_ciphertext: arr(kyber_ct)?,
            aes_payload: payload.to_vec(),
        },
    };
    
    // The secret key must be the exact required length (ML-KEM-1024 = 3168 bytes).
    let sk = arr(secret_key)?;
    
    MrsAuthFramework::full_decrypt(&sk, &env, session_id, &nonce, associated_data)
        .map_err(err)
}

/// Audit view of the Clock KDF for a test seed. NEVER returns the actual key.
#[wasm_bindgen]
pub fn clock_audit(seed: &[u8]) -> String {
    let ck = derive_key_from_clock(seed);
    // Note: if the structure of ck.clock changes in the future, 
    // this format string must be updated accordingly.
    format!(
        "N={}\nclock={:?}\nR(N)={}\nk={}\n(A_k,B_k)={:?}",
        ck.n, ck.clock, ck.rn, ck.k, ck.ab
    )
}
