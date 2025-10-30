use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit, KeyInit};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use thiserror::Error;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes128EcbEnc = ecb::Encryptor<aes::Aes128>;
type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;

/// RSA最大加密明文大小 (for 2048-bit key with PKCS#1 v1.5 padding)
const MAX_ENCRYPT_BLOCK: usize = 117;

/// Custom error types
#[derive(Error, Debug)]
pub enum RsaUtilsError {
    #[error("RSA encryption error: {0}")]
    RsaError(#[from] rsa::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    #[error("PKCS8 error: {0}")]
    Pkcs8Error(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Cipher error: {0}")]
    CipherError(String),
}

/// RSA key pair container
pub struct KeyPair {
    pub public_key: RsaPublicKey,
    pub private_key: RsaPrivateKey,
}

/// Initialize and generate RSA key pair (2048-bit)
pub fn init_key() -> Result<KeyPair, RsaUtilsError> {
    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits)?;
    let public_key = RsaPublicKey::from(&private_key);

    Ok(KeyPair {
        public_key,
        private_key,
    })
}

/// Get public key from base64 encoded string (X.509/SPKI format)
pub fn get_public_key(key_str: &str) -> Result<RsaPublicKey, RsaUtilsError> {
    let key_bytes = BASE64.decode(key_str)?;

    // Try to parse as SPKI (X.509) format
    let public_key = RsaPublicKey::from_public_key_der(&key_bytes)
        .map_err(|e| RsaUtilsError::Pkcs8Error(format!("Failed to parse public key: {}", e)))?;

    Ok(public_key)
}

/// Get private key from base64 encoded string (PKCS#8 format)
pub fn get_private_key(key_str: &str) -> Result<RsaPrivateKey, RsaUtilsError> {
    let key_bytes = BASE64.decode(key_str)?;

    // Try to parse as PKCS#8 format
    let private_key = RsaPrivateKey::from_pkcs8_der(&key_bytes)
        .map_err(|e| RsaUtilsError::Pkcs8Error(format!("Failed to parse private key: {}", e)))?;

    Ok(private_key)
}

/// Encode public key to base64 string (X.509/SPKI format)
pub fn encode_public_key(public_key: &RsaPublicKey) -> Result<String, RsaUtilsError> {
    let der = public_key
        .to_public_key_der()
        .map_err(|e| RsaUtilsError::Pkcs8Error(format!("Failed to encode public key: {}", e)))?;
    Ok(BASE64.encode(der.as_bytes()))
}

/// Encode private key to base64 string (PKCS#8 format)
pub fn encode_private_key(private_key: &RsaPrivateKey) -> Result<String, RsaUtilsError> {
    let der = private_key
        .to_pkcs8_der()
        .map_err(|e| RsaUtilsError::Pkcs8Error(format!("Failed to encode private key: {}", e)))?;
    Ok(BASE64.encode(der.as_bytes()))
}

/// Encrypt data with RSA public key (supports data larger than key size via chunking)
pub fn encrypt(plain_text: &[u8], public_key_str: &str) -> Result<Vec<u8>, RsaUtilsError> {
    let public_key = get_public_key(public_key_str)?;
    let mut rng = OsRng;

    let mut result = Vec::new();
    let mut offset = 0;
    let input_len = plain_text.len();

    while offset < input_len {
        let chunk_size = std::cmp::min(MAX_ENCRYPT_BLOCK, input_len - offset);
        let chunk = &plain_text[offset..offset + chunk_size];

        let encrypted_chunk = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, chunk)?;
        result.extend_from_slice(&encrypted_chunk);

        offset += chunk_size;
    }

    Ok(result)
}

/// Encrypt file using hybrid encryption (AES for file content, RSA for AES key)
/// This matches the Java implementation's approach
pub fn encrypt_file<P: AsRef<Path>>(
    input_path: P,
    output_path: P,
    public_key_str: &str,
) -> Result<(), RsaUtilsError> {
    // Generate random AES key (128-bit)
    let mut aes_key = [0u8; 16];
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut aes_key);
    OsRng.fill_bytes(&mut iv);

    // Get RSA public key
    let public_key = get_public_key(public_key_str)?;
    let mut rng = OsRng;

    // Wrap (encrypt) the AES key with RSA
    let mut key_to_wrap = Vec::new();
    key_to_wrap.extend_from_slice(&aes_key);
    key_to_wrap.extend_from_slice(&iv);

    let wrapped_key = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, &key_to_wrap)?;

    // Open input and output files
    let mut input_file = File::open(input_path)?;
    let mut output_file = File::create(output_path)?;

    // Write wrapped key length and wrapped key
    output_file.write_all(&(wrapped_key.len() as u32).to_be_bytes())?;
    output_file.write_all(&wrapped_key)?;

    // Encrypt file content with AES
    let cipher = Aes128CbcEnc::new(&aes_key.into(), &iv.into());
    encrypt_stream(&mut input_file, &mut output_file, cipher)?;

    Ok(())
}

/// Encrypt file using Java-compatible format (AES/ECB mode)
/// This generates files that can be decrypted by Java's default Cipher.getInstance("AES")
pub fn encrypt_file_java_ecb<P: AsRef<Path>>(
    input_path: P,
    output_path: P,
    public_key_str: &str,
) -> Result<(), RsaUtilsError> {
    // Generate random AES key (128-bit)
    // Note: ECB mode doesn't use IV
    let mut aes_key = [0u8; 16];
    OsRng.fill_bytes(&mut aes_key);

    // Get RSA public key
    let public_key = get_public_key(public_key_str)?;
    let mut rng = OsRng;

    // Wrap (encrypt) only the AES key with RSA (no IV for ECB mode)
    let wrapped_key = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, &aes_key)?;

    // Open input and output files
    let mut input_file = File::open(input_path)?;
    let mut output_file = File::create(output_path)?;

    // Write wrapped key length and wrapped key
    output_file.write_all(&(wrapped_key.len() as u32).to_be_bytes())?;
    output_file.write_all(&wrapped_key)?;

    // Encrypt file content with AES-ECB
    let cipher = Aes128EcbEnc::new(&aes_key.into());
    encrypt_stream_ecb(&mut input_file, &mut output_file, cipher)?;

    Ok(())
}

/// Decrypt file using hybrid decryption (RSA for AES key, AES for file content)
pub fn decrypt_file<P: AsRef<Path>>(
    input_path: P,
    output_path: P,
    private_key_str: &str,
) -> Result<(), RsaUtilsError> {
    // Get RSA private key
    let private_key = get_private_key(private_key_str)?;

    // Open input and output files
    let mut input_file = File::open(input_path)?;
    let mut output_file = File::create(output_path)?;

    // Read wrapped key length
    let mut length_bytes = [0u8; 4];
    input_file.read_exact(&mut length_bytes)?;
    let wrapped_key_len = u32::from_be_bytes(length_bytes) as usize;

    // Read wrapped key
    let mut wrapped_key = vec![0u8; wrapped_key_len];
    input_file.read_exact(&mut wrapped_key)?;

    // Unwrap (decrypt) the AES key with RSA
    let unwrapped = private_key
        .decrypt(Pkcs1v15Encrypt, &wrapped_key)
        .map_err(|e| RsaUtilsError::DecryptionError(format!("Failed to unwrap key: {}", e)))?;

    if unwrapped.len() != 32 {
        return Err(RsaUtilsError::DecryptionError(
            "Invalid unwrapped key size".to_string(),
        ));
    }

    let mut aes_key = [0u8; 16];
    let mut iv = [0u8; 16];
    aes_key.copy_from_slice(&unwrapped[0..16]);
    iv.copy_from_slice(&unwrapped[16..32]);

    // Decrypt file content with AES
    let cipher = Aes128CbcDec::new(&aes_key.into(), &iv.into());
    decrypt_stream(&mut input_file, &mut output_file, cipher)?;

    Ok(())
}

/// Decrypt file encrypted by Java (using AES/ECB mode)
/// Java's default Cipher.getInstance("AES") uses ECB mode without IV
pub fn decrypt_file_java_ecb<P: AsRef<Path>>(
    input_path: P,
    output_path: P,
    private_key_str: &str,
) -> Result<(), RsaUtilsError> {
    // Get RSA private key
    let private_key = get_private_key(private_key_str)?;

    // Open input and output files
    let mut input_file = File::open(input_path)?;
    let mut output_file = File::create(output_path)?;

    // Read wrapped key length
    let mut length_bytes = [0u8; 4];
    input_file.read_exact(&mut length_bytes)?;
    let wrapped_key_len = u32::from_be_bytes(length_bytes) as usize;

    // Read wrapped key
    let mut wrapped_key = vec![0u8; wrapped_key_len];
    input_file.read_exact(&mut wrapped_key)?;

    // Unwrap (decrypt) the AES key with RSA
    let aes_key_bytes = private_key
        .decrypt(Pkcs1v15Encrypt, &wrapped_key)
        .map_err(|e| RsaUtilsError::DecryptionError(format!("Failed to unwrap key: {}", e)))?;

    if aes_key_bytes.len() != 16 {
        return Err(RsaUtilsError::DecryptionError(
            format!("Invalid unwrapped key size: expected 16 bytes, got {}", aes_key_bytes.len()),
        ));
    }

    let mut aes_key = [0u8; 16];
    aes_key.copy_from_slice(&aes_key_bytes[0..16]);

    // Decrypt file content with AES-ECB
    let cipher = Aes128EcbDec::new(&aes_key.into());
    decrypt_stream_ecb(&mut input_file, &mut output_file, cipher)?;

    Ok(())
}

/// Encrypt data stream with AES cipher (CBC mode)
fn encrypt_stream<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    cipher: Aes128CbcEnc,
) -> Result<(), RsaUtilsError> {
    let mut buffer = Vec::new();
    input.read_to_end(&mut buffer)?;

    // Pad and encrypt
    let ciphertext = cipher.encrypt_padded_vec_mut::<Pkcs7>(&buffer);

    output.write_all(&ciphertext)?;
    Ok(())
}

/// Encrypt data stream with AES cipher (ECB mode - for Java compatibility)
fn encrypt_stream_ecb<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    cipher: Aes128EcbEnc,
) -> Result<(), RsaUtilsError> {
    let mut buffer = Vec::new();
    input.read_to_end(&mut buffer)?;

    // Pad and encrypt
    let ciphertext = cipher.encrypt_padded_vec_mut::<Pkcs7>(&buffer);

    output.write_all(&ciphertext)?;
    Ok(())
}

/// Decrypt data stream with AES cipher (CBC mode)
fn decrypt_stream<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    cipher: Aes128CbcDec,
) -> Result<(), RsaUtilsError> {
    let mut buffer = Vec::new();
    input.read_to_end(&mut buffer)?;

    // Decrypt and unpad
    let plaintext = cipher
        .decrypt_padded_vec_mut::<Pkcs7>(&buffer)
        .map_err(|e| RsaUtilsError::DecryptionError(format!("Decryption failed: {}", e)))?;

    output.write_all(&plaintext)?;
    Ok(())
}

/// Decrypt data stream with AES cipher (ECB mode - for Java compatibility)
fn decrypt_stream_ecb<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    cipher: Aes128EcbDec,
) -> Result<(), RsaUtilsError> {
    let mut buffer = Vec::new();
    input.read_to_end(&mut buffer)?;

    // Decrypt and unpad
    let plaintext = cipher
        .decrypt_padded_vec_mut::<Pkcs7>(&buffer)
        .map_err(|e| RsaUtilsError::DecryptionError(format!("Decryption failed: {}", e)))?;

    output.write_all(&plaintext)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::traits::PublicKeyParts;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_key_generation() {
        let key_pair = init_key().unwrap();
        assert_eq!(key_pair.private_key.size(), 256); // 2048 bits = 256 bytes
    }

    #[test]
    fn test_key_encoding_decoding() {
        let key_pair = init_key().unwrap();

        // Test public key
        let pub_key_str = encode_public_key(&key_pair.public_key).unwrap();
        let decoded_pub = get_public_key(&pub_key_str).unwrap();
        assert_eq!(key_pair.public_key.n(), decoded_pub.n());

        // Test private key
        let priv_key_str = encode_private_key(&key_pair.private_key).unwrap();
        let decoded_priv = get_private_key(&priv_key_str).unwrap();
        assert_eq!(key_pair.private_key.n(), decoded_priv.n());
    }

    #[test]
    fn test_small_data_encryption() {
        let key_pair = init_key().unwrap();
        let pub_key_str = encode_public_key(&key_pair.public_key).unwrap();

        let plain_text = b"Hello, RSA!";
        let encrypted = encrypt(plain_text, &pub_key_str).unwrap();

        // Decrypt to verify
        let decrypted = key_pair
            .private_key
            .decrypt(Pkcs1v15Encrypt, &encrypted)
            .unwrap();
        assert_eq!(plain_text, &decrypted[..]);
    }

    #[test]
    fn test_file_encryption_decryption() {
        let key_pair = init_key().unwrap();
        let pub_key_str = encode_public_key(&key_pair.public_key).unwrap();
        let priv_key_str = encode_private_key(&key_pair.private_key).unwrap();

        // Create test file
        let mut input_file = NamedTempFile::new().unwrap();
        let test_data = b"This is a test file for RSA encryption!\nIt has multiple lines.\nAnd some more content to make it interesting.";
        input_file.write_all(test_data).unwrap();
        input_file.flush().unwrap();

        // Create temp files for encrypted and decrypted output
        let encrypted_file = NamedTempFile::new().unwrap();
        let decrypted_file = NamedTempFile::new().unwrap();

        // Encrypt
        encrypt_file(
            input_file.path(),
            encrypted_file.path(),
            &pub_key_str,
        )
            .unwrap();

        // Decrypt
        decrypt_file(
            encrypted_file.path(),
            decrypted_file.path(),
            &priv_key_str,
        )
            .unwrap();

        // Verify
        let mut decrypted_content = Vec::new();
        File::open(decrypted_file.path())
            .unwrap()
            .read_to_end(&mut decrypted_content)
            .unwrap();

        assert_eq!(test_data, &decrypted_content[..]);
    }
}
