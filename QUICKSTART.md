# Quick Start Guide

## Installation

### Prerequisites
- Rust 1.90.0 or later
- Cargo (comes with Rust)

### Add to Your Project

Add this to your `Cargo.toml`:

```toml
[dependencies]
rsa_utils = { path = "../rsa_utils_rust" }
```

Or if published to crates.io:
```toml
[dependencies]
rsa_utils = "0.1.0"
```

## Basic Usage

### 1. Generate RSA Key Pair

```rust
use rsa_utils::{init_key, encode_public_key, encode_private_key};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate 2048-bit RSA key pair
    let key_pair = init_key()?;
    
    // Encode keys to Base64 strings for storage/transmission
    let public_key_str = encode_public_key(&key_pair.public_key)?;
    let private_key_str = encode_private_key(&key_pair.private_key)?;
    
    // Save keys to files or database
    std::fs::write("public_key.txt", &public_key_str)?;
    std::fs::write("private_key.txt", &private_key_str)?;
    
    println!("Keys generated and saved!");
    Ok(())
}
```

### 2. Encrypt Small Data

```rust
use rsa_utils::encrypt;

fn encrypt_message(message: &str, public_key_str: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let encrypted = encrypt(message.as_bytes(), public_key_str)?;
    Ok(encrypted)
}
```

### 3. Encrypt a File

```rust
use rsa_utils::encrypt_file;

fn encrypt_my_file() -> Result<(), Box<dyn std::error::Error>> {
    let public_key_str = std::fs::read_to_string("public_key.txt")?;
    
    encrypt_file(
        "sensitive_data.txt",
        "sensitive_data.encrypted",
        &public_key_str
    )?;
    
    println!("File encrypted successfully!");
    Ok(())
}
```

### 4. Decrypt a File

```rust
use rsa_utils::decrypt_file;

fn decrypt_my_file() -> Result<(), Box<dyn std::error::Error>> {
    let private_key_str = std::fs::read_to_string("private_key.txt")?;
    
    decrypt_file(
        "sensitive_data.encrypted",
        "sensitive_data_decrypted.txt",
        &private_key_str
    )?;
    
    println!("File decrypted successfully!");
    Ok(())
}
```

## Complete Example

```rust
use rsa_utils::{
    init_key, 
    encode_public_key, 
    encode_private_key,
    encrypt_file,
    decrypt_file
};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Generate keys
    let key_pair = init_key()?;
    let public_key_str = encode_public_key(&key_pair.public_key)?;
    let private_key_str = encode_private_key(&key_pair.private_key)?;
    
    // 2. Create a test file
    fs::write("original.txt", "This is secret data!")?;
    
    // 3. Encrypt the file
    encrypt_file("original.txt", "encrypted.bin", &public_key_str)?;
    println!("✓ File encrypted");
    
    // 4. Decrypt the file
    decrypt_file("encrypted.bin", "decrypted.txt", &private_key_str)?;
    println!("✓ File decrypted");
    
    // 5. Verify
    let original = fs::read_to_string("original.txt")?;
    let decrypted = fs::read_to_string("decrypted.txt")?;
    assert_eq!(original, decrypted);
    println!("✓ Verification successful!");
    
    // Cleanup
    fs::remove_file("original.txt")?;
    fs::remove_file("encrypted.bin")?;
    fs::remove_file("decrypted.txt")?;
    
    Ok(())
}
```

## Error Handling

The library uses Rust's `Result` type for error handling:

```rust
use rsa_utils::{encrypt_file, RsaUtilsError};

fn safe_encrypt() -> Result<(), RsaUtilsError> {
    match encrypt_file("input.txt", "output.bin", "invalid_key") {
        Ok(_) => println!("Success!"),
        Err(RsaUtilsError::Base64Error(e)) => {
            eprintln!("Invalid key format: {}", e);
        }
        Err(RsaUtilsError::IoError(e)) => {
            eprintln!("File error: {}", e);
        }
        Err(e) => {
            eprintln!("Encryption failed: {}", e);
        }
    }
    Ok(())
}
```

## Running Tests

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run a specific test
cargo test test_file_encryption_decryption
```

## Running the Example

```bash
# Run the basic usage example
cargo run --example basic_usage
```

## Common Use Cases

### Secure File Storage
```rust
// Encrypt before storing
encrypt_file("user_data.json", "user_data.encrypted", &public_key)?;

// Decrypt when needed
decrypt_file("user_data.encrypted", "user_data.json", &private_key)?;
```

### Secure Data Transfer
```rust
// Sender: encrypt data
let data = b"Confidential message";
let encrypted = encrypt(data, &recipient_public_key)?;
// Send encrypted data...

// Receiver: decrypt data
let decrypted = private_key.decrypt(Pkcs1v15Encrypt, &encrypted)?;
```

### Key Management
```rust
// Store keys securely
let key_pair = init_key()?;
let pub_key = encode_public_key(&key_pair.public_key)?;
let priv_key = encode_private_key(&key_pair.private_key)?;

// Save to secure storage (e.g., encrypted database, key vault)
save_to_secure_storage("my_public_key", &pub_key)?;
save_to_secure_storage("my_private_key", &priv_key)?;

// Load when needed
let loaded_pub_key = load_from_secure_storage("my_public_key")?;
let public_key = get_public_key(&loaded_pub_key)?;
```

## Best Practices

1. **Never hardcode private keys** - Store them securely
2. **Use environment variables** or secure vaults for key storage
3. **Rotate keys regularly** - Generate new keys periodically
4. **Validate inputs** - Check file sizes and paths before encryption
5. **Handle errors properly** - Don't ignore Result types
6. **Use strong random sources** - The library uses `OsRng` by default
7. **Backup private keys** - Store them in multiple secure locations

## Performance Tips

1. **Large files**: The hybrid encryption (RSA + AES) is efficient for any file size
2. **Batch operations**: Reuse key objects instead of parsing repeatedly
3. **Memory**: Files are read into memory - consider streaming for very large files

## Troubleshooting

### "Invalid key format" error
- Ensure the key string is valid Base64
- Check that you're using the correct key type (public vs private)
- Verify the key was encoded with `encode_public_key` or `encode_private_key`

### "Decryption failed" error
- Verify you're using the correct private key
- Check that the file wasn't corrupted during transfer
- Ensure the file was encrypted with the corresponding public key

### File not found
- Check file paths are correct
- Ensure you have read/write permissions
- Use absolute paths if relative paths aren't working

## Next Steps

- Read the [README.md](README.md) for detailed documentation
- Check [COMPARISON.md](COMPARISON.md) to understand differences from Java
- Browse the source code in `src/lib.rs`
- Run the example: `cargo run --example basic_usage`

## Support

For issues or questions:
1. Check the documentation
2. Run tests to verify installation: `cargo test`
3. Review example code in `examples/`
