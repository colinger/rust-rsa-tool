# RSA Utils - Rust Implementation

A Rust implementation of RSA file encryption utilities, converted from Java. This library provides RSA key generation, encryption/decryption, and hybrid file encryption using RSA + AES.

## Features

- **RSA Key Generation**: Generate 2048-bit RSA key pairs
- **Key Encoding/Decoding**: Base64 encoding for public (X.509/SPKI) and private (PKCS#8) keys
- **Data Encryption**: Encrypt data with RSA public key (supports chunking for large data)
- **Hybrid File Encryption**: Encrypt files using AES-128-CBC for content and RSA for key wrapping
- **Compatible Format**: Uses the same hybrid approach as the Java implementation

## Requirements

- Rust 1.90.0 or later

## Usage

### Generate RSA Key Pair

```rust
use rust_rsa_tool::{init_key, encode_public_key, encode_private_key};

let key_pair = init_key()?;
let public_key_str = encode_public_key(&key_pair.public_key)?;
let private_key_str = encode_private_key(&key_pair.private_key)?;

println!("Public Key: {}", public_key_str);
println!("Private Key: {}", private_key_str);
```

### Encrypt Small Data

```rust
use rust_rsa_tool::encrypt;

let plain_text = b"Hello, World!";
let encrypted = encrypt(plain_text, &public_key_str)?;
```

### Encrypt/Decrypt Files

```rust
use rust_rsa_tool::{encrypt_file, decrypt_file};

// Encrypt a file
encrypt_file("input.txt", "encrypted.bin", &public_key_str)?;

// Decrypt a file
decrypt_file("encrypted.bin", "decrypted.txt", &private_key_str)?;
```

## How It Works

### File Encryption Process

1. Generate a random AES-128 key and IV
2. Encrypt the AES key + IV with RSA public key (key wrapping)
3. Write the wrapped key length and wrapped key to output file
4. Encrypt the file content with AES-128-CBC
5. Write encrypted content to output file

### File Decryption Process

1. Read wrapped key length and wrapped key from input file
2. Decrypt (unwrap) the AES key + IV with RSA private key
3. Decrypt the file content with AES-128-CBC
4. Write decrypted content to output file

## Running Tests

```bash
cargo test
```

## Differences from Java Implementation

1. **Error Handling**: Uses Rust's `Result` type with custom error enum instead of exceptions
2. **Memory Safety**: Rust's ownership system ensures memory safety without garbage collection
3. **Cipher Mode**: Uses AES-128-CBC with PKCS7 padding (similar to Java's default AES behavior)
4. **Key Format**: 
   - Public keys: X.509/SPKI format (same as Java's X509EncodedKeySpec)
   - Private keys: PKCS#8 format (same as Java's PKCS8EncodedKeySpec)

## Dependencies

- `rsa`: RSA encryption/decryption
- `aes`: AES encryption
- `cipher`: Cipher traits and block modes
- `base64`: Base64 encoding/decoding
- `rand`: Random number generation
- `pkcs8` & `pkcs1`: Key encoding/decoding
- `thiserror`: Error handling

## License

This is a conversion of Java RSA utilities to Rust.
