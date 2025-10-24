# Java to Rust Conversion Comparison

## Overview
This document compares the original Java RSA utilities implementation with the Rust conversion.

## Key Differences

### 1. **Error Handling**
- **Java**: Uses checked exceptions (`throws Exception`)
- **Rust**: Uses `Result<T, RsaUtilsError>` with custom error enum using `thiserror`

### 2. **Memory Management**
- **Java**: Garbage collected, automatic memory management
- **Rust**: Ownership system with compile-time memory safety guarantees

### 3. **Type System**
- **Java**: Object-oriented with inheritance
- **Rust**: Trait-based with composition, no inheritance

### 4. **Key Storage**
- **Java**: Uses `HashMap<String, Object>` for key pairs
- **Rust**: Uses dedicated `KeyPair` struct with strongly-typed fields

## Function Mapping

| Java Method | Rust Function | Notes |
|------------|---------------|-------|
| `initKey()` | `init_key()` | Returns `KeyPair` struct instead of HashMap |
| `getPublicKey(String)` | `get_public_key(&str)` | Returns `RsaPublicKey` directly |
| `getPrivateKey(String)` | `get_private_key(&str)` | Returns `RsaPrivateKey` directly |
| N/A | `encode_public_key(&RsaPublicKey)` | New function for encoding keys |
| N/A | `encode_private_key(&RsaPrivateKey)` | New function for encoding keys |
| `encrypt(byte[], String)` | `encrypt(&[u8], &str)` | Returns `Vec<u8>` instead of array |
| `encryptFile(String, String, String)` | `encrypt_file(Path, Path, &str)` | Generic over path types |
| `decryptFile(String, String, String)` | `decrypt_file(Path, Path, &str)` | Generic over path types |
| `crypt(InputStream, OutputStream, Cipher)` | `encrypt_stream/decrypt_stream` | Split into two functions |

## Implementation Details

### Key Generation
**Java:**
```java
KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
keyPairGen.initialize(2048);
KeyPair keyPair = keyPairGen.generateKeyPair();
```

**Rust:**
```rust
let mut rng = OsRng;
let bits = 2048;
let private_key = RsaPrivateKey::new(&mut rng, bits)?;
let public_key = RsaPublicKey::from(&private_key);
```

### File Encryption (Hybrid Approach)
Both implementations use the same hybrid encryption approach:
1. Generate random AES key + IV
2. Encrypt AES key with RSA public key
3. Write wrapped key length and wrapped key to file
4. Encrypt file content with AES-128-CBC
5. Write encrypted content

**Java:** Uses `Cipher.WRAP_MODE` and `Cipher.UNWRAP_MODE`
**Rust:** Manually encrypts/decrypts the AES key using RSA

### Chunked RSA Encryption
Both implementations support encrypting data larger than the RSA key size by chunking:
- **MAX_ENCRYPT_BLOCK**: 117 bytes (for 2048-bit key with PKCS#1 v1.5 padding)

## Dependencies

### Java
- JCE (Java Cryptography Extension) - built-in
- Apache Commons Codec (for Base64)

### Rust
- `rsa` - RSA encryption/decryption
- `aes` - AES encryption
- `cbc` - CBC block mode
- `cipher` - Cipher traits
- `base64` - Base64 encoding
- `rand` - Random number generation
- `pkcs8` & `pkcs1` - Key encoding formats
- `thiserror` - Error handling

## Key Format Compatibility

Both implementations use the same key formats:
- **Public Key**: X.509/SPKI format (Base64 encoded)
- **Private Key**: PKCS#8 format (Base64 encoded)

This means keys generated in Java can be used in Rust and vice versa!

## Performance Considerations

### Rust Advantages:
1. **Zero-cost abstractions** - No runtime overhead
2. **No garbage collection** - Predictable performance
3. **Better memory efficiency** - Stack allocation where possible
4. **Compile-time optimizations** - LLVM backend

### Java Advantages:
1. **JIT compilation** - Runtime optimizations
2. **Mature ecosystem** - More cryptographic providers
3. **Cross-platform** - Write once, run anywhere

## Security Notes

Both implementations:
- Use 2048-bit RSA keys (industry standard)
- Use PKCS#1 v1.5 padding for RSA
- Use AES-128-CBC for file encryption
- Use secure random number generators (`SecureRandom` in Java, `OsRng` in Rust)

## Testing

Both implementations include comprehensive tests:
- Key generation
- Key encoding/decoding
- Small data encryption
- File encryption/decryption

**Rust tests run at compile time** and are part of the build process, ensuring correctness before deployment.

## Usage Examples

### Java
```java
Map<String, Object> keyMap = RSAUtils.initKey();
RSAPublicKey publicKey = (RSAPublicKey) keyMap.get("RSAPublicKey");
RSAPrivateKey privateKey = (RSAPrivateKey) keyMap.get("RSAPrivateKey");

RSAUtils.encryptFile("input.txt", "encrypted.bin", publicKeyStr);
RSAUtils.decryptFile("encrypted.bin", "output.txt", privateKeyStr);
```

### Rust
```rust
let key_pair = init_key()?;
let public_key_str = encode_public_key(&key_pair.public_key)?;
let private_key_str = encode_private_key(&key_pair.private_key)?;

encrypt_file("input.txt", "encrypted.bin", &public_key_str)?;
decrypt_file("encrypted.bin", "output.txt", &private_key_str)?;
```

## Conclusion

The Rust implementation provides:
- ✅ **Type safety** - Compile-time guarantees
- ✅ **Memory safety** - No null pointers or buffer overflows
- ✅ **Performance** - Zero-cost abstractions
- ✅ **Compatibility** - Same key formats as Java
- ✅ **Modern error handling** - Result types instead of exceptions
- ✅ **Comprehensive testing** - Built-in test framework

The conversion maintains full functional compatibility with the Java implementation while leveraging Rust's safety and performance benefits.
