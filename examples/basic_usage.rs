use rsa_utils::{
    decrypt_file, encode_private_key, encode_public_key, encrypt, encrypt_file, init_key,
};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== RSA Utils Example ===\n");

    // 1. Generate RSA key pair
    println!("1. Generating RSA key pair (2048-bit)...");
    let key_pair = init_key()?;
    let public_key_str = encode_public_key(&key_pair.public_key)?;
    let private_key_str = encode_private_key(&key_pair.private_key)?;
    println!("✓ Key pair generated successfully\n");

    println!("Public Key (Base64):");
    println!("{}\n", &public_key_str[..80]); // Show first 80 chars
    println!("Private Key (Base64):");
    println!("{}\n", &private_key_str[..80]); // Show first 80 chars

    // 2. Encrypt small data
    println!("2. Encrypting small data with RSA...");
    let plain_text = b"Hello, this is a secret message!";
    let encrypted_data = encrypt(plain_text, &public_key_str)?;
    println!("✓ Original text: {:?}", String::from_utf8_lossy(plain_text));
    println!("✓ Encrypted data length: {} bytes\n", encrypted_data.len());

    // 3. Encrypt a file
    println!("3. Encrypting a file with hybrid encryption (RSA + AES)...");
    
    // Create a test file
    let test_content = "This is a test file for RSA encryption.\n\
                        It contains multiple lines of text.\n\
                        The file will be encrypted using AES-128-CBC,\n\
                        and the AES key will be encrypted with RSA.\n\
                        This is the same approach used in the Java implementation.";
    
    fs::write("test_input.txt", test_content)?;
    println!("✓ Created test file: test_input.txt");

    // Encrypt the file
    encrypt_file("test_input.txt", "test_encrypted.bin", &public_key_str)?;
    println!("✓ File encrypted: test_encrypted.bin");

    let encrypted_size = fs::metadata("test_encrypted.bin")?.len();
    println!("✓ Encrypted file size: {} bytes\n", encrypted_size);

    // 4. Decrypt the file
    println!("4. Decrypting the file...");
    decrypt_file("test_encrypted.bin", "test_decrypted.txt", &private_key_str)?;
    println!("✓ File decrypted: test_decrypted.txt");

    // Verify the content
    let decrypted_content = fs::read_to_string("test_decrypted.txt")?;
    if decrypted_content == test_content {
        println!("✓ Decryption successful! Content matches original.\n");
    } else {
        println!("✗ Decryption failed! Content does not match.\n");
    }

    // 5. Display decrypted content
    println!("5. Decrypted file content:");
    println!("---");
    println!("{}", decrypted_content);
    println!("---\n");

    // Cleanup
    println!("Cleaning up temporary files...");
    fs::remove_file("test_input.txt")?;
    fs::remove_file("test_encrypted.bin")?;
    fs::remove_file("test_decrypted.txt")?;
    println!("✓ Cleanup complete\n");

    println!("=== Example completed successfully! ===");

    Ok(())
}
