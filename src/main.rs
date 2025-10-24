use rsa_utils::{init_key, encode_public_key, encode_private_key, encrypt_file, decrypt_file, encrypt};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // // Generate 2048-bit RSA key pair
    // let key_pair = init_key()?;
    //
    // // Encode keys to Base64 strings for storage/transmission
    // let public_key_str = encode_public_key(&key_pair.public_key)?;
    // let private_key_str = encode_private_key(&key_pair.private_key)?;
    //
    // // Save keys to files or database
    // std::fs::write("public_key.txt", &public_key_str)?;
    // std::fs::write("private_key.txt", &private_key_str)?;
    //
    // println!("Keys generated and saved!");
    // encrypt_my_file();
    decrypt_my_file();
    Ok(())
}

fn encrypt_my_file() -> Result<(), Box<dyn std::error::Error>> {
    let public_key_str = std::fs::read_to_string("public_key.txt")?;

    encrypt_file(
        "/Users/xinying/workspace/workspace-java/aispeech/binencrypt/target/resource.bin",
        "/Users/xinying/workspace/workspace-java/aispeech/binencrypt/target/resource_1.bin",
        &public_key_str
    )?;

    println!("File encrypted successfully!");
    Ok(())
}

fn decrypt_my_file() -> Result<(), Box<dyn std::error::Error>> {
    let private_key_str = std::fs::read_to_string("private_key.txt")?;

    decrypt_file(
        "/Users/xinying/workspace/workspace-java/aispeech/binencrypt/target/resource_1.bin",
        "/Users/xinying/workspace/workspace-java/aispeech/binencrypt/target/resource_1_01.bin",
        &private_key_str
    )?;

    println!("File decrypted successfully!");
    Ok(())
}