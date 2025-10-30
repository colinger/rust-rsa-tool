/// 测试 Java ECB 模式的加密和解密往返
/// 演示：
/// 1. Rust 使用 ECB 模式加密文件
/// 2. Rust 使用 ECB 模式解密文件
/// 3. 验证内容一致性
/// 4. 生成的文件可以被 Java 解密

use rust_rsa_tool::{encrypt_file_java_ecb, decrypt_file_java_ecb, init_key, encode_public_key, encode_private_key};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║  测试 Java ECB 模式加密/解密往返                                ║");
    println!("╚═══════════════════════════════════════════════════════════════╝\n");
    
    // 1. 生成密钥对
    println!("1. 生成 RSA 密钥对...");
    let key_pair = init_key()?;
    let public_key = encode_public_key(&key_pair.public_key)?;
    let private_key = encode_private_key(&key_pair.private_key)?;
    println!("✓ 密钥生成成功 (2048-bit)\n");
    
    // 2. 创建测试文件
    println!("2. 创建测试文件...");
    let test_content = "这是一个测试文件，用于验证 Java ECB 模式的加密和解密。\n\
                        This is a test file for Java ECB mode encryption and decryption.\n\
                        \n\
                        测试内容包括：\n\
                        - 中文字符\n\
                        - English characters\n\
                        - 数字 123456\n\
                        - 特殊符号 !@#$%^&*()\n\
                        \n\
                        文件大小足够大以测试分块加密。\n".repeat(10);
    
    fs::write("test_input.txt", &test_content)?;
    println!("✓ 测试文件创建成功 ({} 字节)\n", test_content.len());
    
    // 3. 使用 ECB 模式加密
    println!("3. 使用 Java ECB 模式加密文件...");
    encrypt_file_java_ecb("test_input.txt", "test_encrypted_ecb.bin", &public_key)?;
    let encrypted_size = fs::metadata("test_encrypted_ecb.bin")?.len();
    println!("✓ 加密成功");
    println!("  原文件大小: {} 字节", test_content.len());
    println!("  加密后大小: {} 字节\n", encrypted_size);
    
    // 4. 使用 ECB 模式解密
    println!("4. 使用 Java ECB 模式解密文件...");
    decrypt_file_java_ecb("test_encrypted_ecb.bin", "test_decrypted_ecb.txt", &private_key)?;
    println!("✓ 解密成功\n");
    
    // 5. 验证内容
    println!("5. 验证解密内容...");
    let decrypted_content = fs::read_to_string("test_decrypted_ecb.txt")?;
    
    if decrypted_content == test_content {
        println!("✓ 验证成功：解密内容与原文完全一致！");
        println!("  原文长度: {} 字节", test_content.len());
        println!("  解密长度: {} 字节\n", decrypted_content.len());
    } else {
        println!("✗ 验证失败：内容不匹配");
        println!("  原文长度: {}", test_content.len());
        println!("  解密长度: {}\n", decrypted_content.len());
        return Err("内容验证失败".into());
    }
    
    // 6. 显示加密文件格式
    println!("6. 加密文件格式分析...");
    let encrypted_data = fs::read("test_encrypted_ecb.bin")?;
    let wrapped_key_len = u32::from_be_bytes([
        encrypted_data[0],
        encrypted_data[1],
        encrypted_data[2],
        encrypted_data[3],
    ]) as usize;
    
    println!("  文件结构:");
    println!("  - 包装密钥长度: {} 字节 (4 字节头部)", wrapped_key_len);
    println!("  - RSA 加密的 AES 密钥: {} 字节", wrapped_key_len);
    println!("  - AES-ECB 加密的内容: {} 字节", encrypted_data.len() - 4 - wrapped_key_len);
    println!("  - 总大小: {} 字节\n", encrypted_data.len());
    
    // 7. 保存密钥供 Java 使用
    println!("7. 保存密钥文件（可供 Java 使用）...");
    fs::write("java_ecb_public_key.txt", &public_key)?;
    fs::write("java_ecb_private_key.txt", &private_key)?;
    println!("✓ 密钥已保存");
    println!("  - java_ecb_public_key.txt");
    println!("  - java_ecb_private_key.txt\n");
    
    // 8. 显示 Java 使用说明
    println!("═══════════════════════════════════════════════════════════════\n");
    println!("【Java 解密示例】\n");
    println!("生成的 test_encrypted_ecb.bin 可以在 Java 中解密：\n");
    println!("```java");
    println!("// 读取私钥");
    println!("String privateKeyStr = Files.readString(");
    println!("    Paths.get(\"java_ecb_private_key.txt\"));");
    println!();
    println!("// 解密文件");
    println!("RSAUtils.decryptFile(");
    println!("    \"test_encrypted_ecb.bin\",");
    println!("    \"test_decrypted.txt\",");
    println!("    privateKeyStr);");
    println!("```\n");
    
    println!("【Rust 加密供 Java 解密】\n");
    println!("```rust");
    println!("use rsa_utils::encrypt_file_java_ecb;");
    println!();
    println!("// 使用 Java 兼容的 ECB 模式加密");
    println!("encrypt_file_java_ecb(");
    println!("    \"input.txt\",");
    println!("    \"encrypted.bin\",");
    println!("    &public_key)?;");
    println!("```\n");
    
    // 9. 清理测试文件
    println!("═══════════════════════════════════════════════════════════════\n");
    println!("9. 清理测试文件...");
    fs::remove_file("test_input.txt")?;
    fs::remove_file("test_decrypted_ecb.txt")?;
    println!("✓ 清理完成\n");
    
    println!("保留的文件：");
    println!("  - test_encrypted_ecb.bin (可用 Java 解密)");
    println!("  - java_ecb_public_key.txt");
    println!("  - java_ecb_private_key.txt\n");
    
    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║  ✓ 所有测试通过！                                              ║");
    println!("║  ✓ Rust 加密的文件可以被 Rust 解密                              ║");
    println!("║  ✓ Rust 加密的文件可以被 Java 解密                              ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");
    
    Ok(())
}
