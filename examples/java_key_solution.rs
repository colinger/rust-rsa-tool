/// Complete solution for decrypting Java-encrypted files in Rust
/// 
/// This example demonstrates:
/// 1. The problem: Java uses AES/ECB by default, Rust code was using AES/CBC
/// 2. The solution: Use decrypt_file_java_ecb() for Java-encrypted files
/// 3. How to decrypt the actual file

use rsa_utils::decrypt_file_java_ecb;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║  Java-Rust RSA 文件解密解决方案                                ║");
    println!("╚═══════════════════════════════════════════════════════════════╝\n");
    
    // 问题说明
    println!("【问题】");
    println!("Java 代码生成的私钥可以解析，但无法解密 Java 加密的文件\n");
    
    println!("【原因】");
    println!("Java 的 Cipher.getInstance(\"AES\") 默认使用 AES/ECB/PKCS5Padding");
    println!("Rust 代码原本使用的是 AES/CBC 模式（需要 IV）");
    println!("两者不兼容！\n");
    
    println!("【解决方案】");
    println!("使用 decrypt_file_java_ecb() 函数来解密 Java 加密的文件\n");
    
    println!("═══════════════════════════════════════════════════════════════\n");
    
    // Java 生成的私钥（1024-bit PKCS#8 格式）
    let java_private_key = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJlmwGz/dBqScOECMbMKG7a4LxLKSftSLmRxknYv54+Bf1vBvH00+XwwQOz9cQilqp2bPAzL1dN8R8nchwvXk4qP34PLjrEKZZIMqHM9znCoa0d1UhbbAm1Nrmmm+EjUrAffdmXDZhFnh28CvATsIOcFVNqgG/R0nwE7GnPvQZsJAgMBAAECgYBGcywYYtFdireQfsN4aEIGDlyAEqsbYsivlIEhCisceuqUp0r7baLOaBLJRDPvNrY+n5Zaghp3f/IwQLk8tQqqtTGS+xH/HNS5ga1tffnA85Qle9qD2caYDJud69186tEkftWzgz44DcsLTzGHztjF1ImUftuItxTKgkNNsNbQAQJBAOzQYZzN5ZPH3mORJUtHW1mek07hItP3OGd5YB6a8beqJ0/4kGkYi52SL5ou34/cPBb/ZePqhwDr6FNda63UVQECQQCl1FvT59ER6WX3qEe1ma98LQdM50A8GPyzjQxTr68xtZaYsV/DljeOBMCfZ63R+ubd8KxoomKGjVYNGKviVJ4JAkEAn//eo6n9Pc6hc9YiQ21PzAo27ulvtZTn2AmKpsL7I6Nj8kU3lLpPwkN9xAd9Zt5e/w7J0aaoVjgNfR22XfkDAQJAdqtgR2WmPM4slS0MnA1uAkvq5IK8egVbmVX/k0eu9MDBE2YjZMDz4qLOAYTdY93MJtkbWAmUvjsYcGjOYDozmQJBAKIaYy/PyeIgEvm4U4b6xyP/3XtBdeaTj65sklq7Roay+OOMbOQasDBHwVewM77Nvo06bV1leYqc5CHt1XTmBAw=";
    
    let encrypted_file = "/Users/xinying/workspace/workspace-java/aispeech/binencrypt/target/resource_en.bin";
    let decrypted_file = "/Users/xinying/workspace/workspace-java/aispeech/binencrypt/target/resource_dec_rust.bin";
    
    println!("【执行解密】\n");
    println!("加密文件: {}", encrypted_file);
    println!("解密文件: {}", decrypted_file);
    
    // 检查文件是否存在
    if !std::path::Path::new(encrypted_file).exists() {
        eprintln!("\n✗ 错误：加密文件不存在！");
        eprintln!("  请确认文件路径是否正确");
        return Ok(());
    }
    
    let metadata = fs::metadata(encrypted_file)?;
    println!("文件大小: {} bytes ({:.2} MB)", metadata.len(), metadata.len() as f64 / 1024.0 / 1024.0);
    println!();
    
    // 使用正确的函数解密
    println!("正在解密...");
    match decrypt_file_java_ecb(encrypted_file, decrypted_file, java_private_key) {
        Ok(_) => {
            let dec_metadata = fs::metadata(decrypted_file)?;
            println!("✓ 解密成功！");
            println!();
            println!("解密后文件大小: {} bytes ({:.2} MB)", 
                     dec_metadata.len(), 
                     dec_metadata.len() as f64 / 1024.0 / 1024.0);
            println!("解密文件已保存到: {}", decrypted_file);
            println!();
            
            // 显示文件头部信息
            let content = fs::read(decrypted_file)?;
            println!("文件头部 (前 64 字节，十六进制):");
            for (i, byte) in content.iter().take(64).enumerate() {
                if i % 16 == 0 {
                    print!("\n  {:04x}: ", i);
                }
                print!("{:02x} ", byte);
            }
            println!("\n");
            
            println!("═══════════════════════════════════════════════════════════════\n");
            println!("【总结】");
            println!("✓ Java 私钥格式正确 (PKCS#8)");
            println!("✓ 使用 decrypt_file_java_ecb() 成功解密");
            println!("✓ Java 和 Rust 现在可以互操作了！\n");
            
            println!("【使用说明】");
            println!("在 Rust 代码中导入：");
            println!("  use rsa_utils::decrypt_file_java_ecb;\n");
            println!("解密 Java 加密的文件：");
            println!("  decrypt_file_java_ecb(input, output, private_key)?;\n");
            
            println!("【注意事项】");
            println!("• decrypt_file()        - 用于 Rust 加密的文件 (AES/CBC)");
            println!("• decrypt_file_java_ecb() - 用于 Java 加密的文件 (AES/ECB)");
        }
        Err(e) => {
            eprintln!("✗ 解密失败！");
            eprintln!("  错误: {}", e);
        }
    }
    
    Ok(())
}
