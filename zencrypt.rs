// ********************************************************************************************
// * Title: ZΞNCɌYP₮ CLI              |********************************************************
// * Developed by: imaCŁ◎NΞ.sol³¹³    |********************************************************
// * Date: August 10th 2022           |********************************************************
// * Last Updated: December 20th 2023 |********************************************************
// * Version: 1.0                     |********************************************************
// * ******************************************************************************************
// * Description: ZΞNCɌYP₮ is a CLI tool that allows you to encrypt and decrypt text and files
// * using AES-256-GCM. It also allows you to hash text using SHA-256.
// * ******************************************************************************************
// * Usage: ZΞNCɌYP₮ [OPTIONS] [SUBCOMMAND]
// * ******************************************************************************************
// * Options:
// *   -h, --help       Prints help information
// *   -V, --version    Prints version information
// * ******************************************************************************************
// * Subcommands:
// *   decrypt    Decrypts text or a file
// *   encrypt    Encrypts text or a file
// *   hash       Hashes text
// * ******************************************************************************************
// * Examples:
// *   ZΞNCɌYP₮ encrypt -t "Hello World" -k "mykey" -i "myiv"
// *   ZΞNCɌYP₮ decrypt -t "Hello World" -k "mykey" -i "myiv"
// *   ZΞNCɌYP₮ hash -t "Hello World" -s "mysalt"
// *   ZΞNCɌYP₮ encrypt -f "path/to/input/file" -o "path/to/encrypted/file" -k "mykey" -i "myiv"
// *   ZΞNCɌYP₮ decrypt -f "path/to/encrypted/file" -o "path/to/decrypted/file" -k "mykey" -i "myiv"
// * ******************************************************************************************
// * Notes:
// *   - The key and IV must be 32 bytes and 12 bytes respectively.
// *   - The key and IV must be the same for encryption and decryption.
// *   - The salt must be 32 bytes.
// *   - The salt must be the same for hashing and verifying.
// *   - The input file must exist for encryption.
// *   - The encrypted file must exist for decryption.
// *   - The encrypted file must be a valid encrypted file.
// *   - The decrypted file must exist for decryption.
// * ******************************************************************************************

extern crate crypto;
extern crate sha2;

use crypto::aead::{AeadEncryptor, AeadDecryptor};
use crypto::aes::KeySize::KeySize256;
use crypto::aes_gcm::AesGcm;
use sha2::{Sha256, Digest};
use std::{fs::File, io::{Read, Write, stdin}, path::Path};

fn encrypt_text(plaintext: &str, key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut encryptor = AesGcm::new(KeySize256, key, iv, &[]);
    let mut ciphertext = vec![0; plaintext.len() + encryptor.tag_len()];
    encryptor.encrypt(plaintext.as_bytes(), &mut ciphertext, &[]);
    ciphertext
}

fn decrypt_text(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Option<String> {
    let mut decryptor = AesGcm::new(KeySize256, key, iv, &[]);
    let mut decrypted = vec![0; ciphertext.len() - decryptor.tag_len()];
    if decryptor.decrypt(&ciphertext, &mut decrypted, &[]) {
        Some(String::from_utf8(decrypted).unwrap_or_else(|_| String::new()))
    } else {
        None
    }
}

fn hash_text(text: &str, salt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hasher.update(salt.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)
}

fn encrypt_file(input_path: &Path, output_path: &Path, key: &[u8], iv: &[u8]) -> Result<(), String> {
    let mut file = File::open(input_path).map_err(|e| e.to_string())?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).map_err(|e| e.to_string())?;

    let encrypted_data = encrypt_text(&String::from_utf8(contents).unwrap(), key, iv);

    let mut output_file = File::create(output_path).map_err(|e| e.to_string())?;
    output_file.write_all(&encrypted_data).map_err(|e| e.to_string())?;

    Ok(())
}

fn decrypt_file(input_path: &Path, output_path: &Path, key: &[u8], iv: &[u8]) -> Result<(), String> {
    let mut file = File::open(input_path).map_err(|e| e.to_string())?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).map_err(|e| e.to_string())?;

    if let Some(decrypted_data) = decrypt_text(&contents, key, iv) {
        let mut output_file = File::create(output_path).map_err(|e| e.to_string())?;
        output_file.write_all(decrypted_data.as_bytes()).map_err(|e| e.to_string())?;
        Ok(())
    } else {
        Err("Decryption failed".into())
    }
}

fn main() {
    let key: [u8; 32] = [0; 32]; // Replace with your key
    let iv: [u8; 12] = [0; 12]; // Replace with your IV

    // Encryption/decryption
    println!("Enter key for encryption/decryption:");   // Prompt user to enter key
    let mut key_input = String::new();  
    stdin().read_line(&mut key_input).expect("Failed to read line");
    let key = key_input.trim().as_bytes(); 
    
    println!("Enter text to encrypt:"); // Prompt user to enter text to encrypt
    let mut text = String::new();
    stdin().read_line(&mut text).expect("Failed to read line");

    let encrypted = encrypt_text(&text.trim(), &key, &iv);
    println!("Encrypted text: {:?}", encrypted);    // Print encrypted text

    match decrypt_text(&encrypted, &key, &iv) {
        Some(decrypted) => println!("Decrypted text: {}", decrypted),
        None => println!("Decryption failed"),  // Print decrypted text
    }

    // Hashing 
    println!("Enter text to hash:");
    let mut hash_text_input = String::new();
    stdin().read_line(&mut hash_text_input).expect("Failed to read line");

    println!("Enter salt for hashing:");
    let mut salt = String::new();
    stdin().read_line(&mut salt).expect("Failed to read line");

    let hashed = hash_text(&hash_text_input.trim(), &salt.trim());
    println!("Hashed text: {}", hashed);

    // File encryption/decryption 
    let input_file_path = Path::new("path/to/input/file"); // Replace with your input file path
    let encrypted_file_path = Path::new("path/to/encrypted/file"); // Replace with your encrypted file path
    let decrypted_file_path = Path::new("path/to/decrypted/file"); // Replace with your decrypted file path

    match encrypt_file(&input_file_path, &encrypted_file_path, &key, &iv) {
        Ok(_) => println!("File encrypted successfully."),
        Err(e) => println!("Error during file encryption: {}", e),
    }

    match decrypt_file(&encrypted_file_path, &decrypted_file_path, &key, &iv) {
        Ok(_) => println!("File decrypted successfully."),
        Err(e) => println!("Error during file decryption: {}", e),
    }
}
