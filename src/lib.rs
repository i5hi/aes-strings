// use std::iter::repeat;
use openssl::symm;
use std::str;
use rand::prelude::*;

use rand_seeder::{Seeder};

/// Create a random 256 bit key to use for aes encryption.
/// This is used if the user wants a strong(ish) key from the application.
pub fn _keygen()->String{
    let key: Vec<u8> =rand::thread_rng().gen::<[u8; 32]>().to_vec();
    base64::encode(key)

}

/// Create a seeded 256 bit key to use for aes encryption.
/// This is used to convert a user provided String key into a compliant aes key.
pub fn seedgen(seed:String)->String{
    let seed: [u8; 32] = Seeder::from(seed.as_str()).make_seed();
    base64::encode(seed)
}

/// String wrapper for AES-256-CBC encrypt w/iv
pub fn encrypt(plaintext:String, key: String)->String{
    let iv = rand::thread_rng().gen::<[u8; 16]>().to_vec();
    let cipher = symm::Cipher::aes_256_cbc();
    let ciphertext = symm::encrypt(
        cipher,
        &base64::decode(key).unwrap(),
        Some(&iv),
        plaintext.as_bytes()
    ).unwrap();
    base64::encode(iv)+ &String::from(":") + &base64::encode(ciphertext).to_string()

}

/// String wrapper for AES-256-CBC decrypt w/iv
pub fn decrypt(iv_ciphertext:String, key: String)->String{
    let cipher = symm::Cipher::aes_256_cbc();
    let iter:Vec<&str> = iv_ciphertext.split(":").collect();
    // println!("{}, {}", iter[0], iter[1]);
    // println!("KEY: {}", key);

    let plaintext = symm::decrypt(
        cipher,
        &base64::decode(key).unwrap(),
        Some(&base64::decode(iter[0]).unwrap()),
        &base64::decode(iter[1]).unwrap()
    ).unwrap();

    str::from_utf8(&plaintext).unwrap().to_string()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen(){
        println!("FRESH RANDOM KEY:  {}  :: length={}",_keygen(), _keygen().len())
    }

    #[test]
    fn test_seedgen(){
        let seed1 = seedgen(String::from("myseed"));
        let seed2 = seedgen(String::from("myseed"));
        assert_eq!(seed1,seed2);
        println!("SEEDED KEY:  {}",seed1);
        println!("SEEDED KEY:  {}",seed2);

    }

    #[test]
    fn test_aes(){
        let secret = String::from("thesecretsauce");
        let key = seedgen(String::from("a79FAWI1IKtuwoSoT3hq0lfkq0oxchoHy1xhOTSpHaU="));
        let iv_ciphertext = encrypt(secret.clone(),key.clone());
        println!("IV ENCRYPTED SECRET:  {}",&iv_ciphertext);
        let plaintext = decrypt(iv_ciphertext.clone(), key.clone());
        println!("IV DECRYPTED SECRET:  {}",&plaintext);
        assert_eq!(secret,plaintext)
    }
}
