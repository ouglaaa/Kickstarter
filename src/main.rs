extern crate easy_http_request;
extern crate base64;
extern crate openssl;

use easy_http_request::DefaultHttpRequest;
use base64::decode;
use std::fs::{read, File};
use cryptostream::write;
use std::io::{Write, IoSlice, prelude, Read};
use openssl::symm::Cipher;
use std::env;
use std::borrow::Borrow;
use json::{JsonValue, JsonError};


fn main() {
    let definitionsUrl = "https://raw.githubusercontent.com/ouglaaa/Kickstarter/main/definitions";
    let mut jsonString;
    if let json = FetchDefinitions(definitionsUrl).unwrap() {
        jsonString = json.to_string();
        ProcessToPing(&jsonString)
    } else {
        println!("Error fetching definitions");
    }
}

fn FetchDefinitions(definitionsUrl: &str) -> Option<String> {
    let response = DefaultHttpRequest::get_from_url_str(definitionsUrl)
        .unwrap()
        .send()
        .unwrap();
    let path = env::current_dir();
    println!("The current directory is {}", path.unwrap().display());

    let bodyAs64 = response.body;
    // println!("Body: {:?}", bodyAs64);
    if let body = decode(bodyAs64).unwrap() {
        if let key64 = read("./aes.key").unwrap() {
            // println!("Key : {:?}", key64);
            // if let key = decode(key64).unwrap() {
            //     println!("KEY : {:?}", key);
            if let IV64 = read("./aes.IV").unwrap() {
                // println!("IV : {:?}", IV64);
                //       if let IV = decode(IV64).unwrap() {
                let mut decrypted = Vec::new();

                // When a `cryptostream` is dropped, all buffers are flushed and it is automatically
                // finalized. We can either call `drop()` on the cryptostream or put its usage in a
                // separate scope.
                {
                    let mut decryptor =
                        write::Decryptor::new(&mut decrypted, Cipher::aes_256_cbc(), &key64, &IV64).unwrap();

                    let mut bytes_decrypted = 0;

                    while bytes_decrypted != body.len() {
                        // Just write encrypted ciphertext to the `Decryptor` instance as if it were any
                        // other `Write` impl. Decryption takes place automatically.
                        let write_count = decryptor.write(&body[bytes_decrypted..]).unwrap();
                        bytes_decrypted += write_count;
                    }
                }

                // The underlying `Write` instance is only guaranteed to contain the complete and
                // finalized contents after the cryptostream is either explicitly finalized with a
                // call to `Cryptostream::finish()` or when it's dropped (either at the end of a scope
                // or via an explicit call to `drop()`, whichever you prefer).
                let mut jsonStr: String =  std::str::from_utf8(&decrypted.as_ref()).unwrap().to_string();
                println!("{}", jsonStr);
                if let mut file = File::create("definitions.json").unwrap() {
                    file.write_all(jsonStr.as_bytes());
                }
                return Some(jsonStr);
            }
        }
    }

    None
}

fn ProcessToPing(_json: &String) {
    if let _data = DeserializeJson(_json) {
        println!(">{:?}<", _data);
    } else {
        ()//Err(())
    }
}

fn DeserializeJson(_json: &String) -> Option<JsonValue> {
    if let data = json::parse( _json.as_str()).unwrap() {
        return Some(data);
    }
    return None;

}
