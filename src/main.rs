extern crate easy_http_request;
extern crate base64;
extern crate openssl;

use easy_http_request::DefaultHttpRequest;
use base64::decode;
use std::fs::{read, File};
use cryptostream::write;
use std::io::{Write};
use openssl::symm::Cipher;
use ping;

use crate::types::types::{Definitions, Target};
use std::net::{IpAddr};
use std::time::Duration;
use std::thread::sleep;
use paho_mqtt as mqtt;
use paho_mqtt::{CreateOptionsBuilder, PersistenceType};
use rayon::prelude::*;
// use rand::prelude::*;
use std::borrow::Borrow;

mod types;

fn main() {
    let definitions_url = "https://raw.githubusercontent.com/ouglaaa/Kickstarter/main/definitions";
    let json = fetch_definitions(definitions_url).unwrap();
    // println!("{:?}", json_string);
    process_to_ping(&json);


    loop {
        println!("alive");
        sleep(Duration::from_secs(10));
    }
}

fn fetch_definitions(definitions_url: &str) -> Option<String> {
    let response = DefaultHttpRequest::get_from_url_str(definitions_url)
        .unwrap()
        .send()
        .unwrap();
    // let path = env::current_dir();
    // println!("The current directory is {}", path.unwrap().display());
    let body_64 = response.body;
    // println!("Body: {:?}", bodyAs64);
    let body = decode(body_64).unwrap();
    let key = read("./aes.key").unwrap();
    // println!("Key : {:?}", key);
    let iv = read("./aes.IV").unwrap();
    // println!("IV : {:?}", iv);
    let mut decrypted = Vec::new();
    {
        let mut decryptor =
            write::Decryptor::new(&mut decrypted, Cipher::aes_256_cbc(), &key, &iv).unwrap();

        let mut bytes_decrypted = 0;

        while bytes_decrypted != body.len() {
            let write_count = decryptor.write(&body[bytes_decrypted..]).unwrap();
            bytes_decrypted += write_count;
            // println!("write_count : {:?}", write_count);
        }
    }
    let decrypted_buffer = decrypted.as_ref();
    let decrypted_json = String::from_utf8_lossy(decrypted_buffer);
    let json_str: String = decrypted_json.to_string();
    //println!("{}", json_str);
    let mut file = File::create("definitions.json").unwrap();
    file.write_all(json_str.as_bytes()).unwrap();

    return Some(json_str);
}

fn process_to_ping(_json: &String) {
    let data = &deserialize_json(_json).unwrap();
    rayon::ThreadPoolBuilder::new().num_threads(data.targets.len()).build_global().unwrap();

    data.targets.par_iter().for_each(move |tgt| {
        let s = rand::random::<u64>()  % 10;
        println!("presleeping {}s", s);
        sleep(Duration::from_secs(s));
        process_target(data.borrow(), tgt.borrow())
    });
}

fn process_target(data: &Definitions, tgt: &Target) {
    let _ip_addr: IpAddr;
    match tgt.ip.parse()
    {
        Ok(addr) => _ip_addr = addr,
        Err(parse_error) => {
            eprintln!("{:?}", parse_error);
            return;
        }
    }
    let mut _max_retries = tgt.max_retries;
    loop
    {
        match ping::ping(_ip_addr, Some(Duration::from_secs(tgt.timeout as u64)),
                         None, None, None, None) {
            Err(err) => {
                eprintln!("ping timeout {} {}", _ip_addr, err);
                _max_retries = _max_retries - 1
            }
            _ => println!("ping {}", _ip_addr),
        }
        if _max_retries <= 0 {
            handle_crash(data, tgt);
            _max_retries = tgt.max_retries;
        }
        sleep(Duration::from_secs(tgt.delay as u64));
    }
}

fn handle_crash(data: &Definitions, tgt: &Target) {
    let topic = &tgt.topic;
    let payload = tgt.message_format.as_bytes();
    let opts = CreateOptionsBuilder::new()
        .persistence(PersistenceType::None)
        .server_uri(&data.mqtt_host)
        .finalize();
    // println!("{}", &data.mqtt_host);
    let mut client = mqtt::client::Client::new(opts).unwrap();
    client.set_timeout(Duration::from_secs(5 as u64));
    let mut retries = tgt.max_retries;
    while retries > 0 {
        if let Err(err) = client.connect(None) {
            eprintln!("error connect: {}", err);
            retries = retries - 1;
            sleep(Duration::from_secs(tgt.delay as u64));
            continue;
        }
        let msg = mqtt::MessageBuilder::new()
            .topic(topic)
            .payload(payload)
            .qos(1)
            .finalize();

        println!("publishing [{}] on [{}]", tgt.message_format, tgt.topic);
        if let Err(err) = client.publish(msg) {
            eprintln!("publish error: {}", err);
            retries = retries - 1;
            continue;
        }
        break;
    }
    if client.is_connected() {
        let _ = client.disconnect(None).unwrap();
    }
    println!("grace period: {}", tgt.grace_period);
    sleep(Duration::from_secs(tgt.grace_period as u64));
}


fn deserialize_json(_json: &String) -> Option<Definitions> {
    let data = serde_json::from_str(_json).unwrap();
    return Some(data);
}
