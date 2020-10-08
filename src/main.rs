extern crate easy_http_request;
extern crate base64;
extern crate openssl;

use easy_http_request::DefaultHttpRequest;
use base64::decode;
use std::fs::{read, File};
use cryptostream::write;
use std::io::{Write, IoSlice, prelude, Read};
use openssl::symm::Cipher;
use std::{env, thread};
use ping;

use crate::types::types::{Definitions, Target};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, AddrParseError};
use std::time::Duration;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::sleep;
use std::borrow::{Borrow, BorrowMut};
use futures::executor::block_on;
use paho_mqtt as mqtt;
use paho_mqtt::PropertyCode::MAXIMUM_QOS;
use futures::StreamExt;
use crossbeam;
use std::cmp::max;
use paho_mqtt::{CreateOptions, CreateOptionsBuilder, PersistenceType};

mod types;

fn main() {
    let definitions_url = "https://raw.githubusercontent.com/ouglaaa/Kickstarter/main/definitions";
    let json_string;
    if let json = fetch_definitions(definitions_url).unwrap() {
        json_string = json.to_string();
        println!("{}", json_string);
        process_to_ping(&json_string)
    } else {
        println!("Error fetching definitions");
    }
    loop {
        println!("ping");
        sleep(Duration::from_secs(1));
    }
}

fn fetch_definitions(definitions_url: &str) -> Option<String> {
    let response = DefaultHttpRequest::get_from_url_str(definitions_url)
        .unwrap()
        .send()
        .unwrap();
    let path = env::current_dir();
    println!("The current directory is {}", path.unwrap().display());

    let body_64 = response.body;
    // println!("Body: {:?}", bodyAs64);
    if let body = decode(body_64).unwrap() {
        if let key = read("./aes.key").unwrap() {
            // println!("Key : {:?}", key);
            if let iv = read("./aes.IV").unwrap() {
                // println!("IV : {:?}", iv);
                let mut decrypted = Vec::new();
                {
                    let mut decryptor =
                        write::Decryptor::new(&mut decrypted, Cipher::aes_256_cbc(), &key, &iv).unwrap();

                    let mut bytes_decrypted = 0;

                    while bytes_decrypted != body.len() {
                        let write_count = decryptor.write(&body[bytes_decrypted..]).unwrap();
                        bytes_decrypted += write_count;
                        println!("write_count : {:?}", write_count);
                    }
                }
                let decrypted_buffer = decrypted.as_ref();
                if let decrypted_json = String::from_utf8_lossy(decrypted_buffer).as_ref() {
                    let mut json_str: String = decrypted_json.to_string();
                    //println!("{}", json_str);
                    if let mut file = File::create("definitions.json").unwrap() {
                        file.write_all(json_str.as_bytes()).unwrap();
                    }
                    return Some(json_str);
                } else {
                    println!("Error decrypting");
                }
            }
        }
    }

    None
}

fn process_to_ping(_json: &String) {
    let data = &deserialize_json(_json).unwrap();
    crossbeam::thread::scope(|scope| {
        data.borrow().targets.iter().clone().for_each(move |tgt| {
            scope.spawn(move |env| {
                process_target(data.borrow(), tgt.borrow())
            }).join().unwrap()
        })
    });
}

fn process_target(data: &Definitions, tgt: &Target) {
    loop {
        // ping
        //      ping result -> max_retries
        //          send_mqtt_message
        let ip_addr: IpAddr;
        match tgt.ip.parse()
        {
            Ok(addr) => ip_addr = addr,
            Err(parse_error) => {
                eprintln!("{:?}", parse_error);
                break;
            }
        }
        let mut max_retries = tgt.max_retries;
        match ping::ping(ip_addr, Some(Duration::from_secs(tgt.timeout as u64)),
                         None, None, None, None) {
            _ => println!("ping {}", ip_addr),
            Err(pp) => {
                eprintln!("ping timeout {}", ip_addr);
                max_retries = max_retries - 1
            }
        }
        if max_retries <= 0 {
            handle_crash(data, tgt);
            max_retries = tgt.max_retries;
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
    if let mut client = mqtt::client::Client::new(opts).unwrap() {
        client.set_timeout(Duration::from_secs(5 as u64));
        let mut retries = 5;
        while retries > 0 {
            if let Err(err) = client.connect(None) {
                eprintln!("{}", err);
                retries = retries - 1;
                continue;
            }
            let msg = mqtt::MessageBuilder::new()
                .topic(topic)
                .payload(payload)
                .qos(1)
                .finalize();

            if let Err(err) = client.publish(msg) {
                eprintln!("{}", err);
                retries = retries - 1;
                continue;
            }
            break;
        }
        client.disconnect(None).unwrap();
    }


    sleep(Duration::from_secs(tgt.grace_period as u64));
}


// fn process_to_ping(_json: &String) {
//     let data = deserialize_json(_json).unwrap();
//     let message_format = data.message_format;
//     data.targets.into_iter().map(|tar| &tar).for_each(move|target|
//         (target.ips.into_iter().for_each(move|ip|
//             thread::spawn(move|| {
//                 let mut ip_address: IpAddr;
//                 match ip.parse()
//                 {
//                     Ok(ip_addr) => ip_address = ip_addr,
//                     Err(parse_error) => {
//                         println!("Error with addr: {}\r\n{}", ip, parse_error);
//                         return ();
//                     }
//                 }
//
//                 let mut max_timeout = target.max_timeout;
//                 loop {
//                     match ping::ping(ip_address, Some(Duration::new(target.timeout as u64, 0)),
//                                      None, None, None, None) {
//                         Err(errors) => max_timeout = max_timeout - 1,
//                         _ => continue
//                     }
//                     if max_timeout <= 0 {
//                         let mut host = ("tcp://arigato:1883".to_string());
//                         let create_opts = mqtt::CreateOptionsBuilder::new()
//                             .server_uri(host)
//                             .persistence(mqtt::PersistenceType::None)
//                             .finalize();
//
//
//                         if let mut cli = mqtt::Client::new(create_opts).unwrap() {
//
// cli.set_timeout(Duration::from_secs(target.timeout));
//
// if let Err(e) = cli.connect(None) {
//     println!("Unable to connect: {:?}", e);
//     return ();
// }
//
// let msg = mqtt::MessageBuilder::new()
//     .topic("test")
//     .payload("Hello synchronous world!")
//     .qos(1)
//     .finalize();
//
//
// if let Err(e) = cli.publish(msg) {
//     println!("Error sending message: {:?}", e);
// }
//
// cli.disconnect(None).unwrap();
// }
// }
// }
// ()
// }).join().unwrap()
// ));
// }

// fn process_to_ping(_json: &String) {
//     let data = deserialize_json(_json).unwrap();
//     data.targets.into_iter().for_each(|target|
//                                       handle_target(Arc::new(Mutex::new(&data)),
//                                                     Arc::new(Mutex::new(&target))));
// }
//
// fn handle_target(data: Arc<Mutex<& 'static Definitions>>, target: Arc<Mutex<&'static Target>>) where
// {
//         if let t = target.lock().unwrap(){
//             t.ips.into_iter().map( |ip|
//                 thread::spawn(move||handle_ping(data.borrow(), target.borrow(), ip.borrow())));
//         }
// }
//
// fn handle_ping(data: &Arc<Mutex<&Definitions>>, target: &Arc<Mutex<&  Target>>, ipAddress: &String) {
//     // ping(addr: IpAddr, timeout: Option<Duration>, ttl: Option<u32>,
//     // ident: Option<u16>, seq_cnt: Option<u16>, payload: Option<&Token>) -> Result<(), Error>
//     let tar = target.lock().unwrap().clone();
//     loop {
//         let ip: IpAddr;
//         let mut max_counter = tar.timeout;
//         // if ipAddr.contains(":") {
//         //     if ip= ipAddr.parse().expect() {
//         //         println!("wrong ipv6 addr : {}", ipAddr);
//         //         break;
//         //     }
//         // } else {
//         match ipAddress.parse() {
//             Ok(val) => ip = val,
//             Err(err) => {
//                 println!("wrong address : {}\n{}\n thread quitting", ipAddress, err);
//                 break;
//             }
//         }
//         // }
//         match ping::ping(ip, Some(Duration::new(tar.timeout as u64, 0)),
//                          None, None, None, None) {
//             Err(errors) => max_counter = max_counter - 1,
//             _ => continue
//         }
//         if max_counter < 0 {
//             handle_crash(data, tar);
//         }
//         sleep(Duration::new(tar.delay as u64, 0));
//     }
// }
//
// fn handle_crash(data: &Arc<Mutex<&Definitions>>, target: &Target) {
//    if let data_acquired = data.lock().unwrap() {
//        let message_format = &(*data_acquired.message_format);
//        let pin = target.digital_pin.or(None);
//    }
// }

fn deserialize_json(_json: &String) -> Option<Definitions> {
    let data = serde_json::from_str(_json).unwrap();
    return Some(data);
}
