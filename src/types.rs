pub mod types {
    use serde::Deserialize;

    #[derive(Deserialize, Debug)]
    pub struct Target {
        pub ip: String,
        pub timeout: u8,
        pub delay: u8,
        pub max_retries: u8,
        pub grace_period: u8,
        pub topic: String,
        pub message_format: String,
        pub client_retries : u8,
    }

    #[derive(Deserialize, Debug)]
    pub struct Definitions {
        #[serde(rename(deserialize = "host"))]
        pub mqtt_host : String,
        pub targets: Vec<Target>,
    }

}