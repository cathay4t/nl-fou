// SPDX-License-Identifier: MIT

use std::env::args;

use nl_fou::FouConfig;

#[tokio::main]
async fn main() {
    env_logger::init();

    let argv: Vec<String> = args().collect();
    if argv.len() < 2 {
        eprintln!("Usage: add_fou_listener <port>");
        return;
    }
    let port: u16 = argv[1].parse().expect("invalid port");

    let mut config = FouConfig::new(port);
    config.ipproto = Some(17);

    let (connection, mut handle, _) = nl_fou::new_connection().unwrap();
    tokio::spawn(connection);
    handle.add(&config).await.unwrap();

    println!("Added listener {config:?}");
    for listener in handle.get_all().await.unwrap() {
        println!("{listener:?}");
    }
}
