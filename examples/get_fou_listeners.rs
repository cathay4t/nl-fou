// SPDX-License-Identifier: MIT

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("debug"),
    )
    .init();

    let (connection, mut handle, _) = nl_fou::new_connection().unwrap();
    tokio::spawn(connection);

    for listener in handle.get_all().await.unwrap() {
        println!("{listener:?}");
    }
}
