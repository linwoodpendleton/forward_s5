mod aes_crypto_b;
mod server_a;
mod server_b;
mod aes_crypto_a;
mod q_server;
mod q_client;

use std::env;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} [server_a|server_b]", args[0]);
        return;
    }

    match args[1].as_str() {
        "server_a" => {
            println!("Starting Server A on 0.0.0.0:5050 ...");
            if let Err(e) = server_a::run().await {
                eprintln!("Server A error: {}", e);
            }
        },
        "server_b" => {
            println!("Starting Server B on 0.0.0.0:6060 ...");
            if let Err(e) = server_b::run().await {
                eprintln!("Server B error: {}", e);
            }
        },
        _ => eprintln!("Unknown option: {}", args[1]),
    }
}
