use tokio::net::{TcpListener, TcpStream};
use tokio::io;
use tokio::time::{timeout, Duration};
use std::error::Error;
use tokio::io::AsyncWriteExt;
use crate::aes_crypto_a::AesCryptoStream;

pub async fn run() -> Result<(), Box<dyn Error>> {
    // 监听本地 5050 端口（192.168.0.2 应配置为绑定该地址，此处示例使用 0.0.0.0 方便测试）
    let listener = TcpListener::bind("0.0.0.0:5050").await?;
    println!("Server A (SOCKS5) listening on 0.0.0.0:5050");

    loop {
        let (mut client, addr) = listener.accept().await?;
        println!("Accepted client connection from {}", addr);

        tokio::spawn(async move {
            // 此处应实现完整的 SOCKS5 握手（省略细节），
            // 假设握手完成后 client 已获得目标请求数据。
            // 为简化示例，直接开始转发
            let client_ip = addr.ip().to_string();
            let client_port = addr.port().to_string();
            //计算client_ip+client_port的hash值
            let client_hash = format!("{:x}", md5::compute(client_ip+&client_port));
            let mut socket_b = match TcpStream::connect("127.0.0.1:58080").await {
                Ok(stream) => stream,
                Err(e) => {
                    eprintln!("Failed to connect to 127.0.0.1:58080: {}", e);
                    return;
                }
            };

            if let Err(e) = socket_b.write_all(client_hash.as_bytes()).await {
                eprintln!("Failed to send hash: {}", e);
                return;
            }
            println!("Connected to server and sent hash");
            // 连接到服务器 B（假设其地址为 127.10.0.200:6060）
            match TcpStream::connect("127.0.0.1:6060").await {
                Ok(remote) => {
                    // 将 remote 包装成 AES 加密的通道

                    let mut crypto_remote_result = AesCryptoStream::new_async(remote,socket_b).await;
                    let mut crypto_remote = match crypto_remote_result {
                        Ok(crypto_remote) => crypto_remote,
                        Err(e) => {
                            eprintln!("Failed to create AES crypto stream: {}", e);
                            return;
                        },
                    };
                    let timeout_duration = Duration::from_secs(60);
                    println!("Forwarding data between client and Server B...");
                    match crypto_remote.write_all(client_hash.as_bytes()).await{
                        Ok(_) => {},
                        Err(e) => eprintln!("Failed to send hash to Server B: {}", e),
                    };
                    // 双向转发：写入 client 的数据经过加密后发送到 Server B，
                    // Server B 返回的数据经过解密后发回 client
                    match timeout(timeout_duration, io::copy_bidirectional(&mut client, &mut crypto_remote)).await {
                        Ok(Ok((from_client, from_remote))) => {
                            println!("Forwarded {} bytes from client and {} bytes from Server B", from_client, from_remote);
                        },
                        Ok(Err(e)) => eprintln!("Error during forwarding: {}", e),
                        Err(e) => eprintln!("Timeout during forwarding: {}", e),
                    }
                },
                Err(e) => eprintln!("Failed to connect to Server B: {}", e),
            }
        });
    }
}
