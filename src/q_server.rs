use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;
use moka::sync::Cache;

const CMD_SEND: u8 = 0x01;
const CMD_RECV: u8 = 0x02;

/// 启动服务端，监听指定端口，等待客户端连接
pub async fn run_server(socket_cache: Arc<Cache<String, Arc<Mutex<TcpStream>>>>) -> Result<(), Box<dyn Error>> {
    // 缓存的值类型改为 Arc<Mutex<TcpStream>>

    // 监听 0.0.0.0:8080 端口
    let listener = TcpListener::bind("0.0.0.0:8080").await?;
    println!("Server listening on 0.0.0.0:8080");

    loop {
        let (socket, addr) = listener.accept().await?;
        println!("Accepted connection from {}", addr);

        let cache = socket_cache.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, cache).await {
                eprintln!("Error handling connection from {}: {}", addr, e);
            }
        });
    }
}

/// 修改 handle_connection，接受 TcpStream 而不是 &mut TcpStream，并包装为 Arc<Mutex<TcpStream>>
async fn handle_connection(socket: TcpStream, socket_cache: Arc<Cache<String, Arc<Mutex<TcpStream>>>>) -> Result<(), Box<dyn Error>> {
    // 将 TcpStream 包装到 Arc<Mutex<_>> 中
    let socket = Arc::new(Mutex::new(socket));

    // 先从 socket 中读取 client_hash
    // 注意：这里必须锁住 socket 才能操作
    let mut client_hash_buf = [0u8; 32];
    {
        let mut locked_socket = socket.lock().await;
        locked_socket.read_exact(&mut client_hash_buf).await?;
    }
    let client_hash = String::from_utf8_lossy(&client_hash_buf).to_string();
    println!("Received client hash: {}", client_hash);

    // 将包装后的 socket 插入到缓存中
    socket_cache.insert(client_hash, socket.clone());

    Ok(())
}
