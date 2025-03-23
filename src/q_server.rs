//q_server.rs
use std::collections::VecDeque;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use futures::lock::Mutex;
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;
use moka::sync::Cache;
use crossbeam_queue::SegQueue;

const CMD_SEND: u8 = 0x01;
const CMD_RECV: u8 = 0x02;

/// 启动服务端，监听指定端口，等待客户端连接
pub async fn run_server(read_que: Arc<Cache<String, Arc<SegQueue<Vec<u8>>>>>,write_que:Arc<Cache<String, Arc<SegQueue<Vec<u8>>>>>) -> Result<(), Box<dyn Error>> {
    // 缓存的值类型改为 Arc<Mutex<TcpStream>>

    // 监听 0.0.0.0:8080 端口
    let listener = TcpListener::bind("0.0.0.0:58080").await?;
    println!("Server listening on 0.0.0.0:8080");

    loop {
        let (socket, addr) = listener.accept().await?;
        println!("Accepted connection from {}", addr);

        let read_cache = read_que.clone();
        let write_cache = write_que.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, read_cache,write_cache).await {
                eprintln!("Error handling connection from {}: {}", addr, e);
            }
        });
    }
}

/// 修改 handle_connection，接受 TcpStream 而不是 &mut TcpStream，并包装为 Arc<Mutex<TcpStream>>
async fn handle_connection(socket: TcpStream, read_que: Arc<Cache<String, Arc<SegQueue<Vec<u8>>>>>,write_que:Arc<Cache<String, Arc<SegQueue<Vec<u8>>>>>) -> Result<(), Box<dyn Error>> {
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

    let r_queue: Arc<SegQueue<Vec<u8>>> = Arc::new(SegQueue::new());
    let w_queue: Arc<SegQueue<Vec<u8>>> = Arc::new(SegQueue::new());

    // 将包装后的 socket 插入到缓存中

    read_que.insert(client_hash.clone(), r_queue.clone());
    write_que.insert(client_hash.clone(),w_queue.clone());
    //循环读取消息
    loop {
        if !w_queue.is_empty() {
            let buf_o = w_queue.pop();
            match buf_o {
                Some(buf) => {
                    println!("Sending data to client len {}", buf.len());
                    let mut locked_socket = socket.lock().await;
                    locked_socket.write_all(&buf).await?;
                },
                None => {}
            }

        }



        let mut buf = [0u8; 4096];
        let mut locked_socket = socket.lock().await;
        let n = locked_socket.read(&mut buf).await?;
            // println!("Received data from client len {}", n);

        if n> 0{

            r_queue.push(buf[..n].to_vec());

        }



        //  暂停一会
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    Ok(())
}
