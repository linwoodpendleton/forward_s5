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
use flume::{unbounded, Receiver, Sender};

const CMD_SEND: u8 = 0x01;
const CMD_RECV: u8 = 0x02;

/// 启动服务端，监听指定端口，等待客户端连接
pub async fn run_server(read_que: Arc<Cache<String, Arc<Receiver<Vec<u8>>>>>,write_que:Arc<Cache<String, Arc<Receiver<Vec<u8>>>>>) -> Result<(), Box<dyn Error>> {
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
async fn handle_connection(mut socket: TcpStream, read_que: Arc<Cache<String, Arc<Receiver<Vec<u8>>>>>, write_que:Arc<Cache<String, Arc<Receiver<Vec<u8>>>>>) -> Result<(), Box<dyn Error>> {
    // 先从 socket 中读取 client_hash
    let mut client_hash_buf = [0u8; 32];

    socket.read_exact(&mut client_hash_buf).await?;

    let client_hash = String::from_utf8_lossy(&client_hash_buf).to_string();
    println!("Received client hash: {}", client_hash);
    let (tx, rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = unbounded();
    // let r_queue = Arc::new(rx.clone());
    let w_queue= Arc::new(rx.clone());

    // 将包装后的 socket 插入到缓存中
    read_que.insert(client_hash.clone(), w_queue.clone());

    // 设置socket为非阻塞模式
    socket.set_nodelay(true)?;

    //循环读取消息
    loop {
        // println!("loop");
        let rx2_result = write_que.get(&client_hash);
        match rx2_result {
            Some(rx2)=>{
                // println!("rx2.len() {}", rx2.len());
                if rx2.len() > 0 {
                    if let Ok(data) = rx2.try_recv() {
                        // println!("Send data to client len {}", data.len());
                        let send_result = socket.write_all(&data).await;
                        match send_result {
                            Ok(_) => {
                                println!("Send data to client len {}", data.len());
                            },
                            Err(e) => {
                                eprintln!("Failed to send data to client: {}", e);
                                break;
                            }
                        }
                    }
                }
            },
            None=>{
                // println!("rx2 is None hash {}", client_hash);
            }
        }

        let mut buf = [0u8; 4096];
        // 使用超时读取，避免永久阻塞
        match tokio::time::timeout(Duration::from_millis(100), socket.read(&mut buf)).await {
            Ok(read_result) => {
                match read_result {
                    Ok(n) => {
                        if n == 0 {
                            // 连接已关闭
                            println!("Connection closed by client");
                            break;
                        } else if n > 0 {
                            println!("Received data from client len {}", n);
                            tx.send(buf[..n].to_vec()).unwrap();
                        }
                    },
                    Err(e) => {
                        eprintln!("Error reading from socket: {}", e);
                        break;
                    }
                }
            },
            Err(_) => {
                // 读取超时，继续循环
            }
        }

        //  暂停一会
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // 清理资源
    println!("Connection handler for {} terminated", client_hash);
    Ok(())
}
