use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::error::Error;

const CMD_SEND: u8 = 0x01;
const CMD_RECV: u8 = 0x02;

/// 客户端使用 CMD_SEND 命令，将数据发送到服务端并等待 ACK 回复
pub async fn run_client_send(data:Vec<u8>) -> Result<(), Box<dyn Error>> {
    // 连接到服务端
    let mut socket = TcpStream::connect("127.0.0.1:8080").await?;
    println!("Connected to server");

    // 发送命令
    socket.write_all(&[CMD_SEND]).await?;
    let data_len = data.len() as u32;
    // 先发送数据长度（大端格式）
    socket.write_all(&data_len.to_be_bytes()).await?;
    // 再发送实际数据
    socket.write_all(&*data).await?;
    // 等待接收服务器回复 ACK
    let mut ack_buf = [0u8; 3];
    socket.read_exact(&mut ack_buf).await?;
    println!("Received ACK: {}", String::from_utf8_lossy(&ack_buf));
    Ok(())
}

/// 客户端使用 CMD_RECV 命令，请求服务端发送数据
pub async fn run_client_recv() -> Result<(), Box<dyn Error>> {
    // 连接到服务端
    let mut socket = TcpStream::connect("127.0.0.1:8080").await?;
    println!("Connected to server");

    // 发送命令
    socket.write_all(&[CMD_RECV]).await?;
    // 先读取4字节数据长度
    let mut len_buf = [0u8; 4];
    socket.read_exact(&mut len_buf).await?;
    let response_len = u32::from_be_bytes(len_buf) as usize;
    // 根据长度读取数据内容
    let mut response = vec![0u8; response_len];
    socket.read_exact(&mut response).await?;
    println!("Received response: {}", String::from_utf8_lossy(&response));
    Ok(())
}
