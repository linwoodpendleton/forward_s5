//server_b.rs
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};
use std::error::Error;
use std::net::SocketAddr;
use std::io;
use std::sync::Arc;
use moka::sync::Cache;
use crate::aes_crypto_b::AesCryptoStream;
use crate::q_server::run_server;
use flume::{unbounded, Receiver, Sender};
const SOCKS_VERSION: u8 = 0x05;
const RESERVED: u8 = 0x00;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USERNAME_PASSWORD: u8 = 0x02;
const AUTH_VERSION: u8 = 0x01;
const AUTH_SUCCESS: u8 = 0x00;
const AUTH_FAILURE: u8 = 0x01;
const COMMAND_CONNECT: u8 = 0x01;
const COMMAND_UDP_ASSOCIATE: u8 = 0x03;

pub async fn run() -> Result<(), Box<dyn Error>> {
    let read_que = Arc::new(Cache::builder()
        .time_to_live(Duration::from_secs(60))
        .time_to_idle(Duration::from_secs(30))
        .build());
    let write_que = Arc::new(Cache::builder()
        .time_to_live(Duration::from_secs(60))
        .time_to_idle(Duration::from_secs(30))
        .build());

    // 克隆一份供 run_server 使用
    let run_server_read_que = read_que.clone();
    let run_server_write_que = write_que.clone();

    tokio::spawn(async move {
        if let Err(e) = run_server(run_server_read_que, run_server_write_que).await {
            eprintln!("Error while running run_server: {}", e);
        }
    });

    let listener = TcpListener::bind("0.0.0.0:6060").await?;
    println!("Server B (SOCKS5) listening on 0.0.0.0:6060");

    loop {
        let (socket, addr) = listener.accept().await?;
        println!("Server B accepted connection from {}", addr);
        let client_ip = addr.ip().to_string();
        let client_port = addr.port().to_string();
        // 这里再次克隆，使用原始的 read_que 和 write_que
        let read_que = read_que.clone();
        let write_que = write_que.clone();
        // 计算 client_ip + client_port 的 hash 值
        let hash = format!("{:x}", md5::compute(client_ip + &client_port));
        let mut crypto_stream = AesCryptoStream::new(socket, hash, read_que.clone(), write_que.clone());

        tokio::spawn(async move {
            if let Err(e) = handle_socks5_connection(&mut crypto_stream).await {
                eprintln!("Error handling connection from2 {}: {}", addr, e);
            }
        });
    }
}


async fn handle_socks5_connection<T>(stream: &mut T) -> Result<(), Box<dyn Error>>
where
    T: AsyncReadExt + AsyncWriteExt + Unpin,
{


    // 1. 读取 SOCKS5 握手：版本号和支持的认证方法数量
    let mut testbuf = [0u8; 32];
    stream.read_exact(&mut testbuf).await?;
    let mut buf = [0u8; 2];
    println!("start read 1");
    stream.read_exact(&mut buf).await?;
    if buf[0] != SOCKS_VERSION {

        return Err("Unsupported SOCKS version".into());
    }
    let nmethods = buf[1] as usize;
    let mut methods = vec![0u8; nmethods];
    println!("start read 2");
    stream.read_exact(&mut methods).await?;

    // 2. 选择认证方式（支持无认证方式）
    let selected_method = if methods.contains(&METHOD_NO_AUTH) {
        METHOD_NO_AUTH
    } else {
        0xFF
    };
    println!("start read 3");
    stream.write_all(&[SOCKS_VERSION, selected_method]).await?;
    if selected_method == 0xFF {
        return Err("No acceptable authentication method".into());
    }
    println!("start read 5");
    // 3. 读取 SOCKS5 请求头（版本、命令、保留字段、地址类型）
    let mut req_header = [0u8; 4];
    stream.read_exact(&mut req_header).await?;
    if req_header[0] != SOCKS_VERSION {
        return Err("Invalid SOCKS version in request".into());
    }
    let command = req_header[1];
    let addr_type = req_header[3];

    if command == COMMAND_CONNECT {
        handle_connect_command(stream, addr_type).await?;
    } else if command == COMMAND_UDP_ASSOCIATE {
        handle_udp_associate(stream, addr_type).await?;
    } else {
        return Err("Unsupported command".into());
    }

    Ok(())
}

async fn handle_connect_command<T>(stream: &mut T, addr_type: u8) -> Result<(), Box<dyn Error>>
where
    T: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let target_addr = match addr_type {
        0x01 => { // IPv4
            let mut ipv4 = [0u8; 4];
            stream.read_exact(&mut ipv4).await?;
            let port = read_port(stream).await?;
            SocketAddr::new(ipv4.into(), port)
        },
        0x03 => { // Domain name
            let mut domain_len = [0u8; 1];
            stream.read_exact(&mut domain_len).await?;
            let mut domain = vec![0u8; domain_len[0] as usize];
            stream.read_exact(&mut domain).await?;
            let port = read_port(stream).await?;
            let domain = String::from_utf8(domain)?;
            let addr_str = format!("{}:{}", domain, port);
            tokio::net::lookup_host(addr_str).await?
                .next().ok_or("Domain resolution failed")?
        },
        0x04 => { // IPv6
            let mut ipv6 = [0u8; 16];
            stream.read_exact(&mut ipv6).await?;
            let port = read_port(stream).await?;
            SocketAddr::new(ipv6.into(), port)
        },
        _ => return Err("Unsupported address type".into()),
    };

    println!("Server B: Connecting to target {}", target_addr);
    let mut target = TcpStream::connect(target_addr).await?;
    println!("Server B: Connected to target");

    // 5. Construct and send SOCKS5 response (success)
    let reply = SocksReply::new(ResponseCode::Success);
    reply.send(stream).await?;

    // 6. Begin bidirectional data forwarding
    let timeout_duration = Duration::from_secs(60);
    timeout(timeout_duration, tokio::io::copy_bidirectional(stream, &mut target)).await??;
    Ok(())
}

async fn handle_udp_associate<T>(stream: &mut T, addr_type: u8) -> Result<(), Box<dyn Error>>
where
    T: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let local_addr = match addr_type {
        0x01 => { // IPv4
            let ipv4 = [0u8; 4];
            let port = 0u16; // Use a placeholder port for now
            SocketAddr::new(ipv4.into(), port)
        },
        _ => return Err("Unsupported address type for UDP".into()),
    };

    // Open a UDP socket to listen for incoming UDP packets
    let udp_socket = UdpSocket::bind(local_addr).await?;
    let reply = SocksReply::new_udp(ResponseCode::Success, local_addr);
    reply.send(stream).await?;

    // Handle incoming UDP datagrams
    let mut buf = [0u8; 65535];
    loop {
        let (len, src_addr) = udp_socket.recv_from(&mut buf).await?;
        println!("Received UDP packet from: {}", src_addr);

        // Forward the UDP packet as needed
        udp_socket.send_to(&buf[..len], src_addr).await?;
    }
}

async fn read_port<T>(stream: &mut T) -> Result<u16, Box<dyn Error>>
where
    T: AsyncReadExt + Unpin,
{
    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).await?;
    Ok(u16::from_be_bytes(port_buf))
}

struct SocksReply {
    buf: [u8; 10],
}

impl SocksReply {
    pub fn new(status: ResponseCode) -> Self {
        let buf = [
            SOCKS_VERSION,
            status as u8,
            RESERVED,
            0x01, // IPv4 response (placeholder)
            0, 0, 0, 0, // Placeholder for BIND address
            0, 0, // Placeholder for port
        ];
        SocksReply { buf }
    }

    pub fn new_udp(status: ResponseCode, addr: SocketAddr) -> Self {
        let buf = match addr.ip() {
            std::net::IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                [
                    SOCKS_VERSION,
                    status as u8,
                    RESERVED,
                    0x01, // IPv4 response
                    octets[0], octets[1], octets[2], octets[3],
                    (addr.port() >> 8) as u8, (addr.port() & 0xFF) as u8,
                ]
            },
            _ => {
                return SocksReply {
                    buf: [0; 10], // Default empty response for unsupported address types
                }
            }
        };

        SocksReply { buf }
    }

    pub async fn send<T>(&self, stream: &mut T) -> io::Result<()>
    where
        T: AsyncWriteExt + Unpin,
    {
        stream.write_all(&self.buf).await
    }
}

#[derive(Debug)]
enum ResponseCode {
    Success = 0x00,
}
