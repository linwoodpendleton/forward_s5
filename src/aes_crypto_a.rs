use std::future::Future;
//aes_crypto.rs
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::io::Result as IoResult;
use tokio::net::TcpStream;

static ENC_TABLE: [u8; 256] = [189, 139, 239, 187, 245, 65, 220, 227, 223, 44, 129, 196, 134, 194, 120, 181, 157, 235, 8, 158, 144, 221, 18, 7, 173, 215, 54, 53, 4, 211, 5, 43, 20, 200, 63, 140, 162, 179, 88, 40, 135, 68, 174, 251, 121, 51, 72, 230, 229, 37, 74, 225, 242, 137, 237, 165, 49, 170, 56, 122, 50, 171, 123, 191, 28, 47, 205, 31, 34, 25, 206, 106, 177, 103, 95, 149, 80, 133, 233, 41, 57, 128, 90, 160, 232, 14, 202, 84, 98, 12, 182, 58, 114, 231, 91, 201, 166, 243, 132, 164, 208, 52, 210, 136, 3, 199, 175, 197, 92, 64, 107, 26, 48, 216, 30, 27, 79, 108, 124, 70, 204, 86, 148, 213, 59, 186, 151, 169, 131, 87, 75, 214, 252, 167, 77, 83, 178, 110, 207, 6, 188, 60, 17, 67, 73, 180, 101, 154, 66, 222, 29, 255, 100, 250, 119, 115, 13, 152, 9, 184, 240, 117, 150, 236, 155, 109, 62, 19, 10, 247, 156, 244, 209, 126, 111, 24, 190, 22, 217, 81, 228, 141, 55, 102, 42, 93, 78, 15, 146, 138, 153, 212, 11, 1, 112, 0, 185, 254, 32, 113, 176, 76, 168, 219, 130, 246, 45, 143, 161, 172, 71, 145, 104, 105, 46, 224, 21, 226, 99, 116, 193, 85, 23, 218, 249, 183, 61, 82, 238, 118, 234, 241, 96, 125, 89, 35, 69, 97, 16, 142, 253, 33, 39, 94, 248, 36, 38, 198, 127, 195, 203, 147, 163, 192, 159, 2];
// 生成与 ENC_TABLE 对应的解密表
fn build_dec_table() -> [u8; 256] {
    let mut dec_table = [0u8; 256];
    for (index, &val) in ENC_TABLE.iter().enumerate() {
        // ENC_TABLE[index] = val
        // 那么 val 在解密时应该对应回 index
        dec_table[val as usize] = index as u8;
    }
    dec_table
}

pub fn encrypt(data: &[u8]) -> Vec<u8> {
    let mut encrypted = Vec::with_capacity(data.len());
    for &byte in data {
        encrypted.push(ENC_TABLE[byte as usize]);
    }
    encrypted
}

pub fn decrypt(data: &[u8]) -> Vec<u8> {
    let dec_table = build_dec_table(); // 也可用懒加载方式全局构建
    let mut decrypted = Vec::with_capacity(data.len());
    for &byte in data {
        decrypted.push(dec_table[byte as usize]);
    }
    decrypted
}

/// 包装器，将底层流的数据写入时进行 AES 加密，读取时进行 AES 解密
pub struct AesCryptoStream<T> {
    pub inner: T,
    read_buf: Vec<u8>,
    read_pos: usize,
    socket_b: TcpStream,
    first: bool,
    wait_count: u32,
}

impl<T> AesCryptoStream<T> {
    const MAX_RETRY: u32 = 25;

    pub async fn new_async(inner: T, client_hash: String) -> IoResult<Self> {
        // 在同一个 Runtime 里异步地去连接 8080
        let mut socket_b = match TcpStream::connect("127.0.0.1:58080").await {
            Ok(stream) => stream,
            Err(e) => {
                eprintln!("Failed to connect to 127.0.0.1:58080: {}", e);
                return Err(e);
            }
        };

        if let Err(e) = socket_b.write_all(client_hash.as_bytes()).await {
            eprintln!("Failed to send hash: {}", e);
            return Err(e);
        }
        println!("Connected to server and sent hash");

        Ok(Self {
            inner,
            read_buf: Vec::new(),
            read_pos: 0,
            socket_b: socket_b,
            first: true,
            wait_count: 0,
        })
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for AesCryptoStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out_buf: &mut ReadBuf<'_>
    ) -> Poll<IoResult<()>> {
        // 递增重试计数并检查
        self.wait_count += 1;
        if self.wait_count > Self::MAX_RETRY as u32 {
            println!("Max retries reached ({}/{}), returning empty result",
                     self.wait_count, Self::MAX_RETRY);
            self.wait_count = 0;  // 重置计数
            return Poll::Ready(Ok(()));  // 返回空结果
        }

        // 如果有已解密数据，则先返回缓冲区中的数据
        if self.read_pos < self.read_buf.len() {
            // 有数据时重置计数
            self.wait_count = 0;

            let remaining = &self.read_buf[self.read_pos..];
            let to_copy = std::cmp::min(remaining.len(), out_buf.remaining());
            out_buf.put_slice(&remaining[..to_copy]);
            self.read_pos += to_copy;
            if self.read_pos == self.read_buf.len() {
                self.read_buf.clear();
                self.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        let mut pinned_socket = Pin::new(&mut self.socket_b);
        let mut temp = [0u8; 4096];
        let mut temp_read_buf = ReadBuf::new(&mut temp);

        // 调用 poll_read 读取数据
        match pinned_socket.as_mut().poll_read(cx, &mut temp_read_buf) {
            Poll::Ready(Ok(_)) => {
                let n = temp_read_buf.filled().len();
                if n == 0 {
                    // println!("Empty read ({}), will retry", self.wait_count);

                    // 使用单独的任务来确保唤醒
                    let waker = cx.waker().clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                        waker.wake();
                    });

                    return Poll::Pending;
                }

                // 重置计数
                self.wait_count = 0;
                println!("Received {} bytes", n);

                let encrypted_data = &temp_read_buf.filled()[..n];
                let decrypted = decrypt(encrypted_data);

                self.read_buf = decrypted;
                self.read_pos = 0;
                let to_copy = std::cmp::min(self.read_buf.len(), out_buf.remaining());
                out_buf.put_slice(&self.read_buf[..to_copy]);
                self.read_pos += to_copy;
                if self.read_pos == self.read_buf.len() {
                    self.read_buf.clear();
                    self.read_pos = 0;
                }

                return Poll::Ready(Ok(()));
            },
            Poll::Pending => {
                // println!("Read pending (retry {}/{})", self.wait_count, Self::MAX_RETRY);

                // 使用单独的任务来确保唤醒
                let waker = cx.waker().clone();
                tokio::spawn(async move {
                    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                    waker.wake();
                });

                return Poll::Pending;
            },
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for AesCryptoStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8]
    ) -> Poll<IoResult<usize>> {
        // 对传入数据整体加密后写入底层流
        let encrypted = encrypt(buf);
        let mut pinned_socket = Pin::new(&mut self.socket_b);

        // 调用 poll_write 写入加密数据
        match pinned_socket.as_mut().poll_write(cx, &encrypted) {
            Poll::Ready(Ok(n)) => {
                // 写入成功，返回写入字节数
                println!("Wrote {} bytes to server b", n);
            },
            Poll::Pending => {
                println!("Write pending to server b");

                // 使用单独的任务来确保唤醒
                let waker = cx.waker().clone();
                tokio::spawn(async move {
                    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                    waker.wake();
                });

                return Poll::Pending;
            },
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        }

        let mut tmp_buf = vec![1u8];
        if self.first {
            self.first = false;
            tmp_buf = encrypted;
        }

        // 写入内部流
        match Pin::new(&mut self.inner).poll_write(cx, &tmp_buf) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(buf.len())), // 返回写入原始数据的长度
            Poll::Pending => {
                println!("Write pending to inner stream");

                // 使用单独的任务来确保唤醒
                let waker = cx.waker().clone();
                tokio::spawn(async move {
                    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                    waker.wake();
                });

                return Poll::Pending;
            },
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>
    ) -> Poll<IoResult<()>> {
        // 先尝试刷新socket_b
        match Pin::new(&mut self.socket_b).poll_flush(cx) {
            Poll::Ready(Ok(())) => {},
            Poll::Pending => {
                // 使用单独的任务来确保唤醒
                let waker = cx.waker().clone();
                tokio::spawn(async move {
                    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                    waker.wake();
                });

                return Poll::Pending;
            },
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        }

        // 然后刷新内部流
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Pending => {
                // 使用单独的任务来确保唤醒
                let waker = cx.waker().clone();
                tokio::spawn(async move {
                    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                    waker.wake();
                });

                return Poll::Pending;
            },
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>
    ) -> Poll<IoResult<()>> {
        // 先尝试关闭socket_b
        match Pin::new(&mut self.socket_b).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => {},
            Poll::Pending => {
                // 使用单独的任务来确保唤醒
                let waker = cx.waker().clone();
                tokio::spawn(async move {
                    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                    waker.wake();
                });

                return Poll::Pending;
            },
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        }

        // 然后关闭内部流
        match Pin::new(&mut self.inner).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Pending => {
                // 使用单独的任务来确保唤醒
                let waker = cx.waker().clone();
                tokio::spawn(async move {
                    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                    waker.wake();
                });

                return Poll::Pending;
            },
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }
}