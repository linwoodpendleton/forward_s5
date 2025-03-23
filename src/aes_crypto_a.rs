//aes_crypto.rs
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::io::Result as IoResult;
use tokio::net::TcpStream;

static ENC_TABLE: [u8; 256] = [34, 44, 94, 250, 111, 130, 151, 79, 193, 16, 210, 229, 133, 182, 78, 184, 103, 135, 32, 218, 93, 232, 126, 110, 113, 40, 185, 89, 14, 163, 132, 70, 197, 209, 245, 13, 224, 8, 69, 159, 12, 29, 53, 240, 173, 196, 39, 177, 35, 66, 72, 10, 15, 160, 169, 176, 236, 6, 200, 49, 99, 107, 48, 140, 125, 22, 36, 253, 80, 54, 31, 143, 115, 112, 187, 165, 226, 144, 45, 222, 51, 65, 74, 199, 24, 248, 228, 118, 181, 231, 131, 5, 2, 179, 213, 191, 114, 202, 47, 20, 243, 63, 25, 147, 223, 198, 17, 146, 84, 62, 71, 58, 238, 174, 241, 207, 145, 128, 67, 215, 109, 234, 129, 101, 212, 77, 239, 203, 95, 21, 59, 76, 136, 208, 178, 246, 189, 247, 26, 97, 88, 221, 38, 188, 230, 28, 167, 46, 86, 139, 108, 166, 251, 190, 104, 56, 211, 220, 123, 155, 81, 168, 148, 175, 117, 30, 124, 183, 201, 242, 192, 138, 11, 233, 235, 33, 162, 57, 161, 82, 142, 60, 37, 249, 255, 7, 73, 180, 83, 91, 90, 18, 106, 120, 171, 237, 96, 41, 252, 195, 64, 141, 244, 172, 186, 194, 23, 61, 52, 152, 55, 154, 27, 156, 134, 92, 219, 216, 204, 105, 102, 4, 9, 68, 119, 164, 217, 137, 158, 227, 254, 87, 100, 122, 205, 127, 121, 157, 42, 170, 214, 3, 206, 225, 149, 85, 0, 43, 1, 153, 116, 75, 50, 150, 98, 19];





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
    first:bool,
}

impl<T> AesCryptoStream<T> {
    pub async fn new_async(inner: T, s: TcpStream) -> IoResult<Self> {
        // 在同一个 Runtime 里异步地去连接 8080



        Ok(Self {
            inner,
            read_buf: Vec::new(),
            read_pos: 0,

            socket_b:s,
            first:true,
        })
    }

}

impl<T: AsyncRead + Unpin> AsyncRead for AesCryptoStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out_buf: &mut ReadBuf<'_>
    ) -> Poll<IoResult<()>> {
        println!("poll_read");
        // 如果有已解密数据，则先返回缓冲区中的数据
        if self.read_pos < self.read_buf.len() {
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
        // 否则，从底层流中读取原始（加密）数据
        let mut tmp = [0u8; 4096];
        let mut tmp_buf = ReadBuf::new(&mut tmp);
        match Pin::new(&mut self.inner).poll_read(cx, &mut tmp_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {

                // 解密获得明文数据


                let mut pinned_socket = Pin::new(&mut self.socket_b);
                let mut temp = [0u8; 4096];
                let mut temp_read_buf = ReadBuf::new(&mut temp);
                // 调用 poll_write 写入解密数据
                let _ = match pinned_socket.as_mut().poll_read(cx, &mut temp_read_buf) {
                    Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                };
                let n = temp_read_buf.filled().len();
                if n == 0 {
                    return Poll::Ready(Ok(()));
                }
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
                Poll::Ready(Ok(()))
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
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        }

        let mut tmp_buf = vec![1u8];
        if self.first {
            self.first = false;
            tmp_buf = encrypted;
        }
        match Pin::new(&mut self.inner).poll_write(cx, &tmp_buf) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(buf.len())), // 这里假设写入成功后返回原始数据长度
            other => other,
        }
        
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>
    ) -> Poll<IoResult<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>
    ) -> Poll<IoResult<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
