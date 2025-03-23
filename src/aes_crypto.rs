//aes_crypto.rs
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::io::Result as IoResult;

static ENC_TABLE: [u8; 256] = [188, 26, 95, 221, 64, 63, 69, 238, 152, 159, 114, 187, 33, 156, 144, 236, 168, 239, 71, 55, 119, 4, 87, 189, 180, 181, 117, 70, 27, 80, 222, 34, 198, 216, 23, 18, 8, 190, 234, 108, 230, 211, 103, 205, 252, 220, 25, 67, 13, 232, 93, 219, 137, 208, 229, 35, 241, 171, 225, 178, 202, 160, 83, 175, 36, 31, 115, 149, 42, 66, 157, 128, 151, 163, 161, 226, 45, 125, 123, 61, 84, 99, 206, 169, 139, 242, 231, 223, 253, 147, 146, 135, 15, 37, 53, 88, 38, 116, 109, 43, 248, 44, 217, 218, 22, 154, 51, 196, 183, 14, 249, 166, 158, 179, 250, 29, 177, 118, 184, 59, 136, 11, 46, 130, 40, 165, 3, 254, 155, 140, 113, 30, 112, 94, 193, 192, 172, 199, 124, 167, 96, 2, 246, 73, 5, 233, 76, 107, 251, 200, 0, 86, 81, 191, 79, 173, 127, 121, 24, 85, 228, 65, 237, 49, 9, 255, 122, 17, 102, 209, 16, 89, 210, 207, 68, 98, 244, 90, 227, 134, 50, 164, 132, 62, 6, 58, 82, 214, 240, 224, 133, 141, 56, 126, 39, 143, 245, 150, 243, 54, 60, 142, 247, 41, 153, 162, 72, 77, 12, 1, 111, 215, 203, 235, 176, 197, 213, 97, 74, 106, 194, 201, 52, 91, 7, 131, 92, 28, 120, 174, 195, 75, 185, 148, 57, 47, 100, 20, 138, 78, 105, 204, 182, 32, 145, 101, 10, 19, 129, 21, 48, 104, 212, 186, 110, 170];




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
}

impl<T> AesCryptoStream<T> {
    pub fn new(inner: T) -> Self {
        Self { inner, read_buf: Vec::new(), read_pos: 0 }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for AesCryptoStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out_buf: &mut ReadBuf<'_>
    ) -> Poll<IoResult<()>> {
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
                let n = tmp_buf.filled().len();
                if n == 0 {
                    return Poll::Ready(Ok(()));
                }
                let encrypted_data = &tmp_buf.filled()[..n];
                // 解密获得明文数据
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
        // println!("encrypted len: {}", encrypted.len());
        //获取前100个字节
        let len_size = 1;
        if encrypted.len() < len_size {
            match Pin::new(&mut self.inner).poll_write(cx, &encrypted) {
                Poll::Ready(Ok(_)) => { return Poll::Ready(Ok(buf.len())) }, // 这里假设写入成功后返回原始数据长度
                other => return other,
            }
        };
        let  byte = &encrypted[..len_size];
        // let byte = [encrypted[0]];
        match Pin::new(&mut self.inner).poll_write(cx, &byte) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(len_size)), // 这里假设写入成功后返回原始数据长度
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
