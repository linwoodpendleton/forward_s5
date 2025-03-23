//aes_crypto.rs
use std::collections::VecDeque;
use std::future::Future;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::io::Result as IoResult;
use std::sync::Arc;
use crossbeam_queue::SegQueue;
use moka::sync::Cache;

use futures::lock::Mutex;

use tokio::time::{Sleep};

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
    hash: String,
    first:bool,
    partial_buf: Vec<u8>,        // 用来存储还没凑够的字节
    partial_needed: usize,       // 还差多少字节才能到 32


    wait_count: u32,
    sleep_future: Option<Pin<Box<Sleep>>>,
    data_len: usize,
    read_que: Arc<Cache<String, Arc<SegQueue<Vec<u8>>>>>,
    write_que:Arc<Cache<String, Arc<SegQueue<Vec<u8>>>>>,
    read_que_d: Option<Arc<SegQueue<Vec<u8>>>>,
    write_que_d:Option<Arc<SegQueue<Vec<u8>>>>,
}

impl<T> AesCryptoStream<T> {
    const MAX_RETRY: u8 = 10;

    pub fn new(inner: T,s:String,read_que: Arc<Cache<String, Arc<SegQueue<Vec<u8>>>>>,write_que:Arc<Cache<String, Arc<SegQueue<Vec<u8>>>>>) -> Self {
        Self { inner, read_buf: Vec::new(), read_pos: 0 ,hash:s,first:true, partial_buf: vec![], partial_needed: 32, wait_count: 0, sleep_future: None, data_len: 0, read_que, write_que, read_que_d: None, write_que_d: None }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for AesCryptoStream<T> {
     fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out_buf: &mut ReadBuf<'_>
    ) -> Poll<IoResult<()>> {
         println!("poll_read start");
        // 如果有已解密数据，则先返回缓冲区中的数据
        if self.read_pos < self.read_buf.len() {
            println!("read_pos:{}",self.read_pos);
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
        println!("poll_read start 2");
        match Pin::new(&mut self.inner).poll_read(cx, &mut tmp_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                println!("poll_read start 3");

                if self.first{
                    let n = tmp_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    println!("n:{}",n);
                    let mut encrypted_data = &tmp_buf.filled()[..n];

                    // 解密获得明文数据
                    let decrypted = decrypt(encrypted_data.clone());
                    self.partial_buf.extend_from_slice(&decrypted);
                    if self.partial_buf.len() < self.partial_needed {
                        return Poll::Pending;
                    }

                    self.first = false;


                    let hash = String::from_utf8_lossy(&self.partial_buf[..32]).to_string();
                    self.hash = hash.to_string();
                    println!("hash:{}",self.hash);
                    let mut temp_p = self.partial_buf[32..].to_vec();
                    let to_copy = std::cmp::min(temp_p.len(), out_buf.remaining());

                    out_buf.put_slice(&temp_p[..to_copy]);
                    if self.read_que_d.is_none() || self.write_que_d.is_none() {
                        let mut max_try = 100000000;
                        // 1) 检查缓存




                            let maybe_read = self.read_que.get(&self.hash);
                            match maybe_read {
                                Some(mut read) => {
                                    println!("Found socket in cache");
                                    self.read_que_d = Some(read);

                                },
                                None => {
                                    println!("Not found socket in cache");
                                }
                            }
                            let maybe_write = self.write_que.get(&self.hash);
                            match maybe_write {
                                Some(mut write) => {
                                    println!("Found socket in cache");
                                    self.write_que_d = Some(write);

                                },
                                None => {
                                    println!("Not found socket in cache");
                                }
                            }


                    }



                }
                // let mut this = self;
                let mut this = self.as_mut();
                loop {
                    let maybe_buf = if let Some(ref read_mutex) = this.read_que_d {
                        let read_mutex_lock = read_mutex.pop();
                        match read_mutex_lock {
                            Some(buf) => {
                                Some(buf)
                            },
                            None => {
                                None
                            }
                        }


                    } else {
                        None
                    };

                    if let Some(buf) = maybe_buf {
                        // 锁已在上面的作用域中释放，现在可以安全地修改 this 内部数据
                        this.read_buf = decrypt(&buf);
                        this.read_pos = 0;
                        println!("read_buf len:{}", this.read_buf.len());
                        let to_copy = std::cmp::min(this.read_buf.len(), out_buf.remaining());
                        out_buf.put_slice(&this.read_buf[..to_copy]);
                        this.read_pos = to_copy;
                        println!("read_pos:{}", this.read_pos);
                        println!("read_buf len:{}", this.read_buf.len());
                        if this.read_pos == this.read_buf.len() {
                            this.read_buf.clear();
                            this.read_pos = 0;
                            println!("read_buf clear");
                        }
                        break;
                    }
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
        // 对传入数据整体加密
        let encrypted = encrypt(buf);


        // 如果找到了写队列，则使用 futures::lock::Mutex 的 poll_lock 方法
        let write_result = match self.write_que_d.clone() {
            Some(write) => {
                write
            },
            None => {
                return Poll::Ready(Ok(buf.len()));
            }
        };
        write_result.push(encrypted);

        let tmp_buf = vec![1u8];
        match Pin::new(&mut self.inner).poll_write(cx, &tmp_buf) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(buf.len())), // 返回写入原始数据的长度
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

