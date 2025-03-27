//aes_crypto.rs
use std::collections::VecDeque;
use std::future::Future;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::io::Result as IoResult;
use std::sync::Arc;
use crossbeam_queue::SegQueue;
use flume::{unbounded, Receiver, Sender};
use moka::sync::Cache;

use futures::lock::Mutex;

use tokio::time::{Sleep};

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
    hash: String,
    first: bool,
    partial_buf: Vec<u8>,        // 用来存储还没凑够的字节
    partial_needed: usize,       // 还差多少字节才能到 32
    wait_count: u32,
    data_len: usize,
    read_que: Arc<Cache<String, Arc<Receiver<Vec<u8>>>>>,
    write_que: Arc<Cache<String, Arc<Receiver<Vec<u8>>>>>,
    read_que_d: Option<Arc<Receiver<Vec<u8>>>>,
    write_que_d: Option<Arc<Sender<Vec<u8>>>>,
}

impl<T> AesCryptoStream<T> {
    const MAX_RETRY: u32 = 25;

    pub fn new(inner: T, s: String, read_que: Arc<Cache<String, Arc<Receiver<Vec<u8>>>>>, write_que: Arc<Cache<String, Arc<Receiver<Vec<u8>>>>>) -> Self {
        Self {
            inner,
            read_buf: Vec::new(),
            read_pos: 0,
            hash: s,
            first: true,
            partial_buf: vec![],
            partial_needed: 32,
            wait_count: 0,
            data_len: 0,
            read_que,
            write_que,
            read_que_d: None,
            write_que_d: None
        }
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
            // self.write_que.remove(&self.hash);
            self.wait_count = 0;  // 重置计数
            return Poll::Ready(Ok(()));  // 返回空结果
        }

        // 如果有已解密数据，则先返回缓冲区中的数据
        if self.read_pos < self.read_buf.len() {
            // 有数据时重置计数
            self.wait_count = 0;

            println!("read_pos:{}", self.read_pos);
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

        // 检查队列中是否有数据
        let maybe_buf = self.read_que_d.as_ref().and_then(|read| {
            match read.try_recv() {
                Ok(buf) => Some(buf),
                Err(_) => None,
            }
        });

        if let Some(buf) = maybe_buf {
            // 有数据，处理它
            self.wait_count = 0;  // 重置计数
            self.read_buf = decrypt(&buf);
            self.read_pos = 0;
            println!("Got data from queue, read_buf len:{}", self.read_buf.len());
            let to_copy = std::cmp::min(self.read_buf.len(), out_buf.remaining());
            out_buf.put_slice(&self.read_buf[..to_copy]);
            self.read_pos = to_copy;
            if self.read_pos == self.read_buf.len() {
                self.read_buf.clear();
                self.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // 否则，从底层流中读取原始（加密）数据
        let mut tmp = [0u8; 4096];
        let mut tmp_buf = ReadBuf::new(&mut tmp);
        // println!("poll_read start 2");
        if self.read_que_d.is_none() || self.write_que_d.is_none() {
            // 1) 检查缓存
            let maybe_read = self.read_que.get(&self.hash);
            match maybe_read {
                Some(read) => {
                    println!("Found socket in cache");
                    self.read_que_d = Some(read);
                },
                None => {
                    println!("Not found socket in cache");
                }
            }
            let (tx, rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = unbounded();
            self.write_que_d = Some(Arc::new(tx));
            self.write_que.insert(self.hash.clone(), Arc::new(rx));
        }
        match Pin::new(&mut self.inner).poll_read(cx, &mut tmp_buf) {
            Poll::Pending => {
                // println!("pending 2 - retry {}/{}", self.wait_count, Self::MAX_RETRY);

                // 使用单独的任务来确保唤醒
                let waker = cx.waker().clone();
                tokio::spawn(async move {
                    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                    waker.wake();
                });

                return Poll::Pending;
            },
            Poll::Ready(Ok(())) => {
                // println!("poll_read start 3");

                if self.first {
                    let n = tmp_buf.filled().len();
                    if n == 0 {
                        // 使用单独的任务来确保唤醒
                        let waker = cx.waker().clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                            waker.wake();
                        });
                        return Poll::Pending;
                    }
                    println!("n:{}", n);
                    let encrypted_data = &tmp_buf.filled()[..n];

                    // 解密获得明文数据
                    let decrypted = decrypt(encrypted_data);
                    self.partial_buf.extend_from_slice(&decrypted);
                    if self.partial_buf.len() < self.partial_needed {
                        // 使用单独的任务来确保唤醒
                        let waker = cx.waker().clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                            waker.wake();
                        });

                        return Poll::Pending;
                    }

                    self.first = false;
                    self.wait_count = 0; // 重置计数

                    let hash = String::from_utf8_lossy(&self.partial_buf[..32]).to_string();
                    self.hash = hash.to_string();
                    println!("hash:{}", self.hash);
                    let temp_p = self.partial_buf[32..].to_vec();
                    let to_copy = std::cmp::min(temp_p.len(), out_buf.remaining());
                    if to_copy == 0 {
                        // 使用单独的任务来确保唤醒
                        let waker = cx.waker().clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                            waker.wake();
                        });

                        return Poll::Pending;
                    }
                    // println!("to_copy:{}", to_copy);
                    out_buf.put_slice(&temp_p[..to_copy]);


                    return Poll::Ready(Ok(()));
                }

                // 再次检查队列中是否有数据
                let maybe_buf = self.read_que_d.as_ref().and_then(|read| {
                    match read.try_recv() {
                        Ok(buf) => Some(buf),
                        Err(_) => None,
                    }
                });

                if let Some(buf) = maybe_buf {
                    // 有数据，处理它
                    self.wait_count = 0; // 重置计数
                    self.read_buf = decrypt(&buf);
                    self.read_pos = 0;
                    println!("read_buf len:{}", self.read_buf.len());
                    let to_copy = std::cmp::min(self.read_buf.len(), out_buf.remaining());
                    out_buf.put_slice(&self.read_buf[..to_copy]);
                    self.read_pos = to_copy;
                    println!("read_pos:{}", self.read_pos);
                    println!("read_buf len:{}", self.read_buf.len());
                    if self.read_pos == self.read_buf.len() {
                        self.read_buf.clear();
                        self.read_pos = 0;
                        println!("read_buf clear");
                    }
                    return Poll::Ready(Ok(()));
                } else {
                    // 没有数据，使用单独的任务来确保唤醒
                    // println!("No data available - retry {}/{}", self.wait_count, Self::MAX_RETRY);

                    let waker = cx.waker().clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                        waker.wake();
                    });

                    // println!("Pending");
                    return Poll::Pending;
                }
            },
            Poll::Ready(Err(e)) => {
                return Poll::Ready(Err(e));
            },
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for AesCryptoStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8]
    ) -> Poll<IoResult<usize>> {
        println!("send 111");

        // 对传入数据整体加密
        let encrypted = encrypt(buf);

        // 尝试发送到write队列
        let send_success = self.write_que_d.clone().and_then(|write| {
            let send_result = write.send(encrypted.clone());
            match send_result {
                Ok(_) => {
                    println!("Send data to write queue success len {}", encrypted.len());
                    Some(true)
                },
                Err(e) => {
                    println!("Error sending data to write queue: {}", e);
                    Some(false)
                },
            }
        }).unwrap_or(false);

        if !send_success {
            // 发送失败，使用单独的任务来确保唤醒
            println!("Send failed, will retry");

            let waker = cx.waker().clone();
            tokio::spawn(async move {
                tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                waker.wake();
            });

            return Poll::Pending;
        }

        // 发送成功，继续调用内部流的poll_write
        let tmp_buf = vec![1u8];
        match Pin::new(&mut self.inner).poll_write(cx, &tmp_buf) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(buf.len())), // 返回写入原始数据的长度
            Poll::Pending => {
                // 内部流挂起，使用单独的任务来确保唤醒
                println!("Inner write pending, will retry");

                let waker = cx.waker().clone();
                tokio::spawn(async move {
                    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                    waker.wake();
                });

                Poll::Pending
            },
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>
    ) -> Poll<IoResult<()>> {
        // 调用内部流的poll_flush
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Pending => {
                // 内部流挂起，使用单独的任务来确保唤醒
                println!("Inner flush pending, will retry");

                let waker = cx.waker().clone();
                tokio::spawn(async move {
                    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                    waker.wake();
                });

                Poll::Pending
            },
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>
    ) -> Poll<IoResult<()>> {
        // 调用内部流的poll_shutdown
        match Pin::new(&mut self.inner).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Pending => {
                // 内部流挂起，使用单独的任务来确保唤醒
                println!("Inner shutdown pending, will retry");

                let waker = cx.waker().clone();
                tokio::spawn(async move {
                    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                    waker.wake();
                });

                Poll::Pending
            },
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }
}