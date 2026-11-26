//! A bounded loopback HTTP provider used only by the release-gate harness.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedRequest {
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl RecordedRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

pub struct MockProvider {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    stop: Arc<AtomicBool>,
    acceptor: Option<JoinHandle<()>>,
}

impl MockProvider {
    pub fn start() -> Self {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("bind loopback mock provider");
        listener
            .set_nonblocking(true)
            .expect("make mock provider listener nonblocking");
        let addr = listener.local_addr().expect("mock provider address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let acceptor = {
            let requests = Arc::clone(&requests);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let requests = Arc::clone(&requests);
                            std::thread::spawn(move || handle_connection(stream, requests));
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            })
        };
        Self {
            addr,
            requests,
            stop,
            acceptor: Some(acceptor),
        }
    }

    pub fn origin(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.requests
            .lock()
            .expect("mock provider requests")
            .clone()
    }

    pub fn count(&self) -> usize {
        self.requests.lock().expect("mock provider requests").len()
    }
}

impl Drop for MockProvider {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.addr);
        if let Some(acceptor) = self.acceptor.take() {
            let _ = acceptor.join();
        }
    }
}

fn read_until(fine: &mut TcpStream, buffer: &mut Vec<u8>, end: usize) -> std::io::Result<bool> {
    while buffer.len() < end {
        let mut chunk = [0u8; 4096];
        let read = fine.read(&mut chunk)?;
        if read == 0 {
            return Ok(false);
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > 1024 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "mock provider request exceeds 1 MiB",
            ));
        }
    }
    Ok(true)
}

struct ParsedHead {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    content_length: usize,
}

fn parse_head(head: &[u8]) -> Option<ParsedHead> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let mut request_line = lines.next()?.split_whitespace();
    let method = request_line.next()?.to_owned();
    let target = request_line.next()?.to_owned();
    if request_line.next()? != "HTTP/1.1" {
        return None;
    }
    let mut headers = Vec::new();
    let mut content_length = 0usize;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':')?;
        let value = value.trim().to_owned();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse().ok()?;
        }
        headers.push((name.to_owned(), value));
    }
    Some(ParsedHead {
        method,
        target,
        headers,
        content_length,
    })
}

fn handle_connection(mut stream: TcpStream, requests: Arc<Mutex<Vec<RecordedRequest>>>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let mut buffer = Vec::new();
    loop {
        let mut chunk = [0u8; 4096];
        let read = match stream.read(&mut chunk) {
            Ok(0) => return,
            Ok(read) => read,
            Err(_) => return,
        };
        buffer.extend_from_slice(&chunk[..read]);
        let Some(head_end) = buffer
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
        else {
            if buffer.len() > 64 * 1024 {
                return;
            }
            continue;
        };
        let Some(head) = parse_head(&buffer[..head_end]) else {
            return;
        };
        if !read_until(&mut stream, &mut buffer, head_end + head.content_length).unwrap_or(false) {
            return;
        }
        let body = buffer[head_end..head_end + head.content_length].to_vec();
        requests
            .lock()
            .expect("mock provider requests")
            .push(RecordedRequest {
                method: head.method,
                target: head.target,
                headers: head.headers,
                body,
            });
        let response_body = br#"{"ok":true,"provider":"kv-v1-release-gate-mock"}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response_body.len()
        );
        if stream.write_all(response.as_bytes()).is_err()
            || stream.write_all(response_body).is_err()
        {
            return;
        }
        return;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_provider_records_method_target_headers_and_body() {
        let provider = MockProvider::start();
        let mut stream = TcpStream::connect(provider.addr).unwrap();
        stream
            .write_all(
                b"POST /v1/messages?q=1 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer test\r\nContent-Length: 7\r\n\r\n{\"x\":1}",
            )
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        let requests = provider.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "POST");
        assert_eq!(requests[0].target, "/v1/messages?q=1");
        assert_eq!(requests[0].header("authorization"), Some("Bearer test"));
        assert_eq!(requests[0].body, b"{\"x\":1}");
    }
}
