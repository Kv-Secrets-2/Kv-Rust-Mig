//! Unix IPC waits matching the Python client's distinct request/probe budgets.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::Errno;
use rustix::net::{AddressFamily, SocketAddrUnix, SocketType};
use serde_json::Value;

use crate::frame::parse_json_payload;
use crate::{
    Frame, FrameKind, IPC_FRAME_HEADER_LEN, IPC_FRAME_MAGIC, MAX_AGENT_RESPONSE_BYTES, MAX_MSG,
    ProtocolError, decode_frame_header, frame_header, python_utf8_error,
};

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "timed out")
}

fn remaining(deadline: Option<Instant>) -> io::Result<Option<Duration>> {
    deadline
        .map(|deadline| {
            deadline
                .checked_duration_since(Instant::now())
                .filter(|left| !left.is_zero())
                .ok_or_else(timed_out)
        })
        .transpose()
}

fn deadline_after(timeout: Option<Duration>) -> io::Result<Option<Instant>> {
    timeout
        .map(|timeout| {
            Instant::now().checked_add(timeout).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "socket timeout is too large")
            })
        })
        .transpose()
}

fn wait_ready(socket: &UnixStream, events: PollFlags, deadline: Option<Instant>) -> io::Result<()> {
    loop {
        // Keep each poll representable on platforms with a signed millisecond
        // timeout. Longer caller budgets remain bounded by the same deadline.
        let timeout = remaining(deadline)?
            .map(|left| Timespec::try_from(left.min(Duration::from_secs(86_400))))
            .transpose()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid poll timeout"))?;
        let mut fds = [PollFd::new(socket, events)];
        match poll(&mut fds, timeout.as_ref()) {
            Ok(0) | Err(Errno::INTR) => continue,
            Ok(_) => {
                remaining(deadline)?;
                // HUP/ERR also wake the caller, whose read/write reports EOF
                // or the socket error without spinning on readiness flags.
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        }
    }
}

/// Connect to a Unix socket within an optional absolute deadline. The returned
/// stream is nonblocking; use the helpers below for bounded writes and reads.
pub fn connect_unix(path: impl AsRef<Path>, deadline: Option<Instant>) -> io::Result<UnixStream> {
    connect_with_mode(path.as_ref(), deadline, false)
}

fn connect_with_mode(
    path: &Path,
    deadline: Option<Instant>,
    immediate: bool,
) -> io::Result<UnixStream> {
    let address = SocketAddrUnix::new(path)?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let socket: UnixStream = rustix::net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        rustix::net::SocketFlags::NONBLOCK | rustix::net::SocketFlags::CLOEXEC,
        None,
    )?
    .into();
    // macOS has no SOCK_NONBLOCK/SOCK_CLOEXEC flags. Set both attributes before
    // connecting; Linux uses the atomic flags above to avoid an exec race.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let socket: UnixStream = {
        let socket = rustix::net::socket(AddressFamily::UNIX, SocketType::STREAM, None)?;
        let flags = rustix::io::fcntl_getfd(&socket)?;
        rustix::io::fcntl_setfd(&socket, flags | rustix::io::FdFlags::CLOEXEC)?;
        socket.into()
    };
    socket.set_nonblocking(true)?;
    loop {
        remaining(deadline)?;
        match rustix::net::connect(&socket, &address) {
            Ok(()) | Err(Errno::ISCONN) => return Ok(socket),
            Err(error) if immediate => return Err(error.into()),
            Err(Errno::INTR) => continue,
            Err(Errno::AGAIN) => {
                // Linux AF_UNIX uses EAGAIN for a full listen queue. No connect
                // is in progress: POLLOUT plus SO_ERROR=0 is NOT success. Retry
                // connect itself after a short bounded pause, until space opens.
                let pause = remaining(deadline)?
                    .unwrap_or(Duration::from_millis(10))
                    .min(Duration::from_millis(10));
                std::thread::sleep(pause);
            }
            Err(Errno::INPROGRESS | Errno::ALREADY) => loop {
                wait_ready(&socket, PollFlags::OUT, deadline)?;
                rustix::net::sockopt::socket_error(&socket)??;
                match rustix::net::getpeername(&socket) {
                    Ok(Some(_)) => return Ok(socket),
                    Ok(None) | Err(Errno::NOTCONN) => continue,
                    Err(error) => return Err(error.into()),
                }
            },
            Err(error) => return Err(error.into()),
        }
    }
}

/// Write the entire payload under one absolute deadline, like Python sendall.
/// Leaves the stream nonblocking and does not half-close it.
pub fn write_all_until(
    socket: &mut UnixStream,
    mut payload: &[u8],
    deadline: Option<Instant>,
) -> io::Result<()> {
    socket.set_nonblocking(true)?;
    while !payload.is_empty() {
        remaining(deadline)?;
        match socket.write(payload) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "socket write returned zero",
                ));
            }
            Ok(written) => payload = &payload[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait_ready(socket, PollFlags::OUT, deadline)?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn receive(
    socket: &mut UnixStream,
    chunk: &mut [u8],
    deadline: Option<Instant>,
) -> io::Result<usize> {
    loop {
        remaining(deadline)?;
        match socket.read(chunk) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait_ready(socket, PollFlags::IN, deadline)?;
            }
            result => return result,
        }
    }
}

fn complete_document(bytes: &[u8], start: usize) -> Result<Option<Value>, ProtocolError> {
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(error) if error.error_len().is_none() => return Ok(None),
        Err(error) => return Err(ProtocolError::InvalidUtf8(python_utf8_error(bytes, error))),
    };
    // StreamDeserializer requires a separator after a scalar; Python's
    // raw_decode instead recognizes its prefix and immediately rejects already
    // buffered extra text (for example trueX, 01, or 1e). Match that framing.
    let tail = &text[start..];
    let scalar_end = ["true", "false", "null"]
        .into_iter()
        .find(|literal| tail.starts_with(literal))
        .map(str::len)
        .or_else(|| number_prefix_end(tail.as_bytes()));
    if let Some(end) = scalar_end {
        return match serde_json::from_str(&tail[..end]) {
            Ok(value) if tail[end..].bytes().all(json_whitespace) => Ok(Some(value)),
            Ok(_) => serde_json::from_slice(bytes)
                .map(Some)
                .map_err(ProtocolError::Json),
            Err(_) => Ok(None),
        };
    }
    let mut documents = serde_json::Deserializer::from_str(tail).into_iter::<Value>();
    match documents.next() {
        Some(Ok(value)) => {
            if tail[documents.byte_offset()..]
                .bytes()
                .any(|byte| !json_whitespace(byte))
            {
                // Preserve the ordinary whole-buffer parse's error category.
                return serde_json::from_slice(bytes)
                    .map(Some)
                    .map_err(ProtocolError::Json);
            }
            Ok(Some(value))
        }
        // Python raw_decode waits after every ValueError, including malformed
        // prefixes; EOF or the deadline ultimately rejects an unfinished reply.
        Some(Err(_)) | None => Ok(None),
    }
}

fn json_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

fn number_prefix_end(bytes: &[u8]) -> Option<usize> {
    let mut end = usize::from(bytes.first() == Some(&b'-'));
    match bytes.get(end) {
        Some(b'0') => end += 1,
        Some(b'1'..=b'9') => {
            end += 1;
            while bytes.get(end).is_some_and(u8::is_ascii_digit) {
                end += 1;
            }
        }
        _ => return None,
    }
    if bytes.get(end) == Some(&b'.') && bytes.get(end + 1).is_some_and(u8::is_ascii_digit) {
        end += 2;
        while bytes.get(end).is_some_and(u8::is_ascii_digit) {
            end += 1;
        }
    }
    if matches!(bytes.get(end), Some(b'e' | b'E')) {
        let mut exponent = end + 1;
        if matches!(bytes.get(exponent), Some(b'+' | b'-')) {
            exponent += 1;
        }
        if bytes.get(exponent).is_some_and(u8::is_ascii_digit) {
            end = exponent + 1;
            while bytes.get(end).is_some_and(u8::is_ascii_digit) {
                end += 1;
            }
        }
    }
    Some(end)
}

/// Read a bounded reply as soon as one whole JSON document arrives, without
/// requiring EOF. Every receive shares `deadline`; already-buffered trailing
/// data and invalid UTF-8 are rejected. Leaves the stream nonblocking.
pub fn read_complete_reply(
    socket: &mut UnixStream,
    deadline: Instant,
) -> Result<Value, ProtocolError> {
    read_reply(socket, ReplyBudget::Deadline(deadline))
}

enum ReplyBudget {
    PerRead(Option<Duration>),
    Deadline(Instant),
}

fn read_reply(socket: &mut UnixStream, budget: ReplyBudget) -> Result<Value, ProtocolError> {
    socket.set_nonblocking(true)?;
    let mut bytes = Vec::new();
    let mut document_start = 0;
    let mut chunk = [0u8; 65_536];
    loop {
        let deadline = match budget {
            ReplyBudget::PerRead(timeout) => deadline_after(timeout)?,
            ReplyBudget::Deadline(deadline) => Some(deadline),
        };
        let read = if matches!(budget, ReplyBudget::PerRead(Some(Duration::ZERO))) {
            // timeout=0 is Python's nonblocking mode: consume ready bytes, but
            // preserve WouldBlock instead of waiting or imposing a deadline.
            socket.read(&mut chunk)?
        } else {
            receive(socket, &mut chunk, deadline)?
        };
        if read == 0 {
            if let Err(error) = std::str::from_utf8(&bytes) {
                return Err(ProtocolError::InvalidUtf8(python_utf8_error(&bytes, error)));
            }
            return serde_json::from_slice(&bytes).map_err(ProtocolError::Json);
        }
        if bytes.len().saturating_add(read) > MAX_AGENT_RESPONSE_BYTES {
            return Err(ProtocolError::ResponseTooLarge);
        }
        bytes.extend_from_slice(&chunk[..read]);
        if matches!(budget, ReplyBudget::Deadline(_)) {
            // Whitespace belongs to the size budget but need not be reparsed
            // after every packet. In particular, a cap-sized whitespace prefix
            // should take linear work rather than repeatedly scanning it.
            while document_start < bytes.len() && json_whitespace(bytes[document_start]) {
                document_start += 1;
            }
            if document_start < bytes.len()
                && let Some(value) = complete_document(&bytes, document_start)?
            {
                return Ok(value);
            }
        }
    }
}

fn read_exact_or_empty_eof(
    socket: &mut UnixStream,
    buf: &mut [u8],
    deadline: Instant,
) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        let read = receive(socket, &mut buf[filled..], Some(deadline))?;
        if read == 0 {
            if filled == 0 {
                return Ok(false);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "IPC frame ended before completion",
            ));
        }
        filled += read;
    }
    Ok(true)
}

fn read_exact_required(
    socket: &mut UnixStream,
    buf: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    if buf.is_empty() {
        return Ok(());
    }
    if read_exact_or_empty_eof(socket, buf, deadline)? {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "IPC frame ended before completion",
        ))
    }
}

fn read_frame_after_first(
    socket: &mut UnixStream,
    first: u8,
    deadline: Instant,
    expected: Option<FrameKind>,
) -> Result<Frame, ProtocolError> {
    let mut header = [0_u8; IPC_FRAME_HEADER_LEN];
    header[0] = first;
    read_exact_required(socket, &mut header[1..], deadline)?;
    let (kind, payload_len) = decode_frame_header(&header)?;
    if let Some(expected) = expected
        && kind != expected
    {
        return Err(crate::FrameError::WrongKind {
            expected,
            actual: kind,
        }
        .into());
    }
    // The header has already bounded this allocation. Read directly into the
    // final buffer rather than concatenating unbounded chunks.
    let mut payload = vec![0_u8; payload_len];
    read_exact_required(socket, &mut payload, deadline)?;
    Ok(Frame { kind, payload })
}

fn read_frame_with_kind_until(
    socket: &mut UnixStream,
    deadline: Instant,
    expected: Option<FrameKind>,
) -> Result<Option<Frame>, ProtocolError> {
    socket.set_nonblocking(true)?;
    let mut first = [0_u8; 1];
    if !read_exact_or_empty_eof(socket, &mut first, deadline)? {
        return Ok(None);
    }
    read_frame_after_first(socket, first[0], deadline, expected).map(Some)
}

/// Read one versioned IPC frame. Returns `None` only when the peer closes
/// before the first header byte; EOF anywhere later is an error.
pub fn read_frame_until(
    socket: &mut UnixStream,
    deadline: Instant,
) -> Result<Option<Frame>, ProtocolError> {
    read_frame_with_kind_until(socket, deadline, None)
}

/// Write one versioned IPC frame within the caller's existing absolute deadline.
pub fn write_frame_until(
    socket: &mut UnixStream,
    kind: FrameKind,
    payload: &[u8],
    deadline: Instant,
) -> Result<(), ProtocolError> {
    socket.set_nonblocking(true)?;
    let header = frame_header(kind, payload.len())?;
    write_all_until(socket, &header, Some(deadline))?;
    write_all_until(socket, payload, Some(deadline))?;
    socket.flush()?;
    Ok(())
}

pub fn write_frame_request_until(
    socket: &mut UnixStream,
    request: &Value,
    deadline: Instant,
) -> Result<(), ProtocolError> {
    let payload = crate::frame::json_payload(request)?;
    write_frame_until(socket, FrameKind::Request, &payload, deadline)
}

pub fn read_frame_request_until(
    socket: &mut UnixStream,
    deadline: Instant,
) -> Result<Option<Value>, ProtocolError> {
    let Some(frame) = read_frame_with_kind_until(socket, deadline, Some(FrameKind::Request))?
    else {
        return Ok(None);
    };
    parse_json_payload(&frame.payload).map(Some)
}

pub fn write_frame_response_until(
    socket: &mut UnixStream,
    response: &Value,
    deadline: Instant,
) -> Result<(), ProtocolError> {
    let payload = crate::frame::json_payload(response)?;
    write_frame_until(socket, FrameKind::Response, &payload, deadline)
}

pub fn read_frame_response_until(
    socket: &mut UnixStream,
    deadline: Instant,
) -> Result<Value, ProtocolError> {
    let frame = read_frame_with_kind_until(socket, deadline, Some(FrameKind::Response))?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "IPC response ended before its frame header",
            )
        })?;
    parse_json_payload(&frame.payload)
}

/// Exchange one framed request for one framed response. Connect, request write
/// and response read all share the single absolute `deadline`; progress never
/// extends it.
pub fn exchange_frames_until(
    path: &Path,
    request: &Value,
    deadline: Instant,
) -> Result<Value, ProtocolError> {
    let mut socket = connect_unix(path, Some(deadline))?;
    write_frame_request_until(&mut socket, request, deadline)?;
    read_frame_response_until(&mut socket, deadline)
}

/// Exchange one framed request for one framed response under one overall
/// timeout. Unlike the legacy compatibility reader, partial progress does not
/// reset this budget.
pub fn exchange_frames(
    path: &Path,
    request: &Value,
    timeout: Duration,
) -> Result<Value, ProtocolError> {
    let deadline = deadline_after(Some(timeout))?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame exchange requires a deadline",
        )
    })?;
    exchange_frames_until(path, request, deadline)
}

/// Wire encoding used by an accepted broker request. A service can accept the
/// legacy unframed JSON encoding while migrated clients use versioned frames,
/// then answer with the matching encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestWire {
    LegacyJson,
    FramedV1,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BrokerRequest {
    pub value: Value,
    pub wire: RequestWire,
}

fn read_legacy_json_after_first(
    socket: &mut UnixStream,
    first: u8,
    deadline: Instant,
) -> Result<Value, ProtocolError> {
    let mut bytes = vec![first];
    let mut document_start = 0;
    let mut chunk = [0_u8; 65_536];
    loop {
        while document_start < bytes.len() && json_whitespace(bytes[document_start]) {
            document_start += 1;
        }
        if document_start < bytes.len()
            && let Some(value) = complete_document(&bytes, document_start)?
        {
            return Ok(value);
        }
        let read = receive(socket, &mut chunk, Some(deadline))?;
        if read == 0 {
            if let Err(error) = std::str::from_utf8(&bytes) {
                return Err(ProtocolError::InvalidUtf8(python_utf8_error(&bytes, error)));
            }
            return serde_json::from_slice(&bytes).map_err(ProtocolError::Json);
        }
        if bytes.len().saturating_add(read) > MAX_MSG {
            return Err(ProtocolError::RequestTooLarge);
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
}

/// Read one broker request in either the current framed encoding or the legacy
/// unframed JSON encoding. Framed input starts with the versioned magic; every
/// other byte is handled by the legacy JSON reader, so existing Rust callers do
/// not need a wire-format negotiation step.
pub fn read_broker_request_until(
    socket: &mut UnixStream,
    deadline: Instant,
) -> Result<Option<BrokerRequest>, ProtocolError> {
    socket.set_nonblocking(true)?;
    let mut first = [0_u8; 1];
    if !read_exact_or_empty_eof(socket, &mut first, deadline)? {
        return Ok(None);
    }
    if first[0] == IPC_FRAME_MAGIC[0] {
        let frame = read_frame_after_first(socket, first[0], deadline, Some(FrameKind::Request))?;
        return Ok(Some(BrokerRequest {
            value: parse_json_payload(&frame.payload)?,
            wire: RequestWire::FramedV1,
        }));
    }
    Ok(Some(BrokerRequest {
        value: read_legacy_json_after_first(socket, first[0], deadline)?,
        wire: RequestWire::LegacyJson,
    }))
}

/// Write a response in the same wire encoding as its request. Legacy responses
/// keep the exact unframed JSON shape; framed responses carry the versioned
/// header and bounded length.
pub fn write_broker_response_until(
    socket: &mut UnixStream,
    response: &Value,
    wire: RequestWire,
    deadline: Instant,
) -> Result<(), ProtocolError> {
    match wire {
        RequestWire::FramedV1 => write_frame_response_until(socket, response, deadline),
        RequestWire::LegacyJson => {
            socket.set_nonblocking(true)?;
            let payload = crate::reply_bytes(response)?;
            write_all_until(socket, &payload, Some(deadline))?;
            socket.flush()?;
            Ok(())
        }
    }
}

pub(super) fn exchange(
    path: &Path,
    request: &Value,
    timeout: Option<Duration>,
    complete_json: bool,
) -> Result<Value, ProtocolError> {
    let immediate = timeout == Some(Duration::ZERO);
    let mut socket = connect_with_mode(
        path,
        if immediate {
            None
        } else {
            deadline_after(timeout)?
        },
        immediate,
    )?;
    let payload = kv_store::pyjson::to_vec_python(request, false)
        .map_err(|error| ProtocolError::Message(error.to_string()))?;
    if payload.len() > MAX_MSG {
        return Err(ProtocolError::RequestTooLarge);
    }
    if immediate {
        socket.write_all(&payload)?;
    } else {
        write_all_until(&mut socket, &payload, deadline_after(timeout)?)?;
    }
    if complete_json {
        // Enforcement always supplies a finite timeout; the reply gets its own
        // budget after sendall rather than sharing connect/write time.
        let deadline = deadline_after(timeout)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "complete reply requires a deadline",
            )
        })?;
        read_complete_reply(&mut socket, deadline)
    } else {
        read_reply(&mut socket, ReplyBudget::PerRead(timeout))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::process::{Child, Command, Output, Stdio};
    use std::thread;

    struct SocketPath(PathBuf);

    impl SocketPath {
        fn new() -> Self {
            let mut random = [0u8; 8];
            getrandom::getrandom(&mut random).unwrap();
            let directory = std::env::temp_dir().join(format!("kvp-{}", hex::encode(random)));
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .unwrap();
            Self(directory.join("s"))
        }
    }

    impl Drop for SocketPath {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
            let _ = fs::remove_dir(self.0.parent().unwrap());
        }
    }

    fn accept_bounded(listener: &UnixListener) -> UnixStream {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((socket, _)) => return socket,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("test server failed to accept within five seconds: {error}"),
            }
        }
    }

    struct TestChild(Option<Child>);

    impl Drop for TestChild {
        fn drop(&mut self) {
            if let Some(child) = self.0.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    fn python_output(command: &mut Command) -> Output {
        let mut child = TestChild(Some(
            command
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        ));
        let deadline = Instant::now() + Duration::from_secs(10);
        while child.0.as_mut().unwrap().try_wait().unwrap().is_none() {
            assert!(
                Instant::now() < deadline,
                "Python comparison exceeded ten seconds"
            );
            thread::sleep(Duration::from_millis(5));
        }
        child.0.take().unwrap().wait_with_output().unwrap()
    }

    fn timeout(error: ProtocolError) {
        assert!(
            matches!(error, ProtocolError::Io(ref io) if io.kind() == io::ErrorKind::TimedOut),
            "{error}"
        );
    }

    fn scripted_pair(
        chunks: Vec<(Duration, Vec<u8>)>,
        hold: Duration,
    ) -> (UnixStream, thread::JoinHandle<()>) {
        let (client, mut server) = UnixStream::pair().unwrap();
        server
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let worker = thread::spawn(move || {
            for (delay, bytes) in chunks {
                thread::sleep(delay);
                if server.write_all(&bytes).is_err() {
                    return;
                }
            }
            thread::sleep(hold);
        });
        (client, worker)
    }

    fn wait_until_read(socket: &UnixStream, deadline: Instant) -> bool {
        // Observe the reader's queue through a clone without stealing bytes.
        // Every caller has already written a nonempty fragment synchronously.
        while rustix::io::ioctl_fionread(socket).unwrap() != 0 {
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(1));
        }
        true
    }

    #[test]
    fn silent_reply_and_complete_json_without_eof_keep_distinct_timeouts() {
        let (mut client, server) = UnixStream::pair().unwrap();
        timeout(
            read_complete_reply(&mut client, Instant::now() + Duration::from_millis(60))
                .unwrap_err(),
        );
        drop(server);

        let (mut client, mut server) = UnixStream::pair().unwrap();
        server.write_all(b"{\"ok\":true}").unwrap();
        assert_eq!(
            read_complete_reply(&mut client, Instant::now() + Duration::from_millis(60)).unwrap(),
            serde_json::json!({"ok":true})
        );
        server.write_all(b"{}").unwrap();
        timeout(
            read_reply(
                &mut client,
                ReplyBudget::PerRead(Some(Duration::from_millis(60))),
            )
            .unwrap_err(),
        );
    }

    #[test]
    fn ordinary_reads_reset_their_timeout_but_probe_reads_share_one_deadline() {
        let budget = Duration::from_secs(2);
        for complete in [false, true] {
            let (mut client, mut server) = UnixStream::pair().unwrap();
            server
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            server.write_all(b"{").unwrap();
            let observer = client.try_clone().unwrap();
            let deadline = Instant::now() + budget;
            let worker = thread::spawn(move || {
                assert!(
                    wait_until_read(&observer, Instant::now() + Duration::from_secs(5)),
                    "reader did not consume the initial fragment"
                );
                // Start the producer's full budget only after a receive. Thus
                // even an ordinary reader that starts late must renew its
                // timeout to reach the final suffix. The probe must expire.
                let finish_after = Instant::now() + budget;
                let mut consumed_fragments = 1;
                while Instant::now() < finish_after {
                    server.write_all(b" ").unwrap();
                    if !wait_until_read(&observer, finish_after) {
                        break;
                    }
                    consumed_fragments += 1;
                    thread::sleep(Duration::from_millis(10));
                }
                assert!(Instant::now() >= deadline);
                server.write_all(b"\"ok\":true}").unwrap();
                // Closing supplies EOF to the ordinary reader. The observer
                // clone is dropped here too, including when the probe timed out.
                consumed_fragments
            });
            let result = if complete {
                read_complete_reply(&mut client, deadline)
            } else {
                read_reply(&mut client, ReplyBudget::PerRead(Some(budget)))
            };
            // Join before inspecting the result so failed assertions never
            // leave a producer alive. Its queue waits and writes are bounded.
            let consumed_fragments = worker.join().unwrap();
            assert!(consumed_fragments >= 2, "reader made no partial progress");
            if complete {
                timeout(result.unwrap_err());
            } else {
                assert_eq!(result.unwrap(), serde_json::json!({"ok":true}));
            }
        }
    }

    #[test]
    fn complete_reply_handles_fragmented_utf8_and_rejects_buffered_extra_data() {
        let prefix = b" \n{\"text\":\"\xc3";
        // Deterministically exercise the incomplete UTF-8 parser boundary in
        // addition to the socket delivery below: streams can coalesce writes.
        assert!(complete_document(prefix, 2).unwrap().is_none());
        let (mut client, mut server) = UnixStream::pair().unwrap();
        server.write_all(prefix).unwrap();
        let observer = client.try_clone().unwrap();
        let mut producer = server.try_clone().unwrap();
        producer
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let worker = thread::spawn(move || {
            assert!(
                wait_until_read(&observer, Instant::now() + Duration::from_secs(5)),
                "reader did not consume the UTF-8 prefix"
            );
            producer.write_all(b"\xa9\"} \t").unwrap();
        });
        let result = read_complete_reply(&mut client, Instant::now() + Duration::from_secs(5));
        worker.join().unwrap();
        assert_eq!(result.unwrap(), serde_json::json!({"text":"é"}));
        // Keep the original server open until after the successful reply;
        // framing must not rely on EOF or a producer's timed hold-open sleep.
        drop(server);

        for bytes in [b"{}garbage".as_slice(), b"{}{}", b"{}\x0b"] {
            let (mut client, mut server) = UnixStream::pair().unwrap();
            server.write_all(bytes).unwrap();
            assert!(matches!(
                read_complete_reply(&mut client, Instant::now() + Duration::from_secs(5)),
                Err(ProtocolError::Json(_))
            ));
        }
        let (mut client, mut server) = UnixStream::pair().unwrap();
        server.write_all(b"{\"text\":\"\xff\"}").unwrap();
        assert!(matches!(
            read_complete_reply(&mut client, Instant::now() + Duration::from_secs(5)),
            Err(ProtocolError::InvalidUtf8(_))
        ));
    }

    #[test]
    fn response_limit_counts_surrounding_whitespace_and_allows_exactly_the_cap() {
        for extra in [0, 1] {
            let mut bytes = vec![b' '; MAX_AGENT_RESPONSE_BYTES - 2 + extra];
            bytes.extend_from_slice(b"{}");
            let (mut client, worker) = scripted_pair(vec![(Duration::ZERO, bytes)], Duration::ZERO);
            let result = read_complete_reply(&mut client, Instant::now() + Duration::from_secs(10));
            if extra == 0 {
                assert_eq!(result.unwrap(), serde_json::json!({}));
            } else {
                assert!(matches!(result, Err(ProtocolError::ResponseTooLarge)));
            }
            drop(client);
            worker.join().unwrap();
        }
    }

    #[test]
    fn stalled_send_uses_one_deadline_even_after_partial_progress() {
        let (mut client, _server) = UnixStream::pair().unwrap();
        let payload = vec![b'x'; 8 * 1024 * 1024];
        let start = Instant::now();
        let error = write_all_until(
            &mut client,
            &payload,
            Some(start + Duration::from_millis(80)),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn zero_request_timeout_consumes_ready_bytes_without_waiting() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        server.write_all(b"{}").unwrap();
        let error =
            read_reply(&mut client, ReplyBudget::PerRead(Some(Duration::ZERO))).unwrap_err();
        assert!(
            matches!(error, ProtocolError::Io(ref error) if error.kind() == io::ErrorKind::WouldBlock)
        );

        let (mut client, mut server) = UnixStream::pair().unwrap();
        server.write_all(b"{}").unwrap();
        drop(server);
        assert_eq!(
            read_reply(&mut client, ReplyBudget::PerRead(Some(Duration::ZERO))).unwrap(),
            serde_json::json!({})
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn full_unix_backlog_is_not_mistaken_for_a_connected_socket() {
        let path = SocketPath::new();
        let listener = UnixListener::bind(&path.0).unwrap();
        rustix::net::listen(&listener, 0).unwrap();
        let queued = UnixStream::connect(&path.0).unwrap();
        assert_eq!(
            connect_with_mode(&path.0, None, true).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let start = Instant::now();
        let error = connect_unix(&path.0, Some(start + Duration::from_millis(80))).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(1));

        let accept = thread::spawn(move || {
            thread::sleep(Duration::from_millis(30));
            let first = accept_bounded(&listener);
            let second = accept_bounded(&listener);
            (first, second)
        });
        let connected =
            connect_unix(&path.0, Some(Instant::now() + Duration::from_secs(1))).unwrap();
        assert!(connected.peer_addr().is_ok());
        drop(queued);
        drop(connected);
        accept.join().unwrap();
    }

    #[test]
    fn reply_modes_match_live_python_reference() {
        let Some(python) = kv_test_support::python_reference() else {
            return;
        };
        let cases = [
            (true, "late_close"),
            (false, "late_close"),
            (true, "trickle"),
            (false, "trickle"),
            (true, "utf8"),
            (true, "extra"),
            (true, "invalid_utf8"),
            (true, "incomplete"),
            (true, "scalar"),
            (true, "scalar_extra"),
            (true, "number_extra"),
        ];
        for (complete, case) in cases {
            let (chunks, hold) = match case {
                "late_close" => (
                    vec![(Duration::ZERO, b"{\"ok\":true}".to_vec())],
                    Duration::from_millis(300),
                ),
                "trickle" => (
                    vec![
                        (Duration::ZERO, b"{".to_vec()),
                        (Duration::from_millis(100), b"\"ok\":".to_vec()),
                        (Duration::from_millis(100), b"true}".to_vec()),
                    ],
                    Duration::from_millis(100),
                ),
                "utf8" => (
                    vec![
                        (Duration::ZERO, b" \n{\"text\":\"\xc3".to_vec()),
                        (Duration::from_millis(20), b"\xa9\"} \t".to_vec()),
                    ],
                    Duration::from_millis(250),
                ),
                "extra" => (vec![(Duration::ZERO, b"{}{}".to_vec())], Duration::ZERO),
                "invalid_utf8" => (
                    vec![(Duration::ZERO, b"{\"x\":\"\xff\"}".to_vec())],
                    Duration::ZERO,
                ),
                "incomplete" => (vec![(Duration::ZERO, b"{\"x\":".to_vec())], Duration::ZERO),
                "scalar" => (
                    vec![(Duration::ZERO, b" true ".to_vec())],
                    Duration::from_millis(250),
                ),
                "scalar_extra" => (
                    vec![(Duration::ZERO, b"trueX".to_vec())],
                    Duration::from_millis(250),
                ),
                "number_extra" => (
                    vec![(Duration::ZERO, b"1e".to_vec())],
                    Duration::from_millis(250),
                ),
                _ => unreachable!(),
            };
            let (mut client, worker) = scripted_pair(chunks.clone(), hold);
            let rust = if complete {
                read_complete_reply(&mut client, Instant::now() + Duration::from_millis(170))
            } else {
                read_reply(
                    &mut client,
                    ReplyBudget::PerRead(Some(Duration::from_millis(170))),
                )
            };
            let rust = match rust {
                Ok(value) => serde_json::json!({"ok":value}),
                Err(ProtocolError::Io(error)) if error.kind() == io::ErrorKind::TimedOut => {
                    serde_json::json!({"error":"TimeoutError"})
                }
                Err(ProtocolError::Json(_)) => serde_json::json!({"error":"JSONDecodeError"}),
                Err(ProtocolError::InvalidUtf8(_)) => {
                    serde_json::json!({"error":"UnicodeDecodeError"})
                }
                Err(error) => panic!("unexpected Rust error: {error}"),
            };
            drop(client);
            worker.join().unwrap();

            let path = SocketPath::new();
            let listener = UnixListener::bind(&path.0).unwrap();
            let server = thread::spawn(move || {
                let mut socket = accept_bounded(&listener);
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                // Both paths send an initial request so the same server starts
                // its script only after the Python reader is ready.
                let mut request = [0u8; 4096];
                let _ = socket.read(&mut request);
                for (delay, bytes) in chunks {
                    thread::sleep(delay);
                    if socket.write_all(&bytes).is_err() {
                        return;
                    }
                }
                thread::sleep(hold);
            });
            let output = python_output(
                Command::new(&python)
                    .args([
                        "-I",
                        "-c",
                        r#"
import json, socket, sys, time
from kv import agent
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(.170)
s.connect(sys.argv[1])
try:
    if sys.argv[2] == 'complete':
        s.sendall(b'{}')
        result = json.loads(agent._read_agent_reply(s, time.monotonic() + .170, complete_json=True))
    else:
        agent._connect_agent_socket = lambda **kw: s
        agent._read_agent_token = lambda *args: ''
        result = agent.agent_request('status', timeout=.170)
    print(json.dumps({'ok': result}))
except Exception as exc:
    print(json.dumps({'error': type(exc).__name__}))
finally:
    s.close()
"#,
                    ])
                    .arg(&path.0)
                    .arg(if complete { "complete" } else { "ordinary" }),
            );
            server.join().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let python: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(rust, python, "case={case}, complete={complete}");
        }
    }

    #[test]
    fn framed_request_response_round_trip_and_direction_errors() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            let request = read_frame_request_until(&mut server, deadline)
                .unwrap()
                .expect("request frame");
            assert_eq!(request, serde_json::json!({"cmd":"status"}));
            write_frame_response_until(&mut server, &serde_json::json!({"running":true}), deadline)
                .unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        write_frame_request_until(&mut client, &serde_json::json!({"cmd":"status"}), deadline)
            .unwrap();
        assert_eq!(
            read_frame_response_until(&mut client, deadline).unwrap(),
            serde_json::json!({"running":true})
        );
        worker.join().unwrap();

        let (mut client, mut server) = UnixStream::pair().unwrap();
        write_frame_response_until(
            &mut server,
            &serde_json::json!({"wrong":"direction"}),
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        let error = read_frame_request_until(&mut client, Instant::now() + Duration::from_secs(2))
            .unwrap_err();
        assert!(matches!(
            error,
            ProtocolError::Frame(crate::FrameError::WrongKind {
                expected: FrameKind::Request,
                actual: FrameKind::Response,
            })
        ));
    }

    #[test]
    fn broker_reader_accepts_framed_and_legacy_requests_with_matching_replies() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let framed_worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            let request = read_broker_request_until(&mut server, deadline)
                .unwrap()
                .expect("framed request");
            assert_eq!(request.wire, RequestWire::FramedV1);
            assert_eq!(request.value, serde_json::json!({"cmd":"status"}));
            write_broker_response_until(
                &mut server,
                &serde_json::json!({"ok":true}),
                request.wire,
                deadline,
            )
            .unwrap();
        });
        write_frame_request_until(
            &mut client,
            &serde_json::json!({"cmd":"status"}),
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(
            read_frame_response_until(&mut client, Instant::now() + Duration::from_secs(2))
                .unwrap(),
            serde_json::json!({"ok":true})
        );
        framed_worker.join().unwrap();

        let (mut client, mut server) = UnixStream::pair().unwrap();
        client.write_all(br#"{"cmd":"status"}"#).unwrap();
        let legacy_worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            let request = read_broker_request_until(&mut server, deadline)
                .unwrap()
                .expect("legacy request");
            assert_eq!(request.wire, RequestWire::LegacyJson);
            assert_eq!(request.value, serde_json::json!({"cmd":"status"}));
            write_broker_response_until(
                &mut server,
                &serde_json::json!({"ok":true}),
                request.wire,
                deadline,
            )
            .unwrap();
        });
        let mut legacy_reply = Vec::new();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.read_to_end(&mut legacy_reply).unwrap();
        assert_eq!(legacy_reply.first(), Some(&b'{'));
        assert_eq!(
            serde_json::from_slice::<Value>(&legacy_reply).unwrap(),
            serde_json::json!({"ok":true})
        );
        legacy_worker.join().unwrap();
    }

    #[test]
    fn framed_exchange_enforces_one_overall_deadline_while_response_trickles() {
        let path = SocketPath::new();
        let listener = UnixListener::bind(&path.0).unwrap();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            let request = read_frame_request_until(&mut socket, deadline).unwrap();
            assert!(request.is_some());
            let bytes =
                crate::encode_json_frame(FrameKind::Response, &serde_json::json!({"slow":true}))
                    .unwrap();
            for byte in bytes {
                if socket.write_all(&[byte]).is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(10));
            }
        });
        let start = Instant::now();
        let error = exchange_frames(
            &path.0,
            &serde_json::json!({"cmd":"status"}),
            Duration::from_millis(80),
        )
        .unwrap_err();
        timeout(error);
        assert!(start.elapsed() < Duration::from_secs(1));
        server.join().unwrap();
    }

    #[test]
    fn framed_write_uses_one_deadline_even_after_partial_progress() {
        let (mut client, _server) = UnixStream::pair().unwrap();
        // Keep the peer open but unread, and fill the socket first so the
        // result does not depend on a platform's default buffer size.
        client.set_nonblocking(true).unwrap();
        let filler = [b'x'; 8192];
        let mut filled = 0;
        loop {
            match client.write(&filler) {
                Ok(0) => break,
                Ok(written) => {
                    filled += written;
                    assert!(filled < 64 * 1024 * 1024, "socket never backpressured");
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("failed to fill test socket: {error}"),
            }
        }
        let payload = vec![b' '; MAX_AGENT_RESPONSE_BYTES];
        let start = Instant::now();
        let error = write_frame_until(
            &mut client,
            FrameKind::Response,
            &payload,
            start + Duration::from_millis(80),
        )
        .unwrap_err();
        timeout(error);
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn wrong_direction_is_rejected_before_payload_read_or_allocation() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let header = frame_header(FrameKind::Response, MAX_AGENT_RESPONSE_BYTES).unwrap();
        server.write_all(&header).unwrap();
        let start = Instant::now();
        let error =
            read_frame_request_until(&mut client, start + Duration::from_secs(5)).unwrap_err();
        assert!(matches!(
            error,
            ProtocolError::Frame(crate::FrameError::WrongKind {
                expected: FrameKind::Request,
                actual: FrameKind::Response,
            })
        ));
        assert!(start.elapsed() < Duration::from_secs(1));
        drop(server);
    }

    #[test]
    fn oversized_declared_frame_is_rejected_before_payload_read_or_allocation() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let mut header = frame_header(FrameKind::Response, 0).unwrap();
        header[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        server.write_all(&header).unwrap();
        let start = Instant::now();
        let error =
            read_frame_response_until(&mut client, start + Duration::from_secs(5)).unwrap_err();
        assert!(matches!(
            error,
            ProtocolError::Frame(crate::FrameError::PayloadTooLarge {
                kind: FrameKind::Response,
                actual,
                ..
            }) if actual == u32::MAX as usize
        ));
        assert!(start.elapsed() < Duration::from_secs(1));
        drop(server);
    }

    #[test]
    fn frame_eof_rules_distinguish_clean_idle_close_from_truncation() {
        let (mut client, server) = UnixStream::pair().unwrap();
        drop(server);
        assert!(
            read_frame_until(&mut client, Instant::now() + Duration::from_secs(1))
                .unwrap()
                .is_none()
        );

        let (mut client, mut server) = UnixStream::pair().unwrap();
        let bytes = crate::encode_json_frame(FrameKind::Response, &serde_json::json!({})).unwrap();
        server.write_all(&bytes[..bytes.len() - 1]).unwrap();
        drop(server);
        let error =
            read_frame_until(&mut client, Instant::now() + Duration::from_secs(1)).unwrap_err();
        assert!(
            matches!(error, ProtocolError::Io(ref error) if error.kind() == io::ErrorKind::UnexpectedEof),
            "{error}"
        );
    }

    #[test]
    fn exact_cap_frame_round_trips_without_extra_memory_slop() {
        let mut payload = vec![b' '; MAX_AGENT_RESPONSE_BYTES - 2];
        payload.extend_from_slice(b"{}");
        assert_eq!(payload.len(), MAX_AGENT_RESPONSE_BYTES);
        let bytes = crate::encode_frame(FrameKind::Response, &payload).unwrap();
        assert_eq!(bytes.len(), IPC_FRAME_HEADER_LEN + MAX_AGENT_RESPONSE_BYTES);

        let (mut client, mut server) = UnixStream::pair().unwrap();
        let writer = thread::spawn(move || {
            server.write_all(&bytes).unwrap();
        });
        assert_eq!(
            read_frame_response_until(&mut client, Instant::now() + Duration::from_secs(5))
                .unwrap(),
            serde_json::json!({})
        );
        writer.join().unwrap();
    }

    #[test]
    fn legacy_compatibility_reader_also_uses_one_overall_deadline() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let writer = thread::spawn(move || {
            for byte in br#"{"cmd":"status"}"# {
                if server.write_all(&[*byte]).is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(10));
            }
        });
        let start = Instant::now();
        let error =
            read_broker_request_until(&mut client, start + Duration::from_millis(80)).unwrap_err();
        timeout(error);
        assert!(start.elapsed() < Duration::from_secs(1));
        drop(client);
        writer.join().unwrap();
    }

    #[test]
    fn framed_agent_exchange_uses_frames_for_preflight_and_request() {
        let path = SocketPath::new();
        let listener = UnixListener::bind(&path.0).unwrap();
        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            for expected in ["enforcement", "list"] {
                let mut socket = accept_bounded(&listener);
                let request = read_frame_request_until(&mut socket, deadline)
                    .unwrap()
                    .expect("framed agent request");
                assert_eq!(request["cmd"], expected);
                let response = if expected == "enforcement" {
                    serde_json::json!({"enforcement":crate::ENFORCEMENT_GENERATION})
                } else {
                    serde_json::json!({"ok":true})
                };
                write_frame_response_until(&mut socket, &response, deadline).unwrap();
            }
        });
        let answer = crate::framed_agent_exchange(
            &path.0,
            "list",
            &serde_json::json!({"cmd":"list","token":"test"}),
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(answer, serde_json::json!({"ok":true}));
        server.join().unwrap();
    }

    #[test]
    fn framed_agent_deadline_spans_preflight_and_request() {
        let path = SocketPath::new();
        let listener = UnixListener::bind(&path.0).unwrap();
        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            for expected in ["enforcement", "list"] {
                let mut socket = accept_bounded(&listener);
                let Ok(Some(request)) = read_frame_request_until(&mut socket, deadline) else {
                    return;
                };
                assert_eq!(request["cmd"], expected);
                thread::sleep(Duration::from_millis(120));
                let response = if expected == "enforcement" {
                    serde_json::json!({"enforcement":crate::ENFORCEMENT_GENERATION})
                } else {
                    serde_json::json!({"ok":true})
                };
                let _ = write_frame_response_until(&mut socket, &response, deadline);
            }
        });
        let start = Instant::now();
        let error = crate::framed_agent_exchange(
            &path.0,
            "list",
            &serde_json::json!({"cmd":"list","token":"test"}),
            Duration::from_millis(200),
        )
        .unwrap_err();
        timeout(error);
        assert!(start.elapsed() < Duration::from_secs(1));
        server.join().unwrap();
    }
}
