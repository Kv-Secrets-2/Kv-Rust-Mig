use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use kv_broker::{ApiCaller, ApiPreview, ApiRequest, UrlSafety};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use serde_json::{Value, json};
use url::Url;

const SECRET: &str = "synthetic-broker-checks-credential";
const HOST: &str = "broker-checks.example";
type Events = Arc<Mutex<Vec<&'static str>>>;

struct TestSafety {
    port: u16,
    events: Events,
    refuse: AtomicBool,
}

impl UrlSafety for TestSafety {
    fn check(&self, url: &Url) -> Result<IpAddr, String> {
        assert_eq!(url.host_str(), Some(HOST));
        assert_eq!(url.port(), Some(self.port));
        self.events.lock().unwrap().push("safety");
        if self.refuse.load(Ordering::SeqCst) {
            Err("synthetic final safety refusal".into())
        } else {
            Ok(IpAddr::V4(Ipv4Addr::LOCALHOST))
        }
    }
}

struct Fixture {
    listener: TcpListener,
    server_config: Arc<rustls::ServerConfig>,
    caller: ApiCaller,
    provider: Value,
    redaction: Value,
    safety: Arc<TestSafety>,
    events: Events,
}

impl Fixture {
    fn new() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let events = Arc::new(Mutex::new(Vec::new()));
        let safety = Arc::new(TestSafety {
            port,
            events: Arc::clone(&events),
            refuse: AtomicBool::new(false),
        });
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Broker checks test CA");
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let key = KeyPair::generate().unwrap();
        let certificate = CertificateParams::new(vec![HOST.into()])
            .unwrap()
            .signed_by(&key, &ca, &ca_key)
            .unwrap();
        let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .unwrap();
        let caller = ApiCaller::with_test_ca_for_test(safety.clone(), ca.der()).unwrap();
        Self {
            listener,
            server_config: Arc::new(server_config),
            caller,
            provider: json!({
                "base_url":format!("https://{HOST}:{port}"),
                "secret_name":"TEST_TOKEN",
                "auth_type":"query",
                "auth_query_param":"k~ey",
                "default_headers":{"Content-Type":"application/json"}
            }),
            redaction: json!({}),
            safety,
            events,
        }
    }

    fn request<'a>(&'a self, body: &'a Value, headers: &'a Value) -> ApiRequest<'a> {
        ApiRequest {
            provider_name: "test",
            provider: &self.provider,
            secret_value: SECRET,
            path: "/v1/items?mode=one",
            method: "post",
            body: Some(body),
            extra_headers: headers,
            secrets_for_redact: &self.redaction,
            timeout: Duration::from_secs(5),
            max_response_bytes: 4096,
        }
    }

    fn assert_no_connection(&self) {
        assert!(matches!(
            self.listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }
}

fn snapshot(preview: &ApiPreview) -> Value {
    json!({
        "method":preview.method,
        "url":preview.url,
        "header_names":preview.header_names,
        "body_bytes":preview.body_bytes,
        "body_length":preview.body_length(),
    })
}

fn accept_bounded(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                return stream;
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("fixture did not receive a connection: {error}"),
        }
    }
}

#[test]
fn preview_and_refused_checks_never_open_the_transport() {
    let fixture = Fixture::new();
    let body = json!({"count":1e-7});
    let headers = json!({"X-Test":"caller value"});
    let preview = fixture
        .caller
        .preview(fixture.request(&body, &headers))
        .unwrap();
    assert_eq!(preview.method, "POST");
    assert!(!snapshot(&preview).to_string().contains(SECRET));
    fixture.assert_no_connection();

    let refusal = json!({"error":"synthetic facts refusal","error_code":"permit_invalid"});
    let result = fixture.caller.call_with_checks(
        fixture.request(&body, &headers),
        |_| {
            fixture.events.lock().unwrap().push("check");
            Err::<(), _>(refusal.clone())
        },
        |()| -> Result<(), Value> { panic!("admission ran after a check refusal") },
    );
    assert_eq!(result, refusal);
    fixture.assert_no_connection();

    let result = fixture.caller.call_with_checks(
        fixture.request(&body, &headers),
        |_| {
            fixture.events.lock().unwrap().push("check");
            Ok("matched-final-facts")
        },
        |checked| {
            assert_eq!(checked, "matched-final-facts");
            fixture.events.lock().unwrap().push("admit");
            Err::<(), _>(json!({"error":"synthetic stop","error_code":"agent_stopping"}))
        },
    );
    assert_eq!(result["error_code"], "agent_stopping");
    fixture.assert_no_connection();
    assert_eq!(
        *fixture.events.lock().unwrap(),
        ["safety", "safety", "check", "safety", "check", "admit"]
    );
}

#[test]
fn invalid_requests_and_final_url_safety_refusals_precede_callbacks() {
    let fixture = Fixture::new();
    let body = json!({});
    let invalid_headers = json!({"X-Test":"first","x-test":"second"});
    let result = fixture.caller.call_with_checks(
        fixture.request(&body, &invalid_headers),
        |_| -> Result<(), Value> { panic!("invalid request reached final check") },
        |()| -> Result<(), Value> { panic!("invalid request reached admission") },
    );
    assert_eq!(result["error_code"], "http_request_invalid");
    assert!(fixture.events.lock().unwrap().is_empty());
    fixture.assert_no_connection();

    let headers = json!({});
    fixture
        .caller
        .preview(fixture.request(&body, &headers))
        .unwrap();
    fixture.safety.refuse.store(true, Ordering::SeqCst);
    let result = fixture.caller.call_with_checks(
        fixture.request(&body, &headers),
        |_| -> Result<(), Value> { panic!("safety refusal reached final check") },
        |()| -> Result<(), Value> { panic!("safety refusal reached admission") },
    );
    assert_eq!(
        result["error"],
        "SSRF blocked: synthetic final safety refusal"
    );
    assert_eq!(*fixture.events.lock().unwrap(), ["safety", "safety"]);
    fixture.assert_no_connection();
}

#[test]
fn final_check_observes_reprepared_method_url_headers_and_body() {
    let fixture = Fixture::new();
    let body = json!({"approved":true});
    let changed_body = json!({"approved":false});
    let headers = json!({"X-Test":"one"});
    let changed_headers = json!({"X-Other":"one"});
    let original = snapshot(
        &fixture
            .caller
            .preview(fixture.request(&body, &headers))
            .unwrap(),
    );
    for change in ["method", "url", "header_names", "body_bytes"] {
        let mut request = fixture.request(&body, &headers);
        match change {
            "method" => request.method = "PUT",
            "url" => request.path = "/v1/different?mode=one",
            "header_names" => request.extra_headers = &changed_headers,
            "body_bytes" => request.body = Some(&changed_body),
            _ => unreachable!(),
        }
        let result = fixture.caller.call_with_checks(
            request,
            |final_preview| {
                let final_facts = snapshot(final_preview);
                assert_ne!(final_facts[change], original[change]);
                Err::<(), _>(json!({"error":"changed request","error_code":"permit_invalid"}))
            },
            |()| -> Result<(), Value> { panic!("changed request reached admission") },
        );
        assert_eq!(result["error_code"], "permit_invalid");
        fixture.assert_no_connection();
    }
    assert_eq!(fixture.events.lock().unwrap().len(), 5);
}

struct AdmissionGuard {
    active: Arc<AtomicBool>,
    events: Events,
}

impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        self.active.store(false, Ordering::SeqCst);
        self.events.lock().unwrap().push("guard-drop");
    }
}

#[test]
fn accepted_check_sends_exact_prepared_bytes_and_retains_admission_guard() {
    let fixture = Fixture::new();
    let listener = fixture.listener.try_clone().unwrap();
    let server_config = Arc::clone(&fixture.server_config);
    let active = Arc::new(AtomicBool::new(false));
    let server_active = Arc::clone(&active);
    let events = Arc::clone(&fixture.events);
    let worker = thread::spawn(move || {
        let stream = accept_bounded(&listener);
        assert!(server_active.load(Ordering::SeqCst));
        let tls = rustls::ServerConnection::new(server_config).unwrap();
        let mut stream = BufReader::new(rustls::StreamOwned::new(tls, stream));
        let mut request_line = String::new();
        stream.read_line(&mut request_line).unwrap();
        let mut received_headers = serde_json::Map::new();
        loop {
            let mut line = String::new();
            assert_ne!(stream.read_line(&mut line).unwrap(), 0);
            if line == "\r\n" {
                break;
            }
            assert!(received_headers.len() < 32);
            let (name, value) = line.trim_end_matches(['\r', '\n']).split_once(':').unwrap();
            received_headers.insert(name.to_ascii_lowercase(), json!(value.trim()));
        }
        let length = received_headers["content-length"]
            .as_str()
            .unwrap()
            .parse::<usize>()
            .unwrap();
        assert!(length <= 4096);
        let mut body = vec![0; length];
        stream.read_exact(&mut body).unwrap();
        assert!(server_active.load(Ordering::SeqCst));
        events.lock().unwrap().push("request");
        let response = format!("{{\"echo\":\"{SECRET}\",\"ok\":true}}");
        write!(
            stream.get_mut(),
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
            response.len()
        )
        .unwrap();
        stream.get_mut().flush().unwrap();
        (request_line, received_headers, body)
    });
    let body = json!({"label":"é\u{7f}","count":1e-7});
    let headers = json!({"X-Test":"caller value"});
    let preview = fixture
        .caller
        .preview(fixture.request(&body, &headers))
        .unwrap();
    let result = fixture.caller.call_with_checks(
        fixture.request(&body, &headers),
        |final_preview| {
            assert_eq!(snapshot(final_preview), snapshot(&preview));
            fixture.events.lock().unwrap().push("check");
            Ok(17)
        },
        |checked| {
            assert_eq!(checked, 17);
            fixture.events.lock().unwrap().push("admit");
            active.store(true, Ordering::SeqCst);
            Ok(AdmissionGuard {
                active: Arc::clone(&active),
                events: Arc::clone(&fixture.events),
            })
        },
    );
    let (request_line, received_headers, sent_body) = worker.join().unwrap();
    assert_eq!(result["status"], 200);
    assert!(!result.to_string().contains(SECRET));
    assert_eq!(
        request_line,
        format!("POST /v1/items?mode=one&k~ey={SECRET} HTTP/1.1\r\n")
    );
    assert_eq!(received_headers["x-test"], "caller value");
    assert_eq!(Some(sent_body), preview.body_bytes);
    assert!(!active.load(Ordering::SeqCst));
    assert_eq!(
        *fixture.events.lock().unwrap(),
        [
            "safety",
            "safety",
            "check",
            "admit",
            "request",
            "guard-drop"
        ]
    );
}
