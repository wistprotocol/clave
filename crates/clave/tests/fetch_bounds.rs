use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

fn read_request(stream: &mut TcpStream) -> String {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    while !buffer.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut chunk).unwrap();
        if n == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..n]);
    }
    String::from_utf8_lossy(&buffer).into_owned()
}

/// Streams a chunked body until the peer stops reading, counting what
/// was written; the body would run to `ceiling` bytes if read whole.
fn stream_until_refused(ceiling: usize) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let written = Arc::new(AtomicUsize::new(0));
    let counter = written.clone();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        read_request(&mut stream);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
            .unwrap();
        let chunk = vec![b'x'; 16 * 1024];
        let header = format!("{:x}\r\n", chunk.len());
        while counter.load(Ordering::SeqCst) < ceiling {
            if stream.write_all(header.as_bytes()).is_err()
                || stream.write_all(&chunk).is_err()
                || stream.write_all(b"\r\n").is_err()
            {
                break;
            }
            counter.fetch_add(chunk.len(), Ordering::SeqCst);
        }
    });
    (port, written)
}

fn loopback_client() -> clave::fetch::Client {
    clave::fetch::Client::with_builder(true, reqwest::blocking::Client::builder().no_proxy())
}

#[test]
fn an_oversized_streamed_response_is_refused_at_its_bound_not_buffered() {
    let ceiling = 256 << 20;
    let (port, written) = stream_until_refused(ceiling);
    let limit = 64 * 1024;
    let err = loopback_client()
        .get_bytes_bounded(&format!("http://127.0.0.1:{port}/big.json"), &[], limit)
        .unwrap_err();
    assert!(matches!(err, clave::error::Error::Oversized(_)), "{err}");
    assert!(
        err.to_string().contains("exceeds the 65536-byte bound"),
        "{err}"
    );
    let mut total = written.load(Ordering::SeqCst);
    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        let now = written.load(Ordering::SeqCst);
        if now == total {
            break;
        }
        total = now;
    }
    assert!(
        total < 32 << 20,
        "the client kept reading {total} bytes past a 64 KiB bound"
    );
}

#[test]
fn a_declared_length_above_the_bound_is_refused_before_the_body_is_read() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let body_read = Arc::new(AtomicUsize::new(0));
    let counter = body_read.clone();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        read_request(&mut stream);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5000000\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut sent = 0usize;
        while sent < 5_000_000 {
            if stream.write_all(&[b'y'; 4096]).is_err() {
                break;
            }
            sent += 4096;
        }
        counter.store(sent, Ordering::SeqCst);
    });
    let err = loopback_client()
        .get_bytes_bounded(&format!("http://127.0.0.1:{port}/long.json"), &[], 1 << 20)
        .unwrap_err();
    assert!(err.to_string().contains("declares 5000000 bytes"), "{err}");
}

#[test]
fn a_response_inside_the_bound_is_read_whole() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        read_request(&mut stream);
        let body = format!("{{\"n\":\"{}\"}}", "z".repeat(40_000));
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .unwrap();
    });
    let (raw, value) = loopback_client()
        .get_json_bounded(&format!("http://127.0.0.1:{port}/ok.json"), &[], 64 * 1024)
        .unwrap();
    assert_eq!(raw.len(), 40_008);
    assert_eq!(value["n"].as_str().unwrap().len(), 40_000);
}

fn scripted_lookup(answers: Vec<(&'static str, Vec<IpAddr>)>) -> clave::fetch::Lookup {
    let answers = Arc::new(Mutex::new(answers));
    Arc::new(move |host: &str| {
        let mut answers = answers.lock().unwrap();
        let position = answers
            .iter()
            .position(|(name, _)| *name == host)
            .ok_or_else(|| std::io::Error::other(format!("no scripted answer for {host}")))?;
        let (_, ips) = answers.remove(position);
        Ok(ips)
    })
}

#[test]
fn a_name_resolving_to_a_non_public_address_is_never_connected() {
    let lookup = scripted_lookup(vec![(
        "publisher.test",
        vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))],
    )]);
    let client = clave::fetch::Client::with_lookup(false, lookup);
    let err = client
        .get_bytes("https://publisher.test/.well-known/wist/publisher.json")
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("private address is not a fetch destination"),
        "{err}"
    );
}

#[test]
fn a_redirect_into_scope_whose_host_resolves_privately_is_refused() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        read_request(&mut stream);
        stream
            .write_all(b"HTTP/1.1 302 Found\r\nLocation: https://www.publisher.test/x.json\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();
    });
    let lookup = scripted_lookup(vec![
        ("localhost", vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]),
        (
            "www.publisher.test",
            vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))],
        ),
    ]);
    let client = clave::fetch::Client::with_lookup(true, lookup);
    let err = client
        .get_bytes_bounded(
            &format!("http://localhost:{port}/x.json"),
            &["www.publisher.test".to_string()],
            1 << 20,
        )
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("private address is not a fetch destination"),
        "{err}"
    );
}

#[test]
fn a_host_that_rebinds_to_a_private_address_is_refused_on_its_next_fetch() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .unwrap();
        }
    });
    let lookup = scripted_lookup(vec![
        ("localhost", vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]),
        ("localhost", vec![IpAddr::V4(Ipv4Addr::new(10, 9, 8, 7))]),
    ]);
    let client = clave::fetch::Client::with_lookup(true, lookup);
    let url = format!("http://localhost:{port}/x.json");
    assert_eq!(client.get_bytes(&url).unwrap(), b"{}");
    let err = client.get_bytes(&url).unwrap_err().to_string();
    assert!(
        err.contains("private address is not a fetch destination"),
        "{err}"
    );
}

fn spec_path(rel: &str) -> std::path::PathBuf {
    std::env::var("WIST_SPEC_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../spec")
                .canonicalize()
                .expect("sibling spec checkout")
        })
        .join(rel)
}

/// WIST-2 §8 (ADR-0044) through the spec's fetch-bounds vector: every
/// address class the fetcher refuses, the loopback opt-in, resolver
/// answers refused whole, and the octets read of each object under two
/// parameter maps.
#[test]
fn fetch_bounds_vector() {
    let vector: serde_json::Value = serde_json::from_slice(
        &std::fs::read(spec_path("vectors/wist2/fetch-bounds.json")).unwrap(),
    )
    .unwrap();
    for case in vector["destinations"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let ip: IpAddr = case["address"].as_str().unwrap().parse().unwrap();
        let outcome =
            clave::fetch::destination_allowed(ip, case["loopback_opt_in"].as_bool().unwrap());
        assert_eq!(
            outcome.is_ok(),
            case["allowed"].as_bool().unwrap(),
            "{label}: {outcome:?}"
        );
        if let Some(class) = case["class"].as_str() {
            assert!(
                outcome
                    .as_ref()
                    .is_err_and(|e| e.to_string().contains(class)),
                "{label}: {outcome:?}"
            );
        }
    }
    for case in vector["resolutions"].as_array().unwrap() {
        let addresses = case["addresses"].as_array().unwrap();
        let allowed = !addresses.is_empty()
            && addresses.iter().all(|a| {
                clave::fetch::destination_allowed(a.as_str().unwrap().parse().unwrap(), false)
                    .is_ok()
            });
        assert_eq!(
            allowed,
            case["allowed"].as_bool().unwrap(),
            "{}",
            case["label"]
        );
    }
    for case in vector["object_bounds"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let params = &case["parameters"];
        let mut schedule = wist_core::parameters::Schedule::new(0);
        for (index, name) in [
            "url_cap_bytes",
            "extract_cap_bytes",
            "links_cap_bytes",
            "summary_cap_bytes",
        ]
        .into_iter()
        .enumerate()
        {
            schedule.adopt(wist_core::parameters::Amendment {
                parameter: name.into(),
                value: params[name].as_i64().unwrap(),
                epoch_number: 0,
                entry_index: index as u64,
                sealed_at_s: 0,
                effective_at_s: 0,
            });
        }
        let caps = clave::ingest::ObjectCaps::from_schedule(&schedule, 0);
        let bound = match case["object"].as_str().unwrap() {
            "declaration" | "feed" | "page" | "mirrors" => clave::fetch::OBJECT_CAP_BYTES,
            "delta" => caps.of(clave::ingest::Object::Delta),
            "label" => caps.of(clave::ingest::Object::Label),
            "payload" => caps.of(clave::ingest::Object::Payload),
            other => panic!("{label}: unknown object {other}"),
        };
        assert_eq!(bound, case["bound"].as_u64().unwrap(), "{label}");
    }
}
