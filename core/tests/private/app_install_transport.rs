use std::{
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    thread,
};

use marketplace_artifacts::digest;

use super::{Client, DownloadAsset, Duration, Http, Instant, Url};

fn response(header: &'static str, body: &'static [u8]) -> (Http, thread::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut connection = loop {
            match listener.accept() {
                Ok((connection, _)) => break connection,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("Local HTTP fixture did not receive a request: {error}"),
            }
        };
        connection.set_nonblocking(false).unwrap();
        connection
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut reader = BufReader::new(&connection);
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap() != 0 && line != "\r\n" {
            line.clear();
        }
        let _ = write!(
            &mut connection,
            "HTTP/1.1 {header}\r\nConnection: close\r\n\r\n"
        );
        let _ = connection.write_all(body);
    });
    let mut http = Http::new("https://example.com/tuf/").unwrap();
    let local = Client::builder().no_proxy().build().unwrap();
    http.metadata_client = local.clone();
    http.package_client = local;
    http.root = url;
    (http, server)
}

#[test]
fn metadata_limits_headers_and_streamed_bytes() {
    for (head, content, expected) in [
        (
            "200 OK\r\nContent-Length: 2",
            &b"ok"[..],
            Ok(Some(b"ok".to_vec())),
        ),
        ("404 Not Found", b"", Ok(None)),
        ("302 Found", b"", Err(())),
        ("200 OK\r\nContent-Length: 5", b"large", Err(())),
        ("200 OK", b"large", Err(())),
    ] {
        let (http, server) = response(head, content);
        assert_eq!(
            http.metadata("metadata/timestamp.json", 3).map_err(|_| ()),
            expected
        );
        server.join().unwrap();
    }
    let mut http = Http::new("https://example.com/tuf/").unwrap();
    http.deadline = Instant::now();
    assert!(http.metadata("metadata/timestamp.json", 5).is_err());
}

#[test]
fn archive_keeps_only_the_exact_signed_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let destination = temp.path().join("archive");
    let hash = digest(b"yes");
    for (head, content, accepted) in [
        ("200 OK", &b"no!"[..], false),
        ("200 OK", b"longer", false),
        ("200 OK\r\nContent-Length: 6", b"longer", false),
        ("503 Unavailable", b"", false),
        ("200 OK", b"yes", true),
    ] {
        let (http, server) = response(head, content);
        let asset = DownloadAsset {
            url: http.root.to_string(),
            sha256: &hash,
            size_bytes: 3,
        };
        assert_eq!(http.archive(&asset, &destination).is_ok(), accepted);
        assert_eq!(destination.exists(), accepted);
        server.join().unwrap();
    }
    assert_eq!(std::fs::read(destination).unwrap(), b"yes");
}
