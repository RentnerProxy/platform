use std::{
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    thread,
};

use rentnerproxy_artifacts::{FileIdentity, digest};

use crate::app_install::package::write_download;

use super::{
    Client, DownloadAsset, Duration, Http, Instant, Source, Url, release_redirect_allowed,
    unreachable_source,
};

#[test]
fn release_redirects_remain_on_approved_https_origins() {
    for url in [
        "https://github.com/release",
        "https://objects.githubusercontent.com/package",
        "https://release-assets.githubusercontent.com:443/package",
    ] {
        let url = Url::parse(url).unwrap();
        assert!(release_redirect_allowed(&url, 3));
        assert!(!release_redirect_allowed(&url, 4));
    }
    for url in [
        "http://github.com/package",
        "https://github.com:8443/package",
        "https://user@github.com/package",
        "https://:password@github.com/package",
        "https://github.com.example.invalid/package",
    ] {
        assert!(!release_redirect_allowed(&Url::parse(url).unwrap(), 1));
    }
}

fn response(header: &'static str, body: &'static [u8]) -> (Http, thread::JoinHandle<()>) {
    answer(Some(header), body)
}

/// Read one request and close the connection without any HTTP response.
fn unanswered() -> (Http, thread::JoinHandle<()>) {
    answer(None, b"")
}

fn answer(header: Option<&'static str>, body: &'static [u8]) -> (Http, thread::JoinHandle<()>) {
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
        let Some(header) = header else {
            return;
        };
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
    let expected = FileIdentity {
        sha256: digest(b"yes"),
        size_bytes: 3,
    };
    for (head, content, accepted) in [
        ("200 OK", &b"no!"[..], false),
        ("200 OK", b"ye", false),
        ("200 OK", b"longer", false),
        ("200 OK\r\nContent-Length: 6", b"longer", false),
        ("503 Unavailable", b"", false),
        ("200 OK", b"yes", true),
    ] {
        let (http, server) = response(head, content);
        let asset = DownloadAsset {
            url: http.root.to_string(),
            sha256: &expected.sha256,
            size_bytes: expected.size_bytes,
        };
        let result = http
            .archive(&asset)
            .and_then(|body| write_download(body, &destination, &expected));
        assert_eq!(result.is_ok(), accepted);
        assert_eq!(destination.exists(), accepted);
        server.join().unwrap();
    }
    assert_eq!(std::fs::read(destination).unwrap(), b"yes");
}

#[test]
fn outages_name_the_source_that_did_not_answer() {
    let asset = |http: &Http| DownloadAsset {
        url: http.root.to_string(),
        sha256: "",
        size_bytes: 3,
    };
    for (fixture, expected) in [
        (unanswered(), Some(Source::Catalog)),
        (
            response("503 Service Unavailable", b""),
            Some(Source::Catalog),
        ),
        (response("302 Found", b""), None),
    ] {
        let (http, server) = fixture;
        let error = http.metadata("metadata/timestamp.json", 3).unwrap_err();
        assert_eq!(unreachable_source(&error), expected, "{error}");
        server.join().unwrap();
    }
    for (fixture, expected) in [
        (unanswered(), Some(Source::Package)),
        (response("502 Bad Gateway", b""), Some(Source::Package)),
        (response("404 Not Found", b""), None),
    ] {
        let (http, server) = fixture;
        let error = http.archive(&asset(&http)).unwrap_err();
        assert_eq!(unreachable_source(&error), expected, "{error}");
        server.join().unwrap();
    }
    for (fixture, answers) in [
        (
            response("206 Partial Content\r\nContent-Length: 1", b"y"),
            true,
        ),
        (response("404 Not Found", b""), true),
        (response("503 Service Unavailable", b""), false),
        (unanswered(), false),
    ] {
        let (http, server) = fixture;
        assert_eq!(http.package_source_answers(&asset(&http)), answers);
        server.join().unwrap();
    }
}
