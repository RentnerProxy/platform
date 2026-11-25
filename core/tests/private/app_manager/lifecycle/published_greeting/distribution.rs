//! Loopback stand-ins for the public app distribution.
//!
//! As in production, signed catalog metadata and release archives come from separate hosts:
//! `raw.githubusercontent.com` serves the TUF repository and `github.com` the release assets.
//! Either host can become unavailable: it then records each request and closes the
//! connection without an HTTP response. A third address stands in for Marketplace and
//! GitHub API endpoints. It never answers and counts every connection attempt. The fixture
//! container has no other network and maps these names to loopback addresses with
//! `--add-host`.

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, BufRead, BufReader, Read, Write},
    net::{IpAddr, Ipv4Addr, TcpListener, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use serde::Serialize;

use crate::app_install::tests::published_greeting::PublishedSnapshot;

pub(super) type Files = BTreeMap<String, Vec<u8>>;

pub(super) const METADATA_HOST: &str = "raw.githubusercontent.com";
pub(super) const RELEASE_HOST: &str = "github.com";
/// The repository URL of the bundled production installer configuration.
pub(super) const REPOSITORY_URL: &str =
    "https://raw.githubusercontent.com/RentnerProxy/app-catalog/main/";
const REPOSITORY_PATH: &str = "/RentnerProxy/app-catalog/main/";
pub(super) const MARKETPLACE_HOSTS: [&str; 2] = ["market.rentner.dev", "api.github.com"];
const METADATA_ADDRESS: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
const RELEASE_ADDRESS: Ipv4Addr = Ipv4Addr::LOCALHOST;
const MARKETPLACE_ADDRESS: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);
const CREDENTIAL_HEADERS: [&str; 3] = ["authorization", "proxy-authorization", "cookie"];

/// Fail fast when the container does not map the public names to the loopback stand-ins.
pub(super) fn require_loopback_hosts() {
    let expected = [
        (METADATA_HOST, METADATA_ADDRESS),
        (RELEASE_HOST, RELEASE_ADDRESS),
    ]
    .into_iter()
    .chain(MARKETPLACE_HOSTS.map(|host| (host, MARKETPLACE_ADDRESS)));
    for (host, address) in expected {
        let resolved: Vec<_> = (host, 443)
            .to_socket_addrs()
            .unwrap_or_else(|error| panic!("{host} does not resolve: {error}"))
            .map(|socket| socket.ip())
            .collect();
        assert!(
            !resolved.is_empty() && resolved.iter().all(|ip| *ip == IpAddr::V4(address)),
            "{host} must resolve only to {address}: {resolved:?}"
        );
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) enum ArchiveResponse {
    #[default]
    Authentic,
    Interrupted,
    SameLengthCorruption,
}

impl ArchiveResponse {
    fn write(self, mut archive: File, length: u64, stream: &mut impl Write) -> io::Result<u64> {
        match self {
            Self::Authentic => io::copy(&mut archive, stream),
            // Advertise the signed length but close the response halfway through the body.
            Self::Interrupted => io::copy(&mut archive.take(length / 2), stream),
            // Keep Content-Length and the on-disk fixture intact. Change a single byte in transit.
            Self::SameLengthCorruption => {
                let mut byte = [0];
                archive.read_exact(&mut byte)?;
                byte[0] ^= 1;
                stream.write_all(&byte)?;
                Ok(1 + io::copy(&mut archive, stream)?)
            }
        }
    }
}

/// One HTTP request received by a stand-in host.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Served {
    pub host: &'static str,
    pub host_header: Option<String>,
    pub method: String,
    pub path: String,
    pub query: bool,
    pub credential_headers: Vec<String>,
    /// `None` when an unavailable host closed the connection without an HTTP response.
    pub status: Option<u16>,
    pub bytes: u64,
}

impl Served {
    fn parse(host: &'static str, head: &[String]) -> io::Result<Self> {
        let malformed = || io::Error::other("Malformed fixture HTTP request");
        let (request_line, fields) = head.split_first().ok_or_else(malformed)?;
        let mut parts = request_line.split_ascii_whitespace();
        let (Some(method), Some(target), Some(_), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(malformed());
        };
        let (path, query) = target
            .split_once('?')
            .map_or((target, false), |(path, _)| (path, true));
        if !path.starts_with('/') {
            return Err(malformed());
        }
        let mut host_header = None;
        let mut credential_headers = Vec::new();
        for field in fields {
            let (name, value) = field.split_once(':').ok_or_else(malformed)?;
            let name = name.trim().to_ascii_lowercase();
            if name == "host" {
                host_header = Some(value.trim().to_owned());
            }
            if CREDENTIAL_HEADERS.contains(&name.as_str())
                || ["token", "ticket", "api-key"]
                    .iter()
                    .any(|marker| name.contains(marker))
            {
                credential_headers.push(name);
            }
        }
        Ok(Self {
            host,
            host_header,
            method: method.to_owned(),
            path: path.to_owned(),
            query,
            credential_headers,
            status: None,
            bytes: 0,
        })
    }

    /// A GET for public content, named for this host, without credentials or a query.
    pub(super) fn anonymous(&self) -> bool {
        self.method == "GET"
            && !self.query
            && self.credential_headers.is_empty()
            && self.host_header.as_deref() == Some(self.host)
    }
}

#[derive(Default)]
struct LogState {
    served: Vec<Served>,
    in_flight: usize,
}

/// Requests in arrival order. A request is recorded before its response starts and
/// completed after the response ends. No lock is held while a response is written, so one
/// host never waits for another host's client.
#[derive(Default)]
struct RequestLog {
    state: Mutex<LogState>,
    settled: Condvar,
}

impl RequestLog {
    fn begin(&self, served: Served) -> usize {
        let mut state = self.state.lock().unwrap();
        state.served.push(served);
        state.in_flight += 1;
        state.served.len() - 1
    }

    fn complete(&self, index: usize, status: Option<u16>, bytes: u64) {
        let mut state = self.state.lock().unwrap();
        state.served[index].status = status;
        state.served[index].bytes = bytes;
        state.in_flight -= 1;
        self.settled.notify_all();
    }

    /// Every recorded request, after each response in flight has ended.
    fn settled(&self) -> Vec<Served> {
        self.settled
            .wait_while(self.state.lock().unwrap(), |state| state.in_flight > 0)
            .unwrap()
            .served
            .clone()
    }
}

struct Shared {
    metadata: Mutex<Files>,
    archives: BTreeMap<String, PathBuf>,
    archive_response: Mutex<ArchiveResponse>,
    metadata_available: AtomicBool,
    releases_available: AtomicBool,
    log: RequestLog,
    marketplace_attempts: AtomicUsize,
}

/// A loopback listener. Dropping it handles the connections already queued, then closes
/// the port, so later connections are refused.
struct Host {
    stop: Arc<AtomicBool>,
    task: Option<thread::JoinHandle<()>>,
}

impl Host {
    fn start(address: Ipv4Addr, handle: impl Fn(TcpStream) + Send + 'static) -> Self {
        let listener = TcpListener::bind((address, 443)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let task = thread::spawn(move || {
            loop {
                // Read the flag before accepting, so a stop still drains the queue.
                let stopped = stopping.load(Ordering::Acquire);
                match listener.accept() {
                    Ok((socket, _)) => handle(socket),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if stopped {
                            break;
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("Distribution fixture listener failed: {error}"),
                }
            }
        });
        Self {
            stop,
            task: Some(task),
        }
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(task) = self.task.take()
            && task.join().is_err()
            && !thread::panicking()
        {
            panic!("Distribution fixture listener panicked");
        }
    }
}

pub(super) struct Distribution {
    shared: Arc<Shared>,
    metadata: Option<Host>,
    releases: Option<Host>,
    _marketplace: Host,
}

impl Distribution {
    /// Serve `metadata` and the release archives of `releases` until told otherwise.
    pub(super) fn start(root: &Path, metadata: Files, releases: &[PublishedSnapshot]) -> Self {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let certificate =
            rcgen::generate_simple_self_signed(vec![METADATA_HOST.into(), RELEASE_HOST.into()])
                .unwrap();
        fs::write(root.join("catalog-ca.pem"), certificate.cert.pem()).unwrap();
        let tls = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![certificate.cert.der().clone()],
                    rustls::pki_types::PrivatePkcs8KeyDer::from(
                        certificate.signing_key.serialize_der(),
                    )
                    .into(),
                )
                .unwrap(),
        );
        let shared = Arc::new(Shared {
            metadata: Mutex::new(metadata),
            archives: releases
                .iter()
                .map(|release| {
                    (
                        release_path(&release.archive_url),
                        release.archive_path.clone(),
                    )
                })
                .collect(),
            archive_response: Mutex::default(),
            metadata_available: AtomicBool::new(true),
            releases_available: AtomicBool::new(true),
            log: RequestLog::default(),
            marketplace_attempts: AtomicUsize::new(0),
        });
        let https = |address: Ipv4Addr, host: &'static str| {
            let shared = Arc::clone(&shared);
            let tls = Arc::clone(&tls);
            Host::start(address, move |socket| {
                if let Err(error) = serve(socket, Arc::clone(&tls), host, &shared) {
                    eprintln!("{host} fixture request failed: {error}");
                }
            })
        };
        let metadata = https(METADATA_ADDRESS, METADATA_HOST);
        let releases = https(RELEASE_ADDRESS, RELEASE_HOST);
        let attempts = Arc::clone(&shared);
        let marketplace = Host::start(MARKETPLACE_ADDRESS, move |socket| {
            attempts.marketplace_attempts.fetch_add(1, Ordering::SeqCst);
            drop(socket);
        });
        Self {
            shared,
            metadata: Some(metadata),
            releases: Some(releases),
            _marketplace: marketplace,
        }
    }

    /// Replace the TUF repository files served from the next request on.
    pub(super) fn serve_metadata(&self, files: Files) {
        *self.shared.metadata.lock().unwrap() = files;
    }

    /// An unavailable host records each request and closes the connection unanswered.
    pub(super) fn set_metadata_available(&self, available: bool) {
        self.shared
            .metadata_available
            .store(available, Ordering::SeqCst);
    }

    /// An unavailable host records each request and closes the connection unanswered.
    pub(super) fn set_releases_available(&self, available: bool) {
        self.shared
            .releases_available
            .store(available, Ordering::SeqCst);
    }

    /// Close the metadata and release hosts. The Marketplace stand-in keeps counting.
    pub(super) fn stop(&mut self) {
        self.metadata = None;
        self.releases = None;
    }

    /// Close every host and return the final number of Marketplace connection attempts,
    /// including connections that were still queued at the listener.
    pub(super) fn finish(self) -> usize {
        let shared = Arc::clone(&self.shared);
        drop(self);
        shared.marketplace_attempts.load(Ordering::SeqCst)
    }

    pub(super) fn set_archive_response(&self, mode: ArchiveResponse) {
        *self.shared.archive_response.lock().unwrap() = mode;
    }

    /// Every request recorded so far. A response in flight completes before this returns.
    pub(super) fn requests(&self) -> Vec<Served> {
        self.shared.log.settled()
    }

    pub(super) fn requests_since(&self, since: usize) -> Vec<Served> {
        self.requests()[since..].to_vec()
    }

    /// Payload bytes of each response for the release asset `url` after `since` requests.
    pub(super) fn deliveries(&self, since: usize, url: &str) -> Vec<u64> {
        let path = release_path(url);
        self.requests_since(since)
            .into_iter()
            .filter(|request| request.host == RELEASE_HOST && request.path == path)
            .map(|request| request.bytes)
            .collect()
    }
}

/// The request path of an official release asset URL.
pub(super) fn release_path(url: &str) -> String {
    url.strip_prefix("https://github.com")
        .expect("official release URL host")
        .to_owned()
}

fn read_head(stream: &mut impl Read) -> io::Result<Vec<String>> {
    let mut reader = BufReader::new(stream.by_ref().take(16_384));
    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Err(io::Error::other("Truncated fixture HTTP request"));
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            return Ok(lines);
        }
        lines.push(line.to_owned());
    }
}

enum Reply {
    /// An unavailable host closes the connection without an HTTP response.
    Unanswered,
    NotFound,
    Metadata(Vec<u8>),
    Archive(PathBuf),
}

fn serve(
    socket: TcpStream,
    tls: Arc<rustls::ServerConfig>,
    host: &'static str,
    shared: &Shared,
) -> io::Result<()> {
    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(Duration::from_secs(15)))?;
    socket.set_write_timeout(Some(Duration::from_secs(180)))?;
    let connection = rustls::ServerConnection::new(tls).map_err(io::Error::other)?;
    let mut stream = rustls::StreamOwned::new(connection, socket);
    let served = Served::parse(host, &read_head(&mut stream)?)?;
    let available = if host == METADATA_HOST {
        &shared.metadata_available
    } else {
        &shared.releases_available
    };
    let reply = if !available.load(Ordering::SeqCst) {
        Reply::Unanswered
    } else if served.method != "GET" {
        Reply::NotFound
    } else if host == METADATA_HOST {
        served
            .path
            .strip_prefix(REPOSITORY_PATH)
            .and_then(|name| shared.metadata.lock().unwrap().get(name).cloned())
            .map_or(Reply::NotFound, Reply::Metadata)
    } else {
        shared
            .archives
            .get(&served.path)
            .cloned()
            .map_or(Reply::NotFound, Reply::Archive)
    };
    // Record the request before answering and its outcome after the TLS flush, so a test
    // that observes the client's outcome also observes the exact payload bytes it received.
    let index = shared.log.begin(served);
    let mode = *shared.archive_response.lock().unwrap();
    let (mut status, mut bytes) = (None, 0);
    let result = respond(&mut stream, reply, mode, &mut status, &mut bytes);
    shared.log.complete(index, status, bytes);
    result
}

fn respond(
    stream: &mut rustls::StreamOwned<rustls::ServerConnection, TcpStream>,
    reply: Reply,
    mode: ArchiveResponse,
    status: &mut Option<u16>,
    bytes: &mut u64,
) -> io::Result<()> {
    fn ok(stream: &mut impl Write, length: u64) -> io::Result<()> {
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {length}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n"
        )
    }
    match reply {
        Reply::Unanswered => {}
        Reply::NotFound => {
            *status = Some(404);
            stream.write_all(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )?;
        }
        Reply::Metadata(body) => {
            *status = Some(200);
            ok(stream, body.len() as u64)?;
            stream.write_all(&body)?;
            *bytes = body.len() as u64;
        }
        // Archive responses are copied from disk to TLS in bounded chunks by io::copy.
        Reply::Archive(path) => {
            let length = fs::metadata(&path)?.len();
            *status = Some(200);
            ok(stream, length)?;
            *bytes = mode.write(File::open(path)?, length, stream)?;
        }
    }
    stream.conn.send_close_notify();
    stream.flush()
}
