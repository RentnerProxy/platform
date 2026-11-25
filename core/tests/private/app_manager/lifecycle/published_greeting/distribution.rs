//! Loopback stand-ins for the public app distribution.
//!
//! As in production, signed catalog metadata and release archives come from separate hosts:
//! `raw.githubusercontent.com` serves the TUF repository and `github.com` the release assets.
//! A third address stands in for Marketplace and GitHub API endpoints. It never answers and
//! counts every connection attempt. The fixture container has no other network and maps
//! these names to loopback addresses with `--add-host`.

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, BufRead, BufReader, Read, Write},
    net::{IpAddr, Ipv4Addr, TcpListener, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
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
    pub status: u16,
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
            status: 0,
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

struct Shared {
    metadata: Mutex<Files>,
    archives: BTreeMap<String, PathBuf>,
    archive_response: Mutex<ArchiveResponse>,
    log: Mutex<Vec<Served>>,
    marketplace_attempts: AtomicUsize,
}

/// A loopback listener. Dropping it closes the port, so new connections are refused.
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
            while !stopping.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((socket, _)) if !stopping.load(Ordering::Acquire) => handle(socket),
                    Ok(_) => break,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
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
    tls: Arc<rustls::ServerConfig>,
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
            log: Mutex::default(),
            marketplace_attempts: AtomicUsize::new(0),
        });
        let attempts = Arc::clone(&shared);
        let marketplace = Host::start(MARKETPLACE_ADDRESS, move |socket| {
            attempts.marketplace_attempts.fetch_add(1, Ordering::SeqCst);
            drop(socket);
        });
        let mut distribution = Self {
            shared,
            tls,
            metadata: None,
            releases: None,
            _marketplace: marketplace,
        };
        distribution.set_metadata_reachable(true);
        distribution.set_releases_reachable(true);
        distribution
    }

    fn https(&self, address: Ipv4Addr, host: &'static str) -> Host {
        let shared = Arc::clone(&self.shared);
        let tls = Arc::clone(&self.tls);
        Host::start(address, move |socket| {
            if let Err(error) = serve(socket, Arc::clone(&tls), host, &shared) {
                eprintln!("{host} fixture request failed: {error}");
            }
        })
    }

    /// Replace the TUF repository files served from the next request on.
    pub(super) fn serve_metadata(&self, files: Files) {
        *self.shared.metadata.lock().unwrap() = files;
    }

    pub(super) fn set_metadata_reachable(&mut self, reachable: bool) {
        if reachable != self.metadata.is_some() {
            self.metadata = None;
            if reachable {
                self.metadata = Some(self.https(METADATA_ADDRESS, METADATA_HOST));
            }
        }
    }

    pub(super) fn set_releases_reachable(&mut self, reachable: bool) {
        if reachable != self.releases.is_some() {
            self.releases = None;
            if reachable {
                self.releases = Some(self.https(RELEASE_ADDRESS, RELEASE_HOST));
            }
        }
    }

    /// Close the metadata and release hosts. The Marketplace stand-in keeps counting.
    pub(super) fn stop(&mut self) {
        self.set_metadata_reachable(false);
        self.set_releases_reachable(false);
    }

    pub(super) fn set_archive_response(&self, mode: ArchiveResponse) {
        *self.shared.archive_response.lock().unwrap() = mode;
    }

    /// Every request served so far. A response in flight completes before this returns.
    pub(super) fn requests(&self) -> Vec<Served> {
        self.shared.log.lock().unwrap().clone()
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

    pub(super) fn marketplace_attempts(&self) -> usize {
        self.shared.marketplace_attempts.load(Ordering::SeqCst)
    }
}

fn release_path(url: &str) -> String {
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

enum Body {
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
    let mut served = Served::parse(host, &read_head(&mut stream)?)?;
    let body = if served.method != "GET" {
        None
    } else if host == METADATA_HOST {
        served
            .path
            .strip_prefix(REPOSITORY_PATH)
            .and_then(|name| shared.metadata.lock().unwrap().get(name).cloned())
            .map(Body::Metadata)
    } else {
        shared
            .archives
            .get(&served.path)
            .cloned()
            .map(Body::Archive)
    };
    // Hold the log through the TLS flush, so a test that observes the client's outcome
    // also observes this request and the exact number of payload bytes it received.
    let mut log = shared.log.lock().unwrap();
    let mode = *shared.archive_response.lock().unwrap();
    let result = respond(&mut stream, body, mode, &mut served);
    log.push(served);
    result
}

fn respond(
    stream: &mut rustls::StreamOwned<rustls::ServerConnection, TcpStream>,
    body: Option<Body>,
    mode: ArchiveResponse,
    served: &mut Served,
) -> io::Result<()> {
    let Some(body) = body else {
        served.status = 404;
        stream.write_all(
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )?;
        stream.conn.send_close_notify();
        return stream.flush();
    };
    let length = match &body {
        Body::Metadata(bytes) => bytes.len() as u64,
        Body::Archive(path) => fs::metadata(path)?.len(),
    };
    served.status = 200;
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Length: {length}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n"
    )?;
    served.bytes = match body {
        Body::Metadata(bytes) => {
            stream.write_all(&bytes)?;
            length
        }
        // Archive responses are copied from disk to TLS in bounded chunks by io::copy.
        Body::Archive(path) => mode.write(File::open(path)?, length, stream)?,
    };
    stream.conn.send_close_notify();
    stream.flush()
}
