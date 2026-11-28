use std::{
    error::Error,
    fmt,
    io::{self, Read},
    time::{Duration, Instant},
};

use rentnerproxy_app_contracts::DownloadAsset;
use rentnerproxy_artifacts::invalid;
use reqwest::{
    StatusCode, Url,
    blocking::{Client, Response},
    header::RANGE,
    redirect::Policy,
};

#[cfg(test)]
#[path = "../../tests/private/app_install_transport.rs"]
mod tests;

/// A remote source the installer could not reach.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Source {
    /// The signed catalog metadata.
    Catalog,
    /// The release assets of approved packages.
    Package,
    /// Neither the catalog nor the package source.
    Network,
}

/// No response arrived from a source, or it answered with a server error.
#[derive(Debug)]
pub(crate) struct SourceUnavailable {
    unreachable: Source,
    detail: String,
}

impl SourceUnavailable {
    pub(crate) fn error(unreachable: Source, detail: impl fmt::Display) -> io::Error {
        io::Error::new(
            io::ErrorKind::NotConnected,
            Self {
                unreachable,
                detail: detail.to_string(),
            },
        )
    }
}

impl fmt::Display for SourceUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let source = match self.unreachable {
            Source::Catalog => "Catalog source",
            Source::Package => "Package source",
            Source::Network => "Catalog and package sources",
        };
        write!(formatter, "{source} unreachable: {}", self.detail)
    }
}

impl Error for SourceUnavailable {}

/// The source an installer error could not reach, if that caused it.
pub(crate) fn unreachable_source(error: &io::Error) -> Option<Source> {
    error
        .get_ref()?
        .downcast_ref::<SourceUnavailable>()
        .map(|cause| cause.unreachable)
}

pub(super) fn repository_url(value: &str) -> io::Result<Url> {
    let url = Url::parse(value).map_err(|_| invalid("Invalid app catalog URL"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.path().ends_with('/')
    {
        return Err(invalid("Expected an HTTPS catalog directory URL"));
    }
    Ok(url)
}

pub(super) struct Http {
    root: Url,
    metadata_client: Client,
    package_client: Client,
    deadline: Instant,
}

impl Http {
    pub(super) fn new(root: &str) -> io::Result<Self> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let builder = || {
            Client::builder()
                .https_only(true)
                .connect_timeout(Duration::from_secs(8))
                .user_agent("RentnerProxy-app-installer")
        };
        let metadata_client = builder()
            .redirect(Policy::none())
            .build()
            .map_err(network)?;
        let package_client = builder()
            .redirect(Policy::custom(|attempt| {
                if release_redirect_allowed(attempt.url(), attempt.previous().len()) {
                    attempt.follow()
                } else {
                    attempt.error("Unexpected release redirect")
                }
            }))
            .build()
            .map_err(network)?;
        Ok(Self {
            root: repository_url(root)?,
            metadata_client,
            package_client,
            deadline: Instant::now() + Duration::from_secs(120),
        })
    }

    pub(super) fn metadata(&self, path: &str, limit: usize) -> io::Result<Option<Vec<u8>>> {
        let url = self
            .root
            .join(path)
            .map_err(|_| invalid("Invalid signed metadata path"))?;
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "Catalog refresh timed out"))?;
        let response = self
            .metadata_client
            .get(url)
            .timeout(remaining.min(Duration::from_secs(20)))
            .send()
            .map_err(|error| unreachable(Source::Catalog, error))?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if response.status().is_server_error() {
            return Err(SourceUnavailable::error(Source::Catalog, response.status()));
        }
        if response.status() != StatusCode::OK
            || response
                .content_length()
                .is_some_and(|size| size > limit as u64)
        {
            return Err(invalid("Catalog server returned an invalid response"));
        }
        let mut bytes = Vec::new();
        response.take(limit as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > limit {
            return Err(invalid("Catalog file exceeds its byte limit"));
        }
        Ok(Some(bytes))
    }

    pub(super) fn archive(&self, asset: &DownloadAsset<'_>) -> io::Result<Response> {
        let response = self
            .package_client
            .get(&asset.url)
            .timeout(Duration::from_secs(180))
            .send()
            .map_err(|error| unreachable(Source::Package, error))?;
        if response.status().is_server_error() {
            return Err(SourceUnavailable::error(Source::Package, response.status()));
        }
        if response.status() != StatusCode::OK
            || response
                .content_length()
                .is_some_and(|n| n != asset.size_bytes)
        {
            return Err(invalid("Package server returned an invalid response"));
        }
        Ok(response)
    }

    /// Whether the package source answers a request for `asset`. Only the response head is
    /// read, so a reachable source transfers at most the requested first byte.
    pub(super) fn package_source_answers(&self, asset: &DownloadAsset<'_>) -> bool {
        self.package_client
            .get(&asset.url)
            .header(RANGE, "bytes=0-0")
            .timeout(Duration::from_secs(20))
            .send()
            .is_ok_and(|response| !response.status().is_server_error())
    }
}

fn release_redirect_allowed(url: &Url, previous_requests: usize) -> bool {
    previous_requests <= 3
        && url.scheme() == "https"
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
        && matches!(
            url.host_str(),
            Some(
                "github.com"
                    | "objects.githubusercontent.com"
                    | "release-assets.githubusercontent.com"
            )
        )
}

fn network(error: reqwest::Error) -> io::Error {
    io::Error::other(error.without_url())
}

/// A request that got no response did not reach `source`. A refused redirect or an invalid
/// request is a local decision, not an outage.
fn unreachable(source: Source, error: reqwest::Error) -> io::Error {
    if error.is_redirect() || error.is_builder() {
        return network(error);
    }
    SourceUnavailable::error(source, error.without_url())
}
