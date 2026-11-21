use std::{
    fs, io,
    path::{Path, PathBuf},
};

use marketplace_artifacts::invalid;
use time::OffsetDateTime;

use super::{Installer, filesystem, transport};

const BUNDLED_INSTALLER_CONFIG: &str = "/usr/share/rentnerproxy/app-catalog/installer.json";

impl Installer {
    pub(crate) fn appliance_override() -> Option<PathBuf> {
        std::env::var_os("RENTNERPROXY_APP_INSTALLER_CONFIG")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    }

    pub(crate) fn open_appliance(override_path: Option<&Path>) -> io::Result<Self> {
        match override_path {
            Some(path) => Self::open(path),
            None => Self::open_bundled(Path::new(BUNDLED_INSTALLER_CONFIG)),
        }
    }

    pub(super) fn open_bundled(path: &Path) -> io::Result<Self> {
        let config = Self::read_config(path)?;
        filesystem::check_root_path(&config.pinned_root, false)?;
        match fs::symlink_metadata(&config.store_directory) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let parent = config.store_directory.parent().ok_or_else(|| {
                    invalid("The bundled application store requires a parent directory")
                })?;
                filesystem::check_root_path(parent, true)?;
                filesystem::directory(&config.store_directory, 0o711)?;
            }
            Err(error) => return Err(error),
            Ok(_) => {}
        }
        Self::with_config(config)
    }

    pub(crate) fn refresh_on_start(self) -> io::Result<()> {
        // A network wait must not delay the manager's async shutdown or app recovery.
        std::thread::Builder::new()
            .name("app-catalog-refresh".into())
            .spawn(move || {
                let result = transport::Http::new(&self.config.repository_url).and_then(|http| {
                    self.refresh_in_background(
                        |path, limit| http.metadata(path, limit),
                        OffsetDateTime::now_utc(),
                    )
                });
                if let Err(error) = result {
                    eprintln!("Could not refresh the application catalog: {error}");
                }
            })?;
        Ok(())
    }
}
