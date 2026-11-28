use super::{
    bad,
    journal::{Grant, private_directory},
};
use crate::app_ipc::filesystem::{connect_peer, require_safe_parents};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs, io,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::Path,
    process::ExitCode,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::timeout,
};

const SOCKET: &str = "/run/rentnerproxy/app-manager/control.sock";
const LIMIT: usize = 96 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum InactiveRelease {
    Candidate,
    Previous,
}

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "action",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(super) enum Command {
    Status,
    Stage {
        installation_id: String,
        app_id: String,
        version: String,
    },
    Activate {
        installation_id: String,
        #[serde(default)]
        grants: Vec<Grant>,
    },
    Start {
        installation_id: String,
    },
    Stop {
        installation_id: String,
    },
    Rollback {
        installation_id: String,
    },
    Discard {
        installation_id: String,
        release: InactiveRelease,
    },
    Remove {
        installation_id: String,
    },
    Purge {
        installation_id: String,
    },
}
impl Command {
    pub fn id(&self) -> Option<&str> {
        match self {
            Self::Status => None,
            Self::Stage {
                installation_id, ..
            }
            | Self::Activate {
                installation_id, ..
            }
            | Self::Discard {
                installation_id, ..
            }
            | Self::Start { installation_id }
            | Self::Stop { installation_id }
            | Self::Remove { installation_id }
            | Self::Purge { installation_id }
            | Self::Rollback { installation_id } => Some(installation_id),
        }
    }
}

pub(super) fn bind() -> io::Result<UnixListener> {
    let path = Path::new(SOCKET);
    private_directory(path.parent().expect("socket directory"))?;
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() && m.uid() == 0 => fs::remove_file(path)?,
        Ok(_) => return Err(bad("Unexpected manager socket file")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

pub(super) async fn read(stream: &mut UnixStream) -> io::Result<Command> {
    if stream.peer_cred()?.uid() != 0 {
        return Err(bad("Manager control requires root"));
    }
    let mut frame = Vec::new();
    timeout(
        Duration::from_secs(2),
        stream.take(LIMIT as u64 + 1).read_to_end(&mut frame),
    )
    .await??;
    if frame.len() > LIMIT {
        return Err(bad("Manager command is too large"));
    }
    Ok(serde_json::from_slice(&frame)?)
}

fn command(args: Vec<String>) -> io::Result<Command> {
    let fields: Vec<_> = args.iter().map(String::as_str).collect();
    Ok(match fields.as_slice() {
        ["status"] => Command::Status,
        ["stage", id, app, version] => Command::Stage {
            installation_id: id.to_string(),
            app_id: app.to_string(),
            version: version.to_string(),
        },
        ["activate", id] => Command::Activate {
            installation_id: id.to_string(),
            grants: vec![],
        },
        ["activate", id, grants] => {
            let path = Path::new(grants);
            require_safe_parents(path, 0)?;
            let meta = fs::symlink_metadata(path)?;
            if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
                return Err(bad("Expected a root-managed grants file"));
            }
            let bytes = rentnerproxy_artifacts::read_file(path, LIMIT as u64)?;
            Command::Activate {
                installation_id: id.to_string(),
                grants: serde_json::from_slice(&bytes)?,
            }
        }
        ["start", id] => Command::Start {
            installation_id: id.to_string(),
        },
        ["stop", id] => Command::Stop {
            installation_id: id.to_string(),
        },
        ["rollback", id] => Command::Rollback {
            installation_id: id.to_string(),
        },
        ["discard", id, role] => Command::Discard {
            installation_id: id.to_string(),
            release: match *role {
                "candidate" => InactiveRelease::Candidate,
                "previous" => InactiveRelease::Previous,
                _ => return Err(bad("Discard requires previous or candidate")),
            },
        },
        ["remove", id] => Command::Remove {
            installation_id: id.to_string(),
        },
        ["purge", id] => Command::Purge {
            installation_id: id.to_string(),
        },
        _ => {
            return Err(bad(
                "Expected status, stage ID APP VERSION, activate ID [GRANTS_FILE], start ID, stop ID, rollback ID, discard ID previous|candidate, remove ID, or purge ID",
            ));
        }
    })
}

pub async fn run_app_control(arguments: impl Iterator<Item = String>) -> ExitCode {
    async fn invoke(request: Command) -> io::Result<()> {
        let mut stream = connect_peer(Path::new(SOCKET), 0).await?;
        stream.write_all(&serde_json::to_vec(&request)?).await?;
        stream.shutdown().await?;
        let mut bytes = Vec::new();
        stream
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .await?;
        let reply: Value = serde_json::from_slice(&bytes)?;
        if reply["ok"] != true {
            return Err(io::Error::other(
                reply["error"]
                    .as_str()
                    .unwrap_or("Manager command failed")
                    .to_owned(),
            ));
        }
        println!("{}", reply["result"]);
        Ok(())
    }
    let result = async { invoke(command(arguments.collect())?).await }.await;
    super::exit(result)
}
