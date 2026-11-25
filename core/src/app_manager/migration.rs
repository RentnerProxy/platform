//! Run an app's declared SQL data migrations as the app, in one transaction.
//!
//! The app's own OS identity runs `psql` under the app sandbox, so client meta-commands cannot
//! reach beyond what the app process itself may do. The session logs in as the runtime role and
//! assumes the schema owner only while the platform grants it. The completed version is stored
//! as the comment on the `app` schema in the same transaction, so a crash between the commit and
//! the journal update cannot rerun or skip a step. Portable backups carry that comment with the
//! data it describes.

use std::{
    fs, io,
    os::unix::process::CommandExt as _,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use tokio::{
    process::Command,
    time::{Instant, sleep, timeout},
};

use super::{bad, journal::Migration, runtime};
use crate::{
    app_ipc::{existing_database_password, has_exited, restrict_child},
    appliance_process::verify_uid_stopped,
};

#[cfg(test)]
#[path = "../../tests/private/app_manager/migration.rs"]
mod tests;

const PSQL: &str = "/usr/lib/postgresql/18/bin/psql";
const APP_SOCKET: &str = "/run/rentnerproxy/app-db";
const MARKER: &str = "rentnerproxy.data-version=";
const MIGRATION_TIMEOUT: Duration = Duration::from_secs(600);
const PROCESS_LIMIT: libc::rlim_t = 16;
const RELEASE_TIMEOUT: Duration = Duration::from_secs(5);

struct Roles {
    uid: u32,
    runtime: String,
    owner: String,
}

impl Roles {
    fn new(uid: u32) -> io::Result<Self> {
        if !(20_000..=59_999).contains(&uid) {
            return Err(bad("Invalid database identity"));
        }
        Ok(Self {
            uid,
            runtime: format!("rp_app_{uid}"),
            owner: format!("rp_migrate_{uid}"),
        })
    }
}

/// Read the schema version the last completed migration recorded, if any.
pub(super) async fn recorded_version(uid: u32) -> io::Result<Option<u32>> {
    let roles = Roles::new(uid)?;
    let exists = runtime::control_sql(&format!(
        "SELECT EXISTS (SELECT FROM pg_catalog.pg_database WHERE datname = '{}');\n",
        roles.runtime
    ))
    .await?;
    match exists.as_slice() {
        b"f\n" => return Ok(None),
        b"t\n" => (),
        _ => return Err(bad("Unexpected app database lookup response")),
    }
    let comment = runtime::control_sql_in(
        &roles.runtime,
        "SELECT d.description FROM pg_catalog.pg_namespace n \
         JOIN pg_catalog.pg_description d ON d.classoid = 'pg_catalog.pg_namespace'::pg_catalog.regclass \
         AND d.objoid = n.oid AND d.objsubid = 0 WHERE n.nspname = 'app';\n",
    )
    .await?;
    Ok(parse_marker(&comment))
}

/// Accept only the exact comment a migration writes. Anything else records no version.
fn parse_marker(output: &[u8]) -> Option<u32> {
    let digits = std::str::from_utf8(output)
        .ok()?
        .strip_suffix('\n')?
        .strip_prefix(MARKER)?;
    if digits.is_empty()
        || digits.len() > 10
        || (digits.len() > 1 && digits.starts_with('0'))
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    digits.parse::<u32>().ok().filter(|v| *v <= i32::MAX as u32)
}

/// Apply `migration` to the fenced installation. The caller holds its writer lock, so no other
/// process of the app identity runs and nothing else changes the recorded version.
pub(super) async fn apply(uid: u32, package: &Path, migration: &Migration) -> io::Result<()> {
    apply_within(uid, package, migration, MIGRATION_TIMEOUT).await
}

async fn apply_within(
    uid: u32,
    package: &Path,
    migration: &Migration,
    limit: Duration,
) -> io::Result<()> {
    let roles = Roles::new(uid)?;
    let steps = migration
        .steps
        .iter()
        .map(|step| package_file(package, step))
        .collect::<io::Result<Vec<_>>>()?;
    runtime::control_sql(&format!(
        "GRANT {} TO {} WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;\n",
        roles.owner, roles.runtime
    ))
    .await?;
    let applied = run(&roles, &steps, migration.to, limit).await;
    let released = release(&roles).await;
    applied?;
    released?;
    if recorded_version(uid).await? != Some(migration.to) {
        return Err(bad("App data migration did not record its version"));
    }
    Ok(())
}

/// Resolve a declared step inside the verified, manager-owned package tree.
fn package_file(package: &Path, step: &str) -> io::Result<PathBuf> {
    let path = package.join(step);
    if fs::symlink_metadata(&path)?.is_file() {
        Ok(path)
    } else {
        Err(bad("Invalid app data migration step"))
    }
}

async fn run(roles: &Roles, steps: &[PathBuf], target: u32, limit: Duration) -> io::Result<()> {
    let password = existing_database_password(roles.uid)?;
    let mut command = Command::new(PSQL);
    command
        .args([
            "--no-psqlrc",
            "--no-password",
            "--quiet",
            "--single-transaction",
            "--set=ON_ERROR_STOP=1",
        ])
        .arg(format!("--host={APP_SOCKET}"))
        .arg(format!("--username={}", roles.runtime))
        .arg(format!("--dbname={}", roles.runtime))
        .arg("--command")
        .arg(format!(
            "SET ROLE {}; SET statement_timeout = 0;",
            roles.owner
        ));
    for step in steps {
        command.arg("--file").arg(step);
    }
    command
        .arg("--command")
        .arg(format!("COMMENT ON SCHEMA app IS '{MARKER}{target}';"))
        .current_dir("/")
        .env_clear()
        .env("LC_ALL", "C")
        .env("PGAPPNAME", "rentnerproxy-migration")
        .env("PGCONNECT_TIMEOUT", "5")
        .env("PGPASSWORD", password.as_str())
        .env("PGREQUIREAUTH", "scram-sha-256")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .process_group(0);
    drop(password);
    let (uid, parent) = (roles.uid, std::process::id());
    // SAFETY: Only async-signal-safe direct syscalls run between fork and exec.
    unsafe {
        command
            .as_std_mut()
            .pre_exec(move || restrict_child(uid, uid, parent, PROCESS_LIMIT));
    }
    let mut child = command.spawn()?;
    let pid = child
        .id()
        .ok_or_else(|| bad("App data migration has no process ID"))?;
    let group = i32::try_from(pid).map_err(io::Error::other)?;
    let deadline = Instant::now() + limit;
    let finished = async {
        loop {
            if has_exited(pid)? {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok::<_, io::Error>(false);
            }
            sleep(Duration::from_millis(50)).await;
        }
    }
    .await;
    // The unreaped PID still names the group. The sandbox denies setsid and setpgid, so shell
    // escapes cannot leave it.
    // SAFETY: kill takes no pointers; the group belongs to this unreaped child.
    if unsafe { libc::kill(-group, libc::SIGKILL) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error);
        }
    }
    let status = timeout(Duration::from_secs(3), child.wait()).await??;
    match (finished?, status.success()) {
        (true, true) => Ok(()),
        (true, false) => Err(bad("App data migration failed")),
        (false, _) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "App data migration timed out",
        )),
    }
}

/// Withdraw the owner role and end every session that may still hold it.
async fn release(roles: &Roles) -> io::Result<()> {
    let stopped = wait_stopped(roles.uid).await;
    let (role, owner) = (&roles.runtime, &roles.owner);
    let released = runtime::control_sql(&format!(
        r"REVOKE {owner} FROM {role};
DO $release$
BEGIN
    PERFORM pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename IN ('{role}', '{owner}');
    LOOP
        PERFORM pg_stat_clear_snapshot();
        EXIT WHEN NOT EXISTS (SELECT FROM pg_stat_activity WHERE usename IN ('{role}', '{owner}'));
        PERFORM pg_sleep(0.05);
    END LOOP;
END;
$release$;
"
    ))
    .await;
    if stopped.is_err() {
        // An unconfirmed process must not reconnect before the next fence completes.
        runtime::fence_database(roles.uid).await?;
    }
    stopped?;
    released.map(drop)
}

async fn wait_stopped(uid: u32) -> io::Result<()> {
    let deadline = Instant::now() + RELEASE_TIMEOUT;
    loop {
        let result = tokio::task::spawn_blocking(move || verify_uid_stopped(uid))
            .await
            .map_err(io::Error::other)?;
        if result.is_ok() || Instant::now() >= deadline {
            return result;
        }
        sleep(Duration::from_millis(100)).await;
    }
}
