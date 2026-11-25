//! Run an app's declared SQL data migrations as the app, in one transaction.
//!
//! Steps must be plain SQL without psql commands or transaction control. The app's own OS
//! identity still runs `psql` under the app sandbox. The session logs in as the runtime role and
//! assumes the schema owner only while the platform grants it. The completed version is stored
//! as the comment on the `app` schema in the same transaction, so a crash between the commit and
//! the journal update cannot rerun or skip a step. Portable backups carry that comment with the
//! data it describes. App-authored SQL can keep owner rights through its own routines, so the
//! marker only steers that app's own data plan; lifecycle decisions rely on the journal.

use std::{
    fs, io,
    os::unix::process::CommandExt as _,
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    time::Duration,
};

use tokio::{
    process::{Child, Command},
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
const MAX_STEP_BYTES: u64 = 16 * 1024 * 1024;

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
    let steps = steps(package, migration)?;
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

/// Resolve every declared step inside the verified, manager-owned package tree and require plain
/// SQL. Callers run this before the fence, so a refused step leaves the current release running.
pub(super) fn steps(package: &Path, migration: &Migration) -> io::Result<Vec<PathBuf>> {
    migration
        .steps
        .iter()
        .map(|step| {
            let path = package.join(step);
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.is_file() || metadata.len() > MAX_STEP_BYTES {
                return Err(bad("Invalid app data migration step"));
            }
            if !plain_sql(&fs::read(&path)?) {
                return Err(bad(
                    "App data migration steps cannot control transactions or use psql commands",
                ));
            }
            Ok(path)
        })
        .collect()
}

/// Split SQL into statements the way psql does and accept only plain statements: no psql
/// meta-command and nothing that ends or opens a transaction, which would let earlier steps
/// commit without the rest (`--single-transaction` cannot prevent that). Quoted text, comments
/// and `BEGIN ATOMIC` routine bodies are skipped as psql lexes them.
fn plain_sql(sql: &[u8]) -> bool {
    let mut scanner = Statements::default();
    let mut i = 0;
    while i < sql.len() {
        let byte = sql[i];
        let next = sql.get(i + 1).copied();
        i = match (byte, next) {
            (b'-', Some(b'-')) => sql[i..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(sql.len(), |end| i + end + 1),
            (b'/', Some(b'*')) => match block_comment(sql, i) {
                Some(end) => end,
                None => return false,
            },
            (b'\'', _) => match quoted(sql, i, b'\'', false) {
                Some(end) => end,
                None => return false,
            },
            (b'"', _) => match quoted(sql, i, b'"', false) {
                Some(end) => end,
                None => return false,
            },
            (b'$', _) => match dollar_quoted(sql, i) {
                Some(Some(end)) => end,
                Some(None) => i + 1,
                None => return false,
            },
            (b'\\', _) => return false,
            (b'(', _) => {
                scanner.parentheses += 1;
                i + 1
            }
            (b')', _) => {
                scanner.parentheses = scanner.parentheses.saturating_sub(1);
                i + 1
            }
            (b';', _) => {
                if scanner.parentheses == 0 && scanner.routine == 0 && !scanner.finish() {
                    return false;
                }
                i + 1
            }
            _ if identifier_start(byte) => {
                let end = sql[i..]
                    .iter()
                    .position(|byte| !identifier_part(*byte))
                    .map_or(sql.len(), |length| i + length);
                let word = String::from_utf8_lossy(&sql[i..end]).to_ascii_lowercase();
                if word == "e" && sql.get(end) == Some(&b'\'') {
                    match quoted(sql, end, b'\'', true) {
                        Some(after) => after,
                        None => return false,
                    }
                } else {
                    scanner.word(word);
                    end
                }
            }
            _ => i + 1,
        };
    }
    scanner.finish()
}

/// psql's statement state: the leading words, open parentheses and `BEGIN` routine bodies.
#[derive(Default)]
struct Statements {
    words: Vec<String>,
    parentheses: u32,
    routine: u32,
}

impl Statements {
    fn word(&mut self, word: String) {
        // Like psql, only CREATE [OR REPLACE] FUNCTION|PROCEDURE opens BEGIN ... END bodies.
        let leading = |index: usize| self.words.get(index).map(String::as_str);
        let routine = leading(0) == Some("create")
            && (matches!(leading(1), Some("function" | "procedure"))
                || (leading(1) == Some("or")
                    && leading(2) == Some("replace")
                    && matches!(leading(3), Some("function" | "procedure"))));
        if routine && self.parentheses == 0 {
            match word.as_str() {
                "begin" => self.routine += 1,
                "case" if self.routine > 0 => self.routine += 1,
                "end" if self.routine > 0 => self.routine -= 1,
                _ => (),
            }
        }
        if self.words.len() < 4 {
            self.words.push(word);
        }
    }

    /// Check the finished statement and start the next one.
    fn finish(&mut self) -> bool {
        let leading = |index: usize| self.words.get(index).map(String::as_str);
        let transaction = match leading(0) {
            Some("begin" | "start" | "commit" | "end" | "abort") => true,
            Some("rollback") => {
                leading(1) != Some("to")
                    && !(matches!(leading(1), Some("work" | "transaction"))
                        && leading(2) == Some("to"))
            }
            Some("prepare") => leading(1) == Some("transaction"),
            _ => false,
        };
        *self = Self::default();
        !transaction
    }
}

fn identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_' || byte >= 0x80
}

fn identifier_part(byte: u8) -> bool {
    identifier_start(byte) || byte.is_ascii_digit() || byte == b'$'
}

/// Skip a nested `/* */` comment starting at `start`.
fn block_comment(sql: &[u8], start: usize) -> Option<usize> {
    let mut depth = 0_u32;
    let mut i = start;
    while i + 1 < sql.len() {
        match (sql[i], sql[i + 1]) {
            (b'/', b'*') => {
                depth += 1;
                i += 2;
            }
            (b'*', b'/') => {
                depth -= 1;
                i += 2;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => i += 1,
        }
    }
    None
}

/// Skip a quoted literal or identifier starting at `start`. Doubled quotes stay inside; escape
/// strings (`E'...'`) also take a backslash-escaped character.
fn quoted(sql: &[u8], start: usize, quote: u8, escapes: bool) -> Option<usize> {
    let mut i = start + 1;
    while i < sql.len() {
        match sql[i] {
            b'\\' if escapes => i += 2,
            byte if byte == quote => {
                if sql.get(i + 1) == Some(&quote) {
                    i += 2;
                } else {
                    return Some(i + 1);
                }
            }
            _ => i += 1,
        }
    }
    None
}

/// Skip a `$tag$ ... $tag$` body. `Some(None)` means the `$` starts no quote, such as `$1`.
fn dollar_quoted(sql: &[u8], start: usize) -> Option<Option<usize>> {
    let tag_end = sql[start + 1..]
        .iter()
        .position(|byte| !(identifier_start(*byte) || byte.is_ascii_digit()))
        .map(|length| start + 1 + length);
    let Some(tag_end) = tag_end.filter(|end| sql[*end] == b'$') else {
        return Some(None);
    };
    if sql.get(start + 1).is_some_and(u8::is_ascii_digit) {
        return Some(None);
    }
    let delimiter = &sql[start..=tag_end];
    sql[tag_end + 1..]
        .windows(delimiter.len())
        .position(|window| window == delimiter)
        .map(|offset| Some(tag_end + 1 + offset + delimiter.len()))
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
    let group = Group::spawn(&mut command)?;
    let deadline = Instant::now() + limit;
    let finished = async {
        loop {
            if has_exited(group.pid)? {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok::<_, io::Error>(false);
            }
            sleep(Duration::from_millis(50)).await;
        }
    }
    .await;
    let status = group.stop().await?;
    match (finished?, status.success()) {
        (true, true) => Ok(()),
        (true, false) => Err(bad("App data migration failed")),
        (false, _) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "App data migration timed out",
        )),
    }
}

/// The migration's process group. The sandbox denies setsid and setpgid, so shell escapes cannot
/// leave it. Until the leader is reaped its PID still names the group, so the group is killed
/// first, also when a cancelled activation drops the migration.
struct Group {
    child: Child,
    pid: u32,
    reaped: bool,
}

impl Group {
    fn spawn(command: &mut Command) -> io::Result<Self> {
        let child = command.spawn()?;
        let pid = child
            .id()
            .filter(|pid| i32::try_from(*pid).is_ok())
            .ok_or_else(|| bad("App data migration has no process ID"))?;
        Ok(Self {
            child,
            pid,
            reaped: false,
        })
    }

    fn kill(&self) -> io::Result<()> {
        let group = -(self.pid as i32);
        // SAFETY: kill takes no pointers; the unreaped leader still reserves the group ID.
        if unsafe { libc::kill(group, libc::SIGKILL) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
        Ok(())
    }

    async fn stop(mut self) -> io::Result<ExitStatus> {
        self.kill()?;
        let status = timeout(Duration::from_secs(3), self.child.wait()).await??;
        self.reaped = true;
        Ok(status)
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.kill();
        }
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
