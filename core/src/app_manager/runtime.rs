use super::{
    bad,
    gateway::{Gateway, lease},
    journal::Slot,
};
use crate::app_install::StagedPackage;
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    io,
    os::{fd::AsRawFd, unix::process::CommandExt},
    path::Path,
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, ChildStdin, Command},
    sync::Mutex,
    task::JoinHandle,
    time::{Instant, sleep_until, timeout, timeout_at},
};

const USERS: &str = "/var/lib/rentnerproxy/apps";

pub(super) fn uid_available(uid: u32) -> io::Result<bool> {
    uid_reusable(uid, false)
}

/// A portable restore may reuse a UID whose persistent storage it retires first.
pub(super) fn uid_reusable(uid: u32, retiring: bool) -> io::Result<bool> {
    let roots: &[&str] = if retiring {
        &["/run/rentnerproxy/apps"]
    } else {
        &[USERS, "/run/rentnerproxy/apps"]
    };
    for root in roots {
        match fs::symlink_metadata(Path::new(root).join(uid.to_string())) {
            Ok(_) => return Ok(false),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
        }
    }
    for (path, column) in [("/etc/passwd", 2), ("/etc/group", 2)] {
        if fs::read_to_string(path)?.lines().any(|line| {
            line.split(':')
                .nth(column)
                .and_then(|id| id.parse::<u32>().ok())
                == Some(uid)
        }) {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) async fn database_uid_vacant(uid: u32) -> io::Result<bool> {
    if !(20000..=59999).contains(&uid) {
        return Err(bad("Invalid database identity"));
    }
    let role = format!("rp_app_{uid}");
    let vacancy = control_sql(&format!("SELECT NOT EXISTS (SELECT FROM pg_roles WHERE rolname IN ('{role}','rp_migrate_{uid}')) AND NOT EXISTS (SELECT FROM pg_database WHERE datname='{role}')")).await?;
    match vacancy.as_slice() {
        b"t\n" => Ok(true),
        b"f\n" => Ok(false),
        _ => Err(bad("Unexpected database vacancy response")),
    }
}

pub(super) async fn fence_database(uid: u32) -> io::Result<()> {
    if !(20000..=59999).contains(&uid) {
        return Err(bad("Invalid database identity"));
    }
    let roles = format!("'rp_app_{uid}', 'rp_migrate_{uid}'");
    // psql commits NOLOGIN before the DO statement. Its statement_timeout bounds
    // the entire signal-and-confirm phase regardless of the number of sessions.
    // An interrupted data migration may have left the owner role granted to the runtime role.
    let sql = format!(
        r"SELECT format('ALTER ROLE %I NOLOGIN', rolname) FROM pg_roles WHERE rolname IN ({roles})
\gexec
SELECT format('REVOKE %I FROM %I', o.rolname, r.rolname)
FROM pg_auth_members m
JOIN pg_roles o ON o.oid = m.roleid
JOIN pg_roles r ON r.oid = m.member
WHERE o.rolname = 'rp_migrate_{uid}' AND r.rolname = 'rp_app_{uid}'
\gexec
DO $fence$
BEGIN
    PERFORM pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename IN ({roles});
    LOOP
        PERFORM pg_stat_clear_snapshot();
        EXIT WHEN NOT EXISTS (SELECT FROM pg_stat_activity WHERE usename IN ({roles}));
        PERFORM pg_sleep(0.05);
    END LOOP;
END;
$fence$;"
    );
    control_sql(&sql).await.map(drop)
}

pub(super) async fn control_sql(sql: &str) -> io::Result<Vec<u8>> {
    control_sql_in("postgres", sql).await
}

/// Run trusted administrative SQL in `database`. Qualify catalog names in app databases.
pub(super) async fn control_sql_in(database: &str, sql: &str) -> io::Result<Vec<u8>> {
    let mut child = Command::new("/usr/local/bin/gosu")
        .args([
            "postgres",
            "/usr/lib/postgresql/18/bin/psql",
            "--no-psqlrc",
            "--no-password",
            "--quiet",
            "--tuples-only",
            "--no-align",
            "--host=/var/run/postgresql",
            "--username=postgres",
            "--set=ON_ERROR_STOP=1",
        ])
        .arg(format!("--dbname={database}"))
        .env_clear()
        .env(
            "PGOPTIONS",
            "-c statement_timeout=5000 -c lock_timeout=2000",
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut input = child
        .stdin
        .take()
        .ok_or_else(|| bad("Missing database control pipe"))?;
    timeout(Duration::from_secs(10), async {
        input.write_all(sql.as_bytes()).await?;
        drop(input);
        let output = child.wait_with_output().await?;
        if output.status.success() {
            Ok(output.stdout)
        } else {
            Err(bad("Database fence or reservation was rejected"))
        }
    })
    .await?
}

pub(super) async fn purge_database(uid: u32) -> io::Result<()> {
    fence_database(uid).await?;
    control_sql(&format!(
        "DROP DATABASE IF EXISTS rp_app_{uid};\nDROP ROLE IF EXISTS rp_app_{uid};\nDROP ROLE IF EXISTS rp_migrate_{uid};"
    )).await.map(drop)
}
fn inherit_writer(command: &mut Command, guard: &File) {
    let fd = guard.as_raw_fd();
    // Only the forked helper changes its FD flags. Its app child closes extra descriptors before exec.
    unsafe {
        command.as_std_mut().pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

pub(super) async fn provision(uid: u32, database: bool, guard: &File) -> io::Result<()> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg("--app-provision")
        .arg(uid.to_string())
        .arg(if database { "database" } else { "files" })
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    inherit_writer(&mut command, guard);
    let status = timeout(Duration::from_secs(70), command.status()).await??;
    if status.success() {
        Ok(())
    } else {
        Err(bad("Native app provisioning failed"))
    }
}

pub(super) struct Running {
    child: Child,
    pipe: Option<ChildStdin>,
    renewal: Option<Renewal>,
    pub ui: Option<super::ui::Publication>,
    pub providers: Option<super::ui::ProviderPublication>,
}

pub(super) struct Renewal {
    confirmed: Arc<Mutex<Instant>>,
    task: JoinHandle<()>,
}

impl Renewal {
    pub fn start(gateway: Gateway, identity: Value, confirmed: Instant) -> Self {
        Self::with_timing(
            gateway,
            identity,
            confirmed,
            Duration::from_secs(20),
            Duration::from_secs(2),
        )
    }

    pub(super) fn with_timing(
        gateway: Gateway,
        identity: Value,
        deadline: Instant,
        interval: Duration,
        retry: Duration,
    ) -> Self {
        let confirmed = Arc::new(Mutex::new(deadline));
        let task = tokio::spawn(renew_lease(
            gateway,
            identity,
            confirmed.clone(),
            interval,
            retry,
        ));
        Self { confirmed, task }
    }

    pub(super) async fn activate(&self, gateway: &Gateway, identity: &Value) -> io::Result<()> {
        // Serialize lease-changing requests so the local deadline follows the gateway's commit order.
        let mut confirmed = self.confirmed.lock().await;
        let (body, deadline) = lease(identity)?;
        timeout_at(*confirmed, gateway.post("activate", body)).await??;
        *confirmed = deadline;
        Ok(())
    }

    pub(super) fn finished(&self) -> bool {
        self.task.is_finished()
    }
}

async fn renew_lease(
    gateway: Gateway,
    identity: Value,
    deadline: Arc<Mutex<Instant>>,
    interval: Duration,
    retry: Duration,
) {
    let mut delay = interval;
    loop {
        let wake = (Instant::now() + delay).min(*deadline.lock().await);
        sleep_until(wake).await;
        let mut confirmed = deadline.lock().await;
        if Instant::now() >= *confirmed {
            return;
        }
        let Ok((body, next)) = lease(&identity) else {
            return;
        };
        match timeout_at(*confirmed, gateway.post("renew", body)).await {
            Ok(Ok(())) if Instant::now() < *confirmed => {
                *confirmed = next.max(*confirmed);
                delay = interval;
            }
            Ok(Err(error)) if error.kind() != io::ErrorKind::PermissionDenied => {
                delay = retry;
            }
            _ => return,
        }
    }
}

impl Drop for Renewal {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Running {
    #[cfg(test)]
    pub(super) fn fixture_child(child: Child) -> Self {
        Self {
            child,
            pipe: None,
            renewal: None,
            ui: None,
            providers: None,
        }
    }

    pub async fn launch(
        id: &str,
        slot: &Slot,
        package: &StagedPackage,
        guard: &File,
        renewal: Renewal,
    ) -> io::Result<Self> {
        let m = &package.manifest;
        let data = Path::new(USERS).join(slot.uid.to_string()).join("data");
        let requirements = &m["requires"];
        let mut frame = serde_json::to_vec(&json!({
            "appId":slot.app_id,"installationId":id,"generation":slot.generation,"uid":slot.uid,"gid":slot.uid,
            "executable":package.directory.join("bin/app"), "dataDirectory":data,
            "databaseUrlFile":m.get("data").map(|_|data.join("database-url")),
            "runtimeProfile":requirements["runtimeProfile"],"appProtocol":requirements["appProtocol"],
            "platformApi":requirements["platformApi"],"uiBridge":requirements.get("uiBridge"),
            "startupTimeoutMs":m["resources"]["startupTimeoutMs"].as_f64().map(|v|v as u64),
            "processLimit":m["resources"]["processLimit"].as_f64().map(|v|v as u64),
            "providers":m.get("providers").cloned().unwrap_or_else(|| json!([]))
        }))?;
        frame.push(b'\n');
        let mut command = Command::new(std::env::current_exe()?);
        let key = crate::config::CONTROLLER_TOKEN_FILE_ENV;
        command
            .arg("--app-ipc")
            .env_clear()
            .env(
                key,
                std::env::var_os(key).ok_or_else(|| bad("Missing controller token path"))?,
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        inherit_writer(&mut command, guard);
        let mut child = command.spawn()?;
        let mut pipe = child
            .stdin
            .take()
            .ok_or_else(|| bad("Missing broker pipe"))?;
        let mut output = child
            .stdout
            .take()
            .ok_or_else(|| bad("Missing readiness pipe"))?;
        let ms = m["resources"]["startupTimeoutMs"]
            .as_f64()
            .filter(|v| v.fract() == 0.0 && (100.0..=120000.0).contains(v))
            .map(|v| v as u64)
            .ok_or_else(|| bad("Missing startup limit"))?;
        timeout(Duration::from_millis(ms), async {
            pipe.write_all(&frame).await?;
            let mut ready = [0; 6];
            output.read_exact(&mut ready).await?;
            if &ready != b"ready\n" || child.try_wait()?.is_some() {
                return Err(bad("App failed readiness"));
            }
            Ok(())
        })
        .await??;
        Ok(Self {
            child,
            pipe: Some(pipe),
            renewal: Some(renewal),
            ui: None,
            providers: None,
        })
    }
    pub fn exited(&mut self) -> io::Result<bool> {
        Ok(
            self.child.try_wait()?.is_some()
                || self.renewal.as_ref().is_some_and(Renewal::finished),
        )
    }
    pub async fn activate(&self, gateway: &Gateway, identity: &Value) -> io::Result<()> {
        self.renewal
            .as_ref()
            .ok_or_else(|| bad("Missing app lease"))?
            .activate(gateway, identity)
            .await
    }
    pub fn close(&mut self) {
        self.ui.take();
        self.renewal.take();
        self.pipe.take();
    }
    pub async fn stop(mut self) -> io::Result<()> {
        self.close();
        timeout(Duration::from_secs(10), self.child.wait()).await??;
        Ok(())
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        self.close();
    }
}
