use std::{
    io, mem::MaybeUninit, os::unix::process::CommandExt, process::Stdio, ptr, time::Duration,
};

use tokio::{io::AsyncWriteExt, process::Command, time::timeout};

const DATABASE_SETUP_TIMEOUT: Duration = Duration::from_secs(25);
const CREATE_DATABASE: &str = include_str!("database.sql");
const CREATE_SCHEMA: &str = include_str!("schema.sql");

pub(super) async fn create(uid: u32, password: &str) -> io::Result<String> {
    let role = format!("rp_app_{uid}");
    let migration_role = format!("rp_migrate_{uid}");
    let identity = postgres_identity()?;
    run_sql(
        identity,
        "postgres",
        &role,
        &migration_role,
        CREATE_DATABASE,
        Some(password),
    )
    .await?;
    run_sql(identity, &role, &role, &migration_role, CREATE_SCHEMA, None).await?;
    Ok(role)
}

async fn run_sql(
    (uid, gid): (u32, u32),
    database: &str,
    role: &str,
    migration_role: &str,
    sql: &str,
    password: Option<&str>,
) -> io::Result<()> {
    let mut command = Command::new("/usr/lib/postgresql/18/bin/psql");
    command
        .args([
            "--no-psqlrc",
            "--no-password",
            "--quiet",
            "--host=/var/run/postgresql",
            "--username=postgres",
            "--set=ON_ERROR_STOP=1",
            "--set=VERBOSITY=terse",
        ])
        .arg(format!("--set=role={role}"))
        .arg(format!("--set=migration_role={migration_role}"))
        .arg(format!("--dbname={database}"))
        .env_clear()
        .env(
            "PGOPTIONS",
            "-c statement_timeout=20000 -c lock_timeout=5000",
        )
        .uid(uid)
        .gid(gid)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if let Some(password) = password {
        command.env("RENTNERPROXY_APP_DATABASE_PASSWORD", password);
    }
    let parent = std::process::id();
    // SAFETY: The hook runs after the child switches identities and uses only direct syscalls.
    unsafe {
        command.as_std_mut().pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            if u32::try_from(libc::getppid()).ok() != Some(parent) {
                return Err(io::Error::from_raw_os_error(libc::ECHILD));
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    let mut input = child.stdin.take().ok_or_else(provision_failed)?;
    timeout(DATABASE_SETUP_TIMEOUT, async {
        input.write_all(sql.as_bytes()).await?;
        drop(input);
        if child.wait().await?.success() {
            Ok(())
        } else {
            Err(provision_failed())
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "App database setup timed out"))?
}

fn postgres_identity() -> io::Result<(u32, u32)> {
    let mut entry = MaybeUninit::<libc::passwd>::uninit();
    let mut buffer = [0_u8; 4096];
    let mut result = ptr::null_mut();
    // SAFETY: The input name is static. The function uses the provided writable buffers.
    let status = unsafe {
        libc::getpwnam_r(
            c"postgres".as_ptr(),
            entry.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() {
        return Err(provision_failed());
    }
    // SAFETY: A found account initializes the passwd structure. Only numeric fields are used.
    let entry = unsafe { entry.assume_init() };
    if entry.pw_uid == 0 || entry.pw_gid == 0 {
        return Err(provision_failed());
    }
    Ok((entry.pw_uid, entry.pw_gid))
}

fn provision_failed() -> io::Error {
    io::Error::other("App database setup failed")
}
