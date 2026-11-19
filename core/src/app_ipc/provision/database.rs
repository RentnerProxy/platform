use std::{io, process::Stdio, time::Duration};

use tokio::{io::AsyncWriteExt, process::Command, time::timeout};

const DATABASE_SETUP_TIMEOUT: Duration = Duration::from_secs(60);
const CREATE_DATABASE: &str = include_str!("database.sql");
const CREATE_SCHEMA: &str = include_str!("schema.sql");

pub(super) async fn create(uid: u32, password: &str) -> io::Result<String> {
    let role = format!("rp_app_{uid}");
    let migration_role = format!("rp_migrate_{uid}");
    run_sql(
        "postgres",
        &role,
        &migration_role,
        CREATE_DATABASE,
        Some(password),
    )
    .await?;
    run_sql(&role, &role, &migration_role, CREATE_SCHEMA, None).await?;
    Ok(role)
}

async fn run_sql(
    database: &str,
    role: &str,
    migration_role: &str,
    sql: &str,
    password: Option<&str>,
) -> io::Result<()> {
    let mut command = Command::new("/usr/local/bin/gosu");
    command
        .args([
            "postgres",
            "/usr/lib/postgresql/18/bin/psql",
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
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if let Some(password) = password {
        command.env("RENTNERPROXY_APP_DATABASE_PASSWORD", password);
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

fn provision_failed() -> io::Error {
    io::Error::other("App database setup failed")
}
