use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, Write},
    mem::MaybeUninit,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            process::CommandExt,
        },
    },
    path::Path,
    process::{Command, Stdio},
    ptr, thread,
    time::{Duration, Instant},
};

use zeroize::Zeroizing;

pub(super) const MAX_ARCHIVE: u64 = 8 * 1024 * 1024 * 1024;
const MAX_LIST: u64 = 16 * 1024 * 1024;
const MAX_CLIENT_MEMORY: libc::rlim_t = 1024 * 1024 * 1024;
const CONTROL: Duration = Duration::from_secs(30);
const TRANSFER: Duration = Duration::from_secs(600);
const TOOLS: &str = "/usr/lib/postgresql/18/bin";
const ADMIN_SOCKET: &str = "/var/run/postgresql";
const APP_SOCKET: &str = "/run/rentnerproxy/app-db";
const APPS: &str = "/var/lib/rentnerproxy/apps";
const PASSWORD_SQL_SETTINGS: &str = "\
SET log_statement='none';\n\
SET log_min_duration_statement=-1;\n\
SET log_min_duration_sample=-1;\n\
SET log_transaction_sample_rate=0;\n\
SET log_min_error_statement='panic';\n\
SET password_encryption='scram-sha-256';\n\
\\getenv portable_password RENTNERPROXY_PORTABLE_DATABASE_PASSWORD\n";

struct App {
    uid: u32,
    role: String,
    owner: String,
}

impl App {
    fn new(uid: u32) -> io::Result<Self> {
        if !(20_000..=59_999).contains(&uid) {
            return Err(rejected("Invalid portable app database UID"));
        }
        Ok(Self {
            uid,
            role: format!("rp_app_{uid}"),
            owner: format!("rp_migrate_{uid}"),
        })
    }
}

pub(super) fn verify_inventory(uids: &[u32]) -> io::Result<()> {
    verify_expected(uids, true, false)
}

fn verify_expected(uids: &[u32], exact: bool, fenced: bool) -> io::Result<()> {
    let mut expected = BTreeSet::new();
    for &uid in uids {
        App::new(uid)?;
        if !expected.insert(uid) {
            return Err(rejected("Duplicate portable app database UID"));
        }
    }
    let values = expected
        .into_iter()
        .map(|uid| uid.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let args = [
        format!("--set=uids={{{values}}}"),
        format!("--set=exact={exact}"),
        format!("--set=fenced={fenced}"),
    ];
    let result = sql(
        "postgres",
        None,
        &args,
        include_str!("database/inventory.sql"),
        None,
    )?;
    if result != "t\n" {
        return Err(rejected(
            "Unexpected app database inventory or active writers",
        ));
    }
    Ok(())
}

pub(super) fn capture(uid: u32, destination: &Path) -> io::Result<()> {
    let app = App::new(uid)?;
    verify_expected(&[uid], false, false)?;
    verify_scope(&app, false)?;
    let output = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)?;
    let result = (|| {
        let mut command = admin("pg_dump")?;
        command
            .args([
                "--format=custom",
                "--compress=none",
                "--no-password",
                "--lock-wait-timeout=5000",
                "--no-privileges",
            ])
            .arg(format!("--dbname={}", app.role))
            .arg(format!("--role={}", app.owner))
            .stdout(Stdio::from(output.try_clone()?));
        run(
            &mut command,
            TRANSFER,
            MAX_ARCHIVE,
            "App database dump failed",
        )?;
        archive_list(&app, &output)?;
        output.sync_all()?;
        verify_scope(&app, false)?;
        verify_expected(&[uid], false, false)
    })();
    drop(output);
    if result.is_err() {
        fs::remove_file(destination)?;
    }
    result
}

pub(super) fn restore(uid: u32, input: &Path) -> io::Result<()> {
    let app = App::new(uid)?;
    let archive = protected_file(input, MAX_ARCHIVE)?;
    let list = archive_list(&app, &archive)?;
    verify_expected(&[uid], false, false)?;
    verify_scope(&app, true)?;
    let password = native_password(&app)?;
    let temporary = temporary_password()?;
    let prepare = format!(
        "{PASSWORD_SQL_SETTINGS}\
        BEGIN;\n\
        GRANT :\"owner\" TO :\"role\" WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;\n\
        SELECT (clock_timestamp() + interval '11 minutes')::text AS expires \\gset\n\
        ALTER ROLE :\"role\" WITH LOGIN CONNECTION LIMIT 1 PASSWORD :'portable_password' VALID UNTIL :'expires';\n\
        COMMIT;\n"
    );
    let result = sql("postgres", Some(&app), &[], &prepare, Some(&temporary))
        .and_then(|_| restore_archive(&app, &archive, &list, &temporary));

    // Fence and drain the restricted login before restoring the normal secret.
    // A process death leaves only an expiring, unpublished credential.
    let fenced = fence(&app);
    let finish = format!(
        "{PASSWORD_SQL_SETTINGS}\
        BEGIN;\n\
        REVOKE :\"owner\" FROM :\"role\";\n\
        ALTER ROLE :\"role\" WITH NOLOGIN CONNECTION LIMIT 4 PASSWORD :'portable_password' VALID UNTIL 'infinity';\n\
        COMMIT;\n"
    );
    let revoked = sql("postgres", Some(&app), &[], &finish, Some(&password));
    fenced?;
    revoked?;
    result?;
    verify_scope(&app, false)?;
    verify_expected(&[uid], false, true)
}

pub(super) fn verify_archive(uid: u32, input: &Path) -> io::Result<()> {
    let app = App::new(uid)?;
    let archive = protected_file(input, MAX_ARCHIVE)?;
    let list = archive_list(&app, &archive)?;
    // Render to a discarded stream so pg_restore validates the data blocks too.
    let mut command = restore_command(&app, &archive, &list)?;
    command.args(["--exit-on-error", "--file=-"]);
    run(
        &mut command,
        TRANSFER,
        MAX_ARCHIVE,
        "Invalid app database archive data",
    )
}

// The portable restore marker and fresh-target preflight authorize cleanup of
// an interrupted reservation for this UID. Never infer ownership from its name.
pub(super) fn reset(uid: u32) -> io::Result<()> {
    let app = App::new(uid)?;
    sql(
        "postgres",
        Some(&app),
        &[],
        include_str!("database/reset.sql"),
        None,
    )?;
    Ok(())
}

fn verify_scope(app: &App, pristine: bool) -> io::Result<()> {
    let args = [format!("--set=pristine={pristine}")];
    let result = sql(
        &app.role,
        Some(app),
        &args,
        include_str!("database/scope.sql"),
        None,
    )?;
    if result != "t\n" {
        return Err(rejected(
            "Unsupported app database ownership, privileges, or objects",
        ));
    }
    Ok(())
}

fn fence(app: &App) -> io::Result<()> {
    sql(
        "postgres",
        Some(app),
        &[],
        "ALTER ROLE :\"role\" NOLOGIN;\n\
         ALTER ROLE :\"owner\" NOLOGIN;\n\
         SELECT pg_terminate_backend(pid, 5000) FROM pg_stat_activity WHERE usename IN (:'role', :'owner');\n\
         SELECT 1 / (NOT EXISTS (SELECT FROM pg_stat_activity WHERE usename IN (:'role', :'owner')))::int;\n",
        None,
    )?;
    Ok(())
}

fn archive_list(app: &App, archive: &File) -> io::Result<File> {
    let listing = tempfile::tempfile()?;
    let mut command = app_command("pg_restore", app);
    command
        .args(["--format=custom", "--list"])
        .stdin(Stdio::from(rewound(archive)?))
        .stdout(Stdio::from(listing.try_clone()?));
    run(
        &mut command,
        CONTROL,
        MAX_LIST,
        "Invalid app database archive",
    )?;

    let mut selected = tempfile::tempfile()?;
    let mut text = String::new();
    rewound(&listing)?
        .take(MAX_LIST + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > MAX_LIST
        || !text.lines().any(|line| line == ";     Compression: none")
        || !text.lines().any(|line| {
            line.strip_prefix(";     dbname: ")
                .is_some_and(|name| name == app.role)
        })
    {
        return Err(rejected("Invalid app database archive identity"));
    }
    let mut entries = BTreeSet::new();
    let mut schema = false;
    let schema_item = format!("SCHEMA - app {}", app.owner);
    for line in text
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with(';'))
    {
        let (id, entry) = line
            .split_once("; ")
            .ok_or_else(|| rejected("Invalid app database archive contents"))?;
        let id = id
            .parse::<u32>()
            .map_err(|_| rejected("Invalid app database archive item"))?;
        let mut fields = entry.splitn(3, ' ');
        if id == 0
            || !entries.insert(id)
            || entries.len() > 65_536
            || fields
                .next()
                .and_then(|oid| oid.parse::<u32>().ok())
                .is_none()
            || fields
                .next()
                .and_then(|oid| oid.parse::<u32>().ok())
                .is_none()
        {
            return Err(rejected("Invalid app database archive item"));
        }
        let item = fields
            .next()
            .ok_or_else(|| rejected("Invalid app database archive item"))?;
        if item == schema_item {
            if schema {
                return Err(rejected("Duplicate app database schema"));
            }
            schema = true;
        } else {
            if !app_archive_item(item, &app.owner) {
                return Err(rejected("Unsupported app database archive item"));
            }
            writeln!(selected, "{line}")?;
        }
    }
    if !schema {
        return Err(rejected("Missing app database schema"));
    }
    // Only the restricted helper receives an inherited handle to this unlinked file.
    selected.set_permissions(fs::Permissions::from_mode(0o444))?;
    Ok(selected)
}

fn app_archive_item(item: &str, owner: &str) -> bool {
    const SCOPED: &[&str] = &[
        "AGGREGATE",
        "CHECK CONSTRAINT",
        "COLLATION",
        "CONSTRAINT",
        "DEFAULT",
        "DOMAIN",
        "DOMAIN CONSTRAINT",
        "FK CONSTRAINT",
        "FUNCTION",
        "INDEX",
        "INDEX ATTACH",
        "OPERATOR",
        "PROCEDURE",
        "RULE",
        "SEQUENCE",
        "SEQUENCE OWNED BY",
        "SEQUENCE SET",
        "STATISTICS",
        "TABLE",
        "TABLE ATTACH",
        "TABLE DATA",
        "TRIGGER",
        "TYPE",
        "VIEW",
        "COMMENT",
    ];
    let Some((object, object_owner)) = item.rsplit_once(' ') else {
        return false;
    };
    object_owner == owner
        && (object == "COMMENT - SCHEMA app"
            || SCOPED.iter().any(|kind| {
                object
                    .strip_prefix(kind)
                    .and_then(|rest| rest.strip_prefix(" app "))
                    .is_some_and(|name| !name.is_empty())
            }))
}

fn restore_archive(app: &App, archive: &File, list: &File, password: &str) -> io::Result<()> {
    let mut command = restore_command(app, archive, list)?;
    command
        .args(["--no-password", "--single-transaction"])
        .arg(format!("--host={APP_SOCKET}"))
        .arg(format!("--username={}", app.role))
        .arg(format!("--dbname={}", app.role))
        .arg(format!("--role={}", app.owner))
        .env("PGREQUIREAUTH", "scram-sha-256")
        .env("PGPASSWORD", password);
    run(
        &mut command,
        TRANSFER,
        MAX_ARCHIVE,
        "App database restore failed",
    )
}

fn restore_command(app: &App, archive: &File, list: &File) -> io::Result<Command> {
    let fd = list.as_raw_fd();
    let mut command = app_command("pg_restore", app);
    command
        .args(["--format=custom", "--no-owner", "--no-privileges"])
        .arg(format!("--use-list=/proc/self/fd/{fd}"))
        .stdin(Stdio::from(rewound(archive)?));
    // SAFETY: The inherited descriptor stays live until the child is reaped.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(command)
}

fn sql(
    database: &str,
    app: Option<&App>,
    args: &[String],
    body: &str,
    secret: Option<&str>,
) -> io::Result<String> {
    let mut input = tempfile::tempfile()?;
    input.write_all(body.as_bytes())?;
    input.rewind()?;
    let mut output = tempfile::tempfile()?;
    let mut command = admin("psql")?;
    command
        .args([
            "--no-psqlrc",
            "--no-password",
            "--quiet",
            "--tuples-only",
            "--no-align",
            "--set=ON_ERROR_STOP=1",
        ])
        .arg(format!("--dbname={database}"))
        .args(args)
        .stdin(Stdio::from(input))
        .stdout(Stdio::from(output.try_clone()?));
    if let Some(app) = app {
        command
            .arg(format!("--set=role={}", app.role))
            .arg(format!("--set=owner={}", app.owner))
            .arg(format!("--set=uid={}", app.uid));
    }
    if let Some(secret) = secret {
        command.env("RENTNERPROXY_PORTABLE_DATABASE_PASSWORD", secret);
    }
    run(
        &mut command,
        CONTROL,
        MAX_LIST,
        "App database control failed",
    )?;
    output.rewind()?;
    let mut result = String::new();
    output.take(MAX_LIST).read_to_string(&mut result)?;
    Ok(result)
}

fn admin(program: &str) -> io::Result<Command> {
    let (uid, gid) = postgres_identity()?;
    let mut command = Command::new(format!("{TOOLS}/{program}"));
    command
        .args([
            format!("--host={ADMIN_SOCKET}"),
            "--username=postgres".to_owned(),
        ])
        .uid(uid)
        .gid(gid)
        .env_clear()
        .env("LC_ALL", "C")
        .env("PGCONNECT_TIMEOUT", "5")
        .env("PGREQUIREAUTH", "none")
        .env(
            "PGOPTIONS",
            "-c search_path=pg_catalog -c statement_timeout=20000 -c lock_timeout=5000",
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    Ok(command)
}

fn postgres_identity() -> io::Result<(u32, u32)> {
    let mut entry = MaybeUninit::<libc::passwd>::uninit();
    let mut buffer = [0_u8; 4096];
    let mut found = ptr::null_mut();
    // SAFETY: The name is static and both output buffers are writable.
    let status = unsafe {
        libc::getpwnam_r(
            c"postgres".as_ptr(),
            entry.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut found,
        )
    };
    if status != 0 || found.is_null() {
        return Err(rejected("Missing local PostgreSQL identity"));
    }
    // SAFETY: A non-null result initializes the returned account entry.
    let entry = unsafe { entry.assume_init() };
    if entry.pw_uid == 0 || entry.pw_gid == 0 {
        return Err(rejected("Invalid local PostgreSQL identity"));
    }
    Ok((entry.pw_uid, entry.pw_gid))
}

fn app_command(program: &str, app: &App) -> Command {
    let mut command = Command::new(format!("{TOOLS}/{program}"));
    command
        .uid(app.uid)
        .gid(app.uid)
        .env_clear()
        .env("LC_ALL", "C")
        .env("PGCONNECT_TIMEOUT", "5")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn run(
    command: &mut Command,
    timeout: Duration,
    file_limit: u64,
    failure: &'static str,
) -> io::Result<()> {
    let parent = std::process::id();
    let file_limit = libc::rlimit {
        rlim_cur: file_limit,
        rlim_max: file_limit,
    };
    let memory_limit = libc::rlimit {
        rlim_cur: MAX_CLIENT_MEMORY,
        rlim_max: MAX_CLIENT_MEMORY,
    };
    // SAFETY: The child hook uses only async-signal-safe syscalls and local data.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) == -1
                || libc::setrlimit(libc::RLIMIT_FSIZE, &file_limit) == -1
                || libc::setrlimit(libc::RLIMIT_AS, &memory_limit) == -1
            {
                return Err(io::Error::last_os_error());
            }
            if u32::try_from(libc::getppid()).ok() != Some(parent) {
                return Err(io::Error::from_raw_os_error(libc::ECHILD));
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return if status.success() {
                Ok(())
            } else {
                Err(rejected(failure))
            };
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            child.wait()?;
            return Err(io::Error::new(io::ErrorKind::TimedOut, failure));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn rewound(file: &File) -> io::Result<File> {
    let mut copy = file.try_clone()?;
    copy.rewind()?;
    Ok(copy)
}

fn protected_file(path: &Path, max: u64) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.gid() != 0
        || meta.nlink() != 1
        || !matches!(meta.mode() & 0o7777, 0o400 | 0o600)
        || meta.len() == 0
        || meta.len() > max
    {
        return Err(rejected("Invalid protected app database file"));
    }
    Ok(file)
}

fn native_password(app: &App) -> io::Result<Zeroizing<String>> {
    let path = Path::new(APPS)
        .join(app.uid.to_string())
        .join("database-password");
    let file = protected_file(&path, 65)?;
    let mut password = Zeroizing::new(String::new());
    file.take(65).read_to_string(&mut password)?;
    if password.ends_with('\n') {
        password.pop();
    }
    if password.len() != 64
        || !password
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(rejected("Invalid protected app database credential"));
    }
    Ok(password)
}

fn temporary_password() -> io::Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    aws_lc_rs::rand::fill(bytes.as_mut())
        .map_err(|_| rejected("Could not generate a temporary app database credential"))?;
    use std::fmt::Write as _;
    let mut password = Zeroizing::new(String::with_capacity(64));
    for byte in bytes.iter() {
        write!(password, "{byte:02x}").map_err(|_| rejected("Could not encode app credential"))?;
    }
    Ok(password)
}

fn rejected(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
