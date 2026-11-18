use std::{
    fs::File,
    io,
    os::{
        fd::AsFd,
        unix::{
            fs::{FileTypeExt, MetadataExt},
            net::UnixStream as StdUnixStream,
            process::CommandExt,
        },
    },
    process::{ExitStatus, Stdio},
    time::Duration,
};

use tokio::{
    io::AsyncWriteExt,
    net::{UnixStream, unix::pipe::Receiver},
    process::{Child, Command},
    time::timeout,
};

use super::LaunchConfig;

const MAX_LAUNCH_BYTES: usize = 8192;

pub(super) enum ManagerPipe {
    Pipe(Receiver),
    Stream(UnixStream),
}

impl ManagerPipe {
    pub(super) fn open() -> io::Result<Self> {
        // SAFETY: geteuid has no pointer arguments or other preconditions.
        if unsafe { libc::geteuid() } != 0 {
            return Err(io::Error::other("App IPC requires the privileged manager"));
        }
        let file = File::from(io::stdin().as_fd().try_clone_to_owned()?);
        let metadata = file.metadata()?;
        if metadata.uid() == 0 && metadata.mode() & 0o077 == 0 && metadata.file_type().is_fifo() {
            return Ok(Self::Pipe(Receiver::from_file(file)?));
        }
        if metadata.file_type().is_socket() {
            let stream = StdUnixStream::from(std::os::fd::OwnedFd::from(file));
            stream.set_nonblocking(true)?;
            let stream = UnixStream::from_std(stream)?;
            if stream.peer_cred()?.uid() == 0 {
                return Ok(Self::Stream(stream));
            }
        }
        Err(io::Error::other(
            "App IPC requires a private root manager channel",
        ))
    }

    async fn read(&self, bytes: &mut [u8]) -> io::Result<usize> {
        loop {
            let result = match self {
                Self::Pipe(pipe) => {
                    pipe.readable().await?;
                    pipe.try_read(bytes)
                }
                Self::Stream(stream) => {
                    stream.readable().await?;
                    stream.try_read(bytes)
                }
            };
            match result {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                result => return result,
            }
        }
    }

    pub(super) async fn launch(&self) -> io::Result<LaunchConfig> {
        let error = || io::Error::other("Invalid manager launch request");
        let mut launch = Vec::new();
        let mut chunk = [0; 1024];
        loop {
            let count = self.read(&mut chunk).await?;
            if count == 0 || launch.len() + count > MAX_LAUNCH_BYTES {
                return Err(error());
            }
            let chunk = &chunk[..count];
            launch.extend_from_slice(chunk);
            if let Some(newline) = chunk.iter().position(|byte| *byte == b'\n') {
                if newline != count - 1 {
                    return Err(error());
                }
                return serde_json::from_slice(&launch).map_err(|_| error());
            }
        }
    }

    pub(super) async fn revoked(&self) {
        // A supervisor may revoke with one byte, by closing the pipe, or by exiting.
        let _ = self.read(&mut [0]).await;
    }
}

pub(super) fn start_child(config: &LaunchConfig) -> io::Result<Child> {
    let mut command = Command::new(&config.executable);
    command
        .current_dir(&config.data_directory)
        .env_clear()
        .env("RENTNERPROXY_APP_BOOTSTRAP_FD", "0")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .process_group(0);
    if let Some(path) = &config.database_url_file {
        command.env("RENTNERPROXY_APP_DATABASE_URL_FILE", path);
    }
    let (gid, uid, parent) = (config.gid, config.uid, std::process::id());
    // SAFETY: Only async-signal-safe direct syscalls and stack-only setup run
    // between fork and exec. The child is single-threaded and owns its FD table.
    unsafe {
        command
            .as_std_mut()
            .pre_exec(move || restrict_child(uid, gid, parent));
    }
    command.spawn()
}

pub(super) async fn deliver_bootstrap(child: &mut Child, descriptor: &[u8]) -> io::Result<()> {
    let mut pipe = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("Unable to acquire private app bootstrap pipe"))?;
    pipe.write_all(descriptor).await?;
    pipe.shutdown().await
}

pub(super) async fn observe_exit(pid: u32) -> io::Result<()> {
    while !has_exited(pid)? {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Ok(())
}

fn has_exited(pid: u32) -> io::Result<bool> {
    let mut information = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
    // SAFETY: waitid writes a siginfo_t. WNOWAIT retains the child PID until
    // the process group has been stopped and the Tokio handle reaps it.
    let outcome = unsafe {
        libc::waitid(
            libc::P_PID,
            pid,
            information.as_mut_ptr(),
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if outcome != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: With WNOHANG, Linux either fills in the exited child or leaves
    // si_pid at zero. The waitid event is always a child-status event.
    Ok(unsafe { information.assume_init().si_pid() } != 0)
}

pub(super) async fn stop_child(pid: u32, child: &mut Child) -> io::Result<ExitStatus> {
    let group = i32::try_from(pid).map_err(io::Error::other)?;
    // SAFETY: The original PID is still reserved since the child was not reaped.
    // process_group(0) assigned its PID as the group and the filter bars escape.
    if unsafe { libc::kill(-group, libc::SIGKILL) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error);
        }
    }
    timeout(Duration::from_secs(3), child.wait()).await?
}

pub(super) fn app_exit(status: ExitStatus) -> io::Result<()> {
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other("Native app process exited unsuccessfully"))
    }
}

fn restrict_child(uid: u32, gid: u32, parent: u32) -> io::Result<()> {
    // SAFETY: close_range only marks inherited descriptors for closure on exec.
    // Standard input/output/error are deliberately assigned by the command.
    if unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3_u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Null is valid with a group count of zero. Credentials are changed
    // only in the forked child. The direct syscalls avoid threaded libc wrappers.
    if unsafe {
        libc::syscall(
            libc::SYS_setgroups,
            0_usize,
            std::ptr::null::<libc::gid_t>(),
        ) != 0
            || libc::syscall(libc::SYS_setresgid, gid, gid, gid) != 0
            || libc::syscall(libc::SYS_setresuid, uid, uid, uid) != 0
            || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
            || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
    } {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: These calls have no pointer arguments. Check the parent after
    // setting the death signal to cover parent exit during setup.
    if unsafe { libc::getppid() } as u32 != parent {
        return Err(io::Error::from_raw_os_error(libc::ECHILD));
    }
    let processes = libc::rlimit {
        rlim_cur: 64,
        rlim_max: 64,
    };
    // SAFETY: setrlimit reads an initialized rlimit while it is live.
    if unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &processes) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: umask only affects the child process.
    unsafe { libc::umask(0o077) };
    restrict_sockets()
}

fn restrict_sockets() -> io::Result<()> {
    // Linux seccomp_data offsets for the syscall number, architecture and first
    // argument. Both supported native architectures are little-endian.
    const NR: u32 = 0;
    const ARCH: u32 = 4;
    const ARG0: u32 = 16;
    #[cfg(target_arch = "x86_64")]
    const NATIVE_ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const NATIVE_ARCH: u32 = 0xc000_00b7;
    const DENY: u32 = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;

    let mut filter = [
        load(ARCH),
        jump(libc::BPF_JEQ, NATIVE_ARCH, 1, 0),
        ret(libc::SECCOMP_RET_KILL_PROCESS),
        load(NR),
        // Reject compatibility-ABI syscall numbers before interpreting any args.
        jump(libc::BPF_JGE, 0x4000_0000, 0, 1),
        ret(DENY),
        jump(libc::BPF_JEQ, libc::SYS_io_uring_setup as u32, 7, 0),
        jump(libc::BPF_JEQ, libc::SYS_setsid as u32, 6, 0),
        jump(libc::BPF_JEQ, libc::SYS_setpgid as u32, 5, 0),
        jump(libc::BPF_JEQ, libc::SYS_socket as u32, 1, 0),
        jump(libc::BPF_JEQ, libc::SYS_socketpair as u32, 0, 2),
        load(ARG0),
        jump(libc::BPF_JEQ, libc::AF_UNIX as u32, 0, 1),
        ret(libc::SECCOMP_RET_ALLOW),
        ret(DENY),
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    // SAFETY: The kernel copies the valid BPF program and its initialized array
    // during this call. Both remain live until the call returns.
    if unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &program,
            0,
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

const fn load(offset: u32) -> libc::sock_filter {
    libc::sock_filter {
        code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
        jt: 0,
        jf: 0,
        k: offset,
    }
}

const fn jump(operator: u32, comparison: u32, yes: u8, no: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: (libc::BPF_JMP | operator | libc::BPF_K) as u16,
        jt: yes,
        jf: no,
        k: comparison,
    }
}

const fn ret(value: u32) -> libc::sock_filter {
    libc::sock_filter {
        code: (libc::BPF_RET | libc::BPF_K) as u16,
        jt: 0,
        jf: 0,
        k: value,
    }
}
