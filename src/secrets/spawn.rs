//! Running `op` as its own responsible process
//!
//! macOS charges a child's file access to the process responsible for it,
//! which for the daemon's children is the daemon. `op` finds the 1Password
//! app integration by reading the app's settings in its group container, and
//! reading another app's container needs codemode-mcp to hold the "access
//! data from other apps" permission. Without it `op` sees no integration and
//! answers that no accounts are configured. Disclaiming responsibility makes
//! `op`, signed by the same team as the container, answer for itself, as it
//! does when started from a terminal or by launchd

use std::{io, process::Output};

/// Why [`output`] has no output for a child
#[derive(Debug, thiserror::Error)]
pub(super) enum RunError {
    /// The child never started, so it did nothing
    #[error("{0}")]
    Start(io::Error),
    /// The child started, but its output or exit status was lost, so what
    /// it did is unknown
    #[error("{0}")]
    Collect(io::Error),
}

impl RunError {
    /// The underlying error, for callers to whom the difference is moot
    pub(super) fn into_io(self) -> io::Error {
        match self {
            Self::Start(error) | Self::Collect(error) => error,
        }
    }
}

/// Runs `program` with `args` to completion and collects its output; dropping
/// the future kills the child
///
/// `stdin` is what the child reads, or nothing: a value passed this way is
/// in neither the argument list nor the environment, which other processes
/// of the same user can read
#[cfg(not(target_os = "macos"))]
pub(super) async fn output(
    program: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
) -> Result<Output, RunError> {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;

    let mut child = tokio::process::Command::new(program)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(RunError::Start)?;
    let pipe = child.stdin.take();
    let write = async {
        if let (Some(mut pipe), Some(input)) = (pipe, stdin) {
            // a child that exits without reading leaves a broken pipe; its
            // status says why
            let _ = pipe.write_all(input).await;
        }
    };
    let (output, ()) = tokio::join!(child.wait_with_output(), write);

    output.map_err(RunError::Collect)
}

/// Runs `program` with `args` to completion and collects its output; dropping
/// the future kills the child
///
/// `stdin` is what the child reads, or nothing: a value passed this way is
/// in neither the argument list nor the environment, which other processes
/// of the same user can read
#[cfg(target_os = "macos")]
pub(super) async fn output(
    program: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
) -> Result<Output, RunError> {
    macos::output(program, args, stdin).await
}

#[cfg(target_os = "macos")]
mod macos {
    use std::{
        ffi::{CString, c_char, c_int, c_void},
        io,
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::process::ExitStatusExt,
        },
        process::{ExitStatus, Output},
        ptr,
        sync::{Arc, Mutex, OnceLock, PoisonError},
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::unix::pipe,
    };

    use super::RunError;

    unsafe extern "C" {
        // not in the SDK headers, but exported by libsystem since macOS
        // 10.14; Chromium and LLDB start their helpers with it for the same
        // reason
        fn responsibility_spawnattrs_setdisclaim(
            attrs: *mut libc::posix_spawnattr_t,
            disclaim: c_int,
        ) -> c_int;
    }

    pub(super) async fn output(
        program: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
    ) -> Result<Output, RunError> {
        let (stdout_read, stdout_write) = pipe().map_err(RunError::Start)?;
        let (stderr_read, stderr_write) = pipe().map_err(RunError::Start)?;
        let input = stdin
            .map(|bytes| pipe().map(|ends| (ends, bytes)))
            .transpose()
            .map_err(RunError::Start)?;
        let pid = spawn(
            program,
            args,
            input.as_ref().map(|((read, _), _)| read),
            &stdout_write,
            &stderr_write,
        )
        .map_err(RunError::Start)?;
        let child = Child::new(pid);

        // the reads end at the child's exit only once no copy of the write
        // ends is left here, and the child sees the end of stdin only once
        // no copy of its read end is
        drop((stdout_write, stderr_write));
        let input = input.map(|((read, write), bytes)| {
            drop(read);

            (write, bytes)
        });

        let write = async {
            match input {
                Some((write, bytes)) => write_all(write, bytes).await,
                None => Ok(()),
            }
        };
        let stdout = read_to_end(stdout_read);
        let stderr = read_to_end(stderr_read);
        let (stdout, stderr, status, ()) =
            tokio::try_join!(stdout, stderr, child.wait(), write).map_err(RunError::Collect)?;

        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }

    /// `pipe2`'s signature
    type Pipe2 = unsafe extern "C" fn(*mut c_int, c_int) -> c_int;

    /// `pipe2`, which macOS has from 27 on; looked up at run time, since
    /// linking it would stop the binary from loading on older releases
    fn pipe2() -> Option<Pipe2> {
        static PIPE2: OnceLock<Option<Pipe2>> = OnceLock::new();

        *PIPE2.get_or_init(|| {
            // SAFETY: the name is NUL-terminated
            let symbol = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"pipe2".as_ptr()) };
            // SAFETY: libsystem's `pipe2` has this signature
            (!symbol.is_null())
                .then(|| unsafe { std::mem::transmute::<*mut c_void, Pipe2>(symbol) })
        })
    }

    /// A pipe whose ends are close-on-exec and above stdio
    ///
    /// With `pipe2` both ends are created close-on-exec. Before macOS 27, a
    /// child another thread starts between `pipe` and `fcntl` can inherit an
    /// end and hold the read open past `op`'s exit, until the read times
    /// out; std creates its own pipes the same way there, so every child
    /// the daemon starts shares that window
    fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
        let mut fds = [0; 2];
        // SAFETY: `fds` has room for the two descriptors either call writes
        let code = match pipe2() {
            Some(pipe2) => unsafe { pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) },
            None => unsafe { libc::pipe(fds.as_mut_ptr()) },
        };
        if code == -1 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: `pipe` succeeded, so both are open descriptors owned by
        // nothing else
        let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };

        Ok((above_stdio(read)?, above_stdio(write)?))
    }

    /// Marks `fd` close-on-exec, moving it above 2 first if it is a stdio
    /// number, which it is when the daemon runs with stdio closed
    ///
    /// `adddup2` of a descriptor onto its own number leaves close-on-exec
    /// set, so `op` would start with that stream closed
    fn above_stdio(fd: OwnedFd) -> io::Result<OwnedFd> {
        if fd.as_raw_fd() > libc::STDERR_FILENO {
            // SAFETY: `fd` is open for as long as the borrow
            if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
                return Err(io::Error::last_os_error());
            }

            return Ok(fd);
        }

        // SAFETY: `fd` is open; the copy is a new descriptor owned by nothing
        // else, and `fd` is closed when it drops
        match unsafe {
            libc::fcntl(
                fd.as_raw_fd(),
                libc::F_DUPFD_CLOEXEC,
                libc::STDERR_FILENO + 1,
            )
        } {
            -1 => Err(io::Error::last_os_error()),
            copy => Ok(unsafe { OwnedFd::from_raw_fd(copy) }),
        }
    }

    /// Starts `program`, looked up on `PATH`, with responsibility disclaimed
    /// and only stdin (from `stdin`, else /dev/null) and the two pipes
    /// inherited
    ///
    /// Like std's `Command`, it unblocks every signal and restores SIGPIPE,
    /// which the daemon ignores, to its default
    fn spawn(
        program: &str,
        args: &[&str],
        stdin: Option<&OwnedFd>,
        stdout: &OwnedFd,
        stderr: &OwnedFd,
    ) -> io::Result<libc::pid_t> {
        let program = CString::new(program)?;
        let args = args
            .iter()
            .map(|arg| CString::new(*arg))
            .collect::<Result<Vec<_>, _>>()?;
        let argv: Vec<*mut c_char> = std::iter::once(&program)
            .chain(&args)
            .map(|arg| arg.as_ptr().cast_mut())
            .chain(std::iter::once(ptr::null_mut()))
            .collect();

        let mut attrs: libc::posix_spawnattr_t = ptr::null_mut();
        let mut actions: libc::posix_spawn_file_actions_t = ptr::null_mut();
        // SAFETY: both are initialised before use and destroyed below, even
        // when a step fails; the strings and `argv` outlive the call, and
        // `_NSGetEnviron` is the process environment `posix_spawnp` expects
        unsafe {
            check(libc::posix_spawnattr_init(&mut attrs))?;
            let spawned = (|| {
                check(libc::posix_spawn_file_actions_init(&mut actions))?;
                // CLOEXEC_DEFAULT closes every other descriptor in the child
                let flags = libc::POSIX_SPAWN_CLOEXEC_DEFAULT
                    | libc::POSIX_SPAWN_SETSIGMASK
                    | libc::POSIX_SPAWN_SETSIGDEF;
                check(libc::posix_spawnattr_setflags(
                    &mut attrs,
                    flags as libc::c_short,
                ))?;

                let mut signals: libc::sigset_t = 0;
                libc::sigemptyset(&mut signals);
                check(libc::posix_spawnattr_setsigmask(&mut attrs, &signals))?;
                libc::sigaddset(&mut signals, libc::SIGPIPE);
                check(libc::posix_spawnattr_setsigdefault(&mut attrs, &signals))?;
                check(responsibility_spawnattrs_setdisclaim(&mut attrs, 1))?;
                match stdin {
                    Some(stdin) => check(libc::posix_spawn_file_actions_adddup2(
                        &mut actions,
                        stdin.as_raw_fd(),
                        libc::STDIN_FILENO,
                    ))?,
                    None => check(libc::posix_spawn_file_actions_addopen(
                        &mut actions,
                        libc::STDIN_FILENO,
                        c"/dev/null".as_ptr(),
                        libc::O_RDONLY,
                        0,
                    ))?,
                }
                check(libc::posix_spawn_file_actions_adddup2(
                    &mut actions,
                    stdout.as_raw_fd(),
                    libc::STDOUT_FILENO,
                ))?;
                check(libc::posix_spawn_file_actions_adddup2(
                    &mut actions,
                    stderr.as_raw_fd(),
                    libc::STDERR_FILENO,
                ))?;

                let mut pid = 0;
                check(libc::posix_spawnp(
                    &mut pid,
                    program.as_ptr(),
                    &actions,
                    &attrs,
                    argv.as_ptr(),
                    *libc::_NSGetEnviron(),
                ))?;

                Ok(pid)
            })();

            if !actions.is_null() {
                libc::posix_spawn_file_actions_destroy(&mut actions);
            }
            libc::posix_spawnattr_destroy(&mut attrs);
            spawned
        }
    }

    /// The spawn calls answer with an error number instead of setting errno
    fn check(code: c_int) -> io::Result<()> {
        match code {
            0 => Ok(()),
            code => Err(io::Error::from_raw_os_error(code)),
        }
    }

    /// Reads on the runtime instead of a blocking thread, so a read given up
    /// closes its end at once: a child of `op` can outlive it and hold the
    /// pipe open, and a blocking read would then run on, keeping the runtime
    /// from shutting down
    async fn read_to_end(fd: OwnedFd) -> io::Result<Vec<u8>> {
        let mut pipe = pipe::Receiver::from_owned_fd(fd)?;
        let mut bytes = Vec::new();
        pipe.read_to_end(&mut bytes).await?;

        Ok(bytes)
    }

    /// Writes `bytes` to the child's stdin and closes it, on the runtime like
    /// the reads; a child that exits without reading leaves a broken pipe,
    /// which its status explains
    async fn write_all(fd: OwnedFd, bytes: &[u8]) -> io::Result<()> {
        let mut pipe = pipe::Sender::from_owned_fd(fd)?;
        let _ = pipe.write_all(bytes).await;

        Ok(())
    }

    /// A started child, killed if dropped before it exits
    struct Child {
        pid: libc::pid_t,
        /// Whether the child has been reaped, after which its pid may belong
        /// to another process; held while reaping and while killing, so a
        /// kill never reaches a reused pid
        reaped: Arc<Mutex<bool>>,
        reaper: tokio::task::JoinHandle<io::Result<ExitStatus>>,
    }

    impl Child {
        /// Starts waiting at once, so the child is reaped even when the
        /// caller gives up before awaiting it
        fn new(pid: libc::pid_t) -> Self {
            let reaped = Arc::new(Mutex::new(false));
            let reaper = tokio::task::spawn_blocking({
                let reaped = Arc::clone(&reaped);
                move || reap(pid, &reaped)
            });

            Self {
                pid,
                reaped,
                reaper,
            }
        }

        async fn wait(mut self) -> io::Result<ExitStatus> {
            let reaper = &mut self.reaper;

            reaper.await.map_err(io::Error::other)?
        }
    }

    impl Drop for Child {
        fn drop(&mut self) {
            let reaped = self.reaped.lock().unwrap_or_else(PoisonError::into_inner);
            if !*reaped {
                // SAFETY: the child has not been reaped and cannot be until
                // the lock is released, so `pid` is still ours, alive or a
                // zombie
                unsafe { libc::kill(self.pid, libc::SIGKILL) };
            }
        }
    }

    /// Waits for `pid` to exit without reaping it, so the pid stays ours
    /// while the lock is not held, then reaps it under the lock
    fn reap(pid: libc::pid_t, reaped: &Mutex<bool>) -> io::Result<ExitStatus> {
        loop {
            // SAFETY: `info` is plain data `waitid` fills in
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // SAFETY: `info` is valid for writes
            let code = unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOWAIT,
                )
            };

            if code == 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if !interrupted(&error) {
                mark_lost(
                    &error,
                    &mut reaped.lock().unwrap_or_else(PoisonError::into_inner),
                );

                return Err(error);
            }
        }

        let mut reaped = reaped.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            let mut status = 0;
            // SAFETY: `status` is valid for writes; the child has exited, so
            // this returns at once
            if unsafe { libc::waitpid(pid, &mut status, 0) } != -1 {
                *reaped = true;

                return Ok(ExitStatus::from_raw(status));
            }
            let error = io::Error::last_os_error();
            if !interrupted(&error) {
                mark_lost(&error, &mut reaped);

                return Err(error);
            }
        }
    }

    fn interrupted(error: &io::Error) -> bool {
        error.raw_os_error() == Some(libc::EINTR)
    }

    /// On `ECHILD` something else has reaped the child, so its pid may
    /// already belong to another process and must not be signalled
    fn mark_lost(error: &io::Error, reaped: &mut bool) {
        if error.raw_os_error() == Some(libc::ECHILD) {
            *reaped = true;
        }
    }
}
