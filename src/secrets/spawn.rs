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

/// Runs `program` with `args` to completion, stdin closed, and collects its
/// output; dropping the future kills the child
#[cfg(not(target_os = "macos"))]
pub(super) async fn output(program: &str, args: &[&str]) -> io::Result<Output> {
    use std::process::Stdio;

    tokio::process::Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .output()
        .await
}

/// Runs `program` with `args` to completion, stdin closed, and collects its
/// output; dropping the future kills the child
#[cfg(target_os = "macos")]
pub(super) async fn output(program: &str, args: &[&str]) -> io::Result<Output> {
    macos::output(program, args).await
}

#[cfg(target_os = "macos")]
mod macos {
    use std::{
        ffi::{CString, c_char, c_int},
        fs::File,
        io::{self, Read},
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::process::ExitStatusExt,
        },
        process::{ExitStatus, Output},
        ptr,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };

    unsafe extern "C" {
        // not in the SDK headers, but exported by libsystem since macOS
        // 10.14; Chromium and LLDB start their helpers with it for the same
        // reason
        fn responsibility_spawnattrs_setdisclaim(
            attrs: *mut libc::posix_spawnattr_t,
            disclaim: c_int,
        ) -> c_int;
    }

    pub(super) async fn output(program: &str, args: &[&str]) -> io::Result<Output> {
        let (stdout_read, stdout_write) = pipe()?;
        let (stderr_read, stderr_write) = pipe()?;
        let pid = spawn(program, args, &stdout_write, &stderr_write)?;
        let child = Child::new(pid);

        // the reads end at the child's exit only once no copy of the write
        // ends is left here
        drop((stdout_write, stderr_write));

        let stdout = read_to_end(stdout_read);
        let stderr = read_to_end(stderr_read);
        let (stdout, stderr, status) = tokio::try_join!(stdout, stderr, child.wait())?;

        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }

    /// A pipe whose ends are not inherited by other children the daemon
    /// starts meanwhile, which would hold the read open past `op`'s exit
    fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
        let mut fds = [0; 2];
        // SAFETY: `fds` has room for the two descriptors `pipe` writes
        if unsafe { libc::pipe(fds.as_mut_ptr()) } == -1 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: `pipe` succeeded, so both are open descriptors owned by
        // nothing else
        let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        for fd in [&read, &write] {
            // SAFETY: `fd` is open for as long as the borrow
            if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok((read, write))
    }

    /// Starts `program`, looked up on `PATH`, with responsibility disclaimed
    /// and only stdin from /dev/null and the two pipes inherited
    fn spawn(
        program: &str,
        args: &[&str],
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
                // closes every other descriptor in the child
                check(libc::posix_spawnattr_setflags(
                    &mut attrs,
                    libc::POSIX_SPAWN_CLOEXEC_DEFAULT as libc::c_short,
                ))?;
                check(responsibility_spawnattrs_setdisclaim(&mut attrs, 1))?;
                check(libc::posix_spawn_file_actions_addopen(
                    &mut actions,
                    libc::STDIN_FILENO,
                    c"/dev/null".as_ptr(),
                    libc::O_RDONLY,
                    0,
                ))?;
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

    fn read_to_end(fd: OwnedFd) -> impl Future<Output = io::Result<Vec<u8>>> {
        let read = tokio::task::spawn_blocking(move || {
            let mut bytes = Vec::new();
            File::from(fd).read_to_end(&mut bytes)?;

            Ok(bytes)
        });

        async move { read.await.map_err(io::Error::other)? }
    }

    /// A started child, killed if dropped before it exits
    struct Child {
        pid: libc::pid_t,
        /// Set once the child has exited, after which its pid may belong to
        /// another process as soon as it is reaped
        exited: Arc<AtomicBool>,
        reaper: tokio::task::JoinHandle<io::Result<ExitStatus>>,
    }

    impl Child {
        /// Starts waiting at once, so the child is reaped even when the
        /// caller gives up before awaiting it
        fn new(pid: libc::pid_t) -> Self {
            let exited = Arc::new(AtomicBool::new(false));
            let reaper = tokio::task::spawn_blocking({
                let exited = Arc::clone(&exited);
                move || reap(pid, &exited)
            });

            Self {
                pid,
                exited,
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
            if !self.exited.load(Ordering::Acquire) {
                // SAFETY: the child has not been reaped, so `pid` is still
                // ours, alive or a zombie
                unsafe { libc::kill(self.pid, libc::SIGKILL) };
            }
        }
    }

    /// Waits for `pid` to exit, marks it exited while it is still a zombie
    /// holding its pid, then reaps it
    fn reap(pid: libc::pid_t, exited: &AtomicBool) -> io::Result<ExitStatus> {
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

            match code {
                0 => break,
                _ => retry_interrupted()?,
            }
        }

        exited.store(true, Ordering::Release);

        loop {
            let mut status = 0;
            // SAFETY: `status` is valid for writes
            match unsafe { libc::waitpid(pid, &mut status, 0) } {
                -1 => retry_interrupted()?,
                _ => return Ok(ExitStatus::from_raw(status)),
            }
        }
    }

    fn retry_interrupted() -> io::Result<()> {
        let error = io::Error::last_os_error();

        match error.kind() {
            io::ErrorKind::Interrupted => Ok(()),
            _ => Err(error),
        }
    }
}
