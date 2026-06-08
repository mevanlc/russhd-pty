//! PTY allocation and child-process spawning.
//!
//! The flow (PLAN §6): allocate a real PTY with [`open_pty`], then [`spawn_child`]
//! forks the configured command attached to the slave side via a `pre_exec` hook
//! that runs `setsid` / `TIOCSCTTY` / `dup2`. The child's stderr is redirected to a
//! separate pipe whose read end is returned for the daemon to drain into its logs.
//!
//! ## File-descriptor discipline
//!
//! Every long-lived fd the daemon keeps open (PTY masters, stderr-read pipes) is
//! marked `FD_CLOEXEC` so it cannot leak into a child of *another* concurrent
//! session at exec time. The slave and stderr-write fds are also `FD_CLOEXEC`: the
//! `dup2` copies onto fds 0/1/2 do **not** inherit the flag (POSIX), so the
//! redirected descriptors survive exec while the originals are closed by the kernel.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::process::Stdio;

use anyhow::{Context, Result};
use nix::pty::{Winsize, openpty};
use tokio::process::{Child, Command};

/// Build a `winsize` from column/row plus optional pixel dimensions.
pub fn winsize(cols: u16, rows: u16, xpix: u16, ypix: u16) -> Winsize {
    Winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: xpix,
        ws_ypixel: ypix,
    }
}

/// Allocate a PTY pair with the given initial window size.
///
/// Returns `(master, slave)`. The master is marked `FD_CLOEXEC` and set
/// non-blocking so it can be wrapped in `tokio`'s `AsyncFd`; the slave is left
/// blocking/inheritable for the child to claim as its controlling terminal.
pub fn open_pty(ws: &Winsize) -> Result<(OwnedFd, OwnedFd)> {
    let res = openpty(Some(ws), None).context("openpty failed")?;
    set_cloexec(res.master.as_raw_fd())?;
    set_nonblocking(res.master.as_raw_fd())?;
    Ok((res.master, res.slave))
}

/// Apply a new window size to the PTY master via `TIOCSWINSZ`. The kernel then
/// raises `SIGWINCH` in the slave's foreground process group.
pub fn set_winsize(master: RawFd, cols: u16, rows: u16, xpix: u16, ypix: u16) -> io::Result<()> {
    let ws = winsize(cols, rows, xpix, ypix);
    // SAFETY: `master` is a valid fd for the duration of the call; `&ws` points to
    // a properly initialized `winsize` matching what TIOCSWINSZ expects.
    let rc = unsafe { libc::ioctl(master, libc::TIOCSWINSZ as _, &ws) };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Spawn the configured command attached to `slave` as its controlling terminal.
///
/// Returns the running [`Child`] and the **read** end of the child's stderr pipe
/// (non-blocking, `FD_CLOEXEC`) for the caller to drain into the daemon log.
///
/// `slave` is consumed: the parent closes it on return (the child has already
/// `dup2`'d it onto fds 0/1).
pub fn spawn_child(argv: &[String], term: &str, slave: OwnedFd) -> Result<(Child, OwnedFd)> {
    debug_assert!(
        !argv.is_empty(),
        "argv must be non-empty (validated in Config)"
    );

    let (stderr_read, stderr_write) = nix::unistd::pipe().context("stderr pipe() failed")?;

    // Long-lived parent fd: don't leak it into any child, and read it async.
    set_cloexec(stderr_read.as_raw_fd())?;
    set_nonblocking(stderr_read.as_raw_fd())?;
    // These survive only as the dup2 targets in the child; CLOEXEC closes the
    // originals at exec.
    set_cloexec(slave.as_raw_fd())?;
    set_cloexec(stderr_write.as_raw_fd())?;

    let slave_raw = slave.as_raw_fd();
    let stderr_write_raw = stderr_write.as_raw_fd();

    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    cmd.env("TERM", term);
    // We perform all stdio wiring ourselves in pre_exec; `inherit` keeps std from
    // installing its own dup2s, so only our hook touches fds 0/1/2.
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    cmd.kill_on_drop(false);

    // SAFETY: the closure runs in the forked child between fork and exec and uses
    // only async-signal-safe libc calls. `slave_raw`/`stderr_write_raw` are valid
    // because the parent holds `slave`/`stderr_write` alive until after `spawn()`.
    unsafe {
        cmd.pre_exec(move || {
            // New session + process group; become session leader (detaches from any
            // controlling terminal so TIOCSCTTY below can claim the PTY).
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            // Make the PTY slave our controlling terminal (enables job control and
            // correct SIGWINCH/SIGHUP delivery).
            if libc::ioctl(slave_raw, libc::TIOCSCTTY as _, 0 as libc::c_int) == -1 {
                return Err(io::Error::last_os_error());
            }
            // Wire stdin/stdout to the PTY slave, stderr to the pipe.
            if libc::dup2(slave_raw, 0) == -1
                || libc::dup2(slave_raw, 1) == -1
                || libc::dup2(stderr_write_raw, 2) == -1
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn {:?}", argv[0]))?;

    // Parent no longer needs the slave or the write end; dropping closes them so
    // the master sees EOF/EIO once the child exits, and the stderr read end sees
    // EOF once the child's fd 2 is closed.
    drop(slave);
    drop(stderr_write);

    Ok((child, stderr_read))
}

/// Set `FD_CLOEXEC` on a descriptor.
pub fn set_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: plain fcntl calls on a borrowed fd; no aliasing concerns.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Set `O_NONBLOCK` on a descriptor (required before wrapping in `AsyncFd`).
pub fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
