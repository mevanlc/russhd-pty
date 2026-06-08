//! Per-session concurrency: the pump tasks and the supervisor (PLAN §7).
//!
//! Each shell session owns a PTY master, the child's stderr-read pipe, the child
//! process, a clone of the connection [`Handle`] + its [`ChannelId`], and a
//! [`CancellationToken`] that is tripped when the client goes away. [`spawn`]
//! launches three tasks:
//!
//! 1. **master → client** — drains the PTY master and forwards bytes to the client.
//! 2. **stderr → logs** — drains the child's stderr pipe into the daemon log.
//! 3. **supervisor** — relays the child's exit, or (on client disconnect) drives the
//!    `SIGHUP` → grace → `SIGKILL` shutdown.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::ExitStatusExt;
use std::sync::Arc;
use std::time::Duration;

use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use russh::server::Handle;
use russh::{ChannelId, Sig};
use tokio::io::unix::AsyncFd;
use tokio::process::Child;
use tokio::time::timeout;
use tokio_util::bytes::Bytes;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Read buffer size for the PTY master pump.
const MASTER_BUF: usize = 32 * 1024;
/// Read buffer size for the stderr pump.
const STDERR_BUF: usize = 8 * 1024;

/// Everything needed to run one shell session's tasks.
pub struct Session {
    /// PTY master, shared with the connection handler (which writes client input).
    pub master: Arc<AsyncFd<OwnedFd>>,
    /// The child process attached to the PTY.
    pub child: Child,
    /// Read end of the child's stderr pipe (non-blocking).
    pub stderr_read: AsyncFd<OwnedFd>,
    /// Clone of the connection handle for pushing data/exit/close to the client.
    pub handle: Handle,
    /// The session's channel.
    pub channel: ChannelId,
    /// Cancelled when the client disconnects; trips graceful shutdown.
    pub cancel: CancellationToken,
    /// Grace period between `SIGHUP` and `SIGKILL`.
    pub grace: Duration,
    /// Child pid (also its process-group id, since it `setsid`'d).
    pub pid: u32,
}

/// Launch the session's pump + supervisor tasks. Returns immediately.
pub fn spawn(s: Session) {
    let Session {
        master,
        child,
        stderr_read,
        handle,
        channel,
        cancel,
        grace,
        pid,
    } = s;

    tokio::spawn(pump_master_to_client(
        master,
        handle.clone(),
        channel,
        cancel.clone(),
    ));
    tokio::spawn(pump_stderr_to_log(stderr_read, channel, cancel.clone()));
    tokio::spawn(supervise(child, handle, channel, cancel, grace, pid));
}

/// PTY master → client. Ends on EOF/`EIO` (child closed the PTY) or cancellation.
async fn pump_master_to_client(
    master: Arc<AsyncFd<OwnedFd>>,
    handle: Handle,
    channel: ChannelId,
    cancel: CancellationToken,
) {
    let mut buf = vec![0u8; MASTER_BUF];
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            r = read_fd(&master, &mut buf) => match r {
                Ok(0) => break,
                Ok(n) => {
                    if handle.data(channel, Bytes::copy_from_slice(&buf[..n])).await.is_err() {
                        // Client channel is gone; nothing more to send.
                        break;
                    }
                }
                Err(e) if is_pty_hangup(&e) => break,
                Err(e) => {
                    warn!(channel = ?channel, error = %e, "PTY master read failed");
                    break;
                }
            },
        }
    }
    debug!(channel = ?channel, "master->client pump finished");
}

/// Child stderr → daemon log (line-oriented, INFO so it lands on stdout).
async fn pump_stderr_to_log(
    stderr: AsyncFd<OwnedFd>,
    channel: ChannelId,
    cancel: CancellationToken,
) {
    let mut buf = vec![0u8; STDERR_BUF];
    let mut pending: Vec<u8> = Vec::new();
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            r = read_fd(&stderr, &mut buf) => match r {
                Ok(0) => break,
                Ok(n) => emit_lines(&mut pending, &buf[..n], channel),
                Err(e) if is_pty_hangup(&e) => break,
                Err(e) => {
                    warn!(channel = ?channel, error = %e, "child stderr read failed");
                    break;
                }
            },
        }
    }
    if !pending.is_empty() {
        info!(channel = ?channel, "child stderr: {}", String::from_utf8_lossy(&pending));
    }
}

/// Split accumulated stderr bytes on newlines, logging each complete line.
fn emit_lines(pending: &mut Vec<u8>, chunk: &[u8], channel: ChannelId) {
    pending.extend_from_slice(chunk);
    while let Some(nl) = pending.iter().position(|&b| b == b'\n') {
        let line: Vec<u8> = pending.drain(..=nl).collect();
        let text = String::from_utf8_lossy(&line);
        info!(channel = ?channel, "child stderr: {}", text.trim_end_matches(['\n', '\r']));
    }
}

/// Supervise the child: relay its exit, or drive graceful shutdown on disconnect.
async fn supervise(
    mut child: Child,
    handle: Handle,
    channel: ChannelId,
    cancel: CancellationToken,
    grace: Duration,
    pid: u32,
) {
    let pgid = Pid::from_raw(pid as i32);
    let mut wait = Box::pin(child.wait());

    tokio::select! {
        res = &mut wait => {
            match res {
                Ok(status) => {
                    info!(channel = ?channel, pid, ?status, "child exited");
                    relay_exit(&handle, channel, status).await;
                }
                Err(e) => warn!(channel = ?channel, pid, error = %e, "waiting on child failed"),
            }
            // Close the channel cleanly (after relaying exit-status above) and let
            // the client tear down the connection, so it reports the child's exit
            // code. Sending a transport-level DISCONNECT here would instead make
            // OpenSSH report 255, discarding the relayed status.
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
            cancel.cancel();
        }
        _ = cancel.cancelled() => {
            info!(channel = ?channel, pid, "client disconnected; sending SIGHUP to child group");
            let _ = killpg(pgid, Signal::SIGHUP);
            match timeout(grace, &mut wait).await {
                Ok(Ok(status)) => {
                    info!(channel = ?channel, pid, ?status, "child exited after SIGHUP");
                }
                Ok(Err(e)) => warn!(channel = ?channel, pid, error = %e, "waiting on child failed"),
                Err(_) => {
                    warn!(channel = ?channel, pid, "child still alive after grace; sending SIGKILL");
                    let _ = killpg(pgid, Signal::SIGKILL);
                    let _ = wait.await;
                }
            }
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
        }
    }
}

/// Relay the child's exit to the client as `exit-status` or `exit-signal`.
async fn relay_exit(handle: &Handle, channel: ChannelId, status: std::process::ExitStatus) {
    if let Some(code) = status.code() {
        let _ = handle.exit_status_request(channel, code as u32).await;
    } else if let Some(sig) = status.signal() {
        let _ = handle
            .exit_signal_request(
                channel,
                map_signal(sig),
                false,
                "killed by signal".to_string(),
                String::new(),
            )
            .await;
    }
}

/// Map a libc signal number to russh's [`Sig`].
fn map_signal(sig: i32) -> Sig {
    match sig {
        libc::SIGABRT => Sig::ABRT,
        libc::SIGALRM => Sig::ALRM,
        libc::SIGFPE => Sig::FPE,
        libc::SIGHUP => Sig::HUP,
        libc::SIGILL => Sig::ILL,
        libc::SIGINT => Sig::INT,
        libc::SIGKILL => Sig::KILL,
        libc::SIGPIPE => Sig::PIPE,
        libc::SIGQUIT => Sig::QUIT,
        libc::SIGSEGV => Sig::SEGV,
        libc::SIGTERM => Sig::TERM,
        libc::SIGUSR1 => Sig::USR1,
        other => Sig::Custom(format!("SIG{other}")),
    }
}

/// A read error that means the PTY/child hung up (normal end of stream).
fn is_pty_hangup(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::EIO))
}

/// Async-read from an `AsyncFd`-wrapped descriptor. Returns `Ok(0)` on EOF.
pub async fn read_fd(afd: &AsyncFd<OwnedFd>, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        let mut guard = afd.readable().await?;
        match guard.try_io(|inner| {
            let fd = inner.get_ref().as_raw_fd();
            // SAFETY: `fd` is valid for the call; `buf` is a valid writable slice.
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }) {
            Ok(result) => return result,
            Err(_would_block) => continue,
        }
    }
}

/// Async-write all of `data` to an `AsyncFd`-wrapped descriptor.
pub async fn write_all_fd(afd: &AsyncFd<OwnedFd>, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        let mut guard = afd.writable().await?;
        match guard.try_io(|inner| {
            let fd = inner.get_ref().as_raw_fd();
            // SAFETY: `fd` is valid for the call; `data` is a valid readable slice.
            let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }) {
            Ok(Ok(n)) => data = &data[n..],
            Ok(Err(e)) => return Err(e),
            Err(_would_block) => continue,
        }
    }
    Ok(())
}
