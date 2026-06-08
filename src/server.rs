//! The SSH layer: a russh [`Server`] that mints one [`Handler`] per connection.
//!
//! Authentication accepts everything (PLAN §5). A session channel allocates a PTY
//! on `pty-req` (or lazily on `shell`), spawns the configured command on `shell`,
//! relays `window-change` to the PTY, and pumps client `data` into the PTY master.
//! `exec` requests are rejected and the connection dropped.

use std::collections::HashMap;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;

use anyhow::Result;
use russh::server::{Auth, Handler, Msg, Server as ServerTrait, Session};
use russh::{Channel, ChannelId, Disconnect};
use tokio::io::AsyncWrite;
use tokio::io::unix::AsyncFd;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::pty;
use crate::session;

/// Default terminal type when the client sends no `pty-req`.
const DEFAULT_TERM: &str = "xterm";
/// Default window size when the client sends no `pty-req` (cols, rows).
const DEFAULT_COLS: u16 = 80;
const DEFAULT_ROWS: u16 = 24;

/// russh server factory. One per daemon; clones shared state into each connection.
#[derive(Clone)]
pub struct Server {
    config: Arc<Config>,
    /// Root of the session cancel-token tree; cancelled to tear down every
    /// session's child at once on daemon shutdown.
    root_cancel: CancellationToken,
    /// Tracks session supervisor tasks so shutdown can await child teardown.
    tracker: TaskTracker,
}

impl Server {
    pub fn new(config: Arc<Config>, root_cancel: CancellationToken, tracker: TaskTracker) -> Self {
        Self {
            config,
            root_cancel,
            tracker,
        }
    }
}

impl ServerTrait for Server {
    type Handler = ClientHandler;

    fn new_client(&mut self, peer: Option<std::net::SocketAddr>) -> Self::Handler {
        info!(?peer, "connection accepted");
        ClientHandler {
            config: self.config.clone(),
            peer,
            channels: HashMap::new(),
            root_cancel: self.root_cancel.clone(),
            tracker: self.tracker.clone(),
        }
    }

    fn handle_session_error(&mut self, error: <Self::Handler as Handler>::Error) {
        warn!(error = %error, "session error");
    }
}

/// Per-connection state. Holds one [`ChannelState`] per open session channel.
pub struct ClientHandler {
    config: Arc<Config>,
    peer: Option<std::net::SocketAddr>,
    channels: HashMap<ChannelId, ChannelState>,
    /// Parent of every channel's cancel token; cancelled on daemon shutdown.
    root_cancel: CancellationToken,
    /// Shared tracker that the session supervisor tasks register with.
    tracker: TaskTracker,
}

/// Per-channel session state.
struct ChannelState {
    term: String,
    cols: u16,
    rows: u16,
    pixw: u16,
    pixh: u16,
    /// PTY master, shared with the session pump once the shell starts.
    master: Option<Arc<AsyncFd<OwnedFd>>>,
    /// PTY slave, held until consumed by the child at `shell_request`.
    slave: Option<OwnedFd>,
    /// Flow-controlled writer to the client, derived from the `Channel` at open.
    ///
    /// Writing through this (rather than `Handle::data`) respects the SSH channel
    /// window: when the client's receive window is exhausted, the write blocks
    /// instead of letting russh buffer the overflow in its unbounded per-channel
    /// `pending_data` queue. That backpressure propagates to the PTY and throttles
    /// a fast producer (e.g. a full-screen TUI) to the client's drain rate.
    writer: Option<Box<dyn AsyncWrite + Send + Unpin>>,
    /// Whether the shell command has been spawned for this channel.
    started: bool,
    /// Cancelled when the client goes away **or** the daemon shuts down (it is a
    /// child of the connection's `root_cancel`); drives graceful child shutdown.
    cancel: CancellationToken,
}

impl ChannelState {
    /// `root` is the connection's shutdown token; this channel's `cancel` is a
    /// child of it, so a daemon-wide shutdown trips every session at once while a
    /// single client/channel close trips only its own token.
    fn new(root: &CancellationToken) -> Self {
        Self {
            term: DEFAULT_TERM.to_string(),
            cols: DEFAULT_COLS,
            rows: DEFAULT_ROWS,
            pixw: 0,
            pixh: 0,
            master: None,
            slave: None,
            writer: None,
            started: false,
            cancel: root.child_token(),
        }
    }

    /// Allocate the PTY if not already present, using the stored window size.
    fn ensure_pty(&mut self) -> Result<()> {
        if self.master.is_some() {
            return Ok(());
        }
        let ws = pty::winsize(self.cols, self.rows, self.pixw, self.pixh);
        let (master, slave) = pty::open_pty(&ws)?;
        self.master = Some(Arc::new(AsyncFd::new(master)?));
        self.slave = Some(slave);
        Ok(())
    }

    /// Apply the stored window size to the PTY master, if one exists.
    fn apply_winsize(&self) {
        if let Some(master) = &self.master
            && let Err(e) = pty::set_winsize(
                master.get_ref().as_raw_fd(),
                self.cols,
                self.rows,
                self.pixw,
                self.pixh,
            )
        {
            warn!(error = %e, "TIOCSWINSZ failed");
        }
    }
}

/// Clamp an SSH `u32` cols/rows dimension into a `u16`. A `0` (sent by clients
/// with no local terminal, e.g. `ssh </dev/null`) means "unspecified" → default.
fn dim(v: u32, default: u16) -> u16 {
    if v == 0 {
        default
    } else {
        v.clamp(1, u16::MAX as u32) as u16
    }
}

/// Clamp an SSH `u32` pixel dimension; `0` ("unknown") is preserved.
fn pix(v: u32) -> u16 {
    v.min(u16::MAX as u32) as u16
}

impl ClientHandler {
    /// Apply the username allow-list policy for an authentication attempt. Any
    /// username is accepted unless `--allow-ssh-usernames` was given, in which
    /// case only listed names pass; everyone else is rejected.
    fn authorize(&self, user: &str, method: &str) -> Auth {
        if self.config.username_allowed(user) {
            info!(user, method, "auth accepted");
            Auth::Accept
        } else {
            warn!(user, method, peer = ?self.peer, "auth rejected: username not in allow-list");
            // No fallback methods: re-prompting under a different method can't
            // change the username, so reject the connection outright.
            Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            }
        }
    }
}

impl Handler for ClientHandler {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        Ok(self.authorize(user, "none"))
    }

    async fn auth_password(&mut self, user: &str, _password: &str) -> Result<Auth, Self::Error> {
        Ok(self.authorize(user, "password"))
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        _key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(self.authorize(user, "publickey"))
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        user: &str,
        _submethods: &str,
        _response: Option<russh::server::Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        Ok(self.authorize(user, "keyboard-interactive"))
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _ssh: &mut Session,
    ) -> Result<bool, Self::Error> {
        debug!(channel = ?channel.id(), "session channel opened");
        let mut st = ChannelState::new(&self.root_cancel);
        // Capture the flow-controlled writer now, then let `channel` drop: its
        // receiver closes so incoming client data flows only through `data()`
        // below (no double-delivery), while the writer keeps working — it owns
        // clones of the session sender and window refs and is `'static`.
        st.writer = Some(Box::new(channel.make_writer()));
        self.channels.insert(channel.id(), st);
        Ok(true)
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        value: &str,
        _ssh: &mut Session,
    ) -> Result<(), Self::Error> {
        // TERM comes from pty-req, not setenv; we ignore env (PLAN §5).
        debug!(channel = ?channel, name, value, "env request ignored");
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        ssh: &mut Session,
    ) -> Result<(), Self::Error> {
        let root = self.root_cancel.clone();
        let st = self
            .channels
            .entry(channel)
            .or_insert_with(|| ChannelState::new(&root));
        if !term.is_empty() {
            st.term = term.to_string();
        }
        st.cols = dim(col_width, DEFAULT_COLS);
        st.rows = dim(row_height, DEFAULT_ROWS);
        st.pixw = pix(pix_width);
        st.pixh = pix(pix_height);

        match st.ensure_pty() {
            Ok(()) => {
                st.apply_winsize();
                info!(
                    channel = ?channel,
                    term = %st.term,
                    cols = st.cols,
                    rows = st.rows,
                    "pty allocated"
                );
                let _ = ssh.channel_success(channel);
            }
            Err(e) => {
                error!(channel = ?channel, error = %e, "pty allocation failed");
                let _ = ssh.channel_failure(channel);
            }
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        ssh: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(st) = self.channels.get_mut(&channel) {
            st.cols = dim(col_width, DEFAULT_COLS);
            st.rows = dim(row_height, DEFAULT_ROWS);
            st.pixw = pix(pix_width);
            st.pixh = pix(pix_height);
            st.apply_winsize();
            debug!(channel = ?channel, cols = st.cols, rows = st.rows, "window changed");
        }
        let _ = ssh.channel_success(channel);
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        ssh: &mut Session,
    ) -> Result<(), Self::Error> {
        let handle = ssh.handle();
        let st = match self.channels.get_mut(&channel) {
            Some(st) => st,
            None => {
                warn!(channel = ?channel, "shell request for unknown channel");
                let _ = ssh.channel_failure(channel);
                return Ok(());
            }
        };
        if st.started {
            warn!(channel = ?channel, "duplicate shell request ignored");
            let _ = ssh.channel_failure(channel);
            return Ok(());
        }

        if let Err(e) = st.ensure_pty() {
            error!(channel = ?channel, error = %e, "pty allocation failed");
            let _ = ssh.channel_failure(channel);
            return Ok(());
        }

        let slave = st.slave.take().expect("ensure_pty set slave");
        let master = st.master.clone().expect("ensure_pty set master");
        let term = st.term.clone();
        let writer = match st.writer.take() {
            Some(w) => w,
            None => {
                error!(channel = ?channel, "no client writer for channel (channel never opened?)");
                let _ = ssh.channel_failure(channel);
                return Ok(());
            }
        };

        let (child, stderr_fd) = match pty::spawn_child(&self.config.argv, &term, slave) {
            Ok(v) => v,
            Err(e) => {
                error!(channel = ?channel, error = %e, "failed to spawn command");
                let _ = ssh.channel_failure(channel);
                return Ok(());
            }
        };
        let pid = child.id().unwrap_or(0);
        let stderr_read = AsyncFd::new(stderr_fd)?;

        session::spawn(
            session::Session {
                master,
                writer,
                child,
                stderr_read,
                handle,
                channel,
                cancel: st.cancel.clone(),
                grace: self.config.grace,
                pid,
            },
            &self.tracker,
        );
        st.started = true;

        info!(channel = ?channel, pid, argv = ?self.config.argv, "shell started");
        let _ = ssh.channel_success(channel);
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        ssh: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data);
        warn!(
            channel = ?channel,
            peer = ?self.peer,
            command = %command,
            "exec request rejected; disconnecting client"
        );
        let _ = ssh.channel_failure(channel);
        let _ = ssh.disconnect(Disconnect::ByApplication, "exec is not permitted", "");
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _ssh: &mut Session,
    ) -> Result<(), Self::Error> {
        // Clone out the master handle (cheap Arc bump) and release the borrow on
        // `ChannelState` *before* awaiting: holding `&ChannelState` across the
        // await would require it to be `Sync`, which the boxed writer is not.
        let Some(master) = self.channels.get(&channel).and_then(|st| st.master.clone()) else {
            return Ok(());
        };
        if let Err(e) = session::write_all_fd(&master, data).await {
            warn!(channel = ?channel, error = %e, "write to PTY failed; shutting down session");
            if let Some(st) = self.channels.get(&channel) {
                st.cancel.cancel();
            }
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _ssh: &mut Session,
    ) -> Result<(), Self::Error> {
        // Client stdin reached EOF. This is NOT a disconnect: the child keeps
        // running and producing output until it exits or the channel/connection
        // is closed. (Interactive PTY programs don't rely on stdin EOF, and a PTY
        // master can't be half-closed without also tearing down output.)
        debug!(channel = ?channel, "channel EOF (client stdin closed); session continues");
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _ssh: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!(channel = ?channel, "channel closed; cancelling session");
        if let Some(st) = self.channels.remove(&channel) {
            st.cancel.cancel();
        }
        Ok(())
    }
}

impl Drop for ClientHandler {
    fn drop(&mut self) {
        // A dropped TCP connection must still trigger graceful child shutdown.
        for st in self.channels.values() {
            st.cancel.cancel();
        }
        debug!(peer = ?self.peer, "connection handler dropped");
    }
}
