//! russhd-pty — a minimal, **unauthenticated** SSH daemon that runs a single
//! operator-configured command inside a real OS PTY. See `devdocs/PLAN-MVP0.md`.

mod config;
mod hostkey;
mod logging;
mod pty;
mod server;
mod session;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use russh::MethodSet;
use russh::server::Server as _;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{info, warn};

use crate::config::{Cli, Config};
use crate::server::Server;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    logging::init();

    let config = Arc::new(Config::from_cli(cli)?);

    // Loud, unconditional reminder: this daemon verifies no credentials. An
    // allow-list (if set) only restricts *which usernames* may connect — it does
    // not authenticate them (any password/key is accepted for a listed name).
    match &config.allowed_usernames {
        Some(allowed) => warn!(
            "NO CREDENTIAL CHECK: any client reaching {} with a username in {:?} can run {:?}",
            config.addr, allowed, config.argv
        ),
        None => warn!(
            "AUTHENTICATION DISABLED: any client reaching {} can run {:?}",
            config.addr, config.argv
        ),
    }
    if !config.addr.ip().is_loopback() {
        warn!(
            "binding non-loopback address {} — the configured command is exposed to the network",
            config.addr
        );
    }

    // Persistent host key: loaded from ~/.config/russhd-pty/ if present, else
    // generated and saved there so it survives restarts (no host-key-changed
    // warning for clients that pinned it).
    let host_key = hostkey::load_or_generate()?;

    let russh_config = Arc::new(russh::server::Config {
        methods: MethodSet::all(),
        auth_rejection_time: Duration::from_secs(1),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        keys: vec![host_key],
        // A passive viewer (e.g. htop) may send no input for long stretches, so
        // don't GC on input inactivity; use keepalives to detect dead peers.
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(60)),
        keepalive_max: 3,
        ..Default::default()
    });

    let listener = TcpListener::bind(config.addr)
        .await
        .with_context(|| format!("failed to bind {}", config.addr))?;
    info!(addr = %config.addr, "listening");

    // Drives child teardown across ALL sessions: every session's cancel token is a
    // child of this root, so cancelling it trips each supervisor's SIGHUP→grace→
    // SIGKILL path at once — without waiting on per-connection handler drops.
    let root_cancel = CancellationToken::new();
    // Tracks the per-session supervisor tasks so shutdown can wait for the children
    // to actually be reaped (or SIGKILLed) before the process exits.
    let tracker = TaskTracker::new();

    let mut server = Server::new(config.clone(), root_cancel.clone(), tracker.clone());
    let running = server.run_on_socket(russh_config, &listener);
    let shutdown = running.handle();

    // Graceful shutdown on SIGINT (Ctrl-C) or SIGTERM (service stop). Stop the
    // accept loop and signal every live session to tear its child down.
    {
        let root_cancel = root_cancel.clone();
        tokio::spawn(async move {
            wait_for_shutdown_signal().await;
            info!("shutdown signal received");
            shutdown.shutdown("daemon shutting down".to_string());
            root_cancel.cancel();
        });
    }

    running.await.context("server loop failed")?;

    // The accept loop has stopped; make sure no children are left behind. Cancel
    // (idempotent — the signal handler may have already done so) to cover a server
    // loop that ended for some reason other than our signal handler, then wait for
    // the supervisors to finish their teardown. Bound the wait so a wedged child
    // (e.g. stuck in uninterruptible sleep after SIGKILL) can't hang shutdown.
    root_cancel.cancel();
    tracker.close();
    let teardown_budget = config.grace + Duration::from_secs(2);
    match timeout(teardown_budget, tracker.wait()).await {
        Ok(()) => info!("all sessions terminated"),
        Err(_) => warn!(
            "timed out after {:?} waiting for sessions to terminate; some children may survive as orphans",
            teardown_budget
        ),
    }

    info!("server stopped");
    Ok(())
}

/// Resolve once either SIGINT (Ctrl-C) or SIGTERM is received.
async fn wait_for_shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    // If we can't install the SIGTERM handler, fall back to SIGINT only rather
    // than aborting startup.
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "failed to install SIGTERM handler; handling SIGINT only");
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    tokio::select! {
        r = tokio::signal::ctrl_c() => {
            if let Err(e) = r {
                warn!(error = %e, "failed to listen for SIGINT");
            }
        }
        _ = sigterm.recv() => {}
    }
}
