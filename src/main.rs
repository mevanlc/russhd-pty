//! russhd-pty — a minimal, **unauthenticated** SSH daemon that runs a single
//! operator-configured command inside a real OS PTY. See `devdocs/PLAN-MVP0.md`.

mod config;
mod logging;
mod pty;
mod server;
mod session;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use russh::MethodSet;
use russh::keys::{Algorithm, PrivateKey};
use russh::server::Server as _;
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::config::{Cli, Config};
use crate::server::Server;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    logging::init();

    let config = Arc::new(Config::from_cli(cli)?);

    // Loud, unconditional reminder: this daemon authenticates no one.
    warn!(
        "AUTHENTICATION DISABLED: any client reaching {} can run {:?}",
        config.addr, config.argv
    );
    if !config.addr.ip().is_loopback() {
        warn!(
            "binding non-loopback address {} — the configured command is exposed to the network",
            config.addr
        );
    }

    // Ephemeral host key: regenerated every startup (PLAN §2). Clients that pinned
    // a previous key will see a host-key-changed warning; acceptable for MVP0.
    let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .context("failed to generate ephemeral ed25519 host key")?;

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

    let mut server = Server::new(config.clone());
    let running = server.run_on_socket(russh_config, &listener);
    let shutdown = running.handle();

    // Graceful shutdown on Ctrl-C / SIGINT.
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            info!("shutdown signal received");
            shutdown.shutdown("daemon shutting down".to_string());
        }
    });

    running.await.context("server loop failed")?;
    info!("server stopped");
    Ok(())
}
