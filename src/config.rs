//! CLI parsing (`clap`) and the runtime [`Config`] derived from it.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Parser;

/// Graceful-shutdown grace period: time a child is given to exit after `SIGHUP`
/// before it is `SIGKILL`ed. Hard-coded in MVP0 (see PLAN §10).
pub const GRACE: Duration = Duration::from_secs(5);

/// Raw command-line arguments.
#[derive(Debug, Parser)]
#[command(
    name = "russhd-pty",
    about = "Minimal SSH daemon that runs a single operator-configured command in a PTY.",
    long_about = "Accepts ANY connection (no authentication) and runs the configured command \
                  inside a real OS PTY. Anyone who can reach the listening socket can run the \
                  command, which is why the default bind is loopback."
)]
pub struct Cli {
    /// TCP port to listen on.
    #[arg(short = 'p', long = "port", default_value_t = 2222)]
    pub port: u16,

    /// Bind address. Honored verbatim; `-l 0.0.0.0` exposes the daemon to the
    /// network with no extra confirmation required.
    #[arg(short = 'l', long = "listen", default_value = "127.0.0.1")]
    pub listen: IpAddr,

    /// The single command (with args) to run for every session, e.g. `'htop'`.
    /// Parsed with `shlex` into argv; argv[0] is the program.
    #[arg(value_name = "COMMAND")]
    pub command: String,
}

/// Validated runtime configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Address to bind the listening socket to.
    pub addr: SocketAddr,
    /// The argv to execute for each session. Non-empty; `argv[0]` is the program.
    pub argv: Vec<String>,
    /// Grace period before force-killing a child during shutdown.
    pub grace: Duration,
}

impl Config {
    /// Build a [`Config`] from parsed [`Cli`] args, validating the command string.
    pub fn from_cli(cli: Cli) -> Result<Self> {
        let argv = shlex::split(&cli.command)
            .context("failed to parse command string (unbalanced quotes?)")?;
        if argv.is_empty() {
            bail!("command string parsed to an empty argv; nothing to run");
        }
        Ok(Config {
            addr: SocketAddr::new(cli.listen, cli.port),
            argv,
            grace: GRACE,
        })
    }
}
