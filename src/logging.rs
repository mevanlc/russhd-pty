//! Logging setup: operational events to **stdout**, exceptional events to **stderr**.
//!
//! Implemented as a `tracing-subscriber` registry with two `fmt` layers: one
//! capturing `INFO`/`DEBUG`/`TRACE` to stdout, one capturing `WARN`/`ERROR` to
//! stderr. The split lets the operator route the two streams independently (the
//! PLAN's `&>` redirect captures both into one file).
//!
//! `RUST_LOG` is honored for target/verbosity selection (default
//! `info,russhd_pty=debug`); the severity split is layered on top so each event
//! lands on exactly one stream.

use std::io;

use tracing::Level;
use tracing_subscriber::filter::{EnvFilter, FilterExt, filter_fn};
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

fn env_filter() -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,russhd_pty=debug"))
}

/// Install the global tracing subscriber. Call once at startup.
pub fn init() {
    // tracing `Level` orders ERROR < WARN < INFO < DEBUG < TRACE, so
    // `>= INFO` selects the operational stream and `<= WARN` the exceptional one.
    let stdout_layer = fmt::layer()
        .with_writer(io::stdout)
        .with_filter(env_filter().and(filter_fn(|m| *m.level() >= Level::INFO)));

    let stderr_layer = fmt::layer()
        .with_writer(io::stderr)
        .with_filter(env_filter().and(filter_fn(|m| *m.level() <= Level::WARN)));

    tracing_subscriber::registry()
        .with(stdout_layer)
        .with(stderr_layer)
        .init();
}
