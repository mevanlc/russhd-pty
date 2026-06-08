# russhd-pty — PLAN (MVP0)

A minimal SSH daemon, built on [`russh`](https://crates.io/crates/russh), that accepts any
connection and runs a single, operator-configured command inside a real OS PTY
(`nix::pty::openpty`). Bytes are pumped both directions; terminal resize is relayed to the
PTY; the child's stderr is split off to the daemon's own logs rather than the client.

> **Security note:** russhd-pty performs **no authentication** — any username/password/key
> (including the SSH `none` method) is accepted. Anyone who can reach the listening socket can
> run the configured command. This is why the default bind is loopback (see below). Treat the
> listening port as equivalent to an unauthenticated local shell to the configured command.

---

## 1. Usage

```
russhd-pty [-p|--port PORT] [-l|--listen ADDR] 'session command and args'
```

- `-p, --port PORT` — TCP port to listen on. **Default: `2222`.**
- `-l, --listen ADDR` — bind address. **Default: `127.0.0.1`.** Honored verbatim; passing
  `-l 0.0.0.0` exposes the daemon to the network with **no extra confirmation flag** required.
- `'session command and args'` — a **single** positional string, parsed with the `shlex`
  crate into `argv`. `argv[0]` is the program; the remainder are its arguments. The configured
  command is the **only** thing ever run; the client cannot choose what executes.

Operational model (per the issue): run under tmux, e.g.

```
russhd-pty -l 0.0.0.0 -p 2222 'htop' &> russhd-pty.log
```

then detach. Normal events → **stdout**; exceptional/unexpected events → **stderr**
(both captured by the `&>` redirect above).

---

## 2. Confirmed design decisions

| Topic | Decision |
|---|---|
| Auth | Accept **everything**: `none`, any password, any public key, any username. |
| Bind default | `127.0.0.1`; `-l` honored as-is, no `--insecure`/confirmation gate. |
| Default port | `2222`. |
| Client command | **Ignored.** Always run the argv-configured command. |
| `exec` requests | **Rejected.** On any `exec` request, log it and disconnect that client. Interactive shell sessions do not require exec. |
| PTY | Always allocate a real PTY for the shell session. Use `pty-req` dimensions/term if the client sent them; otherwise default to `80x24` / `TERM=xterm`. |
| child stderr | Separate **pipe** (fd 2) captured to russhd-pty **stdout** logs. Consequence: the child's stderr is **not a TTY** (may disable color / change buffering). Accepted. |
| child stdout/stdin | The PTY (fds 0 and 1). |
| Host key | **Ephemeral** ed25519, generated fresh on each startup. |
| Resize | `window-change` → `TIOCSWINSZ` on the PTY master → kernel raises `SIGWINCH` in the child. |
| Child exit | Relay exit status/signal to client, then drop the client connection for that session. |
| Client disconnect | Graceful shutdown of child: **`SIGHUP`**, wait up to **5s**, then **`SIGKILL`**. |
| russh dependency | Published `russh` crate from crates.io (current `0.61.x`). |
| Async runtime | `tokio`. |

---

## 3. Dependencies (initial `Cargo.toml`)

- `russh = "0.61"` — SSH server protocol + key types (`russh::keys` for ephemeral host key).
- `tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "io-util", "process", "time", "signal", "sync"] }`
- `tokio-util = { version = "0.7", features = ["rt"] }` — `CancellationToken` for per-session shutdown coordination.
- `nix = { version = "0.29", features = ["term", "process", "signal", "fs", "ioctl"] }` — `openpty`, `setsid`, `TIOCSCTTY`, `TIOCSWINSZ`, `kill`. *(Final feature set verified during impl.)*
- `libc` — winsize struct / ioctl request constants as needed.
- `clap = { version = "4", features = ["derive"] }` — CLI.
- `shlex = "1"` — parse the command string into argv.
- `anyhow` — top-level error handling; `thiserror` if typed errors prove useful.
- `tracing` + `tracing-subscriber` — logging (see §8). Optional; a hand-rolled logger is an acceptable fallback.

---

## 4. Module layout

```
src/
  main.rs      // CLI parse, shlex split, logging init, host key, build russh config, bind+serve
  config.rs    // Cli (clap derive) + runtime Config (SocketAddr, argv, grace timeout)
  logging.rs   // tracing subscriber: INFO/DEBUG -> stdout, WARN/ERROR -> stderr
  server.rs    // russh `Server` + per-connection `Handler` impl
  pty.rs       // openpty, set winsize, spawn child (pre_exec: setsid/TIOCSCTTY/dup2)
  session.rs   // per-session state + pump tasks + supervisor (exit / shutdown)
```

---

## 5. SSH layer (`server.rs`)

Implement `russh::server::Server` (one `Handler` per accepted connection) and
`russh::server::Handler`:

- **Auth** — return `Auth::Accept` from `auth_none`, `auth_password`, `auth_publickey`
  (and the publickey-offered/query path). Log the offered username/method at INFO.
- **`channel_open_session`** — accept; create per-channel session state.
- **`env_request`** — ignore (log at DEBUG). (`TERM` comes from `pty-req`, not `setenv`.)
- **`pty_request(term, col, row, pixw, pixh, modes)`** — record term + winsize for the channel
  and create the PTY now (so an early `window-change` can apply). `channel_success`.
- **`window_change_request(col, row, pixw, pixh)`** — update stored winsize and, if the PTY
  exists, apply `TIOCSWINSZ` to the master.
- **`shell_request`** — ensure a PTY exists (allocate `80x24`/`xterm` if no prior `pty-req`),
  spawn the configured command attached to it, launch the pump + supervisor tasks,
  `channel_success`.
- **`exec_request`** — log the attempted command, `channel_failure`, then **disconnect the
  connection**. (Negotiate-then-drop is acceptable per the decision.)
- **`data`** — write client bytes to the PTY master (stdin to the child), awaiting the async
  write via `AsyncFd`.
- **`channel_eof` / `channel_close`** — treat as client going away → trigger graceful shutdown
  for that session (cancel its `CancellationToken`).
- **`Handler` drop / connection teardown** — also cancels outstanding session tokens so a
  dropped TCP connection still triggers graceful child shutdown.

Server→client output is pushed from the pump tasks via a cloned `russh::server::Handle`
(`session.handle()`): `handle.data(channel, …)`, `eof`, `close`, `exit_status_request` /
`exit_signal_request`, `disconnect`.

> API names above follow russh 0.61 conventions; exact signatures are verified against the
> crate during implementation.

---

## 6. PTY + process (`pty.rs`)

1. `nix::pty::openpty(Some(&winsize), None)` → `OwnedFd` master + slave.
2. Create a `pipe()` for the child's stderr (parent keeps the read end).
3. Spawn via `tokio::process::Command` (`argv[0]` + args), with `unsafe { pre_exec(...) }`
   running async-signal-safe libc/nix calls in the child between fork and exec:
   - `setsid()` — new session, become session leader.
   - `ioctl(slave, TIOCSCTTY, 0)` — make the PTY the controlling terminal (enables job
     control + correct `SIGWINCH`/`SIGHUP` delivery).
   - `dup2(slave, 0)`, `dup2(slave, 1)`, `dup2(stderr_pipe_w, 2)`.
   - close the now-redundant master/slave/pipe fds.
4. Parent: close the slave + stderr-write ends; set the master + stderr-read fds non-blocking
   and wrap each in `tokio::io::unix::AsyncFd` for async read/write.
5. Child env: inherit russhd-pty's env; set `TERM` to the `pty-req` term string (default
   `xterm`). cwd/uid/gid = russhd-pty's own (no privilege change in MVP0).

Resize helper: `set_winsize(master_fd, cols, rows)` issuing `TIOCSWINSZ` with a populated
`libc::winsize`.

---

## 7. Per-session concurrency (`session.rs`)

Each shell session owns:

- the PTY master `AsyncFd`, the stderr-read `AsyncFd`, the `tokio::process::Child`,
- a clone of the connection `Handle` + the `ChannelId`,
- a `CancellationToken` (cancelled on client disconnect).

Tasks (via `tokio::select!` / `spawn`):

1. **master → client**: read PTY master → `handle.data(channel, …)`. Master read returning
   EOF/`EIO` means the child closed the PTY (it's exiting).
2. **client → master**: handled inline in `Handler::data` (async write through the master
   `AsyncFd`); no dedicated task.
3. **stderr → logs**: read the stderr pipe → write to russhd-pty **stdout** (line-oriented,
   tagged with channel id). EOF when the child exits.
4. **supervisor**: `select!` over `child.wait()` vs `token.cancelled()`:
   - **child exits first** → relay `exit-status` (normal exit code) or `exit-signal`
     (signalled), then `eof` + `close` the channel and **disconnect** the client connection
     for that session.
   - **token cancelled first** (client left) → `kill(child_pgid, SIGHUP)`, wait up to **5s**
     for `child.wait()`; if still alive, `kill(SIGKILL)`. Then close out the channel.

All tasks for a session terminate when the supervisor finishes (token cancel + joins).

---

## 8. Logging (`logging.rs`)

- Normal/operational events → **stdout**.
- Unexpected/exceptional events → **stderr**.
- Implementation: a `tracing-subscriber` registry with two `fmt` layers — one filtered to
  `INFO`/`DEBUG`/`TRACE` writing to `io::stdout`, one filtered to `WARN`/`ERROR` writing to
  `io::stderr`. Child stderr bytes are emitted as INFO-level log lines (→ stdout) so they land
  with the rest of the operational log.
- Log key lifecycle events: bind, connection accepted (peer addr), auth accepted (user/method),
  pty-req (term/size), shell start (pid), window-change, exec rejected (and the command),
  child exit (status), shutdown path taken (graceful vs force-kill).

---

## 9. Error handling

- Startup errors (bad `shlex` parse, empty command, bind failure, command not found on first
  spawn) → log to **stderr**, exit non-zero.
- Per-session errors (PTY alloc failure, spawn failure, broken pipe) → log to stderr, fail just
  that session (`channel_failure` / disconnect), keep the daemon running.
- The daemon never exits because of a single misbehaving client/session.

---

## 10. Out of scope for MVP0 (future work)

- Real authentication / authorization, per-key access control.
- Persistent host key, host-key file management.
- Per-session/per-user command selection, command allow-lists.
- SFTP, port forwarding, agent forwarding, X11, multiple subsystems.
- Configurable grace timeout / signal (hard-coded `SIGHUP` + 5s in MVP0; likely a
  `--grace-secs` / `--term-signal` flag later).
- Privilege drop / `setuid`, chroot/sandboxing.
- Rate limiting / max-connection caps.
- Relaying client `setenv` into the child.

---

## 11. Task checklist

- [ ] `cargo init --bin`; add dependencies (§3).
- [ ] `config.rs`: clap CLI + `shlex` argv parse + runtime `Config`.
- [ ] `logging.rs`: stdout/stderr split subscriber.
- [ ] `main.rs`: parse → log init → ephemeral ed25519 host key → russh `server::Config` → bind → serve loop.
- [ ] `server.rs`: `Server` + `Handler` (accept-all auth, channel/pty/shell/exec/window/data/eof/close).
- [ ] `pty.rs`: `openpty` + winsize + `pre_exec` spawn (setsid/TIOCSCTTY/dup2) + stderr pipe + `set_winsize`.
- [ ] `session.rs`: pump tasks + supervisor (exit relay; SIGHUP→5s→SIGKILL).
- [ ] Manual test: `ssh -p 2222 x@127.0.0.1` runs the command; resize the terminal and confirm the child sees `SIGWINCH`; Ctrl-C / disconnect triggers graceful shutdown; child exit drops the connection; child stderr shows in the daemon log, not the client.

---

## 12. Assumptions to flag (correct me if wrong)

- **One child per shell session**; multiple concurrent connections/sessions are supported,
  each with its own PTY + process.
- Child runs as **the same uid/gid/cwd/env** as russhd-pty (no privilege change in MVP0).
- Client `setenv`/`exec` are not honored (exec is actively rejected; setenv ignored).
- Exit status is relayed to the client (`exit-status` / `exit-signal`) before the connection is
  dropped — a small nicety beyond the bare "drop connection" requirement.
- Only the plan is produced now; no code is scaffolded until this plan is approved.
