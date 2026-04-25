//! Child-process wrapper with tee'd log capture and readiness gating.
//!
//! Spawns a `tokio::process::Command` with stdout/stderr piped, asynchronously
//! tees both streams to disk *and* into an in-memory ring keyed for
//! `wait_for_log_line(regex, timeout)`. SIGTERM-then-SIGKILL on shutdown.

use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, OnceLock};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use regex::Regex;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex as TokioMutex;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

fn strip_ansi(s: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"\x1b\[[0-9;]*[a-zA-Z]").unwrap());
    re.replace_all(s, "").into_owned()
}

/// Default per-stream log buffer cap. Lines beyond this drop the oldest.
const RING_CAP: usize = 8192;

/// Default SIGTERM grace period before SIGKILL.
const TERM_GRACE: Duration = Duration::from_secs(5);

#[derive(Default)]
pub struct LogBuffer {
    lines: TokioMutex<Vec<String>>,
    notify: Notify,
    closed: AtomicBool,
}

impl LogBuffer {
    async fn push(&self, line: String) {
        let mut guard = self.lines.lock().await;
        if guard.len() >= RING_CAP {
            let drop_n = RING_CAP / 4;
            guard.drain(..drop_n);
        }
        guard.push(line);
        self.notify.notify_waiters();
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    /// Wait for a line matching `regex`. Scans the existing buffer first, then
    /// awaits new lines. Returns the matching line on success.
    pub async fn wait_for(&self, regex: &Regex, timeout: Duration) -> Result<String> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut scan_from = 0usize;
        loop {
            let snapshot = {
                let guard = self.lines.lock().await;
                guard.clone()
            };
            if let Some(line) = snapshot.iter().skip(scan_from).find(|l| regex.is_match(l)) {
                return Ok(line.clone());
            }
            scan_from = snapshot.len();

            if self.closed.load(Ordering::Acquire) {
                bail!(
                    "stream closed before pattern '{}' matched (last {} lines buffered)",
                    regex.as_str(),
                    snapshot.len()
                );
            }

            let now = tokio::time::Instant::now();
            if now >= deadline {
                bail!(
                    "timeout after {:?} waiting for pattern '{}'",
                    timeout,
                    regex.as_str()
                );
            }
            let remaining = deadline - now;

            let notified = self.notify.notified();
            tokio::pin!(notified);
            let _ = tokio::time::timeout(remaining, &mut notified).await;
            // On Err (timeout), the next loop iteration will check the deadline
            // and bail. On Ok, we go around and re-scan.
        }
    }

    pub async fn snapshot(&self) -> Vec<String> {
        self.lines.lock().await.clone()
    }
}

pub struct ChildProcess {
    pub name: String,
    pub stdout_path: PathBuf,
    pub stderr_path: PathBuf,
    pub stdout_buf: Arc<LogBuffer>,
    pub stderr_buf: Arc<LogBuffer>,
    child: Child,
    _stdout_task: JoinHandle<()>,
    _stderr_task: JoinHandle<()>,
}

impl ChildProcess {
    /// Spawn `cmd` with stdout/stderr piped. Logs are tee'd to
    /// `<log_dir>/<name>.{stdout,stderr}.log` and to in-memory ring buffers.
    pub async fn spawn(name: &str, mut cmd: Command, log_dir: &Path) -> Result<Self> {
        tokio::fs::create_dir_all(log_dir)
            .await
            .with_context(|| format!("create log dir {}", log_dir.display()))?;
        let stdout_path = log_dir.join(format!("{name}.stdout.log"));
        let stderr_path = log_dir.join(format!("{name}.stderr.log"));

        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = cmd
            .spawn()
            .with_context(|| format!("spawn {name}: {cmd:?}"))?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("{name} stdout missing"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow!("{name} stderr missing"))?;

        let stdout_buf = Arc::new(LogBuffer::default());
        let stderr_buf = Arc::new(LogBuffer::default());

        let stdout_task = tokio::spawn(pump_stream(
            stdout,
            stdout_path.clone(),
            Arc::clone(&stdout_buf),
            format!("{name}/stdout"),
        ));
        let stderr_task = tokio::spawn(pump_stream(
            stderr,
            stderr_path.clone(),
            Arc::clone(&stderr_buf),
            format!("{name}/stderr"),
        ));

        Ok(Self {
            name: name.to_string(),
            stdout_path,
            stderr_path,
            stdout_buf,
            stderr_buf,
            child,
            _stdout_task: stdout_task,
            _stderr_task: stderr_task,
        })
    }

    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// Wait for a regex match on stderr (where tracing-subscriber writes by
    /// default). For lines that go to stdout (e.g. fio's progress), use
    /// [`Self::wait_for_stdout`] or [`Self::wait_for_either`].
    pub async fn wait_for_stderr(&self, regex: &Regex, timeout: Duration) -> Result<String> {
        self.stderr_buf.wait_for(regex, timeout).await
    }

    pub async fn wait_for_stdout(&self, regex: &Regex, timeout: Duration) -> Result<String> {
        self.stdout_buf.wait_for(regex, timeout).await
    }

    pub async fn wait_for_either(&self, regex: &Regex, timeout: Duration) -> Result<String> {
        let out = Arc::clone(&self.stdout_buf);
        let err = Arc::clone(&self.stderr_buf);
        let re_a = regex.clone();
        let re_b = regex.clone();
        tokio::select! {
            r = async move { out.wait_for(&re_a, timeout).await } => r,
            r = async move { err.wait_for(&re_b, timeout).await } => r,
        }
    }

    /// SIGTERM, wait up to [`TERM_GRACE`], SIGKILL fallback.
    pub async fn shutdown(mut self) -> Result<ExitStatus> {
        if let Some(pid) = self.child.id() {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid as i32),
                nix::sys::signal::Signal::SIGTERM,
            );
        }
        let status = match tokio::time::timeout(TERM_GRACE, self.child.wait()).await {
            Ok(res) => res.context("waiting for child after SIGTERM")?,
            Err(_) => {
                tracing::warn!(name = %self.name, "child did not exit on SIGTERM, sending SIGKILL");
                let _ = self.child.start_kill();
                self.child
                    .wait()
                    .await
                    .context("waiting for child after SIGKILL")?
            }
        };
        self.stdout_buf.close();
        self.stderr_buf.close();
        Ok(status)
    }

    /// Try-wait without consuming. Returns Some(status) if the process has
    /// exited, None otherwise.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        Ok(self.child.try_wait()?)
    }
}

async fn pump_stream<R: AsyncRead + Unpin>(
    src: R,
    path: PathBuf,
    buf: Arc<LogBuffer>,
    label: String,
) {
    let mut reader = BufReader::new(src).lines();
    let mut file = match tokio::fs::File::create(&path).await {
        Ok(f) => f,
        Err(err) => {
            tracing::error!(label = %label, error = %err, "open log file failed");
            buf.close();
            return;
        }
    };
    use tokio::io::AsyncWriteExt;
    loop {
        match reader.next_line().await {
            Ok(Some(line)) => {
                let stripped = strip_ansi(&line);
                if let Err(err) = file.write_all(stripped.as_bytes()).await {
                    tracing::warn!(label = %label, error = %err, "log write failed");
                }
                let _ = file.write_all(b"\n").await;
                buf.push(stripped).await;
            }
            Ok(None) => break,
            Err(err) => {
                tracing::warn!(label = %label, error = %err, "log read failed");
                break;
            }
        }
    }
    let _ = file.flush().await;
    buf.close();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_ansi_removes_colors() {
        let raw = "\x1b[2m2026-04-26\x1b[0m \x1b[32m INFO\x1b[0m foo: dev_id=\x1b[0m0";
        assert_eq!(strip_ansi(raw), "2026-04-26  INFO foo: dev_id=0");
    }

    #[tokio::test]
    async fn buffer_matches_existing_line() {
        let buf = Arc::new(LogBuffer::default());
        buf.push("nothing".into()).await;
        buf.push("hello world".into()).await;
        let re = Regex::new("hello").unwrap();
        let got = buf
            .wait_for(&re, Duration::from_millis(10))
            .await
            .unwrap();
        assert_eq!(got, "hello world");
    }

    #[tokio::test]
    async fn buffer_waits_for_late_line() {
        let buf = Arc::new(LogBuffer::default());
        let buf2 = Arc::clone(&buf);
        let writer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            buf2.push("ready".into()).await;
        });
        let re = Regex::new("ready").unwrap();
        let got = buf
            .wait_for(&re, Duration::from_millis(500))
            .await
            .unwrap();
        assert_eq!(got, "ready");
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn buffer_times_out() {
        let buf = Arc::new(LogBuffer::default());
        let re = Regex::new("never").unwrap();
        let err = buf
            .wait_for(&re, Duration::from_millis(20))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("timeout"), "got: {err}");
    }

    #[tokio::test]
    async fn buffer_bails_on_close() {
        let buf = Arc::new(LogBuffer::default());
        let buf2 = Arc::clone(&buf);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            buf2.close();
        });
        let re = Regex::new("never").unwrap();
        let err = buf
            .wait_for(&re, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("closed"), "got: {err}");
    }
}
