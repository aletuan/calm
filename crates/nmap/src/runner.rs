//! Runs Nmap for one authorized plan and stops it as a whole (ADR-011 §6).
//!
//! Nmap starts in its own process group, so stopping kills it and anything it
//! spawned. The caller decides when to stop (Stop everything, a network
//! change, a revoked or expired scope) through `should_stop`, polled while
//! Nmap runs: this module knows nothing about scopes or networks.

use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use calm_orchestrator::PlanGrant;
use nix::sys::signal::{killpg, Signal};
use nix::unistd::Pid;

use crate::command::build_args;

/// How long Nmap gets to exit after SIGTERM before SIGKILL.
pub const GRACE: Duration = Duration::from_secs(2);

/// Why a run was stopped before Nmap finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    StopEverything,
    NetworkChanged,
    ScopeEnded,
}

#[derive(Debug)]
pub struct RunOutcome {
    /// The exact argument list Nmap received (evidence, ADR-011 §7).
    pub args: Vec<String>,
    /// Nmap's XML (stdout). Partial when stopped.
    pub xml: String,
    pub stderr: String,
    /// `None` when Nmap was killed by a signal.
    pub exit_code: Option<i32>,
    pub stopped: Option<StopReason>,
}

#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error("could not start Nmap: {0}")]
    Spawn(std::io::Error),
    #[error("lost track of Nmap: {0}")]
    Wait(std::io::Error),
}

/// Run Nmap at `nmap` (the bundled binary, never looked up in PATH) for one
/// grant. `should_stop` is called every `poll` while Nmap runs.
pub fn run(
    nmap: &Path,
    grant: &PlanGrant,
    mut should_stop: impl FnMut() -> Option<StopReason>,
    poll: Duration,
) -> Result<RunOutcome, RunError> {
    let args = build_args(grant);
    let mut child = Command::new(nmap)
        .args(&args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(RunError::Spawn)?;
    // Read both pipes on threads so a chatty Nmap never blocks on a full pipe.
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());

    let mut stopped = None;
    let status = loop {
        if let Some(status) = child.try_wait().map_err(RunError::Wait)? {
            break status;
        }
        if let Some(reason) = should_stop() {
            stopped = Some(reason);
            break stop_group(&mut child)?;
        }
        thread::sleep(poll);
    };
    Ok(RunOutcome {
        args,
        xml: stdout.join().unwrap_or_default(),
        stderr: stderr.join().unwrap_or_default(),
        exit_code: status.code(),
        stopped,
    })
}

fn drain(pipe: Option<impl Read + Send + 'static>) -> thread::JoinHandle<String> {
    thread::spawn(move || {
        let mut s = String::new();
        if let Some(mut p) = pipe {
            let _ = p.read_to_string(&mut s);
        }
        s
    })
}

/// SIGTERM to the whole group, then SIGKILL after [`GRACE`].
fn stop_group(child: &mut Child) -> Result<std::process::ExitStatus, RunError> {
    // The child is its own group leader (process_group(0)), so its pid is the group id.
    let group = Pid::from_raw(child.id() as i32);
    let _ = killpg(group, Signal::SIGTERM);
    let deadline = Instant::now() + GRACE;
    loop {
        if let Some(status) = child.try_wait().map_err(RunError::Wait)? {
            // Children that ignored SIGTERM must not outlive the run.
            let _ = killpg(group, Signal::SIGKILL);
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = killpg(group, Signal::SIGKILL);
            return child.wait().map_err(RunError::Wait);
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{fake_nmap, grant, process_alive};
    use std::fs;

    const POLL: Duration = Duration::from_millis(20);

    #[test]
    fn nmap_receives_exactly_the_built_arguments_and_its_xml_comes_back() {
        let (dir, nmap) = fake_nmap("quick");
        let g = grant();
        let out = run(&nmap, &g, || None, POLL).unwrap();
        let received: Vec<String> = fs::read_to_string(dir.path().join("argv"))
            .unwrap()
            .lines()
            .map(String::from)
            .collect();
        assert_eq!(received, build_args(&g));
        assert_eq!(out.args, received);
        assert_eq!(out.xml.trim(), "<nmaprun/>");
        assert_eq!(out.exit_code, Some(0));
        assert_eq!(out.stopped, None);
    }

    #[test]
    fn nmap_runs_with_an_empty_environment() {
        let (dir, nmap) = fake_nmap("quick");
        run(&nmap, &grant(), || None, POLL).unwrap();
        let env = fs::read_to_string(dir.path().join("env")).unwrap();
        assert!(!env.contains("NMAPDIR") && !env.contains("HOME="), "{env}");
    }

    #[test]
    fn stopping_kills_nmap_and_everything_it_started() {
        let (dir, nmap) = fake_nmap("slow");
        let ready = dir.path().join("child");
        // Stop only once the fake has started its child (not after a fixed delay:
        // a new executable can take a while to start on macOS), with a cap.
        let mut polls = 0;
        let mut stop_requested: Option<Instant> = None;
        let out = run(
            &nmap,
            &grant(),
            || {
                polls += 1;
                if ready.exists() || polls > 500 {
                    stop_requested.get_or_insert_with(Instant::now);
                    Some(StopReason::StopEverything)
                } else {
                    None
                }
            },
            POLL,
        )
        .unwrap();
        assert_eq!(out.stopped, Some(StopReason::StopEverything));
        assert!(ready.exists(), "the fake never started its child");
        let took = stop_requested.expect("stop was requested").elapsed();
        assert!(
            took < GRACE + Duration::from_secs(1),
            "stopped {took:?} after the request; the grace period is {GRACE:?}"
        );
        let child: i32 = fs::read_to_string(dir.path().join("child"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        thread::sleep(Duration::from_millis(100));
        assert!(
            !process_alive(child),
            "a process Nmap spawned outlived the run"
        );
    }

    #[test]
    fn a_missing_binary_is_a_spawn_error_not_a_panic() {
        let err = run(Path::new("/nonexistent/nmap"), &grant(), || None, POLL).unwrap_err();
        assert!(matches!(err, RunError::Spawn(_)));
    }
}
