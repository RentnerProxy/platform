use super::{Budget, budget, drain};
use crate::appliance_supervisor::process::owned_pid;
use std::{
    process::{Command, Stdio},
    time::Duration,
};

#[test]
fn preserves_appliance_stop_budgets_and_forced_stop_policy() {
    for (phase, seconds) in [
        ("apps", 18),
        ("controller", 23),
        ("web", 23),
        ("crowdsec", 40),
    ] {
        let budget = budget(phase).unwrap();
        assert_eq!(budget.term, Duration::from_secs(seconds));
        assert_eq!(budget.forced, None);
    }
    let web = budget("web-recovery").unwrap();
    assert_eq!(web.term, Duration::from_secs(18));
    assert_eq!(web.forced, Some(Duration::from_secs(2)));
}

#[test]
fn forced_stop_fails_backup_and_can_prove_isolated_web_exit() {
    use std::io::{BufRead, BufReader};
    for forced in [None, Some(Duration::from_secs(1))] {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "trap '' TERM; echo ready; exec sleep 30"])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut ready = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        let task = owned_pid(child.id() as i32, std::process::id() as i32, None).unwrap();
        assert_eq!(
            drain(
                &[task],
                &[],
                Budget {
                    term: Duration::from_millis(10),
                    forced
                }
            )
            .is_ok(),
            forced.is_some()
        );
        assert!(!child.wait().unwrap().success());
    }
}

#[test]
fn critical_exit_blocks_drain_even_if_the_target_is_already_gone() {
    let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    let critical = owned_pid(child.id() as i32, std::process::id() as i32, None).unwrap();
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(drain(&[], &[critical], budget("apps").unwrap()).is_err());
}

#[test]
fn already_reaped_pinned_target_satisfies_both_signal_phases() {
    let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    let task = owned_pid(child.id() as i32, std::process::id() as i32, None).unwrap();
    child.kill().unwrap();
    child.wait().unwrap();
    for signal in [libc::SIGTERM, libc::SIGKILL] {
        super::signal_remaining(&task, signal).unwrap();
    }
}
