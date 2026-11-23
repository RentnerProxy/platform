use super::{Budget, budget, drain};
use crate::appliance_supervisor::process::owned_pid;
use std::{
    io::{BufRead, BufReader},
    os::unix::process::ExitStatusExt,
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
        assert_eq!(child.wait().unwrap().signal(), Some(libc::SIGKILL));
    }
}

#[test]
fn app_drain_waits_until_the_child_catches_sigterm() {
    let mut child = Command::new("/bin/sh")
        .args([
            "-c",
            "echo starting; sleep 0.25; trap 'exit 0' TERM; while :; do sleep 0.05; done",
        ])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut starting = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut starting)
        .unwrap();
    assert_eq!(starting.trim(), "starting");
    let args = [child.id().to_string(), "--".to_owned()];
    let result = super::drain_children(
        "apps",
        &args,
        std::process::id() as i32,
        budget("apps").unwrap(),
    );
    if result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait().unwrap();
    result.unwrap();
    assert!(status.success());
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

#[test]
fn maintenance_accepts_already_gone_targets_and_requires_every_critical_child() {
    let mut child = Command::new("/bin/true").spawn().unwrap();
    let target = child.id().to_string();
    child.wait().unwrap();
    let parent = std::process::id() as i32;
    let verify =
        |args: &[String]| super::drain_children("apps", args, parent, budget("apps").unwrap());
    verify(&[target.clone(), "--".into()]).unwrap();
    assert!(verify(&["--".into(), target]).is_err());
    let mut live = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    let wrong_parent = live.id() as i32;
    let args = [live.id().to_string(), "--".into()];
    let result = super::drain_children("apps", &args, wrong_parent, budget("apps").unwrap());
    live.kill().unwrap();
    live.wait().unwrap();
    assert!(result.is_err());
}
