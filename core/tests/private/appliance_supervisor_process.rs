use super::{owned_pid, signal_task, stat_identity};
use std::{fs, process::Command};

#[test]
fn signals_only_owned_pinned_task_with_matching_start_time() {
    let mut child = Command::new("sleep").arg("30").spawn().unwrap();
    let pid = child.id() as i32;
    let stat = fs::read(format!("/proc/{pid}/stat")).unwrap();
    let (parent, ticks) = stat_identity(&stat).unwrap();
    assert_eq!(parent, std::process::id() as i32);
    assert!(owned_pid(pid, parent + 1, Some(ticks)).is_err());
    assert!(owned_pid(pid, parent, Some(ticks + 1)).is_err());
    assert!(child.try_wait().unwrap().is_none());
    let task = owned_pid(pid, parent, Some(ticks)).unwrap();
    signal_task(&task, libc::SIGTERM).unwrap();
    assert!(!child.wait().unwrap().success());
    assert!(signal_task(&task, libc::SIGKILL).is_err());
}

#[test]
fn start_time_follows_the_last_parenthesis_even_with_non_utf8_comm() {
    let mut stat = b"349 (fake )\xff name) S 17".to_vec();
    stat.extend_from_slice(b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 317 0");
    assert_eq!(stat_identity(&stat).unwrap(), (17, 317));
}
