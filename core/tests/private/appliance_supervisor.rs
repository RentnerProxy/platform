use super::{commands, files, online};
use serde_json::json;
use std::{fs, path::Path, time::Duration};
use tokio::{process::Command, time::timeout};
use tokio_util::sync::CancellationToken;

#[test]
fn enrollment_requires_an_exact_single_request() {
    let id = "0123456789abcdef0123456789abcdef";
    let key = ["fixture", "enroll", "_Ab2"].join("-");
    let valid = format!("{id}\n{key}\n");
    assert_eq!(files::enrollment_fields(&valid), Some((id, key.as_str())));
    for invalid in [
        valid.clone() + "\n",
        valid.clone() + "secret",
        valid.replace('a', " "),
        format!("{id}\nx"),
        format!("{id}\n{}", "a".repeat(257)),
    ] {
        assert!(files::enrollment_fields(&invalid).is_none());
    }
}

#[test]
fn native_console_and_machine_checks_require_typed_json_fields() {
    assert!(online::has_json_field(
        br#"[{"machineId":"rentnerproxy-managed"}]"#,
        "machineId",
        &json!("rentnerproxy-managed")
    ));
    assert!(online::has_json_field(
        br#"{"console":{"enrolled":true}}"#,
        "enrolled",
        &json!(true)
    ));
    assert!(!online::has_json_field(
        br#"{"enrolled":"true"}"#,
        "enrolled",
        &json!(true)
    ));
    assert!(!online::has_json_field(
        br#"{"note":"enrolled":true}"#,
        "enrolled",
        &json!(true)
    ));
}

#[tokio::test]
async fn cancelled_helper_and_owned_engine_are_reaped() {
    let temp = tempfile::tempdir().unwrap();
    let pid = temp.path().join("pid");
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "echo $$ > \"$1\"; exec sleep 30", "fixture"])
        .arg(&pid);
    let shutdown = commands::Helpers::new(CancellationToken::new());
    let cancel = shutdown.shutdown.clone();
    let wait_pid = pid.clone();
    let interrupt = tokio::spawn(async move {
        let pid = fixture_pid(&wait_pid).await;
        cancel.cancel();
        pid
    });
    assert!(
        timeout(
            Duration::from_secs(3),
            commands::bounded(command, 25, false, &shutdown)
        )
        .await
        .unwrap()
        .is_err()
    );
    let pid = interrupt.await.unwrap();
    assert!(!Path::new(&format!("/proc/{pid}")).exists());

    let mut engine = Some(Command::new("/bin/sleep").arg("30").spawn().unwrap());
    let pid = engine.as_ref().unwrap().id().unwrap();
    commands::stop(&mut engine).await.unwrap();
    assert!(engine.is_none());
    assert!(!Path::new(&format!("/proc/{pid}")).exists());
}

#[tokio::test]
async fn helper_capture_is_bounded_and_preserves_successful_output() {
    let shutdown = commands::Helpers::new(CancellationToken::new());
    let mut command = Command::new("/bin/echo");
    command.arg("fixture");
    assert_eq!(
        commands::bounded(command, 1, true, &shutdown)
            .await
            .unwrap(),
        b"fixture\n"
    );
    let head = |bytes| {
        let mut command = Command::new("/usr/bin/head");
        command.args(["-c", bytes, "/dev/zero"]);
        command
    };
    let full = commands::bounded(head("1048576"), 10, true, &shutdown)
        .await
        .unwrap();
    assert_eq!(full.len(), 1_048_576);
    let oversized = commands::bounded(head("1048577"), 10, true, &shutdown)
        .await
        .unwrap_err();
    assert_eq!(oversized.to_string(), "Command output exceeded limit");
}

async fn fixture_pid(path: &Path) -> u32 {
    timeout(Duration::from_secs(3), async {
        loop {
            if let Ok(text) = fs::read_to_string(path)
                && let Some(pid) = text
                    .strip_suffix('\n')
                    .and_then(|value| value.parse::<u32>().ok())
                && pid > 1
            {
                return pid;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn helper_deadline_terminates_the_recorded_descendant() {
    let temp = tempfile::tempdir().unwrap();
    let pid = temp.path().join("descendant");
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "sleep 30 & echo $! > \"$1\"; wait", "fixture"])
        .arg(&pid);
    let shutdown = commands::Helpers::new(CancellationToken::new());
    let (result, task) = tokio::join!(commands::bounded(command, 1, false, &shutdown), async {
        let pid = fixture_pid(&pid).await;
        crate::appliance_supervisor::process::open_pid(pid as i32).unwrap()
    });
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    timeout(Duration::from_secs(2), async {
        while !crate::appliance_supervisor::drain::exited(&task).unwrap() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[test]
fn console_probe_requires_authentication_and_typed_enrollment() {
    for (response, expected) in [
        (
            json!({"console":{"authenticated": false, "enrolled": true}}),
            "degraded",
        ),
        (
            json!({"console":{"authenticated": true, "enrolled": true}}),
            "connected",
        ),
        (
            json!({"console":{"authenticated": true, "enrolled": false}}),
            "pending",
        ),
        (json!({"enrolled":true}), "degraded"),
        (json!({"console":{"authenticated":true}}), "degraded"),
    ] {
        assert_eq!(
            online::console_status(&serde_json::to_vec(&response).unwrap()),
            expected
        );
    }
    assert_eq!(online::console_status(b"invalid-json"), "degraded");
}

#[tokio::test]
async fn unconfirmed_reaping_has_a_bounded_failure() {
    let mut child = Command::new("/bin/sleep")
        .arg("30")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let result = commands::reap_killed(&mut child, Duration::from_millis(1)).await;
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    child.start_kill().unwrap();
    commands::reap_killed(&mut child, Duration::from_secs(2))
        .await
        .unwrap();
}

#[tokio::test]
async fn unconfirmed_cleanup_stops_subsequent_helper_launches() {
    for (sent, reaped) in [
        (false, Ok(())),
        (true, Err(std::io::Error::other("fixture"))),
    ] {
        let helpers = commands::Helpers::new(CancellationToken::new());
        assert!(helpers.confirm_cleanup(sent, reaped).is_err());
        assert!(helpers.shutdown.is_cancelled());
        assert!(helpers.ensure_reaped().is_err());
        assert!(
            commands::bounded(Command::new("/bin/true"), 1, false, &helpers)
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn engine_ignoring_term_is_killed_and_reaped_within_the_forced_window() {
    let temp = tempfile::tempdir().unwrap();
    let pidfile = temp.path().join("pid");
    let mut engine = Some(
        Command::new("/bin/sh")
            .args([
                "-c",
                "trap '' TERM; echo $$ > \"$1\"; exec sleep 30",
                "fixture",
            ])
            .arg(&pidfile)
            .kill_on_drop(true)
            .spawn()
            .unwrap(),
    );
    let pid = fixture_pid(&pidfile).await;
    commands::stop_with_grace(&mut engine, Duration::from_millis(10))
        .await
        .unwrap();
    assert!(engine.is_none());
    assert!(!Path::new(&format!("/proc/{pid}")).exists());
}
