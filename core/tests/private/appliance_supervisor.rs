use super::{commands, files, online};
use serde_json::json;
use std::{fs, path::Path, time::Duration};
use tokio::{process::Command, time::timeout};
use tokio_util::sync::CancellationToken;

#[test]
fn enrollment_requires_an_exact_single_request() {
    let id = "0123456789abcdef0123456789abcdef";
    let key = ["fixture", "_Ab2"].join("-");
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
    let shutdown = CancellationToken::new();
    let cancel = shutdown.clone();
    let wait_pid = pid.clone();
    let interrupt = tokio::spawn(async move {
        while !wait_pid.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        cancel.cancel();
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
    interrupt.await.unwrap();
    let pid = fs::read_to_string(pid).unwrap();
    assert!(!Path::new(&format!("/proc/{}", pid.trim())).exists());

    let mut engine = Some(Command::new("/bin/sleep").arg("30").spawn().unwrap());
    let pid = engine.as_ref().unwrap().id().unwrap();
    commands::stop(&mut engine).await.unwrap();
    assert!(engine.is_none());
    assert!(!Path::new(&format!("/proc/{pid}")).exists());
}

#[tokio::test]
async fn helper_capture_is_bounded_and_preserves_successful_output() {
    let shutdown = CancellationToken::new();
    let mut command = Command::new("/bin/echo");
    command.arg("fixture");
    assert_eq!(
        commands::bounded(command, 1, true, &shutdown)
            .await
            .unwrap(),
        b"fixture\n"
    );
    let mut command = Command::new("/usr/bin/head");
    command.args(["-c", "1048577", "/dev/zero"]);
    assert!(
        commands::bounded(command, 1, true, &shutdown)
            .await
            .is_err()
    );
}
