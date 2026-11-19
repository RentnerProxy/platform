use std::process::ExitCode;

use super::{check, run_check_backup_state};

#[test]
fn metadata_validation_requires_exactly_one_kind() {
    for command in [&[][..], &["certificate-index", "unexpected"]] {
        assert_eq!(
            run_check_backup_state(command.iter().map(|value| (*value).to_owned())),
            ExitCode::FAILURE
        );
    }
}

#[test]
fn applies_runtime_dns_admission_without_opening_a_state_store() {
    let accepted = br#"{"version":1,"connections":[]}"#;
    let rejected = br#"{"version":2,"connections":[]}"#;
    assert!(check("dns-registry", accepted.as_slice()).unwrap());
    assert!(!check("dns-registry", rejected.as_slice()).unwrap());
    assert!(!check("certificate-index", b"broken".as_slice()).unwrap());
    assert!(!check("unknown", accepted.as_slice()).unwrap());
}

#[test]
fn accepts_legacy_certificate_index_but_rejects_an_invalid_journal() {
    let legacy = br#"{"certificates":{},"eventJournalVersion":0}"#;
    let invalid = br#"{"certificates":{},"eventJournalVersion":2}"#;
    assert!(check("certificate-index", legacy.as_slice()).unwrap());
    assert!(!check("certificate-index", invalid.as_slice()).unwrap());
    let oversized = vec![b' '; 1024 * 1024 + 1];
    assert!(!check("dns-registry", oversized.as_slice()).unwrap());
}
