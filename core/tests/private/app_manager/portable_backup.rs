use super::*;

const BACKUP: &str = "a";
const OTHER: &str = "b";

fn marker(digest: &str, complete: bool, retiring: bool) -> RestoreMarker {
    RestoreMarker {
        digest: digest.repeat(64),
        complete,
        retiring,
    }
}

fn target(marker: Option<RestoreMarker>, installed: bool, published: bool) -> io::Result<Destination> {
    destination(marker.as_ref(), &BACKUP.repeat(64), installed, published)
}

#[test]
fn installed_apps_are_replaced_only_without_a_pending_restore_of_another_backup() {
    assert_eq!(target(None, false, false).unwrap(), Destination::Fresh);
    assert_eq!(target(None, true, false).unwrap(), Destination::Replacing);
    // A completed restore of another backup leaves no obligation.
    for installed in [false, true] {
        let expected = if installed {
            Destination::Replacing
        } else {
            Destination::Fresh
        };
        assert_eq!(
            target(Some(marker(OTHER, true, false)), installed, false).unwrap(),
            expected
        );
    }
    // A pending restore of another backup must finish first, whatever the journal holds.
    for (installed, retiring) in [(false, false), (true, false), (true, true)] {
        assert!(target(Some(marker(OTHER, false, retiring)), installed, false).is_err());
    }
}

#[test]
fn the_same_backup_resumes_its_retirement_and_restore() {
    for installed in [false, true] {
        assert_eq!(
            target(Some(marker(BACKUP, false, true)), installed, false).unwrap(),
            Destination::Replacing
        );
    }
    assert_eq!(
        target(Some(marker(BACKUP, false, false)), false, false).unwrap(),
        Destination::Resuming
    );
    // The journal is published before the marker completes.
    for complete in [false, true] {
        assert_eq!(
            target(Some(marker(BACKUP, complete, false)), true, true).unwrap(),
            Destination::Published
        );
    }
    assert!(target(Some(marker(BACKUP, false, false)), true, false).is_err());
    // Apps that ran after a completed restore of this backup are replaced again.
    assert_eq!(
        target(Some(marker(BACKUP, true, false)), true, false).unwrap(),
        Destination::Replacing
    );
}

#[test]
fn markers_record_a_retirement_only_while_it_is_pending() {
    let legacy: RestoreMarker =
        serde_json::from_str(&format!(r#"{{"digest":"{}","complete":false}}"#, BACKUP.repeat(64)))
            .unwrap();
    assert!(!legacy.retiring);
    let finished = serde_json::to_value(marker(BACKUP, true, false)).unwrap();
    assert!(finished.get("retiring").is_none());
    let pending = serde_json::to_value(marker(BACKUP, false, true)).unwrap();
    assert_eq!(pending["retiring"], true);
    assert!(
        serde_json::from_str::<RestoreMarker>(&format!(
            r#"{{"digest":"{}","complete":false,"unknown":true}}"#,
            BACKUP.repeat(64)
        ))
        .is_err()
    );
}
