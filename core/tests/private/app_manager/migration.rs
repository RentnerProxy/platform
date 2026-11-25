use super::*;
use std::{
    fs::Permissions,
    os::unix::fs::{PermissionsExt, symlink},
};

const UID: u32 = 59184;

#[test]
fn only_the_exact_migration_comment_records_a_version() {
    assert_eq!(parse_marker(b"rentnerproxy.data-version=2\n"), Some(2));
    assert_eq!(
        parse_marker(b"rentnerproxy.data-version=2147483647\n"),
        Some(2_147_483_647)
    );
    for output in [
        b"".as_slice(),
        b"\n",
        b"app notes\n",
        b"rentnerproxy.data-version=2",
        b"rentnerproxy.data-version=\n",
        b"rentnerproxy.data-version=02\n",
        b"rentnerproxy.data-version=-1\n",
        b"rentnerproxy.data-version= 2\n",
        b"rentnerproxy.data-version=2147483648\n",
        b"rentnerproxy.data-version=2\nrentnerproxy.data-version=3\n",
    ] {
        assert_eq!(parse_marker(output), None);
    }
}

async fn query(sql: &str) -> String {
    let output = runtime::control_sql_in(&format!("rp_app_{UID}"), sql)
        .await
        .unwrap();
    String::from_utf8(output).unwrap().trim_end().to_owned()
}

/// The owner role is withdrawn and no session of the installation outlives a migration.
async fn assert_released() {
    assert_eq!(
        query(&format!(
            "SELECT pg_catalog.pg_has_role('rp_app_{UID}', 'rp_migrate_{UID}', 'SET') \
             OR EXISTS (SELECT FROM pg_catalog.pg_stat_activity \
             WHERE usename IN ('rp_app_{UID}', 'rp_migrate_{UID}'));"
        ))
        .await,
        "f"
    );
    verify_uid_stopped(UID).unwrap();
}

fn missing(table: &str) -> String {
    format!("SELECT pg_catalog.to_regclass('app.{table}') IS NULL;")
}

#[tokio::test]
#[ignore = "requires root and the app-provision.sh PostgreSQL cluster with the production pg_hba"]
async fn privileged_app_data_migrations() {
    let package = tempfile::Builder::new()
        .prefix("migration-package")
        .tempdir_in("/tmp")
        .unwrap();
    let steps = package.path().join("migrations");
    fs::create_dir(&steps).unwrap();
    for directory in [package.path(), steps.as_path()] {
        fs::set_permissions(directory, Permissions::from_mode(0o755)).unwrap();
    }
    let write = |name: &str, sql: &str| {
        let path = steps.join(name);
        fs::write(&path, sql).unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
    };
    let migration = |from, to, names: &[&str]| Migration {
        from,
        to,
        steps: names
            .iter()
            .map(|name| format!("migrations/{name}"))
            .collect(),
    };
    let evidence = tempfile::Builder::new()
        .prefix("migration-evidence")
        .tempdir_in("/tmp")
        .unwrap();
    fs::set_permissions(evidence.path(), Permissions::from_mode(0o777)).unwrap();

    assert_eq!(recorded_version(UID).await.unwrap(), None);

    // A fresh database receives its schema from the owner role, with runtime DML only.
    write(
        "initialize.sql",
        "CREATE TABLE settings (name text PRIMARY KEY, value text NOT NULL);\n\
         INSERT INTO settings VALUES ('greeting', 'hello');\n",
    );
    apply(UID, package.path(), &migration(0, 1, &["initialize.sql"]))
        .await
        .unwrap();
    assert_eq!(recorded_version(UID).await.unwrap(), Some(1));
    assert_eq!(
        query(&format!(
            "SELECT c.relowner::pg_catalog.regrole::text || ':' \
             || pg_catalog.has_table_privilege('rp_app_{UID}', c.oid, 'SELECT,INSERT,UPDATE,DELETE') || ':' \
             || pg_catalog.has_table_privilege('rp_app_{UID}', c.oid, 'TRUNCATE') \
             FROM pg_catalog.pg_class c WHERE c.oid = 'app.settings'::pg_catalog.regclass;"
        ))
        .await,
        format!("rp_migrate_{UID}:true:false")
    );
    assert_released().await;

    // An update keeps the existing rows.
    write(
        "upgrade.sql",
        "ALTER TABLE settings ADD COLUMN updated text;\nUPDATE settings SET updated = 'v2';\n",
    );
    apply(UID, package.path(), &migration(1, 2, &["upgrade.sql"]))
        .await
        .unwrap();
    assert_eq!(recorded_version(UID).await.unwrap(), Some(2));
    assert_eq!(
        query("SELECT value || '/' || updated FROM app.settings;").await,
        "hello/v2"
    );
    assert_released().await;

    // A failing step rolls back every earlier step of the same migration.
    write("audit.sql", "CREATE TABLE audit (entry text);\n");
    write(
        "broken.sql",
        "INSERT INTO audit VALUES ('lost');\nSELECT 1 / 0;\n",
    );
    apply(
        UID,
        package.path(),
        &migration(2, 3, &["audit.sql", "broken.sql"]),
    )
    .await
    .unwrap_err();
    assert_eq!(recorded_version(UID).await.unwrap(), Some(2));
    assert_eq!(query(&missing("audit")).await, "t");
    assert_released().await;

    // Leaving the owner role leaves only runtime privileges, which cannot create objects.
    write(
        "escalate.sql",
        "RESET ROLE;\nCREATE TABLE escaped (entry text);\n",
    );
    apply(UID, package.path(), &migration(2, 3, &["escalate.sql"]))
        .await
        .unwrap_err();
    assert_eq!(recorded_version(UID).await.unwrap(), Some(2));
    assert_eq!(query(&missing("escaped")).await, "t");
    assert_released().await;

    // A step outside the verified regular files is refused before any session starts.
    symlink(steps.join("initialize.sql"), steps.join("link.sql")).unwrap();
    apply(UID, package.path(), &migration(2, 3, &["link.sql"]))
        .await
        .unwrap_err();
    assert_eq!(recorded_version(UID).await.unwrap(), Some(2));

    // Client shell escapes run as the app identity and end with the migration.
    let witness = evidence.path().join("identity");
    write(
        "shell.sql",
        &format!(
            "\\! id -u > {}\n\\! sleep 60 &\nCREATE TABLE shell (entry text);\n",
            witness.display()
        ),
    );
    apply(UID, package.path(), &migration(2, 3, &["shell.sql"]))
        .await
        .unwrap();
    assert_eq!(
        fs::read_to_string(&witness).unwrap().trim(),
        UID.to_string()
    );
    assert_eq!(recorded_version(UID).await.unwrap(), Some(3));
    assert_released().await;

    // A migration past its limit ends with its processes and sessions, and rolls back.
    write(
        "slow.sql",
        "CREATE TABLE slow (entry text);\nSELECT pg_sleep(30);\n",
    );
    let error = apply_within(
        UID,
        package.path(),
        &migration(3, 4, &["slow.sql"]),
        Duration::from_secs(2),
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(recorded_version(UID).await.unwrap(), Some(3));
    assert_eq!(query(&missing("slow")).await, "t");
    assert_released().await;
}
