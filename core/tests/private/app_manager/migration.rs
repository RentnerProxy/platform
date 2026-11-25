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

#[test]
fn steps_stay_plain_sql_inside_the_runner_transaction() {
    for sql in [
        "",
        "CREATE TABLE settings (name text PRIMARY KEY, value text NOT NULL);\nINSERT INTO settings VALUES ('a;b', 'COMMIT');",
        "-- COMMIT; \\! id\nSELECT 1; /* outer /* COMMIT; */ END; */ SELECT 2",
        "SELECT 'it''s; COMMIT', E'quote\\'; COMMIT', \"odd;\"\"name\", U&'\\0041';",
        "DO $$ BEGIN COMMIT; END $$; DO $body$ BEGIN PERFORM 1; END; $body$ LANGUAGE plpgsql;",
        "PREPARE fetch_setting AS SELECT value FROM settings WHERE name = $1; SELECT a$b FROM t$1;",
        "SAVEPOINT step; RELEASE SAVEPOINT step; ROLLBACK TO step; ROLLBACK WORK TO SAVEPOINT step;",
        "CREATE FUNCTION one() RETURNS int LANGUAGE sql BEGIN ATOMIC SELECT 1; SELECT CASE WHEN true THEN 1 END; END;\nSELECT one();",
        "create or replace procedure tidy() language sql begin atomic delete from settings; end; call tidy();",
        "SELECT (SELECT 1; END);",
    ] {
        assert!(plain_sql(sql.as_bytes()), "{sql}");
    }
    for sql in [
        "COMMIT;",
        "SELECT 1; commit",
        "UPDATE settings SET value = 'x'; END;",
        "ROLLBACK;",
        "rollback work;",
        "ABORT;",
        "BEGIN;",
        "START TRANSACTION;",
        "PREPARE TRANSACTION 'held';",
        "COMMIT PREPARED 'held';",
        "SELECT 'it''s'; /* nested /* */ still */ COMMIT;",
        "SELECT E'\\''; COMMIT;",
        "DO $tag$ SELECT 1 $tag$; COMMIT;",
        "\\! id",
        "SELECT 1; \\c other",
        "SELECT 1 \\gexec",
        "SELECT 'unterminated",
        "SELECT \"unterminated",
        "/* unterminated",
        "DO $$ unterminated",
        "CREATE FUNCTION one() RETURNS int LANGUAGE sql BEGIN ATOMIC SELECT 1; END; COMMIT;",
    ] {
        assert!(!plain_sql(sql.as_bytes()), "{sql}");
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

    // psql commands and transaction control are refused before any session starts, so no step
    // reaches a shell and no step commits without the rest.
    let witness = evidence.path().join("identity");
    write(
        "shell.sql",
        &format!(
            "\\! id -u > {}\nCREATE TABLE shell (entry text);\n",
            witness.display()
        ),
    );
    write("split.sql", "CREATE TABLE split (entry text);\nCOMMIT;\n");
    for step in ["shell.sql", "split.sql"] {
        apply(UID, package.path(), &migration(2, 3, &["audit.sql", step]))
            .await
            .unwrap_err();
    }
    assert!(!witness.exists());
    assert_eq!(recorded_version(UID).await.unwrap(), Some(2));
    for table in ["audit", "shell", "split"] {
        assert_eq!(query(&missing(table)).await, "t");
    }
    assert_released().await;
    write("journal.sql", "CREATE TABLE journal (entry text);\n");
    apply(UID, package.path(), &migration(2, 3, &["journal.sql"]))
        .await
        .unwrap();
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

    // A cancelled activation drops the migration with its whole process group. The next fence
    // withdraws the grant and ends the session it left behind.
    write(
        "cancelled.sql",
        "CREATE TABLE cancelled (entry text);\nSELECT pg_sleep(30);\n",
    );
    let cancelled = migration(3, 4, &["cancelled.sql"]);
    tokio::time::timeout(
        Duration::from_secs(2),
        apply(UID, package.path(), &cancelled),
    )
    .await
    .unwrap_err();
    wait_stopped(UID).await.unwrap();
    assert_eq!(
        query(&format!(
            "SELECT pg_catalog.pg_has_role('rp_app_{UID}', 'rp_migrate_{UID}', 'SET');"
        ))
        .await,
        "t"
    );
    runtime::fence_database(UID).await.unwrap();
    assert_released().await;
    assert_eq!(recorded_version(UID).await.unwrap(), Some(3));
    assert_eq!(query(&missing("cancelled")).await, "t");
}
