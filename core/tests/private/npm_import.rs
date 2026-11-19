use super::{
    BoundedJson, Contract, MAXIMUM_OUTPUT, SourceError, read_rows, read_source, run_read_npm_sqlite,
};
use rusqlite::Connection;
use serde_json::json;
use std::{fs, io::Write, process::ExitCode};

#[test]
fn sqlite_projection_excludes_credentials_and_bounds_the_schema() {
    let fixture = tempfile::tempdir().unwrap();
    let file = fixture.path().join("source.sqlite");
    let connection = Connection::open(&file).unwrap();
    let contract: Contract =
        serde_json::from_str(include_str!("../../src/npm-import-contract.json")).unwrap();
    for (name, columns) in &contract.tables {
        let mut columns = columns.clone();
        if name == "access_list_auth" {
            columns.push("password".into());
        }
        connection
            .execute_batch(&format!("CREATE TABLE {name} ({})", columns.join(",")))
            .unwrap();
    }
    for name in contract.migrations {
        connection
            .execute("INSERT INTO knex_migrations VALUES (?1)", [&name])
            .unwrap();
    }
    connection
        .execute(
            "INSERT INTO access_list_auth VALUES (1, 7, 'fixture-secret')",
            [],
        )
        .unwrap();
    drop(connection);
    let output = read_source(&file).unwrap_or_else(|error| panic!("{}", error.code()));
    assert_eq!(output["authCounts"][0]["count"], 1);
    assert!(!output.to_string().contains("fixture-secret"));

    for (sql, expected) in [
        (
            "WITH RECURSIVE records(id) AS (VALUES(2) UNION ALL SELECT id+1 FROM records WHERE id<501) INSERT INTO access_list_auth SELECT id, 7, NULL FROM records",
            "source_limit",
        ),
        (
            "DELETE FROM access_list_auth; INSERT INTO knex_migrations VALUES ('unexpected')",
            "unsupported_schema",
        ),
        (
            "DELETE FROM knex_migrations WHERE name = 'unexpected'; DROP TABLE stream; CREATE VIEW stream AS SELECT 1 AS id",
            "unsupported_schema",
        ),
        (
            "DROP VIEW stream; CREATE TABLE stream (id)",
            "unsupported_schema",
        ),
        ("DROP TABLE stream", "unsupported_schema"),
    ] {
        Connection::open(&file).unwrap().execute_batch(sql).unwrap();
        let Some(error) = read_source(&file).err() else {
            panic!("Invalid projection accepted");
        };
        assert_eq!(error.code(), expected);
    }
}

#[test]
fn rejects_missing_broken_or_oversized_input_and_nonscalar_columns() {
    let fixture = tempfile::tempdir().unwrap();
    let file = fixture.path().join("source.sqlite");
    assert!(matches!(read_source(&file), Err(SourceError::Invalid)));
    fs::write(&file, b"truncated").unwrap();
    assert!(matches!(read_source(&file), Err(SourceError::Invalid)));
    fs::write(&file, [0; 100]).unwrap();
    assert!(matches!(read_source(&file), Err(SourceError::Invalid)));
    assert_eq!(run_read_npm_sqlite(std::iter::empty()), ExitCode::FAILURE);
    assert_eq!(
        run_read_npm_sqlite(std::iter::once(file.to_str().unwrap().to_owned())),
        ExitCode::SUCCESS
    );

    let connection = Connection::open_in_memory().unwrap();
    let mut remaining = MAXIMUM_OUTPUT;
    let scalar = read_rows(
        &connection,
        "SELECT NULL AS missing, 0.5 AS real, 9007199254740991 AS integer, 'text' AS string",
        1,
        &mut remaining,
    )
    .unwrap_or_else(|error| panic!("{}", error.code()));
    assert_eq!(
        scalar,
        vec![json!({"missing":null,"real":0.5,"integer":9007199254740991_i64,"string":"text"})]
    );
    for sql in [
        "SELECT 9007199254740992",
        "SELECT 9.9e999",
        "SELECT CAST(X'FF' AS TEXT)",
        "SELECT X'00'",
        "not a query",
    ] {
        assert!(matches!(
            read_rows(&connection, sql, 1, &mut remaining),
            Err(SourceError::Invalid)
        ));
    }
    assert!(matches!(
        read_rows(
            &connection,
            "SELECT 1 UNION ALL SELECT 2",
            1,
            &mut remaining
        ),
        Err(SourceError::Limit)
    ));
    let mut too_small = 10;
    assert!(matches!(
        read_rows(
            &connection,
            "SELECT 'oversized' AS value",
            1,
            &mut too_small
        ),
        Err(SourceError::Limit)
    ));
    let mut bounded = BoundedJson(vec![0; MAXIMUM_OUTPUT]);
    bounded.flush().unwrap();
    assert!(bounded.write_all(b"x").is_err());
}
