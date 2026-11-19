use super::{Contract, SourceError, read_source};
use rusqlite::Connection;

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

    let connection = Connection::open(&file).unwrap();
    connection
        .execute_batch("DROP TABLE stream; CREATE VIEW stream AS SELECT 1 AS id")
        .unwrap();
    drop(connection);
    assert!(matches!(read_source(&file), Err(SourceError::Unsupported)));
}
