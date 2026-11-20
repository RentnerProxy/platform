use std::{
    collections::{BTreeMap, HashSet},
    io::{self, Write},
    path::Path,
    process::ExitCode,
    time::{Duration, Instant},
};

use rusqlite::{Connection, OpenFlags, limits::Limit, types::ValueRef};
use serde::Deserialize;
use serde_json::{Map, Number, Value, json};

const MAXIMUM_INPUT: u64 = 32 * 1024 * 1024;
const MAXIMUM_OUTPUT: usize = 32 * 1024 * 1024;
const MAXIMUM_ROWS: usize = 500;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Contract {
    migrations: Vec<String>,
    tables: BTreeMap<String, Vec<String>>,
    queries: BTreeMap<String, String>,
}

#[derive(Clone, Copy)]
enum SourceError {
    Invalid,
    Unsupported,
    Limit,
}

impl SourceError {
    fn code(self) -> &'static str {
        match self {
            Self::Invalid => "invalid_source",
            Self::Unsupported => "unsupported_schema",
            Self::Limit => "source_limit",
        }
    }
}

pub fn run_read_npm_sqlite(mut arguments: impl Iterator<Item = String>) -> ExitCode {
    let (Some(input), None) = (arguments.next(), arguments.next()) else {
        return ExitCode::FAILURE;
    };
    let value = match read_source(Path::new(&input)) {
        Ok(document) => json!({"source": document}),
        Err(error) => json!({"error": error.code()}),
    };
    let mut stdout = io::stdout().lock();
    let mut output = BoundedJson(Vec::new());
    let result = if serde_json::to_writer(&mut output, &value).is_ok() {
        stdout.write_all(&output.0)
    } else {
        stdout.write_all(b"{\"error\":\"source_limit\"}")
    };
    if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn read_source(path: &Path) -> Result<Value, SourceError> {
    let (_file, metadata) = marketplace_artifacts::open_regular(path, MAXIMUM_INPUT)
        .map_err(|_| SourceError::Invalid)?;
    if metadata.len() < 100 {
        return Err(SourceError::Invalid);
    }
    let mut connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| SourceError::Invalid)?;
    connection
        .set_limit(Limit::SQLITE_LIMIT_ATTACHED, 0)
        .map_err(|_| SourceError::Invalid)?;
    connection
        .set_limit(Limit::SQLITE_LIMIT_LENGTH, 1_048_576)
        .map_err(|_| SourceError::Invalid)?;
    connection
        .execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY;")
        .map_err(|_| SourceError::Invalid)?;
    let deadline = Instant::now() + Duration::from_secs(4);
    connection
        .progress_handler(1000, Some(move || Instant::now() >= deadline))
        .map_err(|_| SourceError::Invalid)?;

    let contract: Contract = serde_json::from_str(include_str!("npm-import-contract.json"))
        .expect("invalid NPM contract");
    validate_schema(&connection, &contract)?;
    let count: i64 = connection
        .query_row("select count(*) from access_list_auth", [], |row| {
            row.get(0)
        })
        .map_err(|_| SourceError::Invalid)?;
    if count > MAXIMUM_ROWS as i64 {
        return Err(SourceError::Limit);
    }

    let mut output = Map::from_iter([("schema".into(), Value::String("npm-2.16-schema".into()))]);
    let mut remaining = MAXIMUM_OUTPUT;
    for (name, query) in contract.queries {
        output.insert(
            name,
            Value::Array(read_rows(
                &connection,
                &query,
                MAXIMUM_ROWS,
                &mut remaining,
            )?),
        );
    }
    Ok(Value::Object(output))
}

fn validate_schema(connection: &Connection, contract: &Contract) -> Result<(), SourceError> {
    let mut remaining = MAXIMUM_OUTPUT;
    let objects = read_rows(
        connection,
        "select name, type, sql from sqlite_schema where name not like 'sqlite_%' limit 1025",
        1024,
        &mut remaining,
    )?;
    let objects: BTreeMap<_, _> = objects
        .iter()
        .filter_map(|object| object["name"].as_str().map(|name| (name, object)))
        .collect();
    for (table, required) in &contract.tables {
        let Some(object) = objects.get(table.as_str()) else {
            return Err(SourceError::Unsupported);
        };
        let ordinary_table = object["sql"].as_str().is_some_and(|sql| {
            let mut words = sql.split_ascii_whitespace();
            words
                .next()
                .is_some_and(|word| word.eq_ignore_ascii_case("create"))
                && words
                    .next()
                    .is_some_and(|word| word.eq_ignore_ascii_case("table"))
        });
        if object["type"] != "table" || !ordinary_table {
            return Err(SourceError::Unsupported);
        }
        let columns = read_rows(
            connection,
            &format!("pragma table_info({table})"),
            256,
            &mut remaining,
        )?;
        let columns: HashSet<_> = columns
            .iter()
            .filter_map(|row| row["name"].as_str())
            .collect();
        if required.iter().any(|name| !columns.contains(name.as_str())) {
            return Err(SourceError::Unsupported);
        }
    }
    let migrations = read_rows(
        connection,
        "select name from knex_migrations limit 100",
        100,
        &mut remaining,
    )?;
    let installed: HashSet<_> = migrations
        .iter()
        .filter_map(|row| row["name"].as_str())
        .collect();
    if migrations.len() != contract.migrations.len()
        || installed.len() != contract.migrations.len()
        || contract
            .migrations
            .iter()
            .any(|name| !installed.contains(name.as_str()))
    {
        return Err(SourceError::Unsupported);
    }
    Ok(())
}

fn read_rows(
    connection: &Connection,
    sql: &str,
    maximum: usize,
    remaining: &mut usize,
) -> Result<Vec<Value>, SourceError> {
    let mut query = connection.prepare(sql).map_err(|_| SourceError::Invalid)?;
    let columns: Vec<_> = query.column_names().map(str::to_owned).collect();
    let mut reader = query.query([]).map_err(|_| SourceError::Invalid)?;
    let mut rows = Vec::new();
    while let Some(row) = reader.next().map_err(|_| SourceError::Invalid)? {
        if rows.len() == maximum {
            return Err(SourceError::Limit);
        }
        let mut fields = Map::new();
        for (index, key) in columns.iter().enumerate() {
            let item = row.get_ref(index).map_err(|_| SourceError::Invalid)?;
            let payload = match item {
                ValueRef::Text(bytes) => bytes.len(),
                _ => 0,
            };
            *remaining = remaining
                .checked_sub(key.len() + payload + 4)
                .ok_or(SourceError::Limit)?;
            let value = match item {
                ValueRef::Null => Value::Null,
                ValueRef::Integer(value) if value.unsigned_abs() <= 9_007_199_254_740_991 => {
                    Value::Number(value.into())
                }
                ValueRef::Real(value) => {
                    Value::Number(Number::from_f64(value).ok_or(SourceError::Invalid)?)
                }
                ValueRef::Text(value) => Value::String(
                    std::str::from_utf8(value)
                        .map_err(|_| SourceError::Invalid)?
                        .to_owned(),
                ),
                _ => return Err(SourceError::Invalid),
            };
            fields.insert(key.clone(), value);
        }
        rows.push(Value::Object(fields));
    }
    Ok(rows)
}

struct BoundedJson(Vec<u8>);

impl Write for BoundedJson {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.len() > MAXIMUM_OUTPUT - self.0.len() {
            return Err(io::Error::other("Source projection too large"));
        }
        self.0.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "../tests/private/npm_import.rs"]
mod tests;
