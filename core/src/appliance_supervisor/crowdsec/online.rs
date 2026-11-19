use super::commands::{bounded, service};
use super::{Mode, ONLINE_CONFIG, Supervisor, files};
use serde_json::{Value, json};
use std::{fs, io};

pub(super) fn has_json_field(bytes: &[u8], field: &str, expected: &Value) -> bool {
    fn contains(value: &Value, field: &str, expected: &Value) -> bool {
        match value {
            Value::Array(items) => items.iter().any(|item| contains(item, field, expected)),
            Value::Object(object) => {
                object.get(field) == Some(expected)
                    || object.values().any(|item| contains(item, field, expected))
            }
            _ => false,
        }
    }
    serde_json::from_slice::<Value>(bytes).is_ok_and(|value| contains(&value, field, expected))
}

pub(super) fn console_status(bytes: &[u8]) -> &'static str {
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return "degraded";
    };
    if value
        .pointer("/console/authenticated")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return "degraded";
    }
    match value.pointer("/console/enrolled").and_then(Value::as_bool) {
        Some(true) => "connected",
        Some(false) => "pending",
        None => "degraded",
    }
}

impl Supervisor {
    pub(super) async fn enable_online(&self) -> io::Result<()> {
        match fs::symlink_metadata(files::CAPI) {
            Ok(metadata) if !metadata.is_file() => {
                return Err(io::Error::other("Invalid CAPI credential"));
            }
            Ok(_) => (),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let registration = files::registration_file()?;
                let path = registration
                    .path()
                    .to_str()
                    .ok_or_else(|| io::Error::other("Invalid CAPI staging path"))?;
                self.cli(ONLINE_CONFIG, &["capi", "register", "-f", path], 25, false)
                    .await?;
                files::publish_capi(registration.as_file())?;
            }
            Err(error) => return Err(error),
        }
        self.protect_online().await?;
        self.cli(ONLINE_CONFIG, &["capi", "status"], 8, false)
            .await?;
        self.validate(ONLINE_CONFIG).await?;
        Ok(())
    }

    pub(super) async fn protect_online(&self) -> io::Result<()> {
        let protect = service(
            "/usr/local/bin/rentnerproxy-controller",
            &["--appliance-supervisor", "protect-capi"],
        );
        bounded(protect, 8, false, &self.helpers).await?;
        Ok(())
    }

    pub(super) async fn probe_online(&mut self) {
        self.community = if self
            .cli(ONLINE_CONFIG, &["capi", "status"], 8, false)
            .await
            .is_ok()
        {
            "connected"
        } else {
            "degraded"
        };
        self.console = match fs::symlink_metadata(files::CONSOLE) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => "not_enrolled",
            Ok(file) if file.is_file() => match self
                .cli(ONLINE_CONFIG, &["-o", "json", "console", "status"], 8, true)
                .await
            {
                Ok(data) => console_status(&data),
                Err(_) => "degraded",
            },
            _ => "degraded",
        };
    }

    pub(super) async fn enroll(&mut self, text: &str) -> io::Result<()> {
        let (id, key) = files::enrollment_fields(text)
            .ok_or_else(|| io::Error::other("Invalid enrollment request"))?;
        let result = if self.running != Mode::Online
            || self.community != "connected"
            || super::desired() != Mode::Online
        {
            "failed"
        } else if self
            .cli(
                ONLINE_CONFIG,
                &["console", "enroll", "--disable", "all", "--", key],
                25,
                false,
            )
            .await
            .is_ok()
        {
            self.console = "pending";
            "pending"
        } else {
            self.console = "degraded";
            "failed"
        };
        files::status(
            "console-enrollment-result.json",
            json!({"id":id,"state":result}),
        )
    }
}
