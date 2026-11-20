use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::{File, OpenOptions},
    io::{self, Read},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};

use jsonschema::{Draft, Validator};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Map, Value};

use crate::{
    app_install::StagedPackage,
    app_ipc::{filesystem::require_safe_parents, gateway::APP_API_PREFIX, wire_json},
};

use super::super::{bad, journal::Capability, valid_id};

const MAX_ASSET_BYTES: u64 = 8 * 1024 * 1024;
const MAX_DOCUMENT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_ENTRIES: usize = 100;
const MAX_UI_ENTRIES: usize = 32;
const MAX_SCHEMA_NODES: usize = 192;
const MAX_SCHEMA_DEPTH: usize = 20;
const MAX_SCHEMA_BYTES: usize = 32 * 1024;

#[cfg(test)]
#[path = "../../../tests/private/app_ui_package.rs"]
mod tests;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Metadata {
    pub app_id: String,
    pub installation_id: String,
    pub generation: u64,
    pub uid: u32,
    archive_sha256: String,
    name: String,
    entrypoint: String,
    slots: Vec<String>,
    permission_keys: Vec<String>,
    routes: Vec<String>,
    dialogs: Vec<String>,
    events: Vec<String>,
}

pub(in crate::app_manager) struct Package {
    pub(super) metadata: Metadata,
    ui_directory: File,
    pub(super) operations: BTreeMap<String, Operation>,
}

pub(super) struct Operation {
    pub access: Access,
    pub request: Validator,
    pub response: Validator,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Access {
    permission_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resource: Option<Resource>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Resource {
    capability: Capability,
    resource_id_field: String,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct UiDeclarations {
    routes: Vec<String>,
    dialogs: Vec<String>,
    events: Vec<String>,
}

impl Package {
    pub(in crate::app_manager) fn load(
        package: &StagedPackage,
        id: String,
        generation: u64,
        uid: u32,
    ) -> io::Result<Option<Self>> {
        let manifest = &package.manifest;
        let Some(ui) = manifest.get("ui") else {
            return Ok(None);
        };
        let entrypoint = field(ui, "entrypoint")?;
        let relative_entry = entrypoint
            .strip_prefix("ui/")
            .filter(|path| path.ends_with(".html"))
            .ok_or_else(invalid)?;
        let root = open_package(&package.directory)?;
        let ui_directory = open_directory(&root, "ui")?;
        open_beneath(&ui_directory, relative_entry, MAX_ASSET_BYTES)?;
        let permission_keys: Vec<String> = decode_member(manifest, "permissions")?;
        let capabilities: Vec<Capability> = decode_member(manifest, "capabilities")?;
        let document = field(manifest, "api")
            .and_then(|path| read_beneath(&root, path, MAX_DOCUMENT_BYTES))
            .ok()
            .filter(|bytes| wire_json::valid(bytes))
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .filter(|document| {
                document["openapi"]
                    .as_str()
                    .is_some_and(|version| version.starts_with("3.1."))
            });
        let declarations: UiDeclarations = document
            .as_ref()
            .and_then(|value| value.get("x-rentnerproxy-ui"))
            .map(|value| serde_json::from_value(value.clone()))
            .transpose()?
            .unwrap_or_default();
        let UiDeclarations {
            mut routes,
            dialogs,
            events,
        } = declarations;
        if [&routes, &dialogs, &events].iter().any(|list| {
            list.len() > MAX_UI_ENTRIES
                || list.iter().any(|id| !valid_id(id))
                || list.iter().collect::<BTreeSet<_>>().len() != list.len()
        }) {
            return Err(invalid());
        }
        routes.retain(|route| route != "overview");
        if routes.len() == MAX_UI_ENTRIES {
            return Err(invalid());
        }
        routes.insert(0, "overview".into());
        let operations = document.map_or_else(BTreeMap::new, |document| {
            read_operations(&document, &permission_keys, &capabilities)
        });
        let metadata = Metadata {
            app_id: field(manifest, "id")?.into(),
            installation_id: id,
            generation,
            uid,
            archive_sha256: package.archive_sha256.clone(),
            name: field(&manifest["display"], "name")?.into(),
            entrypoint: entrypoint.into(),
            slots: decode_member(ui, "slots")?,
            permission_keys,
            routes,
            dialogs,
            events,
        };
        Ok(Some(Self {
            metadata,
            ui_directory,
            operations,
        }))
    }

    pub(super) fn asset(&self, path: &str) -> io::Result<Vec<u8>> {
        read_beneath(&self.ui_directory, path, MAX_ASSET_BYTES)
    }
}

fn invalid() -> io::Error {
    bad("Invalid installed app UI package")
}

fn field<'a>(value: &'a Value, key: &str) -> io::Result<&'a str> {
    value[key].as_str().ok_or_else(invalid)
}

fn decode_member<T: DeserializeOwned>(value: &Value, key: &str) -> io::Result<T> {
    Ok(serde_json::from_value(value[key].clone())?)
}

pub(super) fn valid_relative_path(path: &str) -> bool {
    path.len() <= 240
        && path.split('/').all(|component| {
            component.split('.').all(|segment| {
                !segment.is_empty()
                    && segment
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            })
        })
}

fn open_package(path: &Path) -> io::Result<File> {
    require_safe_parents(path, 0)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)?;
    verify_directory(&directory)?;
    Ok(directory)
}

fn verify_directory(directory: &File) -> io::Result<()> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o7022 != 0 {
        return Err(invalid());
    }
    Ok(())
}

fn open_relative(directory: &File, component: &str, flags: libc::c_int) -> io::Result<File> {
    let component = CString::new(component).map_err(|_| invalid())?;
    // SAFETY: The directory borrows a live descriptor and component is a single
    // nul-terminated name. Successful openat returns a new owned descriptor.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            component.as_ptr(),
            libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK | flags,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_directory(parent: &File, component: &str) -> io::Result<File> {
    let child = open_relative(parent, component, libc::O_DIRECTORY)?;
    verify_directory(&child)?;
    Ok(child)
}

fn open_beneath(root: &File, path: &str, limit: u64) -> io::Result<File> {
    if !valid_relative_path(path) {
        return Err(invalid());
    }
    let mut directory = root.try_clone()?;
    let mut components = path.split('/').peekable();
    while let Some(component) = components.next() {
        if components.peek().is_some() {
            directory = open_directory(&directory, component)?;
            continue;
        }
        let file = open_relative(&directory, component, libc::O_RDONLY)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o7022 != 0
            || metadata.len() > limit
        {
            return Err(invalid());
        }
        return Ok(file);
    }
    Err(invalid())
}

fn read_beneath(root: &File, path: &str, limit: u64) -> io::Result<Vec<u8>> {
    let file = open_beneath(root, path, limit)?;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(invalid());
    }
    Ok(bytes)
}

fn read_operations(
    document: &Value,
    permissions: &[String],
    capabilities: &[Capability],
) -> BTreeMap<String, Operation> {
    let Some(paths) = document["paths"].as_object() else {
        return BTreeMap::new();
    };
    let candidates = paths
        .iter()
        .filter_map(|(path, declaration)| {
            let id = path
                .strip_prefix(APP_API_PREFIX)
                .filter(|id| valid_id(id))?;
            Some((id, declaration.get("post")?))
        })
        .take(MAX_ENTRIES + 1)
        .collect::<Vec<_>>();
    if candidates.len() > MAX_ENTRIES {
        return BTreeMap::new();
    }
    candidates
        .into_iter()
        .filter_map(|(id, post)| {
            let operation = read_operation(document, permissions, capabilities, id, post)?;
            Some((id.to_owned(), operation))
        })
        .collect()
}

fn read_operation(
    document: &Value,
    permissions: &[String],
    capabilities: &[Capability],
    id: &str,
    post: &Value,
) -> Option<Operation> {
    if post["operationId"] != id {
        return None;
    }
    if post["x-rentnerproxy-access"]
        .get("resource")
        .is_some_and(Value::is_null)
    {
        return None;
    }
    let access: Access = decode_member(post, "x-rentnerproxy-access").ok()?;
    if !permissions.contains(&access.permission_key) {
        return None;
    }
    if let Some(resource) = &access.resource
        && (!valid_field(&resource.resource_id_field)
            || !capabilities.contains(&resource.capability))
    {
        return None;
    }
    Some(Operation {
        access,
        request: compile(
            document,
            post["requestBody"]["content"]["application/json"].get("schema")?,
        )?,
        response: compile(
            document,
            post["responses"]["200"]["content"]["application/json"].get("schema")?,
        )?,
    })
}

fn valid_field(field: &str) -> bool {
    let bytes = field.as_bytes();
    bytes.len() <= 64
        && bytes.first().is_some_and(u8::is_ascii_alphabetic)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}

impl Access {
    pub(super) fn valid_resource(&self, payload: &Value) -> bool {
        self.resource.as_ref().is_none_or(|resource| {
            payload[&resource.resource_id_field]
                .as_str()
                .is_some_and(valid_id)
        })
    }
}

fn compile(document: &Value, schema: &Value) -> Option<Validator> {
    let mut budget = Expansion {
        nodes: MAX_SCHEMA_NODES,
        bytes: MAX_SCHEMA_BYTES,
    };
    let expanded = expand_schema(document, schema, &mut budget, 0)?;
    jsonschema::options()
        .with_draft(Draft::Draft202012)
        .build(&expanded)
        .ok()
}

struct Expansion {
    nodes: usize,
    bytes: usize,
}

impl Expansion {
    fn charge(&mut self, bytes: usize) -> Option<()> {
        self.bytes = self.bytes.checked_sub(bytes)?;
        Some(())
    }

    fn literal(&mut self, value: &Value) -> Option<()> {
        self.charge(16)?;
        match value {
            Value::String(text) => self.charge(text.len())?,
            Value::Array(items) => {
                for item in items {
                    self.literal(item)?;
                }
            }
            Value::Object(fields) => {
                for (name, field) in fields {
                    self.charge(name.len())?;
                    self.literal(field)?;
                }
            }
            _ => {}
        }
        Some(())
    }
}

fn expand_schema(
    document: &Value,
    schema: &Value,
    budget: &mut Expansion,
    depth: usize,
) -> Option<Value> {
    if depth > MAX_SCHEMA_DEPTH {
        return None;
    }
    budget.nodes = budget.nodes.checked_sub(1)?;
    budget.charge(16)?;
    if schema.is_boolean() {
        return Some(schema.clone());
    }
    let fields = schema.as_object()?;
    if let Some(reference) = fields.get("$ref") {
        let pointer = reference.as_str()?.strip_prefix('#')?;
        let name = pointer.strip_prefix("/components/schemas/")?;
        if fields.len() != 1 || name.is_empty() || name.contains(['/', '%']) {
            return None;
        }
        return expand_schema(document, document.pointer(pointer)?, budget, depth + 1);
    }
    let mut expanded = Map::new();
    for (key, value) in fields {
        budget.charge(key.len())?;
        let value = match key.as_str() {
            "properties" => {
                let fields = value.as_object()?;
                let mut properties = Map::new();
                for (name, child) in fields {
                    budget.charge(name.len())?;
                    let child = expand_schema(document, child, budget, depth + 1)?;
                    properties.insert(name.clone(), child);
                }
                Value::Object(properties)
            }
            "items" | "additionalProperties" => expand_schema(document, value, budget, depth + 1)?,
            "allOf" | "anyOf" | "oneOf" | "prefixItems" => {
                let children = value
                    .as_array()?
                    .iter()
                    .map(|child| expand_schema(document, child, budget, depth + 1))
                    .collect::<Option<Vec<_>>>()?;
                Value::Array(children)
            }
            "type" | "const" | "minimum" | "maximum" | "exclusiveMinimum" | "exclusiveMaximum"
            | "multipleOf" | "minLength" | "maxLength" | "minItems" | "maxItems"
            | "minProperties" | "maxProperties" => {
                budget.literal(value)?;
                value.clone()
            }
            "enum" | "required" if value.as_array()?.len() <= MAX_ENTRIES => {
                budget.literal(value)?;
                value.clone()
            }
            "title" | "description" | "default" | "examples" | "example" | "deprecated" => {
                continue;
            }
            _ => return None,
        };
        expanded.insert(key.clone(), value);
    }
    Some(Value::Object(expanded))
}
