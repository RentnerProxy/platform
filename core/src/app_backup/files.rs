use super::{MAX_DATA, MAX_NODES};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use marketplace_artifacts::invalid;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::{self, File, OpenOptions, Permissions},
    io::{self, Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt, fchown},
    },
    path::Path,
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Entry {
    path: String,
    mode: u32,
    contents: Option<String>,
}

#[derive(Default)]
pub(super) struct Budget {
    bytes: usize,
    nodes: usize,
}

impl Budget {
    fn add(&mut self, bytes: usize) -> io::Result<()> {
        self.nodes += 1;
        if bytes > MAX_DATA - self.bytes || self.nodes > MAX_NODES {
            return Err(invalid("Application snapshot exceeds its storage budget"));
        }
        self.bytes += bytes;
        Ok(())
    }
}

fn safe_name(path: &str) -> io::Result<()> {
    if path.len() > 1024
        || path.split('/').count() > 32
        || path.split('/').any(|s| {
            matches!(s, "" | "." | "..")
                || s.len() > 255
                || s.contains('\\')
                || s.chars().any(char::is_control)
        })
    {
        return Err(invalid("Unsupported application data path"));
    }
    Ok(())
}

fn mount_id(path: &Path) -> io::Result<u64> {
    let path = CString::new(path.as_os_str().as_bytes())?;
    let mut stat = std::mem::MaybeUninit::zeroed();
    // statx and llistxattr only inspect this entry; neither follows its final link.
    let result = unsafe {
        libc::statx(
            libc::AT_FDCWD,
            path.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT,
            libc::STATX_MNT_ID,
            stat.as_mut_ptr(),
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    let stat = unsafe { stat.assume_init() };
    if stat.stx_mask & libc::STATX_MNT_ID == 0 {
        return Err(invalid("Mount identity unavailable"));
    }
    let attrs = unsafe { libc::llistxattr(path.as_ptr(), std::ptr::null_mut(), 0) };
    if attrs < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ENOTSUP) {
            return Err(error);
        }
    } else if attrs > 0 {
        return Err(invalid("Extended application metadata is unsupported"));
    }
    Ok(stat.stx_mnt_id)
}

pub(super) fn capture(root: &Path, uid: u32, budget: &mut Budget) -> io::Result<Vec<Entry>> {
    let mount = mount_id(root)?;
    if mount_id(
        root.parent()
            .ok_or_else(|| invalid("Missing installation directory"))?,
    )? != mount
    {
        return Err(invalid("Mounted application data is unsupported"));
    }
    let dev = fs::symlink_metadata(root)?.dev();
    let mut entries = Vec::new();
    let mut pending = vec![String::new()];
    while let Some(directory) = pending.pop() {
        for member in fs::read_dir(root.join(&directory))? {
            let member = member?;
            let name = member
                .file_name()
                .into_string()
                .map_err(|_| invalid("Unsupported file name"))?;
            let path = if directory.is_empty() {
                name
            } else {
                format!("{directory}/{name}")
            };
            safe_name(&path)?;
            let info = fs::symlink_metadata(member.path())?;
            let mode = info.mode() & 0o7777;
            if info.uid() != uid
                || info.gid() != uid
                || mode & 0o7000 != 0
                || info.dev() != dev
                || mount_id(&member.path())? != mount
            {
                return Err(invalid("Unsafe application data metadata"));
            }
            let contents = if info.is_dir() {
                budget.add(0)?;
                pending.push(path.clone());
                None
            } else {
                if !info.is_file() || info.nlink() != 1 {
                    return Err(invalid("Unsupported application data file"));
                }
                budget.add(usize::try_from(info.len()).map_err(|_| invalid("Oversized file"))?)?;
                let mut file = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(member.path())?;
                let pinned = file.metadata()?;
                if pinned.dev() != dev || pinned.ino() != info.ino() || pinned.len() != info.len() {
                    return Err(invalid("Application data changed during capture"));
                }
                let mut bytes = Vec::new();
                (&mut file).take(info.len() + 1).read_to_end(&mut bytes)?;
                if bytes.len() as u64 != info.len() {
                    return Err(invalid("File changed during capture"));
                }
                Some(STANDARD.encode(bytes))
            };
            entries.push(Entry {
                path,
                mode,
                contents,
            });
        }
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(entries)
}

pub(super) fn validate(entries: &[Entry], budget: &mut Budget) -> io::Result<()> {
    let mut parents = BTreeMap::new();
    for entry in entries {
        safe_name(&entry.path)?;
        if entry.mode & !0o777 != 0
            || entry
                .path
                .rsplit_once('/')
                .is_some_and(|(parent, _)| parents.get(parent) != Some(&true))
            || parents
                .insert(entry.path.as_str(), entry.contents.is_none())
                .is_some()
        {
            return Err(invalid("Invalid application snapshot hierarchy"));
        }
        let bytes = entry
            .contents
            .as_ref()
            .map(|data| STANDARD.decode(data))
            .transpose()
            .map_err(|_| invalid("Invalid file contents"))?;
        budget.add(bytes.as_ref().map_or(0, Vec::len))?;
    }
    Ok(())
}

pub(super) fn check_staging(path: &Path) -> io::Result<()> {
    let stat = fs::symlink_metadata(path)?;
    if !stat.is_dir() || stat.uid() != unsafe { libc::geteuid() } || stat.mode() & 0o7777 != 0o700 {
        return Err(invalid("Invalid restore staging directory"));
    }
    Ok(())
}

pub(super) fn restore(
    root: &Path,
    uid: u32,
    entries: &[Entry],
    stage_name: &str,
) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let parent = root
        .parent()
        .ok_or_else(|| invalid("Missing installation directory"))?;
    let stage = parent.join(stage_name);
    match check_staging(&stage) {
        Ok(()) => fs::remove_dir_all(&stage)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    fs::DirBuilder::new().mode(0o700).create(&stage)?;
    let tree = stage.join("data");
    fs::create_dir(&tree)?;
    for entry in entries {
        let to = tree.join(&entry.path);
        if let Some(encoded) = &entry.contents {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(to)?;
            file.write_all(
                &STANDARD
                    .decode(encoded)
                    .map_err(|_| invalid("Invalid file contents"))?,
            )?;
            fchown(&file, Some(uid), Some(uid))?;
            file.set_permissions(Permissions::from_mode(entry.mode))?;
            file.sync_all()?;
        } else {
            fs::create_dir(to)?;
        }
    }
    for entry in entries
        .iter()
        .rev()
        .filter(|entry| entry.contents.is_none())
    {
        let dir = File::open(tree.join(&entry.path))?;
        fchown(&dir, Some(uid), Some(uid))?;
        dir.set_permissions(Permissions::from_mode(entry.mode))?;
        dir.sync_all()?;
    }
    let next = File::open(&tree)?;
    fchown(&next, Some(uid), Some(uid))?;
    next.set_permissions(Permissions::from_mode(0o700))?;
    next.sync_all()?;
    let source = CString::new(tree.as_os_str().as_bytes())?;
    let target = CString::new(root.as_os_str().as_bytes())?;
    // Both directories are under root-owned installation parents, on the same filesystem.
    if unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    File::open(parent)?.sync_all()?;
    fs::remove_dir_all(&stage)?;
    File::open(parent)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn dir(path: &str) -> Entry {
        Entry {
            path: path.into(),
            mode: 0o700,
            contents: None,
        }
    }
    #[test]
    fn restores_a_synthetic_file_tree_and_preserves_its_modes() {
        let uid = unsafe { libc::geteuid() };
        if uid != unsafe { libc::getegid() } {
            return;
        }
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("data");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("kiri")).unwrap();
        let note = root.join("kiri/note");
        fs::write(&note, b"previous note").unwrap();
        fs::set_permissions(&note, Permissions::from_mode(0o640)).unwrap();
        let entries = capture(&root, uid, &mut Budget::default()).unwrap();
        validate(&entries, &mut Budget::default()).unwrap();
        fs::write(&note, b"current note").unwrap();
        fs::write(root.join("later"), b"later").unwrap();
        restore(&root, uid, &entries, ".app-restore-kiri").unwrap();
        assert_eq!(fs::read(&note).unwrap(), b"previous note");
        assert_eq!(fs::metadata(&note).unwrap().mode() & 0o7777, 0o640);
        assert!(!root.join("later").exists());
        std::os::unix::fs::symlink(&note, root.join("shortcut")).unwrap();
        assert!(capture(&root, uid, &mut Budget::default()).is_err());
    }

    #[test]
    fn rejects_invalid_snapshot_paths_and_counts_decoded_bytes() {
        let tree = [
            dir("kiri"),
            Entry {
                path: "kiri/state.json".into(),
                mode: 0o600,
                contents: Some(STANDARD.encode(br#"{"synthetic":true}"#)),
            },
        ];
        let mut budget = Budget::default();
        validate(&tree, &mut budget).unwrap();
        assert_eq!(budget.bytes, 18);
        for name in [
            "",
            "/kiri",
            "../kiri",
            "kiri/../state",
            "a\\b",
            "kiri//state",
        ] {
            assert!(validate(&[dir(name)], &mut Budget::default()).is_err());
        }
        assert!(validate(&[dir("kiri/state")], &mut Budget::default()).is_err());
        assert!(validate(&[dir("kiri"), dir("kiri")], &mut Budget::default()).is_err());
    }
}
