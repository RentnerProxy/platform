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
    path::{Path, PathBuf},
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
    Ok(stat.stx_mnt_id)
}

fn check_attributes(path: &Path) -> io::Result<()> {
    let path = CString::new(path.as_os_str().as_bytes())?;
    let attrs = unsafe { libc::llistxattr(path.as_ptr(), std::ptr::null_mut(), 0) };
    if attrs < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ENOTSUP) {
            return Err(error);
        }
    } else if attrs > 0 {
        return Err(invalid("Extended application metadata is unsupported"));
    }
    Ok(())
}

fn walk_data(
    root: &Path,
    uid: u32,
    mut visit: impl FnMut(String, &fs::Metadata) -> io::Result<()>,
) -> io::Result<()> {
    check_attributes(root)?;
    let mount = mount_id(root)?;
    if mount_id(
        root.parent()
            .ok_or_else(|| invalid("Missing installation directory"))?,
    )? != mount
    {
        return Err(invalid("Mounted application data is unsupported"));
    }
    let dev = fs::symlink_metadata(root)?.dev();
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
            check_attributes(&member.path())?;
            if info.is_dir() {
                pending.push(path.clone());
            } else if !info.is_file() || info.nlink() != 1 {
                return Err(invalid("Unsupported application data file"));
            }
            visit(path, &info)?;
        }
    }
    Ok(())
}

pub(super) fn capture(root: &Path, uid: u32, budget: &mut Budget) -> io::Result<Vec<Entry>> {
    let mut entries = Vec::new();
    walk_data(root, uid, |path, info| {
        let size = if info.is_file() {
            usize::try_from(info.len()).map_err(|_| invalid("Oversized file"))?
        } else {
            0
        };
        budget.add(size)?;
        let contents = if info.is_dir() {
            None
        } else {
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(root.join(&path))?;
            let pinned = file.metadata()?;
            if pinned.dev() != info.dev()
                || pinned.ino() != info.ino()
                || pinned.len() != info.len()
            {
                return Err(invalid("Application data changed during capture"));
            }
            let mut bytes = Vec::new();
            file.take(info.len() + 1).read_to_end(&mut bytes)?;
            if bytes.len() != size {
                return Err(invalid("File changed during capture"));
            }
            Some(STANDARD.encode(bytes))
        };
        entries.push(Entry {
            path,
            mode: info.mode() & 0o7777,
            contents,
        });
        Ok(())
    })?;
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(entries)
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum RestoreTarget {
    Existing,
    Missing,
}

pub(super) fn inspect_target(
    root: &Path,
    uid: u32,
    budget: &mut Budget,
) -> io::Result<RestoreTarget> {
    match fs::symlink_metadata(root) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(RestoreTarget::Missing),
        Ok(info)
            if info.is_dir()
                && info.uid() == uid
                && info.gid() == uid
                && info.mode() & 0o7777 == 0o700 => {}
        Ok(_) => return Err(invalid("Unsafe installation data directory")),
        Err(error) => return Err(error),
    }
    walk_data(root, uid, |_, _| budget.add(0))?;
    Ok(RestoreTarget::Existing)
}

pub(super) fn inspect_targets(
    roots: &BTreeMap<u32, PathBuf>,
    incoming: &BTreeMap<u32, Vec<Entry>>,
    budget: &mut Budget,
) -> io::Result<Vec<(u32, RestoreTarget)>> {
    let mut shrinking = Vec::new();
    let mut growing = Vec::new();
    for (&uid, root) in roots {
        let previous_nodes = budget.nodes;
        let target = inspect_target(root, uid, budget)?;
        if incoming[&uid].len() <= budget.nodes - previous_nodes {
            shrinking.push((uid, target));
        } else {
            growing.push((uid, target));
        }
    }
    // Every intermediate inventory stays within the validated old/new node totals on retry.
    shrinking.extend(growing);
    Ok(shrinking)
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
    target_state: RestoreTarget,
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
            match target_state {
                RestoreTarget::Existing => libc::RENAME_EXCHANGE,
                RestoreTarget::Missing => libc::RENAME_NOREPLACE,
            },
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
        restore(
            &root,
            uid,
            &entries,
            ".app-restore-kiri",
            RestoreTarget::Existing,
        )
        .unwrap();
        assert_eq!(fs::read(&note).unwrap(), b"previous note");
        assert_eq!(fs::metadata(&note).unwrap().mode() & 0o7777, 0o640);
        assert!(!root.join("later").exists());
        std::os::unix::fs::symlink(&note, root.join("shortcut")).unwrap();
        assert!(capture(&root, uid, &mut Budget::default()).is_err());
    }

    #[test]
    fn inspects_only_metadata_and_publishes_missing_storage_exclusively() {
        let uid = unsafe { libc::geteuid() };
        if uid != unsafe { libc::getegid() } {
            return;
        }
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("data");
        let missing = inspect_target(&root, uid, &mut Budget::default()).unwrap();
        assert_eq!(missing, RestoreTarget::Missing);
        assert!(!root.exists());
        let entries = [dir("kiri")];
        restore(&root, uid, &entries, ".app-restore-kiri", missing).unwrap();
        let existing = root.join("outgoing");
        File::create(&existing)
            .unwrap()
            .set_len(MAX_DATA as u64 + 1)
            .unwrap();
        assert_eq!(
            inspect_target(&root, uid, &mut Budget::default()).unwrap(),
            RestoreTarget::Existing
        );
        assert!(capture(&root, uid, &mut Budget::default()).is_err());
        let error = restore(&root, uid, &entries, ".app-restore-kiri", missing).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EEXIST));
        assert!(existing.is_file());
        std::os::unix::fs::symlink(&existing, root.join("link")).unwrap();
        assert!(inspect_target(&root, uid, &mut Budget::default()).is_err());
        let link = fixture.path().join("linked-data");
        std::os::unix::fs::symlink(&root, &link).unwrap();
        assert!(inspect_target(&link, uid, &mut Budget::default()).is_err());
    }

    #[test]
    fn resumes_after_the_first_exchange_when_old_and_new_counts_move_between_apps() {
        use std::os::unix::fs::chown;
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let grow = 25001;
        let shrink = 25002;
        let mut roots = BTreeMap::new();
        for uid in [grow, shrink] {
            let root = temp.path().join(uid.to_string());
            fs::create_dir(&root).unwrap();
            chown(&root, Some(uid), Some(uid)).unwrap();
            fs::set_permissions(&root, Permissions::from_mode(0o700)).unwrap();
            roots.insert(uid, root);
        }
        for name in ["one", "two"] {
            let file = roots[&shrink].join(name);
            fs::write(&file, b"old").unwrap();
            chown(&file, Some(shrink), Some(shrink)).unwrap();
        }
        let incoming = BTreeMap::from([(grow, vec![dir("one"), dir("two")]), (shrink, vec![])]);
        // Other unchanged installations already occupy the rest of the global inventory budget.
        let occupied = || Budget {
            nodes: MAX_NODES - 2,
            bytes: 0,
        };
        let first = inspect_targets(&roots, &incoming, &mut occupied()).unwrap()[0];
        assert_eq!(first.0, shrink);
        restore(
            &roots[&first.0],
            first.0,
            &incoming[&first.0],
            ".app-restore-kiri",
            first.1,
        )
        .unwrap();
        for (uid, target) in inspect_targets(&roots, &incoming, &mut occupied()).unwrap() {
            restore(
                &roots[&uid],
                uid,
                &incoming[&uid],
                ".app-restore-kiri",
                target,
            )
            .unwrap();
        }
        assert!(roots[&grow].join("two").is_dir());
        assert_eq!(fs::read_dir(&roots[&shrink]).unwrap().count(), 0);
    }

    #[test]
    fn installation_parent_attributes_are_outside_the_snapshot() {
        let uid = unsafe { libc::geteuid() };
        if uid != unsafe { libc::getegid() } {
            return;
        }
        let fixture = tempfile::tempdir().unwrap();
        let set_attr = |path: &Path| {
            let path = CString::new(path.as_os_str().as_bytes()).unwrap();
            unsafe {
                libc::lsetxattr(
                    path.as_ptr(),
                    c"user.fixture".as_ptr(),
                    c"1".as_ptr().cast(),
                    1,
                    0,
                )
            }
        };
        if set_attr(fixture.path()) != 0 {
            assert!(matches!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::ENOTSUP | libc::EPERM)
            ));
            return;
        }
        let root = fixture.path().join("data");
        fs::create_dir(&root).unwrap();
        assert!(capture(&root, uid, &mut Budget::default()).is_ok());
        assert_eq!(set_attr(&root), 0);
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
