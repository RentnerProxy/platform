use super::{MAX_DATA, MAX_NODES};

const MAX_OUTGOING_NODES: usize = 65_536;
const DATABASE_URL: &str = "database-url";
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

// Linux returns NUL-terminated attribute names. Only the destination-managed
// SELinux context is accepted; its value is never read or written by backup.
const SELINUX_ATTRIBUTE: &[u8] = b"security.selinux\0";

fn supported_attribute_names(names: &[u8]) -> bool {
    names.is_empty() || names == SELINUX_ATTRIBUTE
}

fn check_attributes(path: &Path) -> io::Result<()> {
    let path = CString::new(path.as_os_str().as_bytes())?;
    let mut names = [0u8; SELINUX_ATTRIBUTE.len()];
    let count = unsafe { libc::llistxattr(path.as_ptr(), names.as_mut_ptr().cast(), names.len()) };
    if count < 0 {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENOTSUP) => Ok(()),
            Some(libc::ERANGE) => Err(invalid("Extended application metadata is unsupported")),
            _ => Err(error),
        };
    }
    if supported_attribute_names(&names[..count as usize]) {
        Ok(())
    } else {
        Err(invalid("Extended application metadata is unsupported"))
    }
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
    capture_files(root, uid, budget, false)
}

pub(super) fn capture_files(
    root: &Path,
    uid: u32,
    budget: &mut Budget,
    database: bool,
) -> io::Result<Vec<Entry>> {
    let mut entries = Vec::new();
    walk_data(root, uid, |path, info| {
        if database && path == DATABASE_URL {
            return if info.is_file() {
                Ok(())
            } else {
                Err(invalid("Unsafe application database URL file"))
            };
        }
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
    outgoing_nodes: &mut usize,
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
    walk_data(root, uid, |_, _| {
        if *outgoing_nodes >= MAX_OUTGOING_NODES {
            return Err(invalid(
                "Outgoing application inventory exceeds its inspection limit",
            ));
        }
        *outgoing_nodes += 1;
        Ok(())
    })?;
    Ok(RestoreTarget::Existing)
}

pub(super) fn inspect_targets(
    roots: &BTreeMap<u32, PathBuf>,
    incoming: &BTreeMap<u32, Vec<Entry>>,
    outgoing_nodes: &mut usize,
) -> io::Result<Vec<(u32, RestoreTarget)>> {
    let mut shrinking = Vec::new();
    let mut growing = Vec::new();
    for (&uid, root) in roots {
        let previous_nodes = *outgoing_nodes;
        let target = inspect_target(root, uid, outgoing_nodes)?;
        if incoming[&uid].len() <= *outgoing_nodes - previous_nodes {
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
    validate_files(entries, budget, false)
}

pub(super) fn validate_files(
    entries: &[Entry],
    budget: &mut Budget,
    database: bool,
) -> io::Result<()> {
    let mut parents = BTreeMap::new();
    for entry in entries {
        safe_name(&entry.path)?;
        if (database && entry.path == DATABASE_URL)
            || entry.mode & !0o777 != 0
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
    if !stat.is_dir() || stat.uid() != unsafe { libc::geteuid() } || stat.mode() & 0o7077 != 0 {
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
    let parent = File::open(parent)?;
    match check_staging(&stage) {
        // The previous exchange may still need its durability barrier on retry.
        Ok(()) => discard_exchanged_stage(&parent, &stage)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    fs::DirBuilder::new().mode(0o700).create(&stage)?;
    if let Err(error) = stage_and_exchange(&stage, root, uid, entries, target_state) {
        fs::remove_dir_all(&stage)?;
        parent.sync_all()?;
        return Err(error);
    }
    // After exchange, staging may hold the only copy of the outgoing tree. Keep
    // it available for resume until the exchange is durable.
    discard_exchanged_stage(&parent, &stage)
}

fn discard_exchanged_stage(parent: &File, stage: &Path) -> io::Result<()> {
    // The exchange changes one directory entry in each of these directories.
    File::open(stage)?.sync_all()?;
    parent.sync_all()?;
    fs::remove_dir_all(stage)?;
    parent.sync_all()
}

fn stage_and_exchange(
    stage: &Path,
    root: &Path,
    uid: u32,
    entries: &[Entry],
    target_state: RestoreTarget,
) -> io::Result<()> {
    // An installation parent may have a default ACL. Strip both inherited ACLs
    // from our private directory before it can propagate them to snapshot files.
    let stage_path = CString::new(stage.as_os_str().as_bytes())?;
    for acl in [c"system.posix_acl_default", c"system.posix_acl_access"] {
        if unsafe { libc::lremovexattr(stage_path.as_ptr(), acl.as_ptr()) } != 0 {
            let error = io::Error::last_os_error();
            if !matches!(error.raw_os_error(), Some(libc::ENODATA | libc::ENOTSUP)) {
                return Err(error);
            }
        }
    }
    fs::set_permissions(stage, Permissions::from_mode(0o700))?;
    check_attributes(stage)?;
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
    walk_data(&tree, uid, |_, _| Ok(()))?;
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
    Ok(())
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
        let missing = inspect_target(&root, uid, &mut 0).unwrap();
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
            inspect_target(&root, uid, &mut 0).unwrap(),
            RestoreTarget::Existing
        );
        assert!(capture(&root, uid, &mut Budget::default()).is_err());
        // An unrelated installation can already occupy the entire incoming snapshot entry budget.
        let mut outgoing_nodes = MAX_NODES;
        assert_eq!(
            inspect_target(&root, uid, &mut outgoing_nodes).unwrap(),
            RestoreTarget::Existing
        );
        assert_eq!(outgoing_nodes, MAX_NODES + 2);
        let mut at_limit = MAX_OUTGOING_NODES;
        assert!(inspect_target(&root, uid, &mut at_limit).is_err());
        assert!(existing.is_file());
        let error = restore(&root, uid, &entries, ".app-restore-kiri", missing).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EEXIST));
        assert!(!fixture.path().join(".app-restore-kiri").exists());
        assert!(existing.is_file());
        std::os::unix::fs::symlink(&existing, root.join("link")).unwrap();
        assert!(inspect_target(&root, uid, &mut 0).is_err());
        let link = fixture.path().join("linked-data");
        std::os::unix::fs::symlink(&root, &link).unwrap();
        assert!(inspect_target(&link, uid, &mut 0).is_err());
    }

    #[test]
    fn accepts_only_the_filesystem_selinux_context() {
        assert!(supported_attribute_names(b""));
        assert!(supported_attribute_names(b"security.selinux\0"));
        for names in [
            b"security.selinux".as_slice(),
            b"security.selinux2\0",
            b"security.capability\0",
            b"system.posix_acl_access\0",
            b"system.posix_acl_default\0",
            b"security.selinux\0user.extra\0",
        ] {
            assert!(!supported_attribute_names(names));
        }
    }

    #[test]
    fn retains_staging_until_both_exchange_directories_are_synced() {
        let fixture = tempfile::tempdir().unwrap();
        let parent = File::open(fixture.path()).unwrap();
        // Use a disposable link to inject a directory whose fsync returns EINVAL.
        let unsyncable_stage = fixture.path().join("unsyncable-stage");
        std::os::unix::fs::symlink("/proc/self/fd", &unsyncable_stage).unwrap();
        assert_eq!(
            discard_exchanged_stage(&parent, &unsyncable_stage)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EINVAL)
        );
        assert!(unsyncable_stage.is_symlink());

        let stage = fixture.path().join(".app-restore-kiri");
        fs::create_dir(&stage).unwrap();
        let outgoing = stage.join("data");
        fs::write(&outgoing, b"last copy").unwrap();
        let unsyncable = File::open("/dev/null").unwrap();
        assert!(discard_exchanged_stage(&unsyncable, &stage).is_err());
        assert_eq!(fs::read(&outgoing).unwrap(), b"last copy");
        discard_exchanged_stage(&parent, &stage).unwrap();
        assert!(!stage.exists());
    }

    #[test]
    fn cleans_partial_staging_when_a_file_cannot_be_created() {
        let uid = unsafe { libc::geteuid() };
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("data");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("original"), b"kiri").unwrap();
        let entries = [
            dir("partial"),
            Entry {
                path: "missing/note".into(),
                mode: 0o600,
                contents: Some(STANDARD.encode(b"new")),
            },
        ];
        let error = restore(
            &root,
            uid,
            &entries,
            ".app-restore-kiri",
            RestoreTarget::Existing,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert_eq!(fs::read(root.join("original")).unwrap(), b"kiri");
        assert!(!root.join("partial").exists());
        assert!(!parent.path().join(".app-restore-kiri").exists());
    }

    #[test]
    fn verifies_a_live_tree_larger_than_the_incoming_snapshot_without_mutating_it() {
        let uid = unsafe { libc::geteuid() };
        if uid != unsafe { libc::getegid() } {
            return;
        }
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("data");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, Permissions::from_mode(0o700)).unwrap();
        for index in 0..=MAX_NODES {
            File::create(root.join(index.to_string())).unwrap();
        }
        let roots = BTreeMap::from([(uid, root.clone())]);
        let incoming = BTreeMap::from([(uid, vec![dir("replacement")])]);
        let mut nodes = 0;
        let plan = inspect_targets(&roots, &incoming, &mut nodes).unwrap();
        assert_eq!(nodes, MAX_NODES + 1);
        assert_eq!(plan, vec![(uid, RestoreTarget::Existing)]);
        assert_eq!(fs::read_dir(&root).unwrap().count(), MAX_NODES + 1);
        assert!(!root.join("replacement").exists());
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 1);
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
        let occupied = || MAX_OUTGOING_NODES - 2;
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
    fn restores_without_inheriting_the_installation_parents_default_acl() {
        let uid = unsafe { libc::geteuid() };
        if uid != unsafe { libc::getegid() } {
            return;
        }
        let parent = tempfile::tempdir().unwrap();
        // Linux's POSIX ACL xattr format: version, then (tag, permissions, id) entries.
        let mut acl = 2_u32.to_le_bytes().to_vec();
        for (tag, permissions, id) in [
            (1_u16, 7_u16, u32::MAX),
            (2, 4, 25001),
            (4, 0, u32::MAX),
            (16, 4, u32::MAX),
            (32, 0, u32::MAX),
        ] {
            acl.extend(tag.to_le_bytes());
            acl.extend(permissions.to_le_bytes());
            acl.extend(id.to_le_bytes());
        }
        let path = CString::new(parent.path().as_os_str().as_bytes()).unwrap();
        if unsafe {
            libc::lsetxattr(
                path.as_ptr(),
                c"system.posix_acl_default".as_ptr(),
                acl.as_ptr().cast(),
                acl.len(),
                0,
            )
        } != 0
        {
            assert!(matches!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::ENOTSUP | libc::EPERM)
            ));
            return;
        }
        let inherited = parent.path().join("inherited");
        fs::create_dir(&inherited).unwrap();
        assert!(check_attributes(&inherited).is_err());
        let root = parent.path().join("data");
        let entries = [
            dir("folder"),
            Entry {
                path: "folder/note".into(),
                mode: 0o640,
                contents: Some(STANDARD.encode(b"kiri")),
            },
        ];
        restore(
            &root,
            uid,
            &entries,
            ".app-restore-kiri",
            RestoreTarget::Missing,
        )
        .unwrap();
        assert_eq!(
            capture(&root, uid, &mut Budget::default()).unwrap().len(),
            2
        );
        assert_eq!(fs::read(root.join("folder/note")).unwrap(), b"kiri");
        assert!(check_attributes(parent.path()).is_err());
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
    fn encoded_archive_budget_covers_maximum_data_paths_and_inventory() {
        let longest = Entry {
            path: "\"".repeat(1024),
            mode: 0o777,
            contents: Some(String::new()),
        };
        let entry_overhead = serde_json::to_vec(&longest).unwrap().len() + 1;
        let file_contents = MAX_DATA.div_ceil(3) * 4 + MAX_NODES * 4;
        let journal_and_uid_map = 4 * 1024 * 1024 + 65536;
        assert!(
            file_contents + MAX_NODES * entry_overhead + journal_and_uid_map
                <= super::super::MAX_ARCHIVE
        );
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
