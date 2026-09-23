use std::{fs, path::Path};

use crate::Result;

pub(crate) fn ensure_private_dir(path: &Path) -> Result<()> {
    if !path.is_dir() {
        fs::create_dir_all(path)?;
    }
    set_owner_read_write_execute_only(path)?;
    Ok(())
}

pub(crate) fn set_owner_read_write_only(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        set_mode(path, 0o600)?;
    }
    Ok(())
}

pub(crate) fn set_owner_read_write_execute_only(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        set_mode(path, 0o700)?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    // chmod always rewrites the inode (ctime, FSEvents) even when the mode is unchanged,
    // and these helpers run on every store open.
    if fs::metadata(path)?.permissions().mode() & 0o7777 == mode {
        return Ok(());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use super::*;

    #[test]
    fn ensure_private_dir_leaves_correct_directories_untouched() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = root.path().join("private");
        ensure_private_dir(dir.as_path()).expect("create private dir");
        let before = fs::metadata(dir.as_path()).expect("metadata");
        assert_eq!(before.permissions().mode() & 0o7777, 0o700);

        std::thread::sleep(std::time::Duration::from_millis(20));
        ensure_private_dir(dir.as_path()).expect("ensure private dir again");
        let after = fs::metadata(dir.as_path()).expect("metadata");
        assert_eq!(
            (after.ctime(), after.ctime_nsec()),
            (before.ctime(), before.ctime_nsec()),
            "an already-private directory must not be chmodded again"
        );
    }

    #[test]
    fn ensure_private_dir_still_tightens_broad_permissions() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = root.path().join("broad");
        fs::create_dir(dir.as_path()).expect("create dir");
        fs::set_permissions(dir.as_path(), fs::Permissions::from_mode(0o755)).expect("chmod");
        ensure_private_dir(dir.as_path()).expect("ensure private dir");
        let mode = fs::metadata(dir.as_path())
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o7777, 0o700);
    }
}
