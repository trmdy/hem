use std::{fs, path::Path};

use crate::Result;

pub(crate) fn ensure_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
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

    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}
