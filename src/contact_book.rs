// SPDX-License-Identifier: GPL-3.0-or-later
//! Local identifier list shared by contact commands and receiving policy.
use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

const LIMIT: u64 = 1024 * 1024;
const MAX_CONTACTS: usize = 4096;

pub fn default_path(home: &Path) -> PathBuf {
    home.join(".config/owl_rs/known-senders")
}

// The receiving policy also accepts hand-edited, formatted identifiers.
fn normalize(identifier: &str) -> String {
    let identifier = identifier.trim();
    if identifier.contains('@') {
        identifier.to_lowercase()
    } else {
        identifier.chars().filter(char::is_ascii_digit).collect()
    }
}
fn identifier_line(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let normalized = normalize(line);
    (!normalized.is_empty()).then_some(normalized)
}
fn entries(text: &str) -> Result<Vec<String>> {
    let mut seen = HashSet::new();
    let mut entries = Vec::new();
    for id in text.lines().filter_map(identifier_line) {
        if seen.insert(id.clone()) {
            entries.push(id);
            ensure!(
                entries.len() <= MAX_CONTACTS,
                "contacts file exceeds 4096 identifiers"
            );
        }
    }
    Ok(entries)
}
fn read(path: &Path) -> Result<String> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(e) => return Err(e).context("read contacts file"),
    };
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= LIMIT,
        "invalid contacts file"
    );
    let mut text = String::new();
    file.take(LIMIT + 1).read_to_string(&mut text)?;
    ensure!(text.len() as u64 <= LIMIT, "contacts file exceeds 1 MiB");
    Ok(text)
}
/// Return normalized, distinct identifiers in file order; a missing list is empty.
pub fn list(path: &Path) -> Result<Vec<String>> {
    entries(&read(path)?)
}

fn validate(identifier: &str) -> Result<String> {
    ensure!(
        !identifier.chars().any(char::is_control),
        "contact contains control characters"
    );
    let id = identifier.trim();
    let normalized = normalize(id);
    let valid = if id.contains('@') {
        let parts: Vec<_> = id.split('@').collect();
        !id.starts_with('#')
            && parts.len() == 2
            && !parts[0].is_empty()
            && parts[1].split('.').count() >= 2
            && parts[1].split('.').all(|part| !part.is_empty())
            && !id.chars().any(char::is_whitespace)
    } else {
        id.chars()
            .all(|c| c.is_ascii_digit() || "+().- ".contains(c))
            && (7..=15).contains(&normalized.len())
    };
    ensure!(
        valid,
        "contact must be an email address or a phone number with 7–15 digits (include the country code)"
    );
    Ok(normalized)
}

/// Atomic, serialized updates. The owner applies to newly created directories and files.
pub struct Book {
    path: PathBuf,
    owner: Option<(u32, u32)>,
}
impl Book {
    pub fn new(path: PathBuf, owner: Option<(u32, u32)>) -> Self {
        Self { path, owner }
    }
    /// Add identifiers after validating the entire batch; return the number added.
    pub fn add(&self, identifiers: &[String]) -> Result<usize> {
        self.update(identifiers, true)
    }
    /// Remove all matching spellings; return the number of distinct identifiers removed.
    pub fn remove(&self, identifiers: &[String]) -> Result<usize> {
        self.update(identifiers, false)
    }
    fn update(&self, identifiers: &[String], add: bool) -> Result<usize> {
        ensure!(!identifiers.is_empty(), "provide at least one contact");
        let identifiers = identifiers
            .iter()
            .map(|id| validate(id))
            .collect::<Result<Vec<_>>>()?;
        let parent = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        crate::identity::private_directory(parent, self.owner)?;
        // Lock a stable sidecar: replacing the list changes its inode.
        let mut lock_name = self
            .path
            .file_name()
            .context("contacts path has no filename")?
            .to_os_string();
        lock_name.push(".lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(parent.join(lock_name))?;
        ensure!(lock.metadata()?.is_file(), "invalid contacts lock file");
        lock.lock_exclusive()?;
        if let Some((uid, gid)) = self.owner {
            set_owner(&lock, uid, gid)?;
        }
        ensure!(
            !self.path.is_symlink(),
            "cannot update a symlink; use its target as --contacts-file"
        );
        let mut text = read(&self.path)?;
        let original: HashSet<_> = entries(&text)?.into_iter().collect();
        let mut changed = 0;
        if add {
            let mut known = original;
            for id in identifiers {
                if known.insert(id.clone()) {
                    if !text.is_empty() && !text.ends_with('\n') {
                        text.push('\n');
                    }
                    text.push_str(&id);
                    text.push('\n');
                    changed += 1;
                }
            }
        } else {
            let targets: HashSet<_> = identifiers.into_iter().collect();
            changed = original.intersection(&targets).count();
            text = text
                .split_inclusive('\n')
                .filter(|line| identifier_line(line).is_none_or(|id| !targets.contains(&id)))
                .collect();
        }
        if changed == 0 {
            return Ok(0);
        }
        ensure!(text.len() as u64 <= LIMIT, "contacts file exceeds 1 MiB");
        entries(&text)?;
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        if let Some((uid, gid)) = self.owner {
            set_owner(file.as_file(), uid, gid)?;
        }
        file.write_all(text.as_bytes())?;
        file.as_file().sync_all()?;
        file.persist(&self.path)?;
        File::open(parent)?.sync_all()?;
        Ok(changed)
    }
}
fn set_owner(file: &File, uid: u32, gid: u32) -> Result<()> {
    nix::unistd::fchown(
        file,
        Some(nix::unistd::Uid::from_raw(uid)),
        Some(nix::unistd::Gid::from_raw(gid)),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn updates_preserve_policy_normalization_privacy_and_concurrent_edits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("contacts");
        std::fs::write(
            &path,
            "# Keep this comment\n Friend@Example.COM \n+1 (555) 010-1234\n",
        )
        .unwrap();
        let book = Book::new(path.clone(), None);
        assert_eq!(
            book.add(&["FRIEND@example.com".into(), "15550101234".into()])
                .unwrap(),
            0
        );
        let original = std::fs::read(&path).unwrap();
        assert!(
            book.add(&[
                "new@example.com".into(),
                "invalid\nextra@example.com".into()
            ])
            .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert!(book.add(&["#injection@example.com".into()]).is_err());
        std::thread::scope(|scope| {
            for id in ["second@example.com", "third@example.com"] {
                let book = &book;
                scope.spawn(move || book.add(&[id.into()]).unwrap());
            }
        });
        assert_eq!(list(&path).unwrap().len(), 4);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // Removal matches the hashes used by the receiver, even for hand-edited entries.
        assert_eq!(
            book.remove(&["friend@example.com".into(), "+1-555-010-1234".into()])
                .unwrap(),
            2
        );
        assert_eq!(list(&path).unwrap().len(), 2);
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .starts_with("# Keep this comment\n")
        );
        let remaining = list(&path).unwrap();
        assert_eq!(book.remove(&remaining).unwrap(), 2);
        assert!(list(&path).unwrap().is_empty());
        assert_eq!(book.remove(&remaining).unwrap(), 0);
        let missing = dir.path().join("missing");
        assert!(list(&missing).unwrap().is_empty());
        assert_eq!(
            Book::new(missing.clone(), None).remove(&remaining).unwrap(),
            0
        );
        assert!(!missing.exists());
    }
}
