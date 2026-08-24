//! The named-vault registry: `~/.passlane/vaults.json` plus the
//! `~/.passlane/.active_vault` pointer, and the process-wide "current vault"
//! that actions operate on.
//!
//! A vault is one kdbx file with optional keyfile and hardware-key factors;
//! any vault can hold credentials, payment cards, notes and TOTP entries.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

use crate::hwkey::HwKeyConfig;
use crate::store;
use crate::vault::entities::Error;

pub const REGISTRY_FILENAME: &str = "vaults.json";
pub const ACTIVE_VAULT_FILENAME: &str = ".active_vault";

/// Name given to the legacy main vault during migration.
pub const LEGACY_MAIN_VAULT_NAME: &str = "default";
/// Name given to the legacy TOTP vault during migration.
pub const LEGACY_TOTP_VAULT_NAME: &str = "totp";

const REGISTRY_VERSION: u32 = 1;

const LEGACY_CONFIG_FILES: [&str; 5] = [
    ".vault_path",
    ".keyfile_path",
    ".hwkey",
    ".totp_vault_path",
    ".totp_keyfile_path",
];

/// A named vault: one kdbx file plus its optional unlock factors.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VaultConfig {
    pub name: String,
    /// Path of the kdbx file. Stored absolute — passlane expands `~` and
    /// resolves relative input against the working directory at
    /// registration time (see `absolutize`).
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Stored absolute like `path`: a relative keyfile would resolve against
    /// whatever directory passlane runs from.
    pub keyfile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hwkey: Option<HwKeyConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RegistryFile {
    version: u32,
    vaults: Vec<VaultConfig>,
}

/// Vault names end up in keychain account names, cache filenames and the
/// shell; keep them short and filename-safe.
pub fn validate_name(name: &str) -> Result<(), Error> {
    if name.is_empty() {
        return Err(Error::new("Vault name must not be empty"));
    }
    if name.len() > 64 {
        return Err(Error::new("Vault name must be at most 64 characters"));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Error::new(
            "Vault name may only contain letters, digits, '-' and '_'",
        ));
    }
    Ok(())
}

pub fn find<'a>(vaults: &'a [VaultConfig], name: &str) -> Option<&'a VaultConfig> {
    vaults.iter().find(|v| v.name == name)
}

fn unknown_vault_error(name: &str, vaults: &[VaultConfig]) -> Error {
    if vaults.is_empty() {
        return Error::new(
            "No vaults are configured. Run 'passlane init' to create one, \
             or 'passlane vault add' to register an existing vault file.",
        );
    }
    let names: Vec<&str> = vaults.iter().map(|v| v.name.as_str()).collect();
    Error::new(&format!(
        "No vault named '{}'. Configured vaults: {}. \
         Use '--vault <name>' for a single command or 'passlane vault use <name>' to switch.",
        name,
        names.join(", ")
    ))
}

fn registry_path(dir: &Path) -> PathBuf {
    dir.join(REGISTRY_FILENAME)
}

/// The registry file location, for error messages that tell the user where
/// to fix things by hand.
pub fn registry_file_display() -> String {
    registry_path(&store::dir_path()).display().to_string()
}

fn active_vault_path(dir: &Path) -> PathBuf {
    dir.join(ACTIVE_VAULT_FILENAME)
}

/// Load the registry; an absent file is an empty registry (first run).
pub fn load_from(dir: &Path) -> Result<Vec<VaultConfig>, Error> {
    let path = registry_path(dir);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(&path).map_err(|e| {
        Error::new(&format!(
            "Could not read the vault registry {}: {}",
            path.display(),
            e
        ))
    })?;
    let file: RegistryFile = serde_json::from_str(&content).map_err(|e| {
        Error::new(&format!(
            "Could not parse the vault registry {}: {}",
            path.display(),
            e
        ))
    })?;
    if file.version > REGISTRY_VERSION {
        return Err(Error::new(&format!(
            "The vault registry {} was written by a newer passlane version \
             (format version {}); upgrade passlane to read it.",
            path.display(),
            file.version
        )));
    }
    validate_entries(&path, &file.vaults)?;
    Ok(file.vaults)
}

/// The registry is normally only written by passlane, but it is a
/// hand-editable JSON file and vault names end up in keychain account names
/// and completion-cache filenames — so entries are validated on load too.
fn validate_entries(path: &Path, vaults: &[VaultConfig]) -> Result<(), Error> {
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for vault in vaults {
        if let Err(e) = validate_name(&vault.name) {
            return Err(Error::new(&format!(
                "{}: vault entry '{}' has an invalid name ({}). \
                 Fix the file or remove the entry.",
                path.display(),
                vault.name,
                e.message
            )));
        }
        if vault.path.trim().is_empty() {
            return Err(Error::new(&format!(
                "{}: vault '{}' has no path. Fix the file or remove the entry.",
                path.display(),
                vault.name
            )));
        }
        if !seen.insert(vault.name.as_str()) {
            return Err(Error::new(&format!(
                "{}: more than one vault named '{}'. Fix the file or remove the duplicate.",
                path.display(),
                vault.name
            )));
        }
    }
    Ok(())
}

/// Save the registry atomically (temp file + rename) so a crash mid-write
/// cannot leave a truncated vaults.json behind.
pub fn save_to(dir: &Path, vaults: &[VaultConfig]) -> Result<(), Error> {
    let file = RegistryFile {
        version: REGISTRY_VERSION,
        vaults: vaults.to_vec(),
    };
    let path = registry_path(dir);
    // The temp name is unique per process: concurrent passlane invocations
    // must not fight over one temp file. Each rename then atomically
    // replaces the previous registry (last writer wins).
    let tmp = dir.join(format!("{}.{}.tmp", REGISTRY_FILENAME, std::process::id()));
    let content = serde_json::to_string_pretty(&file).map_err(|e| {
        Error::new(&format!(
            "Could not serialize the vault registry {}: {}",
            path.display(),
            e
        ))
    })?;
    {
        use std::io::Write;
        let mut out = store::create_private_file(&tmp)?;
        out.write_all(content.as_bytes())?;
        out.flush()?;
    }
    // rename replaces the destination on Unix and (via MoveFileEx) on
    // Windows; fall back to a two-step swap for platforms that refuse. The
    // previous registry is only given up once the new one is in place, and
    // the temp file always holds the new content for manual recovery.
    if let Err(e) = fs::rename(&tmp, &path) {
        if !path.exists() {
            return Err(Error::new(&format!(
                "Could not save {}: {}. The new content is preserved in {}.",
                path.display(),
                e,
                tmp.display()
            )));
        }
        let backup = dir.join(format!("{}.{}.bak", REGISTRY_FILENAME, std::process::id()));
        fs::rename(&path, &backup).map_err(|swap_err| {
            Error::new(&format!(
                "Could not save {}: {}; moving the existing registry aside failed: {}. \
                 The new content is preserved in {}.",
                path.display(),
                e,
                swap_err,
                tmp.display()
            ))
        })?;
        if let Err(place_err) = fs::rename(&tmp, &path) {
            let restore_result = fs::rename(&backup, &path);
            return Err(Error::new(&format!(
                "Could not save {}: {}. {}",
                path.display(),
                place_err,
                match restore_result {
                    Ok(()) => format!(
                        "The previous registry is unchanged; the new content is preserved in {}.",
                        tmp.display()
                    ),
                    Err(restore_err) => format!(
                        "Restoring the previous registry also failed: {}; it is preserved in {}.",
                        restore_err,
                        backup.display()
                    ),
                }
            )));
        }
        let _ = fs::remove_file(&backup);
    }
    Ok(())
}

/// Vault paths are stored absolute: a relative path (typed at a prompt or
/// found in a legacy config file) would otherwise resolve against whatever
/// directory passlane happens to run from. A leading `~` is expanded to the
/// home directory.
pub(crate) fn absolutize(path: &str) -> String {
    let trimmed = path.trim();
    let expanded = if trimmed == "~" {
        dirs::home_dir().map(|h| h.to_string_lossy().to_string())
    } else if let Some(rest) = trimmed.strip_prefix("~/") {
        dirs::home_dir().map(|h| h.join(rest).to_string_lossy().to_string())
    } else {
        None
    };
    let candidate = expanded.unwrap_or_else(|| trimmed.to_string());
    if Path::new(&candidate).is_absolute() {
        candidate
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(&candidate).to_string_lossy().to_string())
            .unwrap_or(candidate)
    }
}

pub fn get_active_from(dir: &Path) -> Option<String> {
    fs::read_to_string(active_vault_path(dir))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Write (or, with None, remove) the active-vault pointer. The name is not
/// re-validated; callers pass a name from the registry.
fn write_active_to(dir: &Path, name: Option<&str>) -> Result<(), Error> {
    let path = active_vault_path(dir);
    match name {
        Some(name) => {
            use std::io::Write;
            let mut out = store::create_private_file(&path)?;
            out.write_all(name.as_bytes())?;
            out.flush()?;
        }
        None => {
            fs::remove_file(&path).or_else(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    Ok(())
                } else {
                    Err(e)
                }
            })?;
        }
    }
    Ok(())
}

/// Make `name` the active vault. Fails when no vault with that name exists.
pub fn set_active_to(dir: &Path, name: &str) -> Result<(), Error> {
    let vaults = load_from(dir)?;
    if find(&vaults, name).is_none() {
        return Err(unknown_vault_error(name, &vaults));
    }
    write_active_to(dir, Some(name))
}

pub fn add_vault_to(dir: &Path, mut config: VaultConfig) -> Result<(), Error> {
    validate_name(&config.name)?;
    config.path = absolutize(&config.path);
    config.keyfile = config.keyfile.as_deref().map(absolutize);
    let mut vaults = load_from(dir)?;
    if find(&vaults, &config.name).is_some() {
        return Err(Error::new(&format!(
            "A vault named '{}' already exists",
            config.name
        )));
    }
    vaults.push(config);
    save_to(dir, &vaults)
}

/// Remove a vault from the registry. Returns the removed config so callers
/// can clean up keychain entries and caches. If it was the active vault, the
/// pointer moves to the first remaining vault (or is removed when the
/// registry becomes empty).
pub fn remove_vault_from(dir: &Path, name: &str) -> Result<VaultConfig, Error> {
    let mut vaults = load_from(dir)?;
    let index = vaults
        .iter()
        .position(|v| v.name == name)
        .ok_or_else(|| unknown_vault_error(name, &vaults))?;
    let removed = vaults.remove(index);
    save_to(dir, &vaults)?;
    if get_active_from(dir).as_deref() == Some(name) {
        let next = vaults.first().map(|v| v.name.clone());
        write_active_to(dir, next.as_deref())?;
    }
    Ok(removed)
}

/// Validate that `rename_vault_from` would succeed, without mutating
/// anything — callers move the vault's keychain entry around the rename and
/// need every failure to surface before any mutation happens.
pub fn check_rename_to(dir: &Path, old_name: &str, new_name: &str) -> Result<(), Error> {
    validate_name(new_name)?;
    let vaults = load_from(dir)?;
    if find(&vaults, old_name).is_none() {
        return Err(unknown_vault_error(old_name, &vaults));
    }
    if old_name != new_name && find(&vaults, new_name).is_some() {
        return Err(Error::new(&format!(
            "A vault named '{}' already exists",
            new_name
        )));
    }
    Ok(())
}

/// Rename a vault. The keychain entry move is the caller's job (it needs the
/// password, not just the registry).
pub fn rename_vault_from(dir: &Path, old_name: &str, new_name: &str) -> Result<(), Error> {
    check_rename_to(dir, old_name, new_name)?;
    let mut vaults = load_from(dir)?;
    let vault = vaults.iter_mut().find(|v| v.name == old_name).unwrap();
    vault.name = new_name.to_string();
    save_to(dir, &vaults)?;
    if get_active_from(dir).as_deref() == Some(old_name) {
        write_active_to(dir, Some(new_name))?;
    }
    Ok(())
}

/// Update the hardware-key enrollment stored for a vault.
pub fn set_hwkey_to(dir: &Path, vault_name: &str, hwkey: Option<HwKeyConfig>) -> Result<(), Error> {
    let mut vaults = load_from(dir)?;
    if find(&vaults, vault_name).is_none() {
        return Err(unknown_vault_error(vault_name, &vaults));
    }
    let vault = vaults.iter_mut().find(|v| v.name == vault_name).unwrap();
    vault.hwkey = hwkey;
    save_to(dir, &vaults)
}

/// Pick the vault a command operates on: an explicit `--vault`/`PASSLANE_VAULT`
/// name first, then the active vault, then the only registered vault.
pub fn resolve_from(dir: &Path, explicit: Option<&str>) -> Result<VaultConfig, Error> {
    let vaults = load_from(dir)?;
    if let Some(name) = explicit.filter(|n| !n.is_empty()) {
        return find(&vaults, name)
            .cloned()
            .ok_or_else(|| unknown_vault_error(name, &vaults));
    }
    if let Some(active) = get_active_from(dir) {
        if let Some(vault) = find(&vaults, &active) {
            return Ok(vault.clone());
        }
        eprintln!(
            "Warning: the active vault '{}' is not registered; ignoring it.",
            active
        );
    }
    if vaults.len() == 1 {
        return Ok(vaults[0].clone());
    }
    if vaults.is_empty() {
        return Err(Error::new(
            "No vaults are configured. Run 'passlane init' to create one, \
             or 'passlane vault add' to register an existing vault file.",
        ));
    }
    let names: Vec<&str> = vaults.iter().map(|v| v.name.as_str()).collect();
    Err(Error::new(&format!(
        "Several vaults are configured and none is active: {}. \
         Use 'passlane vault use <name>' to pick one, or --vault <name> for a single command.",
        names.join(", ")
    )))
}

/// The process-wide current vault, set once per invocation after argument
/// parsing (and re-set by the REPL on 'vault use'). Held in a global to keep
/// the existing parameterless lookups (store::get_vault_path and friends)
/// working during the migration to the registry.
static CURRENT: RwLock<Option<VaultConfig>> = RwLock::new(None);

pub fn set_current(vault: VaultConfig) {
    *CURRENT.write().unwrap() = Some(vault);
}

pub fn current() -> Result<VaultConfig, Error> {
    CURRENT
        .read()
        .unwrap()
        .clone()
        .ok_or_else(|| Error::new("No vault selected. Run 'passlane init' or 'passlane vault use'."))
}

/// Resolve the target vault and make it the current one. Errors are deferred:
/// callers that can work without a vault (init, gen, vault management) ignore
/// them, the rest surface them via current().
pub fn init_current(explicit: Option<&str>) -> Result<VaultConfig, Error> {
    let vault = resolve_from(&store::dir_path(), explicit)?;
    set_current(vault.clone());
    Ok(vault)
}

fn read_trimmed(dir: &Path, filename: &str) -> Option<String> {
    fs::read_to_string(dir.join(filename))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Read the legacy `~/.passlane/.hwkey` enrollment. A file that exists but
/// cannot be read is a hard error: migrating the vault without the factor
/// would let passlane drop it from every future unlock, locking the user out
/// of a hardware-key-protected vault with a misleading wrong-password error.
fn read_legacy_hwkey(dir: &Path) -> Result<Option<HwKeyConfig>, Error> {
    let path = dir.join(".hwkey");
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(&path).map_err(|e| {
        Error::new(&format!(
            "The hardware key config {} exists but cannot be read: {}. \
             Fix its permissions and run passlane again to retry the migration.",
            path.display(),
            e
        ))
    })?;
    Ok(Some(HwKeyConfig::parse(&content)?))
}

/// Migrate the pre-multi-vault dot-files into the registry. Pure file work,
/// no keychain access, so it is unit-testable. Returns the names of the
/// vaults created, or None when there was nothing to migrate.
fn migrate_files_from(dir: &Path) -> Result<Option<Vec<String>>, Error> {
    if registry_path(dir).exists() {
        return Ok(None);
    }
    let main_configured = [".vault_path", ".keyfile_path", ".hwkey"]
        .iter()
        .any(|f| dir.join(f).exists());
    let totp_configured = [".totp_vault_path", ".totp_keyfile_path"]
        .iter()
        .any(|f| dir.join(f).exists());
    if !main_configured && !totp_configured {
        return Ok(None);
    }

    let mut vaults = Vec::new();
    if main_configured {
        vaults.push(VaultConfig {
            name: LEGACY_MAIN_VAULT_NAME.to_string(),
            path: absolutize(
                &read_trimmed(dir, ".vault_path")
                    .unwrap_or_else(|| dir.join("store.kdbx").to_string_lossy().to_string()),
            ),
            keyfile: read_trimmed(dir, ".keyfile_path").as_deref().map(absolutize),
            hwkey: read_legacy_hwkey(dir)?,
        });
    }
    if totp_configured {
        vaults.push(VaultConfig {
            name: LEGACY_TOTP_VAULT_NAME.to_string(),
            path: absolutize(
                &read_trimmed(dir, ".totp_vault_path")
                    .unwrap_or_else(|| dir.join("totp.kdbx").to_string_lossy().to_string()),
            ),
            keyfile: read_trimmed(dir, ".totp_keyfile_path").as_deref().map(absolutize),
            hwkey: None,
        });
    }

    let names: Vec<String> = vaults.iter().map(|v| v.name.clone()).collect();
    save_to(dir, &vaults)?;
    write_active_to(dir, vaults.first().map(|v| v.name.as_str()))?;
    // Only after the registry is safely on disk do the old dot-files go away;
    // a failed removal is inert (nothing reads them anymore) so it just warns.
    for file in LEGACY_CONFIG_FILES {
        if let Err(e) = fs::remove_file(dir.join(file)) {
            if e.kind() != std::io::ErrorKind::NotFound {
                eprintln!("Warning: could not remove the legacy config '{}': {}", file, e);
            }
        }
    }
    Ok(Some(names))
}

/// Migrate the legacy single-vault configuration to the registry, including
/// the best-effort keychain re-keying. Ok(true) when a migration happened.
pub fn migrate_legacy() -> Result<bool, Error> {
    let dir = store::dir_path();
    let Some(names) = migrate_files_from(&dir)? else {
        return Ok(false);
    };

    // Re-key the keychain entries. Best-effort: when the machine was locked
    // the old entry is absent, and the user just re-enters the password once
    // at the next unlock.
    if names.iter().any(|n| n == LEGACY_MAIN_VAULT_NAME) {
        if let Err(e) =
            crate::keychain::migrate_legacy_password("passlane_master_pwd", LEGACY_MAIN_VAULT_NAME)
        {
            eprintln!(
                "Warning: could not move the stored master password to vault '{}': {}",
                LEGACY_MAIN_VAULT_NAME, e
            );
        }
    }
    if names.iter().any(|n| n == LEGACY_TOTP_VAULT_NAME) {
        if let Err(e) = crate::keychain::migrate_legacy_password(
            "passlane_totp_master_pwd",
            LEGACY_TOTP_VAULT_NAME,
        ) {
            eprintln!(
                "Warning: could not move the stored TOTP master password to vault '{}': {}",
                LEGACY_TOTP_VAULT_NAME, e
            );
        }
    }

    println!(
        "Migrated the existing configuration to the multi-vault registry ({}). \
         Vaults: {}. Manage them with 'passlane vault list'.",
        dir.join(REGISTRY_FILENAME).display(),
        names.join(", ")
    );
    Ok(true)
}

// Home-directory convenience wrappers used outside tests.

pub fn load() -> Result<Vec<VaultConfig>, Error> {
    load_from(&store::dir_path())
}

pub fn get_active() -> Option<String> {
    get_active_from(&store::dir_path())
}

pub fn set_active(name: &str) -> Result<(), Error> {
    set_active_to(&store::dir_path(), name)
}

pub fn add_vault(config: VaultConfig) -> Result<(), Error> {
    add_vault_to(&store::dir_path(), config)
}

pub fn remove_vault(name: &str) -> Result<VaultConfig, Error> {
    remove_vault_from(&store::dir_path(), name)
}

pub fn rename_vault(old_name: &str, new_name: &str) -> Result<(), Error> {
    rename_vault_from(&store::dir_path(), old_name, new_name)
}

/// Home-directory variant of `check_rename_to`.
pub fn check_rename(old_name: &str, new_name: &str) -> Result<(), Error> {
    check_rename_to(&store::dir_path(), old_name, new_name)
}

pub fn set_hwkey(vault_name: &str, hwkey: Option<HwKeyConfig>) -> Result<(), Error> {
    set_hwkey_to(&store::dir_path(), vault_name, hwkey)
}

pub fn resolve(explicit: Option<&str>) -> Result<VaultConfig, Error> {
    resolve_from(&store::dir_path(), explicit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample_vault(name: &str) -> VaultConfig {
        VaultConfig {
            name: name.to_string(),
            path: format!("/tmp/{}.kdbx", name),
            keyfile: None,
            hwkey: None,
        }
    }

    fn write(dir: &Path, file: &str, content: &str) {
        std::fs::write(dir.join(file), content).unwrap();
    }

    #[test]
    fn registry_roundtrip() {
        let dir = tempdir().unwrap();
        assert!(load_from(dir.path()).unwrap().is_empty());
        let vaults = vec![
            sample_vault("personal"),
            VaultConfig {
                name: "work".to_string(),
                path: "/vaults/work.kdbx".to_string(),
                keyfile: Some("/vaults/key".to_string()),
                hwkey: Some(HwKeyConfig {
                    slot: 2,
                    serial: Some(42),
                }),
            },
        ];
        save_to(dir.path(), &vaults).unwrap();
        assert_eq!(load_from(dir.path()).unwrap(), vaults);
        // Saving again must replace the existing registry, not fail on it.
        save_to(dir.path(), &vaults).unwrap();
        assert_eq!(load_from(dir.path()).unwrap(), vaults);
        // Temp files must not linger next to the registry.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("vaults.json."))
            .collect();
        assert!(leftovers.is_empty(), "leftover temp files: {:?}", leftovers);
    }

    #[test]
    fn load_rejects_hand_edited_registry_entries() {
        let dir = tempdir().unwrap();
        let path = registry_path(dir.path());
        // Unsafe name: path separators would leak into keychain accounts and
        // completion-cache filenames.
        std::fs::write(
            &path,
            r#"{"version":1,"vaults":[{"name":"../evil","path":"/x.kdbx"}]}"#,
        )
        .unwrap();
        let err = load_from(dir.path()).unwrap_err();
        assert!(err.message.contains("../evil"), "{}", err.message);

        // Duplicate names.
        std::fs::write(
            &path,
            r#"{"version":1,"vaults":[{"name":"a","path":"/a.kdbx"},{"name":"a","path":"/b.kdbx"}]}"#,
        )
        .unwrap();
        let err = load_from(dir.path()).unwrap_err();
        assert!(err.message.contains("more than one vault named 'a'"), "{}", err.message);

        // Missing path.
        std::fs::write(&path, r#"{"version":1,"vaults":[{"name":"a","path":""}]}"#).unwrap();
        let err = load_from(dir.path()).unwrap_err();
        assert!(err.message.contains("has no path"), "{}", err.message);

        // Every error points the user at the registry file.
        assert!(err.message.contains(path.file_name().unwrap().to_string_lossy().as_ref()));
    }

    #[test]
    fn add_rejects_duplicate_and_invalid_names() {
        let dir = tempdir().unwrap();
        add_vault_to(dir.path(), sample_vault("work")).unwrap();
        assert!(add_vault_to(dir.path(), sample_vault("work")).is_err());
        assert!(add_vault_to(dir.path(), sample_vault("has space")).is_err());
        assert!(add_vault_to(dir.path(), sample_vault("")).is_err());
        assert!(add_vault_to(dir.path(), sample_vault("a/b")).is_err());
    }

    #[test]
    fn active_vault_requires_known_name() {
        let dir = tempdir().unwrap();
        add_vault_to(dir.path(), sample_vault("work")).unwrap();
        assert!(set_active_to(dir.path(), "nope").is_err());
        set_active_to(dir.path(), "work").unwrap();
        assert_eq!(get_active_from(dir.path()), Some("work".to_string()));
    }

    #[test]
    fn resolve_prefers_explicit_then_active_then_single() {
        let dir = tempdir().unwrap();
        add_vault_to(dir.path(), sample_vault("work")).unwrap();
        add_vault_to(dir.path(), sample_vault("home")).unwrap();

        // Single vault is implicit before a second one exists.
        let single = tempdir().unwrap();
        add_vault_to(single.path(), sample_vault("only")).unwrap();
        assert_eq!(resolve_from(single.path(), None).unwrap().name, "only");

        // Several vaults, no active: explicit still works, bare resolve errors.
        let err = resolve_from(dir.path(), None).unwrap_err();
        assert!(err.message.contains("none is active"));
        assert_eq!(resolve_from(dir.path(), Some("home")).unwrap().name, "home");

        // Active beats the implicit single vault but not the explicit name.
        set_active_to(dir.path(), "work").unwrap();
        assert_eq!(resolve_from(dir.path(), None).unwrap().name, "work");
        assert_eq!(resolve_from(dir.path(), Some("home")).unwrap().name, "home");

        // Unknown explicit name lists the configured vaults.
        let err = resolve_from(dir.path(), Some("nope")).unwrap_err();
        assert!(err.message.contains("work, home"));
    }

    #[test]
    fn unknown_vault_on_empty_registry_gives_setup_guidance() {
        let dir = tempdir().unwrap();
        let err = resolve_from(dir.path(), Some("ghost")).unwrap_err();
        assert!(err.message.contains("passlane init"), "{}", err.message);
        assert!(!err.message.contains("Configured vaults: ."), "{}", err.message);
        let err = set_active_to(dir.path(), "ghost").unwrap_err();
        assert!(err.message.contains("passlane vault add"), "{}", err.message);
    }

    #[test]
    fn remove_moves_active_pointer_to_first_remaining() {
        let dir = tempdir().unwrap();
        add_vault_to(dir.path(), sample_vault("a")).unwrap();
        add_vault_to(dir.path(), sample_vault("b")).unwrap();
        set_active_to(dir.path(), "a").unwrap();

        remove_vault_from(dir.path(), "a").unwrap();
        assert_eq!(get_active_from(dir.path()), Some("b".to_string()));

        remove_vault_from(dir.path(), "b").unwrap();
        assert_eq!(get_active_from(dir.path()), None);
        assert!(load_from(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn rename_updates_active_pointer() {
        let dir = tempdir().unwrap();
        add_vault_to(dir.path(), sample_vault("old")).unwrap();
        set_active_to(dir.path(), "old").unwrap();
        rename_vault_from(dir.path(), "old", "new").unwrap();
        assert_eq!(get_active_from(dir.path()), Some("new".to_string()));
        assert!(find(&load_from(dir.path()).unwrap(), "new").is_some());
    }

    #[test]
    fn check_rename_validates_without_mutating() {
        let dir = tempdir().unwrap();
        add_vault_to(dir.path(), sample_vault("a")).unwrap();
        add_vault_to(dir.path(), sample_vault("b")).unwrap();

        assert!(check_rename_to(dir.path(), "a", "c").is_ok());
        // Unknown source, duplicate target and invalid names all fail...
        assert!(check_rename_to(dir.path(), "nope", "c").is_err());
        assert!(check_rename_to(dir.path(), "a", "b").is_err());
        assert!(check_rename_to(dir.path(), "a", "has space").is_err());
        // ...but leave the registry untouched.
        let vaults = load_from(dir.path()).unwrap();
        assert!(find(&vaults, "a").is_some());
        assert!(find(&vaults, "b").is_some());
        assert!(find(&vaults, "c").is_none());
    }

    #[test]
    fn set_hwkey_updates_the_right_vault() {
        let dir = tempdir().unwrap();
        add_vault_to(dir.path(), sample_vault("a")).unwrap();
        add_vault_to(dir.path(), sample_vault("b")).unwrap();
        let hwkey = HwKeyConfig {
            slot: 1,
            serial: None,
        };
        set_hwkey_to(dir.path(), "b", Some(hwkey.clone())).unwrap();
        let vaults = load_from(dir.path()).unwrap();
        assert_eq!(find(&vaults, "a").unwrap().hwkey, None);
        assert_eq!(find(&vaults, "b").unwrap().hwkey, Some(hwkey));
    }

    #[test]
    fn migrate_full_legacy_config() {
        let dir = tempdir().unwrap();
        write(dir.path(), ".vault_path", "/old/store.kdbx\n");
        write(dir.path(), ".keyfile_path", "/old/keyfile\n");
        write(dir.path(), ".hwkey", "slot=2\nserial=12345678\n");
        write(dir.path(), ".totp_vault_path", "/old/totp.kdbx\n");

        let names = migrate_files_from(dir.path()).unwrap().unwrap();
        assert_eq!(names, vec!["default", "totp"]);

        let vaults = load_from(dir.path()).unwrap();
        let main = find(&vaults, "default").unwrap();
        assert_eq!(main.path, "/old/store.kdbx");
        assert_eq!(main.keyfile.as_deref(), Some("/old/keyfile"));
        assert_eq!(
            main.hwkey,
            Some(HwKeyConfig {
                slot: 2,
                serial: Some(12345678),
            })
        );
        let totp = find(&vaults, "totp").unwrap();
        assert_eq!(totp.path, "/old/totp.kdbx");
        assert_eq!(get_active_from(dir.path()), Some("default".to_string()));

        for file in LEGACY_CONFIG_FILES {
            assert!(!dir.path().join(file).exists(), "{} still exists", file);
        }
    }

    #[test]
    fn migrate_totp_only_config() {
        let dir = tempdir().unwrap();
        write(dir.path(), ".totp_vault_path", "/old/totp.kdbx\n");
        let names = migrate_files_from(dir.path()).unwrap().unwrap();
        assert_eq!(names, vec!["totp"]);
        assert_eq!(get_active_from(dir.path()), Some("totp".to_string()));
    }

    #[test]
    fn migrate_skips_fresh_installs_and_existing_registry() {
        // No config at all: nothing to do.
        let dir = tempdir().unwrap();
        assert!(migrate_files_from(dir.path()).unwrap().is_none());
        assert!(!registry_path(dir.path()).exists());

        // Registry already present: never touch anything.
        write(dir.path(), ".vault_path", "/old/store.kdbx\n");
        add_vault_to(dir.path(), sample_vault("mine")).unwrap();
        assert!(migrate_files_from(dir.path()).unwrap().is_none());
        assert!(dir.path().join(".vault_path").exists());
    }

    #[test]
    fn migrate_defaults_paths_when_only_dotfiles_exist() {
        let dir = tempdir().unwrap();
        // A keyfile config without a vault path still migrates the main vault
        // with the default store.kdbx location.
        write(dir.path(), ".keyfile_path", "/old/keyfile\n");
        let names = migrate_files_from(dir.path()).unwrap().unwrap();
        assert_eq!(names, vec!["default"]);
        let vaults = load_from(dir.path()).unwrap();
        let main = find(&vaults, "default").unwrap();
        assert!(main.path.ends_with("store.kdbx"));
        assert_eq!(main.keyfile.as_deref(), Some("/old/keyfile"));
    }

    #[test]
    fn absolutize_resolves_relative_and_home_paths() {
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(
            Path::new(&absolutize("vaults/x.kdbx")),
            cwd.join("vaults/x.kdbx")
        );
        assert_eq!(absolutize("/abs/store.kdbx"), "/abs/store.kdbx");
        let home = dirs::home_dir().unwrap();
        assert_eq!(
            Path::new(&absolutize("~/store.kdbx")),
            home.join("store.kdbx")
        );
    }

    #[test]
    fn add_vault_to_stores_absolute_path() {
        let dir = tempdir().unwrap();
        add_vault_to(
            dir.path(),
            VaultConfig {
                name: "rel".to_string(),
                path: "some/vault.kdbx".to_string(),
                keyfile: None,
                hwkey: None,
            },
        )
        .unwrap();
        let vaults = load_from(dir.path()).unwrap();
        assert!(Path::new(&vaults[0].path).is_absolute());
        assert!(vaults[0].path.ends_with("some/vault.kdbx"));
    }

    #[test]
    fn add_vault_to_stores_absolute_keyfile() {
        let dir = tempdir().unwrap();
        add_vault_to(
            dir.path(),
            VaultConfig {
                name: "rel".to_string(),
                path: "/abs/vault.kdbx".to_string(),
                keyfile: Some("keys/keyfile".to_string()),
                hwkey: None,
            },
        )
        .unwrap();
        let vaults = load_from(dir.path()).unwrap();
        let keyfile = Path::new(vaults[0].keyfile.as_deref().unwrap());
        assert!(keyfile.is_absolute());
        assert!(keyfile.ends_with("keys/keyfile"));
    }

    #[test]
    fn migrate_makes_relative_keyfile_absolute() {
        let dir = tempdir().unwrap();
        write(dir.path(), ".vault_path", "/old/store.kdbx\n");
        write(dir.path(), ".keyfile_path", "keys/keyfile\n");
        migrate_files_from(dir.path()).unwrap();
        let vaults = load_from(dir.path()).unwrap();
        let keyfile = Path::new(vaults[0].keyfile.as_deref().unwrap());
        assert!(keyfile.is_absolute());
        assert!(keyfile.ends_with("keys/keyfile"));
    }

    #[test]
    fn migrate_makes_relative_legacy_paths_absolute() {
        let dir = tempdir().unwrap();
        write(dir.path(), ".vault_path", "relative/store.kdbx\n");
        let names = migrate_files_from(dir.path()).unwrap().unwrap();
        assert_eq!(names, vec!["default"]);
        let vaults = load_from(dir.path()).unwrap();
        assert!(Path::new(&vaults[0].path).is_absolute());
        assert!(vaults[0].path.ends_with("relative/store.kdbx"));
    }

    #[cfg(unix)]
    #[test]
    fn migrate_fails_hard_on_unreadable_hwkey_config() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        write(dir.path(), ".vault_path", "/old/store.kdbx\n");
        let hwkey = dir.path().join(".hwkey");
        std::fs::write(&hwkey, "slot=2\n").unwrap();
        std::fs::set_permissions(&hwkey, std::fs::Permissions::from_mode(0o000)).unwrap();

        let err = migrate_files_from(dir.path()).unwrap_err();
        assert!(err.message.contains(".hwkey"), "{}", err.message);
        // The migration aborted without touching anything.
        assert!(!registry_path(dir.path()).exists());
        assert!(hwkey.exists());
        assert!(dir.path().join(".vault_path").exists());
    }
}
