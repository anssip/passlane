use std::sync::Arc;

use clap::ArgMatches;
use comfy_table::Table;
use comfy_table::presets::ASCII_MARKDOWN;

use crate::actions::Action;
use crate::completion_cache;
use crate::keychain;
use crate::ui::input::{
    SecondFactor, ask_existing_path, ask_existing_vault_second_factor, ask_keyfile_path,
    ask_make_vault_active, ask_master_password, ask_new_master_password, ask_open_existing_vault,
    ask_remove_vault, ask_second_factor, ask_store_master_password, ask_vault_name, ask_vault_path,
    newline,
};
use crate::vault_registry::{self, PhoneKeyConfig, VaultConfig};
use passlane_core::vault::entities::Error;
use passlane_core::vault::keepass_vault::KeepassVault;

pub struct VaultAction {
    pub command: VaultCommand,
}

pub enum VaultCommand {
    List,
    Add { name: Option<String> },
    Use { name: String },
    Remove { name: String },
    Rename { old_name: String, new_name: String },
    Info { name: Option<String> },
}

impl VaultAction {
    pub fn new(matches: &ArgMatches) -> VaultAction {
        match matches.subcommand() {
            Some(("add", sub)) => VaultAction {
                command: VaultCommand::Add {
                    name: sub.get_one::<String>("NAME").cloned(),
                },
            },
            Some(("use", sub)) | Some(("switch", sub)) => VaultAction {
                command: VaultCommand::Use {
                    name: sub.get_one::<String>("NAME").cloned().unwrap_or_default(),
                },
            },
            Some(("remove", sub)) => VaultAction {
                command: VaultCommand::Remove {
                    name: sub.get_one::<String>("NAME").cloned().unwrap_or_default(),
                },
            },
            Some(("rename", sub)) => VaultAction {
                command: VaultCommand::Rename {
                    old_name: sub
                        .get_one::<String>("OLD_NAME")
                        .cloned()
                        .unwrap_or_default(),
                    new_name: sub
                        .get_one::<String>("NEW_NAME")
                        .cloned()
                        .unwrap_or_default(),
                },
            },
            Some(("info", sub)) => VaultAction {
                command: VaultCommand::Info {
                    name: sub.get_one::<String>("NAME").cloned(),
                },
            },
            _ => VaultAction {
                command: VaultCommand::List,
            },
        }
    }
}

impl Action for VaultAction {
    fn run(&self) -> Result<String, Error> {
        match &self.command {
            VaultCommand::List => self.list(),
            VaultCommand::Add { name } => setup_vault(name.clone()),
            VaultCommand::Use { name } => self.use_vault(name),
            VaultCommand::Remove { name } => self.remove(name),
            VaultCommand::Rename { old_name, new_name } => self.rename(old_name, new_name),
            VaultCommand::Info { name } => self.info(name.as_deref()),
        }
    }
}

impl VaultAction {
    fn list(&self) -> Result<String, Error> {
        let vaults = vault_registry::load()?;
        if vaults.is_empty() {
            return Ok("No vaults configured. Run 'passlane init' to create one.".to_string());
        }
        let active = vault_registry::get_active();
        let mut table = Table::new();
        table.load_preset(ASCII_MARKDOWN);
        table.set_header(vec![
            "Active",
            "Name",
            "Location",
            "Keyfile",
            "Hardware key",
            "Phone key",
            "State",
        ]);
        for vault in &vaults {
            table.add_row(vec![
                if active.as_deref() == Some(vault.name.as_str()) {
                    "*".to_string()
                } else {
                    String::new()
                },
                vault.name.clone(),
                vault.path.clone(),
                yes_no(vault.keyfile.is_some()),
                yes_no(vault.hwkey.is_some()),
                yes_no(vault.phone_key.is_some()),
                lock_state(&vault.name),
            ]);
        }
        Ok(table.to_string())
    }

    fn use_vault(&self, name: &str) -> Result<String, Error> {
        vault_registry::set_active(name)?;
        Ok(format!(
            "Vault '{}' is now the active vault. Unlock it with 'passlane unlock'.",
            name
        ))
    }

    fn remove(&self, name: &str) -> Result<String, Error> {
        let vaults = vault_registry::load()?;
        if vault_registry::find(&vaults, name).is_none() {
            return Err(vault_registry::unknown_vault_error(name, &vaults));
        }
        if !ask_remove_vault(name) {
            return Ok("Aborted".to_string());
        }
        let removed = vault_registry::remove_vault(name)?;
        // Lock it too: a stored master password for an unregistered vault
        // would linger in the keychain forever.
        if let Err(e) = keychain::delete_master_password_if_stored(name) {
            eprintln!(
                "Warning: could not remove the stored master password of vault '{}': {}",
                name, e
            );
        }
        completion_cache::clear_cache_for(name);
        Ok(format!(
            "Vault '{}' removed. The vault file {} was NOT deleted.",
            removed.name, removed.path
        ))
    }

    fn rename(&self, old_name: &str, new_name: &str) -> Result<String, Error> {
        // Everything that can fail must fail before any mutation happens, so
        // the keychain entry is never left filed under a name no vault has.
        vault_registry::check_rename(old_name, new_name)?;

        // Rename the registry entry first. If moving the keychain entry
        // fails afterwards, the worst case is the password staying filed
        // under the old name — the user is re-prompted once at the next
        // unlock and it gets re-stored. The reverse order could orphan it.
        let password = keychain::get_master_password(old_name).ok();
        vault_registry::rename_vault(old_name, new_name)?;
        completion_cache::clear_cache_for(old_name);

        let mut warning = String::new();
        if let Some(password) = &password {
            let result = keychain::save_master_password(new_name, password)
                .and_then(|()| keychain::delete_master_password_if_stored(old_name).map(|_| ()));
            if let Err(e) = result {
                eprintln!(
                    "Warning: could not move the stored master password of vault '{}' to its new name ({}). \
                     You will be asked for the password at the next unlock.",
                    new_name, e
                );
                warning = "\n(The stored master password could not be moved and will be re-requested at the next unlock.)".to_string();
            }
        }
        Ok(format!(
            "Vault '{}' renamed to '{}'{}",
            old_name, new_name, warning
        ))
    }

    fn info(&self, name: Option<&str>) -> Result<String, Error> {
        let config = match name {
            Some(name) => {
                let vaults = vault_registry::load()?;
                vault_registry::find(&vaults, name)
                    .cloned()
                    .ok_or_else(|| vault_registry::unknown_vault_error(name, &vaults))?
            }
            None => vault_registry::current()?,
        };
        let active = vault_registry::get_active();
        let lines = vec![
            format!("Name:         {}", config.name),
            format!("Location:     {}", config.path),
            format!(
                "Keyfile:      {}",
                config.keyfile.as_deref().unwrap_or("none")
            ),
            match &config.hwkey {
                Some(hwkey) => match hwkey.serial {
                    Some(serial) => {
                        format!("Hardware key: slot {} (key serial {})", hwkey.slot, serial)
                    }
                    None => format!("Hardware key: slot {}", hwkey.slot),
                },
                None => "Hardware key: none".to_string(),
            },
            match &config.phone_key {
                Some(phone_key) => format!(
                    "Phone key:    {}",
                    super::approvals::describe_holder(
                        phone_key,
                        crate::approvals::load_peers_pinned(&crate::approvals::state_dir())
                    )
                ),
                None => "Phone key:    none".to_string(),
            },
            format!("State:        {}", lock_state(&config.name)),
            format!(
                "Active vault: {}",
                if active.as_deref() == Some(config.name.as_str()) {
                    "yes"
                } else {
                    "no"
                }
            ),
        ];
        Ok(lines.join("\n"))
    }
}

fn vault_names(vaults: &[VaultConfig]) -> String {
    vaults
        .iter()
        .map(|v| v.name.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

fn yes_no(flag: bool) -> String {
    if flag { "yes" } else { "no" }.to_string()
}

fn lock_state(name: &str) -> String {
    match keychain::has_master_password(name) {
        Ok(true) => "unlocked".to_string(),
        Ok(false) => "locked".to_string(),
        // A keychain error is not "locked": report it instead of guessing.
        Err(e) => {
            eprintln!(
                "Warning: could not read the keychain state of vault '{}': {}",
                name, e
            );
            "unknown".to_string()
        }
    }
}

/// Interactively register and set up a vault. Shared by 'passlane init'
/// (first vault) and 'passlane vault add'. Returns a summary message.
pub fn setup_vault(name_arg: Option<String>) -> Result<String, Error> {
    let existing = vault_registry::load()?;
    let name = match name_arg {
        Some(name) => {
            vault_registry::validate_name(&name)?;
            if vault_registry::find(&existing, &name).is_some() {
                return Err(Error::new(&format!(
                    "A vault named '{}' already exists. Configured vaults: {}",
                    name,
                    vault_names(&existing)
                )));
            }
            name
        }
        None => loop {
            let name = ask_vault_name();
            if let Err(e) = vault_registry::validate_name(&name) {
                println!("{}", e.message);
                continue;
            }
            if vault_registry::find(&existing, &name).is_some() {
                println!(
                    "A vault named '{}' already exists. Configured vaults: {}",
                    name,
                    vault_names(&existing)
                );
                continue;
            }
            break name;
        },
    };

    let open_existing = ask_open_existing_vault();
    let default_path = crate::store::dir_path()
        .join(format!("{}.kdbx", name))
        .to_string_lossy()
        .to_string();
    let path = if open_existing {
        ask_existing_path()
    } else {
        ask_vault_path(&default_path)
    };
    let keyfile = ask_keyfile_path(None).filter(|k| !k.is_empty());

    let password;
    let mut hwkey_config = None;
    let mut phone_key = None;
    // Set for a vault created in this run: only then may a failed registry
    // write need to strip an enrolled hardware-key factor again.
    let mut created_vault: Option<KeepassVault> = None;
    // Set when the phone-key enrollment wrote the registry entry itself
    // (creating a vault with the phone does, together with the factor):
    // the write below is then already done.
    let mut registered_by_ceremony = false;

    if open_existing {
        password = ask_master_password(Some(&format!(
            "Please enter master password of the vault at {}",
            path
        )));
        // The vault may already be protected by a second factor (e.g.
        // registered on another machine): record the factor and verify all
        // unlock factors together — opening without the challenge factor
        // would fail with a misleading wrong-password error.
        let mut challenge_factor = None;
        match ask_existing_vault_second_factor() {
            SecondFactor::None => {
                println!("Verifying that the vault opens with the given password...");
                KeepassVault::open_with_challenge_factor(&password, &path, keyfile.clone(), None)?;
            }
            SecondFactor::HardwareKey => {
                let (factor, config) = crate::hwkey::resolve_new_key(None, None)?;
                challenge_factor = Some(factor);
                hwkey_config = Some(config);
            }
            // The phone twin: the pinned holder is asked for the approval
            // the vault's own challenge needs, and only a vault that
            // opens with the password and that approval is registered
            // with the factor — so later unlocks route through the
            // approval flow instead of failing with a wrong-password
            // error.
            SecondFactor::Phone => {
                let peers = crate::approvals::load_peers_pinned(&crate::approvals::state_dir())
                    .map_err(|e| Error::new(&e))?;
                let holder = crate::actions::hwkey::choose_registered_holder(peers)?;
                let holder_kid = holder.enc_kid().map_err(|e| {
                    Error::new(&format!("the pinned approver's key is unusable: {e}"))
                })?;
                let source = link_transport(holder);
                println!(
                    "Verifying that the vault opens with the given password and the phone-held \
                     key (the phone is asked for an approval)..."
                );
                phone_key = Some(register_phone_protected_vault(
                    &name,
                    &path,
                    keyfile.as_deref(),
                    &password,
                    &holder_kid,
                    source,
                )?);
            }
        }
        if challenge_factor.is_some() || hwkey_config.is_some() {
            println!("Verifying that the vault opens with the given password and factors...");
            KeepassVault::open_with_challenge_factor(
                &password,
                &path,
                keyfile.clone(),
                challenge_factor.as_ref(),
            )?;
        }
    } else {
        // The phone is the lead second factor (passlane#85): it is the
        // factor nearly everyone has. Whatever the choice names is
        // resolved BEFORE the master password is asked — the hardware
        // key must be connected, the phone paired — so nothing is typed
        // that a missing factor then wastes (the ask_store_hwkey ->
        // resolve_new_key -> new_with_challenge_factor ordering, kept).
        let second = ask_second_factor();
        let holder = (second == SecondFactor::Phone)
            .then(|| crate::actions::hwkey::choose_holder(None, None))
            .transpose()?;
        let (hwkey_factor, config) = if second == SecondFactor::HardwareKey {
            let (factor, config) = crate::hwkey::resolve_new_key(None, None)?;
            (Some(factor), Some(config))
        } else {
            (None, None)
        };
        hwkey_config = config;

        if let Some(holder) = &holder {
            println!(
                "Asking '{}' to create the key for vault '{}'. On that device: print or save the \
                 recovery sheet it shows, then scan or type the secret back from that copy — the \
                 key is not enrolled until you do.",
                holder.label, name
            );
            println!("{}", crate::actions::hwkey::enrollment_approval_notice());
        }
        println!("Initializing new vault '{}' at {}...", name, path);
        password = ask_new_master_password();

        match holder {
            // The phone-held key: the vault is created password-only and
            // the ceremony re-keys it — pair (above), the create-key
            // approval with the recovery sheet and its scan-back, then
            // the save approval — with this machine never seeing the
            // secret, and the registry entry written only once the vault
            // opens with the holder's answer.
            Some(holder) => {
                let holder_kid = holder.enc_kid().map_err(|e| {
                    Error::new(&format!("the pinned approver's key is unusable: {e}"))
                })?;
                let source = link_transport(holder);
                let ceremony_config = VaultConfig {
                    name: name.clone(),
                    path: path.clone(),
                    keyfile: keyfile.clone(),
                    hwkey: None,
                    phone_key: None,
                };
                phone_key = Some(create_vault_with_phone_key(
                    &ceremony_config,
                    &password,
                    holder_kid,
                    source,
                    &|entry| {
                        vault_registry::add_vault(VaultConfig {
                            name: ceremony_config.name.clone(),
                            path: ceremony_config.path.clone(),
                            keyfile: ceremony_config.keyfile.clone(),
                            hwkey: None,
                            phone_key: entry,
                        })
                    },
                )?);
                registered_by_ceremony = true;
            }
            None => {
                created_vault = Some(KeepassVault::new_with_challenge_factor(
                    &path,
                    &password,
                    keyfile.as_deref(),
                    hwkey_factor.as_ref(),
                )?);
            }
        }
    }

    if !registered_by_ceremony {
        if let Err(e) = vault_registry::add_vault(VaultConfig {
            name: name.clone(),
            path: path.clone(),
            keyfile: keyfile.clone(),
            hwkey: hwkey_config.clone(),
            phone_key: phone_key.clone(),
        }) {
            // When the just-created vault already demands the hardware key but
            // the enrollment could not be persisted, strip the factor again —
            // otherwise nothing would tell passlane to use the key on open and
            // the vault would be unreachable.
            if let Some(mut vault) = created_vault {
                if hwkey_config.is_some() {
                    if let Err(rollback) = vault.update_challenge_factor(None) {
                        eprintln!(
                            "Warning: failed to roll back the hardware key enrollment: {}",
                            rollback
                        );
                    }
                }
            }
            return Err(e);
        }
    }
    if hwkey_config.is_some() {
        crate::hwkey::print_backup_reminder();
    }
    if let Some(phone_key) = &phone_key {
        let holder = crate::actions::approvals::describe_holder(
            phone_key,
            crate::approvals::load_peers_pinned(&crate::approvals::state_dir()),
        );
        println!("{}", phone_key_notice(&name, &holder));
    }

    if ask_make_vault_active(&name) {
        vault_registry::set_active(&name)?;
    }
    if ask_store_master_password() {
        keychain::save_master_password(&name, &password)?;
    }
    newline();
    Ok(format!(
        "Vault '{}' added. Use 'passlane --vault {} <command>' or 'passlane vault use {}' to work with it.",
        name, name, name
    ))
}

/// The link transport for a vault's holder — the one piece both setup
/// paths that talk to a phone need.
fn link_transport(
    holder: passlane_approval::keys::PeerPin,
) -> Arc<dyn crate::phone_key::ResponseSource> {
    Arc::new(crate::phone_key::transport::LinkTransport::new(
        &crate::approvals::state_dir(),
        holder,
        crate::agent::requester(),
        Arc::new(crate::session_agent::AgentAnswerStore),
    ))
}

/// Create a vault whose second factor is a phone-held key, in one flow
/// (passlane#85): the vault file is written password-only, then the
/// holder creates its key (the create-key approval, gated on the
/// recovery sheet and its scan-back), the re-key rides the ceremony's
/// save approval — this machine never sees the secret — and the
/// registry entry, `record`, is written with the factor only once the
/// vault opens with the holder's answer. The caller has already paired
/// (or resolved) the holder and its `holder_kid`; `source` is the
/// transport its answers arrive through.
///
/// Failure semantics follow the hardware-key-at-creation precedent
/// (`ask_store_hwkey` → `resolve_new_key` → `new_with_challenge_factor`):
/// a registry write that fails rolls the re-key back, and a ceremony
/// that is refused or expires registers nothing — the untouched file
/// this run just created is removed again (nothing of value is in it
/// yet), while a file the ceremony — or anyone else — touched stands,
/// with the error's own words describing its state.
pub(crate) fn create_vault_with_phone_key(
    config: &VaultConfig,
    password: &str,
    holder_kid: String,
    source: Arc<dyn crate::phone_key::ResponseSource>,
    record: &dyn Fn(Option<PhoneKeyConfig>) -> Result<(), Error>,
) -> Result<PhoneKeyConfig, Error> {
    // The vault lands on disk password-only first: the ceremony's
    // challenge is the file's KDF seed, so it needs the file, and the
    // re-key that follows is what protects it.
    let mut vault = KeepassVault::new(&config.path, password, config.keyfile.as_deref(), None)?;
    let created_with = crate::phone_key::kdf_seed::read_kdf_seed(&config.path)?;
    match crate::actions::hwkey::enroll_and_record(
        config, password, &mut vault, holder_kid, source, record,
    ) {
        Ok(enrolled) => Ok(enrolled),
        Err(e) => {
            let removed = remove_untouched_vault(&config.path, created_with);
            Err(Error::new(&format!(
                "{} Nothing was registered, so the vault is not set up. {}",
                e.message,
                if removed {
                    "The file this run had just created was removed; re-run the command to try \
                     again."
                        .to_string()
                } else {
                    format!(
                        "The vault file at {} stands as the message above describes; re-run the \
                         command to replace it, or register it with 'passlane vault add' once \
                         its factor is settled.",
                        config.path
                    )
                }
            )))
        }
    }
}

/// Remove the vault file this run just created when the enrollment did
/// not complete: the setup failed, so the vault never lands. Only an
/// untouched file is removed — one whose KDF seed is still the seed it
/// was created with (every save rotates the seed; a replacement file
/// has another) — so nothing the ceremony, its rollback, or anyone
/// else wrote is ever deleted. Returns whether the file is gone.
fn remove_untouched_vault(path: &str, created_with: [u8; crate::phone_key::CHALLENGE_LEN]) -> bool {
    match crate::phone_key::kdf_seed::read_kdf_seed(path) {
        Ok(seed) if seed == created_with => match std::fs::remove_file(path) {
            Ok(()) => true,
            Err(e) => {
                eprintln!(
                    "Warning: could not remove the just-created vault file {}: {}",
                    path, e
                );
                false
            }
        },
        _ => false,
    }
}

/// Register a vault that is already phone-protected — enrolled, on
/// another machine (passlane#85): the phone twin of the hardware-key
/// question's verify step. The vault's holder-side identity is derived
/// from `holder_kid` and the vault's path, so the holder — `source`'s
/// other end, the approver the vault was enrolled under — recognizes
/// the vault and answers the approval its own challenge needs. Only a
/// vault that opens with the password and that approval returns the
/// factor to record; anything else is an error that registers nothing,
/// in place of the misleading wrong-password error a bare open would
/// give.
pub(crate) fn register_phone_protected_vault(
    name: &str,
    path: &str,
    keyfile: Option<&str>,
    password: &str,
    holder_kid: &str,
    source: Arc<dyn crate::phone_key::ResponseSource>,
) -> Result<PhoneKeyConfig, Error> {
    let phone_key = PhoneKeyConfig {
        holder_kid: holder_kid.to_string(),
        vault_uid: Some(PhoneKeyConfig::assigned_vault_uid(holder_kid, path)),
        // The re-key happened elsewhere, on the machine that enrolled
        // the holder; what this machine knows is when the factor was
        // registered here, and that is the date 'vault info' shows.
        enrolled_at: crate::approvals::now_secs(),
    };
    let config = VaultConfig {
        name: name.to_string(),
        path: path.to_string(),
        keyfile: keyfile.map(str::to_string),
        hwkey: None,
        phone_key: Some(phone_key.clone()),
    };
    // The holder is asked for the vault's current challenge — the
    // approval that opens it.
    let factor = crate::phone_key::open_key(&config, source)?;
    match KeepassVault::open_with_challenge_factor(
        password,
        path,
        keyfile.map(str::to_string),
        Some(&factor),
    ) {
        Ok(_) => Ok(phone_key),
        Err(e) => Err(Error::new(&format!(
            "The vault did not open with the given password and the phone-held key: {}. Nothing \
             was registered. If the vault was enrolled on another machine, the approver pinned \
             here must be the one that holds its key, and the vault file must be at the same \
             location it was enrolled under — the phone otherwise does not recognize this vault.",
            e.message
        ))),
    }
}

/// The announcement a phone-protected vault's setup ends with — the
/// convention every enrollment states in its own words: every open and
/// save asks the phone, and the recovery sheet is the only way in
/// without it.
pub(crate) fn phone_key_notice(vault: &str, holder: &str) -> String {
    format!(
        "Every open and save of vault '{}' now asks the phone holding its key ({}) for an \
         approval. 'passlane unlock --session <secs>' holds one approval in the session agent \
         for repeated use. Keep the recovery sheet offline: without that device, it is the only \
         way in ('passlane hwkey remove --secret').",
        vault, holder
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phone_key::tests::MockPhone;
    use crate::phone_key::{open_key, save_only_key};
    use passlane_approval::message::Operation;

    const SECRET: [u8; 20] = [0x9d; 20];
    const KID: &str = "0123456789abcdef";

    /// A phone that holds its key under one vault id — the sim-app's
    /// model: requests under any other id (a different derived id, from
    /// another path or holder) are refused, since it holds no key for
    /// that vault.
    struct KeyedByVault {
        vault_id: String,
        inner: Arc<MockPhone>,
    }

    impl crate::phone_key::ResponseSource for KeyedByVault {
        fn respond(
            &self,
            request: &crate::phone_key::PhoneRequest,
        ) -> Result<crate::phone_key::Answer, crate::phone_key::ResponseError> {
            if request.vault_id != self.vault_id {
                return Err(crate::phone_key::ResponseError::Denied(format!(
                    "this app holds no key for vault '{}'",
                    request.vault_id
                )));
            }
            self.inner.respond(request)
        }
    }

    /// A config for the vault at `path`, with no second factor.
    fn plain_config(path: &std::path::Path) -> VaultConfig {
        VaultConfig {
            name: "work".to_string(),
            path: path.to_str().unwrap().to_string(),
            keyfile: None,
            hwkey: None,
            phone_key: None,
        }
    }

    #[test]
    fn creating_a_vault_enrols_the_phone_and_registers_it_together() {
        let dir = tempfile::tempdir().unwrap();
        let registry = dir.path().join("registry");
        std::fs::create_dir_all(&registry).unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();
        let config = plain_config(&path);
        let phone = Arc::new(MockPhone::new(&SECRET));

        let enrolled = create_vault_with_phone_key(
            &config,
            "master-pw",
            KID.to_string(),
            phone.clone(),
            &|entry| {
                vault_registry::add_vault_to(
                    &registry,
                    VaultConfig {
                        name: "work".to_string(),
                        path: path_str.to_string(),
                        keyfile: None,
                        hwkey: None,
                        phone_key: entry,
                    },
                )
            },
        )
        .unwrap();

        // The ceremony ran in order: create the key (gated on the
        // recovery sheet's scan-back), then the re-key's save.
        assert_eq!(
            phone
                .asked()
                .iter()
                .map(|r| r.operation.clone())
                .collect::<Vec<_>>(),
            [Operation::EnrollKey, Operation::Save]
        );
        // The registry entry and the factor landed together, under the
        // derived holder-side id.
        let vaults = vault_registry::load_from(&registry).unwrap();
        let recorded = vault_registry::find(&vaults, "work").unwrap().clone();
        assert_eq!(recorded.phone_key, Some(enrolled.clone()));
        assert_eq!(
            enrolled.vault_uid.as_deref(),
            Some(PhoneKeyConfig::assigned_vault_uid(KID, path_str).as_str())
        );
        assert!(recorded.hwkey.is_none());
        assert!(enrolled.enrolled_at > 0);

        // The vault opens only through the phone.
        assert!(KeepassVault::open("master-pw", path_str, None, None).is_err());
        let key = open_key(&recorded, phone).unwrap();
        assert!(
            KeepassVault::open_with_challenge_factor("master-pw", path_str, None, Some(&key))
                .is_ok()
        );
    }

    #[test]
    fn a_refused_ceremony_registers_nothing_and_leaves_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let config = plain_config(&path);
        let phone = Arc::new(MockPhone::new(&SECRET));
        phone.refuse(crate::phone_key::ResponseError::Denied("not now".into()));

        let err =
            create_vault_with_phone_key(&config, "master-pw", KID.to_string(), phone, &|_| {
                panic!("a refused ceremony records nothing")
            })
            .unwrap_err();
        assert!(
            err.message.contains("refused by the approver: not now"),
            "{}",
            err.message
        );
        assert!(
            err.message
                .contains("Nothing was registered, so the vault is not set up"),
            "{}",
            err.message
        );
        assert!(
            err.message.contains("was removed; re-run"),
            "{}",
            err.message
        );
        assert!(
            !path.exists(),
            "the vault never lands when the ceremony is refused"
        );
    }

    #[test]
    fn a_registry_write_failure_rolls_the_re_key_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();
        let config = plain_config(&path);
        let phone = Arc::new(MockPhone::new(&SECRET));

        let err =
            create_vault_with_phone_key(&config, "master-pw", KID.to_string(), phone, &|_| {
                Err(Error::new("registry is read-only"))
            })
            .unwrap_err();
        assert!(
            err.message.contains("registry is read-only"),
            "{}",
            err.message
        );
        // The re-key was rolled back — password-only again — and, as for
        // a hardware key whose registry write fails at creation, the
        // file stands.
        assert!(path.exists(), "the rolled-back vault file is not deleted");
        assert!(KeepassVault::open("master-pw", path_str, None, None).is_ok());
        assert!(
            err.message
                .contains("stands as the message above describes"),
            "{}",
            err.message
        );
    }

    /// A vault at `path`, re-keyed by a phone that keys its secret under
    /// `vault_id` — as another machine's enrollment left it.
    fn phone_enrolled_vault(path: &str, vault_id: &str, phone: &Arc<MockPhone>) {
        let mut vault = KeepassVault::new(path, "master-pw", None, None).unwrap();
        vault
            .update_challenge_factor(Some(save_only_key(vault_id, "work", phone.clone())))
            .unwrap();
    }

    #[test]
    fn a_phone_protected_vault_registers_through_its_holder_approval() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();
        let phone = Arc::new(MockPhone::new(&SECRET));
        // Enrolled elsewhere: the holder keys its secret under the id
        // derived from the holder and the vault's path — which this
        // machine derives identically for the same file location.
        let uid = PhoneKeyConfig::assigned_vault_uid(KID, path_str);
        phone_enrolled_vault(path_str, &uid, &phone);
        assert!(KeepassVault::open("master-pw", path_str, None, None).is_err());

        let mark = phone.mark();
        let holder = Arc::new(KeyedByVault {
            vault_id: uid.clone(),
            inner: phone.clone(),
        });
        let registered =
            register_phone_protected_vault("work", path_str, None, "master-pw", KID, holder)
                .unwrap();

        assert_eq!(registered.holder_kid, KID);
        assert_eq!(registered.vault_uid.as_deref(), Some(uid.as_str()));
        assert!(registered.enrolled_at > 0);
        assert_eq!(
            phone
                .asked_since(mark)
                .iter()
                .map(|r| r.operation.clone())
                .collect::<Vec<_>>(),
            [Operation::Unlock],
            "one approval: the unlock that verified the vault"
        );

        // The recorded factor is the one the unlock chain then uses: the
        // vault opens through the approval flow, not a wrong-password
        // error.
        let config = VaultConfig {
            name: "work".to_string(),
            path: path_str.to_string(),
            keyfile: None,
            hwkey: None,
            phone_key: Some(registered),
        };
        let key = open_key(&config, phone).unwrap();
        assert!(
            KeepassVault::open_with_challenge_factor("master-pw", &config.path, None, Some(&key))
                .is_ok()
        );
    }

    #[test]
    fn a_vault_enrolled_under_another_path_is_not_registered() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();
        let phone = Arc::new(MockPhone::new(&SECRET));
        // Enrolled on another machine, under that machine's path-derived
        // id — the vault file here sits at a different location.
        let elsewhere = PhoneKeyConfig::assigned_vault_uid(KID, "/elsewhere/vault.kdbx");
        phone_enrolled_vault(path_str, &elsewhere, &phone);
        let holder = Arc::new(KeyedByVault {
            vault_id: elsewhere,
            inner: phone.clone(),
        });

        let err = register_phone_protected_vault("work", path_str, None, "master-pw", KID, holder)
            .unwrap_err();
        // An honest refusal — the holder does not know this vault under
        // the id derived here — instead of a wrong-password error.
        assert!(
            err.message.contains("this app holds no key for vault"),
            "{}",
            err.message
        );
        assert!(err.message.contains("did not open"), "{}", err.message);
        assert!(
            err.message.contains("Nothing was registered"),
            "{}",
            err.message
        );
        assert!(
            err.message.contains("same location it was enrolled under"),
            "{}",
            err.message
        );
    }

    #[test]
    fn a_phone_with_the_wrong_key_cannot_register_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();
        let phone = Arc::new(MockPhone::new(&SECRET));
        let uid = PhoneKeyConfig::assigned_vault_uid(KID, path_str);
        phone_enrolled_vault(path_str, &uid, &phone);

        // The right id, but a phone whose key is not the vault's.
        let other = Arc::new(MockPhone::new(&[0x37; 20]));
        let err = register_phone_protected_vault("work", path_str, None, "master-pw", KID, other)
            .unwrap_err();
        assert!(
            err.message
                .contains("did not open with the given password and the phone-held key"),
            "{}",
            err.message
        );
        // The vault still needs the right phone.
        assert!(KeepassVault::open("master-pw", path_str, None, None).is_err());
    }

    #[test]
    fn only_the_untouched_just_created_file_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();
        KeepassVault::new(path_str, "master-pw", None, None).unwrap();
        let seed = crate::phone_key::kdf_seed::read_kdf_seed(path_str).unwrap();

        // Untouched: the file this run created, gone.
        assert!(remove_untouched_vault(path_str, seed));
        assert!(!path.exists());

        // Written over by anything else — here another vault entirely:
        // the seed differs, so nothing is deleted.
        KeepassVault::new(path_str, "other-pw", None, None).unwrap();
        assert!(!remove_untouched_vault(path_str, seed));
        assert!(path.exists());
    }

    #[test]
    fn the_notice_states_the_every_open_and_save_convention() {
        let notice = phone_key_notice("work", "held by 'anssi-iphone', since 2026-11-28");
        assert!(
            notice.contains("Every open and save of vault 'work'"),
            "{notice}"
        );
        assert!(
            notice.contains("asks the phone holding its key (held by 'anssi-iphone'"),
            "{notice}"
        );
        assert!(notice.contains("recovery sheet"), "{notice}");
        assert!(notice.contains("hwkey remove --secret"), "{notice}");
    }
}
