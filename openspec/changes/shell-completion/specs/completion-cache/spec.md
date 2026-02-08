## ADDED Requirements

### Requirement: Completion cache file location
The system SHALL use `~/.passlane/.completion_cache` as the path for the completion cache file.

#### Scenario: Cache file path
- **WHEN** the system writes or reads the completion cache
- **THEN** it uses the file path `~/.passlane/.completion_cache`

### Requirement: Cache file format
The completion cache file SHALL contain one entry per line, plain text, with deduplicated service names and usernames. The file SHALL NOT contain passwords, TOTP secrets, payment card numbers, or any other sensitive data.

#### Scenario: Cache file contents
- **WHEN** the vault contains credentials for services "github" (user "alice"), "google" (user "bob"), and "github" (user "bob")
- **THEN** the cache file contains the deduplicated values "github", "google", "alice", and "bob", one per line

#### Scenario: No sensitive data in cache
- **WHEN** the cache file is written
- **THEN** the file contains only service names and usernames, no passwords or secrets

### Requirement: Cache created on vault unlock
When the `unlock` command succeeds for the main vault, the system SHALL write the completion cache file with current vault entry names.

#### Scenario: Unlock creates cache
- **WHEN** the user runs `passlane unlock` and the vault is successfully unlocked
- **THEN** the system writes `~/.passlane/.completion_cache` with service names and usernames from the vault

#### Scenario: Unlock with empty vault
- **WHEN** the user unlocks a vault that contains no entries
- **THEN** the system writes an empty completion cache file

### Requirement: Cache updated on vault-modifying actions
When a vault-modifying action (`add`, `edit`, `delete`, `import`) completes successfully, the system SHALL update the completion cache file with the current vault entry names.

#### Scenario: Add updates cache
- **WHEN** the user adds a new credential for service "gitlab"
- **THEN** the completion cache file is updated to include "gitlab"

#### Scenario: Delete updates cache
- **WHEN** the user deletes a credential for service "github"
- **THEN** the completion cache file is updated and no longer contains "github" (unless other entries still reference it)

### Requirement: Cache deleted on vault lock
When the `lock` command is run, the system SHALL delete the completion cache file.

#### Scenario: Lock deletes cache
- **WHEN** the user runs `passlane lock`
- **THEN** the system deletes `~/.passlane/.completion_cache`

#### Scenario: Lock when cache does not exist
- **WHEN** the user runs `passlane lock` and the cache file does not exist
- **THEN** the system proceeds without error

### Requirement: Cache auto-refresh when stale
When any CLI command runs and the completion cache file exists but is older than 7 days, and the vault is unlocked (master password available in the OS keychain), the system SHALL silently refresh the cache by opening the vault and rewriting the cache file with current entry names.

#### Scenario: Cache is stale and vault is unlocked
- **WHEN** a CLI command runs, the cache file exists and is older than 7 days, and the master password is stored in the keychain
- **THEN** the system refreshes the cache file with current vault entry names before proceeding with the command

#### Scenario: Cache is stale but vault is locked
- **WHEN** a CLI command runs, the cache file exists and is older than 7 days, but the master password is not in the keychain
- **THEN** the system leaves the stale cache in place and proceeds with the command normally

#### Scenario: Cache is fresh
- **WHEN** a CLI command runs and the cache file exists and is less than 7 days old
- **THEN** the system does not refresh the cache

### Requirement: Cache reading for completions
The system SHALL provide a function to read entry names from the cache file. If the cache file does not exist, the function SHALL return an empty list.

#### Scenario: Read existing cache
- **WHEN** the completion system reads the cache file and it exists with entries
- **THEN** it returns the list of service names and usernames

#### Scenario: Read missing cache
- **WHEN** the completion system reads the cache file and it does not exist
- **THEN** it returns an empty list without error
