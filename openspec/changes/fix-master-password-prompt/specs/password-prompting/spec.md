## ADDED Requirements

### Requirement: Single prompt when unlocking vault
When a vault is locked (master password not stored in keychain), the system SHALL prompt for the master password exactly once to unlock it. The system SHALL NOT ask for password confirmation when entering an existing master password.

#### Scenario: Unlock main vault when locked
- **WHEN** user runs any command requiring vault access and the main vault master password is not in the keychain
- **THEN** the system SHALL prompt for the master password exactly once before attempting to open the vault

#### Scenario: Unlock TOTP vault when locked
- **WHEN** user runs any TOTP command requiring vault access and the TOTP vault master password is not in the keychain
- **THEN** the system SHALL prompt for the TOTP master password exactly once before attempting to open the vault

### Requirement: Double prompt when creating new master password
When creating a new master password during initialization, the system SHALL prompt for the password twice and compare the entries to confirm they match.

#### Scenario: New master password confirmation matches
- **WHEN** user initializes a new vault and enters the same password for both prompts
- **THEN** the system SHALL accept the password and proceed with vault creation

#### Scenario: New master password confirmation does not match
- **WHEN** user initializes a new vault and enters different passwords for the two prompts
- **THEN** the system SHALL display "Passwords do not match, please try again" and re-prompt

### Requirement: Password prompt count is testable
The password prompt functions SHALL be structured so that the number of prompts and confirmation behavior can be verified by unit tests.

#### Scenario: ask_master_password invokes password reader once
- **WHEN** `ask_master_password_with` is called with a mock password reader
- **THEN** the reader SHALL be invoked exactly once and its return value SHALL be the result

#### Scenario: ask_new_master_password invokes password reader twice on match
- **WHEN** `ask_new_master_password_with` is called with a mock reader that returns the same password each time
- **THEN** the reader SHALL be invoked exactly twice and the matching password SHALL be the result

#### Scenario: ask_new_master_password retries on mismatch
- **WHEN** `ask_new_master_password_with` is called with a mock reader that returns mismatched passwords on the first pair and matching passwords on the second pair
- **THEN** the reader SHALL be invoked four times total and the matching password from the second pair SHALL be the result
