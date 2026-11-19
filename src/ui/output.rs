use comfy_table::*;

use passlane_core::vault::entities::{AgentPolicy, Credential, Note, PaymentCard, Totp};

/// Secret cell text for a cleartext table. `ask` entries stay redacted
/// until their row is selected — the selection path runs the approval
/// prompt (the ask flow) and only then reveals the entry in full.
fn table_secret(value: &str, policy: AgentPolicy) -> String {
    if policy == AgentPolicy::Ask {
        "[agent=ask]".to_string()
    } else {
        value.to_string()
    }
}

/// Whether an entry's note may appear in a table cell. Notes can carry
/// secrets: `ask` entries stay redacted until the approval prompt (in any
/// context), and `never` entries only show for the owner — in agent
/// contexts nothing but `allow` notes are displayed.
fn table_note_visible(policy: AgentPolicy, agent_context: bool) -> bool {
    match policy {
        AgentPolicy::Allow => true,
        AgentPolicy::Ask => false,
        AgentPolicy::Never => !agent_context,
    }
}

pub fn show_credentials_table(
    credentials: &[Credential],
    show_password: bool,
    plain: bool,
    agent_context: bool,
) {
    let mut table = Table::new();
    apply_plain(&mut table, plain);
    let header_cell = |label: String| -> Cell { Cell::new(label).fg(Color::Green) };
    let headers = if show_password {
        vec!["", "Title", "Username/email", "Password"]
    } else {
        vec!["", "Title", "Username/email"]
    };
    table.set_header(
        headers
            .iter()
            .map(|&h| header_cell(String::from(h)))
            .collect::<Vec<Cell>>(),
    );
    for (index, creds) in (0_i16..).zip(credentials.iter()) {
        // Char-based truncation: byte slicing would panic when the cut lands
        // inside a multi-byte UTF-8 character.
        let truncated: String = creds.title().chars().take(30).collect();
        let modified = creds.last_modified().format("%d.%m.%Y").to_string();
        let mut lines: Vec<String> = vec![truncated];
        if let Some(url) = creds.url() {
            let url_truncated: String = url.chars().take(40).collect();
            lines.push(format!("🔗 {}", url_truncated));
        }
        if !creds.tags().is_empty() {
            lines.push(format!("🏷 {}", creds.tags().join(", ")));
        }
        if let Some(note) = creds.note() {
            if table_note_visible(creds.agent_policy(), agent_context) {
                lines.push(format!("📝 {}", note));
            } else {
                lines.push(format!("📝 [withheld: agent={}]", creds.agent_policy().as_str()));
            }
        }
        lines.push(format!("🕐 {}", modified));
        let title_cell = lines.join("\n");
        let columns = if show_password {
            vec![
                Cell::new(index.to_string()).fg(Color::Yellow),
                Cell::new(title_cell),
                Cell::new(String::from(creds.username())),
                Cell::new(table_secret(creds.password(), creds.agent_policy())),
            ]
        } else {
            vec![
                Cell::new(index.to_string()).fg(Color::Yellow),
                Cell::new(title_cell),
                Cell::new(String::from(creds.username())),
            ]
        };
        table.add_row(columns);
    }
    println!("{table}");
}

/// Full detail view of a single credential, showing every stored field
/// including custom attributes.
pub fn show_credential(credential: &Credential, show_password: bool, plain: bool) {
    let mut table = Table::new();
    apply_plain(&mut table, plain);
    let mut add_row = |label: &str, value: String| {
        table.add_row(vec![
            Cell::new(label).fg(Color::Yellow),
            Cell::new(value),
        ]);
    };
    add_row("Title", credential.title().to_string());
    add_row(
        "URL",
        credential.url().unwrap_or("-").to_string(),
    );
    add_row("Username", credential.username().to_string());
    if show_password {
        add_row("Password", credential.password().to_string());
    }
    add_row("Note", credential.note().unwrap_or("-").to_string());
    add_row(
        "Tags",
        if credential.tags().is_empty() {
            "-".to_string()
        } else {
            credential.tags().join(", ")
        },
    );
    add_row(
        "Expires",
        match (credential.expires(), credential.expiry_time()) {
            (true, Some(expiry)) => expiry.format("%d.%m.%Y").to_string(),
            _ => "-".to_string(),
        },
    );
    for (key, value) in credential.custom_attributes() {
        add_row(key, value.to_string());
    }
    add_row(
        "Last modified",
        credential.last_modified().format("%d.%m.%Y %H:%M").to_string(),
    );
    println!("{table}");
}

fn header_cell(label: String) -> Cell {
    Cell::new(label).fg(Color::Green)
}

fn apply_plain(table: &mut Table, plain: bool) {
    if plain {
        table.load_preset(comfy_table::presets::NOTHING);
        table.set_content_arrangement(comfy_table::ContentArrangement::Disabled);
    }
}

pub fn show_payment_cards_table(cards: &Vec<PaymentCard>, show_cleartext: bool, plain: bool) {
    let mut table = Table::new();
    apply_plain(&mut table, plain);
    let headers = if show_cleartext {
        vec![
            "",
            "Name",
            "Color",
            "Number",
            "Expiry",
            "CVV",
            "Name on card",
            "Modified",
        ]
    } else {
        vec!["", "Name", "Last 4", "Color", "Expiry", "Modified"]
    };
    table.set_header(
        headers
            .iter()
            .map(|&h| header_cell(String::from(h)))
            .collect::<Vec<Cell>>(),
    );
    for (index, card) in (0_i16..).zip(cards.iter()) {
        let columns = if show_cleartext {
            vec![
                Cell::new(index.to_string()).fg(Color::Yellow),
                Cell::new(String::from(card.name())),
                Cell::new(String::from(if let Some(color) = card.color() {
                    &color
                } else {
                    ""
                })),
                Cell::new(table_secret(card.number(), card.agent_policy())),
                Cell::new(String::from(format!("{}", card.expiry()))),
                Cell::new(table_secret(card.cvv(), card.agent_policy())),
                Cell::new(String::from(card.name_on_card())),
                Cell::new(card.last_modified().format("%d.%m.%Y %H:%M").to_string()),
            ]
        } else {
            vec![
                Cell::new(index.to_string()).fg(Color::Yellow),
                Cell::new(String::from(card.name())),
                Cell::new(card.last4()),
                Cell::new(card.color_str()),
                Cell::new(card.expiry_str()),
                Cell::new(card.last_modified().format("%d.%m.%Y %H:%M").to_string()),
            ]
        };
        table.add_row(columns);
    }
    println!("{table}");
}

pub fn show_card(card: &PaymentCard) {
    let mut table = Table::new();
    let mut add_row = |label: &str, value: &str, color: Option<comfy_table::Color>| {
        table.add_row(vec![
            Cell::new(label).fg(if let Some(col) = color {
                col
            } else {
                Color::Yellow
            }),
            Cell::new(value),
        ]);
    };
    add_row("Name", card.name(), None);
    add_row("Color", &card.color_str(), None);
    add_row("Number", card.number(), None);
    add_row("Expiry", &card.expiry_str(), None);
    add_row("CVV", card.cvv(), None);
    add_row("Name on card", card.name_on_card(), None);
    if let Some(address) = card.billing_address() {
        add_row("Billing address", "", Some(comfy_table::Color::Cyan));
        add_row("Street", address.street(), Some(comfy_table::Color::Cyan));
        add_row("Zip", address.zip(), Some(comfy_table::Color::Cyan));
        add_row("City", address.city(), Some(comfy_table::Color::Cyan));
        if let Some(state) = address.state() {
            add_row("State", &state, Some(comfy_table::Color::Cyan));
        }
        add_row("Country", address.country(), Some(comfy_table::Color::Cyan));
    }
    println!("{table}");
}

pub(crate) fn show_notes_table(notes: &[Note], show_cleartext: bool, plain: bool) {
    let mut table = Table::new();
    apply_plain(&mut table, plain);
    let headers = if show_cleartext {
        vec!["", "Title", "Note", "Modified"]
    } else {
        vec!["", "Title", "Modified"]
    };
    table.set_header(
        headers
            .iter()
            .map(|&h| header_cell(String::from(h)))
            .collect::<Vec<Cell>>(),
    );
    for (index, note) in notes.iter().enumerate() {
        let columns = if show_cleartext {
            vec![
                Cell::new(index.to_string()).fg(Color::Yellow),
                Cell::new(note.title()),
                Cell::new(table_secret(note.content(), note.agent_policy())),
                Cell::new(&note.last_modified().format("%Y-%m-%d %H:%M:%S").to_string()),
            ]
        } else {
            vec![
                Cell::new(index.to_string()).fg(Color::Yellow),
                Cell::new(&note.title()),
                Cell::new(&note.last_modified().format("%Y-%m-%d %H:%M:%S").to_string()),
            ]
        };
        table.add_row(columns);
    }
    println!("{table}");
}

pub(crate) fn show_note(note: &Note) {
    println!("---------------------------");
    println!("{}\n", note.title());
    println!("{}", note.content());
    println!("---------------------------");
}

pub(crate) fn show_totp_table(totps: &[Totp], plain: bool) {
    let mut table = Table::new();
    apply_plain(&mut table, plain);
    table.set_header(
        vec![
            header_cell("".to_string()),
            header_cell("Label".to_string()),
            header_cell("Issuer".to_string()),
            header_cell("Modified".to_string()),
        ]
        .into_iter()
        .collect::<Vec<Cell>>(),
    );
    for (index, totp) in totps.iter().enumerate() {
        table.add_row(vec![
            Cell::new(index.to_string()).fg(Color::Yellow),
            Cell::new(totp.label().to_string()),
            Cell::new(totp.issuer().to_string()),
            Cell::new(totp.last_modified().format("%d.%m.%Y %H:%M").to_string()),
        ]);
    }
    println!("{table}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};

    #[test]
    fn table_secret_redacts_ask_until_approved_selection() {
        assert_eq!(table_secret("hunter2", AgentPolicy::Ask), "[agent=ask]");
        assert_eq!(table_secret("hunter2", AgentPolicy::Allow), "hunter2");
        // `never` entries never reach a cleartext table in agent contexts
        // (the table is refused), and at the owner's terminal the owner's
        // own view is unrestricted.
        assert_eq!(table_secret("hunter2", AgentPolicy::Never), "hunter2");
    }

    #[test]
    fn table_notes_follow_the_policy_and_context() {
        // Notes can carry secrets: ask stays redacted everywhere until the
        // approval prompt; never shows only for the owner.
        assert!(!table_note_visible(AgentPolicy::Ask, false));
        assert!(!table_note_visible(AgentPolicy::Ask, true));
        assert!(table_note_visible(AgentPolicy::Allow, true));
        assert!(table_note_visible(AgentPolicy::Allow, false));
        assert!(table_note_visible(AgentPolicy::Never, false));
        assert!(!table_note_visible(AgentPolicy::Never, true));
    }

    // Renders without panicking; run with --nocapture to eyeball the layout.
    #[test]
    fn show_credential_renders_all_fields() {
        let expiry = DateTime::parse_from_rfc3339("2027-01-31T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let credential = Credential::new(None, "secret", "GitHub", "user", Some("note"), None)
            .with_url(Some("https://github.com/login"))
            .with_tags(&["work".to_string()])
            .with_expiry(true, Some(expiry))
            .with_custom_attributes(&[("Recovery code".to_string(), "12345".to_string())]);
        show_credential(&credential, true, false);
        show_credential(&credential, false, true);
    }

    // Long multi-byte titles/URLs must truncate on char boundaries, not bytes.
    #[test]
    fn credentials_table_truncates_multibyte_titles_without_panicking() {
        let credential = Credential::new(
            None,
            "secret",
            "パスワードマネージャーのタイトルが非常に長い場合の切り詰めテスト",
            "user",
            None,
            None,
        )
        .with_url(Some("https://example.com/パスワード/とても長いURLを切り詰めるテスト"));
        show_credentials_table(&[credential], false, true, false);
    }
}
