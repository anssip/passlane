use crate::graphql;
use crate::graphql::queries::types::*;
use crate::store::get_encryption_key;
use anyhow::Context;
use log::debug;

pub fn grep(access_token: &str, grep: Option<String>) -> anyhow::Result<Vec<Credentials>> {
    let me = graphql::run_me_query(access_token, grep)
        .context("Failed to fetch credentials")?
        .me;
    debug!("me: {:?}", me);

    let encryption_key = get_encryption_key()?;

    let result_credentials = &mut Vec::new();
    debug!("vaults: {:?}", me.vaults);

    for vault in me.vaults {
        if let Some(credentials) = vault.credentials {
            for creds in credentials {
                if let Some(cred) = creds {
                    result_credentials.push(cred.decrypt(&encryption_key)?);
                }
            }
        }
    }
    Ok(result_credentials.to_vec())
}

pub fn find_payment_cards(access_token: &str) -> anyhow::Result<Vec<PaymentCard>> {
    let me = graphql::run_payment_card_query(access_token)
        .context("Failed to fetch payment cards")?
        .me;

    debug!("me: {:?}", me);
    let encryption_key = get_encryption_key()?;

    let result_cards = &mut Vec::new();
    debug!("vaults: {:?}", me.vaults);

    for vault in me.vaults {
        if let Some(payment_cards) = vault.payment_cards {
            for cards in payment_cards {
                if let Some(card) = cards {
                    let decrypted = card.decrypt(&encryption_key)?;
                    result_cards.push(decrypted);
                }
            }
        }
    }
    debug!("result_cards: {:?}", result_cards);
    Ok(result_cards.to_vec())
}

pub fn push_credentials(
    access_token: &str,
    credentials: &Vec<CredentialsIn>,
    vault_id: Option<i32>,
) -> anyhow::Result<i32> {
    Ok(
        graphql::run_add_credentials_group_mutation(access_token, credentials.clone(), vault_id)
            .context("Failed to push credentials")?
            .add_credentials_group,
    )
}

pub fn push_one_credential(
    access_token: &str,
    credentials: &CredentialsIn,
    vault_id: Option<i32>,
) -> anyhow::Result<i32> {
    let vec = &mut Vec::new();
    vec.push(credentials.clone());
    push_credentials(access_token, &vec, vault_id)
}

pub fn delete_credentials(
    access_token: &str,
    grep: &str,
    index: Option<i32>,
) -> anyhow::Result<i32> {
    Ok(
        graphql::run_delete_credentials_mutation(access_token, grep, index)
            .context("Failed to delete credentials")?
            .delete_credentials,
    )
}

pub fn migrate(access_token: &str, old_key: &str, new_key: &str) -> anyhow::Result<i32> {
    Ok(
        graphql::run_migrate_mutation(access_token, old_key, new_key)
            .context("Failed to migrate")?
            .migrate,
    )
}

pub fn get_plain_me(access_token: &str) -> anyhow::Result<PlainUser> {
    Ok(graphql::run_plain_me_query(access_token)
        .context("Failed to fetch account data")?
        .me)
}

pub fn save_payment(
    access_token: &str,
    payment: PaymentCardIn,
    vault_id: Option<i32>,
) -> anyhow::Result<PaymentCard> {
    Ok(
        graphql::run_add_payment_card_mutation(access_token, payment, vault_id)
            .context("Failed to save payment card")?
            .add_payment_card,
    )
}

pub fn delete_payment_card(access_token: &str, id: i32) -> anyhow::Result<i32> {
    Ok(graphql::run_delete_payment_card_mutation(access_token, id)
        .context("Failed to delete payment card")?
        .delete_payment_card)
}

pub fn delete_note(access_token: &str, id: i32) -> anyhow::Result<i32> {
    Ok(graphql::run_delete_note_mutation(access_token, id)
        .context("Failed to delete note")?
        .delete_note)
}

pub fn save_note(access_token: &str, note: &NoteIn) -> anyhow::Result<Note> {
    Ok(graphql::run_add_note_mutation(access_token, note)
        .context("Failed to save note")?
        .add_note)
}

pub(crate) fn find_notes(access_token: &str) -> anyhow::Result<Vec<Note>> {
    let me = graphql::run_notes_query(access_token)
        .context("Failed to fetch notes")?
        .me;
    debug!("me: {:?}", me);

    let encryption_key = get_encryption_key()?;
    let result_notes = &mut Vec::new();

    for vault in me.vaults {
        if let Some(notes) = vault.notes {
            for notes in notes {
                if let Some(note) = notes {
                    let decrypted = note.decrypt(&encryption_key)?;
                    result_notes.push(decrypted);
                }
            }
        }
    }
    debug!("result_notes: {:?}", result_notes);
    Ok(result_notes.to_vec())
}
