use crate::graphql;
use crate::graphql::queries::types::*;
use crate::store::get_encryption_key;
use anyhow::bail;
use log::debug;

pub async fn grep(access_token: &str, grep: &str) -> anyhow::Result<Vec<Credentials>> {
    let response = graphql::run_me_query(access_token, Some(grep.to_string())).await;
    let me = match response.data {
        Some(MeQuery { me }) => me,
        None => bail!(check_response_errors(response)),
    };
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

pub async fn find_payment_cards(access_token: &str) -> anyhow::Result<Vec<PaymentCard>> {
    let response = graphql::run_payment_card_query(access_token).await;
    let me = match response.data {
        Some(PaymentCardMeQuery { me }) => me,
        None => bail!(check_response_errors(response)),
    };
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

pub async fn push_credentials(
    access_token: &str,
    credentials: &Vec<CredentialsIn>,
    vault_id: Option<i32>,
) -> anyhow::Result<i32> {
    let response =
        graphql::run_add_credentials_group_mutation(access_token, credentials.clone(), vault_id)
            .await;
    match response.data {
        Some(AddGredentialsGroupMutation {
            add_credentials_group,
        }) => Ok(add_credentials_group),
        None => bail!(check_response_errors(response)),
    }
}

pub async fn push_one_credential(
    access_token: &str,
    credentials: &CredentialsIn,
    vault_id: Option<i32>,
) -> anyhow::Result<i32> {
    let vec = &mut Vec::new();
    vec.push(credentials.clone());
    push_credentials(access_token, &vec, vault_id).await
}

pub async fn delete_credentials(
    access_token: &str,
    grep: &str,
    index: Option<i32>,
) -> anyhow::Result<i32> {
    let response = graphql::run_delete_credentials_mutation(access_token, grep, index).await;
    match response.data {
        Some(DeleteCredentialsMutation { delete_credentials }) => Ok(delete_credentials),
        None => bail!(check_response_errors(response)),
    }
}

pub async fn migrate(access_token: &str, old_key: &str, new_key: &str) -> anyhow::Result<i32> {
    let response = graphql::run_migrate_mutation(access_token, old_key, new_key).await;
    match response.data {
        Some(MigrateMutation { migrate }) => Ok(migrate),
        None => bail!(check_response_errors(response)),
    }
}

fn check_response_errors<T>(response: cynic::GraphQlResponse<T>) -> String {
    match response.errors {
        Some(errors) => {
            debug!("errors: {:?}", errors);
            errors[0].message.to_string()
        }
        None => "".to_string(),
    }
}

pub async fn get_plain_me(access_token: &str) -> anyhow::Result<PlainUser> {
    let response = graphql::run_plain_me_query(access_token).await;
    match response.data {
        Some(PlainMeQuery { me }) => Ok(me),
        None => bail!(check_response_errors(response)),
    }
}

pub async fn save_payment(
    access_token: &str,
    payment: PaymentCardIn,
    vault_id: Option<i32>,
) -> anyhow::Result<()> {
    let response = graphql::run_add_payment_card_mutation(access_token, payment, vault_id).await;
    match response.data {
        Some(AddPaymentCardMutation {
            add_payment_card: _,
        }) => Ok(()),
        None => bail!(check_response_errors(response)),
    }
}

pub async fn delete_payment_card(access_token: &str, id: i32) -> anyhow::Result<i32> {
    let response = graphql::run_delete_payment_card_mutation(access_token, id).await;
    match response.data {
        Some(DeletePaymentCardMutation {
            delete_payment_card,
        }) => Ok(delete_payment_card),
        None => bail!(check_response_errors(response)),
    }
}

pub async fn delete_note(access_token: &str, id: i32) -> anyhow::Result<i32> {
    let response = graphql::run_delete_note_mutation(access_token, id).await;
    match response.data {
        Some(DeleteNoteMutation { delete_note }) => Ok(delete_note),
        None => bail!(check_response_errors(response)),
    }
}

pub async fn save_note(access_token: &str, note: &NoteIn) -> anyhow::Result<Note> {
    let response = graphql::run_add_note_mutation(access_token, note).await;
    match response.data {
        Some(AddNoteMutation { add_note }) => Ok(add_note),
        None => bail!(check_response_errors(response)),
    }
}

pub(crate) async fn find_notes(access_token: &str) -> anyhow::Result<Vec<Note>> {
    let response = graphql::run_notes_query(access_token).await;
    let me = match response.data {
        Some(NotesMeQuery { me }) => me,
        None => bail!(check_response_errors(response)),
    };
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
