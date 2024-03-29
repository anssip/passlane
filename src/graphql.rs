use anyhow::bail;
use cynic::http::ReqwestExt;
use cynic::MutationBuilder;
use cynic::Operation;
use cynic::QueryBuilder;
use log::debug;
use reqwest::header;

use crate::graphql::queries::types::*;

pub mod queries;

//const API_ENDPOINT: &str = "http://localhost:3000/api/graphql";
const API_ENDPOINT: &str = "https://passlanevault.fly.dev/api/graphql";

fn check_response_errors<T>(response: cynic::GraphQlResponse<T>) -> String {
    match response.errors {
        Some(errors) => {
            debug!("errors: {:?}", errors);
            errors[0].message.to_string()
        }
        None => "".to_string(),
    }
}

fn new_request(access_token: &str) -> reqwest::RequestBuilder {
    reqwest::Client::new()
        .post(API_ENDPOINT)
        .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
}

async fn run_request<'a, R: 'a>(
    access_token: &str,
    operation: Operation<'a, R>,
) -> anyhow::Result<R> {
    let response = new_request(access_token).run_graphql(operation).await;
    match response {
        Ok(response) => match response.data {
            Some(data) => Ok(data),
            None => bail!(check_response_errors(response)),
        },
        Err(err) => bail!(err),
    }
}

pub async fn run_me_query(access_token: &str, grep: Option<String>) -> anyhow::Result<MeQuery> {
    let operation = MeQuery::build(CredentialsQueryVariables { grep });
    run_request(access_token, operation).await
}

pub async fn run_payment_card_query(access_token: &str) -> anyhow::Result<PaymentCardMeQuery> {
    let operation = PaymentCardMeQuery::build(EmptyQueryVariables {});
    run_request(access_token, operation).await
}

pub async fn run_notes_query(access_token: &str) -> anyhow::Result<NotesMeQuery> {
    let operation = NotesMeQuery::build(EmptyQueryVariables {});
    run_request(access_token, operation).await
}

pub async fn run_plain_me_query(access_token: &str) -> anyhow::Result<PlainMeQuery> {
    let operation = PlainMeQuery::build(EmptyQueryVariables {});
    run_request(access_token, operation).await
}

pub async fn run_add_credentials_group_mutation(
    access_token: &str,
    credentials: Vec<CredentialsIn>,
    vault_id: Option<i32>,
) -> anyhow::Result<AddGredentialsGroupMutation> {
    let operation = AddGredentialsGroupMutation::build(&AddGredentialsGroupMutationVariables {
        input: AddCredentialsGroupIn {
            credentials,
            vault_id,
        },
    });
    run_request(access_token, operation).await
}

pub async fn run_delete_credentials_mutation(
    access_token: &str,
    grep: &str,
    index: Option<i32>,
) -> anyhow::Result<DeleteCredentialsMutation> {
    let operation = {
        let grep = String::from(grep);
        DeleteCredentialsMutation::build(&DeleteCredentialsMutationVariables {
            input: DeleteCredentialsIn { grep, index },
        })
    };
    run_request(access_token, operation).await
}

pub async fn run_migrate_mutation(
    access_token: &str,
    old_key: &str,
    new_key: &str,
) -> anyhow::Result<MigrateMutation> {
    let operation = MigrateMutation::build(&MigrateMutationVariables {
        old_key: String::from(old_key),
        new_key: String::from(new_key),
    });
    run_request(access_token, operation).await
}

pub async fn run_add_payment_card_mutation(
    access_token: &str,
    payment: PaymentCardIn,
    vault_id: Option<i32>,
) -> anyhow::Result<AddPaymentCardMutation> {
    let operation: Operation<AddPaymentCardMutation> =
        AddPaymentCardMutation::build(&AddPaymentCardMutationVariables {
            input: AddPaymentCardIn {
                payment,
                vault_id,
            },
        });
    run_request(access_token, operation).await
}

pub async fn run_delete_payment_card_mutation(
    access_token: &str,
    id: i32,
) -> anyhow::Result<DeletePaymentCardMutation> {
    let operation: Operation<DeletePaymentCardMutation> =
        DeletePaymentCardMutation::build(&DeletePaymentCardMutationVariables { id });
    run_request(access_token, operation).await
}

pub async fn run_add_note_mutation(
    access_token: &str,
    note: &NoteIn,
) -> anyhow::Result<AddNoteMutation> {
    let operation: Operation<AddNoteMutation> = AddNoteMutation::build(note);
    run_request(access_token, operation).await
}

pub async fn run_delete_note_mutation(
    access_token: &str,
    id: i32,
) -> anyhow::Result<DeleteNoteMutation> {
    let operation = DeleteNoteMutation::build(&DeleteNoteMutationVariables { id });
    run_request(access_token, operation).await
}
