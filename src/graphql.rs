use cynic::http::ReqwestExt;
use cynic::MutationBuilder;
use cynic::Operation;
use cynic::QueryBuilder;
use reqwest::header;

use crate::graphql::queries::types::*;

pub mod queries;

//const API_ENDPOINT: &str = "http://localhost:3000/api/graphql";
const API_ENDPOINT: &str = "https://passlanevault.fly.dev/api/graphql";

fn new_request(access_token: &str) -> reqwest::RequestBuilder {
    reqwest::Client::new()
        .post(API_ENDPOINT)
        .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
}

async fn run_request<'a, T: 'a>(
    access_token: &str,
    operation: Operation<'a, T>,
) -> cynic::GraphQlResponse<T> {
    new_request(access_token)
        .run_graphql(operation)
        .await
        .unwrap()
}

pub async fn run_me_query(
    access_token: &str,
    grep: Option<String>,
) -> cynic::GraphQlResponse<MeQuery> {
    let operation = MeQuery::build(CredentialsQueryVariables { grep: grep });
    run_request(access_token, operation).await
}

pub async fn run_payment_card_query(
    access_token: &str,
) -> cynic::GraphQlResponse<PaymentCardMeQuery> {
    let operation = PaymentCardMeQuery::build(EmptyQueryVariables {});
    run_request(access_token, operation).await
}

pub async fn run_notes_query(access_token: &str) -> cynic::GraphQlResponse<NotesMeQuery> {
    let operation = NotesMeQuery::build(EmptyQueryVariables {});
    run_request(access_token, operation).await
}

pub async fn run_plain_me_query(access_token: &str) -> cynic::GraphQlResponse<PlainMeQuery> {
    let operation = PlainMeQuery::build(EmptyQueryVariables {});
    run_request(access_token, operation).await
}

pub async fn run_add_credentials_group_mutation(
    access_token: &str,
    credentials: Vec<CredentialsIn>,
    vault_id: Option<i32>,
) -> cynic::GraphQlResponse<AddGredentialsGroupMutation> {
    let operation = AddGredentialsGroupMutation::build(&AddGredentialsGroupMutationVariables {
        input: AddCredentialsGroupIn {
            credentials: credentials,
            vault_id: vault_id,
        },
    });
    run_request(access_token, operation).await
}

pub async fn run_delete_credentials_mutation(
    access_token: &str,
    grep: &str,
    index: Option<i32>,
) -> cynic::GraphQlResponse<DeleteCredentialsMutation> {
    let operation = {
        let grep = grep.into();
        DeleteCredentialsMutation::build(&DeleteCredentialsMutationVariables {
            input: DeleteCredentialsIn { grep, index: index },
        })
    };
    run_request(access_token, operation).await
}

pub async fn run_migrate_mutation(
    access_token: &str,
    old_key: &str,
    new_key: &str,
) -> cynic::GraphQlResponse<MigrateMutation> {
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
) -> cynic::GraphQlResponse<AddPaymentCardMutation> {
    let operation: cynic::Operation<AddPaymentCardMutation> =
        AddPaymentCardMutation::build(&AddPaymentCardMutationVariables {
            input: AddPaymentCardIn {
                payment: payment,
                vault_id: vault_id,
            },
        });
    run_request(access_token, operation).await
}

pub async fn run_delete_payment_card_mutation(
    access_token: &str,
    id: i32,
) -> cynic::GraphQlResponse<DeletePaymentCardMutation> {
    let operation: cynic::Operation<DeletePaymentCardMutation> =
        DeletePaymentCardMutation::build(&DeletePaymentCardMutationVariables { id: id });
    run_request(access_token, operation).await
}

pub async fn run_add_note_mutation(
    access_token: &str,
    note: &NoteIn,
) -> cynic::GraphQlResponse<AddNoteMutation> {
    let operation: cynic::Operation<AddNoteMutation> = AddNoteMutation::build(note);
    run_request(access_token, operation).await
}

pub async fn run_delete_note_mutation(
    access_token: &str,
    id: i32,
) -> cynic::GraphQlResponse<DeleteNoteMutation> {
    let operation = DeleteNoteMutation::build(&DeleteNoteMutationVariables { id });
    run_request(access_token, operation).await
}
