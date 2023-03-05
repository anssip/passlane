use cynic::http::ReqwestExt;
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

pub async fn run_me_query(
    access_token: &str,
    grep: Option<String>,
) -> cynic::GraphQlResponse<MeQuery> {
    let operation = build_me_query(grep);

    new_request(access_token)
        .run_graphql(operation)
        .await
        .unwrap()
}

fn build_me_query(grep: Option<String>) -> cynic::Operation<'static, MeQuery> {
    use cynic::QueryBuilder;
    MeQuery::build(CredentialsQueryVariables { grep })
}

pub async fn run_payment_card_query(
    access_token: &str,
) -> cynic::GraphQlResponse<PaymentCardMeQuery> {
    let operation = build_payment_card_query();
    new_request(access_token)
        .run_graphql(operation)
        .await
        .unwrap()
}

fn build_payment_card_query() -> cynic::Operation<'static, PaymentCardMeQuery> {
    use cynic::QueryBuilder;
    PaymentCardMeQuery::build(EmptyQueryVariables {})
}

pub async fn run_notes_query(access_token: &str) -> cynic::GraphQlResponse<NotesMeQuery> {
    let operation = build_notes_query();
    new_request(access_token)
        .run_graphql(operation)
        .await
        .unwrap()
}

fn build_notes_query() -> cynic::Operation<'static, NotesMeQuery> {
    use cynic::QueryBuilder;
    NotesMeQuery::build(EmptyQueryVariables {})
}

pub async fn run_plain_me_query(access_token: &str) -> cynic::GraphQlResponse<PlainMeQuery> {
    let operation = build_plain_me_query();
    new_request(access_token)
        .run_graphql(operation)
        .await
        .unwrap()
}

fn build_plain_me_query() -> cynic::Operation<'static, PlainMeQuery> {
    use cynic::QueryBuilder;
    PlainMeQuery::build(EmptyQueryVariables {})
}

pub async fn run_add_credentials_group_mutation(
    access_token: &str,
    credentials: Vec<CredentialsIn>,
    vault_id: Option<i32>,
) -> cynic::GraphQlResponse<AddGredentialsGroupMutation> {
    let operation = build_add_credentials_group_mutation(credentials, vault_id);

    new_request(access_token)
        .run_graphql(operation)
        .await
        .unwrap()
}

fn build_add_credentials_group_mutation(
    credentials: Vec<CredentialsIn>,
    vault_id: Option<i32>,
) -> cynic::Operation<'static, AddGredentialsGroupMutation> {
    use cynic::MutationBuilder;

    AddGredentialsGroupMutation::build(&AddGredentialsGroupMutationVariables {
        input: AddCredentialsGroupIn {
            credentials,
            vault_id,
        },
    })
}

pub async fn run_delete_credentials_mutation(
    access_token: &str,
    grep: &str,
    index: Option<i32>,
) -> cynic::GraphQlResponse<DeleteCredentialsMutation> {
    let operation = build_delete_credentials_mutation(grep.into(), index);
    new_request(access_token)
        .run_graphql(operation)
        .await
        .unwrap()
}

fn build_delete_credentials_mutation(
    grep: String,
    index: Option<i32>,
) -> cynic::Operation<'static, DeleteCredentialsMutation> {
    use cynic::MutationBuilder;

    DeleteCredentialsMutation::build(&DeleteCredentialsMutationVariables {
        input: DeleteCredentialsIn { grep, index },
    })
}

pub async fn run_migrate_mutation(
    access_token: &str,
    old_key: &str,
    new_key: &str,
) -> cynic::GraphQlResponse<MigrateMutation> {
    let operation = build_migrate_mutation(old_key, new_key);
    new_request(access_token)
        .run_graphql(operation)
        .await
        .unwrap()
}

fn build_migrate_mutation(
    old_key: &str,
    new_key: &str,
) -> cynic::Operation<'static, MigrateMutation> {
    use cynic::MutationBuilder;

    MigrateMutation::build(&MigrateMutationVariables {
        old_key: String::from(old_key),
        new_key: String::from(new_key),
    })
}

pub async fn run_add_payment_card_mutation(
    access_token: &str,
    payment: PaymentCardIn,
    vault_id: Option<i32>,
) -> cynic::GraphQlResponse<AddPaymentCardMutation> {
    let operation: cynic::Operation<AddPaymentCardMutation> =
        build_add_payment_card_mutation(payment, vault_id);

    new_request(access_token)
        .run_graphql(operation)
        .await
        .unwrap()
}

fn build_add_payment_card_mutation(
    payment: PaymentCardIn,
    vault_id: Option<i32>,
) -> cynic::Operation<'static, AddPaymentCardMutation> {
    use cynic::MutationBuilder;

    AddPaymentCardMutation::build(&AddPaymentCardMutationVariables {
        input: AddPaymentCardIn { payment, vault_id },
    })
}

pub async fn run_delete_payment_card_mutation(
    access_token: &str,
    id: i32,
) -> cynic::GraphQlResponse<DeletePaymentCardMutation> {
    let operation: cynic::Operation<DeletePaymentCardMutation> =
        build_delete_payment_card_mutation(id);

    new_request(access_token)
        .run_graphql(operation)
        .await
        .unwrap()
}

fn build_delete_payment_card_mutation(
    id: i32,
) -> cynic::Operation<'static, DeletePaymentCardMutation> {
    use cynic::MutationBuilder;

    DeletePaymentCardMutation::build(&DeletePaymentCardMutationVariables { id })
}

pub async fn run_add_note_mutation(
    access_token: &str,
    note: &NoteIn,
) -> cynic::GraphQlResponse<AddNoteMutation> {
    let operation: cynic::Operation<AddNoteMutation> = build_add_note_mutation(note);

    new_request(access_token)
        .run_graphql(operation)
        .await
        .unwrap()
}

fn build_add_note_mutation(note: &NoteIn) -> cynic::Operation<'static, AddNoteMutation> {
    use cynic::MutationBuilder;

    AddNoteMutation::build(note)
}

pub async fn run_delete_note_mutation(
    access_token: &str,
    id: i32,
) -> cynic::GraphQlResponse<DeleteNoteMutation> {
    let operation = build_delete_note_mutation(id);
    new_request(access_token)
        .run_graphql(operation)
        .await
        .unwrap()
}

fn build_delete_note_mutation(id: i32) -> cynic::Operation<'static, DeleteNoteMutation> {
    use cynic::MutationBuilder;

    DeleteNoteMutation::build(&DeleteNoteMutationVariables { id })
}
