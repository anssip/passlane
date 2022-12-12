use cynic::http::ReqwestExt;
use reqwest::header;

//const API_ENDPOINT: &str = "http://localhost:3000/api/graphql";
const API_ENDPOINT: &str = "https://passlanevault.fly.dev/api/graphql";

#[cynic::schema_for_derives(file = r#"src/schema.graphql"#, module = "schema")]
pub mod queries {
    use super::schema;
    use crate::password::derive_encryption_key;
    use core::fmt::Display;
    use core::fmt::Formatter;
    use log::debug;
    #[derive(cynic::FragmentArguments, Debug)]
    pub struct CredentialsQueryVariables {
        pub grep: Option<String>,
    }

    #[derive(cynic::QueryFragment, Debug)]
    #[cynic(graphql_type = "Query", argument_struct = "CredentialsQueryVariables")]
    pub struct MeQuery {
        pub me: User,
    }

    #[derive(cynic::QueryFragment, Debug)]
    #[cynic(argument_struct = "CredentialsQueryVariables")]
    pub struct User {
        pub auth_user_id: String,
        pub created: Date,
        pub email: String,
        pub first_name: String,
        pub id: i32,
        pub last_name: String,
        pub modified: Option<Date>,
        pub vaults: Vec<Vault>,
    }

    impl User {
        pub fn get_salt(&self) -> String {
            format!("{}-{}", self.id, self.created).replace(":", "")
        }

        pub fn get_encryption_key(&self, master_pwd: &str) -> String {
            debug!("created: {}", self.created.to_string());

            let salt = self.get_salt();
            debug!("salt: {}", salt);

            let encryption_key = derive_encryption_key(&salt, master_pwd);
            debug!("encryption_key: {}", encryption_key);
            encryption_key
        }
    }

    #[derive(cynic::QueryFragment, Debug)]
    #[cynic(argument_struct = "CredentialsQueryVariables")]
    pub struct Vault {
        pub id: i32,
        pub name: String,
        #[arguments(grep = &args.grep)]
        pub credentials: Option<Vec<Option<Credentials>>>,
        pub personal: bool,
    }

    #[derive(cynic::QueryFragment, Debug)]
    pub struct Credentials {
        pub created: Date,
        pub modified: Option<Date>,
        pub id: i32,
        pub password: String,
        pub iv: Option<String>,
        pub service: String,
        pub username: String,
    }

    #[derive(cynic::Scalar, Debug, Clone)]
    pub struct Date(pub String);

    impl Display for Date {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    #[derive(cynic::FragmentArguments, Debug)]
    pub struct AddGredentialsGroupMutationVariables {
        pub input: AddCredentialsGroupIn,
    }
    #[derive(cynic::QueryFragment, Debug)]
    #[cynic(
        graphql_type = "Mutation",
        argument_struct = "AddGredentialsGroupMutationVariables"
    )]
    pub struct AddGredentialsGroupMutation {
        #[arguments(input = AddCredentialsGroupIn {
            credentials: args.input.credentials.clone(),
            vault_id: args.input.vault_id
        })]
        pub add_credentials_group: i32,
    }

    #[derive(cynic::InputObject, Debug)]
    pub struct AddCredentialsGroupIn {
        pub credentials: Vec<CredentialsIn>,
        pub vault_id: Option<i32>,
    }

    #[derive(cynic::InputObject, Debug, Clone)]
    #[cynic(rename_all = "camelCase")]
    pub struct CredentialsIn {
        pub password_encrypted: String,
        pub iv: String,
        pub service: String,
        pub username: String,
    }

    #[derive(cynic::FragmentArguments, Debug)]
    pub struct DeleteCredentialsMutationVariables {
        pub input: DeleteCredentialsIn,
    }

    #[derive(cynic::InputObject, Debug, Clone)]
    #[cynic(rename_all = "camelCase")]
    pub struct DeleteCredentialsIn {
        pub grep: String,
        pub index: Option<i32>,
    }

    #[derive(cynic::QueryFragment, Debug)]
    #[cynic(
        graphql_type = "Mutation",
        argument_struct = "DeleteCredentialsMutationVariables"
    )]
    pub struct DeleteCredentialsMutation {
        #[arguments(input = DeleteCredentialsIn {
            grep: args.input.grep.clone(),
            index: args.input.index
        })]
        pub delete_credentials: i32,
    }

    #[derive(cynic::FragmentArguments, Debug)]
    pub struct MigrateMutationVariables {
        pub new_key: String,
        pub old_key: String,
    }

    #[derive(cynic::QueryFragment, Debug)]
    #[cynic(
        graphql_type = "Mutation",
        argument_struct = "MigrateMutationVariables"
    )]
    pub struct MigrateMutation {
        #[arguments(new_key = args.new_key.clone(), old_key = args.old_key.clone())]
        pub migrate: i32,
    }
}

mod schema {
    cynic::use_schema!(r#"src/schema.graphql"#);
}
fn new_request(access_token: &str) -> reqwest::RequestBuilder {
    reqwest::Client::new()
        .post(API_ENDPOINT)
        .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
}

pub async fn run_me_query(
    access_token: &str,
    grep: Option<String>,
) -> cynic::GraphQlResponse<queries::MeQuery> {
    let operation = build_me_query(grep);

    new_request(access_token)
        .run_graphql(operation)
        .await
        .unwrap()
}

fn build_me_query(grep: Option<String>) -> cynic::Operation<'static, queries::MeQuery> {
    use cynic::QueryBuilder;
    queries::MeQuery::build(queries::CredentialsQueryVariables { grep })
}

pub async fn run_add_credentials_group_mutation(
    access_token: &str,
    credentials: Vec<queries::CredentialsIn>,
    vault_id: Option<i32>,
) -> cynic::GraphQlResponse<queries::AddGredentialsGroupMutation> {
    let operation = build_add_credentials_group_mutation(credentials, vault_id);

    new_request(access_token)
        .run_graphql(operation)
        .await
        .unwrap()
}

fn build_add_credentials_group_mutation(
    credentials: Vec<queries::CredentialsIn>,
    vault_id: Option<i32>,
) -> cynic::Operation<'static, queries::AddGredentialsGroupMutation> {
    use cynic::MutationBuilder;
    use queries::{AddGredentialsGroupMutation, AddGredentialsGroupMutationVariables};

    AddGredentialsGroupMutation::build(&AddGredentialsGroupMutationVariables {
        input: queries::AddCredentialsGroupIn {
            credentials: credentials,
            vault_id: vault_id,
        },
    })
}

pub async fn run_delete_credentials_mutation(
    access_token: &str,
    grep: &str,
    index: Option<i32>,
) -> cynic::GraphQlResponse<queries::DeleteCredentialsMutation> {
    let operation = build_delete_credentials_mutation(grep.into(), index);
    new_request(access_token)
        .run_graphql(operation)
        .await
        .unwrap()
}

fn build_delete_credentials_mutation(
    grep: String,
    index: Option<i32>,
) -> cynic::Operation<'static, queries::DeleteCredentialsMutation> {
    use cynic::MutationBuilder;
    use queries::{DeleteCredentialsMutation, DeleteCredentialsMutationVariables};

    DeleteCredentialsMutation::build(&DeleteCredentialsMutationVariables {
        input: queries::DeleteCredentialsIn {
            grep: grep,
            index: index,
        },
    })
}

pub async fn run_migrate_mutation(
    access_token: &str,
    old_key: &str,
    new_key: &str,
) -> cynic::GraphQlResponse<queries::MigrateMutation> {
    let operation = build_migrate_mutation(old_key, new_key);
    new_request(access_token)
        .run_graphql(operation)
        .await
        .unwrap()
}

fn build_migrate_mutation(
    old_key: &str,
    new_key: &str,
) -> cynic::Operation<'static, queries::MigrateMutation> {
    use cynic::MutationBuilder;
    use queries::{MigrateMutation, MigrateMutationVariables};

    MigrateMutation::build(&MigrateMutationVariables {
        old_key: String::from(old_key),
        new_key: String::from(new_key),
    })
}
