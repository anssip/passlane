use crate::graphql;
use crate::graphql::queries::AddGredentialsGroupMutation;
use crate::graphql::queries::CredentialsIn;
use crate::graphql::queries::DeleteCredentialsMutation;
use crate::graphql::queries::MeQuery;
use crate::graphql::queries::UpdateMasterPasswordMutation;
use crate::graphql::queries::User;
use crate::password::Credentials as CredentialsModel;
use crate::store::get_encryption_key;
use anyhow::bail;
use log::debug;

pub async fn grep(access_token: &str, grep: &str) -> anyhow::Result<Vec<CredentialsModel>> {
    let response = graphql::run_me_query(access_token, Some(grep.to_string())).await;
    let me = match response.data {
        Some(MeQuery { me }) => me,
        None => bail!(check_response_errors(response)),
    };
    debug!("me: {:?}", me);
    let encryption_key = get_encryption_key()?;

    let result = &mut Vec::new();
    for vault in me.vaults {
        if let Some(credentials) = vault.credentials {
            for creds in credentials {
                if let Some(cred) = creds {
                    let model = CredentialsModel {
                        password: cred.password,
                        iv: cred.iv,
                        username: cred.username,
                        service: cred.service,
                    };
                    result.push(model.decrypt(&encryption_key));
                }
            }
        }
    }
    // TODO: sort by vaultId, service
    Ok(result.to_vec())
}

pub async fn push_credentials(
    access_token: &str,
    credentials: &Vec<CredentialsModel>,
    vault_id: Option<i32>,
) -> anyhow::Result<i32> {
    let credentials_in: Vec<CredentialsIn> = credentials
        .into_iter()
        .map(|c| CredentialsIn {
            password_encrypted: String::from(&c.password),
            iv: String::from(c.iv.as_ref().unwrap()),
            service: String::from(&c.service),
            username: String::from(&c.username),
        })
        .collect();

    let response =
        graphql::run_add_credentials_group_mutation(access_token, credentials_in, vault_id).await;
    match response.data {
        Some(AddGredentialsGroupMutation {
            add_credentials_group,
        }) => Ok(add_credentials_group),
        None => bail!(check_response_errors(response)),
    }
}

pub async fn push_one_credential(
    access_token: &str,
    credentials: &CredentialsModel,
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

pub async fn update_master_password(
    access_token: &str,
    old_password: &str,
    new_password: &str,
) -> anyhow::Result<i32> {
    let response =
        graphql::run_update_master_password_mutation(access_token, old_password, new_password)
            .await;
    match response.data {
        Some(UpdateMasterPasswordMutation {
            update_master_password,
        }) => Ok(update_master_password),
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

pub async fn get_me(access_token: &str) -> anyhow::Result<User> {
    let response = graphql::run_me_query(access_token, None).await;
    match response.data {
        Some(MeQuery { me }) => Ok(me),
        None => bail!(check_response_errors(response)),
    }
}
