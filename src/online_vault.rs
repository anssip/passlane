use crate::graphql;
use crate::graphql::queries::AddGredentialsGroupMutation;
use crate::graphql::queries::CredentialsIn;
use crate::graphql::queries::DeleteCredentialsMutation;
use crate::graphql::queries::LockMutation;
use crate::graphql::queries::MeQuery;
use crate::graphql::queries::UnlockMutation;
use crate::graphql::queries::UpdateMasterPasswordMutation;
use crate::password::get_random_key;
use crate::password::Credentials as CredentialsModel;
use anyhow::bail;
use log::debug;

pub async fn grep(access_token: &str, grep: &str) -> anyhow::Result<Vec<CredentialsModel>> {
    let response = graphql::run_me_query(access_token, grep).await;
    if response.errors.is_some() {
        bail!(format!("errors: {:?}", response));
    }
    let me = match response.data {
        Some(MeQuery { me }) => me,
        _ => {
            bail!("User account not found. Did you sign up at https://passlanevault.com already?");
        }
    };
    debug!("me: {:?}", me);
    let encryption_key = match me.key {
        Some(key) => key,
        _ => {
            bail!("Vault is locked. Run `passlane unlock` to unlock.");
        }
    };
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
            password: String::from(&c.password),
            iv: get_random_key(),
            service: String::from(&c.service),
            username: String::from(&c.username),
        })
        .collect();

    let response =
        graphql::run_add_credentials_group_mutation(access_token, credentials_in, vault_id).await;
    if response.errors.is_some() {
        bail!(format!("errors: {:?}", response));
    }
    match response.data {
        Some(AddGredentialsGroupMutation {
            add_credentials_group,
        }) => Ok(add_credentials_group),
        None => bail!("Something went wrong and no credentials were pushed"),
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
    if response.errors.is_some() {
        bail!(format!("errors: {:?}", response));
    }
    match response.data {
        Some(DeleteCredentialsMutation { delete_credentials }) => Ok(delete_credentials),
        _ => bail!("Failed to delete from the online vault"),
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
    if response.errors.is_some() {
        bail!(format!("errors: {:?}", response));
    }
    match response.data {
        Some(UpdateMasterPasswordMutation {
            update_master_password,
        }) => Ok(update_master_password),
        None => Ok(0),
    }
}

pub async fn lock(access_token: &str, master_password: &str) -> anyhow::Result<bool> {
    let response = graphql::run_lock_mutation(access_token, master_password).await;
    if response.errors.is_some() {
        bail!(format!("errors: {:?}", response));
    }
    match response.data {
        Some(LockMutation { lock }) => Ok(lock),
        None => bail!("Failed to lock the vault"),
    }
}

pub async fn unlock(access_token: &str, master_password: &str) -> anyhow::Result<String> {
    let response = graphql::run_unlock_mutation(access_token, master_password).await;
    if response.errors.is_some() {
        bail!(format!("errors: {:?}", response));
    }
    match response.data {
        Some(UnlockMutation { unlock }) => Ok(unlock),
        None => bail!("Failed to unlock the vault"),
    }
}
