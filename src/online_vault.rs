use crate::graphql;
use crate::graphql::queries::AddGredentialsGroupMutation;
use crate::graphql::queries::CredentialsIn;
use crate::graphql::queries::MeQuery;
use crate::password::Credentials as CredentialsModel;
use anyhow::bail;

pub async fn grep(
    access_token: &str,
    master_password: &str,
    grep: &str,
) -> anyhow::Result<Vec<CredentialsModel>> {
    let response = graphql::run_me_query(access_token, master_password, grep).await;
    if response.errors.is_some() {
        bail!(format!("errors: {:?}", response));
    }
    let vaults = match response.data {
        Some(MeQuery { me }) => me.vaults,
        _ => {
            println!("No credentials found");
            Vec::new()
        }
    };
    let result = &mut Vec::new();
    for vault in vaults {
        if let Some(credentials) = vault.credentials {
            for creds in credentials {
                if let Some(cred) = creds {
                    result.push(
                        (CredentialsModel {
                            password: cred.password,
                            username: cred.username,
                            service: cred.service,
                        })
                        .decrypt(&master_password.into()),
                    )
                }
            }
        }
    }
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
