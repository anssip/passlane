#[cynic::schema("passlane")]
mod schema {}

pub mod types {
    use super::schema;
    use crate::crypto::derive_encryption_key;
    use crate::crypto::{decrypt, encrypt};
    use core::fmt::Display;
    use core::fmt::Formatter;
    use log::debug;

    #[derive(cynic::QueryVariables, Debug)]
    pub struct CredentialsQueryVariables {
        pub grep: Option<String>,
    }

    #[derive(cynic::QueryVariables, Debug)]
    pub struct EmptyQueryVariables {}

    #[derive(cynic::QueryFragment, Debug)]
    #[cynic(graphql_type = "Query", variables = "CredentialsQueryVariables")]
    pub struct MeQuery {
        pub me: User,
    }

    #[derive(cynic::QueryFragment, Debug)]
    #[cynic(graphql_type = "Query", variables = "EmptyQueryVariables")]
    pub struct PaymentCardMeQuery {
        pub me: UserWithPaymentCards,
    }

    #[derive(cynic::QueryFragment, Debug)]
    #[cynic(graphql_type = "Query", variables = "EmptyQueryVariables")]
    pub struct NotesMeQuery {
        pub me: UserWithNotes,
    }

    #[derive(cynic::QueryFragment, Debug)]
    #[cynic(graphql_type = "Query", variables = "EmptyQueryVariables")]
    pub struct PlainMeQuery {
        pub me: PlainUser,
    }

    #[derive(cynic::QueryFragment, Debug)]
    #[cynic(variables = "CredentialsQueryVariables")]
    #[allow(dead_code)]
    pub struct User {
        pub auth_user_id: String,
        pub created: Date,
        pub email: String,
        pub first_name: Option<String>,
        pub last_name: Option<String>,
        pub id: i32,
        pub modified: Option<Date>,
        pub vaults: Vec<Vault>,
    }

    #[derive(cynic::QueryFragment, Debug)]
    #[cynic(variables = "EmptyQueryVariables", graphql_type = "User")]
    #[allow(dead_code)]
    pub struct UserWithPaymentCards {
        pub auth_user_id: String,
        pub created: Date,
        pub email: String,
        pub first_name: Option<String>,
        pub last_name: Option<String>,
        pub id: i32,
        pub modified: Option<Date>,
        pub vaults: Vec<VaultWithPaymentCards>,
    }

    #[derive(cynic::QueryFragment, Debug)]
    #[cynic(variables = "EmptyQueryVariables", graphql_type = "User")]
    #[allow(dead_code)]
    pub struct UserWithNotes {
        pub auth_user_id: String,
        pub created: Date,
        pub email: String,
        pub first_name: Option<String>,
        pub last_name: Option<String>,
        pub id: i32,
        pub modified: Option<Date>,
        pub vaults: Vec<VaultWithNotes>,
    }

    #[derive(cynic::QueryFragment, Debug)]
    #[cynic(variables = "EmptyQueryVariables", graphql_type = "User")]
    #[allow(dead_code)]
    pub struct PlainUser {
        pub auth_user_id: String,
        pub created: Date,
        pub email: String,
        pub first_name: Option<String>,
        pub last_name: Option<String>,
        pub id: i32,
        pub modified: Option<Date>,
    }

    impl PlainUser {
        pub fn get_salt(&self) -> String {
            format!("{}-{}", self.id, self.created).replace(":", "")
        }

        pub fn get_encryption_key(&self, master_pwd: &str) -> String {
            let salt = self.get_salt();
            derive_encryption_key(&salt, master_pwd)
        }
    }

    #[derive(cynic::QueryFragment, Debug)]
    #[cynic(variables = "CredentialsQueryVariables")]
    #[allow(dead_code)]
    pub struct Vault {
        pub id: i32,
        pub name: String,
        #[arguments(grep: $grep)]
        pub credentials: Option<Vec<Option<Credentials>>>,
        pub personal: bool,
    }

    #[derive(cynic::QueryFragment, Debug)]
    #[cynic(variables = "EmptyQueryVariables", graphql_type = "Vault")]
    #[allow(dead_code)]
    pub struct VaultWithPaymentCards {
        pub id: i32,
        pub name: String,
        pub payment_cards: Option<Vec<Option<PaymentCard>>>,
        pub personal: bool,
    }

    #[derive(cynic::QueryFragment, Debug)]
    #[cynic(variables = "EmptyQueryVariables", graphql_type = "Vault")]
    #[allow(dead_code)]
    pub struct VaultWithNotes {
        pub id: i32,
        pub name: String,
        pub notes: Option<Vec<Option<Note>>>,
        pub personal: bool,
    }

    #[derive(cynic::QueryFragment, Debug)]
    #[cynic(variables = "EmptyQueryVariables", graphql_type = "Vault")]
    #[allow(dead_code)]
    pub struct VaultWithCredentials {
        pub id: i32,
    }

    #[derive(cynic::QueryFragment, Debug, Clone)]
    pub struct Credentials {
        pub created: Date,
        pub modified: Option<Date>,
        pub id: i32,
        pub password: String,
        pub iv: Option<String>,
        pub service: String,
        pub username: String,
    }

    impl Credentials {
        fn clone_with_password(&self, password_and_iv: (&str, &str)) -> Credentials {
            Credentials {
                id: self.id,
                password: String::from(password_and_iv.0),
                iv: Some(String::from(password_and_iv.1)),
                username: String::from(&self.username),
                service: String::from(&self.service),
                created: self.created.clone(),
                modified: self.modified.clone(),
            }
        }
        pub fn decrypt(&self, key: &str) -> anyhow::Result<Credentials> {
            let iv = &self.iv.as_ref().expect("Cannot decrypt without iv");
            debug!("decrypt() key: {}, iv {}", &key, &iv);
            debug!("decrypt() encrypted: {}", &self.password);
            let decrypted_passwd = decrypt((key, iv), &self.password)?;
            Ok(self.clone_with_password((&decrypted_passwd, iv)))
        }
    }

    impl Display for Credentials {
        fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
            write!(f, "{} - username: {}", self.service, self.username)
        }
    }

    impl PartialEq for Credentials {
        fn eq(&self, other: &Self) -> bool {
            self.username == other.username && self.service == other.service
        }
    }

    #[derive(cynic::InputObject, Debug, Clone)]
    #[cynic(rename_all = "camelCase")]
    pub struct CredentialsIn {
        pub password_encrypted: String,
        pub iv: String,
        pub service: String,
        pub username: String,
    }

    impl CredentialsIn {
        pub fn encrypt(&self, key: &str) -> CredentialsIn {
            let password = encrypt(key, &self.iv, &self.password_encrypted);
            debug!("encrypt() key: {}, iv {}", &key, &self.iv);

            CredentialsIn {
                password_encrypted: password,
                iv: String::from(&self.iv),
                username: String::from(&self.username),
                service: String::from(&self.service),
            }
        }
    }

    #[derive(cynic::Scalar, Debug, Clone)]
    pub struct Date(pub String);

    impl Display for Date {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    #[derive(cynic::QueryVariables, Debug)]
    pub struct AddCredentialsGroupMutationVariables {
        pub credentials: Vec<CredentialsIn>,
        pub vault_id: Option<i32>,
    }

    #[derive(cynic::QueryFragment, Debug)]
    #[cynic(
    graphql_type = "Mutation",
    variables = "AddCredentialsGroupMutationVariables"
    )]
    pub struct AddCredentialsGroupMutation {
        #[arguments(input: {
            credentials: $credentials,
            vaultId: $vault_id
        })]
        pub add_credentials_group: i32,
    }

    #[derive(cynic::InputObject, Debug)]
    pub struct AddCredentialsGroupIn {
        pub credentials: Vec<CredentialsIn>,
        pub vault_id: Option<i32>,
    }

    #[derive(cynic::QueryVariables, Debug)]
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
    variables = "DeleteCredentialsMutationVariables"
    )]
    pub struct DeleteCredentialsMutation {
        #[arguments(input: $input)]
        pub delete_credentials: i32,
    }

    #[derive(cynic::QueryVariables, Debug)]
    pub struct DeletePaymentCardMutationVariables {
        pub id: i32,
    }

    #[derive(cynic::QueryFragment, Debug)]
    #[cynic(
    graphql_type = "Mutation",
    variables = "DeletePaymentCardMutationVariables"
    )]
    pub struct DeletePaymentCardMutation {
        #[arguments(id: $id)]
        pub delete_payment_card: i32,
    }

    #[derive(cynic::QueryVariables, Debug)]
    pub struct MigrateMutationVariables {
        pub new_key: String,
        pub old_key: String,
    }

    #[derive(cynic::QueryFragment, Debug)]
    #[cynic(
    graphql_type = "Mutation",
    variables = "MigrateMutationVariables"
    )]
    pub struct MigrateMutation {
        #[arguments(newKey: $new_key, oldKey: $old_key)]
        pub migrate: i32,
    }

    #[derive(cynic::InputObject, Debug, Clone)]
    pub struct ExpiryIn {
        pub month: i32,
        pub year: i32,
    }

    #[derive(cynic::QueryFragment, Debug, Clone)]
    pub struct Expiry {
        pub month: i32,
        pub year: i32,
    }

    impl Display for Expiry {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}/{}", self.month, self.year)
        }
    }

    #[derive(cynic::InputObject, Debug, Clone)]
    pub struct AddressIn {
        pub street: String,
        pub city: String,
        pub country: String,
        pub state: Option<String>,
        pub zip: String,
    }

    impl AddressIn {
        pub fn encrypt(&self, key: &str, iv: &str) -> AddressIn {
            AddressIn {
                street: encrypt(key, iv, &self.street),
                city: encrypt(key, iv, &self.city),
                country: encrypt(key, iv, &self.country),
                state: if let Some(state) = &self.state {
                    Some(encrypt(key, iv, state))
                } else {
                    None
                },
                zip: encrypt(key, iv, &self.zip),
            }
        }
    }

    #[derive(cynic::QueryFragment, Debug, Clone)]
    pub struct Address {
        pub id: i32,
        pub street: String,
        pub city: String,
        pub country: String,
        pub state: Option<String>,
        pub zip: String,
    }

    impl Address {
        pub fn decrypt(&self, key: &str, iv: &str) -> anyhow::Result<Address> {
            Ok(Address {
                id: self.id,
                street: decrypt((key, iv), &self.street)?,
                city: decrypt((key, iv), &self.city)?,
                country: decrypt((key, iv), &self.country)?,
                state: if let Some(state) = &self.state {
                    Some(decrypt((key, iv), state)?)
                } else {
                    None
                },
                zip: decrypt((key, iv), &self.zip)?,
            })
        }
    }

    impl Display for Address {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "{}, {}, {}, {}",
                self.street, self.zip, self.city, self.country
            )
        }
    }

    #[derive(cynic::InputObject, Debug, Clone)]
    pub struct PaymentCardIn {
        pub iv: String,
        pub name: String,
        pub name_on_card: String,
        pub number: String,
        pub cvv: String,
        pub expiry: ExpiryIn,
        pub color: Option<String>,
        pub billing_address: Option<AddressIn>,
    }

    impl PaymentCardIn {
        pub fn encrypt(&self, key: &str) -> PaymentCardIn {
            PaymentCardIn {
                iv: self.iv.clone(),
                name: self.name.clone(),
                expiry: self.expiry.clone(),
                number: encrypt(key, &self.iv, &self.number),
                name_on_card: encrypt(key, &self.iv, &self.name_on_card),
                cvv: encrypt(key, &self.iv, &self.cvv),
                color: if let Some(color) = &self.color {
                    Some(encrypt(key, &self.iv, color))
                } else {
                    None
                },
                billing_address: if let Some(address) = &self.billing_address {
                    Some(address.encrypt(key, &self.iv))
                } else {
                    None
                },
            }
        }
    }

    #[derive(cynic::QueryFragment, Debug, Clone)]
    pub struct PaymentCard {
        pub id: i32,
        pub iv: String,
        pub name: String,
        pub name_on_card: String,
        pub number: String,
        pub cvv: String,
        pub expiry: Expiry,
        pub color: Option<String>,
        pub billing_address: Option<Address>,
    }

    impl PaymentCard {
        pub fn last_four(&self) -> String {
            self.number
                .chars()
                .skip(self.number.len() - 4)
                .take(4)
                .collect::<String>()
        }
        pub fn color_str(&self) -> String {
            if let Some(color) = &self.color {
                color.clone()
            } else {
                "".to_string()
            }
        }
        pub fn expiry_str(&self) -> String {
            self.expiry.to_string()
        }
        pub fn decrypt(&self, key: &str) -> anyhow::Result<PaymentCard> {
            Ok(PaymentCard {
                id: self.id,
                iv: self.iv.clone(),
                name: self.name.clone(),
                expiry: self.expiry.clone(),
                number: decrypt((key, &self.iv), &self.number)?,
                name_on_card: decrypt((key, &self.iv), &self.name_on_card)?,
                cvv: decrypt((key, &self.iv), &self.cvv)?,
                color: if let Some(color) = &self.color {
                    Some(decrypt((key, &self.iv), color)?)
                } else {
                    None
                },
                billing_address: if let Some(address) = &self.billing_address {
                    Some(address.decrypt(key, &self.iv)?)
                } else {
                    None
                },
            })
        }
    }

    #[derive(cynic::InputObject, Debug, Clone)]
    pub struct AddPaymentCardIn {
        pub payment: PaymentCardIn,
        pub vault_id: Option<i32>,
    }

    #[derive(cynic::QueryVariables, Debug)]
    pub struct AddPaymentCardMutationVariables {
        pub payment: PaymentCardIn,
        pub vault_id: Option<i32>,
    }

    #[derive(cynic::QueryFragment, Debug)]
    #[cynic(
        schema = "passlane",
        graphql_type = "Mutation",
        variables = "AddPaymentCardMutationVariables"
    )]
    pub struct AddPaymentCardMutation {
        #[arguments(input: {
            payment: $payment,
            vaultId: $vault_id
        })]
        pub add_payment_card: PaymentCard,
    }

    #[derive(cynic::QueryFragment, Debug, Clone)]
    pub struct Note {
        pub id: i32,
        pub iv: String,
        pub title: String,
        pub content: String,
        pub created: Date,
        pub modified: Option<Date>,
    }

    impl Note {
        pub fn decrypt(&self, key: &str) -> anyhow::Result<Note> {
            Ok(Note {
                id: self.id,
                iv: self.iv.clone(),
                title: decrypt((key, &self.iv), &self.title)?,
                content: decrypt((key, &self.iv), &self.content)?,
                created: self.created.clone(),
                modified: if let Some(modified) = &self.modified {
                    Some(modified.clone())
                } else {
                    None
                },
            })
        }
    }

    #[derive(cynic::QueryVariables, Debug, Clone)]
    pub struct NoteIn {
        pub iv: String,
        pub title: String,
        pub content: String,
        pub vault_id: Option<i32>,
    }

    impl NoteIn {
        pub fn encrypt(&self, key: &str) -> NoteIn {
            NoteIn {
                iv: self.iv.clone(),
                title: encrypt(key, &self.iv, &self.title),
                content: encrypt(key, &self.iv, &self.content),
                vault_id: self.vault_id,
            }
        }
    }

    #[derive(cynic::QueryFragment, Debug)]
    #[cynic(graphql_type = "Mutation", variables = "NoteIn")]
    pub struct AddNoteMutation {
        #[arguments(input: {
            iv: $iv,
            title: $title,
            content: $content,
            vaultId: $vault_id
        })]
        pub add_note: Note,
    }

    #[derive(cynic::QueryVariables, Debug)]
    pub struct DeleteNoteMutationVariables {
        pub id: i32,
    }

    #[derive(cynic::QueryFragment, Debug)]
    #[cynic(
    graphql_type = "Mutation",
    variables = "DeleteNoteMutationVariables"
    )]
    pub struct DeleteNoteMutation {
        #[arguments(id: $id)]
        pub delete_note: i32,
    }
}
