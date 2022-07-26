#[cynic::schema_for_derives(file = r#"src/schema.graphql"#, module = "schema")]
pub mod queries {
    use super::schema;
    #[derive(cynic::FragmentArguments, Debug)]
    pub struct CredentialsQueryVariables {
        pub grep: Option<String>,
        pub master_password: String,
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

    #[derive(cynic::QueryFragment, Debug)]
    #[cynic(argument_struct = "CredentialsQueryVariables")]
    pub struct Vault {
        pub id: i32,
        pub name: String,
        #[arguments(grep =  &args.grep, master_password = &args.master_password)]
        pub credentials: Option<Vec<Option<Credentials>>>,
        pub personal: bool,
    }

    #[derive(cynic::QueryFragment, Debug)]
    pub struct Credentials {
        pub created: Date,
        pub modified: Option<Date>,
        pub id: i32,
        pub password: String,
        pub service: String,
        pub username: String,
    }

    #[derive(cynic::Scalar, Debug, Clone)]
    pub struct Date(pub String);
}

mod schema {
    cynic::use_schema!(r#"src/schema.graphql"#);
}

pub async fn run_me_query(
    access_token: &str,
    master_password: &str,
    grep: &str,
) -> cynic::GraphQlResponse<queries::MeQuery> {
    use cynic::http::ReqwestExt;
    use reqwest::header;
    let operation = build_me_query(master_password, grep);

    reqwest::Client::new()
        .post("https://passlanevault.fly.dev/api/graphql")
        .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
        .run_graphql(operation)
        .await
        .unwrap()
}

fn build_me_query(
    master_password: &str,
    grep: &str,
) -> cynic::Operation<'static, queries::MeQuery> {
    use cynic::QueryBuilder;

    queries::MeQuery::build(queries::CredentialsQueryVariables {
        master_password: master_password.into(),
        grep: Some(grep.into()),
    })
}
