use crate::ui;
use chrono::{LocalResult};
use chrono::Duration;
use chrono::Local;
use chrono::TimeZone;
use chrono::Utc;
use core::fmt::Display;
use core::fmt::Formatter;
use oauth2::basic::BasicTokenType;
use oauth2::EmptyExtraTokenFields;
use oauth2::RefreshToken;
use oauth2::StandardTokenResponse;
use serde::Deserialize;
use std::net::{SocketAddr, TcpListener};
use std::time::UNIX_EPOCH;

use anyhow::bail;
use log::error;
use oauth2::basic::BasicClient;
use oauth2::{
    AuthType, AuthUrl, AuthorizationCode, ClientId, CsrfToken, PkceCodeChallenge,
    RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use std::time::SystemTime;
use std::io::{BufRead, BufReader, Write};
use url::Url;
// use oauth2::reqwest;

pub struct AccessTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<Duration>,
    pub created_timestamp: String,
}

impl AccessTokens {
    fn seconds_since_creation(&self) -> i64 {
        match self.created_timestamp.parse::<i64>() {
            Ok(ts) => {
                match Utc.timestamp_opt(ts, 0) {
                    LocalResult::Single(created_datetime) => {
                        let now = Local::now();
                        now.signed_duration_since(created_datetime).num_seconds()
                    }
                    _ => {
                        error!("Out-of-range timestamp");
                        0
                    }
                }
            }
            Err(err) => {
                error!("failed to parse access_token timestamp: {}", err);
                0
            }
        }
    }
    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires_in {
            self.seconds_since_creation() > expires.num_seconds()
        } else {
            false
        }
    }
}

impl Display for AccessTokens {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "AccessTokens:: seconds since created {} - expires after {} seconds",
            self.seconds_since_creation(),
            if let Some(expires_in_duration) = self.expires_in {
                expires_in_duration.num_seconds() - self.seconds_since_creation()
            } else {
                -1
            }
        )
    }
}

#[derive(Deserialize)]
pub struct ReceivedCode {
    pub code: AuthorizationCode
}

fn new_client() -> anyhow::Result<BasicClient> {
    let client = BasicClient::new(
        ClientId::new("fZILwNkyzH09Vc4n1VQ0SsDWenMZlOBY".to_string()),
        None,
        AuthUrl::new("https://passlane.eu.auth0.com/authorize".to_string())?,
        Some(TokenUrl::new("https://passlane.eu.auth0.com/oauth/token".to_string())?),
    )
        .set_redirect_uri(RedirectUrl::new("http://localhost:8080/login".to_string())?)
        .set_auth_type(AuthType::RequestBody);
    Ok(client)
}

fn create_access_tokens(
    token_response: StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
) -> AccessTokens {
    let timestamp = SystemTime::now();
    let since_the_epoch = timestamp.duration_since(UNIX_EPOCH).unwrap();
    AccessTokens {
        access_token: String::from(token_response.access_token().secret()),
        refresh_token: token_response.refresh_token().map(|token| String::from(token.secret())),
        expires_in: token_response.expires_in().map(|duration| Duration::from_std(duration)
            .expect("Oauth returned expiration value larger than life")),
        created_timestamp: format!("{}", since_the_epoch.as_secs()),
    }
}

pub fn login() -> Result<AccessTokens, anyhow::Error> {
    let client = new_client()?;
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let csrf_token = CsrfToken::new_random_len(256);

    // Generate the full authorization URL.
    let (auth_url, csrf_state) = client
        .authorize_url(|| csrf_token)
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("offline_access".to_string()))
        .add_extra_param(
            "audience".to_string(),
            "https://passlane.eu.auth0.com/api/v2/",
        )
        .set_pkce_challenge(pkce_challenge)
        .url();

    if !ui::open_browser(
        &String::from(auth_url),
        "Press ENTER to open up the browser to login or q to exit: ",
    )? {
        bail!("Failed to open login page in browser");
    }
    let received: ReceivedCode = listen_for_code(8080, &csrf_state)?;

    let token_result = client
        .exchange_code(AuthorizationCode::new(received.code.secret().to_string()))
        .set_pkce_verifier(pkce_verifier)
        .request(oauth2::reqwest::http_client)?;

    Ok(create_access_tokens(token_result))
}

fn listen_for_code(port: u32, csrf_state: &CsrfToken) -> Result<ReceivedCode, anyhow::Error> {
    let bind = format!("127.0.0.1:{}", port);
    log::info!("Listening on: http://{}", bind);
    let addr: SocketAddr = str::parse(&bind)?;

    let (code, state) = {
        // A very naive implementation of the redirect server.
        let listener = TcpListener::bind(addr).unwrap();

        // The server will terminate itself after collecting the first code.
        let Some(mut stream) = listener.incoming().flatten().next() else {
            panic!("listener terminated without accepting a connection");
        };

        let mut reader = BufReader::new(&stream);

        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();

        let redirect_url = request_line.split_whitespace().nth(1).unwrap();
        let url = Url::parse(&("http://localhost".to_string() + redirect_url)).unwrap();

        let code = url
            .query_pairs()
            .find(|(key, _)| key == "code")
            .map(|(_, code)| AuthorizationCode::new(code.into_owned()))
            .unwrap();

        let state = url
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, state)| CsrfToken::new(state.into_owned()))
            .unwrap();

        let document = "<!DOCTYPE html>
<html>

<head>
    <title>Success!</title>
</head>

<body>
    <h1>You are now logged in to the Passlane Vault</h1>
    <p>The passlane client now uses the Vault as storage</p>
</body>

</html>
";
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
            document.len(),
            document
        );
        stream.write_all(response.as_bytes()).unwrap();
        log::debug!("html document sent");

        (code, state)
    };

    log::debug!("Github returned the following code:\n{}\n", code.secret());
    log::debug!(
        "Github returned the following state:\n{} (expected `{}`)\n",
        state.secret(),
        csrf_state.secret()
    );
    if state.secret() != csrf_state.secret() {
        bail!("CSRF token mismatch :(");
    }
    Ok(ReceivedCode { code })
}

pub fn exchange_refresh_token(token: AccessTokens) -> anyhow::Result<AccessTokens> {
    let client = new_client()?;
    if let Some(refresh_token) = token.refresh_token {
        let token_result = client
            .exchange_refresh_token(&RefreshToken::new(refresh_token))
            .request(oauth2::reqwest::http_client)?;
        Ok(create_access_tokens(token_result))
    } else {
        bail!("no refresh token available")
    }
}
