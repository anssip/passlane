use crate::ui;
use chrono::DateTime;
use chrono::Duration;
use chrono::Local;
use chrono::NaiveDateTime;
use chrono::Utc;
use core::fmt::Display;
use core::fmt::Formatter;
use futures::{
    channel::oneshot,
    prelude::*,
    task::{Context, Poll},
};
use hyper::{body::Body, server, service, Request, Response};
use oauth2::basic::BasicTokenType;
use oauth2::EmptyExtraTokenFields;
use oauth2::RefreshToken;
use oauth2::StandardTokenResponse;
use serde::Deserialize;
use std::net::SocketAddr;
use std::time::UNIX_EPOCH;
use tower_service::Service;

use anyhow;
use anyhow::bail;
use log::error;
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthType, AuthUrl, AuthorizationCode, ClientId, CsrfToken, PkceCodeChallenge,
    RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use std::time::SystemTime;

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
                let naive = NaiveDateTime::from_timestamp(ts, 0);
                let created_datetime: DateTime<Utc> = DateTime::from_utc(naive, Utc);
                let now = Local::now();
                now.signed_duration_since(created_datetime).num_seconds()
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
    pub code: AuthorizationCode,
    pub state: CsrfToken,
}
pub struct Server {
    channel: Option<oneshot::Sender<ReceivedCode>>,
    document: Vec<u8>,
}

impl Service<Request<Body>> for Server {
    type Response = Response<Body>;
    type Error = anyhow::Error;
    type Future = future::BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    // Handle the request
    fn call(&mut self, req: Request<Body>) -> Self::Future {
        if let Ok(code) =
            serde_urlencoded::from_str::<ReceivedCode>(req.uri().query().unwrap_or(""))
        {
            if let Some(channel) = self.channel.take() {
                let _ = channel.send(code);
            }
        }
        Box::pin(future::ok(Response::new(Body::from(self.document.clone()))))
    }
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
        refresh_token: if let Some(token) = token_response.refresh_token() {
            Some(String::from(token.secret()))
        } else {
            None
        },
        expires_in: if let Some(duration) = token_response.expires_in() {
            Some(
                Duration::from_std(duration)
                    .expect("Oauth returned expiration value larger than life"),
            )
        } else {
            None
        },
        created_timestamp: format!("{}", since_the_epoch.as_secs()),
    }
}

pub async fn login() -> Result<AccessTokens, anyhow::Error> {
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
    let received: ReceivedCode = listen_for_code(8080).await?;
    if received.state.secret() != csrf_state.secret() {
        bail!("CSRF token mismatch :(");
    }
    let token_result = client
        .exchange_code(AuthorizationCode::new(received.code.secret().to_string()))
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await?;

    Ok(create_access_tokens(token_result))
}

async fn listen_for_code(port: u32) -> Result<ReceivedCode, anyhow::Error> {
    let bind = format!("127.0.0.1:{}", port);
    log::info!("Listening on: http://{}", bind);

    let addr: SocketAddr = str::parse(&bind)?;

    let (tx, rx) = oneshot::channel::<ReceivedCode>();
    let mut channel = Some(tx);
    let document = b"<!DOCTYPE html>
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

    log::debug!("html document sent");
    let server_future = server::Server::bind(&addr).serve(service::make_service_fn(move |_| {
        let channel = channel.take().expect("channel is not available");
        let mut server = Server {
            channel: Some(channel),
            document: document.to_vec(),
        };
        let service = service::service_fn(move |req| server.call(req));

        async move { Ok::<_, hyper::Error>(service) }
    }));

    let mut server_future = server_future.fuse();
    let mut rx = rx.fuse();

    futures::select! {
        _ = server_future => panic!("server exited for some reason"),
        received = rx => Ok(received?),
    }
}

pub async fn exchange_refresh_token(token: AccessTokens) -> anyhow::Result<AccessTokens> {
    let client = new_client()?;
    if let Some(refresh_token) = token.refresh_token {
        let token_result = client
            .exchange_refresh_token(&RefreshToken::new(refresh_token))
            .request_async(async_http_client)
            .await?;
        Ok(create_access_tokens(token_result))
    } else {
        bail!("no refresh token available")
    }
}
