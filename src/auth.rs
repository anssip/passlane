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
use hyper::{body::Body, Request, Response};
use oauth2::basic::BasicTokenType;
use oauth2::devicecode::DeviceAuthorizationResponse;
use oauth2::devicecode::ExtraDeviceAuthorizationFields;
use oauth2::DeviceAuthorizationUrl;
use oauth2::EmptyExtraTokenFields;
use oauth2::RefreshToken;
use oauth2::StandardTokenResponse;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::UNIX_EPOCH;
use tower_service::Service;

use anyhow;
use anyhow::bail;
use log::error;
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::reqwest::http_client;
use oauth2::{
    AuthType, AuthUrl, AuthorizationCode, ClientId, CsrfToken, Scope, TokenResponse, TokenUrl,
};
use std::time::SystemTime;

#[derive(Debug, Serialize, Deserialize)]
struct StoringFields(HashMap<String, serde_json::Value>);

impl ExtraDeviceAuthorizationFields for StoringFields {}
type StoringDeviceAuthorizationResponse = DeviceAuthorizationResponse<StoringFields>;

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
        Some(TokenUrl::new(
            "https://passlane.eu.auth0.com/oauth/token".to_string(),
        )?),
    )
    .set_device_authorization_url(DeviceAuthorizationUrl::new(
        "https://passlane.eu.auth0.com/oauth/device/code".to_string(),
    )?)
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

pub fn login() -> Result<AccessTokens, anyhow::Error> {
    let client = new_client()?;
    let details: StoringDeviceAuthorizationResponse = client
        .exchange_device_code()?
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("offline_access".to_string()))
        .add_extra_param(
            "audience".to_string(),
            "https://passlane.eu.auth0.com/api/v2/",
        )
        .request(http_client)?;

    if !ui::open_browser(
        &details.verification_uri().to_string(),
        &format!(
            "Press ENTER to open up the browser to authorize this device. Enter the following code in the browser window: {}",
            details.user_code().secret().to_string()
        ),
    )? {
        bail!("Failed to open login page in browser");
    }
    // Now poll for the token
    let token_response = client.exchange_device_access_token(&details).request(
        http_client,
        std::thread::sleep,
        None,
    )?;
    Ok(create_access_tokens(token_response))
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
