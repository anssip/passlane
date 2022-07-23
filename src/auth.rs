use crate::ui;
use futures::{
    channel::oneshot,
    prelude::*,
    task::{Context, Poll},
};
use hyper::{body::Body, server, service, Request, Response};
use serde::Deserialize;
use std::env;
use std::net::SocketAddr;
use tower_service::Service;

use anyhow;
use anyhow::bail;
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    RedirectUrl, Scope, TokenResponse, TokenUrl,
};

#[derive(Deserialize)]
pub struct ReceivedCode {
    pub code: AuthorizationCode,
    pub state: CsrfToken,
}
pub struct Server {
    channel: Option<oneshot::Sender<ReceivedCode>>,
    document: Vec<u8>,
}

async fn file_send(filename: &str) -> anyhow::Result<Vec<u8>> {
    if let Ok(contents) = tokio::fs::read(filename).await {
        let body = contents.into();
        return Ok(body);
    }
    bail!("file not found")
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
        // Box::pin(future::ok(Response::new(Body::from("<h1>Success!</h1>"))))
    }
}

pub async fn login() -> Result<String, anyhow::Error> {
    // Create an OAuth2 client by specifying the client ID, client secret, authorization URL and
    // token URL.
    let client = BasicClient::new(
        ClientId::new(env::var("AUTH_CLIENT_ID")?),
        Some(ClientSecret::new(env::var("AUTH_CLIENT_SECRET")?)),
        AuthUrl::new(env::var("AUTH_AUTHORIZE_URL")?)?,
        Some(TokenUrl::new(env::var("AUTH_TOKEN_URL")?)?),
    )
    .set_redirect_uri(RedirectUrl::new(env::var("AUTH_REDIRECT_URL")?)?)
    .set_auth_type(AuthType::RequestBody);

    // Generate a PKCE challenge.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let csrf_token = CsrfToken::new_random_len(256);

    // Generate the full authorization URL.
    let (auth_url, csrf_state) = client
        .authorize_url(|| csrf_token)
        // Set the desired scopes.
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_extra_param(
            "audience".to_string(),
            "https://passlane.eu.auth0.com/api/v2/",
        )
        // Set the PKCE code challenge.
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
    // Now you can trade it for an access token.
    let token_result = client
        .exchange_code(AuthorizationCode::new(received.code.secret().to_string()))
        // Set the PKCE code verifier.
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await?;
    Ok(String::from(token_result.access_token().secret()))
}

async fn listen_for_code(port: u32) -> Result<ReceivedCode, anyhow::Error> {
    let bind = format!("127.0.0.1:{}", port);
    log::info!("Listening on: http://{}", bind);

    let addr: SocketAddr = str::parse(&bind)?;

    let (tx, rx) = oneshot::channel::<ReceivedCode>();
    let mut channel = Some(tx);
    let document = file_send("resources/auth_success.html").await?;
    let server_future = server::Server::bind(&addr).serve(service::make_service_fn(move |_| {
        let channel = channel.take().expect("channel is not available");
        let mut server = Server {
            channel: Some(channel),
            document: document.clone(),
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
