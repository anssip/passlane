use crate::ui;
use anyhow::bail;
use futures::{
    channel::oneshot,
    prelude::*,
    task::{Context, Poll},
};
use hyper::{body::Body, server, service, Request, Response};
use oauth2::*;
use oauth2::{AuthorizationCode, State};
use serde::Deserialize;
use std::env;
use std::net::SocketAddr;
use tower_service::Service;

#[derive(Deserialize)]
pub struct ReceivedCode {
    pub code: AuthorizationCode,
    pub state: State,
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

pub async fn login() -> Result<oauth2::StandardToken, anyhow::Error> {
    let reqwest_client = reqwest::Client::new();

    let mut client = Client::new(
        env::var("AUTH_CLIENT_ID")?,
        Url::parse(&env::var("AUTH_AUTHORIZE_URL")?)?,
        Url::parse(&env::var("AUTH_TOKEN_URL")?)?,
    );
    client.set_client_secret(&env::var("AUTH_CLIENT_SECRET")?);
    client.set_redirect_url(Url::parse(&env::var("AUTH_REDIRECT_URL")?)?);
    client.add_scope("read");
    client.add_scope("write");

    let state = State::new_random();
    let auth_url = client.authorize_url(&state);
    if !ui::open_browser(
        &String::from(auth_url),
        "Press ENTER to open up the browser to login or q to exit: ",
    )? {
        bail!("Failed to open login page in browser");
    }
    let received: ReceivedCode = listen_for_code(8080).await?;
    if received.state != state {
        panic!("CSRF token mismatch :(");
    }

    let token = client
        .exchange_code(received.code)
        .with_client(&reqwest_client)
        .execute::<StandardToken>()
        .await?;

    return Ok(token);
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
