use rama::http::body::util::BodyExt;
use rama::http::core::body::Incoming;
use rama::http::{Body, Request, Response};
use rama::service::service_fn;
use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::task::JoinSet;

#[allow(dead_code)]
#[path = "../../src/adapters/transport/io.rs"]
mod io;

pub struct Receiver {
    pub address: SocketAddr,
    arrivals: Arc<AtomicU64>,
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
    authorizations: Arc<Mutex<Vec<Option<String>>>>,
    release: Arc<tokio::sync::Notify>,
    task: tokio::task::JoinHandle<()>,
    _runtime: Runtime,
}
impl Receiver {
    pub fn start(drop_response: bool, hold_response: bool) -> Self {
        Self::configured(drop_response, hold_response, None, false)
    }
    pub fn authenticated(authorization: String, echo_credential: bool) -> Self {
        Self::configured(false, false, Some(authorization), echo_credential)
    }
    fn configured(
        drop_response: bool,
        hold_response: bool,
        authorization: Option<String>,
        echo_credential: bool,
    ) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let listener = runtime
            .block_on(TcpListener::bind((Ipv4Addr::LOCALHOST, 0)))
            .unwrap();
        let address = listener.local_addr().unwrap();
        let arrivals = Arc::new(AtomicU64::new(0));
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let authorizations = Arc::new(Mutex::new(Vec::new()));
        let captured_authorizations = Arc::clone(&authorizations);
        let observed = Arc::clone(&arrivals);
        let captured = Arc::clone(&bodies);
        let release = Arc::new(tokio::sync::Notify::new());
        let response_gate = Arc::clone(&release);
        let task = runtime.spawn(async move {
            let mut children = JoinSet::new();
            while let Ok((stream, _)) = listener.accept().await {
                let observed = Arc::clone(&observed);
                let captured = Arc::clone(&captured);
                let response_gate = Arc::clone(&response_gate);
                let captured_authorizations = Arc::clone(&captured_authorizations);
                let authorization = authorization.clone();
                children.spawn(async move {
                    let abort = drop_response.then(|| Arc::new(tokio::sync::Notify::new()));
                    let abort_response = abort.clone();
                    let service = service_fn(move |request: Request<Incoming>| {
                        let observed = Arc::clone(&observed);
                        let captured = Arc::clone(&captured);
                        let response_gate = Arc::clone(&response_gate);
                        let captured_authorizations = Arc::clone(&captured_authorizations);
                        let authorization = authorization.clone();
                        let abort_response = abort_response.clone();
                        async move {
                            let supplied = request
                                .headers()
                                .get("authorization")
                                .map(|value| value.to_str().unwrap().to_owned());
                            let authorized = authorization
                                .as_ref()
                                .is_none_or(|expected| supplied.as_ref() == Some(expected));
                            captured_authorizations.lock().unwrap().push(supplied);
                            let mut body = request.into_body();
                            let mut bytes = Vec::new();
                            while let Some(frame) = body.frame().await {
                                if let Ok(data) = frame.unwrap().into_data() {
                                    assert!(bytes.len() + data.len() <= 2 * 1024 * 1024);
                                    bytes.extend_from_slice(&data);
                                }
                            }
                            captured.lock().unwrap().push(bytes.clone());
                            observed.fetch_add(1, Ordering::SeqCst);
                            if hold_response {
                                response_gate.notified().await;
                            }
                            if let Some(abort) = abort_response {
                                // Drop the real connection before any response headers are sent.
                                abort.notify_one();
                                return std::future::pending::<Result<Response, Infallible>>()
                                    .await;
                            }
                            let mut response =
                                Response::builder().status(if authorized { 200 } else { 401 });
                            if echo_credential {
                                response = response.header(
                                    "x-observed-credential",
                                    authorization.as_deref().unwrap(),
                                );
                            }
                            Ok::<_, Infallible>(response.body(Body::from(bytes)).unwrap())
                        }
                    });
                    let connection = rama::http::core::server::conn::http1::Builder::new()
                        .serve_connection(io::RamaIo::new(stream), service);
                    if let Some(abort) = abort {
                        tokio::select! {
                            _ = abort.notified() => {}
                            _ = connection => {}
                        }
                    } else {
                        let _ = connection.await;
                    }
                    Ok::<_, Infallible>(())
                });
                while children.try_join_next().is_some() {}
            }
        });
        Self {
            address,
            arrivals,
            bodies,
            authorizations,
            release,
            task,
            _runtime: runtime,
        }
    }
    pub fn count(&self) -> u64 {
        self.arrivals.load(Ordering::SeqCst)
    }
    pub fn bodies(&self) -> Vec<Vec<u8>> {
        self.bodies.lock().unwrap().clone()
    }
    pub fn authorizations(&self) -> Vec<Option<String>> {
        self.authorizations.lock().unwrap().clone()
    }
    pub fn wait_for_effect(&self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.count() == 0 {
            assert!(
                Instant::now() < deadline,
                "actual receiver never observed dispatch"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    pub fn release_response(&self) {
        self.release.notify_one();
    }
}
impl Drop for Receiver {
    fn drop(&mut self) {
        self.task.abort();
    }
}
