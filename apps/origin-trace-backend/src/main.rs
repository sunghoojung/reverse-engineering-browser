use clap::Parser;
use origin_trace_backend::{App, Options, PublishedEndpoint};
use std::{sync::Arc, time::Duration};
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut options = Options::parse().resolve()?;
    // Register before browser spawn: launch-pending SIGINT/SIGTERM must run
    // owned-process cleanup rather than terminate us with the default action.
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let (stop, mut cancelled) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        tokio::select! { _=interrupt.recv()=>(), _=terminate.recv()=>() }
        let _ = stop.send(true);
    });
    let browser = Arc::new(tokio::sync::Mutex::new(
        origin_trace_backend::CaptureFirstBrowser::launch(&mut options, &mut cancelled).await?,
    ));
    let result = async {
        let listener = tokio::net::TcpListener::bind(options.address()?).await?;
        let address = listener.local_addr()?;
        let endpoint = PublishedEndpoint::new(options.endpoint_file.as_deref(), address)?;
        println!("Research UI: {}", endpoint.url());
        let app = App::new(options, address.port()).await;
        let shutdown = app.clone();
        let owned_browser = browser.clone();
        axum::serve(listener, app.router())
            .with_graceful_shutdown(async move {
                let disposable = owned_browser.lock().await.is_some();
                tokio::select! {
                    _=async { if !*cancelled.borrow() { let _ = cancelled.changed().await; } }=>(),
                    _=async {
                        loop {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            if owned_browser.lock().await.as_mut().is_some_and(|browser| browser.exited()) { break; }
                        }
                    }, if disposable => {
                        eprintln!("Capture-first owned browser exited; ending this experiment.");
                    },
                    _=tokio::time::sleep(Duration::from_secs(3600)), if disposable => {
                        eprintln!("Capture-first disposable experiment expired after one hour.");
                    }
                }
                if disposable {
                    // A wedged transport must not keep the disposable browser alive.
                    let _ = tokio::time::timeout(Duration::from_secs(8), shutdown.stop()).await;
                    if let Some(browser) = owned_browser.lock().await.as_mut() { browser.stop().await; }
                } else { shutdown.stop().await; }
            })
            .await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }.await;
    if let Some(browser) = browser.lock().await.as_mut() {
        browser.stop().await;
    }
    result
}
