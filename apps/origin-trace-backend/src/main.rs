use clap::Parser;
use origin_trace_backend::{App, Options, PublishedEndpoint};
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let options = Options::parse().resolve()?;
    let listener = tokio::net::TcpListener::bind(options.address()?).await?;
    let address = listener.local_addr()?;
    let endpoint = PublishedEndpoint::new(options.endpoint_file.as_deref(), address)?;
    println!("Research UI: {}", endpoint.url());
    let app = App::new(options, address.port()).await;
    let shutdown = app.clone();
    axum::serve(listener, app.router())
        .with_graceful_shutdown(async move {
            #[cfg(unix)]
            {
                let mut termination =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("SIGTERM handler");
                tokio::select! {_=tokio::signal::ctrl_c()=>(),_=termination.recv()=>()}
            }
            #[cfg(not(unix))]
            {
                let _ = tokio::signal::ctrl_c().await;
            }
            shutdown.stop().await;
        })
        .await?;
    Ok(())
}
