use clap::Parser;
use origin_trace_backend::{App, Options, PublishedEndpoint};
#[tokio::main]
async fn run_main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let options = Options::parse().resolve()?;
    let listener = tokio::net::TcpListener::bind(options.address()?).await?;
    let address = listener.local_addr()?;
    // Arm the live console bridge before publishing the endpoint. The capture
    // launcher waits for that file, then starts Brave, and the bridge must
    // already be listening.
    let endpoint_file = options.endpoint_file.clone();
    let active_endpoint_file = options.active_endpoint_file.clone();
    let app = App::new(options, address.port()).await;
    let endpoint = PublishedEndpoint::new(endpoint_file.as_deref(), address)?;
    // Only the live launcher opts into this alias. Idle/development backends
    // must never replace the active capture endpoint merely by starting.
    let _active_endpoint = PublishedEndpoint::new(active_endpoint_file.as_deref(), address)?;
    println!("Research UI: {}", endpoint.url());
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

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    origin_trace_backend::javascript_worker_entry();
    run_main()
}

#[cfg(test)]
origin_trace_backend::javascript_worker_test_entry!();
