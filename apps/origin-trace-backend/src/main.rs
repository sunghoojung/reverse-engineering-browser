use clap::Parser;
use origin_trace_backend::{App, Options, PublishedEndpoint};
use tiny_http::Server;

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let options = Options::parse();
    let server = Server::http(options.address())?;
    let endpoint = PublishedEndpoint::new(options.endpoint_file.as_deref(), server.server_addr())?;
    println!("Research UI: {}", endpoint.url());

    let port = server
        .server_addr()
        .to_ip()
        .map(|address| address.port())
        .ok_or("HTTP listener is not IP-based")?;
    let app = App::new(options, port);
    for request in server.incoming_requests() {
        app.handle(request);
    }
    Ok(())
}
