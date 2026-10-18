use o3kd::composition;
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = o3k_config::Config::from_sources(std::env::args(), std::env::vars())?;
    let subscriber =
        tracing_subscriber::fmt().with_env_filter(EnvFilter::try_new(&config.log_filter)?);
    match config.log_format {
        o3k_config::LogFormat::Json => subscriber.json().init(),
        o3k_config::LogFormat::Pretty => subscriber.pretty().init(),
    }

    let listen_addr = config.listen_addr;
    let data_dir = config.data_dir.clone();
    let provider = config.provider;
    // Bind before composition starts workers or opens canonical storage, so a
    // bind failure cannot leave detached background tasks behind the lock.
    let listener = TcpListener::bind(listen_addr).await?;
    let composition = composition::build_composition(config).await?;

    info!(
        address = %listen_addr,
        data_dir = %data_dir.display(),
        provider = ?provider,
        "o3kd listening"
    );

    let serve_state = composition.state.clone();
    let shutdown_state = composition.state.clone();
    let serve_result = axum::serve(listener, o3k_api::router_with_state(serve_state))
        .with_graceful_shutdown(composition::shutdown_signal(shutdown_state))
        .await;

    composition.shutdown().await;
    serve_result?;
    Ok(())
}
