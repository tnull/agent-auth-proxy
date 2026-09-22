fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
fn run() -> aap_types::Result<()> {
    use aap_types::ErrorCode;
    use std::io::Read;
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.len() != 2 {
        return Err(ErrorCode::RequestInvalid.into());
    }
    let directory = std::path::PathBuf::from(&arguments[1]);
    if arguments[0] == "mcp-bridge" {
        // This branch consumes MCP on stdin, never the store unlock protocol.
        // Its only authority is the host-provided session attachment.
        let runtime = runtime()?;
        let client = std::sync::Arc::new(aap_client::DaemonSessionClient::new(directory));
        let result = runtime.block_on(aap_mcp::serve(
            tokio::io::stdin(),
            tokio::io::stdout(),
            aap_mcp::Tools::new(client),
        ));
        runtime.shutdown_timeout(std::time::Duration::from_secs(2));
        return result;
    }
    if arguments[0] == "validate" {
        let directory = aap_config::PrivateDir::open(&directory, false)
            .map_err(|_| ErrorCode::RequestInvalid)?;
        let loaded = aap_daemon::load(&directory)?;
        println!(
            "{}",
            serde_json::json!({"valid":true,"configuration_revision":loaded.configuration.configuration_revision})
        );
        return Ok(());
    }
    if arguments[0] != "serve" {
        return Err(ErrorCode::RequestInvalid.into());
    }
    // The trusted launcher supplies exactly 32 random raw key bytes and EOF.
    // Keys never come from arguments, environment variables, or configuration.
    let mut key = vec![0; 32];
    let mut input = std::io::stdin().lock();
    input
        .read_exact(&mut key)
        .map_err(|_| ErrorCode::VaultLocked)?;
    let mut extra = [0; 1];
    if input.read(&mut extra).map_err(|_| ErrorCode::VaultLocked)? != 0 {
        return Err(ErrorCode::RequestInvalid.into());
    }
    drop(input);
    let runtime = runtime()?;
    let result = runtime.block_on(aap_daemon::runtime::serve(
        directory,
        aap_secrets::SecretBytes::new(key)?,
    ));
    runtime.shutdown_timeout(std::time::Duration::from_secs(2));
    result
}

#[cfg(target_os = "linux")]
fn runtime() -> aap_types::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|_| aap_types::ErrorCode::InternalError.into())
}

#[cfg(not(target_os = "linux"))]
fn run() -> aap_types::Result<()> {
    Err(aap_types::ErrorCode::AuthProfileUnsupported.into())
}
