use aap_types::{ErrorCode, Result};
use reuse_client::{Job, scenarios};
use std::{
    io::{Read, Write},
    sync::Arc,
    time::Duration,
};

fn run() -> Result<()> {
    let mut input = vec![];
    std::io::stdin()
        .lock()
        .take(64 * 1024 + 1)
        .read_to_end(&mut input)
        .map_err(|_| ErrorCode::RequestInvalid)?;
    if input.len() > 64 * 1024 {
        return Err(ErrorCode::LimitExceeded.into());
    }
    let job: Job = aap_types::json::decode(&input).map_err(|_| ErrorCode::RequestInvalid)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ErrorCode::InternalError)?;
    let report = runtime.block_on(async {
        tokio::time::timeout(
            Duration::from_secs(30),
            scenarios::run(
                Arc::new(aap_client::DaemonSessionClient::new(
                    job.sessions[0].clone(),
                )),
                Arc::new(aap_client::DaemonSessionClient::new(
                    job.sessions[1].clone(),
                )),
                &job.origin,
            ),
        )
        .await
        .map_err(|_| ErrorCode::ResultUnavailable)?
    })?;
    let output = serde_json::to_vec(&report).map_err(|_| ErrorCode::InternalError)?;
    if output.len() > 64 * 1024 {
        return Err(ErrorCode::LimitExceeded.into());
    }
    std::io::stdout()
        .lock()
        .write_all(&output)
        .map_err(|_| ErrorCode::ResultUnavailable.into())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("reuse client failed: {:?}", error.code);
        std::process::exit(1);
    }
}
