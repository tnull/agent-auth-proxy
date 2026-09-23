#[cfg(target_os = "linux")]
mod actions;
#[cfg(target_os = "linux")]
mod connect;
#[cfg(target_os = "linux")]
mod probes;
#[cfg(target_os = "linux")]
mod protocol;
#[cfg(target_os = "linux")]
mod stream;

#[cfg(target_os = "linux")]
fn main() {
    let result = if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg == "--mcp-bridge")
    {
        actions::bridge()
    } else {
        run()
    };
    if result.is_err() {
        eprintln!("confinement probe failed");
        std::process::exit(1);
    }
}
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("the confinement probe requires Linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn run() -> std::io::Result<()> {
    use aap_types::AgentService;
    use http_body_util::{BodyExt, Limited};
    use protocol::{Job, RequestResult};
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    // Capture the inherited table before constructing a runtime or opening any
    // probe sockets. An absent descriptor must not be confused with a reused one.
    let inherited = probes::inherited()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    for _ in 0..32 {
        let Some(mut job) = protocol::read::<Job>(&mut std::io::stdin().lock())? else {
            return Ok(());
        };
        job.validate()?;
        let mut report = probes::run(&job, &inherited)?;
        if job.descendant {
            let mut descendant = job.clone();
            descendant.descendant = false;
            descendant.request = None;
            descendant.action = None;
            let mut child = Command::new(std::env::current_exe()?)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()?;
            protocol::write(&mut child.stdin.take().unwrap(), &descendant)?;
            let child_report = protocol::read(&mut child.stdout.take().unwrap())?
                .ok_or_else(|| std::io::Error::other("missing descendant report"))?;
            if !child.wait()?.success() {
                return Err(std::io::Error::other("descendant failed"));
            }
            report.descendant = Some(Box::new(child_report));
        }
        if let Some(request) = job.request.take() {
            let id = request.request_id.clone();
            let client = aap_client::DaemonSessionClient::new(job.session.clone());
            report.request = Some(runtime.block_on(async {
                let response = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    client.execute(request),
                )
                .await;
                match response {
                    Ok(Ok(response)) => {
                        let status = response.status().as_u16();
                        let body = tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            Limited::new(response.into_body(), 16 * 1024).collect(),
                        )
                        .await;
                        match body {
                            Ok(Ok(body)) => RequestResult {
                                id,
                                status: Some(status),
                                body: body.to_bytes().to_vec(),
                                error: None,
                            },
                            _ => RequestResult {
                                id,
                                status: None,
                                body: vec![],
                                error: Some(aap_types::ErrorCode::ResultUnavailable),
                            },
                        }
                    }
                    Ok(Err(error)) => RequestResult {
                        id,
                        status: None,
                        body: vec![],
                        error: Some(error.code),
                    },
                    Err(_) => RequestResult {
                        id,
                        status: None,
                        body: vec![],
                        error: Some(aap_types::ErrorCode::ResultUnavailable),
                    },
                }
            }));
        }
        if let Some(action) = job.action.take() {
            report.action = Some(runtime.block_on(actions::run(action, job)));
        }
        protocol::write(&mut std::io::stdout().lock(), &report)?;
        std::io::stdout().flush()?;
    }
    Err(std::io::Error::other("probe job limit"))
}
