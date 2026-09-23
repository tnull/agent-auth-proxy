#[cfg(target_os = "linux")]
#[path = "demo/mod.rs"]
mod demo;

#[cfg(target_os = "linux")]
#[tokio::main(worker_threads = 2)]
async fn main() {
    if let Err(error) = demo::main().await {
        eprintln!("Demo failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("The synthetic demo currently requires Linux.");
    std::process::exit(1);
}
