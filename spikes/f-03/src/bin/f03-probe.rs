//! Runs the spike checks and prints one line per check. Exit status 0 only if all passed.

fn main() {
    let https_host = std::env::var("F03_HTTPS_HOST").unwrap_or_else(|_| "example.com".into());
    let wss_host = std::env::var("F03_WSS_HOST").unwrap_or_else(|_| "echo.websocket.org".into());
    let db_dir = std::env::var_os("F03_DB_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    println!("stack {}", f03_spike::stack_name());
    let mut ok = true;
    for check in f03_spike::run(&https_host, &wss_host, &db_dir) {
        match check.outcome {
            Ok(detail) => println!("PASS {}: {detail}", check.name),
            Err(detail) => {
                ok = false;
                println!("FAIL {}: {detail}", check.name);
            }
        }
    }
    std::process::exit(if ok { 0 } else { 1 });
}
