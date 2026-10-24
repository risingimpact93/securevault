use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use keyhaven_web::{default_data_dir, default_dist_dir, Config, DEFAULT_IDLE_SECS, DEFAULT_PORT};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_args(&args) {
        Ok(config) => {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(err) => {
                    eprintln!("keyhaven-web: {err}");
                    return ExitCode::from(1);
                }
            };
            if let Err(err) = rt.block_on(keyhaven_web::serve(config)) {
                eprintln!("keyhaven-web: {err}");
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(2)
        }
    }
}

fn parse_args(args: &[String]) -> Result<Config, String> {
    let mut bind: IpAddr = "127.0.0.1"
        .parse()
        .expect("localhost");
    let mut port = DEFAULT_PORT;
    let mut data_dir = default_data_dir();
    let mut dist_dir = Some(default_dist_dir());
    let mut dev_insecure_cookie = false;
    let mut idle_timeout = Duration::from_secs(DEFAULT_IDLE_SECS);
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "--dev-insecure-cookie" => {
                dev_insecure_cookie = true;
                i += 1;
            }
            "--bind" => {
                let value = args.get(i + 1).ok_or("--bind requires an address")?;
                bind = value
                    .parse()
                    .map_err(|_| format!("invalid --bind address: {value}"))?;
                i += 2;
            }
            "--port" => {
                let value = args.get(i + 1).ok_or("--port requires a number")?;
                port = value
                    .parse()
                    .map_err(|_| format!("invalid --port: {value}"))?;
                if port == 0 {
                    return Err("--port must be 1-65535".into());
                }
                i += 2;
            }
            "--data-dir" => {
                let value = args.get(i + 1).ok_or("--data-dir requires a path")?;
                data_dir = PathBuf::from(value);
                i += 2;
            }
            "--dist-dir" => {
                let value = args.get(i + 1).ok_or("--dist-dir requires a path")?;
                dist_dir = Some(PathBuf::from(value));
                i += 2;
            }
            "--idle-timeout-secs" => {
                let value = args.get(i + 1).ok_or("--idle-timeout-secs requires a number")?;
                let secs: u64 = value
                    .parse()
                    .map_err(|_| format!("invalid --idle-timeout-secs: {value}"))?;
                idle_timeout = Duration::from_secs(secs.max(1));
                i += 2;
            }
            other => return Err(format!("unknown argument: {other}\nUse --help for usage.")),
        }
    }
    Ok(Config {
        bind,
        port,
        data_dir,
        dist_dir,
        dev_insecure_cookie,
        idle_timeout,
        use_vault_idle: true,
        approval_timeout: Duration::from_secs(60),
        mcp_enabled: false,
    })
}

fn print_help() {
    eprintln!(
        "\
Keyhaven web server

USAGE:
    keyhaven-web [OPTIONS]

OPTIONS:
    --bind ADDR                 Listen address (default: 127.0.0.1)
    --port PORT                 Listen port (default: {DEFAULT_PORT})
    --data-dir DIR              Vault and config directory
    --dist-dir DIR              Built React UI (npm run build → dist/)
    --dev-insecure-cookie       Omit the Secure flag on the session cookie
                                (http://127.0.0.1 testing only)
    --idle-timeout-secs N       Idle auto-lock before a vault is open (default: {DEFAULT_IDLE_SECS}).
                                After unlock, the value stored in the vault is used.
    -h, --help                  Show this help

The server binds 127.0.0.1 by default. Do not expose it to the network without
HTTPS and an access layer. See README section '웹 버전'.
"
    );
}
