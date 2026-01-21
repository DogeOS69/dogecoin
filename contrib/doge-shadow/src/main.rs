//! doge-shadow: Shadow fork orchestration CLI for Dogecoin Core
//!
//! This CLI tool manages shadow fork instances for local development and testing.
//! It wraps dogecoind with the appropriate flags and provides convenience commands.

use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

/// Sentinel signature bytes (DER-encoded r=1, s=1)
/// Format: 30 06 02 01 01 02 01 01 [hashtype]
pub const SENTINEL_SIG: [u8; 8] = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];

/// Shadow fork orchestration CLI for Dogecoin Core
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start a new shadow fork instance
    Start {
        /// Fork height (block to fork from)
        #[arg(short = 'H', long)]
        height: u64,

        /// Source chain: main or test
        #[arg(short, long, default_value = "main")]
        chain: String,

        /// Coinbase maturity (default: 1)
        #[arg(short, long, default_value = "1")]
        maturity: u32,

        /// Path to dogecoind binary
        #[arg(long, default_value = "dogecoind")]
        dogecoind: PathBuf,

        /// Path to source datadir to copy blocks from
        #[arg(long)]
        source_datadir: Option<PathBuf>,

        /// RPC port (default: 32555)
        #[arg(long, default_value = "32555")]
        rpcport: u16,

        /// Run in foreground (don't daemonize)
        #[arg(long)]
        foreground: bool,
    },

    /// Mine a single block
    MineBlock {
        /// Address to receive coinbase reward
        #[arg(short, long)]
        address: String,

        /// RPC port (default: 32555)
        #[arg(long, default_value = "32555")]
        rpcport: u16,

        /// Path to dogecoin-cli binary
        #[arg(long, default_value = "dogecoin-cli")]
        cli: PathBuf,
    },

    /// Start interval mining
    MineInterval {
        /// Mining interval in seconds
        #[arg(short, long, default_value = "10")]
        interval: u64,

        /// Address to receive coinbase reward
        #[arg(short, long)]
        address: String,

        /// RPC port (default: 32555)
        #[arg(long, default_value = "32555")]
        rpcport: u16,

        /// Path to dogecoin-cli binary
        #[arg(long, default_value = "dogecoin-cli")]
        cli: PathBuf,

        /// Number of blocks to mine (0 = unlimited)
        #[arg(short, long, default_value = "0")]
        count: u64,
    },

    /// Stop the shadow fork instance
    Stop {
        /// RPC port (default: 32555)
        #[arg(long, default_value = "32555")]
        rpcport: u16,

        /// Path to dogecoin-cli binary
        #[arg(long, default_value = "dogecoin-cli")]
        cli: PathBuf,
    },

    /// Get the sentinel signature hex for use in transactions
    SentinelSig {
        /// Hash type to append (default: SIGHASH_ALL = 0x01)
        #[arg(long, default_value = "1")]
        hashtype: u8,
    },

    /// Get blockchain info from running instance
    Info {
        /// RPC port (default: 32555)
        #[arg(long, default_value = "32555")]
        rpcport: u16,

        /// Path to dogecoin-cli binary
        #[arg(long, default_value = "dogecoin-cli")]
        cli: PathBuf,
    },
}

/// Execute a dogecoin-cli command and return the output
fn rpc_call(cli: &Path, rpcport: u16, args: &[&str]) -> Result<String, String> {
    let output = Command::new(cli)
        .arg(format!("-rpcport={}", rpcport))
        .args(args)
        .output()
        .map_err(|e| format!("Failed to execute dogecoin-cli: {}", e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

/// Wait for RPC to become available
fn wait_for_rpc(cli: &Path, rpcport: u16, timeout_secs: u64) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed().as_secs() < timeout_secs {
        if rpc_call(cli, rpcport, &["getblockchaininfo"]).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_secs(1));
    }
    false
}

/// Spawn dogecoind and optionally wait for it
fn spawn_dogecoind(
    dogecoind: &Path,
    height: u64,
    chain: &str,
    maturity: u32,
    datadir: &Path,
    rpcport: u16,
    foreground: bool,
) -> Result<Option<Child>, String> {
    let mut cmd = Command::new(dogecoind);
    cmd.arg(format!("-shadowfork={}", height))
        .arg(format!("-shadowforkchain={}", chain))
        .arg(format!("-shadowforkmaturity={}", maturity))
        .arg(format!("-datadir={}", datadir.display()))
        .arg(format!("-rpcport={}", rpcport))
        .arg("-server=1")
        .arg("-listen=0")
        .arg("-dnsseed=0")
        .arg("-fixedseeds=0");

    if foreground {
        cmd.arg("-printtoconsole");
        cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    } else {
        cmd.arg("-daemon");
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
    }

    let child = cmd.spawn().map_err(|e| format!("Failed to spawn dogecoind: {}", e))?;

    if foreground {
        Ok(Some(child))
    } else {
        Ok(None)
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Start {
            height,
            chain,
            maturity,
            dogecoind,
            source_datadir,
            rpcport,
            foreground,
        } => {
            eprintln!("Starting shadow fork...");
            eprintln!("  Fork height: {}", height);
            eprintln!("  Source chain: {}", chain);
            eprintln!("  Coinbase maturity: {}", maturity);
            eprintln!("  RPC port: {}", rpcport);

            // Create persistent datadir (keep() persists directory and returns path)
            let datadir_path = TempDir::new().expect("Failed to create temp directory").keep();
            eprintln!("  Datadir: {:?}", datadir_path);

            // Copy blocks from source if provided
            if let Some(source) = source_datadir {
                eprintln!("  Copying blocks from {:?}...", source);
                let blocks_src = source.join("blocks");
                let blocks_dst = datadir_path.join("blocks");
                if blocks_src.exists() {
                    std::fs::create_dir_all(&blocks_dst).expect("Failed to create blocks dir");
                    // Copy block files
                    for entry in std::fs::read_dir(&blocks_src).expect("Failed to read blocks dir")
                    {
                        let entry = entry.expect("Failed to read entry");
                        let path = entry.path();
                        if path.is_file() {
                            let dest = blocks_dst.join(path.file_name().unwrap());
                            std::fs::copy(&path, &dest).expect("Failed to copy block file");
                        }
                    }
                    eprintln!("  Blocks copied.");
                }
            }

            // Spawn dogecoind
            match spawn_dogecoind(
                &dogecoind,
                height,
                &chain,
                maturity,
                &datadir_path,
                rpcport,
                foreground,
            ) {
                Ok(Some(mut child)) => {
                    // Foreground mode - wait for child
                    eprintln!("\nShadow fork running in foreground. Press Ctrl+C to stop.\n");
                    let _ = child.wait();
                }
                Ok(None) => {
                    // Daemon mode - wait for RPC and return
                    eprintln!("\nWaiting for RPC to become available...");
                    let cli_path = PathBuf::from("dogecoin-cli");
                    if wait_for_rpc(&cli_path, rpcport, 30) {
                        eprintln!("Shadow fork started successfully!");
                        eprintln!("  RPC port: {}", rpcport);
                        eprintln!("  Datadir: {:?}", datadir_path);
                        eprintln!("\nUse 'doge-shadow stop --rpcport {}' to stop.", rpcport);
                    } else {
                        eprintln!("Warning: RPC did not become available within 30 seconds.");
                        eprintln!("Check the datadir for debug.log: {:?}", datadir_path);
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::MineBlock { address, rpcport, cli } => {
            eprintln!("Mining block to address: {}", address);
            match rpc_call(&cli, rpcport, &["generatetoaddress", "1", &address]) {
                Ok(result) => {
                    println!("{}", result);
                    eprintln!("Block mined successfully!");
                }
                Err(e) => {
                    eprintln!("Error mining block: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::MineInterval { interval, address, rpcport, cli, count } => {
            eprintln!("Starting interval mining...");
            eprintln!("  Interval: {}s", interval);
            eprintln!("  Address: {}", address);
            eprintln!(
                "  Count: {}",
                if count == 0 { "unlimited".to_string() } else { count.to_string() }
            );
            eprintln!("\nPress Ctrl+C to stop.\n");

            let mut mined = 0u64;
            loop {
                match rpc_call(&cli, rpcport, &["generatetoaddress", "1", &address]) {
                    Ok(result) => {
                        mined += 1;
                        let block_hash = result.lines().next().unwrap_or("<unknown>");
                        eprintln!("Block {} mined: {}", mined, block_hash);
                    }
                    Err(e) => {
                        eprintln!("Error mining block: {}", e);
                    }
                }

                if count > 0 && mined >= count {
                    eprintln!("\nMined {} blocks. Stopping.", count);
                    break;
                }

                thread::sleep(Duration::from_secs(interval));
            }
        }

        Commands::Stop { rpcport, cli } => {
            eprintln!("Stopping shadow fork on port {}...", rpcport);
            match rpc_call(&cli, rpcport, &["stop"]) {
                Ok(_) => {
                    eprintln!("Shadow fork stopped.");
                }
                Err(e) => {
                    eprintln!("Error stopping: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::SentinelSig { hashtype } => {
            let mut sig = SENTINEL_SIG.to_vec();
            sig.push(hashtype);
            println!("{}", hex::encode(&sig));
            eprintln!("\nThis signature bypasses CHECKSIG verification in shadow fork mode.");
            eprintln!("Use it to spend any UTXO without knowing the private key.");
        }

        Commands::Info { rpcport, cli } => match rpc_call(&cli, rpcport, &["getblockchaininfo"]) {
            Ok(result) => {
                println!("{}", result);
            }
            Err(e) => {
                eprintln!("Error getting info: {}", e);
                std::process::exit(1);
            }
        },
    }
}
