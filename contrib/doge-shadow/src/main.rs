//! doge-shadow: Shadow fork orchestration CLI for Dogecoin Core
//!
//! This CLI tool manages shadow fork instances for local development and testing.
//! It wraps dogecoind with the appropriate flags and provides convenience commands.
//!
//! Configuration can be provided via:
//! 1. TOML config file (~/.config/doge-shadow/config.toml or ./doge-shadow.toml)
//! 2. Environment variables (DOGE_SHADOW_*)
//! 3. Command-line arguments
//!
//! Precedence: CLI > env vars > config file

use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

/// Sentinel signature bytes (DER-encoded r=1, s=1)
/// Format: 30 06 02 01 01 02 01 01 [hashtype]
pub const SENTINEL_SIG: [u8; 8] = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];

/// Config file structure (TOML)
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Config {
    /// Default RPC port for shadow node
    rpcport: Option<u16>,
    /// Default source RPC port
    source_rpcport: Option<u16>,
    /// Path to dogecoin-cli binary
    cli: Option<PathBuf>,
    /// Path to dogecoind binary
    dogecoind: Option<PathBuf>,
    /// Default source chain (main/test)
    chain: Option<String>,
    /// Default coinbase maturity
    maturity: Option<u32>,
    /// Default mining address
    address: Option<String>,
    /// Default mining interval
    interval: Option<u64>,
    /// Shadow node datadir
    datadir: Option<PathBuf>,
    /// Source node datadir
    source_datadir: Option<PathBuf>,
}

impl Config {
    /// Load config from file, checking multiple locations
    fn load() -> Self {
        // Check locations in order of precedence (later overrides earlier)
        let locations = [
            // System-wide config
            PathBuf::from("/etc/doge-shadow/config.toml"),
            // User config directory
            dirs::config_dir().map(|p| p.join("doge-shadow/config.toml")).unwrap_or_default(),
            // Home directory
            dirs::home_dir().map(|p| p.join(".doge-shadow.toml")).unwrap_or_default(),
            // Current directory
            PathBuf::from("doge-shadow.toml"),
        ];

        let mut config = Config::default();

        for path in locations.iter().filter(|p| !p.as_os_str().is_empty()) {
            if path.exists() {
                if let Ok(contents) = fs::read_to_string(path) {
                    if let Ok(file_config) = toml::from_str::<Config>(&contents) {
                        // Merge: file values override defaults
                        config.merge(file_config);
                        eprintln!("Loaded config from {:?}", path);
                    }
                }
            }
        }

        config
    }

    /// Merge another config into this one (other takes precedence)
    fn merge(&mut self, other: Config) {
        if other.rpcport.is_some() {
            self.rpcport = other.rpcport;
        }
        if other.source_rpcport.is_some() {
            self.source_rpcport = other.source_rpcport;
        }
        if other.cli.is_some() {
            self.cli = other.cli;
        }
        if other.dogecoind.is_some() {
            self.dogecoind = other.dogecoind;
        }
        if other.chain.is_some() {
            self.chain = other.chain;
        }
        if other.maturity.is_some() {
            self.maturity = other.maturity;
        }
        if other.address.is_some() {
            self.address = other.address;
        }
        if other.interval.is_some() {
            self.interval = other.interval;
        }
        if other.datadir.is_some() {
            self.datadir = other.datadir;
        }
        if other.source_datadir.is_some() {
            self.source_datadir = other.source_datadir;
        }
    }

    /// Set environment variables from config (for clap to pick up)
    fn set_env_vars(&self) {
        if let Some(v) = &self.rpcport {
            if std::env::var("DOGE_SHADOW_RPCPORT").is_err() {
                std::env::set_var("DOGE_SHADOW_RPCPORT", v.to_string());
            }
        }
        if let Some(v) = &self.source_rpcport {
            if std::env::var("DOGE_SHADOW_SOURCE_RPCPORT").is_err() {
                std::env::set_var("DOGE_SHADOW_SOURCE_RPCPORT", v.to_string());
            }
        }
        if let Some(v) = &self.cli {
            if std::env::var("DOGE_SHADOW_CLI").is_err() {
                std::env::set_var("DOGE_SHADOW_CLI", v.as_os_str());
            }
        }
        if let Some(v) = &self.dogecoind {
            if std::env::var("DOGE_SHADOW_DOGECOIND").is_err() {
                std::env::set_var("DOGE_SHADOW_DOGECOIND", v.as_os_str());
            }
        }
        if let Some(v) = &self.chain {
            if std::env::var("DOGE_SHADOW_CHAIN").is_err() {
                std::env::set_var("DOGE_SHADOW_CHAIN", v);
            }
        }
        if let Some(v) = &self.maturity {
            if std::env::var("DOGE_SHADOW_MATURITY").is_err() {
                std::env::set_var("DOGE_SHADOW_MATURITY", v.to_string());
            }
        }
        if let Some(v) = &self.address {
            if std::env::var("DOGE_SHADOW_ADDRESS").is_err() {
                std::env::set_var("DOGE_SHADOW_ADDRESS", v);
            }
        }
        if let Some(v) = &self.interval {
            if std::env::var("DOGE_SHADOW_INTERVAL").is_err() {
                std::env::set_var("DOGE_SHADOW_INTERVAL", v.to_string());
            }
        }
        if let Some(v) = &self.datadir {
            if std::env::var("DOGE_SHADOW_DATADIR").is_err() {
                std::env::set_var("DOGE_SHADOW_DATADIR", v.as_os_str());
            }
        }
        if let Some(v) = &self.source_datadir {
            if std::env::var("DOGE_SHADOW_SOURCE_DATADIR").is_err() {
                std::env::set_var("DOGE_SHADOW_SOURCE_DATADIR", v.as_os_str());
            }
        }
    }
}

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
        #[arg(short = 'H', long, env = "DOGE_SHADOW_HEIGHT")]
        height: u64,

        /// Source chain: main or test
        #[arg(short, long, default_value = "main", env = "DOGE_SHADOW_CHAIN")]
        chain: String,

        /// Coinbase maturity (default: 1)
        #[arg(short, long, default_value = "1", env = "DOGE_SHADOW_MATURITY")]
        maturity: u32,

        /// Path to dogecoind binary
        #[arg(long, default_value = "dogecoind", env = "DOGE_SHADOW_DOGECOIND")]
        dogecoind: PathBuf,

        /// Path to source datadir to copy blocks from
        #[arg(long, env = "DOGE_SHADOW_SOURCE_DATADIR")]
        source_datadir: Option<PathBuf>,

        /// RPC port (default: 32555)
        #[arg(long, default_value = "32555", env = "DOGE_SHADOW_RPCPORT")]
        rpcport: u16,

        /// Run in foreground (don't daemonize)
        #[arg(long, env = "DOGE_SHADOW_FOREGROUND")]
        foreground: bool,
    },

    /// Mine a single block
    MineBlock {
        /// Address to receive coinbase reward
        #[arg(short, long, env = "DOGE_SHADOW_ADDRESS")]
        address: String,

        /// RPC port (default: 32555)
        #[arg(long, default_value = "32555", env = "DOGE_SHADOW_RPCPORT")]
        rpcport: u16,

        /// Shadow node datadir (for cookie auth with temp datadirs)
        #[arg(long, env = "DOGE_SHADOW_DATADIR")]
        datadir: Option<PathBuf>,

        /// Path to dogecoin-cli binary
        #[arg(long, default_value = "dogecoin-cli", env = "DOGE_SHADOW_CLI")]
        cli: PathBuf,
    },

    /// Start interval mining
    MineInterval {
        /// Mining interval in seconds
        #[arg(short, long, default_value = "10", env = "DOGE_SHADOW_INTERVAL")]
        interval: u64,

        /// Address to receive coinbase reward
        #[arg(short, long, env = "DOGE_SHADOW_ADDRESS")]
        address: String,

        /// RPC port (default: 32555)
        #[arg(long, default_value = "32555", env = "DOGE_SHADOW_RPCPORT")]
        rpcport: u16,

        /// Shadow node datadir (for cookie auth with temp datadirs)
        #[arg(long, env = "DOGE_SHADOW_DATADIR")]
        datadir: Option<PathBuf>,

        /// Path to dogecoin-cli binary
        #[arg(long, default_value = "dogecoin-cli", env = "DOGE_SHADOW_CLI")]
        cli: PathBuf,

        /// Number of blocks to mine (0 = unlimited)
        #[arg(short, long, default_value = "0")]
        count: u64,
    },

    /// Stop the shadow fork instance
    Stop {
        /// RPC port (default: 32555)
        #[arg(long, default_value = "32555", env = "DOGE_SHADOW_RPCPORT")]
        rpcport: u16,

        /// Shadow node datadir (for cookie auth with temp datadirs)
        #[arg(long, env = "DOGE_SHADOW_DATADIR")]
        datadir: Option<PathBuf>,

        /// Path to dogecoin-cli binary
        #[arg(long, default_value = "dogecoin-cli", env = "DOGE_SHADOW_CLI")]
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
        #[arg(long, default_value = "32555", env = "DOGE_SHADOW_RPCPORT")]
        rpcport: u16,

        /// Shadow node datadir (for cookie auth with temp datadirs)
        #[arg(long, env = "DOGE_SHADOW_DATADIR")]
        datadir: Option<PathBuf>,

        /// Path to dogecoin-cli binary
        #[arg(long, default_value = "dogecoin-cli", env = "DOGE_SHADOW_CLI")]
        cli: PathBuf,
    },

    /// Step through canonical blocks from source chain
    ///
    /// Fetches blocks from a running mainnet/testnet node and submits them
    /// to the shadow fork. Once the shadow chain diverges (a local block is
    /// mined), stepping is disabled.
    Step {
        /// Source node RPC port to fetch blocks from
        #[arg(long, env = "DOGE_SHADOW_SOURCE_RPCPORT")]
        source_rpcport: u16,

        /// Source node datadir (for cookie auth if not using default)
        #[arg(long, env = "DOGE_SHADOW_SOURCE_DATADIR")]
        source_datadir: Option<PathBuf>,

        /// Shadow node RPC port (default: 32555)
        #[arg(long, default_value = "32555", env = "DOGE_SHADOW_RPCPORT")]
        rpcport: u16,

        /// Shadow node datadir (required for cookie auth with temp datadirs)
        #[arg(long, env = "DOGE_SHADOW_DATADIR")]
        datadir: Option<PathBuf>,

        /// Path to dogecoin-cli binary
        #[arg(long, default_value = "dogecoin-cli", env = "DOGE_SHADOW_CLI")]
        cli: PathBuf,

        /// Number of blocks to step (default: 1)
        #[arg(short, long, default_value = "1")]
        count: u64,

        /// Step until reaching this height (overrides --count)
        #[arg(long)]
        to_height: Option<u64>,
    },
}

/// Execute a dogecoin-cli command and return the output
fn rpc_call(cli: &Path, rpcport: u16, args: &[&str]) -> Result<String, String> {
    rpc_call_with_datadir(cli, rpcport, None, args)
}

/// Execute a dogecoin-cli command with optional datadir for cookie auth
fn rpc_call_with_datadir(
    cli: &Path,
    rpcport: u16,
    datadir: Option<&Path>,
    args: &[&str],
) -> Result<String, String> {
    let mut cmd = Command::new(cli);
    cmd.arg(format!("-rpcport={}", rpcport));
    if let Some(dir) = datadir {
        cmd.arg(format!("-datadir={}", dir.display()));
    }
    cmd.args(args);

    let output = cmd.output().map_err(|e| format!("Failed to execute dogecoin-cli: {}", e))?;

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

/// Get current block height from node with optional datadir
fn get_block_height_with_datadir(
    cli: &Path,
    rpcport: u16,
    datadir: Option<&Path>,
) -> Result<u64, String> {
    let result = rpc_call_with_datadir(cli, rpcport, datadir, &["getblockcount"])?;
    result.trim().parse::<u64>().map_err(|e| format!("Failed to parse block height: {}", e))
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
    // Load config file and set env vars before CLI parsing
    // This allows: CLI > env vars > config file precedence
    let config = Config::load();
    config.set_env_vars();

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

        Commands::MineBlock { address, rpcport, datadir, cli } => {
            eprintln!("Mining block to address: {}", address);
            match rpc_call_with_datadir(
                &cli,
                rpcport,
                datadir.as_deref(),
                &["generatetoaddress", "1", &address],
            ) {
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

        Commands::MineInterval { interval, address, rpcport, datadir, cli, count } => {
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
                match rpc_call_with_datadir(
                    &cli,
                    rpcport,
                    datadir.as_deref(),
                    &["generatetoaddress", "1", &address],
                ) {
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

        Commands::Stop { rpcport, datadir, cli } => {
            eprintln!("Stopping shadow fork on port {}...", rpcport);
            match rpc_call_with_datadir(&cli, rpcport, datadir.as_deref(), &["stop"]) {
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

        Commands::Info { rpcport, datadir, cli } => {
            match rpc_call_with_datadir(&cli, rpcport, datadir.as_deref(), &["getblockchaininfo"]) {
                Ok(result) => {
                    println!("{}", result);
                }
                Err(e) => {
                    eprintln!("Error getting info: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Step {
            source_rpcport,
            source_datadir,
            rpcport,
            datadir,
            cli,
            count,
            to_height,
        } => {
            eprintln!("Canonical block stepping...");
            eprintln!("  Source RPC port: {}", source_rpcport);
            if let Some(ref dir) = source_datadir {
                eprintln!("  Source datadir: {:?}", dir);
            }
            eprintln!("  Shadow RPC port: {}", rpcport);
            if let Some(ref dir) = datadir {
                eprintln!("  Shadow datadir: {:?}", dir);
            }

            // Convert Option<PathBuf> to Option<&Path> for RPC calls
            let source_dir = source_datadir.as_deref();
            let shadow_dir = datadir.as_deref();

            // Get current shadow chain state
            let shadow_height = match get_block_height_with_datadir(&cli, rpcport, shadow_dir) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("Error getting shadow chain height: {}", e);
                    std::process::exit(1);
                }
            };
            eprintln!("  Shadow chain height: {}", shadow_height);

            // Get shadow chain tip hash
            let shadow_tip_hash = match rpc_call_with_datadir(
                &cli,
                rpcport,
                shadow_dir,
                &["getblockhash", &shadow_height.to_string()],
            ) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("Error getting shadow tip hash: {}", e);
                    std::process::exit(1);
                }
            };

            // Get source chain hash at same height to check for divergence
            let source_hash_at_height = match rpc_call_with_datadir(
                &cli,
                source_rpcport,
                source_dir,
                &["getblockhash", &shadow_height.to_string()],
            ) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("Error getting source block hash at height {}: {}", shadow_height, e);
                    eprintln!("Make sure source node is synced past height {}", shadow_height);
                    std::process::exit(1);
                }
            };

            // Check for divergence
            if shadow_tip_hash != source_hash_at_height {
                eprintln!("\nError: Chain has diverged from canonical chain.");
                eprintln!("  Shadow tip hash: {}", shadow_tip_hash);
                eprintln!("  Source hash:     {}", source_hash_at_height);
                eprintln!("\nCanonical block stepping is disabled once a local block is mined.");
                std::process::exit(1);
            }

            // Calculate target height
            let target_height = match to_height {
                Some(h) => h,
                None => shadow_height + count,
            };

            if target_height <= shadow_height {
                eprintln!("Already at or past target height {}", target_height);
                return;
            }

            eprintln!(
                "  Stepping from {} to {} ({} blocks)",
                shadow_height,
                target_height,
                target_height - shadow_height
            );
            eprintln!();

            // Step through each block
            let mut stepped = 0u64;
            for height in (shadow_height + 1)..=target_height {
                // Get block hash from source
                let block_hash = match rpc_call_with_datadir(
                    &cli,
                    source_rpcport,
                    source_dir,
                    &["getblockhash", &height.to_string()],
                ) {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!("Error getting block hash at height {}: {}", height, e);
                        eprintln!("Source chain may not be synced to height {}", height);
                        break;
                    }
                };

                // Get raw block from source (verbosity=0 for hex)
                let block_hex = match rpc_call_with_datadir(
                    &cli,
                    source_rpcport,
                    source_dir,
                    &["getblock", &block_hash, "0"],
                ) {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!("Error getting block data at height {}: {}", height, e);
                        break;
                    }
                };

                // Submit block to shadow chain
                match rpc_call_with_datadir(&cli, rpcport, shadow_dir, &["submitblock", &block_hex])
                {
                    Ok(result) => {
                        // submitblock returns null on success, or an error string
                        if result.is_empty() || result == "null" {
                            stepped += 1;
                            eprintln!("  Block {} submitted: {}", height, &block_hash[..16]);
                        } else {
                            eprintln!("Error submitting block {}: {}", height, result);
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("Error submitting block {}: {}", height, e);
                        break;
                    }
                }
            }

            eprintln!();
            if stepped > 0 {
                eprintln!("Stepped {} canonical blocks.", stepped);
                let new_height = shadow_height + stepped;
                eprintln!("Shadow chain now at height {}.", new_height);
            } else {
                eprintln!("No blocks stepped.");
            }
        }
    }
}
