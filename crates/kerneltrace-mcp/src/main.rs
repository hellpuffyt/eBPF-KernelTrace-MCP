//! `kerneltrace-mcp`: an MCP server (stdio) exposing kernel telemetry.

#![forbid(unsafe_code)]

mod protocol;
mod server;
mod stdio;
mod tools;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::Parser;
use kerneltrace_core::{Config, Engine, Filter, Mode, Pacing, SyntheticSource, capability, live};

/// Command-line arguments. Flags override the config file.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// TOML config file (see examples/kerneltrace.toml).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Event source: synthetic (default, unprivileged) or live (Linux eBPF).
    #[arg(long, value_parser = ["synthetic", "live"])]
    mode: Option<String>,
    /// Seed for the synthetic source.
    #[arg(long)]
    seed: Option<u64>,
    /// Synthetic events per second (0 = unpaced).
    #[arg(long)]
    rate: Option<u64>,
    /// Also collect openat events.
    #[arg(long)]
    open: bool,
    /// Keep (redacted) file paths. Sensitive.
    #[arg(long)]
    include_paths: bool,
    /// Print host capabilities as JSON and exit.
    #[arg(long)]
    capabilities: bool,
    /// Collect N events, print them as JSON lines and exit (no MCP).
    #[arg(long, value_name = "N")]
    dump: Option<usize>,
}

fn load_config(args: &Args) -> Result<Config> {
    let mut cfg = match &args.config {
        Some(p) => Config::load(p)?,
        None => Config::default(),
    };
    if let Some(m) = &args.mode {
        cfg.mode = if m == "live" {
            Mode::Live
        } else {
            Mode::Synthetic
        };
    }
    if let Some(s) = args.seed {
        cfg.synthetic.seed = s;
    }
    if let Some(r) = args.rate {
        cfg.synthetic.rate_per_sec = r;
    }
    cfg.sources.open |= args.open;
    cfg.sources.include_paths |= args.include_paths;
    cfg.validate()?;
    Ok(cfg)
}

fn start_engine(cfg: &Config) -> Result<Engine> {
    let (source, pacing): (Box<dyn kerneltrace_core::Source>, Pacing) = match cfg.mode {
        Mode::Synthetic => {
            let rate = cfg.synthetic.rate_per_sec;
            // Virtual time advances at the configured rate (1 µs/event when unpaced).
            let step_ns = 1_000_000_000u64.checked_div(rate).unwrap_or(1_000);
            let pacing = if rate == 0 {
                Pacing::Unpaced
            } else {
                Pacing::PerSecond(rate)
            };
            (
                Box::new(SyntheticSource::new(
                    cfg.synthetic.seed,
                    step_ns,
                    cfg.synthetic.malformed_every,
                )),
                pacing,
            )
        }
        Mode::Live => (
            live::open(&cfg.live, &cfg.sources).context("cannot start live mode")?,
            Pacing::Unpaced,
        ),
    };
    Engine::start(cfg, source, pacing).context("cannot start pipeline threads")
}

fn dump(engine: &Engine, n: usize) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    while engine.stats().stored < n {
        if Instant::now() > deadline {
            bail!("timed out waiting for {n} events");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let filter = Filter {
        after_seq: Some(0),
        ..Filter::default()
    };
    for e in engine.query(&filter, n).events {
        println!("{}", serde_json::to_string(&e)?);
    }
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.capabilities {
        println!("{}", serde_json::to_string_pretty(&capability::detect())?);
        return Ok(());
    }
    let cfg = load_config(&args)?;
    let mut engine = start_engine(&cfg)?;
    if let Some(n) = args.dump {
        let res = dump(&engine, n.min(cfg.limits.max_query_limit));
        engine.shutdown();
        return res;
    }
    eprintln!(
        "kerneltrace-mcp {}: serving MCP on stdio (mode={:?}, open={}, include_paths={})",
        env!("CARGO_PKG_VERSION"),
        cfg.mode,
        cfg.sources.open,
        cfg.sources.include_paths
    );
    let mut srv = server::Server::new(&engine, &cfg);
    let reason = stdio::serve(&mut srv)?;
    eprintln!("kerneltrace-mcp: shutting down ({reason})");
    engine.shutdown();
    Ok(())
}
