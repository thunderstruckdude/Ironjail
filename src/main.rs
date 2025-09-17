use clap::{Parser, Subcommand};
use ironjail::{
    core::{SandboxEngine, SandboxConfig},
    policy::PolicyManager,
    reporting::ReportGenerator,
    Result,
};
use std::path::PathBuf;
use tracing::{info, error, Level};
use tracing_subscriber::{FmtSubscriber, EnvFilter};

#[derive(Parser)]
#[command(name = "ironjail")]
#[command(about = "Advanced Malware Analysis Sandbox")]
#[command(version = "1.0.0")]
#[command(author = "Security Research Team")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    /// Verbose output
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
    
    /// Configuration file path
    #[arg(short, long, default_value = "config/default.yaml")]
    config: PathBuf,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a binary in the sandbox
    Run {
        /// Path to the binary to execute
        binary: PathBuf,
        
        /// Arguments to pass to the binary
        #[arg(last = true)]
        args: Vec<String>,
        
        /// Working directory for the sandboxed process
        #[arg(short, long)]
        workdir: Option<PathBuf>,
        
        /// Policy file to use
        #[arg(short, long)]
        policy: Option<PathBuf>,
        
        /// Output directory for reports
        #[arg(short, long, default_value = "reports")]
        output: PathBuf,
        
        /// Session name for this analysis run
        #[arg(short, long)]
        session: Option<String>,
        
        /// Enable network capture
        #[arg(long)]
        capture_network: bool,
        
        /// Enable environment deception
        #[arg(long)]
        enable_deception: bool,
        
        /// Timeout in seconds
        #[arg(short, long, default_value = "300")]
        timeout: u64,
    },
    
    /// Validate a policy configuration
    Validate {
        /// Policy file to validate
        policy: PathBuf,
    },
    
    /// Generate a sample policy file
    GeneratePolicy {
        /// Output path for the policy file
        #[arg(short, long, default_value = "sample-policy.yaml")]
        output: PathBuf,
        
        /// Policy template type
        #[arg(short, long, default_value = "default")]
        template: String,
    },
    
    /// Generate reports from previous runs
    Report {
        /// Session ID or name to generate report for
        session: String,
        
        /// Output format (json, html)
        #[arg(short, long, default_value = "html")]
        format: String,
        
        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    
    /// List available sessions
    List {
        /// Show detailed information
        #[arg(short, long)]
        detailed: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Setup logging based on verbosity level
    let log_level = match cli.verbose {
        0 => Level::INFO,
        1 => Level::DEBUG,
        _ => Level::TRACE,
    };
    
    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_env_filter(EnvFilter::from_default_env())
        .finish();
    
    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set tracing subscriber");
    
    info!("IronJail v{} starting", env!("CARGO_PKG_VERSION"));
    
    // Check if running as root (required for many sandbox operations)
    if !nix::unistd::geteuid().is_root() {
        error!("IronJail requires root privileges for full functionality");
        eprintln!("Warning: Some sandbox features may not work without root privileges");
    }
    
    match cli.command {
        Commands::Run {
            binary,
            args,
            workdir,
            policy,
            output,
            session,
            capture_network,
            enable_deception,
            timeout,
        } => {
            run_analysis(
                &cli.config,
                binary,
                args,
                workdir,
                policy,
                output,
                session,
                capture_network,
                enable_deception,
                timeout,
            ).await?;
        }
        
        Commands::Validate { policy } => {
            validate_policy(policy).await?;
        }
        
        Commands::GeneratePolicy { output, template } => {
            generate_policy(output, template).await?;
        }
        
        Commands::Report { session, format, output } => {
            generate_report(session, format, output).await?;
        }
        
        Commands::List { detailed } => {
            list_sessions(detailed).await?;
        }
    }
    
    Ok(())
}

async fn run_analysis(
    config_path: &PathBuf,
    binary: PathBuf,
    args: Vec<String>,
    workdir: Option<PathBuf>,
    policy: Option<PathBuf>,
    output: PathBuf,
    session: Option<String>,
    capture_network: bool,
    enable_deception: bool,
    timeout: u64,
) -> Result<()> {
    info!("Starting malware analysis for: {:?}", binary);
    
    // Load configuration
    let config = SandboxConfig::load(config_path)?;
    
    // Load policy if specified
    let policy_manager = if let Some(policy_path) = policy {
        PolicyManager::from_file(&policy_path)?
    } else {
        PolicyManager::default()
    };
    
    // Create sandbox engine
    let mut sandbox = SandboxEngine::new(config)?;
    
    // Configure sandbox options
    sandbox.set_capture_network(capture_network);
    sandbox.set_enable_deception(enable_deception);
    sandbox.set_timeout(timeout);
    
    if let Some(wd) = workdir {
        sandbox.set_working_directory(wd);
    }
    
    // Generate session ID
    let session_id = session.unwrap_or_else(|| {
        format!("session_{}", chrono::Utc::now().format("%Y%m%d_%H%M%S"))
    });
    
    info!("Session ID: {}", session_id);
    
    // Run the analysis
    let analysis_result = sandbox.execute_with_monitoring(
        &binary,
        &args,
        &policy_manager,
        &session_id,
    ).await?;
    
    // Generate report
    let report_generator = ReportGenerator::new(&output)?;
    report_generator.generate_comprehensive_report(&analysis_result, &session_id).await?;
    
    info!("Analysis completed. Reports saved to: {:?}", output);
    println!("Session ID: {}", session_id);
    println!("Reports location: {:?}", output);
    
    Ok(())
}

async fn validate_policy(policy_path: PathBuf) -> Result<()> {
    info!("Validating policy: {:?}", policy_path);
    
    let policy_manager = PolicyManager::from_file(&policy_path)?;
    policy_manager.validate()?;
    
    println!("✅ Policy validation successful");
    Ok(())
}

async fn generate_policy(output_path: PathBuf, template: String) -> Result<()> {
    info!("Generating policy template: {} -> {:?}", template, output_path);
    
    PolicyManager::generate_template(&template, &output_path)?;
    
    println!("✅ Policy template generated: {:?}", output_path);
    Ok(())
}

async fn generate_report(session: String, format: String, output: Option<PathBuf>) -> Result<()> {
    info!("Generating report for session: {} (format: {})", session, format);
    
    let report_generator = ReportGenerator::new(&PathBuf::from("reports"))?;
    
    match format.as_str() {
        "json" => {
            let output_path = output.unwrap_or_else(|| PathBuf::from(format!("{}_report.json", session)));
            report_generator.generate_json_report(&session, &output_path).await?;
        }
        "html" => {
            let output_path = output.unwrap_or_else(|| PathBuf::from(format!("{}_report.html", session)));
            report_generator.generate_html_report(&session, &output_path).await?;
        }
        _ => {
            error!("Unsupported report format: {}", format);
            return Err(anyhow::anyhow!("Unsupported report format: {}", format));
        }
    }
    
    println!("✅ Report generated successfully");
    Ok(())
}

async fn list_sessions(detailed: bool) -> Result<()> {
    info!("Listing analysis sessions");
    
    let report_generator = ReportGenerator::new(&PathBuf::from("reports"))?;
    let sessions = report_generator.list_sessions().await?;
    
    if sessions.is_empty() {
        println!("No analysis sessions found");
        return Ok(());
    }
    
    println!("Available sessions:");
    for session in sessions {
        if detailed {
            println!("  📊 {} ({})", session.name, session.timestamp);
            println!("     Binary: {}", session.binary);
            println!("     Duration: {}s", session.duration);
            println!("     Status: {}", session.status);
            println!();
        } else {
            println!("  📊 {} ({})", session.name, session.timestamp);
        }
    }
    
    Ok(())
}
