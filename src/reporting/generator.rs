use crate::{Result, IronJailError};
use crate::reporting::analysis::{AnalysisResult, SessionInfo};
use serde_json;
use handlebars::{Handlebars, Template};
use std::path::{Path, PathBuf};
use std::fs;
use std::collections::HashMap;
use tracing::{debug, info, error};
use chrono::{DateTime, Utc};

/// Report generator for creating JSON and HTML reports
pub struct ReportGenerator {
    /// Handlebars template engine
    handlebars: Handlebars<'static>,
    
    /// Output directory for reports
    output_dir: PathBuf,
    
    /// Template directory
    template_dir: Option<PathBuf>,
}

/// Report format options
#[derive(Debug, Clone, serde::Serialize)]
pub enum ReportFormat {
    Json,
    Html,
    Both,
}

/// Report configuration
#[derive(Debug, Clone, serde::Serialize)]
pub struct ReportConfig {
    /// Output format
    pub format: ReportFormat,
    
    /// Include timeline visualization
    pub include_timeline: bool,
    
    /// Include detailed syscall traces
    pub include_syscall_details: bool,
    
    /// Include file activity details
    pub include_file_details: bool,
    
    /// Include network activity details
    pub include_network_details: bool,
    
    /// Include threat assessment
    pub include_threat_assessment: bool,
    
    /// Include statistics charts
    pub include_charts: bool,
    
    /// Custom template path
    pub custom_template: Option<PathBuf>,
    
    /// Output filename (without extension)
    pub output_filename: Option<String>,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            format: ReportFormat::Both,
            include_timeline: true,
            include_syscall_details: true,
            include_file_details: true,
            include_network_details: true,
            include_threat_assessment: true,
            include_charts: true,
            custom_template: None,
            output_filename: None,
        }
    }
}

impl ReportGenerator {
    /// Create a new report generator
    pub fn new(output_dir: &Path) -> Result<Self> {
        let mut handlebars = Handlebars::new();
        
        // Register built-in templates
        handlebars.register_template_string("main_report", MAIN_REPORT_TEMPLATE)?;
        handlebars.register_template_string("timeline", TIMELINE_TEMPLATE)?;
        handlebars.register_template_string("syscall_table", SYSCALL_TABLE_TEMPLATE)?;
        handlebars.register_template_string("file_table", FILE_TABLE_TEMPLATE)?;
        handlebars.register_template_string("network_table", NETWORK_TABLE_TEMPLATE)?;
        handlebars.register_template_string("threat_assessment", THREAT_ASSESSMENT_TEMPLATE)?;
        handlebars.register_template_string("statistics", STATISTICS_TEMPLATE)?;
        
        // Register helper functions
        handlebars.register_helper("format_timestamp", Box::new(format_timestamp_helper));
        handlebars.register_helper("format_duration", Box::new(format_duration_helper));
        handlebars.register_helper("format_bytes", Box::new(format_bytes_helper));
        handlebars.register_helper("threat_level_color", Box::new(threat_level_color_helper));
        handlebars.register_helper("severity_badge", Box::new(severity_badge_helper));
        
        // Create output directory if it doesn't exist
        fs::create_dir_all(output_dir)?;
        
        Ok(Self {
            handlebars,
            output_dir: output_dir.to_path_buf(),
            template_dir: None,
        })
    }
    
    /// Set custom template directory
    pub fn set_template_dir(&mut self, template_dir: &Path) -> Result<()> {
        if template_dir.exists() && template_dir.is_dir() {
            self.template_dir = Some(template_dir.to_path_buf());
            
            // Load custom templates if they exist
            for entry in fs::read_dir(template_dir)? {
                let entry = entry?;
                let path = entry.path();
                
                if path.extension().map_or(false, |ext| ext == "hbs") {
                    let template_name = path.file_stem()
                        .and_then(|s| s.to_str())
                        .ok_or_else(|| IronJailError::Configuration("Invalid template filename".to_string()))?;
                    
                    let template_content = fs::read_to_string(&path)?;
                    self.handlebars.register_template_string(template_name, template_content)?;
                    
                    info!("Loaded custom template: {}", template_name);
                }
            }
        }
        
        Ok(())
    }
    
    /// Generate a report from analysis results
    pub async fn generate_report(&self, analysis: &AnalysisResult, config: &ReportConfig) -> Result<Vec<PathBuf>> {
        let mut generated_files = Vec::new();
        
        // Determine output filename
        let base_filename = config.output_filename
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or(&analysis.session_id);
        
        // Generate JSON report
        if matches!(config.format, ReportFormat::Json | ReportFormat::Both) {
            let json_file = self.generate_json_report(analysis, base_filename).await?;
            generated_files.push(json_file);
        }
        
        // Generate HTML report
        if matches!(config.format, ReportFormat::Html | ReportFormat::Both) {
            let html_file = self.generate_html_report(analysis, config, base_filename).await?;
            generated_files.push(html_file);
        }
        
        info!("Generated {} report files", generated_files.len());
        Ok(generated_files)
    }
    
    /// Generate JSON report
    async fn generate_json_report(&self, analysis: &AnalysisResult, filename: &str) -> Result<PathBuf> {
        let json_content = serde_json::to_string_pretty(analysis)?;
        let json_path = self.output_dir.join(format!("{}.json", filename));
        
        tokio::fs::write(&json_path, json_content).await?;
        
        info!("Generated JSON report: {}", json_path.display());
        Ok(json_path)
    }
    
    /// Generate HTML report
    async fn generate_html_report(&self, analysis: &AnalysisResult, config: &ReportConfig, filename: &str) -> Result<PathBuf> {
        // Prepare template data
        let mut template_data = serde_json::Map::new();
        template_data.insert("analysis".to_string(), serde_json::to_value(analysis)?);
        template_data.insert("config".to_string(), serde_json::to_value(config)?);
        template_data.insert("generated_at".to_string(), serde_json::to_value(&Utc::now())?);
        
        // Generate timeline data if requested
        let timeline_data = if config.include_timeline {
            Some(self.generate_timeline_data(analysis))
        } else {
            None
        };
        
        if let Some(timeline) = &timeline_data {
            template_data.insert("timeline".to_string(), serde_json::to_value(timeline)?);
        }
        
        // Generate statistics data if requested
        let statistics_data = if config.include_charts {
            Some(self.generate_statistics_data(analysis))
        } else {
            None
        };
        
        if let Some(stats) = &statistics_data {
            template_data.insert("statistics_charts".to_string(), serde_json::to_value(stats)?);
        }
        
        // Choose template
        let template_name = if let Some(custom_template) = &config.custom_template {
            custom_template.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("main_report")
        } else {
            "main_report"
        };
        
        // Render template
        let html_content = self.handlebars.render(template_name, &template_data)?;
        let html_path = self.output_dir.join(format!("{}.html", filename));
        
        tokio::fs::write(&html_path, html_content).await?;
        
        info!("Generated HTML report: {}", html_path.display());
        Ok(html_path)
    }
    
    /// Generate timeline data for visualization
    fn generate_timeline_data(&self, analysis: &AnalysisResult) -> Vec<TimelineEvent> {
        let mut events = Vec::new();
        
        // Add syscall events
        for syscall in &analysis.syscalls {
            events.push(TimelineEvent {
                timestamp: syscall.timestamp,
                event_type: "syscall".to_string(),
                title: syscall.syscall_name.clone(),
                description: format!("PID: {}, Args: {:?}", syscall.pid, syscall.arguments),
                category: "system".to_string(),
                severity: 1,
            });
        }
        
        // Add file activity events
        for activity in &analysis.file_activities {
            events.push(TimelineEvent {
                timestamp: activity.timestamp,
                event_type: "file".to_string(),
                title: format!("{:?}", activity.activity_type),
                description: format!("Path: {}", activity.path.display()),
                category: "filesystem".to_string(),
                severity: 2,
            });
        }
        
        // Add network activity events
        for activity in &analysis.network_activities {
            events.push(TimelineEvent {
                timestamp: activity.timestamp,
                event_type: "network".to_string(),
                title: format!("{:?}", activity.activity_type),
                description: format!("Destination: {}", activity.destination),
                category: "network".to_string(),
                severity: 3,
            });
        }
        
        // Sort events by timestamp
        events.sort_by_key(|e| e.timestamp);
        
        events
    }
    
    /// Generate statistics data for charts
    fn generate_statistics_data(&self, analysis: &AnalysisResult) -> StatisticsChartData {
        StatisticsChartData {
            syscall_chart: self.create_chart_data(&analysis.statistics.syscalls_by_name),
            file_activity_chart: self.create_chart_data(&analysis.statistics.file_activities_by_type),
            network_activity_chart: self.create_chart_data(&analysis.statistics.network_activities_by_type),
            timeline_chart: self.create_timeline_chart_data(analysis),
        }
    }
    
    /// Create chart data from a HashMap
    fn create_chart_data(&self, data: &HashMap<String, u64>) -> ChartData {
        let mut labels = Vec::new();
        let mut values = Vec::new();
        
        for (label, value) in data {
            labels.push(label.clone());
            values.push(*value);
        }
        
        ChartData { labels, values }
    }
    
    /// Create timeline chart data
    fn create_timeline_chart_data(&self, analysis: &AnalysisResult) -> TimelineChartData {
        // Group events by time intervals (e.g., per second)
        let mut timeline_buckets: HashMap<i64, TimelineBucket> = HashMap::new();
        
        // Process syscalls
        for syscall in &analysis.syscalls {
            let timestamp = syscall.timestamp.timestamp();
            let bucket = timeline_buckets.entry(timestamp).or_insert_with(|| TimelineBucket::new(timestamp));
            bucket.syscalls += 1;
        }
        
        // Process file activities
        for activity in &analysis.file_activities {
            let timestamp = activity.timestamp.timestamp();
            let bucket = timeline_buckets.entry(timestamp).or_insert_with(|| TimelineBucket::new(timestamp));
            bucket.file_activities += 1;
        }
        
        // Process network activities
        for activity in &analysis.network_activities {
            let timestamp = activity.timestamp.timestamp();
            let bucket = timeline_buckets.entry(timestamp).or_insert_with(|| TimelineBucket::new(timestamp));
            bucket.network_activities += 1;
        }
        
        let mut buckets: Vec<TimelineBucket> = timeline_buckets.into_values().collect();
        buckets.sort_by_key(|b| b.timestamp);
        
        TimelineChartData { buckets }
    }
    
    /// List available sessions
    pub async fn list_sessions(&self) -> Result<Vec<SessionInfo>> {
        let mut sessions = Vec::new();
        
        let mut entries = tokio::fs::read_dir(&self.output_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            
            if path.extension().map_or(false, |ext| ext == "json") {
                if let Ok(content) = tokio::fs::read_to_string(&path).await {
                    if let Ok(analysis) = serde_json::from_str::<AnalysisResult>(&content) {
                        sessions.push(SessionInfo {
                            name: analysis.session_id.clone(),
                            binary: analysis.binary.display().to_string(),
                            timestamp: analysis.start_timestamp,
                            duration: analysis.duration,
                            status: analysis.status,
                            threat_level: analysis.threat_assessment.threat_level,
                        });
                    }
                }
            }
        }
        
        // Sort by timestamp (newest first)
        sessions.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        
        Ok(sessions)
    }
    
    /// Load a specific analysis result
    pub async fn load_analysis(&self, session_id: &str) -> Result<AnalysisResult> {
        let json_path = self.output_dir.join(format!("{}.json", session_id));
        
        if !json_path.exists() {
            return Err(IronJailError::NotFound(format!("Session '{}' not found", session_id)).into());
        }
        
        let content = tokio::fs::read_to_string(&json_path).await?;
        let analysis = serde_json::from_str::<AnalysisResult>(&content)?;
        
        Ok(analysis)
    }
    
    /// Clean old reports
    pub async fn cleanup_old_reports(&self, max_age_days: u64) -> Result<u64> {
        let cutoff_time = Utc::now() - chrono::Duration::days(max_age_days as i64);
        let mut deleted_count = 0;
        
        let mut entries = tokio::fs::read_dir(&self.output_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let metadata = entry.metadata().await?;
            
            if let Ok(modified) = metadata.modified() {
                let modified_datetime: DateTime<Utc> = modified.into();
                
                if modified_datetime < cutoff_time {
                    tokio::fs::remove_file(&path).await?;
                    deleted_count += 1;
                    debug!("Deleted old report: {}", path.display());
                }
            }
        }
        
        info!("Cleaned up {} old report files", deleted_count);
        Ok(deleted_count)
    }
}

/// Timeline event for visualization
#[derive(Debug, Clone, serde::Serialize)]
struct TimelineEvent {
    timestamp: DateTime<Utc>,
    event_type: String,
    title: String,
    description: String,
    category: String,
    severity: u8,
}

/// Chart data structure
#[derive(Debug, Clone, serde::Serialize)]
struct ChartData {
    labels: Vec<String>,
    values: Vec<u64>,
}

/// Timeline chart data
#[derive(Debug, Clone, serde::Serialize)]
struct TimelineChartData {
    buckets: Vec<TimelineBucket>,
}

/// Timeline bucket for grouping events
#[derive(Debug, Clone, serde::Serialize)]
struct TimelineBucket {
    timestamp: i64,
    syscalls: u64,
    file_activities: u64,
    network_activities: u64,
}

impl TimelineBucket {
    fn new(timestamp: i64) -> Self {
        Self {
            timestamp,
            syscalls: 0,
            file_activities: 0,
            network_activities: 0,
        }
    }
}

/// Statistics chart data
#[derive(Debug, Clone, serde::Serialize)]
struct StatisticsChartData {
    syscall_chart: ChartData,
    file_activity_chart: ChartData,
    network_activity_chart: ChartData,
    timeline_chart: TimelineChartData,
}

// Handlebars helper functions
fn format_timestamp_helper(
    h: &handlebars::Helper,
    _: &handlebars::Handlebars,
    _: &handlebars::Context,
    _: &mut handlebars::RenderContext,
    out: &mut dyn handlebars::Output,
) -> handlebars::HelperResult {
    if let Some(param) = h.param(0) {
        if let Some(datetime_str) = param.value().as_str() {
            if let Ok(datetime) = DateTime::parse_from_rfc3339(datetime_str) {
                out.write(&datetime.format("%Y-%m-%d %H:%M:%S UTC").to_string())?;
            }
        }
    }
    Ok(())
}

fn format_duration_helper(
    h: &handlebars::Helper,
    _: &handlebars::Handlebars,
    _: &handlebars::Context,
    _: &mut handlebars::RenderContext,
    out: &mut dyn handlebars::Output,
) -> handlebars::HelperResult {
    if let Some(param) = h.param(0) {
        if let Some(seconds) = param.value().as_u64() {
            let hours = seconds / 3600;
            let minutes = (seconds % 3600) / 60;
            let secs = seconds % 60;
            
            if hours > 0 {
                out.write(&format!("{}h {}m {}s", hours, minutes, secs))?;
            } else if minutes > 0 {
                out.write(&format!("{}m {}s", minutes, secs))?;
            } else {
                out.write(&format!("{}s", secs))?;
            }
        }
    }
    Ok(())
}

fn format_bytes_helper(
    h: &handlebars::Helper,
    _: &handlebars::Handlebars,
    _: &handlebars::Context,
    _: &mut handlebars::RenderContext,
    out: &mut dyn handlebars::Output,
) -> handlebars::HelperResult {
    if let Some(param) = h.param(0) {
        if let Some(bytes) = param.value().as_u64() {
            let formatted = if bytes < 1024 {
                format!("{} B", bytes)
            } else if bytes < 1024 * 1024 {
                format!("{:.1} KB", bytes as f64 / 1024.0)
            } else if bytes < 1024 * 1024 * 1024 {
                format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
            } else {
                format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
            };
            out.write(&formatted)?;
        }
    }
    Ok(())
}

fn threat_level_color_helper(
    h: &handlebars::Helper,
    _: &handlebars::Handlebars,
    _: &handlebars::Context,
    _: &mut handlebars::RenderContext,
    out: &mut dyn handlebars::Output,
) -> handlebars::HelperResult {
    if let Some(param) = h.param(0) {
        if let Some(level) = param.value().as_u64() {
            let color = match level {
                0..=2 => "success",
                3..=5 => "warning",
                6..=8 => "danger",
                9..=10 => "dark",
                _ => "secondary",
            };
            out.write(color)?;
        }
    }
    Ok(())
}

fn severity_badge_helper(
    h: &handlebars::Helper,
    _: &handlebars::Handlebars,
    _: &handlebars::Context,
    _: &mut handlebars::RenderContext,
    out: &mut dyn handlebars::Output,
) -> handlebars::HelperResult {
    if let Some(param) = h.param(0) {
        if let Some(severity) = param.value().as_u64() {
            let (color, text) = match severity {
                1 => ("info", "Low"),
                2 => ("primary", "Medium"),
                3 => ("warning", "High"),
                4 => ("danger", "Critical"),
                5 => ("dark", "Severe"),
                _ => ("secondary", "Unknown"),
            };
            out.write(&format!("<span class=\"badge bg-{}\">{}</span>", color, text))?;
        }
    }
    Ok(())
}

// Built-in HTML templates
const MAIN_REPORT_TEMPLATE: &str = include_str!("templates/main_report.hbs");
const TIMELINE_TEMPLATE: &str = include_str!("templates/timeline.hbs");
const SYSCALL_TABLE_TEMPLATE: &str = include_str!("templates/syscall_table.hbs");
const FILE_TABLE_TEMPLATE: &str = include_str!("templates/file_table.hbs");
const NETWORK_TABLE_TEMPLATE: &str = include_str!("templates/network_table.hbs");
const THREAT_ASSESSMENT_TEMPLATE: &str = include_str!("templates/threat_assessment.hbs");
const STATISTICS_TEMPLATE: &str = include_str!("templates/statistics.hbs");