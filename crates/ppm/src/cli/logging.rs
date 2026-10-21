//! Where the CLI's messages go: a console sink on stderr and, inside a portable root, a rotating
//! file sink under `.ppm/logs/`.
//!
//! # Why stderr for the console
//! `list` and `check` print tables on stdout - that is the command's data and may be piped or
//! redirected. Progress and diagnostics are not data, so they stay out of that stream.

use anyhow::{Context, Result};
use std::fmt;
use std::path::Path;
use tracing::{Event, Level, Subscriber};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

use ppm::core::layout::PortableLayout;

/// Environment variable holding the `tracing` filter for the log file. The injected engine reads
/// the same variable for `redirector.log`, so one setting raises or lowers both files.
const FILE_FILTER_VAR: &str = "PPM_LOG";
const DEFAULT_FILE_FILTER: &str = "info";

// Why: one file per day, a week of history - enough to cover the run before "it broke yesterday"
//      while keeping the portable volume's log directory bounded. Raise it if support requests
//      routinely need older runs.
const RETAINED_LOG_FILES: usize = 7;

/// How much the console shows, chosen by `--quiet` / `--verbose`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConsoleVerbosity {
    Quiet,
    Normal,
    Verbose,
}

impl ConsoleVerbosity {
    fn level(self) -> Level {
        match self {
            ConsoleVerbosity::Quiet => Level::WARN,
            ConsoleVerbosity::Normal => Level::INFO,
            ConsoleVerbosity::Verbose => Level::DEBUG,
        }
    }
}

/// Installs the global subscriber. The returned guard flushes the file sink when dropped, so the
/// caller holds it until the process is about to exit.
///
/// The file sink is attached only when `root` already carries a `.ppm` directory: a command run
/// outside a portable root must not create one as a side effect of logging.
pub(crate) fn init(root: &Path, verbosity: ConsoleVerbosity) -> Result<Option<WorkerGuard>> {
    let console = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .event_format(ConsoleFormat)
        .with_filter(tracing_subscriber::filter::LevelFilter::from_level(
            verbosity.level(),
        ));

    let ppm_dir = PortableLayout::new(root).ppm_dir();
    let (file, guard) = if ppm_dir.is_dir() {
        // Why create it first: the appender prunes old files by listing the directory as it
        // opens, and reports a missing one on stderr itself rather than through an error.
        let logs_dir = ppm_dir.join("logs");
        std::fs::create_dir_all(&logs_dir)
            .with_context(|| format!("Failed to create '{}'", logs_dir.display()))?;
        let appender = RollingFileAppender::builder()
            .rotation(Rotation::DAILY)
            .filename_prefix("ppm")
            .filename_suffix("log")
            .max_log_files(RETAINED_LOG_FILES)
            .build(&logs_dir)
            .context("Failed to open the log file under .ppm/logs")?;
        let (writer, guard) = tracing_appender::non_blocking(appender);
        let layer = tracing_subscriber::fmt::layer()
            .with_writer(writer)
            .with_ansi(false)
            .with_target(false)
            .with_filter(file_filter()?);
        (Some(layer), Some(guard))
    } else {
        (None, None)
    };

    tracing_subscriber::registry()
        .with(console)
        .with(file)
        .try_init()
        .context("Failed to install the logger")?;
    Ok(guard)
}

/// The file sink's filter: `PPM_LOG` when set, the documented default when absent. A value
/// that is set but malformed is an error rather than a silent fallback to the default.
fn file_filter() -> Result<EnvFilter> {
    match std::env::var(FILE_FILTER_VAR) {
        Ok(directive) => EnvFilter::try_new(&directive)
            .with_context(|| format!("{FILE_FILTER_VAR}='{directive}' is not a valid log filter")),
        Err(std::env::VarError::NotPresent) => Ok(EnvFilter::new(DEFAULT_FILE_FILTER)),
        Err(error) => Err(error).with_context(|| format!("{FILE_FILTER_VAR} is not valid Unicode")),
    }
}

/// Console lines read like the CLI's own output: an informational message is printed as is,
/// anything else carries its level.
///
/// # Ex
/// `info!("Found version 1.2")` -> `Found version 1.2`; `warn!("cache kept")` -> `warn: cache kept`
struct ConsoleFormat;

impl<S, N> FormatEvent<S, N> for ConsoleFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let level = *event.metadata().level();
        if level != Level::INFO {
            write!(writer, "{}: ", level.as_str().to_ascii_lowercase())?;
        }
        ctx.field_format().format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}
