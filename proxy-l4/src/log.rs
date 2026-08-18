#![allow(unused)]
pub use tracing::{debug, error, info, warn};

use crate::{ACCESS_LOG_FILE, SYSTEM_LOG_FILE};
use rpxy_l4_lib::log_event_names;
use std::str::FromStr;
use tracing_subscriber::{fmt, prelude::*};

pub fn init_logger(log_dir_path: Option<&str>) -> std::io::Result<()> {
  let level_string = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
  let level = tracing::Level::from_str(level_string.as_str()).unwrap_or(tracing::Level::INFO);

  match log_dir_path {
    None => {
      // log to stdout
      init_stdio_logger(level);
      Ok(())
    }
    Some(log_dir_path) => {
      // log to files
      println!("Activate logging to files: {log_dir_path}");
      init_file_logger(level, log_dir_path)
    }
  }
}

/// stdio logging
fn init_stdio_logger(level: tracing::Level) {
  // This limits the logger to emits only this crate with any level above RUST_LOG, for included crates it will emit only ERROR (in prod)/INFO (in dev) or above level.
  let stdio_layer = fmt::layer().with_level(true).with_thread_ids(false);
  if level <= tracing::Level::INFO {
    // in normal deployment environment
    let stdio_layer = stdio_layer
      .with_target(false)
      .compact()
      .with_filter(tracing_subscriber::filter::filter_fn(move |metadata| {
        (metadata
          .target()
          .starts_with(env!("CARGO_PKG_NAME").replace('-', "_").as_str())
          && metadata.level() <= &level)
          || metadata.level() <= &tracing::Level::WARN.min(level)
      }));
    tracing_subscriber::registry().with(stdio_layer).init();
  } else {
    // debugging
    let stdio_layer = stdio_layer
      .with_line_number(true)
      .with_target(true)
      .with_thread_names(true)
      .with_target(true)
      .compact()
      .with_filter(tracing_subscriber::filter::filter_fn(move |metadata| {
        (metadata
          .target()
          .starts_with(env!("CARGO_PKG_NAME").replace('-', "_").as_str())
          && metadata.level() <= &level)
          || metadata.level() <= &tracing::Level::INFO.min(level)
      }));
    tracing_subscriber::registry().with(stdio_layer).init();
  };
}

/// file logging
fn init_file_logger(level: tracing::Level, log_dir_path: &str) -> std::io::Result<()> {
  let log_dir_path = std::path::PathBuf::from(log_dir_path);
  // create the directory if it does not exist
  if !log_dir_path.exists() {
    println!("Directory does not exist, creating: {}", log_dir_path.display());
    std::fs::create_dir_all(&log_dir_path)?;
  }
  let access_log_path = log_dir_path.join(ACCESS_LOG_FILE);
  let system_log_path = log_dir_path.join(SYSTEM_LOG_FILE);
  println!("Access log: {}", access_log_path.display());
  println!("System and error log: {}", system_log_path.display());

  let access_log = open_log_file(&access_log_path)?;
  let system_log = open_log_file(&system_log_path)?;

  let reg = tracing_subscriber::registry();

  let access_log_base = fmt::layer()
    .with_line_number(false)
    .with_thread_ids(false)
    .with_thread_names(false)
    .with_target(false)
    .with_level(false)
    .compact()
    .with_ansi(false);
  let reg = reg.with(access_log_base.with_writer(access_log).with_filter(AccessLogFilter));

  let system_log_base = fmt::layer()
    .with_line_number(false)
    .with_thread_ids(false)
    .with_thread_names(false)
    .with_target(false)
    .with_level(true) // with level for system log
    .compact()
    .with_ansi(false);
  let reg = reg.with(
    system_log_base
      .with_writer(system_log)
      .with_filter(tracing_subscriber::filter::filter_fn(move |metadata| {
        (metadata
          .target()
          .starts_with(env!("CARGO_PKG_NAME").replace('-', "_").as_str())
          && metadata.name() != log_event_names::ACCESS_LOG_START
          && metadata.name() != log_event_names::ACCESS_LOG_FINISH
          && metadata.level() <= &level)
          || metadata.level() <= &tracing::Level::WARN.min(level)
      })),
  );

  reg.init();
  Ok(())
}

/// Access log filter
struct AccessLogFilter;
impl<S> tracing_subscriber::layer::Filter<S> for AccessLogFilter {
  fn enabled(&self, metadata: &tracing::Metadata<'_>, _: &tracing_subscriber::layer::Context<'_, S>) -> bool {
    metadata
      .target()
      .starts_with(env!("CARGO_PKG_NAME").replace('-', "_").as_str())
      && (metadata.name().contains(log_event_names::ACCESS_LOG_START)
        || metadata.name().contains(log_event_names::ACCESS_LOG_FINISH))
      && metadata.level() <= &tracing::Level::INFO
  }
}

#[inline]
/// Create a file for logging
fn open_log_file<P>(path: P) -> std::io::Result<std::fs::File>
where
  P: AsRef<std::path::Path>,
{
  // crate a file if it does not exist
  std::fs::OpenOptions::new().create(true).append(true).open(path)
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::sync::atomic::{AtomicU64, Ordering};

  fn unique_test_path(label: &str) -> std::path::PathBuf {
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
      "rpxy-l4-{label}-{}-{}",
      std::process::id(),
      NEXT_ID.fetch_add(1, Ordering::Relaxed)
    ))
  }

  #[test]
  fn test_init_file_logger_returns_directory_creation_error() {
    let blocking_file = unique_test_path("log-parent-file");
    std::fs::write(&blocking_file, b"not a directory").expect("failed to create blocking test file");
    let log_dir = blocking_file.join("logs");

    let result = init_file_logger(tracing::Level::INFO, log_dir.to_str().expect("test path must be valid UTF-8"));
    std::fs::remove_file(&blocking_file).expect("failed to remove blocking test file");

    assert!(result.is_err());
  }

  #[test]
  fn test_init_file_logger_returns_log_file_open_error() {
    let log_dir = unique_test_path("log-file-directory");
    std::fs::create_dir(&log_dir).expect("failed to create test log directory");
    std::fs::create_dir(log_dir.join(ACCESS_LOG_FILE)).expect("failed to create blocking access-log directory");

    let result = init_file_logger(tracing::Level::INFO, log_dir.to_str().expect("test path must be valid UTF-8"));
    std::fs::remove_dir_all(&log_dir).expect("failed to remove test log directory");

    assert!(result.is_err());
  }
}
