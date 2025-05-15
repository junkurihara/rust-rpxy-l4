#![allow(unused)]
pub use tracing::{debug, error, info, warn};

use std::str::FromStr;
use tracing_subscriber::{fmt, prelude::*};

pub fn init_logger(log_dir_path: Option<&str>) {
  let level_string = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
  let level = tracing::Level::from_str(level_string.as_str()).unwrap_or(tracing::Level::INFO);

  let passed_pkg_names = [env!("CARGO_PKG_NAME").replace('-', "_")];

  // This limits the logger to emits only this crate with any level, for included crates it will emit only INFO or above level.
  let stdio_layer = fmt::layer()
    .with_line_number(true)
    .with_thread_ids(false)
    .with_thread_names(true)
    .with_target(true)
    .with_level(true)
    .compact()
    .with_filter(tracing_subscriber::filter::filter_fn(move |metadata| {
      (passed_pkg_names
        .iter()
        .any(|pkg_name| metadata.target().starts_with(pkg_name))
        && metadata.level() <= &level)
        || metadata.level() <= &tracing::Level::INFO.min(level)
    }));

  let reg = tracing_subscriber::registry().with(stdio_layer);
  reg.init();
}
