use anyhow::anyhow;
use clap::Arg;

/// Parsed options
pub struct Opts {
  /// Configuration file path
  pub config_file_path: String,
  pub log_dir_path: Option<String>,
}

/// Parse arg values passed from cli
pub fn parse_opts() -> Result<Opts, anyhow::Error> {
  let _ = include_str!("../../Cargo.toml");
  let options = clap::command!()
    .arg(
      Arg::new("config_file")
        .long("config")
        .short('c')
        .value_name("FILE")
        .required(true)
        .help("Configuration file path like ./config.toml"),
    )
    .arg(
      Arg::new("log_dir")
        .long("log-dir")
        .short('l')
        .value_name("LOG_DIR")
        .help("Directory for log files. If not specified, logs are printed to stdout."),
    );
  let matches = options.get_matches();

  ///////////////////////////////////
  let config_file_path = matches
    .get_one::<String>("config_file")
    .ok_or_else(|| anyhow!("config_file is required"))?
    .to_owned();
  let log_dir_path = matches.get_one::<String>("log_dir").map(|v| v.to_owned());

  Ok(Opts {
    config_file_path,
    log_dir_path,
  })
}
