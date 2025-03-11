use anyhow::anyhow;
use clap::Arg;

/// Parsed options
pub struct Opts {
  /// Configuration file path
  pub config_file_path: String,
}

/// Parse arg values passed from cli
pub fn parse_opts() -> Result<Opts, anyhow::Error> {
  let _ = include_str!("../../Cargo.toml");
  let options = clap::command!().arg(
    Arg::new("config_file")
      .long("config")
      .short('c')
      .value_name("FILE")
      .required(true)
      .help("Configuration file path like ./config.toml"),
  );
  let matches = options.get_matches();

  ///////////////////////////////////
  let config_file_path = matches
    .get_one::<String>("config_file")
    .ok_or_else(|| anyhow!("config_file is required"))?
    .to_owned();

  Ok(Opts { config_file_path })
}
