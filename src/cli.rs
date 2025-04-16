use std::path::PathBuf;

use clap::{ArgAction, Parser};

#[derive(veil::Redact, Parser)]
#[command(version)]
pub struct Cli {
    #[arg(short, long, env = "UCS_IP")]
    pub ip: String,

    #[arg(short, long, env = "UCS_USERNAME")]
    pub username: String,

    #[redact]
    #[arg(short, long, env = "UCS_PASSWORD")]
    pub password: String,

    /// path to OpenWebStart's javaws executable (or some other javaws, but YMMV)
    #[arg(short, long, env = "JAVAWS_PATH")]
    pub javaws: PathBuf,

    /// extra arguments to be passed to javaws
    #[arg(long, num_args(1..), allow_hyphen_values = true)]
    pub javaws_args: Vec<String>,

    /// enable certificate validation (disabled by default)
    #[arg(long = "do-cert-validation", default_value_t = true, action = ArgAction::SetFalse)]
    pub ignore_cert_validation: bool,

    /// use https (will be http by default)
    #[arg(long, default_value_t = false, action = ArgAction::SetTrue)]
    pub use_https: bool,

    /// skip patching the jvm version in the downloaded jnlp file
    #[arg(long, default_value_t = false, action = ArgAction::SetTrue)]
    pub no_patch_jnlp_version: bool,

    #[arg(long, default_value_t = String::from("1.8*"), value_name("VERSION"))]
    pub patch_jnlp_version_to: String,
}

impl Cli {
    pub fn protocol_string(&self) -> &'static str {
        if self.use_https { "https" } else { "http" }
    }
}
