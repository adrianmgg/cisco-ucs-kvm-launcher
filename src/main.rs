use std::process::Stdio;

use clap::Parser;
use eyre::{ContextCompat, Result};
use reqwest::Url;
use tap::Pipe as _;
use tokio::io::AsyncBufReadExt;

mod cisco_imc;
mod cli;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::new().default_filter_or("info")).init();
    color_eyre::install()?;

    let args = cli::Cli::parse();

    let cimc_ip_url = Url::parse(&format!("{}://{}/", args.protocol_string(), args.ip))?;

    let mut client = cisco_imc::Client::new(
        cisco_imc::Credentials {
            username: args.username,
            password: args.password,
        },
        args.ignore_cert_validation,
        cimc_ip_url,
        args.ip.clone(),
    )?;

    let kvm_ws_tmpfile = tempfile::Builder::new()
        .prefix("cisco-kvm")
        .suffix(".jnlp")
        .tempfile()?;

    {
        let ws_text = client.get_kvm_webstart_content().await?;
        log::info!(
            "patching jnlp file (will be written to {})",
            kvm_ws_tmpfile.path().to_string_lossy()
        );
        let mut reader = quick_xml::Reader::from_str(&ws_text);
        let mut writer = quick_xml::Writer::new(std::io::Cursor::new(Vec::new()));
        use quick_xml::events::Event;
        loop {
            match reader.read_event() {
                Ok(ref event @ (Event::Empty(ref e) | Event::Start(ref e)))
                    if !args.no_patch_jnlp_version && e.name().as_ref() == b"j2se" =>
                {
                    let mut e_patched = e.clone();
                    e_patched.clear_attributes();
                    e_patched.extend_attributes(
                        e.attributes()
                            .map(|attr| attr.unwrap())
                            .filter(|attr| attr.key.as_ref() != b"version"),
                    );
                    e_patched.push_attribute(("version", args.patch_jnlp_version_to.as_ref()));
                    writer.write_event(match event {
                        Event::Empty(_) => Event::Empty(e_patched),
                        Event::Start(_) => Event::Start(e_patched),
                        _ => unreachable!(),
                    })?;
                }
                Ok(Event::Eof) => break,
                Err(err) => Err(err)?,
                Ok(e) => writer.write_event(e.borrow())?,
            }
        }
        let patched = writer.into_inner().into_inner();
        std::fs::write(kvm_ws_tmpfile.path(), patched)?;
    }

    let mut command = tokio::process::Command::new(args.javaws);
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .args(args.javaws_args)
        .arg(kvm_ws_tmpfile.path());

    let mut child = command.spawn()?;
    let mut stdout = child
        .stdout
        .take()
        .wrap_err("failed to get handle to child process stdout")?
        .pipe(|s| tokio::io::BufReader::new(s).lines());
    let mut stderr = child
        .stderr
        .take()
        .wrap_err("failed to get handle to child process stderr")?
        .pipe(|s| tokio::io::BufReader::new(s).lines());

    tokio::spawn(async move {
        _ = child.wait().await;
    });
    loop {
        let (stdout_line, stderr_line) = tokio::select! {
            line = stdout.next_line() => {
                if let Some(line) = line? { (Some(line), None) } else { break }
            }
            line = stderr.next_line() => {
                if let Some(line) = line? { (None, Some(line)) } else { break }
            }
        };
        if let Some(stdout_line) = stdout_line {
            log::debug!("javaws out: {}", stdout_line);
        }
        if let Some(stderr_line) = stderr_line {
            log::debug!("javaws err: {}", stderr_line);
        }
    }

    client.logout().await?;

    Ok(())
}
