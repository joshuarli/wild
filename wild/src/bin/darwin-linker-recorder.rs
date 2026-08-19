//! A transparent Darwin linker wrapper for recording the rustc-to-linker ABI.
//!
//! Cargo/rustc invoke this executable in place of the normal compiler driver. The wrapper records
//! the exact argument bytes and the Darwin-relevant environment, then delegates unchanged to the
//! configured working driver. It is intentionally separate from Wild so a successful capture is
//! never mistaken for a successful Wild link.

use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitCode;

const RECORD_DIRECTORY_ENV: &str = "WILD_DARWIN_LINKER_RECORD_DIR";
const DELEGATE_ENV: &str = "WILD_DARWIN_LINKER_DELEGATE";

const RECORDED_ENVIRONMENT: &[&str] = &[
    "MACOSX_DEPLOYMENT_TARGET",
    "SDKROOT",
    "DEVELOPER_DIR",
    "RUSTC",
    "RUSTFLAGS",
    "CARGO_MANIFEST_DIR",
    "CARGO_PKG_NAME",
    "CARGO_CRATE_NAME",
    "CARGO_CFG_TARGET_ARCH",
    "CARGO_CFG_TARGET_OS",
    "TARGET",
    "HOST",
    "CC",
    "CXX",
    "CFLAGS",
    "CXXFLAGS",
    "LDFLAGS",
];

fn main() -> ExitCode {
    match run() {
        Ok(status) => ExitCode::from(status),
        Err(error) => {
            eprintln!("darwin-linker-recorder: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<u8, Box<dyn Error>> {
    let config = RecorderConfig::from_environment()?;
    let args: Vec<_> = env::args_os().skip(1).collect();
    let record_dir = create_record_dir(&config.output_directory)?;
    write_invocation(&record_dir, &config, &args)?;

    let status = Command::new(&config.delegate)
        .args(&args)
        .status()
        .map_err(|error| {
            format!(
                "failed to execute delegate `{}`: {error}",
                config.delegate.display()
            )
        })?;

    let status_text = match status.code() {
        Some(code) => format!("exit_code={code}\n"),
        None => "exit_code=signal\n".to_owned(),
    };
    fs::write(record_dir.join("delegate-status.txt"), status_text)?;

    Ok(status.code().and_then(|code| u8::try_from(code).ok()).unwrap_or(1))
}

#[derive(Debug)]
struct RecorderConfig {
    output_directory: PathBuf,
    delegate: PathBuf,
}

impl RecorderConfig {
    fn from_environment() -> Result<Self, Box<dyn Error>> {
        let output_directory = env::var_os(RECORD_DIRECTORY_ENV).ok_or_else(|| {
            format!("{RECORD_DIRECTORY_ENV} must name a directory for invocation records")
        })?;
        let delegate = env::var_os(DELEGATE_ENV).ok_or_else(|| {
            format!("{DELEGATE_ENV} must name the working Apple compiler driver to delegate to")
        })?;

        Ok(Self {
            output_directory: PathBuf::from(output_directory),
            delegate: PathBuf::from(delegate),
        })
    }
}

fn create_record_dir(base: &Path) -> io::Result<PathBuf> {
    fs::create_dir_all(base)?;
    let process_id = std::process::id();
    for sequence in 0..u32::MAX {
        let candidate = base.join(format!("link-{process_id}-{sequence}"));
        match fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::other("exhausted Darwin linker recorder directory names"))
}

fn write_invocation(record_dir: &Path, config: &RecorderConfig, args: &[std::ffi::OsString]) -> io::Result<()> {
    let cwd = env::current_dir()?;
    fs::write(record_dir.join("argv.nul"), nul_delimited(args))?;

    let mut metadata = String::new();
    metadata.push_str("delegate=");
    metadata.push_str(&escape_for_text(&config.delegate));
    metadata.push_str("\ncwd=");
    metadata.push_str(&escape_for_text(&cwd));
    metadata.push('\n');
    fs::write(record_dir.join("metadata.txt"), metadata)?;

    let environment = selected_environment();
    let mut environment_text = String::new();
    for (name, value) in environment {
        environment_text.push_str(name);
        environment_text.push('=');
        environment_text.push_str(&escape_for_text(value));
        environment_text.push('\n');
    }
    fs::write(record_dir.join("environment.txt"), environment_text)?;

    fs::write(record_dir.join("inputs.txt"), classify_arguments(args))?;
    Ok(())
}

fn nul_delimited(args: &[std::ffi::OsString]) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;

        let mut bytes = Vec::new();
        for arg in args {
            bytes.extend_from_slice(arg.as_os_str().as_bytes());
            bytes.push(0);
        }
        bytes
    }

    #[cfg(not(unix))]
    {
        let mut bytes = Vec::new();
        for arg in args {
            bytes.extend_from_slice(arg.to_string_lossy().as_bytes());
            bytes.push(0);
        }
        bytes
    }
}

fn selected_environment() -> BTreeMap<&'static str, std::ffi::OsString> {
    RECORDED_ENVIRONMENT
        .iter()
        .filter_map(|name| env::var_os(name).map(|value| (*name, value)))
        .collect()
}

fn classify_arguments(args: &[std::ffi::OsString]) -> String {
    let mut lines = String::new();
    let mut previous_was_framework = false;
    for arg in args {
        let value = arg.to_string_lossy();
        let kind = if previous_was_framework {
            previous_was_framework = false;
            "framework-name"
        } else if value == "-framework" {
            previous_was_framework = true;
            "framework-option"
        } else {
            classify_argument(&value)
        };
        lines.push_str(kind);
        lines.push('\t');
        lines.push_str(&escape_for_text(arg));
        lines.push('\n');
    }
    lines
}

fn classify_argument(arg: &str) -> &'static str {
    if arg.ends_with(".o") {
        "object"
    } else if arg.ends_with(".a") {
        "archive"
    } else if arg.ends_with(".dylib") {
        "dylib"
    } else if arg.ends_with(".tbd") {
        "tbd"
    } else if arg.ends_with(".framework") || arg.contains(".framework/") {
        "framework-path"
    } else if arg.starts_with("-F") {
        "framework-search-path"
    } else if arg.starts_with("-L") {
        "library-search-path"
    } else if arg == "-dynamiclib" || arg == "-dylib" {
        "output-kind"
    } else if arg == "-o" {
        "output-option"
    } else {
        "argument"
    }
}

fn escape_for_text(value: impl AsRef<OsStr>) -> String {
    value
        .as_ref()
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_darwin_linker_inputs_and_options() {
        assert_eq!(classify_argument("foo.o"), "object");
        assert_eq!(classify_argument("libfoo.a"), "archive");
        assert_eq!(classify_argument("/sdk/usr/lib/libSystem.tbd"), "tbd");
        assert_eq!(classify_argument("/sdk/System.framework/Security"), "framework-path");
        assert_eq!(classify_argument("-F/frameworks"), "framework-search-path");
        assert_eq!(classify_argument("-dylib"), "output-kind");
    }

    #[test]
    fn escapes_metadata_without_losing_line_boundaries() {
        assert_eq!(escape_for_text("a\\b\nc\td"), "a\\\\b\\nc\\td");
    }

    #[test]
    fn writes_exact_nul_delimited_argument_boundaries() {
        let args = ["-Ldir", "two words", "input.o"];
        let args = args.map(std::ffi::OsString::from);
        assert_eq!(nul_delimited(&args), b"-Ldir\0two words\0input.o\0");
    }
}
