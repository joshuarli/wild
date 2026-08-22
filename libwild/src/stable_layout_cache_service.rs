//! Opt-in same-user service for consecutive Mach-O stable-layout cache hits.
//!
//! The disk cache remains the authoritative crash-recovery source. This service only retains one
//! already-validated image between linker processes, and exits shortly after it becomes idle.

use crate::Args;
use crate::stable_layout_cache;
use crate::args::macho::MachOArgs;
use std::env;
use std::fs;
use std::io;
use std::io::Read as _;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;
use std::time::Instant;

const ENABLE_ENV: &str = "WILD_MACHO_INCREMENTAL_CACHE_SERVICE";
const SERVICE_DIRECTORY_ENV: &str = "WILD_MACHO_INCREMENTAL_CACHE_SERVICE_DIR";
const DIAGNOSTICS_ENV: &str = "WILD_MACHO_INCREMENTAL_CACHE_DIAGNOSTICS";
const DAEMON_ARGUMENT: &str = "--wild-macho-cache-service";
const REQUEST_MAGIC: &[u8] = b"WILD-MACHO-CACHE-SERVICE-1\0";
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
const MAX_ARGUMENTS: usize = 100_000;
const STARTUP_RETRIES: usize = 100;
const IDLE_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) fn requested() -> bool {
    env::var_os(ENABLE_ENV).is_some()
}

pub(crate) fn try_apply(
    args: &MachOArgs,
    command_line: &[String],
    version: &str,
) -> Option<bool> {
    let cache_dir = args.incremental_cache.as_deref()?;
    try_apply_for_cache_dir(cache_dir, command_line, version)
}

fn try_apply_for_cache_dir(cache_dir: &Path, command_line: &[String], version: &str) -> Option<bool> {
    let socket = socket_path(cache_dir)?;
    let mut stream = connect_or_start(cache_dir, &socket).ok()?;
    let current_dir = env::current_dir().ok()?;
    write_request(&mut stream, &current_dir, command_line, version).ok()?;
    let mut response = [0_u8; 1];
    stream.read_exact(&mut response).ok()?;
    Some(response[0] == 1)
}

pub fn run(cache_dir: PathBuf) -> crate::error::Result {
    let Some(socket) = socket_path(&cache_dir) else {
        return Ok(());
    };
    let listener = match UnixListener::bind(&socket) {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
            // A concurrently spawned or still-live service owns this cache root. Do not disturb
            // it; clients will connect to that listener instead.
            return Ok(());
        }
        Err(_) => return Ok(()),
    };
    let _cleanup = SocketCleanup(socket);
    let _ = fs::set_permissions(listener_path(&_cleanup.0), fs::Permissions::from_mode(0o600));
    let _ = listener.set_nonblocking(true);
    stable_layout_cache::enable_resident_image_cache();

    let mut last_request = Instant::now();
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let hit = match read_request(&mut stream) {
                    Ok(request) => match apply_request(request) {
                        Ok(hit) => hit,
                        Err(error) => {
                            if env::var_os(DIAGNOSTICS_ENV).is_some() {
                                eprintln!("wild: Mach-O cache service request failed: {error:?}");
                            }
                            false
                        }
                    },
                    Err(_) => false,
                };
                let _ = stream.write_all(&[u8::from(hit)]);
                last_request = Instant::now();
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if last_request.elapsed() >= IDLE_TIMEOUT {
                    return Ok(());
                }
                thread::sleep(Duration::from_millis(20));
            }
            // A peer can disappear immediately after a successful reply. Treat any listener
            // error as transient until the same idle boundary rather than dropping the resident
            // image and leaving a stale pathname for the next linker process.
            Err(_) => {
                if last_request.elapsed() >= IDLE_TIMEOUT {
                    return Ok(());
                }
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

fn socket_path(cache_dir: &Path) -> Option<PathBuf> {
    let service_directory = env::var_os(SERVICE_DIRECTORY_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| cache_dir.to_path_buf());
    fs::create_dir_all(&service_directory).ok()?;
    let cache_key = blake3::hash(cache_dir.as_os_str().as_encoded_bytes()).to_hex();
    let path = service_directory.join(format!("macho-{}.sock", &cache_key[..16]));
    (path.as_os_str().as_encoded_bytes().len() < 100).then_some(path)
}

fn connect_or_start(cache_dir: &Path, socket: &Path) -> io::Result<UnixStream> {
    if let Ok(stream) = UnixStream::connect(socket) {
        return Ok(stream);
    }
    // A previous service can disappear between its last request and socket cleanup. Only remove
    // this exact socket after a failed connection; a live listener was returned above.
    if socket.exists() {
        fs::remove_file(socket)?;
    }
    let executable = env::current_exe()?;
    let mut command = Command::new(executable);
    command
        .arg(DAEMON_ARGUMENT)
        .arg(cache_dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null());
    if env::var_os(DIAGNOSTICS_ENV).is_some() {
        command.stderr(std::process::Stdio::inherit());
    } else {
        command.stderr(std::process::Stdio::null());
    }
    let _ = command.spawn()?;
    for _ in 0..STARTUP_RETRIES {
        if let Ok(stream) = UnixStream::connect(socket) {
            return Ok(stream);
        }
        thread::sleep(Duration::from_millis(10));
    }
    Err(io::Error::new(io::ErrorKind::TimedOut, "cache service did not start"))
}

fn write_request(
    stream: &mut UnixStream,
    current_dir: &Path,
    command_line: &[String],
    version: &str,
) -> io::Result<()> {
    stream.write_all(REQUEST_MAGIC)?;
    write_string(stream, &current_dir.to_string_lossy())?;
    write_string(stream, version)?;
    write_u32(stream, u32::try_from(command_line.len()).map_err(frame_too_large)?)?;
    for argument in command_line {
        write_string(stream, argument)?;
    }
    Ok(())
}

struct Request {
    current_dir: PathBuf,
    version: String,
    command_line: Vec<String>,
}

fn read_request(stream: &mut UnixStream) -> io::Result<Request> {
    let mut magic = vec![0_u8; REQUEST_MAGIC.len()];
    stream.read_exact(&mut magic)?;
    if magic != REQUEST_MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "wrong cache service request"));
    }
    let current_dir = PathBuf::from(read_string(stream)?);
    let version = read_string(stream)?;
    let count = usize::try_from(read_u32(stream)?).map_err(frame_too_large)?;
    if count > MAX_ARGUMENTS {
        return Err(frame_too_large(count));
    }
    let mut command_line = Vec::with_capacity(count);
    for _ in 0..count {
        command_line.push(read_string(stream)?);
    }
    Ok(Request {
        current_dir,
        version,
        command_line,
    })
}

fn apply_request(request: Request) -> crate::error::Result<bool> {
    env::set_current_dir(request.current_dir)?;
    let arguments = || request.command_line.iter().map(String::as_str);
    let mut args = Args::new(arguments)?;
    args.set_version(&request.version);
    args.parse(arguments)?;
    let Args::MachO(args) = args else {
        return Ok(false);
    };
    Ok(stable_layout_cache::try_apply(&args))
}

fn write_u32(stream: &mut UnixStream, value: u32) -> io::Result<()> {
    stream.write_all(&value.to_le_bytes())
}

fn read_u32(stream: &mut UnixStream) -> io::Result<u32> {
    let mut bytes = [0_u8; size_of::<u32>()];
    stream.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn write_string(stream: &mut UnixStream, value: &str) -> io::Result<()> {
    let bytes = value.as_bytes();
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(frame_too_large(bytes.len()));
    }
    write_u32(stream, u32::try_from(bytes.len()).map_err(frame_too_large)?)?;
    stream.write_all(bytes)
}

fn read_string(stream: &mut UnixStream) -> io::Result<String> {
    let length = usize::try_from(read_u32(stream)?).map_err(frame_too_large)?;
    if length > MAX_FRAME_BYTES {
        return Err(frame_too_large(length));
    }
    let mut bytes = vec![0_u8; length];
    stream.read_exact(&mut bytes)?;
    String::from_utf8(bytes).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 request"))
}

fn frame_too_large<T: std::fmt::Display>(value: T) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("cache service frame is too large: {value}"))
}

struct SocketCleanup(PathBuf);

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn listener_path(path: &Path) -> &Path {
    path
}
