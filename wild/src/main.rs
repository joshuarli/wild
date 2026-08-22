#[cfg(feature = "mimalloc")]
#[global_allocator]
static MIMALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature = "dhat")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn main() {
    if let Err(error) = run() {
        libwild::error::report_error_and_exit(&error)
    }
}

/// The current Wild version as written by build.rs.
const VERSION: &str = include_str!(concat!(env!("OUT_DIR"), "/version.txt"));

fn run() -> libwild::error::Result {
    #[cfg(feature = "dhat")]
    let _profiler = dhat::Profiler::new_heap();

    let command_line = std::env::args().collect::<Vec<_>>();
    #[cfg(target_os = "macos")]
    if command_line.get(1).is_some_and(|argument| argument == "--wild-macho-cache-service") {
        let cache_dir = command_line
            .get(2)
            .map(std::path::PathBuf::from)
            .ok_or_else(|| libwild::error::Error::with_message("cache service requires a cache directory"))?;
        return libwild::stable_layout_cache_service::run(cache_dir);
    }

    libwild::init_timing()?;

    let arguments = || command_line.iter().map(String::as_str);
    let mut args = libwild::Args::new(arguments)?;
    args.set_version(VERSION);
    args.parse(arguments)?;

    if libwild::should_preflight_macho_stable_layout_cache(&args)
        && libwild::try_apply_macho_stable_layout_cache_preflight(&args, &command_line, VERSION)
    {
        return Ok(());
    }

    if libwild::should_fork(&args) {
        // Safety: We haven't spawned any threads yet.
        unsafe { libwild::run_in_subprocess(args) };
    } else {
        // Run the linker in this process without forking.

        // Note, we need to setup tracing before worker, otherwise the threads won't contribute to
        // counters such as --time=cycles,instructions etc.
        libwild::setup_tracing(&args)?;

        libwild::run(args)
    }
}
