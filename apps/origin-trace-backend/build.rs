//! Compiles the vendored Triskel graph layout engine and its C ABI bridge
//! (`cpp/triskel_bridge.cpp`) into one static library. Only the contained
//! `--graph-layout-worker` process calls it; see `src/graph_layout.rs`.
use std::path::{Path, PathBuf};

const COMPILER_HINT: &str = "Triskel needs a C++23 compiler and standard library with \
std::ranges::to and std::ranges::contains: GCC 14 or later, Clang 18 or later, or a current \
Apple Clang. Point the cc crate at one with CXX or CXX_<target>, for example \
CXX_x86_64_unknown_linux_gnu=g++-14 on Ubuntu 24.04.";

fn main() {
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let triskel = manifest.join("vendor/triskel/lib");
    let fmt = manifest.join("vendor/fmt/include");
    let bridge = manifest.join("cpp/triskel_bridge.cpp");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=cpp");
    println!("cargo:rerun-if-changed=vendor");

    let mut sources = Vec::new();
    collect(&triskel.join("src"), &mut sources);
    sources.sort();
    assert!(
        !sources.is_empty(),
        "vendor/triskel/lib/src holds no C++ sources; see vendor/README.md"
    );

    let mut base = cc::Build::new();
    base.cpp(true)
        .std("c++23")
        // Layout time matters even in debug builds, and Triskel's asserts are
        // not a safety boundary: the worker process is.
        .opt_level(2)
        .debug(false)
        .define("NDEBUG", None)
        .define("FMT_HEADER_ONLY", None);
    // Upstream warnings are not ours to fix in an unmodified copy.
    let mut vendored = base.clone();
    vendored
        .include(triskel.join("include"))
        .include(&fmt)
        .warnings(false)
        .cargo_warnings(false);
    let mut own = base.clone();
    own.flag("-isystem")
        .flag(triskel.join("include"))
        .flag("-isystem")
        .flag(&fmt)
        .warnings(true)
        .extra_warnings(true)
        .warnings_into_errors(true);

    // One thread per translation unit: Triskel is about 30 s of serial -O2
    // compilation, and this avoids a jobserver dependency for 17 files.
    let threads = std::env::var("NUM_JOBS")
        .ok()
        .and_then(|jobs| jobs.parse::<usize>().ok())
        .unwrap_or(4)
        .max(1);
    let mut jobs = sources
        .iter()
        .map(|source| (&vendored, source.as_path()))
        .collect::<Vec<_>>();
    jobs.push((&own, bridge.as_path()));
    let mut objects = Vec::new();
    for chunk in jobs.chunks(threads) {
        let compiled = std::thread::scope(|scope| {
            chunk
                .iter()
                .map(|(build, source)| {
                    scope.spawn(move || {
                        let mut build = (*build).clone();
                        build.file(source).try_compile_intermediates()
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|handle| handle.join().expect("compiler thread"))
                .collect::<Vec<_>>()
        });
        for (result, (_, source)) in compiled.into_iter().zip(chunk) {
            match result {
                Ok(mut files) => objects.append(&mut files),
                Err(error) => fail(source, &error),
            }
        }
    }
    let library = base
        .try_create_archive("reb_triskel", &objects)
        .unwrap_or_else(|error| fail(&bridge, &error));
    cc::try_emit_link_directives(&base, &library).unwrap_or_else(|error| fail(&bridge, &error));
}

fn collect(directory: &Path, sources: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("{}: {error}", directory.display()));
    for entry in entries {
        let path = entry.expect("vendored source entry").path();
        if path.is_dir() {
            collect(&path, sources);
        } else if path.extension().is_some_and(|extension| extension == "cpp") {
            sources.push(path);
        }
    }
}

fn fail(source: &Path, error: &cc::Error) -> ! {
    panic!(
        "Could not compile the graph layout engine ({}): {error}\n{COMPILER_HINT}",
        source.display()
    )
}
