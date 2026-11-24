//! Compiles the vendored Triskel graph layout engine and its C ABI bridge
//! (`cpp/triskel_bridge.cpp`) into one static library. Only the contained
//! `--graph-layout-worker` process calls it; see `src/graph_layout.rs`.
use std::path::{Path, PathBuf};

const COMPILER_HINT: &str = "Triskel needs a C++23 compiler and standard library with \
std::ranges::to and std::ranges::contains: GCC 14 or later, Clang 18 or later, or a current \
Apple Clang. Point the cc crate at one with CXX or CXX_<target>, for example \
CXX_x86_64_unknown_linux_gnu=g++-14 on Ubuntu 24.04.";

/// A fix to one upstream Triskel source. The engine is compiled from a copy
/// in `OUT_DIR` with each edit applied, so the vendored file stays the
/// upstream copy that `vendor/README.md` verifies.
struct Fix {
    /// The source, under `vendor/triskel/lib/src`.
    file: &'static str,
    edits: &'static [Edit],
}

struct Edit {
    /// Text that occurs exactly once in the source.
    upstream: &'static str,
    fixed: &'static str,
}

const FIXES: &[Fix] = &[
    // `SugiyamaAnalysis::coordinate_assignment_iteration` places a layer's
    // nodes and edge waypoints in priority order, and the bounds it places
    // them in (`min_x`, `max_x`) keep them apart only when entries of equal
    // priority are placed left to right, as `min_x` says. `std::ranges::sort`
    // does not keep that order: libc++ can reorder equal entries in a range
    // of 24 or more, libstdc++ in one of more than 16. An entry placed before
    // its left neighbour is bounded by where that neighbour was in the
    // previous pass; the neighbour then moves without regard to it, and nodes
    // overlap or an edge runs through a node. A stable sort keeps the order
    // the bounds assume.
    Fix {
        file: "layout/sugiyama/sugiyama.cpp",
        edits: &[Edit {
            upstream: "    std::ranges::sort(sorted_indexes, [&](size_t a, size_t b) {",
            fixed: "    std::ranges::stable_sort(sorted_indexes, [&](size_t a, size_t b) {",
        }],
    },
    // `SpanningTree::init_rank` ranks, in each pass, every node whose
    // parents are all ranked. Without cycles every node is ranked within one
    // pass per node, so a pass past the node count means cycle removal missed
    // a loop, and the loop would never end (the SESE defect in
    // `vendor/README.md`). It throws there instead, and the graph fails at
    // once rather than holding its worker until someone stops it.
    Fix {
        file: "layout/sugiyama/network_simplex.cpp",
        edits: &[
            Edit {
                upstream: "#include <deque>\n",
                fixed: "#include <deque>\n#include <stdexcept>\n",
            },
            Edit {
                upstream: "        while (found_nodes < nodes.size()) {\n",
                fixed: "        while (found_nodes < nodes.size()) {\n            if (rank > nodes.size()) {\n                throw std::runtime_error(\n                    \"its layer assignment met a loop its cycle removal \"\n                    \"missed, and would never end\");\n            }\n",
            },
        ],
    },
];

fn main() {
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("out dir"));
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
    for fix in FIXES {
        let source = triskel.join("src").join(fix.file);
        let at = sources
            .iter()
            .position(|path| *path == source)
            .unwrap_or_else(|| {
                panic!("{} is not vendored; see vendor/README.md", source.display())
            });
        sources[at] = fixed(&source, fix, &out);
    }

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

/// Writes `source` with `fix` applied under `out` and returns its path. A new
/// upstream revision without an edit's text stops the build, so the fix is
/// either carried over or dropped on purpose.
fn fixed(source: &Path, fix: &Fix, out: &Path) -> PathBuf {
    let mut text = std::fs::read_to_string(source)
        .unwrap_or_else(|error| panic!("{}: {error}", source.display()));
    for edit in fix.edits {
        assert_eq!(
            text.matches(edit.upstream).count(),
            1,
            "{} no longer holds the text build.rs fixes once; see vendor/README.md",
            source.display()
        );
        text = text.replacen(edit.upstream, edit.fixed, 1);
    }
    let copy = out.join("triskel-fixed").join(fix.file);
    std::fs::create_dir_all(copy.parent().expect("a file has a directory"))
        .unwrap_or_else(|error| panic!("{}: {error}", copy.display()));
    std::fs::write(&copy, text).unwrap_or_else(|error| panic!("{}: {error}", copy.display()));
    copy
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
