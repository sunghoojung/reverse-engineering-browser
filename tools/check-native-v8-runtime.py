#!/usr/bin/env python3
"""Build the pinned native V8 runtime tests, not a Brave/browser acceptance run.

This independent system-Clang profile does not fetch Chromium's binary
toolchains. Authored C++ patches are unchanged. Brave-specific GN wiring is
omitted; modernized upstream lifetime-attribute spellings are receipt-recorded.
"""

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
DEPOT_REV = "94e89b10b92cc9d6e58fc8d1b6474b7d29e8a114"
PUBLIC_TEST = "test-run-wasm/RebNativePublicQuickJSGuestState"
TEST_NAMES = [
    "RebNativeBrTableRuntimeDispatch",
    "RebNativeBrTableAdmissionPredicate",
    "RebNativeBrTablePreservesLiveValues",
    "RebNativeBrTableDisabledCompilation",
    "RebNativeBrTableDirectCaller",
    "RebNativeBrTableLeftLiftoff",
    "RebNativeBrTableFlagOffTurbofanHasNoScopeGap",
    "RebNativeBrTableJitlessUnsupported",
    "RebNativeBrTableJitlessFlagOffHasNoScopeGap",
    "RebNativeCallIndirectRuntimeDispatch",
    "RebNativeCallIndirectAdmissionPredicate",
    "RebNativeCallIndirectNullAndOutOfBounds",
    "RebNativeCallIndirectReturnCall",
    "RebNativeCallIndirectPreservesLiveValues",
    "RebNativeCallIndirectDisabledCompilation",
    "RebNativeCallIndirectLeftLiftoff",
    "RebNativeBrTablePhysicalOnlyHasNoGuestMetadata",
    "RebNativeGuestLargeLocalIndexAndMemory",
    "RebNativeGuestHelperImportAndExceptionScope",
    "RebNativeGuestAdmissionPolicyReplacement",
    "RebNativeGuestRejectedModuleIsNotReadmitted",
    "RebNativeGuestPhysicalObserverClearsCallback",
    "RebNativeGuestPhysicalObserverDisablesReplacement",
    "RebNativeGuestPhysicalObserverReplacesPolicy",
    "RebNativeGuestSelectedAncestorAndDropBarrier",
    "RebNativeGuestDepthAndCounterExhaustionFailClosed",
    "RebNativeGuestDistinctInstances",
    "RebNativeGuestWeakIdentityLifetime",
    "RebNativeGuestDescriptorBudgetRejectsOverflow",
    "RebNativeGuestZeroLocalDescriptorBudget",
    "RebNativeGuestNestedActivationExactParent",
    "RebNativeGuestParentUnresolvedFailsClosed",
    "RebNativeGuestParentBarrierCoversEveryDispatcher",
    "RebNativeGuestParentWalkNeedsEnabledCapture",
    "test-api/RebNativeJsDispatchDisabledAndUnarmedBytecodeIdentity",
    "test-api/RebNativeJsDispatchSelectorKinds",
    "test-api/RebNativeJsDispatchIndexedCallHandlerSpan",
    "test-api/RebNativeJsDispatchEvalAndFunction",
    "test-api/RebNativeCompiledScriptEvalNeedsNoCodeGenerationPolicy",
    "test-api/RebNativeCompiledScriptFunctionConstructor",
    "test-api/RebNativeCompiledScriptNestedEvalChains",
    "test-api/RebNativeCompiledScriptEvalCacheHitKeepsScriptId",
    "test-api/RebNativeCompiledScriptKeepsOriginOffsets",
    "test-api/RebNativeCompiledScriptModule",
    "test-api/RebNativeCompiledScriptWrappedFunction",
    "test-api/RebNativeCompiledScriptCodeCacheConsumer",
    "test-api/RebNativeCompiledScriptStreaming",
    "test-api/RebNativeCompiledScriptDisabledRunsNothing",
    "test-api/RebNativePromiseRegistrations",
    "test-api/RebNativePromiseRegistrationsNeedTheFlag",
    "test-api/RebNativeJsDispatchLateArmingAndLazyFunctions",
    "test-api/RebNativeJsDispatchFlushRegenerationAndRearm",
    "test-api/RebNativeJsDispatchRefusesCodeCache",
    "test-api/RebNativeJsDispatchSparkplugAndNoOptimization",
    "test-api/RebNativeJsDispatchParentActivation",
    "test-api/RebNativeJsDispatchAdmissionAndSiteCap",
    "test-api/RebNativeJsInvocationDisabledAndUnarmedBytecodeIdentity",
    "test-api/RebNativeJsInvocationArgumentsAndSynchronousSettlement",
    "test-api/RebNativeJsInvocationPromiseJobsAndDigest",
    "test-api/RebNativeJsInvocationInterleavedAsyncCallsKeepTheirIds",
    "test-api/RebNativeJsInvocationPreservesEmbedderData",
    "test-api/RebNativeJsInvocationLeavesUnhandledRejectionVisible",
    "test-api/RebNativeJsInvocationAdmissionAndUnsupportedKinds",
]


def cctest_name(name):
    """Bare names are Wasm runner tests; others already name their cctest file."""
    return name if "/" in name else "test-run-wasm/" + name


def split_patch(text):
    """Return all C++ hunks and standalone-compatible GN hunks without fuzz."""
    source, build, omitted = [], [], []
    for part in re.split(r"(?=^diff --git )", text, flags=re.M):
        if not part.strip():
            continue
        if not part.startswith("diff --git a/BUILD.gn b/BUILD.gn\n"):
            source.append(part)
            continue
        prefix, *hunks = re.split(r"(?=^@@ )", part, flags=re.M)
        retained = []
        for hunk in hunks:
            if "brave/" in hunk or "brave_" in hunk:
                changed = [line for line in hunk.splitlines() if line[:1] in ("+", "-")]
                if any("include/v8-" in line for line in changed):
                    raise ValueError("Mixed production header and Brave-only hunk needs review")
                omitted.append(hashlib.sha256(hunk.encode()).hexdigest())
            else:
                retained.append(hunk)
        if retained:
            build.append(prefix + "".join(retained))
    return "".join(source), "".join(build), omitted


def binary_dependencies(deps):
    """Read literal dependency kinds without executing the DEPS file."""
    for statement in ast.parse(deps).body:
        if not isinstance(statement, ast.Assign) or not any(
            isinstance(target, ast.Name) and target.id == "deps" for target in statement.targets
        ):
            continue
        if not isinstance(statement.value, ast.Dict):
            raise ValueError("Unsupported DEPS shape")
        excluded = {}
        for key, value in zip(statement.value.keys, statement.value.values):
            if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                raise ValueError("Nonliteral dependency path")
            if not isinstance(value, ast.Dict):
                continue
            for field, kind in zip(value.keys, value.values):
                if isinstance(field, ast.Constant) and field.value == "dep_type":
                    if isinstance(kind, ast.Constant) and kind.value in ("gcs", "cipd"):
                        excluded["v8/" + key.value] = None
        return excluded
    raise ValueError("Missing DEPS dictionary")


ABSEIL_CAPTURE_COUNTS = {
    "status/statusor.h": 1,
    "synchronization/mutex.h": 8,
    "base/internal/spinlock.h": 1,
    "container/internal/raw_hash_map.h": 8,
    "container/internal/raw_hash_set.h": 4,
    "container/internal/btree_container.h": 5,
}


def modernize_abseil_capture(source, expected):
    # Preserve lifetime analysis: Clang23 replaced the deprecated spelling for
    # captures by this with a dedicated attribute, not an absent annotation.
    pattern = r"ABSL_INTERNAL_ATTRIBUTE_CAPTURED_BY\((?:\s|\\\n)*this\s*\)"
    result, count = re.subn(pattern, "[[clang::lifetime_capture_by_this]]", source)
    if count != expected:
        raise ValueError("Pinned Abseil lifetime annotations changed; review required")
    return result


def create_clang_toolchain_view(destination, system_base, resource_dir, builtins):
    """Expose the real distro archive at Chromium's expected x64 runtime path."""
    if not builtins.is_file() or not (resource_dir / "include").is_dir():
        raise ValueError("Missing real Clang runtime archive or resource headers")
    if builtins.read_bytes()[:8] != b"!<arch>\n":
        raise ValueError("Compiler-reported builtins must be a real archive")
    destination.mkdir()
    (destination / "bin").symlink_to(system_base / "bin", target_is_directory=True)
    resource_view = destination / "lib/clang/23"
    runtime_view = resource_view / "lib/x86_64-unknown-linux-gnu"
    runtime_view.mkdir(parents=True)
    (resource_view / "include").symlink_to(resource_dir / "include", target_is_directory=True)
    (runtime_view / "libclang_rt.builtins.a").symlink_to(builtins)
    return destination


def self_test():
    patches = sorted((ROOT / "browser/integration/brave/patches/v8").glob("*.patch"))
    assert patches
    for patch in patches:
        original = patch.read_text()
        source, build, omitted = split_patch(original)
        original_source = "".join(
            part for part in re.split(r"(?=^diff --git )", original, flags=re.M)
            if part.strip() and not part.startswith("diff --git a/BUILD.gn b/BUILD.gn\n")
        )
        assert source == original_source, patch
        assert "brave/" not in build and "brave_" not in build, patch
        assert len(omitted) <= 8, patch
    assert cctest_name("RebNativeBrTableRuntimeDispatch") == "test-run-wasm/RebNativeBrTableRuntimeDispatch"
    assert cctest_name("test-api/RebNativeJsDispatchSelectorKinds") == "test-api/RebNativeJsDispatchSelectorKinds"
    assert len({cctest_name(name) for name in TEST_NAMES}) == len(TEST_NAMES)
    assert all(re.fullmatch(r"(?:[a-z0-9-]+/)?Reb[A-Za-z0-9]+", name) for name in TEST_NAMES)
    v8_patches = ROOT / "browser/integration/brave/patches/v8"
    chromium_patches = ROOT / "browser/integration/brave/patches/chromium"
    scope_patch = (v8_patches / "0014-report-wasm-dispatch-scope-gaps.patch").read_text()
    for name in (
        "RebNativeBrTableLeftLiftoff",
        "RebNativeBrTableFlagOffTurbofanHasNoScopeGap",
        "RebNativeBrTableJitlessUnsupported",
        "RebNativeBrTableJitlessFlagOffHasNoScopeGap",
    ):
        assert f"TEST({name})" in scope_patch, name
        assert name in TEST_NAMES
    attribute = (v8_patches / "0012-attribute-wasm-br-table-direct-caller.patch").read_text()
    assert "TEST(RebNativeBrTableDirectCaller)" in attribute
    assert "RebNativeBrTableDirectCaller" in TEST_NAMES
    assert not (v8_patches / "0012-report-wasm-dispatch-scope-gaps.patch").exists()
    assert not (chromium_patches / "0022-report-wasm-dispatch-scope-gaps.patch").exists()
    v8_names = [patch.name for patch in patches]
    assert v8_names.index("0013-record-wasm-execution-outcomes.patch") < v8_names.index(
        "0014-report-wasm-dispatch-scope-gaps.patch")
    chromium_names = sorted(patch.name for patch in chromium_patches.glob("*.patch"))
    assert chromium_names.index("0023-record-wasm-execution-outcomes.patch") < chromium_names.index(
        "0024-report-wasm-dispatch-scope-gaps.patch")
    chromium_scope = (chromium_patches / "0024-report-wasm-dispatch-scope-gaps.patch").read_text()
    assert "CaptureWasmExecutionTrap" in chromium_scope
    assert "SetWasmDispatchScopeCallback" in chromium_scope
    assert "IsWorkletGlobalScope" in (
        chromium_patches / "0017-observe-native-wasm-dispatch.patch"
    ).read_text()
    assert (chromium_patches / "0024-report-wasm-dispatch-scope-gaps.patch").is_file()
    assert "WasmDirectCaller" in (
        chromium_patches / "0022-attribute-wasm-br-table-direct-caller.patch"
    ).read_text()
    assert binary_dependencies("deps={'tool':{'dep_type':'gcs'},'src':'git','gn':{'dep_type':'cipd'}}") == {
        "v8/tool": None, "v8/gn": None,
    }
    original = "ABSL_INTERNAL_ATTRIBUTE_CAPTURED_BY(this)"
    assert modernize_abseil_capture(original, 1) == "[[clang::lifetime_capture_by_this]]"
    multiline = "ABSL_INTERNAL_ATTRIBUTE_CAPTURED_BY(" + "\\" + "\n this)"
    assert modernize_abseil_capture(multiline, 1) == "[[clang::lifetime_capture_by_this]]"
    other_owner = "ABSL_INTERNAL_ATTRIBUTE_CAPTURED_BY(owner)"
    assert modernize_abseil_capture(other_owner, 0) == other_owner
    try:
        modernize_abseil_capture(original, 2)
    except ValueError:
        pass
    else:
        raise AssertionError("Changed Abseil annotations must fail closed")
    with tempfile.TemporaryDirectory() as directory:
        # Resolve once: macOS temp directories live behind a /var symlink.
        root = Path(directory).resolve()
        system = root / "system"
        (system / "bin").mkdir(parents=True)
        resource = root / "resource"
        (resource / "include").mkdir(parents=True)
        builtins = root / "libclang_rt.builtins-x86_64.a"
        builtins.write_bytes(b"!<arch>\n")
        view = create_clang_toolchain_view(root / "view", system, resource, builtins)
        linked = view / "lib/clang/23/lib/x86_64-unknown-linux-gnu/libclang_rt.builtins.a"
        assert linked.resolve() == builtins and linked.read_bytes() == builtins.read_bytes()
        assert (view / "bin").resolve() == system / "bin"
        builtins.write_text("not an archive")
        try:
            create_clang_toolchain_view(root / "invalid", system, resource, builtins)
        except ValueError:
            pass
        else:
            raise AssertionError("Invalid builtins must fail closed")
    check_claim(claim_work_directory, WORK_MARKER, ("running", "failed"), "passed")
    check_gn_cache()
    print("PASS standalone adapter preserves every production C++ hunk and excludes only embedder GN wiring")


# Written inside a work directory this tool creates, so a rerun can tell its
# own interrupted or failed attempt from a checkout it must never reset.
WORK_MARKER = ".reb-native-v8-work.json"


def write_json(path, value):
    """Replace a status record only with complete bytes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, prefix=f".{path.name}.", delete=False) as target:
        temporary = Path(target.name)
        target.write(json.dumps(value, indent=2) + "\n")
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def claim_work_directory(work):
    """Create the work directory, or replace only one this tool left unfinished."""
    marker = work / WORK_MARKER
    if work.is_symlink():
        raise ValueError("The work directory must not be a symlink")
    if work.exists() and any(work.iterdir()):
        status = None
        if marker.is_file() and not marker.is_symlink():
            try:
                status = json.loads(marker.read_text()).get("status")
            except (ValueError, AttributeError):
                status = None
        if status not in ("running", "failed"):
            raise ValueError("Use a fresh work directory; existing checkouts are never reset")
        print(f"Removing the unfinished work directory an earlier attempt left in {work}", flush=True)
        shutil.rmtree(work)
    work.mkdir(parents=True, exist_ok=True)
    write_json(marker, {"status": "running"})


# GN is built from the exact revision V8's DEPS pins, so one built binary
# serves every later run with the same V8 pin and compiler. The record names
# both and the binary's digest; anything else is rebuilt, never trusted.
GN_CACHE_RECORD = "gn-binary.json"


def cached_gn(cache_dir, gn_revision, compiler):
    """Return the cached GN for this revision and compiler, or None."""
    binary = cache_dir / gn_revision / "gn"
    record = binary.parent / GN_CACHE_RECORD
    if binary.is_symlink() or record.is_symlink() or not binary.is_file() or not record.is_file():
        return None
    try:
        expected = json.loads(record.read_text())
    except ValueError:
        return None
    if not isinstance(expected, dict):
        return None
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    if expected != {"gn_revision": gn_revision, "compiler": compiler, "sha256": digest}:
        return None
    return binary


def store_gn(cache_dir, gn_revision, compiler, built):
    """Keep a built GN for later runs and return its digest."""
    binary = cache_dir / gn_revision / "gn"
    binary.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(built, binary)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    write_json(binary.parent / GN_CACHE_RECORD,
               {"gn_revision": gn_revision, "compiler": compiler, "sha256": digest})
    return digest


def check_gn_cache():
    """A cached GN is reused only for its own revision, compiler and bytes."""
    with tempfile.TemporaryDirectory() as directory:
        cache = Path(directory) / "cache"
        built = Path(directory) / "built-gn"
        built.write_bytes(b"gn binary")
        revision, other = "a" * 40, "b" * 40
        assert cached_gn(cache, revision, "clang 23") is None
        digest = store_gn(cache, revision, "clang 23", built)
        assert digest == hashlib.sha256(b"gn binary").hexdigest()
        assert cached_gn(cache, revision, "clang 23") == cache / revision / "gn"
        assert cached_gn(cache, other, "clang 23") is None
        assert cached_gn(cache, revision, "clang 24") is None
        (cache / revision / "gn").write_bytes(b"altered")
        assert cached_gn(cache, revision, "clang 23") is None
        (cache / revision / GN_CACHE_RECORD).write_text("not json")
        assert cached_gn(cache, revision, "clang 23") is None


def check_claim(claim, marker, incomplete, complete):
    """A rerun replaces only this tool's own unfinished directory."""
    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory) / "target"
        claim(target)
        (target / "partial").write_text("left by an interrupted attempt")
        for status in incomplete:
            (target / marker).write_text(json.dumps({"status": status}))
            (target / "partial").write_text("left by an interrupted attempt")
            claim(target)
            assert not (target / "partial").exists()
        for status in (complete, None):
            (target / marker).write_text(json.dumps({"status": status}))
            (target / "kept").write_text("not ours to remove")
            try:
                claim(target)
            except ValueError:
                pass
            else:
                raise AssertionError(f"Directory with status {status} was replaced")
            assert (target / "kept").exists()
        (target / marker).unlink()
        try:
            claim(target)
        except ValueError:
            pass
        else:
            raise AssertionError("Unmarked directory was replaced")
        assert (target / "kept").exists()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--receipt", type=Path)
    # A V8 compile job peaks near 2 GiB, so CI passes the runner's core count
    # (4 cores and 16 GiB on the hosted Linux runner) and the default stays low.
    parser.add_argument("--jobs", type=int, default=2, help="Parallel compile and fetch jobs (1 to 64)")
    parser.add_argument("--ccache-dir", type=Path, help="Optional isolated compiler-object cache")
    parser.add_argument("--gn-cache-dir", type=Path,
                        help="Optional cache of the GN binary built for V8's pinned GN revision")
    args = parser.parse_args()
    if not 1 <= args.jobs <= 64:
        parser.error("--jobs must be between 1 and 64")
    if args.self_test:
        self_test()
        return
    if args.work_dir is None or args.receipt is None:
        parser.error("--work-dir and --receipt are required")
    claim_work_directory(args.work_dir.absolute())
    work = args.work_dir.resolve()
    receipt = {
        "status": "running", "profile": "standalone-system-clang23-hardened-libcxx-not-Brave",
        "tests": {}, "patches": [], "brave_validated": False,
        "public_native_hook_validated": False,
    }
    def save_receipt():
        write_json(args.receipt, receipt)

    save_receipt()
    # Explicit disposable checkouts must not inherit Git hook routing/config.
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    for variable, directory in {
        "HOME": ".home", "XDG_CONFIG_HOME": ".config", "XDG_CACHE_HOME": ".cache",
        "VPYTHON_VIRTUALENV_ROOT": ".vpython", "CIPD_CACHE_DIR": ".cipd",
    }.items():
        path = work / directory
        path.mkdir()
        env[variable] = str(path)
    if args.ccache_dir is not None:
        cache_dir = args.ccache_dir.resolve()
        cache_dir.mkdir(parents=True, exist_ok=True)
        if shutil.which("ccache", path=env["PATH"]) is None:
            raise RuntimeError("--ccache-dir requires ccache")
        # Never inherit a remote cache, permissive sloppiness or cached config.
        env = {key: value for key, value in env.items() if not key.startswith("CCACHE_")}
        cache_config = work / "ccache.conf"
        cache_config.write_text("")
        env.update(CCACHE_DIR=str(cache_dir), CCACHE_CONFIGPATH=str(cache_config),
                   CCACHE_COMPILERCHECK="content", CCACHE_MAXSIZE="6G",
                   CCACHE_BASEDIR=str(work), CCACHE_COMPRESS="true")
        receipt["compiler_cache"] = {"path": str(cache_dir), "max_size": "6G",
                                     "compiler_check": "content", "sloppiness": "none"}
    env.update(DEPOT_TOOLS_UPDATE="0", DEPOT_TOOLS_METRICS="0", CC="clang-23", CXX="clang++-23")

    def run(command, cwd=work, capture=False):
        receipt["stage"] = " ".join(map(str, command))
        print("RUN", receipt["stage"], flush=True)
        save_receipt()
        if capture:
            result = subprocess.check_output(command, cwd=cwd, env=env, text=True, timeout=300)
            receipt["last_successful_stage"] = receipt["stage"]
            save_receipt()
            return result
        process = subprocess.Popen(command, cwd=cwd, env=env, start_new_session=True)
        try:
            # A cold -j2 V8 cctest compile was 1650/1981 objects at 90 minutes.
            # The job timeout is 180 minutes and leaves room for the tests.
            deadline = time.monotonic() + 140 * 60
            while process.poll() is None:
                if shutil.disk_usage(work).free < 1024 ** 3:
                    raise RuntimeError("Stopped owned build before exhausting disk")
                if time.monotonic() > deadline:
                    raise TimeoutError("Owned build stage exceeded 140 minutes")
                try:
                    process.wait(timeout=0.25)
                except subprocess.TimeoutExpired:
                    pass
            if process.returncode:
                raise subprocess.CalledProcessError(process.returncode, command)
            receipt["last_successful_stage"] = receipt["stage"]
            save_receipt()
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()

    def checkout(url, revision, path, full=False):
        run(["git", "clone", *([] if full else ["--depth=1"]), "--no-checkout", url, str(path)])
        run(["git", "fetch", *([] if full else ["--depth=1"]), "origin", revision], path)
        run(["git", "checkout", "--detach", "FETCH_HEAD"], path)
        assert run(["git", "rev-parse", "HEAD"], path, True).strip() == revision

    try:
        if shutil.disk_usage(work).free < 8 * 1024 ** 3:
            raise RuntimeError("Need at least 8 GiB free before standalone source setup")
        base_path = env["PATH"]
        compiler_paths = {}
        for name in ("clang-23", "clang++-23"):
            resolved = shutil.which(name, path=base_path)
            if resolved is None:
                raise RuntimeError("Missing required compiler: " + name)
            compiler_paths[name] = str(Path(resolved).resolve())
        clang_base = Path(compiler_paths["clang-23"]).parent.parent
        for name in ("clang", "clang++", "llvm-ar", "llvm-nm", "llvm-readelf", "ld.lld"):
            if not (clang_base / "bin" / name).is_file():
                raise RuntimeError("Incomplete system LLVM toolchain: " + name)
        receipt["compiler"] = run([compiler_paths["clang++-23"], "--version"], capture=True).splitlines()[0]
        receipt["c_compiler"] = run([compiler_paths["clang-23"], "--version"], capture=True).splitlines()[0]
        receipt["compiler_paths"] = compiler_paths
        resource_dir = Path(run([compiler_paths["clang-23"], "-print-resource-dir"], capture=True).strip()).resolve()
        builtins = Path(run([compiler_paths["clang-23"], "--rtlib=compiler-rt",
                             "-print-libgcc-file-name"], capture=True).strip()).resolve()
        system_clang_base = clang_base
        clang_base = create_clang_toolchain_view(work / "clang-toolchain-view",
                                                system_clang_base, resource_dir, builtins)
        receipt["system_clang_runtime"] = {
            "system_base": str(system_clang_base), "resource_dir": str(resource_dir),
            "builtins": str(builtins), "builtins_sha256": hashlib.sha256(builtins.read_bytes()).hexdigest(),
            "view": str(clang_base),
        }
        v8_pin = (ROOT / "browser/config/v8.rev").read_text().strip()
        assert re.fullmatch(r"[0-9a-f]{40}", v8_pin)
        receipt["v8_revision"] = v8_pin
        depot, v8 = work / "depot_tools", work / "v8"
        checkout("https://chromium.googlesource.com/chromium/tools/depot_tools.git", DEPOT_REV, depot)
        checkout("https://github.com/v8/v8.git", v8_pin, v8)
        env["PATH"] = os.pathsep.join((str(depot), base_path))
        deps = (v8 / "DEPS").read_text()
        gn_pin = re.search(r"'gn_version': 'git_revision:([0-9a-f]{40})'", deps).group(1)
        excluded = binary_dependencies(deps)
        excluded.update({"v8/" + name: None for name in (
            "agents/shared", "test/benchmarks/data", "test/mozilla/data",
            "test/test262/data", "third_party/depot_tools",
        )})
        receipt["excluded_dependency_paths"] = sorted(excluded)
        # custom_deps=None does not suppress GCS objects in pinned gclient.
        # Its type filter applies to every recursively parsed DEPS file.
        receipt["ignored_dependency_types"] = ["gcs", "cipd"]
        (work / ".gclient").write_text("solutions = " + repr([{
            "name": "v8", "url": "https://github.com/v8/v8.git", "managed": False,
            "deps_file": "DEPS", "custom_deps": excluded,
            "custom_vars": {"checkout_benchmarks": False, "download_remoteexec_cfg": False},
        }]) + "\ntarget_os = ['linux']\n")
        run(["python3", str(depot / "gclient.py"), "sync", "--nohooks", "--noprehooks", "--shallow",
             "--ignore-dep-type=gcs", "--ignore-dep-type=cipd",
             "-j", str(args.jobs), "--revision", "v8@" + v8_pin])
        receipt["jobs"] = args.jobs
        gn_cache = None if args.gn_cache_dir is None else args.gn_cache_dir.resolve()
        gn_binary = None if gn_cache is None else cached_gn(gn_cache, gn_pin, receipt["compiler"])
        if gn_binary is not None:
            receipt["gn_binary"] = {"reused": True,
                                    "sha256": hashlib.sha256(gn_binary.read_bytes()).hexdigest()}
        else:
            gn_source = work / "gn-source"
            # GN's version generator needs its initial-commit tag/history.
            checkout("https://gn.googlesource.com/gn", gn_pin, gn_source, full=True)
            run(["python3", "build/gen.py", "--out-path=out"], gn_source)
            run(["ninja", "-C", "out", "-j", str(args.jobs), "gn"], gn_source)
            gn_binary = gn_source / "out/gn"
            digest = hashlib.sha256(gn_binary.read_bytes()).hexdigest()
            if gn_cache is not None:
                digest = store_gn(gn_cache, gn_pin, receipt["compiler"], gn_binary)
            receipt["gn_binary"] = {"reused": False, "sha256": digest}
        receipt["gn_binary"]["version"] = run([str(gn_binary), "--version"], capture=True).strip()
        receipt["gn_revision"] = gn_pin
        for patch in sorted((ROOT / "browser/integration/brave/patches/v8").glob("*.patch")):
            source, build, omitted = split_patch(patch.read_text())
            entry = {"name": patch.name, "sha256": hashlib.sha256(patch.read_bytes()).hexdigest(),
                     "omitted_embedder_gn_hunks": omitted}
            for label, content in (("source", source), ("gn", build)):
                if content:
                    temporary = work / (patch.name + "." + label)
                    temporary.write_text(content)
                    run(["git", "apply", "--check", str(temporary)], v8)
                    run(["git", "apply", str(temporary)], v8)
            receipt["patches"].append(entry)
        receipt["standalone_upstream_annotations"] = []
        for relative, count in ABSEIL_CAPTURE_COUNTS.items():
            path = v8 / "third_party/abseil-cpp/absl" / relative
            original = path.read_text()
            modernized = modernize_abseil_capture(original, count)
            path.write_text(modernized)
            receipt["standalone_upstream_annotations"].append({
                "path": str(path.relative_to(v8)), "count": count,
                "change": "lifetime_capture_by(this) to lifetime_capture_by_this",
                "before_sha256": hashlib.sha256(original.encode()).hexdigest(),
                "after_sha256": hashlib.sha256(modernized.encode()).hexdigest(),
            })
        save_receipt()
        # Temporal alone pulls Rust into this standalone build; guest capture
        # and the public QuickJS fixture do not use the Temporal API.
        gn_args = " ".join((
            'is_debug=false', 'is_component_build=false', 'symbol_level=0',
            'is_clang=true', 'use_lld=true',
            'clang_use_chrome_plugins=false', 'clang_version="23"', 'clang_base_path=' + json.dumps(str(clang_base)), 'use_custom_libcxx=true', 'use_sysroot=false',
            'use_custom_libcxx_for_host=true', 'v8_enable_sandbox=true',
            'enable_rust=false', 'v8_enable_temporal_support=false',
            'use_remoteexec=false', 'treat_warnings_as_errors=true',
            'target_cpu="x64"', 'v8_target_cpu="x64"', 'v8_enable_i18n_support=false',
            'v8_use_external_startup_data=false', 'v8_dcheck_always_on=true',
        ))
        if args.ccache_dir is not None:
            gn_args += ' cc_wrapper="ccache"'
            receipt["compiler_cache"]["version"] = run(["ccache", "--version"], capture=True).splitlines()[0]
        receipt["gn_args"] = gn_args
        fixture = ROOT / "tools/quickjs-native-fixture"
        public_inputs = work / "public-quickjs"
        run(["npm", "ci", "--ignore-scripts", "--prefix", str(fixture)], ROOT)
        run(["node", str(fixture / "verify.mjs")], ROOT)
        run(["node", str(fixture / "build-native-hook.mjs"), str(public_inputs)], ROOT)
        run(["node", str(fixture / "check-native-hook-loader.mjs"), str(public_inputs)], ROOT)
        receipt["public_fixture_inputs"] = json.loads((public_inputs / "input-receipt.json").read_text())
        save_receipt()
        run([str(gn_binary), "gen", "out/native-runtime", "--fail-on-unused-args", "--args=" + gn_args], v8)
        run(["ninja", "-C", "out/native-runtime", "-j", str(args.jobs), "d8", "cctest"], v8)
        binary = v8 / "out/native-runtime/cctest"
        listed = run([str(binary), "--list"], v8, True)
        for name in TEST_NAMES:
            test = cctest_name(name)
            if test not in listed.split():
                raise RuntimeError("Expected compiled test missing: " + test)
            run([str(binary), test], v8)
            receipt["tests"][test] = "passed"
            save_receipt()
        if PUBLIC_TEST not in listed.split():
            raise RuntimeError("Expected public native test missing: " + PUBLIC_TEST)
        env["REB_PUBLIC_QUICKJS_WASM"] = str(public_inputs / "quickjs.wasm")
        env["REB_PUBLIC_QUICKJS_BUNDLE"] = str(public_inputs / "quickjs-native-hook.js")
        output = run([str(binary), PUBLIC_TEST], v8, True)
        print(output, end="", flush=True)
        witnesses = []
        for line in output.splitlines():
            if line.startswith('{"target":"public-quickjs-0.32.0"'):
                witnesses.append(json.loads(line))
        if len(witnesses) != 1:
            raise RuntimeError("Expected exactly one completed public native-hook witness")
        witness = witnesses[0]
        if not (witness.get("native_hook_validated") is True
                and witness.get("brave_validated") is False
                and witness.get("host_calls") == 8
                and isinstance(witness.get("dispatches"), int)
                and witness["dispatches"] >= 8
                # Both visit() guest calls name their caller's exact dispatch.
                and isinstance(witness.get("exact_parent_activations"), int)
                and witness["exact_parent_activations"] >= 2):
            raise RuntimeError("Incomplete public native-hook witness")
        receipt["public_native_hook"] = witness
        receipt["public_native_hook_validated"] = True
        receipt["tests"][PUBLIC_TEST] = "passed"
        receipt["status"] = "passed"
        receipt["limits"] = ["No Brave/Blink build or browser execution"]
    except Exception as error:
        receipt["status"] = "failed"
        receipt["error"] = str(error)
        raise
    finally:
        if args.ccache_dir is not None:
            try:
                stats = subprocess.run(["ccache", "--show-stats"], env=env, text=True,
                                       capture_output=True, timeout=30, check=False)
                receipt["compiler_cache"]["statistics"] = stats.stdout
            except (OSError, subprocess.TimeoutExpired) as error:
                receipt["compiler_cache"]["statistics_error"] = str(error)
        save_receipt()
        write_json(work / WORK_MARKER, {"status": receipt["status"]})


if __name__ == "__main__":
    main()
