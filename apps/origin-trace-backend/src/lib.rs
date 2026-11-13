pub mod action_guidance;
mod analysis_catalog;
mod analyst;
mod app;
mod artifact_lookup;
pub mod artifact_map;
mod artifact_query;
mod artifact_text;
mod capture;
mod config;
mod debugger_observation;
mod debugger_watch;
mod decoder;
mod deobfuscation;
mod durable;
mod endpoint;
mod error;
mod event_query;
mod event_window;
mod evidence;
pub mod evidence_comparison;
pub mod evidence_package;
pub mod float32;
mod flow_graph;
mod gap_tally;
mod graph_layout;
mod js_invocation;
mod js_invocation_sites;
pub mod live_wasm;
mod native_console;
mod native_debugger;
pub mod native_debugger_pause;
mod native_guest_binding;
mod origin_trace;
mod owned_vm_debugger;
mod request_cookies;
mod request_headers;
mod request_index;
mod request_stack;
mod request_tabs;
mod session_context;
#[cfg(unix)]
pub mod session_launch;
mod session_summary;
mod source_facts;
mod source_format;
mod source_format_doc;
mod source_format_js;
mod store_scan;
mod validation;
pub mod vm;
mod vm_byte_coverage;
mod vm_bytecode;
pub mod vm_dispatch_input;
mod vm_effects;
mod vm_experiment;
mod vm_host_links;
mod vm_opcode;
pub mod vm_pack;
mod vm_reachability;
mod vm_request_links;
pub mod wasm;
mod wasm_constants;
pub mod wasm_graph;
pub mod wasm_identification;
mod wasm_names;
mod wasm_run;
mod worker;
mod workspace;
mod workspace_lease;
mod xrefs;
pub use app::App;
pub use config::Options;
pub use endpoint::{PublishedEndpoint, has_live_publisher};

pub use durable::write_private_noclobber;

mod js_worker_alloc;
mod live_browser;
mod native_input;
#[doc(hidden)]
pub use js_worker_alloc::JavaScriptWorkerAllocator;
#[doc(hidden)]
pub use vm::dispatch_shape::javascript::worker_entry as javascript_worker_entry;

// libtest owns main, so each harness explicitly includes this ignored entry.
// The parent still re-executes itself, including integration and binary tests.
#[doc(hidden)]
#[macro_export]
macro_rules! javascript_worker_test_entry {
    () => {
        #[test]
        #[ignore]
        fn __reb_javascript_worker() {
            if std::env::var_os("REB_JS_TEST_WORKER").is_some() {
                $crate::javascript_worker_entry();
            }
        }
    };
}
#[cfg(test)]
javascript_worker_test_entry!();

#[global_allocator]
static JS_TEST_ALLOCATOR: JavaScriptWorkerAllocator = JavaScriptWorkerAllocator;
