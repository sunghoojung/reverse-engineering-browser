from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse, urlunparse
from urllib.request import Request, urlopen

from debugger.automation import (
    automation_failure_result,
    automation_recipe_id,
    automation_runner_config,
    normalize_automation_recipe,
    normalize_automation_result,
    normalize_automation_variables,
    normalize_runtime_hook_json,
    runtime_hook_source_label,
    runtime_hook_text,
)
from debugger.errors import (
    DebuggerBridgeError,
    ProtocolError,
    WebSocketClosed,
)
from debugger.heap_snapshot import (
    HeapSnapshotCapture,
    HeapSnapshotCollector,
)
from debugger.limits import (
    AUTOMATION_EXECUTION_TIMEOUT_MS,
    AUTOMATION_WATCHDOG_GRACE_SECONDS,
    FORBIDDEN_OBJECT_EXPERIMENT_PROPERTIES,
    HEAP_SNAPSHOT_CAPTURE_TIMEOUT_SECONDS,
    HEAP_SNAPSHOT_DIFF_TIMEOUT_SECONDS,
    HEAP_SNAPSHOT_PROBE_TIMEOUT_SECONDS,
    HEAP_SNAPSHOT_SEARCH_TIMEOUT_SECONDS,
    INTERCEPTION_RUN_TIMEOUT_SECONDS,
    LIVE_OBJECT_SEARCH_TIMEOUT_MS,
    MAX_ACTION_SCOPE_PENDING_TRIGGERS,
    MAX_ACTION_SCOPE_TARGETS,
    MAX_ACTIVE_PORT_BYTES,
    MAX_ASYNC_STACK_DEPTH,
    MAX_AUTOMATION_AUTO_RECIPES,
    MAX_AUTOMATION_AUTO_RUNS,
    MAX_AUTOMATION_BINDING_REPORT_BYTES,
    MAX_AUTOMATION_LOG_BYTES,
    MAX_AUTOMATION_LOGS,
    MAX_AUTOMATION_RECIPE_SOURCE_BYTES,
    MAX_AUTOMATION_RECIPES,
    MAX_AUTOMATION_RESULT_BYTES,
    MAX_AUTOMATION_RETAINED_RUNS,
    MAX_AUTOMATION_RUNS,
    MAX_AUTOMATION_TOTAL_SOURCE_BYTES,
    MAX_AUTOMATION_VARIABLE_BYTES,
    MAX_AUTOMATION_VARIABLE_VALUE_BYTES,
    MAX_AUTOMATION_VARIABLES,
    MAX_BREAKPOINT_LOCATIONS,
    MAX_BREAKPOINT_TEXT_BYTES,
    MAX_BREAKPOINTS,
    MAX_CALL_FRAMES,
    MAX_CONSOLE_ARGUMENTS,
    MAX_CONSOLE_ENTRIES,
    MAX_EVENT_BREAKPOINTS,
    MAX_HEAP_INCOMING_REFERENCES,
    MAX_HEAP_RETAINING_PATH,
    MAX_HEAP_SNAPSHOT_BYTES,
    MAX_HEAP_SNAPSHOT_RESULTS,
    MAX_INTERCEPTION_AUDIT_ENTRIES,
    MAX_INTERCEPTION_BODY_BYTES,
    MAX_INTERCEPTION_HEADER_BYTES,
    MAX_INTERCEPTION_HEADER_VALUE_BYTES,
    MAX_INTERCEPTION_HEADERS,
    MAX_INTERCEPTION_METHOD_BYTES,
    MAX_INTERCEPTION_PENDING_REQUESTS,
    MAX_INTERCEPTION_RESPONSE_BYTES,
    MAX_INTERCEPTION_URL_BYTES,
    MAX_LIVE_OBJECT_PREVIEW_PROPERTIES,
    MAX_LIVE_OBJECT_RESULTS,
    MAX_LIVE_OBJECT_SCAN,
    MAX_MEMORY_ORIGIN_TRACE_AFTER_STEPS,
    MAX_MEMORY_ORIGIN_TRACE_BEFORE_STEPS,
    MAX_MEMORY_ORIGIN_TRACE_STEPS,
    MAX_OBJECT_EXPERIMENT_AUDIT_ENTRIES,
    MAX_OBJECT_EXPERIMENT_MUTATIONS,
    MAX_OBJECT_EXPERIMENT_PROPERTY_BYTES,
    MAX_OBJECT_EXPERIMENT_STRING_BYTES,
    MAX_OBJECT_EXPERIMENT_VALUE_BYTES,
    MAX_OBJECT_EXPERIMENT_VALUE_DEPTH,
    MAX_OBJECT_EXPERIMENT_VALUE_ENTRIES,
    MAX_REMOTE_TEXT_BYTES,
    MAX_REPEATER_HISTORY_BYTES,
    MAX_REPEATER_HISTORY_ENTRIES,
    MAX_REPEATER_TIMEOUT_MS,
    MAX_REPEATER_VARIABLE_BYTES,
    MAX_REPEATER_VARIABLES,
    MAX_RUNTIME_HOOK_BINDING_PREVIEW_BYTES,
    MAX_RUNTIME_HOOK_BINDINGS,
    MAX_RUNTIME_HOOK_BREAKPOINTS,
    MAX_RUNTIME_HOOK_CONDITION_BYTES,
    MAX_RUNTIME_HOOK_HITS,
    MAX_RUNTIME_HOOK_LABEL_BYTES,
    MAX_RUNTIME_HOOK_LOGIC_BYTES,
    MAX_RUNTIME_HOOK_RETAINED_HITS,
    MAX_RUNTIME_HOOK_RETURN_BYTES,
    MAX_RUNTIME_HOOK_RETURN_POINTS,
    MAX_RUNTIME_HOOKS,
    MAX_SCOPE_PROPERTIES,
    MAX_SCOPES_PER_FRAME,
    MAX_SCRIPT_SOURCE_BYTES,
    MAX_SCRIPTS,
    MAX_TARGET_ID_BYTES,
    MAX_TARGET_LIST_BYTES,
    MAX_TARGET_TYPE_BYTES,
    MAX_TARGET_URL_BYTES,
    MAX_TARGETS,
    MAX_TOTAL_SCOPE_PROPERTIES,
    MAX_WATCH_EXPRESSION_BYTES,
    MAX_WATCHES,
    MAX_XHR_BREAKPOINTS,
    MEMORY_ORIGIN_TRACE_FRAMEWORK_PATTERNS,
    MEMORY_ORIGIN_TRACE_IDLE_TIMEOUT_SECONDS,
    MEMORY_ORIGIN_TRACE_TIMEOUT_SECONDS,
    OBJECT_EXPERIMENT_NAVIGATION_TIMEOUT_SECONDS,
    RUNTIME_HOOK_EVALUATION_TIMEOUT_MS,
)
from debugger.memory import (
    empty_object_experiment_descriptor,
    live_object_search_criteria,
    normalize_heap_snapshot_probe,
    normalize_object_experiment_descriptor,
    normalize_object_experiment_value,
    optional_search_text,
)
from debugger.requests import (
    compare_repeater_entries,
    default_request_interception_rule,
    normalize_repeater_result,
    normalize_repeater_template,
    normalize_repeater_variables,
    normalize_request_interception_request,
    normalize_request_interception_result,
    normalize_request_interception_rule,
    redacted_request_url,
    request_interception_preflight_headers,
    resolve_repeater_request,
    validate_request_interception_url,
)
from debugger.runtime_scripts import (
    AUTOMATION_RECIPE_FUNCTION,
    LIVE_OBJECT_SEARCH_FUNCTION,
    OBJECT_EXPERIMENT_MUTATE_FUNCTION,
    REQUEST_INTERCEPTION_FUNCTION,
)
from debugger.transport import (
    ActionScopeTargetSession,
    NativeDebuggerConnection,
    PendingCommand,
)
from debugger.validation import (
    bounded_integer,
    is_finite_protocol_number,
    required_protocol_identifier,
    required_text,
    runtime_result_object_id,
    truncate_text,
)


class DebuggerBridge:
    def __init__(
        self,
        active_port_path: Optional[Path] = None,
        heap_snapshot_binary: Optional[Path] = None,
        debugger_transport_binary: Optional[Path] = None,
    ) -> None:
        self.active_port_path = active_port_path
        self.heap_snapshot_binary = heap_snapshot_binary or (
            Path(__file__).resolve().parents[2] / "build" / "reb-heap-snapshot"
        )
        self.debugger_transport_binary = debugger_transport_binary or (
            Path(__file__).resolve().parents[2]
            / "build"
            / "reb-debugger-transport"
        )
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._reader_thread: Optional[threading.Thread] = None
        self._connection: Optional[NativeDebuggerConnection] = None
        self._pending: dict[int, PendingCommand] = {}
        self._next_command_id = 1
        self._generation = 0
        self._state = "unavailable" if active_port_path is None else "waiting"
        self._error: Optional[str] = None
        self._target: Optional[dict[str, str]] = None
        self._targets: list[dict[str, str]] = []
        self._preferred_target_id: Optional[str] = None
        self._scripts: dict[str, dict[str, Any]] = {}
        self._paused: Optional[dict[str, Any]] = None
        self._pause_serial = 0
        self._breakpoints: dict[str, dict[str, Any]] = {}
        self._watches: list[dict[str, Any]] = []
        self._watch_frame_id: Optional[str] = None
        self._next_watch_id = 1
        self._console: list[dict[str, Any]] = []
        self._next_console_id = 1
        self._breakpoints_active = True
        self._pause_on_exceptions = "none"
        self._xhr_breakpoints: list[str] = []
        self._event_breakpoints: list[str] = []
        self._heap_snapshot_collector: Optional[HeapSnapshotCollector] = None
        self._heap_diff_baseline: Optional[HeapSnapshotCapture] = None
        self._heap_diff_busy = False
        self._next_memory_origin_trace_id = 1
        self._memory_origin_trace = self._empty_memory_origin_trace()
        self._memory_origin_trace_started = 0.0
        self._memory_origin_trace_processing = False
        self._memory_origin_trace_stop_requested = False
        self._memory_origin_trace_added_click_breakpoint = False
        self._memory_origin_trace_timer: Optional[threading.Timer] = None
        self._next_request_interception_id = 1
        self._next_request_interception_audit_id = 1
        self._request_interception = self._empty_request_interception()
        self._request_interception_rule = default_request_interception_rule()
        self._request_interception_configured = False
        self._request_interception_context_id: Optional[str] = None
        self._request_interception_return_target_id: Optional[str] = None
        self._request_interception_pending: set[tuple[str, str]] = set()
        self._action_scope_mode = "global"
        self._action_scope_target_id: Optional[str] = None
        self._action_scope_targets: dict[str, dict[str, Any]] = {}
        self._action_scope_sessions: dict[str, ActionScopeTargetSession] = {}
        self._action_scope_target_overflow = 0
        self._action_scope_revision = 0
        self._action_scope_last_error: Optional[str] = None
        self._next_object_experiment_navigation_id = 1
        self._next_object_experiment_search_id = 1
        self._next_object_experiment_audit_id = 1
        self._object_experiment = self._empty_object_experiment()
        self._object_experiment_group: Optional[str] = None
        self._object_experiment_objects_id: Optional[str] = None
        self._object_experiment_result_indices: set[int] = set()
        self._next_runtime_hook_id = 1
        self._next_runtime_hook_hit_id = 1
        self._runtime_hooks = self._empty_runtime_hooks()
        self._runtime_hook_points: dict[str, dict[str, Any]] = {}
        self._runtime_hook_processing = False
        self._runtime_hook_stop_requested = False
        self._runtime_hook_deferred_pause: Optional[dict[str, Any]] = None
        self._runtime_hook_epoch = 0
        self._next_automation_recipe_id = 1
        self._next_automation_run_id = 1
        self._automation_recipes: list[dict[str, Any]] = []
        self._automation_source_bytes = 0
        self._automation_recipes_state = self._empty_automation_recipes()
        self._automation_variables: dict[str, str] = {}
        self._automation_auto_script_ids: dict[str, str] = {}
        self._automation_binding_target_ids: set[str] = set()
        self._automation_binding_name = f"__reb_automation_{os.urandom(16).hex()}"
        self._automation_binding_nonce: Optional[str] = None
        self._automation_active_run_id: Optional[int] = None
        self._automation_active_document_id: Optional[str] = None
        self._automation_active_target_id: Optional[str] = None
        self._automation_active_session: Optional[ActionScopeTargetSession] = None
        self._automation_cancel_requested = False
        self._automation_auto_watchdog: Optional[threading.Timer] = None
        self._automation_pending_triggers: list[tuple[str, str]] = []
        self._automation_processing = False
        self._automation_epoch = 0
        self._next_repeater_execution_id = 1
        self._repeater = self._empty_repeater()
        self._repeater_history_bytes = 0
        self._repeater_active_execution_id: Optional[int] = None
        self._repeater_cancel_requested = False
        self._repeater_controller_key = (
            f"__reb_repeater_controllers_{os.urandom(16).hex()}"
        )

    def start(self) -> None:
        if self.active_port_path is None or self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run, name="reb-debugger-bridge", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        with self._condition:
            connection = self._connection
            self._cancel_memory_origin_trace_timer_locked()
            self._condition.notify_all()
        if connection is not None:
            connection.close()
        if self._thread is not None:
            self._thread.join(timeout=3.0)
        self._fail_pending(DebuggerBridgeError("Debugger bridge stopped"))
        self._clear_heap_diff_baseline(force=True)
        self._dispose_request_interception_context(preserve_result=False, force=True)
        self._close_action_scope_sessions()

    def generation(self) -> int:
        with self._lock:
            return self._generation

    def state(self) -> str:
        with self._lock:
            return self._state

    def wait_for_change(self, generation: int, timeout: float) -> int:
        with self._condition:
            self._condition.wait_for(
                lambda: self._generation != generation or self._stop.is_set(),
                timeout=max(0.0, timeout),
            )
            return self._generation

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "protocol_version": 1,
                "state": self._state,
                "generation": self._generation,
                "error": self._error,
                "target": dict(self._target) if self._target is not None else None,
                "targets": [
                    {key: target[key] for key in ("id", "type", "title", "url")}
                    for target in self._targets
                ],
                # Script records contain only scalar values, so copying each mapping
                # preserves snapshot isolation without a full recursive traversal.
                "scripts": [dict(script) for script in self._scripts.values()],
                "paused": copy.deepcopy(self._paused),
                "breakpoints": copy.deepcopy(list(self._breakpoints.values())),
                "watches": copy.deepcopy(self._watches),
                "console": copy.deepcopy(self._console),
                "settings": {
                    "breakpoints_active": self._breakpoints_active,
                    "pause_on_exceptions": self._pause_on_exceptions,
                    "xhr_breakpoints": list(self._xhr_breakpoints),
                    "event_breakpoints": list(self._event_breakpoints),
                },
                "heap_diff_baseline": self._heap_diff_baseline_metadata(),
                "memory_origin_trace": copy.deepcopy(self._memory_origin_trace),
                "action_scope": self._public_action_scope_locked(),
                "request_interception": copy.deepcopy(self._request_interception),
                "object_experiment": copy.deepcopy(self._object_experiment),
                "runtime_hooks": copy.deepcopy(self._runtime_hooks),
                "automation_recipes": copy.deepcopy(
                    self._automation_recipes_state
                ),
                "repeater": copy.deepcopy(self._repeater),
                "limits": {
                    "scripts": MAX_SCRIPTS,
                    "call_frames": MAX_CALL_FRAMES,
                    "scope_properties": MAX_TOTAL_SCOPE_PROPERTIES,
                    "console_entries": MAX_CONSOLE_ENTRIES,
                    "source_bytes": MAX_SCRIPT_SOURCE_BYTES,
                },
            }

    def action(self, request: dict[str, Any]) -> dict[str, Any]:
        action = request.get("action")
        if not isinstance(action, str):
            raise DebuggerBridgeError("Debugger action is required")
        with self._lock:
            origin_trace_active = self._memory_origin_trace_active_locked()
            request_interception_running = (
                self._request_interception["state"] == "running"
            )
            repeater_running = self._repeater_active_execution_id is not None
            object_experiment_running = self._object_experiment["state"] in {
                "navigating",
                "searching",
                "mutating",
            }
            runtime_hooks_active = self._runtime_hooks["state"] in {
                "arming",
                "armed",
                "handling",
                "stopping",
            }
            automation_running = (
                self._automation_active_run_id is not None
                or self._automation_processing
                or self._automation_recipes_state["state"]
                in {"arming", "running", "stopping"}
            )
            automation_armed = self._automation_recipes_state["auto_armed"]
        if origin_trace_active and action != "stop_memory_origin_trace":
            raise DebuggerBridgeError(
                "Memory Origin Trace controls the debugger until it finishes or is stopped"
            )
        if request_interception_running:
            raise DebuggerBridgeError(
                "The isolated experiment controls the debugger until its request finishes"
            )
        if repeater_running and action != "cancel_repeater_request":
            raise DebuggerBridgeError(
                "Repeater controls the isolated debugger target until its request finishes or is cancelled"
            )
        if object_experiment_running:
            raise DebuggerBridgeError(
                "Object Lab controls the isolated debugger target until its action finishes"
            )
        if runtime_hooks_active and action != "disarm_runtime_hooks":
            raise DebuggerBridgeError(
                "Runtime Hooks controls the isolated debugger target until it is disarmed"
            )
        automation_control_actions = {
            "add_automation_recipe",
            "update_automation_recipe",
            "remove_automation_recipe",
            "arm_automation_recipes",
            "disarm_automation_recipes",
            "run_automation_recipe",
            "cancel_automation_recipe",
            "clear_automation_runs",
        }
        if automation_running and action not in {
            "cancel_automation_recipe",
            "disarm_automation_recipes",
        }:
            raise DebuggerBridgeError(
                "Automation Recipes controls the isolated debugger target until the active run finishes or is cancelled"
            )
        if automation_armed and action not in automation_control_actions | {
            "navigate_object_experiment",
            "dispose_request_interception_experiment",
        }:
            raise DebuggerBridgeError(
                "Automatic recipes control the isolated debugger target until they are disarmed"
            )
        if action == "pause":
            self._command("Debugger.pause")
        elif action == "resume":
            self._command("Debugger.resume")
        elif action == "step_over":
            self._command("Debugger.stepOver")
        elif action == "step_into":
            self._command("Debugger.stepInto", {"breakOnAsyncCall": True})
        elif action == "step_out":
            self._command("Debugger.stepOut")
        elif action == "restart_frame":
            frame_id = required_text(request, "call_frame_id", 4_096)
            self._command(
                "Debugger.restartFrame", {"callFrameId": frame_id, "mode": "StepInto"}
            )
        elif action == "set_breakpoint":
            return self._set_breakpoint(request)
        elif action == "remove_breakpoint":
            breakpoint_id = required_text(
                request, "breakpoint_id", MAX_BREAKPOINT_TEXT_BYTES
            )
            self._command("Debugger.removeBreakpoint", {"breakpointId": breakpoint_id})
            with self._lock:
                self._breakpoints.pop(breakpoint_id, None)
                self._changed()
        elif action == "update_breakpoint":
            breakpoint_id = required_text(
                request, "breakpoint_id", MAX_BREAKPOINT_TEXT_BYTES
            )
            with self._lock:
                existing = self._breakpoints.get(breakpoint_id)
            if existing is None:
                raise DebuggerBridgeError("Breakpoint is unavailable")
            replacement = self._set_breakpoint(
                {
                    "url": existing["url"],
                    "script_id": existing["script_id"],
                    "line": existing["line"],
                    "column": existing["column"],
                    "kind": request.get("kind"),
                    "expression": request.get("expression"),
                },
                replacing=breakpoint_id,
            )
            self._command("Debugger.removeBreakpoint", {"breakpointId": breakpoint_id})
            with self._lock:
                self._breakpoints.pop(breakpoint_id, None)
                self._changed()
            return replacement
        elif action == "set_breakpoints_active":
            active = request.get("active")
            if not isinstance(active, bool):
                raise DebuggerBridgeError("Breakpoint active state must be boolean")
            self._command("Debugger.setBreakpointsActive", {"active": active})
            with self._lock:
                self._breakpoints_active = active
                self._changed()
        elif action == "set_pause_on_exceptions":
            mode = request.get("mode")
            if mode not in {"none", "uncaught", "all"}:
                raise DebuggerBridgeError("Pause-on-exceptions mode is invalid")
            self._command("Debugger.setPauseOnExceptions", {"state": mode})
            with self._lock:
                self._pause_on_exceptions = mode
                self._changed()
        elif action == "add_watch":
            expression = required_text(
                request, "expression", MAX_WATCH_EXPRESSION_BYTES
            )
            with self._lock:
                if len(self._watches) >= MAX_WATCHES:
                    raise DebuggerBridgeError("Watch expression limit reached")
                watch = {
                    "id": str(self._next_watch_id),
                    "expression": expression,
                    "result": None,
                    "error": None,
                }
                self._next_watch_id += 1
                self._watches.append(watch)
                watch_frame_id = self._watch_frame_id
                self._changed()
            if watch_frame_id is not None:
                self._evaluate_watches_async(watch_frame_id)
        elif action == "remove_watch":
            watch_id = required_text(request, "watch_id", 32)
            with self._lock:
                self._watches = [
                    watch for watch in self._watches if watch["id"] != watch_id
                ]
                self._changed()
        elif action == "evaluate_watches":
            frame_id = required_text(request, "call_frame_id", 4_096)
            with self._lock:
                valid_frame = self._paused is not None and any(
                    frame["id"] == frame_id for frame in self._paused["call_frames"]
                )
            if not valid_frame:
                raise DebuggerBridgeError("Call frame is unavailable")
            with self._lock:
                self._watch_frame_id = frame_id
            self._evaluate_watches(frame_id)
        elif action == "set_xhr_breakpoint":
            self._set_xhr_breakpoint(request)
        elif action == "remove_xhr_breakpoint":
            pattern = required_text(
                request, "pattern", MAX_BREAKPOINT_TEXT_BYTES, allow_empty=True
            )
            self._command("DOMDebugger.removeXHRBreakpoint", {"url": pattern})
            with self._lock:
                self._xhr_breakpoints = [
                    value for value in self._xhr_breakpoints if value != pattern
                ]
                self._changed()
        elif action == "set_event_breakpoint":
            event_name = required_text(request, "event_name", 256)
            with self._lock:
                if (
                    event_name not in self._event_breakpoints
                    and len(self._event_breakpoints) >= MAX_EVENT_BREAKPOINTS
                ):
                    raise DebuggerBridgeError("Event breakpoint limit reached")
            self._command(
                "DOMDebugger.setEventListenerBreakpoint", {"eventName": event_name}
            )
            with self._lock:
                if event_name not in self._event_breakpoints:
                    self._event_breakpoints.append(event_name)
                self._changed()
        elif action == "remove_event_breakpoint":
            event_name = required_text(request, "event_name", 256)
            self._command(
                "DOMDebugger.removeEventListenerBreakpoint", {"eventName": event_name}
            )
            with self._lock:
                self._event_breakpoints = [
                    value for value in self._event_breakpoints if value != event_name
                ]
                self._changed()
        elif action == "select_target":
            target_id = required_text(request, "target_id", 4_096)
            with self._lock:
                if not any(target["id"] == target_id for target in self._targets):
                    raise DebuggerBridgeError("Debugger target is unavailable")
                if self._heap_diff_busy:
                    raise DebuggerBridgeError("Heap snapshot comparison is running")
                self._preferred_target_id = target_id
                connection = self._connection
            self._clear_heap_diff_baseline()
            if connection is not None:
                connection.close()
        elif action == "search_live_objects":
            return self._search_live_objects(request)
        elif action == "search_heap_snapshot":
            return self._search_heap_snapshot(request)
        elif action == "start_memory_origin_trace":
            return self._start_memory_origin_trace(request)
        elif action == "stop_memory_origin_trace":
            return self._stop_memory_origin_trace()
        elif action == "clear_memory_origin_trace":
            with self._lock:
                self._memory_origin_trace = self._empty_memory_origin_trace()
                self._changed()
        elif action == "set_action_scope":
            return self._set_action_scope(request)
        elif action == "create_request_interception_experiment":
            return self._create_request_interception_experiment()
        elif action == "create_experiment_page":
            return self._create_experiment_page(request)
        elif action == "close_experiment_page":
            return self._close_experiment_page(request)
        elif action == "navigate_object_experiment":
            return self._navigate_object_experiment(request)
        elif action == "search_object_experiment":
            return self._search_object_experiment(request)
        elif action == "mutate_object_experiment":
            return self._mutate_object_experiment(request)
        elif action == "add_runtime_hook":
            return self._add_runtime_hook(request)
        elif action == "remove_runtime_hook":
            return self._remove_runtime_hook(request)
        elif action == "arm_runtime_hooks":
            return self._arm_runtime_hooks(request)
        elif action == "disarm_runtime_hooks":
            return self._disarm_runtime_hooks()
        elif action == "clear_runtime_hook_hits":
            return self._clear_runtime_hook_hits()
        elif action == "add_automation_recipe":
            return self._add_automation_recipe(request)
        elif action == "update_automation_recipe":
            return self._update_automation_recipe(request)
        elif action == "remove_automation_recipe":
            return self._remove_automation_recipe(request)
        elif action == "arm_automation_recipes":
            return self._arm_automation_recipes(request)
        elif action == "disarm_automation_recipes":
            return self._disarm_automation_recipes()
        elif action == "run_automation_recipe":
            return self._run_automation_recipe(request)
        elif action == "cancel_automation_recipe":
            return self._cancel_automation_recipe()
        elif action == "clear_automation_runs":
            return self._clear_automation_runs()
        elif action == "configure_request_interception":
            return self._configure_request_interception(request)
        elif action == "run_request_interception":
            return self._run_request_interception(request)
        elif action == "dispose_request_interception_experiment":
            return self._dispose_request_interception_experiment()
        elif action == "clear_request_interception_result":
            return self._clear_request_interception_result()
        elif action == "configure_repeater_variables":
            return self._configure_repeater_variables(request)
        elif action == "run_repeater_request":
            return self._run_repeater_request(request)
        elif action == "cancel_repeater_request":
            return self._cancel_repeater_request()
        elif action == "compare_repeater_history":
            return self._compare_repeater_history(request)
        elif action == "clear_repeater_history":
            return self._clear_repeater_history()
        elif action == "capture_heap_diff_baseline":
            return self._capture_heap_diff_baseline()
        elif action == "compare_heap_diff":
            return self._compare_heap_diff()
        elif action == "clear_heap_diff_baseline":
            self._clear_heap_diff_baseline()
        elif action == "clear_console":
            with self._lock:
                self._console = []
                self._changed()
        else:
            raise DebuggerBridgeError("Debugger action is not allowed")
        return {"ok": True, "generation": self.generation()}

    def get_script_source(self, script_id: str) -> dict[str, Any]:
        if not script_id or len(script_id.encode("utf-8")) > 4_096:
            raise DebuggerBridgeError("Script ID is invalid")
        with self._lock:
            script = self._scripts.get(script_id)
            if script is None:
                raise DebuggerBridgeError("Script is unavailable")
            if script["length"] > MAX_SCRIPT_SOURCE_BYTES:
                raise DebuggerBridgeError("Live script exceeds the 2 MiB viewer limit")
        result = self._command(
            "Debugger.getScriptSource", {"scriptId": script_id}, timeout=5.0
        )
        source = result.get("scriptSource")
        if not isinstance(source, str):
            bytecode = result.get("bytecode")
            if not isinstance(bytecode, str):
                raise DebuggerBridgeError("Debugger returned malformed script source")
            source = bytecode
        encoded = source.encode("utf-8")
        truncated = len(encoded) > MAX_SCRIPT_SOURCE_BYTES
        if truncated:
            encoded = encoded[:MAX_SCRIPT_SOURCE_BYTES]
            source = encoded.decode("utf-8", errors="replace")
        return {
            "protocol_version": 1,
            "script_id": script_id,
            "source": source,
            "truncated": truncated,
        }

    def _search_live_objects(self, request: dict[str, Any]) -> dict[str, Any]:
        criteria = live_object_search_criteria(request)
        prototype_id: Optional[str] = None
        objects_id: Optional[str] = None
        try:
            prototype = self._command(
                "Runtime.evaluate",
                {
                    "expression": "Object.prototype",
                    "objectGroup": "reb-live-object-search",
                    "silent": True,
                },
            )
            prototype_id = runtime_result_object_id(prototype, "prototype")
            objects = self._command(
                "Runtime.queryObjects", {"prototypeObjectId": prototype_id}, timeout=5.0
            )
            objects_id = runtime_result_object_id(
                objects, "object collection", field="objects"
            )
            evaluated = self._command(
                "Runtime.callFunctionOn",
                {
                    "objectId": objects_id,
                    "functionDeclaration": LIVE_OBJECT_SEARCH_FUNCTION,
                    "arguments": [{"value": criteria}],
                    "returnByValue": True,
                    "silent": True,
                    "awaitPromise": False,
                    "userGesture": False,
                    "timeout": LIVE_OBJECT_SEARCH_TIMEOUT_MS,
                },
                timeout=3.0,
            )
        finally:
            for object_id in (objects_id, prototype_id):
                if object_id is None:
                    continue
                try:
                    self._command("Runtime.releaseObject", {"objectId": object_id})
                except DebuggerBridgeError:
                    pass

        if isinstance(evaluated.get("exceptionDetails"), dict):
            raise DebuggerBridgeError("Live object search failed in the target")
        remote = evaluated.get("result")
        document = remote.get("value") if isinstance(remote, dict) else None
        return self._normalize_live_object_search(document)


    def _normalize_live_object_search(self, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict) or value.get("protocolVersion") != 2:
            raise ProtocolError("Debugger returned a malformed live object search")
        integer_fields = (
            "analyzed",
            "totalObjects",
            "resultLimit",
            "durationMs",
        )
        if any(
            not isinstance(value.get(field), int)
            or isinstance(value.get(field), bool)
            or value[field] < 0
            or value[field] > 2**53 - 1
            for field in integer_fields
        ):
            raise ProtocolError("Debugger returned invalid live object search counts")
        if value["resultLimit"] != MAX_LIVE_OBJECT_RESULTS:
            raise ProtocolError("Debugger returned an invalid live object result limit")
        boolean_fields = (
            "resultLimitReached",
            "scanLimitReached",
            "propertyLimitReached",
            "timedOut",
        )
        if any(not isinstance(value.get(field), bool) for field in boolean_fields):
            raise ProtocolError("Debugger returned invalid live object coverage")
        raw_results = value.get("results")
        if not isinstance(raw_results, list) or len(raw_results) > MAX_LIVE_OBJECT_RESULTS:
            raise ProtocolError("Debugger returned too many live object results")
        results = []
        for raw_result in raw_results:
            if not isinstance(raw_result, dict):
                raise ProtocolError("Debugger returned a malformed live object result")
            result_id = raw_result.get("id")
            class_name = raw_result.get("className")
            property_count = raw_result.get("propertyCount")
            properties_truncated = raw_result.get("propertiesTruncated")
            similarity = raw_result.get("similarity")
            preview = raw_result.get("preview")
            if (
                not isinstance(result_id, str)
                or not isinstance(class_name, str)
                or not isinstance(property_count, int)
                or isinstance(property_count, bool)
                or property_count < 0
                or property_count > 2**31 - 1
                or not isinstance(properties_truncated, bool)
                or (
                    similarity is not None
                    and (
                        not is_finite_protocol_number(similarity)
                        or isinstance(similarity, bool)
                        or similarity < 0
                        or similarity > 1
                    )
                )
                or not isinstance(preview, list)
                or len(preview) > MAX_LIVE_OBJECT_PREVIEW_PROPERTIES
            ):
                raise ProtocolError("Debugger returned a malformed live object result")
            properties = []
            for raw_property in preview:
                if not isinstance(raw_property, dict) or any(
                    not isinstance(raw_property.get(field), str)
                    for field in ("name", "type", "value")
                ):
                    raise ProtocolError(
                        "Debugger returned a malformed live object preview"
                    )
                properties.append(
                    {
                        "name": truncate_text(raw_property["name"]),
                        "type": truncate_text(raw_property["type"], 128),
                        "value": truncate_text(raw_property["value"]),
                    }
                )
            results.append(
                {
                    "id": truncate_text(result_id, 128),
                    "class_name": truncate_text(class_name, 256),
                    "property_count": property_count,
                    "properties_truncated": properties_truncated,
                    "similarity": float(similarity)
                    if similarity is not None
                    else None,
                    "preview": properties,
                }
            )
        return {
            "ok": True,
            "search": {
                "protocol_version": 2,
                "analyzed": value["analyzed"],
                "total_objects": value["totalObjects"],
                "result_limit": value["resultLimit"],
                "result_limit_reached": value["resultLimitReached"],
                "scan_limit_reached": value["scanLimitReached"],
                "property_limit_reached": value["propertyLimitReached"],
                "timed_out": value["timedOut"],
                "duration_ms": value["durationMs"],
                "results": results,
            },
            "generation": self.generation(),
        }

    def _clear_object_experiment_search_locked(self) -> Optional[str]:
        group = self._object_experiment_group
        releasable_group = (
            group
            if group is not None
            and self._connection is not None
            and self._target is not None
            and self._target["id"] == self._object_experiment.get("target_id")
            else None
        )
        self._object_experiment_group = None
        self._object_experiment_objects_id = None
        self._object_experiment_result_indices.clear()
        self._object_experiment["search_id"] = 0
        self._object_experiment["search"] = None
        self._object_experiment["results"] = []
        self._object_experiment["last_mutation"] = None
        return releasable_group

    def _release_object_experiment_group(self, group: Optional[str]) -> None:
        if group is not None:
            try:
                self._command("Runtime.releaseObjectGroup", {"objectGroup": group})
            except DebuggerBridgeError:
                pass

    def _release_object_experiment_search(self) -> None:
        with self._lock:
            group = self._clear_object_experiment_search_locked()
        self._release_object_experiment_group(group)

    def _require_object_experiment_target_locked(
        self, require_navigation: bool
    ) -> None:
        if self._object_experiment["state"] in {
            "navigating",
            "searching",
            "mutating",
        }:
            raise DebuggerBridgeError(
                "Object Lab is already running an isolated-page action"
            )
        if (
            self._request_interception_context_id is None
            or not self._object_experiment["isolated"]
            or self._object_experiment["target_id"] is None
            or self._target is None
            or self._target["id"] != self._object_experiment["target_id"]
            or self._state not in {"running", "paused"}
        ):
            raise DebuggerBridgeError(
                "Object Lab requires its attached disposable Experiment page"
            )
        if self._request_interception_pending:
            raise DebuggerBridgeError(
                "Wait for paused Experiment requests before using Object Lab"
            )
        if require_navigation and (
            self._object_experiment["navigation_id"] <= 0
            or not self._object_experiment["url"]
        ):
            raise DebuggerBridgeError(
                "Open an HTTP or HTTPS page in Object Lab before searching"
            )

    def _navigate_object_experiment(
        self, request: dict[str, Any]
    ) -> dict[str, Any]:
        url = required_text(
            request, "url", MAX_INTERCEPTION_URL_BYTES
        ).strip()
        validate_request_interception_url(url)
        with self._lock:
            self._require_object_experiment_target_locked(require_navigation=False)
            stale_group = self._clear_object_experiment_search_locked()
            navigation_id = self._next_object_experiment_navigation_id
            self._next_object_experiment_navigation_id += 1
            self._object_experiment["state"] = "navigating"
            self._object_experiment["navigation_id"] = navigation_id
            self._object_experiment["url"] = redacted_request_url(url)
            self._object_experiment["message"] = (
                "Opening one credential-free page inside the disposable context."
            )
            self._changed()
        self._release_object_experiment_group(stale_group)

        try:
            navigation = self._command(
                "Page.navigate", {"url": url}, timeout=5.0
            )
            error_text = navigation.get("errorText")
            if isinstance(error_text, str) and error_text:
                raise DebuggerBridgeError(
                    truncate_text(f"Object Lab navigation failed: {error_text}", 512)
                )
            deadline = time.monotonic() + OBJECT_EXPERIMENT_NAVIGATION_TIMEOUT_SECONDS
            loaded_url = url
            while True:
                if time.monotonic() >= deadline:
                    raise DebuggerBridgeError(
                        "Object Lab page did not become interactive within 15 seconds"
                    )
                try:
                    evaluated = self._command(
                        "Runtime.evaluate",
                        {
                            "expression": (
                                "({protocolVersion:1,readyState:document.readyState,"
                                "url:location.href})"
                            ),
                            "returnByValue": True,
                            "silent": True,
                            "throwOnSideEffect": True,
                        },
                        timeout=2.0,
                    )
                    if isinstance(evaluated.get("exceptionDetails"), dict):
                        raise DebuggerBridgeError("Navigation is still replacing the page")
                    remote = evaluated.get("result")
                    status = remote.get("value") if isinstance(remote, dict) else None
                    if (
                        isinstance(status, dict)
                        and status.get("protocolVersion") == 1
                        and status.get("readyState") in {"interactive", "complete"}
                        and isinstance(status.get("url"), str)
                    ):
                        loaded_url = status["url"]
                        break
                except DebuggerBridgeError:
                    pass
                time.sleep(0.05)
            final_url = urlunparse(urlparse(loaded_url)._replace(fragment=""))
            validate_request_interception_url(final_url)
        except DebuggerBridgeError as exception:
            with self._lock:
                if self._object_experiment["navigation_id"] == navigation_id:
                    self._object_experiment["state"] = "error"
                    self._object_experiment["message"] = truncate_text(
                        str(exception), 512
                    )
                    self._changed()
            raise

        with self._lock:
            if self._object_experiment["navigation_id"] != navigation_id:
                raise DebuggerBridgeError("Object Lab navigation became stale")
            self._object_experiment["state"] = "loaded"
            self._object_experiment["url"] = redacted_request_url(loaded_url)
            self._object_experiment["message"] = (
                "Isolated page loaded. Run a bounded live-object search."
            )
            self._changed()
            experiment = copy.deepcopy(self._object_experiment)
        return {
            "ok": True,
            "object_experiment": experiment,
            "generation": self.generation(),
        }

    def _search_object_experiment(
        self, request: dict[str, Any]
    ) -> dict[str, Any]:
        criteria = live_object_search_criteria(request)
        with self._lock:
            self._require_object_experiment_target_locked(require_navigation=True)
            stale_group = self._clear_object_experiment_search_locked()
            search_id = self._next_object_experiment_search_id
            self._next_object_experiment_search_id += 1
            session_id = self._object_experiment["session_id"]
            navigation_id = self._object_experiment["navigation_id"]
            target_id = self._object_experiment["target_id"]
            group = f"reb-object-experiment-{session_id}-{navigation_id}-{search_id}"
            self._object_experiment["state"] = "searching"
            self._object_experiment["message"] = (
                "Searching the isolated page without invoking property getters."
            )
            self._changed()
        self._release_object_experiment_group(stale_group)

        prototype_id: Optional[str] = None
        objects_id: Optional[str] = None
        try:
            prototype = self._command(
                "Runtime.evaluate",
                {
                    "expression": "Object.prototype",
                    "objectGroup": group,
                    "silent": True,
                },
            )
            prototype_id = runtime_result_object_id(prototype, "prototype")
            objects = self._command(
                "Runtime.queryObjects",
                {"prototypeObjectId": prototype_id, "objectGroup": group},
                timeout=5.0,
            )
            objects_id = runtime_result_object_id(
                objects, "object collection", field="objects"
            )
            evaluated = self._command(
                "Runtime.callFunctionOn",
                {
                    "objectId": objects_id,
                    "functionDeclaration": LIVE_OBJECT_SEARCH_FUNCTION,
                    "arguments": [{"value": criteria}],
                    "returnByValue": True,
                    "silent": True,
                    "awaitPromise": False,
                    "userGesture": False,
                    "timeout": LIVE_OBJECT_SEARCH_TIMEOUT_MS,
                },
                timeout=3.0,
            )
            if isinstance(evaluated.get("exceptionDetails"), dict):
                raise DebuggerBridgeError("Live object search failed in Object Lab")
            remote = evaluated.get("result")
            document = remote.get("value") if isinstance(remote, dict) else None
            normalized = self._normalize_live_object_search(document)["search"]
            indices: set[int] = set()
            for result in normalized["results"]:
                if not result["id"].isdigit():
                    raise ProtocolError("Object Lab returned an invalid result identifier")
                index = int(result["id"])
                if index >= normalized["total_objects"] or index in indices:
                    raise ProtocolError("Object Lab returned a stale result identifier")
                indices.add(index)
        except DebuggerBridgeError as exception:
            try:
                self._command("Runtime.releaseObjectGroup", {"objectGroup": group})
            except DebuggerBridgeError:
                pass
            with self._lock:
                if (
                    self._object_experiment["session_id"] == session_id
                    and self._object_experiment["navigation_id"] == navigation_id
                ):
                    self._object_experiment["state"] = "error"
                    self._object_experiment["message"] = truncate_text(
                        str(exception), 512
                    )
                    self._changed()
            raise
        finally:
            if prototype_id is not None:
                try:
                    self._command("Runtime.releaseObject", {"objectId": prototype_id})
                except DebuggerBridgeError:
                    pass

        stale = False
        with self._lock:
            stale = (
                self._object_experiment["session_id"] != session_id
                or self._object_experiment["navigation_id"] != navigation_id
                or self._object_experiment["target_id"] != target_id
            )
            if not stale:
                self._object_experiment_group = group
                self._object_experiment_objects_id = objects_id
                self._object_experiment_result_indices = indices
                self._object_experiment["state"] = "loaded"
                self._object_experiment["search_id"] = search_id
                self._object_experiment["search"] = {
                    key: value for key, value in normalized.items() if key != "results"
                }
                self._object_experiment["results"] = normalized["results"]
                self._object_experiment["message"] = (
                    f"Found {len(normalized['results'])} matching live objects in the isolated page."
                )
                self._changed()
                experiment = copy.deepcopy(self._object_experiment)
        if stale:
            try:
                self._command("Runtime.releaseObjectGroup", {"objectGroup": group})
            except DebuggerBridgeError:
                pass
            raise DebuggerBridgeError("Object Lab search became stale")
        return {
            "ok": True,
            "object_experiment": experiment,
            "generation": self.generation(),
        }

    def _mutate_object_experiment(
        self, request: dict[str, Any]
    ) -> dict[str, Any]:
        operation = request.get("operation")
        if operation not in {"set", "delete"}:
            raise DebuggerBridgeError("Object Lab mutation operation is invalid")
        if request.get("confirmed") is not True:
            raise DebuggerBridgeError("Object Lab mutation requires explicit confirmation")
        search_id = request.get("search_id")
        if (
            not isinstance(search_id, int)
            or isinstance(search_id, bool)
            or search_id <= 0
            or search_id > 2**53 - 1
        ):
            raise DebuggerBridgeError("Object Lab search identifier is invalid")
        result_id = required_text(request, "result_id", 128)
        if not result_id.isdigit():
            raise DebuggerBridgeError("Object Lab result identifier is invalid")
        result_index = int(result_id)
        property_name = required_text(
            request, "property", MAX_OBJECT_EXPERIMENT_PROPERTY_BYTES
        )
        if (
            property_name in FORBIDDEN_OBJECT_EXPERIMENT_PROPERTIES
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in property_name)
        ):
            raise DebuggerBridgeError("Object Lab property name is not allowed")

        value: Any = None
        value_bytes = 0
        value_digest: Optional[str] = None
        if operation == "set":
            if "value" not in request:
                raise DebuggerBridgeError("Object Lab set requires a JSON value")
            value, canonical = normalize_object_experiment_value(request["value"])
            value_bytes = len(canonical)
            value_digest = hashlib.sha256(canonical).hexdigest()
        elif "value" in request:
            raise DebuggerBridgeError("Object Lab delete does not accept a value")

        with self._lock:
            self._require_object_experiment_target_locked(require_navigation=True)
            if (
                self._object_experiment["search_id"] != search_id
                or self._object_experiment_objects_id is None
                or self._object_experiment_group is None
                or result_index not in self._object_experiment_result_indices
            ):
                raise DebuggerBridgeError(
                    "Object Lab result is stale; run the live-object search again"
                )
            if (
                self._object_experiment["mutation_attempts"]
                >= MAX_OBJECT_EXPERIMENT_MUTATIONS
            ):
                raise DebuggerBridgeError(
                    "Object Lab reached the 256-attempt session limit"
                )
            selected = next(
                (
                    result
                    for result in self._object_experiment["results"]
                    if result["id"] == result_id
                ),
                None,
            )
            if selected is None:
                raise DebuggerBridgeError("Object Lab result is unavailable")
            objects_id = self._object_experiment_objects_id
            group = self._object_experiment_group
            session_id = self._object_experiment["session_id"]
            navigation_id = self._object_experiment["navigation_id"]
            target_class = selected["class_name"]
            similarity = selected["similarity"]
            self._object_experiment["mutation_attempts"] += 1
            self._object_experiment["state"] = "mutating"
            self._object_experiment["message"] = (
                f"Applying one confirmed {operation} operation inside Object Lab."
            )
            self._changed()

        candidate_id: Optional[str] = None
        try:
            candidate = self._command(
                "Runtime.callFunctionOn",
                {
                    "objectId": objects_id,
                    "functionDeclaration": (
                        "function(index){const value=this[index];"
                        "if((typeof value!==\"object\"&&typeof value!==\"function\")||value===null)"
                        "throw new TypeError(\"Object Lab result is unavailable\");return value;}"
                    ),
                    "arguments": [{"value": result_index}],
                    "returnByValue": False,
                    "objectGroup": group,
                    "silent": True,
                },
            )
            if isinstance(candidate.get("exceptionDetails"), dict):
                raise DebuggerBridgeError("Object Lab result is no longer available")
            candidate_id = runtime_result_object_id(candidate, "object result")
            config: dict[str, Any] = {
                "operation": operation,
                "property": property_name,
                "previewProperties": MAX_LIVE_OBJECT_PREVIEW_PROPERTIES,
                "resultId": result_id,
                "similarity": similarity,
            }
            if operation == "set":
                config["value"] = value
            evaluated = self._command(
                "Runtime.callFunctionOn",
                {
                    "objectId": candidate_id,
                    "functionDeclaration": OBJECT_EXPERIMENT_MUTATE_FUNCTION,
                    "arguments": [{"value": config}],
                    "returnByValue": True,
                    "silent": True,
                    "awaitPromise": False,
                    "userGesture": False,
                    "timeout": 1_000,
                },
                timeout=3.0,
            )
            if isinstance(evaluated.get("exceptionDetails"), dict):
                raise DebuggerBridgeError("Object Lab mutation failed in the target")
            remote = evaluated.get("result")
            document = remote.get("value") if isinstance(remote, dict) else None
            mutation = self._normalize_object_experiment_mutation(document)
        except DebuggerBridgeError as exception:
            mutation = {
                "ok": False,
                "outcome": "error",
                "error": truncate_text(str(exception), 512),
                "before": empty_object_experiment_descriptor("unknown"),
                "after": empty_object_experiment_descriptor("unknown"),
                "object": None,
            }
        finally:
            if candidate_id is not None:
                try:
                    self._command("Runtime.releaseObject", {"objectId": candidate_id})
                except DebuggerBridgeError:
                    pass

        with self._lock:
            if (
                self._object_experiment["session_id"] != session_id
                or self._object_experiment["navigation_id"] != navigation_id
            ):
                raise DebuggerBridgeError("Object Lab mutation became stale")
            search_invalidated = self._object_experiment["search_id"] != search_id
            audit = self._append_object_experiment_audit_locked(
                operation=operation,
                property_name=property_name,
                result_id=result_id,
                search_id=search_id,
                target_class=target_class,
                mutation=mutation,
                value_bytes=value_bytes,
                value_digest=value_digest,
            )
            if mutation["object"] is not None and not search_invalidated:
                self._object_experiment["results"] = [
                    mutation["object"] if result["id"] == result_id else result
                    for result in self._object_experiment["results"]
                ]
            if not search_invalidated:
                self._object_experiment["state"] = "loaded"
            self._object_experiment["last_mutation"] = {
                "audit_id": audit["id"],
                "ok": mutation["ok"],
                "operation": operation,
                "property": property_name,
                "result_id": result_id,
                "outcome": mutation["outcome"],
                "error": mutation["error"],
                "before": mutation["before"],
                "after": mutation["after"],
                "value_bytes": value_bytes,
                "value_digest": value_digest,
            }
            self._object_experiment["message"] = (
                f"Object Lab {operation} completed and audit entry {audit['id']} was recorded."
                if mutation["ok"]
                else f"Object Lab rejected the mutation: {mutation['error']}"
            )
            if search_invalidated:
                self._object_experiment["message"] += (
                    " The target disconnected, so run the search again."
                )
            self._changed()
            experiment = copy.deepcopy(self._object_experiment)
        return {
            "ok": True,
            "object_experiment": experiment,
            "generation": self.generation(),
        }


    def _normalize_object_experiment_mutation(self, value: Any) -> dict[str, Any]:
        outcomes = {
            "created",
            "updated",
            "deleted",
            "missing",
            "non_configurable",
            "rejected",
            "accessor",
            "non_writable",
            "non_extensible",
            "error",
        }
        if (
            not isinstance(value, dict)
            or value.get("protocolVersion") != 1
            or not isinstance(value.get("ok"), bool)
            or value.get("outcome") not in outcomes
        ):
            raise ProtocolError("Object Lab returned a malformed mutation result")
        error = value.get("error")
        if error is not None and (
            not isinstance(error, str) or len(error.encode("utf-8")) > 512
        ):
            raise ProtocolError("Object Lab returned an invalid mutation error")
        if value["ok"] != (error is None):
            raise ProtocolError("Object Lab returned an inconsistent mutation result")
        before = normalize_object_experiment_descriptor(value.get("before"))
        after = normalize_object_experiment_descriptor(value.get("after"))
        raw_object = value.get("object")
        normalized_object = None
        if raw_object is not None:
            synthetic = {
                "protocolVersion": 2,
                "analyzed": 1,
                "totalObjects": 1,
                "resultLimit": MAX_LIVE_OBJECT_RESULTS,
                "resultLimitReached": False,
                "scanLimitReached": False,
                "propertyLimitReached": False,
                "timedOut": False,
                "durationMs": 0,
                "results": [raw_object],
            }
            normalized_object = self._normalize_live_object_search(synthetic)["search"][
                "results"
            ][0]
        if value["ok"] and normalized_object is None:
            raise ProtocolError("Object Lab omitted the patched object preview")
        return {
            "ok": value["ok"],
            "outcome": value["outcome"],
            "error": error,
            "before": before,
            "after": after,
            "object": normalized_object,
        }

    def _append_object_experiment_audit_locked(
        self,
        *,
        operation: str,
        property_name: str,
        result_id: str,
        search_id: int,
        target_class: str,
        mutation: dict[str, Any],
        value_bytes: int,
        value_digest: Optional[str],
    ) -> dict[str, Any]:
        entry = {
            "id": self._next_object_experiment_audit_id,
            "occurred_at_ms": int(time.time() * 1_000),
            "session_id": self._object_experiment["session_id"],
            "navigation_id": self._object_experiment["navigation_id"],
            "search_id": search_id,
            "result_id": result_id,
            "operation": operation,
            "property": property_name,
            "target_class": truncate_text(target_class, 256),
            "outcome": mutation["outcome"],
            "success": mutation["ok"],
            "before_type": mutation["before"]["type"],
            "after_type": mutation["after"]["type"],
            "value_bytes": value_bytes,
            "value_digest": value_digest,
            "url": self._object_experiment["url"],
        }
        self._next_object_experiment_audit_id += 1
        audit = self._object_experiment["audit"]
        audit.append(entry)
        if len(audit) > MAX_OBJECT_EXPERIMENT_AUDIT_ENTRIES:
            del audit[: len(audit) - MAX_OBJECT_EXPERIMENT_AUDIT_ENTRIES]
            self._object_experiment["audit_evictions"] += 1
        return entry

    def _runtime_hook_target_ready_locked(self) -> None:
        if (
            self._request_interception_context_id is None
            or not self._runtime_hooks["isolated"]
            or self._runtime_hooks["target_id"] is None
            or self._target is None
            or self._target["id"] != self._runtime_hooks["target_id"]
            or self._state not in {"running", "paused"}
        ):
            raise DebuggerBridgeError(
                "Runtime Hooks requires its attached disposable Experiment page"
            )
        if self._request_interception_pending:
            raise DebuggerBridgeError(
                "Wait for paused Experiment requests before using Runtime Hooks"
            )
        if self._runtime_hook_processing:
            raise DebuggerBridgeError("Runtime Hooks is handling a function call")


    def _normalize_runtime_hook_definition(
        self, request: dict[str, Any]
    ) -> dict[str, Any]:
        label = runtime_hook_text(
            request, "label", MAX_RUNTIME_HOOK_LABEL_BYTES
        ).strip()
        if not label:
            raise DebuggerBridgeError("Runtime Hooks label is required")
        script_id = required_text(request, "script_id", MAX_TARGET_ID_BYTES)
        line = request.get("line")
        column = request.get("column", 0)
        if not all(
            isinstance(value, int) and not isinstance(value, bool)
            for value in (line, column)
        ) or not (0 <= line < 2**31 and 0 <= column < 2**31):
            raise DebuggerBridgeError("Runtime Hooks source location is invalid")
        entry_enabled = request.get("entry_enabled", True)
        return_enabled = request.get("return_enabled", True)
        if not isinstance(entry_enabled, bool) or not isinstance(return_enabled, bool):
            raise DebuggerBridgeError("Runtime Hooks phases must be boolean")
        if not entry_enabled and not return_enabled:
            raise DebuggerBridgeError("Runtime Hooks requires an entry or return phase")
        condition = runtime_hook_text(
            request, "condition", MAX_RUNTIME_HOOK_CONDITION_BYTES
        )
        entry_logic = runtime_hook_text(
            request, "entry_logic", MAX_RUNTIME_HOOK_LOGIC_BYTES
        )
        return_logic = runtime_hook_text(
            request, "return_logic", MAX_RUNTIME_HOOK_LOGIC_BYTES
        )
        return_mode = request.get("return_mode", "none")
        if return_mode not in {"none", "json", "expression"}:
            raise DebuggerBridgeError("Runtime Hooks return mode is invalid")
        return_expression = ""
        return_value: Any = None
        return_value_bytes = 0
        if return_mode == "expression":
            return_expression = runtime_hook_text(
                request, "return_expression", MAX_RUNTIME_HOOK_RETURN_BYTES
            ).strip()
            if not return_expression:
                raise DebuggerBridgeError(
                    "Runtime Hooks return expression is required"
                )
        elif return_mode == "json":
            if "return_value" not in request:
                raise DebuggerBridgeError("Runtime Hooks JSON replacement is required")
            return_value, canonical = normalize_runtime_hook_json(
                request["return_value"]
            )
            return_value_bytes = len(canonical)
        if return_mode != "none" and not return_enabled:
            raise DebuggerBridgeError(
                "Runtime Hooks return replacement requires the return phase"
            )
        with self._lock:
            script = self._scripts.get(script_id)
            if script is None or script["language"] != "JavaScript":
                raise DebuggerBridgeError(
                    "Runtime Hooks requires a live JavaScript source"
                )
            if line < script["start_line"] or line > script["end_line"]:
                raise DebuggerBridgeError(
                    "Runtime Hooks location is outside the selected script"
                )
            source_url = runtime_hook_source_label(script["url"])
        return {
            "id": 0,
            "label": label,
            "script_id": script_id,
            "url": source_url,
            "line": line,
            "column": column,
            "entry_enabled": entry_enabled,
            "return_enabled": return_enabled,
            "condition": condition,
            "entry_logic": entry_logic,
            "return_logic": return_logic,
            "return_mode": return_mode,
            "return_expression": return_expression,
            "return_value": return_value,
            "return_value_bytes": return_value_bytes,
            "resolved": None,
        }

    def _add_runtime_hook(self, request: dict[str, Any]) -> dict[str, Any]:
        definition = self._normalize_runtime_hook_definition(request)
        with self._lock:
            self._runtime_hook_target_ready_locked()
            if self._runtime_hooks["state"] in {
                "arming",
                "armed",
                "handling",
                "stopping",
            }:
                raise DebuggerBridgeError(
                    "Disarm Runtime Hooks before changing definitions"
                )
            definitions = self._runtime_hooks["definitions"]
            if len(definitions) >= MAX_RUNTIME_HOOKS:
                raise DebuggerBridgeError("Runtime Hooks reached the 8-definition limit")
            if any(
                item["script_id"] == definition["script_id"]
                and item["line"] == definition["line"]
                and item["column"] == definition["column"]
                for item in definitions
            ):
                raise DebuggerBridgeError(
                    "A Runtime Hook already uses this script location"
                )
            definition["id"] = self._next_runtime_hook_id
            self._next_runtime_hook_id += 1
            definitions.append(definition)
            self._runtime_hooks["state"] = "ready"
            self._runtime_hooks["last_failure"] = None
            self._runtime_hooks["message"] = (
                f"Added {definition['label']}. Confirm mutation permission to arm."
            )
            self._changed()
            hooks = copy.deepcopy(self._runtime_hooks)
        return {"ok": True, "runtime_hooks": hooks, "generation": self.generation()}

    def _remove_runtime_hook(self, request: dict[str, Any]) -> dict[str, Any]:
        hook_id = request.get("hook_id")
        if (
            not isinstance(hook_id, int)
            or isinstance(hook_id, bool)
            or hook_id <= 0
        ):
            raise DebuggerBridgeError("Runtime Hooks definition identifier is invalid")
        with self._lock:
            self._runtime_hook_target_ready_locked()
            if self._runtime_hooks["state"] in {
                "arming",
                "armed",
                "handling",
                "stopping",
            }:
                raise DebuggerBridgeError(
                    "Disarm Runtime Hooks before changing definitions"
                )
            before = len(self._runtime_hooks["definitions"])
            self._runtime_hooks["definitions"] = [
                item
                for item in self._runtime_hooks["definitions"]
                if item["id"] != hook_id
            ]
            if len(self._runtime_hooks["definitions"]) == before:
                raise DebuggerBridgeError("Runtime Hooks definition is unavailable")
            self._runtime_hooks["message"] = "Runtime Hook definition removed."
            self._changed()
            hooks = copy.deepcopy(self._runtime_hooks)
        return {"ok": True, "runtime_hooks": hooks, "generation": self.generation()}

    def _runtime_hook_possible_locations(
        self, definition: dict[str, Any]
    ) -> list[dict[str, Any]]:
        result = self._command(
            "Debugger.getPossibleBreakpoints",
            {
                "start": {
                    "scriptId": definition["script_id"],
                    "lineNumber": definition["line"],
                    "columnNumber": definition["column"],
                },
                "restrictToFunction": True,
            },
            timeout=3.0,
        )
        raw_locations = result.get("locations")
        if not isinstance(raw_locations, list):
            raise ProtocolError("Debugger returned malformed hook locations")
        first_location = None
        return_locations = []
        return_keys: set[tuple[str, int, int]] = set()
        for raw in raw_locations:
            location = self._parse_location(raw)
            if location is None or location["script_id"] != definition["script_id"]:
                continue
            location["type"] = (
                raw.get("type")
                if isinstance(raw, dict)
                and raw.get("type") in {"debuggerStatement", "call", "return"}
                else "other"
            )
            if first_location is None:
                first_location = location
            if location["type"] != "return" or not definition["return_enabled"]:
                continue
            key = (location["script_id"], location["line"], location["column"])
            if key in return_keys:
                continue
            if len(return_locations) >= MAX_RUNTIME_HOOK_RETURN_POINTS:
                raise DebuggerBridgeError(
                    f"{definition['label']} exceeds 32 synchronous return points"
                )
            return_keys.add(key)
            return_locations.append(location)
        if first_location is None:
            raise DebuggerBridgeError(
                f"No breakable function was found for {definition['label']}"
            )
        first_key = (
            first_location["script_id"],
            first_location["line"],
            first_location["column"],
        )
        return [
            first_location,
            *(
                location
                for location in return_locations
                if (
                    location["script_id"],
                    location["line"],
                    location["column"],
                )
                != first_key
            ),
        ]

    def _arm_runtime_hooks(self, request: dict[str, Any]) -> dict[str, Any]:
        if request.get("confirmed") is not True:
            raise DebuggerBridgeError(
                "Runtime Hooks requires explicit isolated-page mutation confirmation"
            )
        with self._lock:
            self._runtime_hook_target_ready_locked()
            if not self._runtime_hooks["definitions"]:
                raise DebuggerBridgeError("Add a Runtime Hook before arming")
            if not self._breakpoints_active:
                raise DebuggerBridgeError(
                    "Activate debugger breakpoints before arming Runtime Hooks"
                )
            if self._runtime_hooks["state"] in {
                "arming",
                "armed",
                "handling",
                "stopping",
            }:
                raise DebuggerBridgeError("Runtime Hooks is already active")
            self._runtime_hook_epoch += 1
            epoch = self._runtime_hook_epoch
            definitions = copy.deepcopy(self._runtime_hooks["definitions"])
            self._runtime_hook_stop_requested = False
            self._runtime_hook_deferred_pause = None
            self._runtime_hooks["state"] = "arming"
            self._runtime_hooks["last_failure"] = None
            self._runtime_hooks["message"] = (
                "Resolving bounded entry and synchronous return points."
            )
            self._changed()

        point_specs: list[dict[str, Any]] = []
        installed: dict[str, dict[str, Any]] = {}
        try:
            for definition in definitions:
                locations = self._runtime_hook_possible_locations(definition)
                returns = [item for item in locations if item["type"] == "return"]
                if definition["return_enabled"] and not returns:
                    raise DebuggerBridgeError(
                        f"{definition['label']} has no synchronous return point"
                    )
                by_location: dict[tuple[str, int, int], dict[str, Any]] = {}
                if definition["entry_enabled"]:
                    entry = locations[0]
                    key = (entry["script_id"], entry["line"], entry["column"])
                    by_location[key] = {
                        "hook_id": definition["id"],
                        "location": entry,
                        "phases": ["entry"],
                    }
                if definition["return_enabled"]:
                    for location in returns:
                        key = (
                            location["script_id"],
                            location["line"],
                            location["column"],
                        )
                        spec = by_location.setdefault(
                            key,
                            {
                                "hook_id": definition["id"],
                                "location": location,
                                "phases": [],
                            },
                        )
                        if "return" not in spec["phases"]:
                            spec["phases"].append("return")
                definition["resolved"] = {
                    "entry_points": 1 if definition["entry_enabled"] else 0,
                    "return_points": len(returns)
                    if definition["return_enabled"]
                    else 0,
                }
                point_specs.extend(by_location.values())
                with self._lock:
                    if self._runtime_hook_stop_requested or epoch != self._runtime_hook_epoch:
                        raise DebuggerBridgeError("Runtime Hooks arming was cancelled")
            if len(point_specs) > MAX_RUNTIME_HOOK_BREAKPOINTS:
                raise DebuggerBridgeError(
                    "Runtime Hooks exceeds the 64 active-point limit"
                )
            for spec in point_specs:
                location = spec["location"]
                result = self._command(
                    "Debugger.setBreakpoint",
                    {
                        "location": {
                            "scriptId": location["script_id"],
                            "lineNumber": location["line"],
                            "columnNumber": location["column"],
                        }
                    },
                )
                breakpoint_id = required_protocol_identifier(
                    result.get("breakpointId"), "runtime hook breakpoint"
                )
                installed[breakpoint_id] = spec
                with self._lock:
                    if self._runtime_hook_stop_requested or epoch != self._runtime_hook_epoch:
                        raise DebuggerBridgeError("Runtime Hooks arming was cancelled")
        except BaseException as exception:
            for breakpoint_id in installed:
                try:
                    self._command(
                        "Debugger.removeBreakpoint", {"breakpointId": breakpoint_id}
                    )
                except DebuggerBridgeError:
                    pass
            with self._lock:
                if epoch == self._runtime_hook_epoch:
                    self._runtime_hook_points.clear()
                    self._runtime_hooks["active_points"] = 0
                    self._runtime_hooks["state"] = "disarmed"
                    self._runtime_hooks["last_failure"] = truncate_text(
                        str(exception), 512
                    )
                    self._runtime_hooks["message"] = (
                        "No hook points were left armed. Fix the definition and try again."
                    )
                    self._runtime_hook_stop_requested = False
                    self._runtime_hook_deferred_pause = None
                    self._changed()
            raise

        with self._lock:
            if epoch != self._runtime_hook_epoch:
                raise DebuggerBridgeError("Runtime Hooks arming became stale")
            resolved_by_id = {item["id"]: item["resolved"] for item in definitions}
            for definition in self._runtime_hooks["definitions"]:
                definition["resolved"] = resolved_by_id.get(definition["id"])
            self._runtime_hook_points = installed
            self._runtime_hooks["active_points"] = len(installed)
            self._runtime_hooks["state"] = "armed"
            self._runtime_hooks["message"] = (
                f"Armed {len(definitions)} hooks across {len(installed)} bounded points."
            )
            self._changed()
            hooks = copy.deepcopy(self._runtime_hooks)
        return {"ok": True, "runtime_hooks": hooks, "generation": self.generation()}

    def _remove_runtime_hook_points(
        self, reason: str, expected_epoch: Optional[int] = None
    ) -> None:
        with self._lock:
            if expected_epoch is not None and expected_epoch != self._runtime_hook_epoch:
                return
            self._runtime_hook_epoch += 1
            epoch = self._runtime_hook_epoch
            breakpoint_ids = list(self._runtime_hook_points)
            self._runtime_hook_stop_requested = True
            self._runtime_hooks["state"] = "stopping"
            self._runtime_hooks["message"] = "Removing Runtime Hooks breakpoints."
            self._changed()
        failures = 0
        for breakpoint_id in breakpoint_ids:
            try:
                self._command(
                    "Debugger.removeBreakpoint", {"breakpointId": breakpoint_id}
                )
            except DebuggerBridgeError:
                failures += 1
        with self._lock:
            if epoch != self._runtime_hook_epoch:
                return
            self._runtime_hook_points.clear()
            self._runtime_hooks["active_points"] = 0
            self._runtime_hook_processing = False
            self._runtime_hook_stop_requested = False
            self._runtime_hook_deferred_pause = None
            self._runtime_hooks["state"] = "disarmed"
            self._runtime_hooks["message"] = reason
            if failures:
                self._runtime_hooks["last_failure"] = (
                    f"{failures} stale breakpoint removals could not be confirmed."
                )
            self._changed()

    def _disarm_runtime_hooks(self) -> dict[str, Any]:
        with self._lock:
            if self._runtime_hooks["state"] not in {
                "arming",
                "armed",
                "handling",
                "stopping",
            }:
                hooks = copy.deepcopy(self._runtime_hooks)
                return {
                    "ok": True,
                    "runtime_hooks": hooks,
                    "generation": self._generation,
                }
            if self._runtime_hook_processing or self._runtime_hooks["state"] == "arming":
                self._runtime_hook_stop_requested = True
                self._runtime_hooks["state"] = "stopping"
                self._runtime_hooks["message"] = (
                    "Stopping after the current bounded hook operation."
                )
                self._changed()
                hooks = copy.deepcopy(self._runtime_hooks)
                return {
                    "ok": True,
                    "runtime_hooks": hooks,
                    "generation": self._generation,
                }
        self._remove_runtime_hook_points("Runtime Hooks disarmed. Definitions remain editable.")
        with self._lock:
            hooks = copy.deepcopy(self._runtime_hooks)
        return {"ok": True, "runtime_hooks": hooks, "generation": self.generation()}

    def _clear_runtime_hook_hits(self) -> dict[str, Any]:
        with self._lock:
            self._runtime_hook_target_ready_locked()
            if self._runtime_hooks["state"] in {
                "arming",
                "armed",
                "handling",
                "stopping",
            }:
                raise DebuggerBridgeError("Disarm Runtime Hooks before clearing hits")
            self._runtime_hooks["total_hits"] = 0
            self._runtime_hooks["hits"] = []
            self._runtime_hooks["hit_evictions"] = 0
            self._runtime_hooks["last_failure"] = None
            self._runtime_hooks["message"] = "Runtime Hooks hit records were cleared."
            self._changed()
            hooks = copy.deepcopy(self._runtime_hooks)
        return {"ok": True, "runtime_hooks": hooks, "generation": self.generation()}

    def _handle_runtime_hook_navigation(self) -> None:
        with self._lock:
            if (
                not self._runtime_hooks["definitions"]
                and not self._runtime_hook_points
                and self._runtime_hooks["state"]
                not in {"arming", "armed", "handling", "stopping"}
            ):
                return
            self._runtime_hook_epoch += 1
            self._runtime_hook_points.clear()
            self._runtime_hook_processing = False
            self._runtime_hook_stop_requested = False
            self._runtime_hook_deferred_pause = None
            self._runtime_hooks["definitions"] = []
            self._runtime_hooks["active_points"] = 0
            self._runtime_hooks["state"] = "ready"
            self._runtime_hooks["last_failure"] = (
                "The page navigated. Script identifiers changed, so all hooks were cleared."
            )
            self._runtime_hooks["message"] = (
                "Navigation disarmed Runtime Hooks. Choose a live function and add it again."
            )
            self._changed()

    def _handle_runtime_hook_pause_async(self, params: dict[str, Any]) -> bool:
        raw_hits = params.get("hitBreakpoints")
        if not isinstance(raw_hits, list):
            return False
        with self._lock:
            matches = [
                copy.deepcopy(self._runtime_hook_points[item])
                for item in raw_hits
                if isinstance(item, str) and item in self._runtime_hook_points
            ]
            if not matches:
                return False
            if self._runtime_hooks["state"] == "stopping":
                self._command_without_wait("Debugger.resume")
                return True
            if self._runtime_hook_processing:
                if self._runtime_hook_deferred_pause is not None:
                    self._runtime_hooks["last_failure"] = (
                        "Runtime Hooks received more than one deferred pause."
                    )
                    self._runtime_hook_stop_requested = True
                    self._command_without_wait("Debugger.resume")
                    self._changed()
                    return True
                self._runtime_hook_deferred_pause = {
                    "epoch": self._runtime_hook_epoch,
                    "matches": matches,
                    "params": params,
                }
                self._runtime_hooks["message"] = (
                    "Handing the synchronous return phase to the bounded hook worker."
                )
                self._changed()
                return True
            self._runtime_hook_processing = True
            epoch = self._runtime_hook_epoch
            self._runtime_hooks["state"] = "handling"
            self._runtime_hooks["message"] = "Handling one bounded function hook."
            self._changed()
        thread = threading.Thread(
            target=self._process_runtime_hook_pause,
            args=(epoch, matches, params),
            name="reb-runtime-hooks",
            daemon=True,
        )
        thread.start()
        return True

    def _runtime_hook_evaluate(
        self,
        frame_id: str,
        expression: str,
        object_group: str,
        *,
        return_by_value: bool,
        throw_on_side_effect: bool,
    ) -> dict[str, Any]:
        result = self._command(
            "Debugger.evaluateOnCallFrame",
            {
                "callFrameId": frame_id,
                "expression": expression,
                "objectGroup": object_group,
                "includeCommandLineAPI": False,
                "silent": True,
                "returnByValue": return_by_value,
                "generatePreview": not return_by_value,
                "throwOnSideEffect": throw_on_side_effect,
                "timeout": RUNTIME_HOOK_EVALUATION_TIMEOUT_MS,
            },
            timeout=1.0,
        )
        if isinstance(result.get("exceptionDetails"), dict):
            raise DebuggerBridgeError("Runtime Hooks evaluation threw an exception")
        remote = result.get("result")
        if not isinstance(remote, dict) or not isinstance(remote.get("type"), str):
            raise ProtocolError("Debugger returned a malformed hook evaluation")
        return remote

    def _runtime_hook_bindings(
        self, raw_frame: dict[str, Any]
    ) -> tuple[list[dict[str, Any]], bool]:
        raw_scopes = raw_frame.get("scopeChain")
        if not isinstance(raw_scopes, list):
            return [], False
        local_id = None
        for scope in raw_scopes[:MAX_SCOPES_PER_FRAME]:
            if not isinstance(scope, dict) or scope.get("type") != "local":
                continue
            remote = scope.get("object")
            if isinstance(remote, dict) and isinstance(remote.get("objectId"), str):
                local_id = remote["objectId"]
                break
        if local_id is None or len(local_id.encode("utf-8")) > MAX_TARGET_ID_BYTES:
            return [], False
        result = self._command(
            "Runtime.getProperties",
            {
                "objectId": local_id,
                "ownProperties": True,
                "accessorPropertiesOnly": False,
                "generatePreview": True,
            },
            timeout=1.0,
        )
        raw_properties = result.get("result")
        if not isinstance(raw_properties, list):
            raise ProtocolError("Debugger returned malformed hook bindings")
        bindings = []
        for item in raw_properties[:MAX_RUNTIME_HOOK_BINDINGS]:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                continue
            name = truncate_text(item["name"], 256)
            if isinstance(item.get("value"), dict):
                preview = self._runtime_hook_remote_preview(item["value"])
                accessor = False
            else:
                accessor = isinstance(item.get("get"), dict) or isinstance(
                    item.get("set"), dict
                )
                preview = {
                    "type": "accessor" if accessor else "unavailable",
                    "subtype": None,
                    "class_name": None,
                    "description": (
                        "Accessor not invoked"
                        if accessor
                        else "Not initialized or unavailable"
                    ),
                    "value": None,
                    "unserializable_value": None,
                    "value_truncated": False,
                }
            bindings.append(
                {"name": name, "value": preview, "accessor": accessor}
            )
        return bindings, len(raw_properties) > MAX_RUNTIME_HOOK_BINDINGS

    def _runtime_hook_remote_preview(self, value: Any) -> Optional[dict[str, Any]]:
        remote = self._remote_object(value)
        if remote is None:
            return None
        remote.pop("object_id", None)
        if isinstance(remote.get("value"), str):
            original = remote["value"]
            remote["value_truncated"] = (
                remote["value_truncated"]
                or len(original.encode("utf-8"))
                > MAX_RUNTIME_HOOK_BINDING_PREVIEW_BYTES
            )
            remote["value"] = truncate_text(
                original, MAX_RUNTIME_HOOK_BINDING_PREVIEW_BYTES
            )
        for field in ("description", "unserializable_value", "class_name"):
            if isinstance(remote.get(field), str):
                remote[field] = truncate_text(
                    remote[field], MAX_RUNTIME_HOOK_BINDING_PREVIEW_BYTES
                )
        return remote

    @staticmethod
    def _runtime_hook_call_argument(remote: dict[str, Any]) -> dict[str, Any]:
        if "value" in remote:
            return {"value": remote["value"]}
        if isinstance(remote.get("unserializableValue"), str):
            return {"unserializableValue": remote["unserializableValue"]}
        if isinstance(remote.get("objectId"), str):
            return {"objectId": remote["objectId"]}
        raise DebuggerBridgeError("Runtime Hooks expression result cannot be returned")

    def _append_runtime_hook_hit_locked(
        self,
        *,
        hook: dict[str, Any],
        phase: str,
        raw_frame: dict[str, Any],
        operation: str,
        bindings: list[dict[str, Any]],
        bindings_truncated: bool,
        original_return: Optional[dict[str, Any]],
        replacement_return: Optional[dict[str, Any]],
        error: Optional[str],
    ) -> None:
        location = self._parse_location(raw_frame.get("location")) or {
            "script_id": hook["script_id"],
            "line": hook["line"],
            "column": hook["column"],
        }
        function_name = raw_frame.get("functionName")
        entry = {
            "id": self._next_runtime_hook_hit_id,
            "occurred_at_ms": int(time.time() * 1_000),
            "session_id": self._runtime_hooks["session_id"],
            "hook_id": hook["id"],
            "target_id": self._runtime_hooks["target_id"],
            "label": hook["label"],
            "source": truncate_text(hook["url"], MAX_INTERCEPTION_URL_BYTES),
            "function": truncate_text(function_name, 256)
            if isinstance(function_name, str) and function_name
            else "(anonymous)",
            "category": phase,
            "operation": operation,
            "line": location["line"],
            "column": location["column"],
            "bindings": bindings,
            "bindings_truncated": bindings_truncated,
            "original_return": original_return,
            "replacement_return": replacement_return,
            "error": truncate_text(error, 512) if error else None,
        }
        self._next_runtime_hook_hit_id += 1
        self._runtime_hooks["total_hits"] += 1
        hits = self._runtime_hooks["hits"]
        hits.append(entry)
        if len(hits) > MAX_RUNTIME_HOOK_RETAINED_HITS:
            del hits[: len(hits) - MAX_RUNTIME_HOOK_RETAINED_HITS]
            self._runtime_hooks["hit_evictions"] += 1
        if error:
            self._runtime_hooks["last_failure"] = entry["error"]

    def _process_runtime_hook_pause(
        self,
        epoch: int,
        matches: list[dict[str, Any]],
        params: dict[str, Any],
    ) -> None:
        raw_frames = params.get("callFrames")
        raw_frame = raw_frames[0] if isinstance(raw_frames, list) and raw_frames else None
        frame_id = raw_frame.get("callFrameId") if isinstance(raw_frame, dict) else None
        with self._lock:
            hooks_by_id = {
                item["id"]: copy.deepcopy(item)
                for item in self._runtime_hooks["definitions"]
            }
            session_id = self._runtime_hooks["session_id"]
        object_group = f"reb-runtime-hook-{session_id}-{self._next_runtime_hook_hit_id}"
        auto_disarm = False
        fatal_error: Optional[str] = None
        try:
            if (
                not isinstance(raw_frame, dict)
                or not isinstance(frame_id, str)
                or len(frame_id.encode("utf-8")) > MAX_TARGET_ID_BYTES
            ):
                raise ProtocolError("Debugger omitted the Runtime Hooks top frame")
            for match in matches:
                hook = hooks_by_id.get(match["hook_id"])
                if hook is None:
                    continue
                for phase in match["phases"]:
                    with self._lock:
                        if (
                            epoch != self._runtime_hook_epoch
                            or self._runtime_hooks["total_hits"]
                            >= MAX_RUNTIME_HOOK_HITS
                        ):
                            auto_disarm = True
                            break
                    bindings: list[dict[str, Any]] = []
                    bindings_truncated = False
                    original_return = (
                        self._runtime_hook_remote_preview(raw_frame.get("returnValue"))
                        if phase == "return"
                        else None
                    )
                    replacement_return = None
                    operation = "observed"
                    error = None
                    try:
                        if hook["condition"]:
                            condition_remote = self._runtime_hook_evaluate(
                                frame_id,
                                f"Boolean(({hook['condition']}))",
                                object_group,
                                return_by_value=True,
                                throw_on_side_effect=True,
                            )
                            if condition_remote.get("value") is not True:
                                operation = "skipped"
                                with self._lock:
                                    self._append_runtime_hook_hit_locked(
                                        hook=hook,
                                        phase=phase,
                                        raw_frame=raw_frame,
                                        operation=operation,
                                        bindings=[],
                                        bindings_truncated=False,
                                        original_return=original_return,
                                        replacement_return=None,
                                        error=None,
                                    )
                                    self._changed()
                                continue
                        bindings, bindings_truncated = self._runtime_hook_bindings(
                            raw_frame
                        )
                        logic = (
                            hook["entry_logic"]
                            if phase == "entry"
                            else hook["return_logic"]
                        )
                        if logic:
                            logic_remote = self._runtime_hook_evaluate(
                                frame_id,
                                f"(()=>{{\n{logic}\n}})()",
                                object_group,
                                return_by_value=False,
                                throw_on_side_effect=False,
                            )
                            if logic_remote.get("subtype") == "promise":
                                raise DebuggerBridgeError(
                                    "Injected logic returned a Promise; only synchronous logic is supported"
                                )
                            operation = "logic_run"
                        if phase == "return" and hook["return_mode"] != "none":
                            raw_return = raw_frame.get("returnValue")
                            if (
                                isinstance(raw_return, dict)
                                and raw_return.get("subtype") == "promise"
                            ):
                                raise DebuggerBridgeError(
                                    "Promise return values cannot be synchronously replaced"
                                )
                            if hook["return_mode"] == "json":
                                argument = {"value": hook["return_value"]}
                                replacement_return = {
                                    "type": (
                                        "null"
                                        if hook["return_value"] is None
                                        else type(hook["return_value"]).__name__
                                    ),
                                    "subtype": None,
                                    "class_name": None,
                                    "description": truncate_text(
                                        json.dumps(
                                            hook["return_value"],
                                            ensure_ascii=False,
                                            separators=(",", ":"),
                                        ),
                                        MAX_RUNTIME_HOOK_BINDING_PREVIEW_BYTES,
                                    ),
                                    "value": hook["return_value"]
                                    if isinstance(
                                        hook["return_value"],
                                        (str, bool, int, float),
                                    )
                                    or hook["return_value"] is None
                                    else None,
                                    "unserializable_value": None,
                                    "value_truncated": hook["return_value_bytes"]
                                    > MAX_RUNTIME_HOOK_BINDING_PREVIEW_BYTES,
                                }
                            else:
                                replacement_remote = self._runtime_hook_evaluate(
                                    frame_id,
                                    hook["return_expression"],
                                    object_group,
                                    return_by_value=False,
                                    throw_on_side_effect=False,
                                )
                                if replacement_remote.get("subtype") == "promise":
                                    raise DebuggerBridgeError(
                                        "A Promise expression cannot be used as a synchronous return value"
                                    )
                                argument = self._runtime_hook_call_argument(
                                    replacement_remote
                                )
                                replacement_return = self._runtime_hook_remote_preview(
                                    replacement_remote
                                )
                            self._command(
                                "Debugger.setReturnValue", {"newValue": argument}
                            )
                            operation = "return_overridden"
                    except DebuggerBridgeError as exception:
                        operation = "failed"
                        error = str(exception)
                    with self._lock:
                        if epoch != self._runtime_hook_epoch:
                            auto_disarm = True
                            break
                        self._append_runtime_hook_hit_locked(
                            hook=hook,
                            phase=phase,
                            raw_frame=raw_frame,
                            operation=operation,
                            bindings=bindings,
                            bindings_truncated=bindings_truncated,
                            original_return=original_return,
                            replacement_return=replacement_return,
                            error=error,
                        )
                        auto_disarm = (
                            self._runtime_hooks["total_hits"]
                            >= MAX_RUNTIME_HOOK_HITS
                        )
                        self._changed()
                    if auto_disarm:
                        break
                if auto_disarm:
                    break
        except DebuggerBridgeError as exception:
            fatal_error = truncate_text(str(exception), 512)
            auto_disarm = True
        finally:
            try:
                self._command("Runtime.releaseObjectGroup", {"objectGroup": object_group})
            except DebuggerBridgeError:
                pass
            try:
                self._command("Debugger.resume")
            except DebuggerBridgeError as exception:
                fatal_error = truncate_text(str(exception), 512)
                auto_disarm = True
            deferred: Optional[dict[str, Any]] = None
            with self._lock:
                stop_requested = self._runtime_hook_stop_requested
                still_current = epoch == self._runtime_hook_epoch
                if still_current and fatal_error:
                    self._runtime_hooks["last_failure"] = fatal_error
                    self._runtime_hooks["message"] = fatal_error
                if still_current:
                    candidate = self._runtime_hook_deferred_pause
                    self._runtime_hook_deferred_pause = None
                    if (
                        isinstance(candidate, dict)
                        and candidate.get("epoch") == epoch
                    ):
                        deferred = candidate
                if (
                    still_current
                    and deferred is not None
                    and not (auto_disarm or stop_requested)
                ):
                    self._runtime_hooks["state"] = "handling"
                    self._runtime_hooks["message"] = (
                        "Handling the queued synchronous return phase."
                    )
                    self._changed()
                elif still_current and not (auto_disarm or stop_requested):
                    self._runtime_hook_processing = False
                    self._runtime_hooks["state"] = "armed"
                    self._runtime_hooks["message"] = (
                        f"Runtime Hooks armed. {self._runtime_hooks['total_hits']} hits observed."
                    )
                    self._changed()
            if still_current and deferred is not None and not (
                auto_disarm or stop_requested
            ):
                try:
                    threading.Thread(
                        target=self._process_runtime_hook_pause,
                        args=(epoch, deferred["matches"], deferred["params"]),
                        name="reb-runtime-hooks",
                        daemon=True,
                    ).start()
                    return
                except RuntimeError as exception:
                    fatal_error = truncate_text(
                        f"Runtime Hooks worker could not continue: {exception}", 512
                    )
                    auto_disarm = True
                    with self._lock:
                        if epoch == self._runtime_hook_epoch:
                            self._runtime_hooks["last_failure"] = fatal_error
                            self._changed()
            if still_current and deferred is not None and (
                auto_disarm or stop_requested
            ):
                try:
                    self._command("Debugger.resume")
                except DebuggerBridgeError:
                    pass
            if still_current and (auto_disarm or stop_requested):
                reason = (
                    "Runtime Hooks reached the 512-hit limit and disarmed automatically."
                    if auto_disarm and not fatal_error
                    else "Runtime Hooks disarmed after the current hook operation."
                )
                self._remove_runtime_hook_points(reason, expected_epoch=epoch)

    def _search_heap_snapshot(self, request: dict[str, Any]) -> dict[str, Any]:
        query = optional_search_text(request, "query").strip()
        case_sensitive = request.get("case_sensitive", False)
        scope = request.get("scope", "all")
        if not query:
            raise DebuggerBridgeError("Heap snapshot search requires a value")
        if not isinstance(case_sensitive, bool):
            raise DebuggerBridgeError("Heap snapshot search options must be boolean")
        if not isinstance(scope, str) or scope not in {
            "all",
            "reachable",
            "unreachable",
        }:
            raise DebuggerBridgeError("Heap snapshot reference scope is invalid")
        binary = self._heap_snapshot_binary()

        capture = self._capture_heap_snapshot()
        try:
            command = [
                str(binary),
                "--snapshot",
                str(capture.path),
                "--query",
                query,
                "--scope",
                scope,
                "--limit",
                str(MAX_HEAP_SNAPSHOT_RESULTS),
            ]
            if case_sensitive:
                command.append("--case-sensitive")
            document = self._run_native_heap_snapshot(
                command,
                HEAP_SNAPSHOT_SEARCH_TIMEOUT_SECONDS,
                "search",
            )
            return self._normalize_heap_snapshot_search(document)
        finally:
            capture.path.unlink(missing_ok=True)

    @staticmethod
    def _empty_memory_origin_trace() -> dict[str, Any]:
        return {
            "protocol_version": 1,
            "trace_id": 0,
            "state": "idle",
            "target_id": None,
            "query": "",
            "scope": "all",
            "case_sensitive": False,
            "before_steps": 0,
            "after_steps": 0,
            "step_limit": MAX_MEMORY_ORIGIN_TRACE_STEPS,
            "step_count": 0,
            "first_match_step": None,
            "started_at_ms": 0,
            "elapsed_ms": 0,
            "partial": False,
            "limit_reason": None,
            "message": "Enter a value and arm a trace.",
            "steps": [],
        }

    def _memory_origin_trace_active_locked(self) -> bool:
        return self._memory_origin_trace["state"] in {
            "armed",
            "capturing",
            "stepping",
            "stopping",
        }

    def _cancel_memory_origin_trace_timer_locked(self) -> None:
        timer = self._memory_origin_trace_timer
        self._memory_origin_trace_timer = None
        if timer is not None:
            timer.cancel()

    def _start_memory_origin_trace(self, request: dict[str, Any]) -> dict[str, Any]:
        query = optional_search_text(request, "query").strip()
        scope = request.get("scope", "all")
        case_sensitive = request.get("case_sensitive", False)
        before_steps = request.get("before_steps", 3)
        after_steps = request.get("after_steps", 8)
        if not query:
            raise DebuggerBridgeError("Memory Origin Trace requires a value")
        if not isinstance(scope, str) or scope not in {
            "all",
            "reachable",
            "unreachable",
        }:
            raise DebuggerBridgeError("Memory Origin Trace reference scope is invalid")
        if not isinstance(case_sensitive, bool):
            raise DebuggerBridgeError("Memory Origin Trace options must be boolean")
        if (
            not isinstance(before_steps, int)
            or isinstance(before_steps, bool)
            or before_steps < 0
            or before_steps > MAX_MEMORY_ORIGIN_TRACE_BEFORE_STEPS
            or not isinstance(after_steps, int)
            or isinstance(after_steps, bool)
            or after_steps < 0
            or after_steps > MAX_MEMORY_ORIGIN_TRACE_AFTER_STEPS
        ):
            raise DebuggerBridgeError("Memory Origin Trace tolerance window is invalid")
        self._heap_snapshot_binary()

        with self._lock:
            if self._state != "running" or self._target is None:
                raise DebuggerBridgeError(
                    "Memory Origin Trace requires a running debugger target"
                )
            if self._heap_diff_busy or self._heap_snapshot_collector is not None:
                raise DebuggerBridgeError("A heap snapshot operation is already running")
            trace_id = self._next_memory_origin_trace_id
            self._next_memory_origin_trace_id += 1
            target_id = self._target["id"]
            self._memory_origin_trace_started = time.monotonic()
            self._memory_origin_trace_processing = False
            self._memory_origin_trace_stop_requested = False
            self._memory_origin_trace_added_click_breakpoint = (
                not any(
                    event_name in {"click", "listener:click"}
                    for event_name in self._event_breakpoints
                )
            )
            self._memory_origin_trace = {
                "protocol_version": 1,
                "trace_id": trace_id,
                "state": "armed",
                "target_id": target_id,
                "query": query,
                "scope": scope,
                "case_sensitive": case_sensitive,
                "before_steps": before_steps,
                "after_steps": after_steps,
                "step_limit": MAX_MEMORY_ORIGIN_TRACE_STEPS,
                "step_count": 0,
                "first_match_step": None,
                "started_at_ms": int(time.time() * 1_000),
                "elapsed_ms": 0,
                "partial": False,
                "limit_reason": None,
                "message": "Trace armed. Click the page action that creates the value.",
                "steps": [],
            }
            self._changed()
            add_click_breakpoint = self._memory_origin_trace_added_click_breakpoint
        try:
            if add_click_breakpoint:
                self._command(
                    "DOMDebugger.setEventListenerBreakpoint",
                    {"eventName": "click", "targetName": "*"},
                )
        except BaseException as exception:
            self._complete_memory_origin_trace(
                trace_id,
                "error",
                truncate_text(str(exception), 512),
                resume=False,
            )
            raise
        with self._lock:
            trace = copy.deepcopy(self._memory_origin_trace)
        return {"ok": True, "trace": trace, "generation": self.generation()}

    def _stop_memory_origin_trace(self) -> dict[str, Any]:
        with self._lock:
            if not self._memory_origin_trace_active_locked():
                raise DebuggerBridgeError("Memory Origin Trace is not running")
            trace_id = self._memory_origin_trace["trace_id"]
            self._memory_origin_trace_stop_requested = True
            self._cancel_memory_origin_trace_timer_locked()
            if self._memory_origin_trace_processing:
                self._memory_origin_trace["state"] = "stopping"
                self._memory_origin_trace["message"] = (
                    "Stopping after the current bounded snapshot finishes."
                )
                self._changed()
                return {"ok": True, "generation": self._generation}
        self._complete_memory_origin_trace(trace_id, "aborted", "Trace stopped.")
        return {"ok": True, "generation": self.generation()}

    def _start_memory_origin_trace_pause_async(
        self, pause_serial: int, paused: dict[str, Any]
    ) -> None:
        with self._lock:
            if (
                not self._memory_origin_trace_active_locked()
                or self._memory_origin_trace["state"] == "stopping"
                or self._memory_origin_trace_processing
            ):
                return
            self._cancel_memory_origin_trace_timer_locked()
            self._memory_origin_trace_processing = True
            self._memory_origin_trace["state"] = "capturing"
            self._memory_origin_trace["message"] = (
                "Capturing and probing the bounded heap at this debugger pause."
            )
            trace_id = self._memory_origin_trace["trace_id"]
            self._changed()
        thread = threading.Thread(
            target=self._process_memory_origin_trace_pause,
            args=(trace_id, pause_serial, paused),
            name="reb-memory-origin-trace",
            daemon=True,
        )
        thread.start()

    def _process_memory_origin_trace_pause(
        self, trace_id: int, pause_serial: int, paused: dict[str, Any]
    ) -> None:
        capture: Optional[HeapSnapshotCapture] = None
        try:
            with self._lock:
                trace = dict(self._memory_origin_trace)
            capture = self._capture_heap_snapshot()
            if capture.target_id != trace["target_id"]:
                raise DebuggerBridgeError(
                    "Debugger target changed during Memory Origin Trace"
                )
            command = [
                str(self._heap_snapshot_binary()),
                "--snapshot",
                str(capture.path),
                "--query",
                trace["query"],
                "--scope",
                trace["scope"],
                "--probe",
            ]
            if trace["case_sensitive"]:
                command.append("--case-sensitive")
            document = self._run_native_heap_snapshot(
                command,
                HEAP_SNAPSHOT_PROBE_TIMEOUT_SECONDS,
                "probe",
            )
            probe = normalize_heap_snapshot_probe(document)
            if probe["scope"] != trace["scope"]:
                raise ProtocolError(
                    "Native heap snapshot probe returned an unexpected scope"
                )
        except BaseException as exception:
            with self._lock:
                stopped = self._memory_origin_trace_stop_requested
            self._complete_memory_origin_trace(
                trace_id,
                "aborted" if stopped else "error",
                "Trace stopped."
                if stopped
                else truncate_text(str(exception), 512),
            )
            return
        finally:
            if capture is not None:
                capture.path.unlink(missing_ok=True)

        location = self._memory_origin_trace_location(paused)
        finish: Optional[tuple[str, str, bool, Optional[str]]] = None
        should_step = False
        with self._lock:
            if (
                self._memory_origin_trace["trace_id"] != trace_id
                or not self._memory_origin_trace_active_locked()
            ):
                return
            self._memory_origin_trace_processing = False
            if self._memory_origin_trace_stop_requested:
                finish = ("aborted", "Trace stopped.", False, None)
            elif pause_serial != self._pause_serial or self._state != "paused":
                finish = (
                    "error",
                    "Debugger pause changed before the heap probe completed.",
                    False,
                    None,
                )
            else:
                trace = self._memory_origin_trace
                trace["step_count"] += 1
                step_number = trace["step_count"]
                coverage_partial = any(
                    probe[field]
                    for field in (
                        "node_limit_reached",
                        "edge_limit_reached",
                        "string_limit_reached",
                    )
                )
                if coverage_partial:
                    trace["partial"] = True
                    trace["limit_reason"] = "snapshot_coverage"
                step = {
                    "id": f"origin-{trace_id}-{step_number}",
                    "step": step_number,
                    "captured_at_ms": int(time.time() * 1_000),
                    "capture_bytes": capture.byte_count,
                    "duration_ms": probe["duration_ms"],
                    "analyzed_nodes": probe["analyzed_nodes"],
                    "total_nodes": probe["total_nodes"],
                    "indexed_edges": probe["indexed_edges"],
                    "total_edges": probe["total_edges"],
                    "matched": probe["match_found"],
                    "coverage_partial": coverage_partial,
                    "is_first_match": False,
                    "location": location,
                    "match": probe["match"],
                }
                if probe["match_found"] and trace["first_match_step"] is None:
                    trace["first_match_step"] = step_number
                    step["is_first_match"] = True
                trace["steps"].append(step)
                if trace["first_match_step"] is None:
                    while len(trace["steps"]) > trace["before_steps"]:
                        trace["steps"].pop(0)
                elapsed = max(
                    0,
                    int((time.monotonic() - self._memory_origin_trace_started) * 1_000),
                )
                trace["elapsed_ms"] = elapsed
                after_captured = (
                    step_number - trace["first_match_step"]
                    if trace["first_match_step"] is not None
                    else 0
                )
                if (
                    trace["first_match_step"] is not None
                    and after_captured >= trace["after_steps"]
                ):
                    finish = (
                        "found",
                        f"First appearance found at debugger step {trace['first_match_step']}.",
                        trace["partial"],
                        trace["limit_reason"],
                    )
                elif step_number >= trace["step_limit"]:
                    finish = (
                        "found" if trace["first_match_step"] is not None else "not_found",
                        "Trace reached its 32-step limit.",
                        True,
                        "step_limit",
                    )
                elif elapsed >= int(MEMORY_ORIGIN_TRACE_TIMEOUT_SECONDS * 1_000):
                    finish = (
                        "found" if trace["first_match_step"] is not None else "not_found",
                        "Trace reached its five-minute limit.",
                        True,
                        "time_limit",
                    )
                else:
                    trace["state"] = "stepping"
                    trace["message"] = (
                        "First appearance found; collecting the requested after-window."
                        if trace["first_match_step"] is not None
                        else "Value not present yet; stepping out to the next function boundary."
                    )
                    should_step = True
                    self._changed()

        if finish is not None:
            self._complete_memory_origin_trace(trace_id, *finish)
            return
        if should_step:
            try:
                self._command("Debugger.stepOut")
            except BaseException as exception:
                self._complete_memory_origin_trace(
                    trace_id,
                    "error",
                    truncate_text(str(exception), 512),
                    resume=False,
                )
                return
            self._schedule_memory_origin_trace_idle_timeout(trace_id)

    def _schedule_memory_origin_trace_idle_timeout(self, trace_id: int) -> None:
        with self._lock:
            if (
                self._memory_origin_trace["trace_id"] != trace_id
                or self._memory_origin_trace["state"] != "stepping"
            ):
                return
            self._cancel_memory_origin_trace_timer_locked()
            expected_step = self._memory_origin_trace["step_count"]
            timer = threading.Timer(
                MEMORY_ORIGIN_TRACE_IDLE_TIMEOUT_SECONDS,
                self._memory_origin_trace_idle_timeout,
                args=(trace_id, expected_step),
            )
            timer.daemon = True
            self._memory_origin_trace_timer = timer
        timer.start()

    def _memory_origin_trace_idle_timeout(
        self, trace_id: int, expected_step: int
    ) -> None:
        with self._lock:
            if (
                self._memory_origin_trace["trace_id"] != trace_id
                or self._memory_origin_trace["state"] != "stepping"
                or self._memory_origin_trace["step_count"] != expected_step
                or self._memory_origin_trace_processing
            ):
                return
            self._memory_origin_trace_timer = None
            found = self._memory_origin_trace["first_match_step"] is not None
            requested_after = self._memory_origin_trace["after_steps"]
            captured_after = (
                expected_step - self._memory_origin_trace["first_match_step"]
                if found
                else 0
            )
            incomplete_after = found and captured_after < requested_after
            first_match_step = self._memory_origin_trace["first_match_step"]
        self._complete_memory_origin_trace(
            trace_id,
            "found" if found else "not_found",
            "Execution returned before another function-boundary pause."
            if incomplete_after
            else "Execution returned before the value appeared."
            if not found
            else f"First appearance found at debugger step {first_match_step}.",
            partial=incomplete_after,
            limit_reason="execution_quiet" if incomplete_after else None,
            resume=False,
        )

    def _complete_memory_origin_trace(
        self,
        trace_id: int,
        state: str,
        message: str,
        partial: bool = False,
        limit_reason: Optional[str] = None,
        resume: bool = True,
    ) -> None:
        with self._lock:
            if (
                self._memory_origin_trace["trace_id"] != trace_id
                or not self._memory_origin_trace_active_locked()
            ):
                return
            if self._memory_origin_trace_stop_requested and state != "aborted":
                state = "aborted"
                message = "Trace stopped."
                limit_reason = None
            self._cancel_memory_origin_trace_timer_locked()
            self._memory_origin_trace_processing = False
            self._memory_origin_trace_stop_requested = False
            self._memory_origin_trace["state"] = state
            self._memory_origin_trace["message"] = truncate_text(message, 512)
            self._memory_origin_trace["elapsed_ms"] = max(
                0,
                int((time.monotonic() - self._memory_origin_trace_started) * 1_000),
            )
            self._memory_origin_trace["partial"] = (
                self._memory_origin_trace["partial"] or partial
            )
            if limit_reason is not None:
                self._memory_origin_trace["limit_reason"] = limit_reason
            remove_click_breakpoint = self._memory_origin_trace_added_click_breakpoint
            self._memory_origin_trace_added_click_breakpoint = False
            should_resume = resume and self._state == "paused"
            self._changed()
        if remove_click_breakpoint:
            try:
                self._command(
                    "DOMDebugger.removeEventListenerBreakpoint",
                    {"eventName": "click", "targetName": "*"},
                )
            except DebuggerBridgeError:
                pass
        if should_resume:
            try:
                self._command("Debugger.resume")
            except DebuggerBridgeError:
                pass

    def _memory_origin_trace_location(
        self, paused: dict[str, Any]
    ) -> dict[str, Any]:
        frames = paused.get("call_frames", [])
        selected = frames[0] if frames else None
        filtered = False
        for frame in frames:
            url = frame.get("url", "")
            if not url:
                with self._lock:
                    script = self._scripts.get(frame["location"]["script_id"])
                if script is not None:
                    url = script["url"]
            lower_url = url.lower()
            if (
                lower_url.startswith(("chrome-extension:", "devtools:", "extensions::"))
                or any(
                    pattern in lower_url
                    for pattern in MEMORY_ORIGIN_TRACE_FRAMEWORK_PATTERNS
                )
            ):
                filtered = True
                continue
            selected = frame
            break
        if selected is None:
            return {
                "script_id": "",
                "url": "",
                "function_name": "(unknown)",
                "line": 0,
                "column": 0,
                "framework_filtered": filtered,
            }
        location = selected["location"]
        url = selected.get("url", "")
        if not url:
            with self._lock:
                script = self._scripts.get(location["script_id"])
            if script is not None:
                url = script["url"]
        return {
            "script_id": location["script_id"],
            "url": truncate_text(url, MAX_TARGET_URL_BYTES),
            "function_name": truncate_text(
                selected.get("function_name", "(anonymous)"), 512
            ),
            "line": location["line"],
            "column": location["column"],
            "framework_filtered": filtered,
        }

    @staticmethod
    def _empty_action_scope() -> dict[str, Any]:
        return {
            "protocol_version": 1,
            "state": "idle",
            "mode": "global",
            "target_id": None,
            "revision": 0,
            "targets": [],
            "matched_target_count": 0,
            "connected_target_count": 0,
            "target_overflow": 0,
            "message": (
                "Create an isolated Experiment context to choose mutable-rule scope."
            ),
            "rule_families": ["request_interception", "automation_recipes"],
            "target_only_families": [
                "object_experiment",
                "runtime_hooks",
                "repeater",
            ],
            "limits": {
                "targets": MAX_ACTION_SCOPE_TARGETS,
                "pending_triggers": MAX_ACTION_SCOPE_PENDING_TRIGGERS,
            },
        }

    def _public_action_scope_locked(self) -> dict[str, Any]:
        targets = []
        for target_id, target in self._action_scope_targets.items():
            session = self._action_scope_sessions.get(target_id)
            targets.append(
                {
                    "id": target_id,
                    "type": target["type"],
                    "title": truncate_text(target["title"], 512),
                    "url": redacted_request_url(target["url"])
                    if target["url"].startswith(("http://", "https://"))
                    else truncate_text(target["url"], MAX_TARGET_URL_BYTES),
                    "connected": session is not None and session.ready(),
                    "matched": self._action_scope_mode == "global"
                    or self._action_scope_target_id == target_id,
                }
            )
        matched_targets = [target for target in targets if target["matched"]]
        connected_targets = [target for target in matched_targets if target["connected"]]
        context_exists = self._request_interception_context_id is not None
        if not context_exists:
            state = (
                "disposed"
                if self._request_interception["state"] == "disposed"
                else "idle"
            )
        elif self._action_scope_last_error is not None or (
            self._action_scope_mode == "target"
            and not any(
                target["id"] == self._action_scope_target_id for target in targets
            )
        ):
            state = "error"
        elif not targets:
            state = "discovering"
        elif (
            self._action_scope_target_overflow > 0
            or len(connected_targets) != len(matched_targets)
        ):
            state = "partial"
        else:
            state = "ready"
        if self._action_scope_last_error is not None:
            message = self._action_scope_last_error
        elif state == "idle":
            message = "Create an isolated Experiment context to choose mutable-rule scope."
        elif state == "disposed":
            message = "The disposable context and every scoped target were deleted."
        elif state == "discovering":
            message = "Discovering bounded page targets in the disposable context."
        elif state == "error":
            message = "The selected page target is no longer available. Choose a new scope."
        elif state == "partial":
            message = (
                f"{len(connected_targets)} of {len(matched_targets)} matched targets are connected."
            )
        elif self._action_scope_mode == "global":
            message = (
                f"Mutable rules apply to all {len(matched_targets)} disposable page targets."
            )
        else:
            message = "Mutable rules apply only to the selected disposable page target."
        return {
            "protocol_version": 1,
            "state": state,
            "mode": self._action_scope_mode,
            "target_id": self._action_scope_target_id,
            "revision": self._action_scope_revision,
            "targets": targets,
            "matched_target_count": len(matched_targets),
            "connected_target_count": len(connected_targets),
            "target_overflow": self._action_scope_target_overflow,
            "message": truncate_text(message, 512),
            "rule_families": ["request_interception", "automation_recipes"],
            "target_only_families": [
                "object_experiment",
                "runtime_hooks",
                "repeater",
            ],
            "limits": {
                "targets": MAX_ACTION_SCOPE_TARGETS,
                "pending_triggers": MAX_ACTION_SCOPE_PENDING_TRIGGERS,
            },
        }

    def _matching_action_scope_sessions_locked(
        self,
    ) -> list[ActionScopeTargetSession]:
        sessions = []
        for target_id in self._action_scope_targets:
            if (
                self._action_scope_mode == "target"
                and target_id != self._action_scope_target_id
            ):
                continue
            session = self._action_scope_sessions.get(target_id)
            if session is not None and session.ready():
                sessions.append(session)
        return sessions

    def _require_action_scope_sessions_locked(
        self, label: str
    ) -> list[ActionScopeTargetSession]:
        public = self._public_action_scope_locked()
        sessions = self._matching_action_scope_sessions_locked()
        if (
            public["state"] not in {"ready", "partial"}
            or not sessions
            or len(sessions) != public["matched_target_count"]
            or public["target_overflow"] != 0
        ):
            raise DebuggerBridgeError(
                f"{label} requires every matched disposable page target to be connected"
            )
        return sessions

    def _scoped_command(
        self,
        session: Optional[ActionScopeTargetSession],
        method: str,
        params: Optional[dict[str, Any]] = None,
        timeout: float = 3.0,
    ) -> dict[str, Any]:
        if session is None:
            return self._command(method, params, timeout)
        return session.command(method, params, timeout)

    def _scoped_command_without_wait(
        self,
        session: Optional[ActionScopeTargetSession],
        method: str,
        params: Optional[dict[str, Any]] = None,
    ) -> bool:
        if session is None:
            return self._command_without_wait(method, params)
        return session.command_without_wait(method, params)


    @classmethod
    def _public_request_interception_rule(cls, rule: dict[str, Any]) -> dict[str, Any]:
        return {
            "mode": rule["mode"],
            "url_pattern": rule["url_pattern"],
            "method_filter": rule["method_filter"],
            "rewrite_url": redacted_request_url(rule["rewrite_url"])
            if rule["rewrite_url"]
            else "",
            "rewrite_method": rule["rewrite_method"],
            "rewrite_header_count": len(rule["rewrite_headers"]),
            "rewrite_body_bytes": len(rule["rewrite_body"].encode("utf-8")),
            "response_code": rule["response_code"],
            "response_header_count": len(rule["response_headers"]),
            "response_body_bytes": len(rule["response_body"].encode("utf-8")),
        }

    @classmethod
    def _empty_request_interception(cls) -> dict[str, Any]:
        return {
            "protocol_version": 1,
            "experiment_id": 0,
            "state": "idle",
            "isolated": False,
            "target_id": None,
            "created_at_ms": 0,
            "disposed_at_ms": 0,
            "rule": cls._public_request_interception_rule(
                default_request_interception_rule()
            ),
            "last_request": None,
            "result": None,
            "audit": [],
            "audit_evictions": 0,
            "pending_requests": 0,
            "message": "Create an isolated experiment to intercept a request.",
            "limits": {
                "audit_entries": MAX_INTERCEPTION_AUDIT_ENTRIES,
                "pending_requests": MAX_INTERCEPTION_PENDING_REQUESTS,
                "headers": MAX_INTERCEPTION_HEADERS,
                "body_bytes": MAX_INTERCEPTION_BODY_BYTES,
                "response_bytes": MAX_INTERCEPTION_RESPONSE_BYTES,
            },
        }

    @staticmethod
    def _empty_object_experiment() -> dict[str, Any]:
        return {
            "protocol_version": 1,
            "session_id": 0,
            "state": "idle",
            "isolated": False,
            "target_id": None,
            "url": "",
            "navigation_id": 0,
            "search_id": 0,
            "search": None,
            "results": [],
            "last_mutation": None,
            "audit": [],
            "audit_evictions": 0,
            "mutation_attempts": 0,
            "message": "Create an isolated Experiment context to use Object Lab.",
            "limits": {
                "search_results": MAX_LIVE_OBJECT_RESULTS,
                "search_candidates": MAX_LIVE_OBJECT_SCAN,
                "search_timeout_ms": LIVE_OBJECT_SEARCH_TIMEOUT_MS,
                "preview_properties": MAX_LIVE_OBJECT_PREVIEW_PROPERTIES,
                "mutation_attempts": MAX_OBJECT_EXPERIMENT_MUTATIONS,
                "audit_entries": MAX_OBJECT_EXPERIMENT_AUDIT_ENTRIES,
                "property_bytes": MAX_OBJECT_EXPERIMENT_PROPERTY_BYTES,
                "value_bytes": MAX_OBJECT_EXPERIMENT_VALUE_BYTES,
                "value_depth": MAX_OBJECT_EXPERIMENT_VALUE_DEPTH,
                "value_entries": MAX_OBJECT_EXPERIMENT_VALUE_ENTRIES,
                "value_string_bytes": MAX_OBJECT_EXPERIMENT_STRING_BYTES,
            },
        }

    @staticmethod
    def _empty_runtime_hooks() -> dict[str, Any]:
        return {
            "protocol_version": 1,
            "session_id": 0,
            "state": "idle",
            "isolated": False,
            "target_id": None,
            "definitions": [],
            "active_points": 0,
            "total_hits": 0,
            "hits": [],
            "hit_evictions": 0,
            "last_failure": None,
            "message": "Create an isolated Experiment context to use Runtime Hooks.",
            "limits": {
                "definitions": MAX_RUNTIME_HOOKS,
                "active_points": MAX_RUNTIME_HOOK_BREAKPOINTS,
                "return_points_per_definition": MAX_RUNTIME_HOOK_RETURN_POINTS,
                "total_hits": MAX_RUNTIME_HOOK_HITS,
                "retained_hits": MAX_RUNTIME_HOOK_RETAINED_HITS,
                "bindings_per_hit": MAX_RUNTIME_HOOK_BINDINGS,
                "binding_preview_bytes": MAX_RUNTIME_HOOK_BINDING_PREVIEW_BYTES,
                "condition_bytes": MAX_RUNTIME_HOOK_CONDITION_BYTES,
                "logic_bytes": MAX_RUNTIME_HOOK_LOGIC_BYTES,
                "return_bytes": MAX_RUNTIME_HOOK_RETURN_BYTES,
                "evaluation_timeout_ms": RUNTIME_HOOK_EVALUATION_TIMEOUT_MS,
            },
        }

    @staticmethod
    def _empty_automation_recipes() -> dict[str, Any]:
        return {
            "protocol_version": 1,
            "session_id": 0,
            "state": "idle",
            "isolated": False,
            "target_id": None,
            "recipes": [],
            "source_bytes": 0,
            "auto_armed": False,
            "active_run": None,
            "total_runs": 0,
            "automatic_runs": 0,
            "runs": [],
            "run_evictions": 0,
            "dropped_triggers": 0,
            "variable_count": 0,
            "variable_bytes": 0,
            "last_failure": None,
            "message": "Create recipes now, then open an isolated Experiment context to run them.",
            "limits": {
                "recipes": MAX_AUTOMATION_RECIPES,
                "automatic_recipes": MAX_AUTOMATION_AUTO_RECIPES,
                "recipe_source_bytes": MAX_AUTOMATION_RECIPE_SOURCE_BYTES,
                "total_source_bytes": MAX_AUTOMATION_TOTAL_SOURCE_BYTES,
                "variables": MAX_AUTOMATION_VARIABLES,
                "variable_value_bytes": MAX_AUTOMATION_VARIABLE_VALUE_BYTES,
                "variable_bytes": MAX_AUTOMATION_VARIABLE_BYTES,
                "total_runs": MAX_AUTOMATION_RUNS,
                "automatic_runs": MAX_AUTOMATION_AUTO_RUNS,
                "retained_runs": MAX_AUTOMATION_RETAINED_RUNS,
                "logs_per_run": MAX_AUTOMATION_LOGS,
                "log_bytes": MAX_AUTOMATION_LOG_BYTES,
                "result_bytes": MAX_AUTOMATION_RESULT_BYTES,
                "execution_timeout_ms": AUTOMATION_EXECUTION_TIMEOUT_MS,
            },
        }

    @staticmethod
    def _empty_repeater() -> dict[str, Any]:
        return {
            "protocol_version": 1,
            "session_id": 0,
            "state": "idle",
            "variables": [],
            "history": [],
            "history_bytes": 0,
            "history_evictions": 0,
            "active_execution": None,
            "comparison": None,
            "message": "Create an isolated request-lab context to use Repeater.",
            "limits": {
                "history_entries": MAX_REPEATER_HISTORY_ENTRIES,
                "history_bytes": MAX_REPEATER_HISTORY_BYTES,
                "variables": MAX_REPEATER_VARIABLES,
                "variable_bytes": MAX_REPEATER_VARIABLE_BYTES,
                "request_bytes": MAX_INTERCEPTION_BODY_BYTES,
                "response_bytes": MAX_INTERCEPTION_RESPONSE_BYTES,
                "timeout_ms": MAX_REPEATER_TIMEOUT_MS,
            },
        }

    def _begin_repeater_session_locked(self, session_id: int) -> None:
        self._repeater = self._empty_repeater()
        self._repeater.update(
            {
                "session_id": session_id,
                "state": "attaching",
                "message": "Waiting for the disposable page debugger to attach.",
            }
        )
        self._repeater_history_bytes = 0
        self._repeater_active_execution_id = None
        self._repeater_cancel_requested = False

    def _begin_object_experiment_session_locked(self, session_id: int) -> None:
        self._object_experiment = self._empty_object_experiment()
        self._object_experiment.update(
            {
                "session_id": session_id,
                "state": "attaching",
                "message": "Waiting for the disposable Object Lab page to attach.",
            }
        )
        self._object_experiment_group = None
        self._object_experiment_objects_id = None
        self._object_experiment_result_indices.clear()

    def _begin_runtime_hook_session_locked(self, session_id: int) -> None:
        self._runtime_hooks = self._empty_runtime_hooks()
        self._runtime_hooks.update(
            {
                "session_id": session_id,
                "state": "attaching",
                "message": "Waiting for the disposable Runtime Hooks page to attach.",
            }
        )
        self._runtime_hook_points.clear()
        self._runtime_hook_processing = False
        self._runtime_hook_stop_requested = False
        self._runtime_hook_deferred_pause = None
        self._runtime_hook_epoch += 1

    def _begin_automation_session_locked(self, session_id: int) -> None:
        self._cancel_automation_watchdog_locked()
        self._automation_recipes_state = self._empty_automation_recipes()
        self._automation_recipes_state.update(
            {
                "session_id": session_id,
                "state": "attaching",
                "recipes": copy.deepcopy(self._automation_recipes),
                "source_bytes": self._automation_source_bytes,
                "message": "Waiting for the disposable Automation Recipes page to attach.",
            }
        )
        self._automation_variables = {}
        self._automation_auto_script_ids = {}
        self._automation_binding_target_ids = set()
        self._automation_binding_nonce = None
        self._automation_active_run_id = None
        self._automation_active_document_id = None
        self._automation_active_target_id = None
        self._automation_active_session = None
        self._automation_cancel_requested = False
        self._automation_pending_triggers = []
        self._automation_processing = False
        self._automation_epoch += 1

    def _dispose_object_experiment_locked(self, session_id: int) -> None:
        self._object_experiment = self._empty_object_experiment()
        self._object_experiment.update(
            {
                "session_id": session_id,
                "state": "disposed",
                "message": (
                    "Disposable context deleted. Object references, mutation values, "
                    "previews, and audit records were cleared."
                ),
            }
        )
        self._object_experiment_group = None
        self._object_experiment_objects_id = None
        self._object_experiment_result_indices.clear()

    def _dispose_runtime_hooks_locked(self, session_id: int) -> None:
        self._runtime_hooks = self._empty_runtime_hooks()
        self._runtime_hooks.update(
            {
                "session_id": session_id,
                "state": "disposed",
                "message": (
                    "Disposable context deleted. Hook code, captured bindings, "
                    "return values, and hit records were cleared."
                ),
            }
        )
        self._runtime_hook_points.clear()
        self._runtime_hook_processing = False
        self._runtime_hook_stop_requested = False
        self._runtime_hook_deferred_pause = None
        self._runtime_hook_epoch += 1

    def _dispose_automation_locked(self, session_id: int) -> None:
        self._cancel_automation_watchdog_locked()
        self._automation_recipes_state = self._empty_automation_recipes()
        self._automation_recipes_state.update(
            {
                "session_id": session_id,
                "state": "disposed",
                "recipes": copy.deepcopy(self._automation_recipes),
                "source_bytes": self._automation_source_bytes,
                "message": (
                    "Disposable context deleted. Variables, results, logs, and "
                    "automatic execution state were erased; recipe definitions remain local."
                ),
            }
        )
        self._automation_variables = {}
        self._automation_auto_script_ids = {}
        self._automation_binding_target_ids = set()
        self._automation_binding_nonce = None
        self._automation_active_run_id = None
        self._automation_active_document_id = None
        self._automation_active_target_id = None
        self._automation_active_session = None
        self._automation_cancel_requested = False
        self._automation_pending_triggers = []
        self._automation_processing = False
        self._automation_epoch += 1

    def _dispose_repeater_locked(self, session_id: int) -> None:
        self._repeater = self._empty_repeater()
        self._repeater.update(
            {
                "session_id": session_id,
                "state": "disposed",
                "message": (
                    "Disposable context deleted. Repeater variables, request bodies, "
                    "responses, and history were cleared."
                ),
            }
        )
        self._repeater_history_bytes = 0
        self._repeater_active_execution_id = None
        self._repeater_cancel_requested = False

    def _repeater_context_ready_locked(self) -> bool:
        return (
            self._request_interception_context_id is not None
            and self._request_interception["target_id"] is not None
            and self._target is not None
            and self._target["id"] == self._request_interception["target_id"]
            and self._request_interception["state"] in {"ready", "error"}
            and self._repeater["state"] in {"ready", "error"}
        )


    def _configure_repeater_variables(
        self, request: dict[str, Any]
    ) -> dict[str, Any]:
        variables = normalize_repeater_variables(request.get("variables", {}))
        with self._lock:
            if not self._repeater_context_ready_locked():
                raise DebuggerBridgeError("The isolated Repeater target is not ready")
            self._repeater["variables"] = variables
            self._repeater["state"] = "ready"
            self._repeater["message"] = (
                f"{len(variables)} session-scoped Repeater "
                f"{'variable is' if len(variables) == 1 else 'variables are'} ready."
            )
            self._changed()
            repeater = copy.deepcopy(self._repeater)
        return {"ok": True, "repeater": repeater, "generation": self.generation()}

    def _install_repeater_controller(self, execution_id: int) -> None:
        key = json.dumps(self._repeater_controller_key)
        identifier = json.dumps(str(execution_id))
        expression = f"""(() => {{
          const key = {key};
          const id = {identifier};
          let registry = globalThis[key];
          if (!(registry instanceof Map)) {{
            registry = new Map();
            Object.defineProperty(globalThis, key, {{value: registry, configurable: true}});
          }}
          if (registry.size >= 1 || registry.has(id)) return false;
          registry.set(id, new AbortController());
          return true;
        }})()"""
        evaluated = self._command(
            "Runtime.evaluate",
            {
                "expression": expression,
                "returnByValue": True,
                "awaitPromise": False,
                "silent": True,
                "userGesture": False,
            },
            timeout=3.0,
        )
        remote = evaluated.get("result")
        installed = remote.get("value") if isinstance(remote, dict) else None
        if installed is not True:
            raise DebuggerBridgeError("Repeater could not reserve a request controller")

    def _run_repeater_request(self, request: dict[str, Any]) -> dict[str, Any]:
        template = normalize_repeater_template(request)
        with self._lock:
            variables = copy.deepcopy(self._repeater["variables"])
        resolved, variable_names = resolve_repeater_request(template, variables)
        with self._lock:
            if not self._repeater_context_ready_locked():
                raise DebuggerBridgeError("The isolated Repeater target is not ready")
            if self._repeater_active_execution_id is not None:
                raise DebuggerBridgeError("A Repeater request is already running")
            execution_id = self._next_repeater_execution_id
            self._next_repeater_execution_id += 1
            session_id = self._repeater["session_id"]
            started_at_ms = int(time.time() * 1_000)
            self._repeater_active_execution_id = execution_id
            self._repeater_cancel_requested = False
            self._repeater["state"] = "running"
            self._repeater["active_execution"] = {
                "execution_id": execution_id,
                "started_at_ms": started_at_ms,
                "request": copy.deepcopy(template),
                "resolved_url": redacted_request_url(resolved["url"]),
                "resolved_method": resolved["method"],
                "variable_names": variable_names,
                "collection_request_id": template["collection_request_id"],
                "cancel_requested": False,
            }
            self._repeater["message"] = (
                "Sending one credential-free Repeater request through the disposable page."
            )
            self._changed()
        try:
            self._install_repeater_controller(execution_id)
        except BaseException as exception:
            with self._lock:
                if self._repeater_active_execution_id == execution_id:
                    self._repeater_active_execution_id = None
                    self._repeater["active_execution"] = None
                    self._repeater["state"] = "error"
                    self._repeater["message"] = truncate_text(str(exception), 512)
                    self._changed()
            raise

        worker = threading.Thread(
            target=self._execute_repeater_request,
            args=(
                session_id,
                execution_id,
                started_at_ms,
                template,
                resolved,
                variable_names,
            ),
            name="reb-repeater-request",
            daemon=True,
        )
        try:
            worker.start()
        except RuntimeError as exception:
            try:
                self._abort_repeater_controller(execution_id)
            except DebuggerBridgeError:
                pass
            with self._lock:
                if self._repeater_active_execution_id == execution_id:
                    self._repeater_active_execution_id = None
                    self._repeater["active_execution"] = None
                    self._repeater["state"] = "error"
                    self._repeater["message"] = truncate_text(
                        f"Repeater worker could not start: {exception}", 512
                    )
                    self._changed()
            raise DebuggerBridgeError("Repeater worker could not start") from exception
        with self._lock:
            repeater = copy.deepcopy(self._repeater)
        return {"ok": True, "repeater": repeater, "generation": self.generation()}

    def _execute_repeater_request(
        self,
        session_id: int,
        execution_id: int,
        started_at_ms: int,
        template: dict[str, Any],
        resolved: dict[str, Any],
        variable_names: list[str],
    ) -> None:
        configuration = {
            "url": resolved["url"],
            "method": resolved["method"],
            "headers": {
                header["name"]: header["value"] for header in resolved["headers"]
            },
            "body": resolved["body"],
            "timeoutMs": resolved["timeout_ms"],
            "headerLimit": MAX_INTERCEPTION_HEADERS,
            "headerValueLimit": MAX_INTERCEPTION_HEADER_VALUE_BYTES,
            "headerTotalLimit": MAX_INTERCEPTION_HEADER_BYTES,
            "responseByteLimit": MAX_INTERCEPTION_RESPONSE_BYTES,
            "controllerRegistryKey": self._repeater_controller_key,
            "executionId": str(execution_id),
        }
        expression = (
            f"({REQUEST_INTERCEPTION_FUNCTION})"
            f"({json.dumps(configuration, separators=(',', ':'))})"
        )
        try:
            evaluated = self._command(
                "Runtime.evaluate",
                {
                    "expression": expression,
                    "returnByValue": True,
                    "awaitPromise": True,
                    "silent": True,
                    "userGesture": False,
                    "timeout": resolved["timeout_ms"],
                },
                timeout=resolved["timeout_ms"] / 1_000.0 + 2.0,
            )
            if isinstance(evaluated.get("exceptionDetails"), dict):
                raise DebuggerBridgeError(
                    "The isolated Repeater runner failed before returning a result"
                )
            remote = evaluated.get("result")
            document = remote.get("value") if isinstance(remote, dict) else None
            result = normalize_repeater_result(document)
        except BaseException as exception:
            with self._lock:
                cancelled = (
                    self._repeater_active_execution_id == execution_id
                    and self._repeater_cancel_requested
                )
            duration_ms = max(0, int(time.time() * 1_000) - started_at_ms)
            result = {
                "protocol_version": 1,
                "ok": False,
                "status": 0,
                "status_text": "",
                "url": "",
                "headers": [],
                "headers_truncated": False,
                "body": "",
                "body_truncated": False,
                "error": truncate_text(
                    "Request cancelled" if cancelled else str(exception), 512
                ),
                "duration_ms": duration_ms,
                "cancelled": cancelled,
                "timed_out": False,
                "body_sha256": hashlib.sha256(b"").hexdigest(),
            }
        self._complete_repeater_execution(
            session_id,
            execution_id,
            started_at_ms,
            template,
            resolved,
            variable_names,
            result,
        )


    def _complete_repeater_execution(
        self,
        session_id: int,
        execution_id: int,
        started_at_ms: int,
        template: dict[str, Any],
        resolved: dict[str, Any],
        variable_names: list[str],
        result: dict[str, Any],
    ) -> None:
        with self._lock:
            if (
                self._repeater["session_id"] != session_id
                or self._repeater_active_execution_id != execution_id
            ):
                return
            completed_at_ms = max(
                started_at_ms, int(time.time() * 1_000)
            )
            entry_state = (
                "complete"
                if result["ok"]
                else "cancelled"
                if result["cancelled"]
                else "timed_out"
                if result["timed_out"]
                else "error"
            )
            entry = {
                "id": execution_id,
                "started_at_ms": started_at_ms,
                "completed_at_ms": completed_at_ms,
                "state": entry_state,
                "collection_request_id": template["collection_request_id"],
                "variable_names": variable_names,
                "request": copy.deepcopy(template),
                "resolved_request": {
                    "url": resolved["url"],
                    "method": resolved["method"],
                    "headers": copy.deepcopy(resolved["headers"]),
                    "body": resolved["body"],
                    "timeout_ms": resolved["timeout_ms"],
                },
                "response": copy.deepcopy(result),
            }
            self._append_repeater_history_locked(entry)
            self._repeater_active_execution_id = None
            self._repeater_cancel_requested = False
            self._repeater["active_execution"] = None
            self._repeater["state"] = "ready"
            self._repeater["message"] = (
                f"Repeater request completed with status {result['status']}."
                if result["ok"]
                else "Repeater request was cancelled."
                if result["cancelled"]
                else "Repeater request reached its timeout."
                if result["timed_out"]
                else f"Repeater request failed: {result['error']}"
            )
            successful = [
                item for item in self._repeater["history"] if item["response"]["ok"]
            ]
            if len(successful) >= 2:
                self._repeater["comparison"] = compare_repeater_entries(
                    successful[-2], successful[-1]
                )
            self._changed()

    def _append_repeater_history_locked(self, entry: dict[str, Any]) -> None:
        stored_bytes = len(
            json.dumps(entry, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8"
            )
        )
        entry["stored_bytes"] = stored_bytes
        history = self._repeater["history"]
        while history and (
            len(history) >= MAX_REPEATER_HISTORY_ENTRIES
            or self._repeater_history_bytes + stored_bytes
            > MAX_REPEATER_HISTORY_BYTES
        ):
            evicted = history.pop(0)
            self._repeater_history_bytes -= evicted["stored_bytes"]
            self._repeater["history_evictions"] += 1
        history.append(entry)
        self._repeater_history_bytes += stored_bytes
        self._repeater["history_bytes"] = self._repeater_history_bytes
        comparison = self._repeater.get("comparison")
        retained_ids = {item["id"] for item in history}
        if comparison is not None and (
            comparison["baseline_id"] not in retained_ids
            or comparison["current_id"] not in retained_ids
        ):
            self._repeater["comparison"] = None

    def _abort_repeater_controller(self, execution_id: int) -> bool:
        key = json.dumps(self._repeater_controller_key)
        identifier = json.dumps(str(execution_id))
        expression = f"""(() => {{
          const registry = globalThis[{key}];
          const controller = registry instanceof Map ? registry.get({identifier}) : null;
          if (!(controller instanceof AbortController)) return false;
          controller.abort();
          return true;
        }})()"""
        evaluated = self._command(
            "Runtime.evaluate",
            {
                "expression": expression,
                "returnByValue": True,
                "awaitPromise": False,
                "silent": True,
                "userGesture": False,
            },
            timeout=3.0,
        )
        remote = evaluated.get("result")
        value = remote.get("value") if isinstance(remote, dict) else None
        if not isinstance(value, bool):
            raise ProtocolError("Debugger returned a malformed cancellation result")
        return value

    def _cancel_repeater_request(self) -> dict[str, Any]:
        with self._lock:
            execution_id = self._repeater_active_execution_id
            if execution_id is None:
                raise DebuggerBridgeError("No Repeater request is running")
            self._repeater_cancel_requested = True
            self._repeater["state"] = "cancelling"
            if self._repeater["active_execution"] is not None:
                self._repeater["active_execution"]["cancel_requested"] = True
            self._repeater["message"] = "Cancelling the active Repeater request."
            self._changed()
        try:
            delivered = self._abort_repeater_controller(execution_id)
        except BaseException:
            with self._lock:
                if self._repeater_active_execution_id == execution_id:
                    self._repeater_cancel_requested = False
                    self._repeater["state"] = "running"
                    if self._repeater["active_execution"] is not None:
                        self._repeater["active_execution"]["cancel_requested"] = False
                    self._repeater["message"] = (
                        "Cancellation could not be delivered; the request is still running."
                    )
                    self._changed()
            raise
        with self._lock:
            if self._repeater_active_execution_id == execution_id and not delivered:
                self._repeater_cancel_requested = False
                self._repeater["state"] = "running"
                if self._repeater["active_execution"] is not None:
                    self._repeater["active_execution"]["cancel_requested"] = False
                self._repeater["message"] = (
                    "The request completed before cancellation was delivered."
                )
                self._changed()
            repeater = copy.deepcopy(self._repeater)
        return {"ok": True, "repeater": repeater, "generation": self.generation()}


    def _compare_repeater_history(
        self, request: dict[str, Any]
    ) -> dict[str, Any]:
        baseline_id = request.get("baseline_id")
        current_id = request.get("current_id")
        if (
            not isinstance(baseline_id, int)
            or isinstance(baseline_id, bool)
            or baseline_id <= 0
            or not isinstance(current_id, int)
            or isinstance(current_id, bool)
            or current_id <= 0
            or baseline_id == current_id
        ):
            raise DebuggerBridgeError("Repeater comparison identifiers are invalid")
        with self._lock:
            entries = {entry["id"]: entry for entry in self._repeater["history"]}
            baseline = entries.get(baseline_id)
            current = entries.get(current_id)
            if (
                baseline is None
                or current is None
                or not baseline["response"]["ok"]
                or not current["response"]["ok"]
            ):
                raise DebuggerBridgeError(
                    "Repeater comparison requires two retained successful responses"
                )
            self._repeater["comparison"] = compare_repeater_entries(
                baseline, current
            )
            self._repeater["message"] = (
                f"Compared Repeater runs {baseline_id} and {current_id}."
            )
            self._changed()
            repeater = copy.deepcopy(self._repeater)
        return {"ok": True, "repeater": repeater, "generation": self.generation()}

    def _clear_repeater_history(self) -> dict[str, Any]:
        with self._lock:
            if self._repeater_active_execution_id is not None:
                raise DebuggerBridgeError(
                    "Cancel or finish the active Repeater request before clearing history"
                )
            self._repeater["history"] = []
            self._repeater["history_bytes"] = 0
            self._repeater["history_evictions"] = 0
            self._repeater["comparison"] = None
            self._repeater_history_bytes = 0
            self._repeater["message"] = "Repeater history and comparisons were cleared."
            self._changed()
            repeater = copy.deepcopy(self._repeater)
        return {"ok": True, "repeater": repeater, "generation": self.generation()}

    def _sync_automation_library_locked(self) -> None:
        self._automation_recipes_state["recipes"] = copy.deepcopy(
            self._automation_recipes
        )
        self._automation_recipes_state["source_bytes"] = (
            self._automation_source_bytes
        )

    def _require_automation_library_editable_locked(self) -> None:
        if (
            self._automation_recipes_state["auto_armed"]
            or self._automation_active_run_id is not None
            or self._automation_processing
        ):
            raise DebuggerBridgeError(
                "Disarm or finish Automation Recipes before editing the recipe library"
            )


    def _add_automation_recipe(self, request: dict[str, Any]) -> dict[str, Any]:
        normalized = normalize_automation_recipe(request)
        with self._lock:
            self._require_automation_library_editable_locked()
            if len(self._automation_recipes) >= MAX_AUTOMATION_RECIPES:
                raise DebuggerBridgeError("Automation recipe limit reached")
            if (
                self._automation_source_bytes + normalized["source_bytes"]
                > MAX_AUTOMATION_TOTAL_SOURCE_BYTES
            ):
                raise DebuggerBridgeError(
                    "Automation recipe library exceeds the 64 KiB source limit"
                )
            recipe = {
                "id": self._next_automation_recipe_id,
                **normalized,
            }
            self._next_automation_recipe_id += 1
            self._automation_recipes.append(recipe)
            self._automation_source_bytes += recipe["source_bytes"]
            self._sync_automation_library_locked()
            self._automation_recipes_state["message"] = (
                f"Added recipe {recipe['label']}."
            )
            self._changed()
            state = copy.deepcopy(self._automation_recipes_state)
        return {
            "ok": True,
            "recipe": copy.deepcopy(recipe),
            "automation_recipes": state,
            "generation": self.generation(),
        }

    def _update_automation_recipe(self, request: dict[str, Any]) -> dict[str, Any]:
        recipe_id = automation_recipe_id(request)
        normalized = normalize_automation_recipe(request)
        with self._lock:
            self._require_automation_library_editable_locked()
            index = next(
                (
                    index
                    for index, recipe in enumerate(self._automation_recipes)
                    if recipe["id"] == recipe_id
                ),
                None,
            )
            if index is None:
                raise DebuggerBridgeError("Automation recipe is unavailable")
            existing = self._automation_recipes[index]
            source_bytes = (
                self._automation_source_bytes
                - existing["source_bytes"]
                + normalized["source_bytes"]
            )
            if source_bytes > MAX_AUTOMATION_TOTAL_SOURCE_BYTES:
                raise DebuggerBridgeError(
                    "Automation recipe library exceeds the 64 KiB source limit"
                )
            recipe = {"id": recipe_id, **normalized}
            self._automation_recipes[index] = recipe
            self._automation_source_bytes = source_bytes
            self._sync_automation_library_locked()
            self._automation_recipes_state["message"] = (
                f"Updated recipe {recipe['label']}."
            )
            self._changed()
            state = copy.deepcopy(self._automation_recipes_state)
        return {
            "ok": True,
            "recipe": copy.deepcopy(recipe),
            "automation_recipes": state,
            "generation": self.generation(),
        }

    def _remove_automation_recipe(self, request: dict[str, Any]) -> dict[str, Any]:
        recipe_id = automation_recipe_id(request)
        with self._lock:
            self._require_automation_library_editable_locked()
            recipe = next(
                (
                    recipe
                    for recipe in self._automation_recipes
                    if recipe["id"] == recipe_id
                ),
                None,
            )
            if recipe is None:
                raise DebuggerBridgeError("Automation recipe is unavailable")
            self._automation_recipes = [
                item for item in self._automation_recipes if item["id"] != recipe_id
            ]
            self._automation_source_bytes -= recipe["source_bytes"]
            self._sync_automation_library_locked()
            self._automation_recipes_state["message"] = (
                f"Removed recipe {recipe['label']}."
            )
            self._changed()
            state = copy.deepcopy(self._automation_recipes_state)
        return {
            "ok": True,
            "automation_recipes": state,
            "generation": self.generation(),
        }


    def _require_automation_target_locked(
        self,
    ) -> list[Optional[ActionScopeTargetSession]]:
        if (
            self._request_interception_context_id is None
            or self._automation_recipes_state["target_id"] is None
            or self._target is None
            or self._target["id"] != self._automation_recipes_state["target_id"]
            or self._state not in {"running", "paused"}
            or not self._automation_recipes_state["isolated"]
        ):
            raise DebuggerBridgeError(
                "Automation Recipes requires its attached disposable Experiment page"
            )
        if self._action_scope_targets:
            return list(
                self._require_action_scope_sessions_locked("Automation Recipes")
            )
        return [None]

    def _automation_recipe_locked(self, recipe_id: int) -> dict[str, Any]:
        recipe = next(
            (
                recipe
                for recipe in self._automation_recipes
                if recipe["id"] == recipe_id
            ),
            None,
        )
        if recipe is None:
            raise DebuggerBridgeError("Automation recipe is unavailable")
        return copy.deepcopy(recipe)


    def _automation_before_load_source(
        self,
        recipes: list[dict[str, Any]],
        variables: dict[str, str],
        nonce: str,
    ) -> str:
        configs = [
            {
                "recipeId": recipe["id"],
                "config": automation_runner_config(
                    recipe, variables, binding=True
                ),
            }
            for recipe in recipes
        ]
        binding = json.dumps(self._automation_binding_name)
        encoded_nonce = json.dumps(nonce)
        encoded_configs = json.dumps(configs, separators=(",", ":"))
        return f"""(() => {{
  if (globalThis !== globalThis.top) return;
  const report = globalThis[{binding}];
  if (typeof report !== "function") return;
  const run = ({AUTOMATION_RECIPE_FUNCTION});
  const nonce = {encoded_nonce};
  const documentId = `${{Date.now()}}-${{Math.random().toString(16).slice(2)}}`;
  const configs = {encoded_configs};
  const reportEncoder = new TextEncoder();
  const send = value => {{
    let payload = JSON.stringify(value);
    if (reportEncoder.encode(payload).length > {MAX_AUTOMATION_BINDING_REPORT_BYTES}) {{
      const result = value && value.kind === "done" && value.result;
      if (!result || typeof result !== "object") return;
      value = {{...value, result: {{...result, resultText: "", resultTruncated: true,
        logs: [], logsTruncated: true}}}};
      payload = JSON.stringify(value);
      if (reportEncoder.encode(payload).length > {MAX_AUTOMATION_BINDING_REPORT_BYTES}) return;
    }}
    report(payload);
  }};
  void (async () => {{
    for (const entry of configs) {{
      send({{protocolVersion:1, nonce, kind:"start", recipeId:entry.recipeId, documentId}});
      const result = await run(entry.config);
      send({{protocolVersion:1, nonce, kind:"done", recipeId:entry.recipeId, documentId, result}});
    }}
  }})();
}})();
//# sourceURL=reb-automation-before-load.js"""

    def _automation_source_locked(self, target_id: Optional[str] = None) -> str:
        if target_id is not None:
            target = self._action_scope_targets.get(target_id)
            if target is not None:
                source = target.get("url", "")
                return (
                    redacted_request_url(source)
                    if source.startswith(("http://", "https://"))
                    else truncate_text(source, MAX_TARGET_URL_BYTES)
                    if source
                    else "about:blank"
                )
        source = self._object_experiment.get("url", "")
        if not source and self._target is not None:
            source = self._target.get("url", "")
        return redacted_request_url(source) if source else "about:blank"

    def _start_automation_run_locked(
        self,
        recipe: dict[str, Any],
        trigger: str,
        automatic: bool,
        document_id: Optional[str] = None,
        target_id: Optional[str] = None,
        session: Optional[ActionScopeTargetSession] = None,
    ) -> int:
        if self._automation_active_run_id is not None:
            raise DebuggerBridgeError("Another Automation Recipe is already running")
        if self._automation_recipes_state["total_runs"] >= MAX_AUTOMATION_RUNS:
            raise DebuggerBridgeError("Automation session run limit reached")
        if (
            automatic
            and self._automation_recipes_state["automatic_runs"]
            >= MAX_AUTOMATION_AUTO_RUNS
        ):
            raise DebuggerBridgeError("Automatic recipe run limit reached")
        run_id = self._next_automation_run_id
        self._next_automation_run_id += 1
        started_at_ms = int(time.time() * 1_000)
        active = {
            "id": run_id,
            "recipe_id": recipe["id"],
            "label": recipe["label"],
            "trigger": trigger,
            "automatic": automatic,
            "source": self._automation_source_locked(target_id),
            "target_id": target_id
            or self._automation_recipes_state.get("target_id"),
            "started_at_ms": started_at_ms,
            "cancel_requested": False,
        }
        self._automation_active_run_id = run_id
        self._automation_active_document_id = document_id
        self._automation_active_target_id = active["target_id"]
        self._automation_active_session = session
        self._automation_cancel_requested = False
        self._automation_recipes_state["active_run"] = {
            key: value
            for key, value in active.items()
            if key != "automatic"
        }
        self._automation_recipes_state["total_runs"] += 1
        if automatic:
            self._automation_recipes_state["automatic_runs"] += 1
        self._automation_recipes_state["state"] = "running"
        self._automation_recipes_state["message"] = (
            f"Running {recipe['label']} for {trigger}."
        )
        self._changed()
        return run_id


    def _finish_automation_run_locked(
        self,
        run_id: int,
        result: dict[str, Any],
        outcome: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        active = self._automation_recipes_state.get("active_run")
        if (
            self._automation_active_run_id != run_id
            or not isinstance(active, dict)
            or active.get("id") != run_id
        ):
            return next(
                (
                    copy.deepcopy(run)
                    for run in self._automation_recipes_state["runs"]
                    if run["id"] == run_id
                ),
                None,
            )
        if outcome is None:
            outcome = "completed" if result["ok"] else "failed"
        duration_ms = max(
            0,
            int(time.time() * 1_000) - active["started_at_ms"],
        )
        run = {
            "id": run_id,
            "session_id": self._automation_recipes_state["session_id"],
            "recipe_id": active["recipe_id"],
            "label": active["label"],
            "occurred_at_ms": active["started_at_ms"],
            "source": active["source"],
            "category": active["trigger"],
            "operation": outcome,
            "duration_ms": duration_ms,
            "target_id": active["target_id"],
            "result_type": result["result_type"],
            "result_text": result["result_text"],
            "result_truncated": result["result_truncated"],
            "logs": copy.deepcopy(result["logs"]),
            "logs_truncated": result["logs_truncated"],
            "error": result["error"],
        }
        runs = self._automation_recipes_state["runs"]
        if len(runs) >= MAX_AUTOMATION_RETAINED_RUNS:
            runs.pop(0)
            self._automation_recipes_state["run_evictions"] += 1
        runs.append(run)
        self._automation_active_run_id = None
        self._automation_active_document_id = None
        self._automation_active_target_id = None
        self._automation_active_session = None
        self._automation_cancel_requested = False
        self._automation_recipes_state["active_run"] = None
        if outcome in {"failed", "timed_out"}:
            self._automation_recipes_state["last_failure"] = result["error"]
        else:
            self._automation_recipes_state["last_failure"] = None
        self._automation_recipes_state["state"] = (
            "armed" if self._automation_recipes_state["auto_armed"] else "ready"
        )
        self._automation_recipes_state["message"] = (
            f"{active['label']} {outcome.replace('_', ' ')} in {duration_ms} ms."
        )
        self._changed()
        return copy.deepcopy(run)


    def _execute_automation_recipe(
        self,
        recipe: dict[str, Any],
        trigger: str,
        automatic: bool,
        target_id: Optional[str] = None,
        session: Optional[ActionScopeTargetSession] = None,
    ) -> Optional[dict[str, Any]]:
        with self._lock:
            if automatic and not self._automation_recipes_state["auto_armed"]:
                return None
            sessions = self._require_automation_target_locked()
            if self._action_scope_targets and session not in sessions:
                raise DebuggerBridgeError(
                    "Automation target is outside the active action scope"
                )
            resolved_target_id = (
                session.target_id
                if session is not None
                else target_id or self._automation_recipes_state.get("target_id")
            )
            run_id = self._start_automation_run_locked(
                recipe,
                trigger,
                automatic,
                target_id=resolved_target_id,
                session=session,
            )
            variables = dict(self._automation_variables)
        configuration = automation_runner_config(recipe, variables)
        expression = (
            f"({AUTOMATION_RECIPE_FUNCTION})"
            f"({json.dumps(configuration, separators=(',', ':'))})"
            "\n//# sourceURL=reb-automation-runner.js"
        )
        outcome: Optional[str] = None
        runner_failure = False
        try:
            evaluated = self._scoped_command(
                session,
                "Runtime.evaluate",
                {
                    "expression": expression,
                    "returnByValue": True,
                    "awaitPromise": True,
                    "silent": True,
                    "userGesture": False,
                    "allowUnsafeEvalBlockedByCSP": True,
                    "timeout": AUTOMATION_EXECUTION_TIMEOUT_MS,
                },
                timeout=(AUTOMATION_EXECUTION_TIMEOUT_MS / 1_000)
                + AUTOMATION_WATCHDOG_GRACE_SECONDS
                + 1.0,
            )
            if isinstance(evaluated.get("exceptionDetails"), dict):
                raise DebuggerBridgeError(
                    "The automation recipe failed before returning a result"
                )
            remote = evaluated.get("result")
            document = remote.get("value") if isinstance(remote, dict) else None
            result = normalize_automation_result(document)
            if result["timed_out"]:
                outcome = "timed_out"
        except BaseException as exception:
            runner_failure = True
            with self._lock:
                cancelled = self._automation_cancel_requested
            message = str(exception)
            if cancelled:
                outcome = "cancelled"
                message = "Recipe cancelled"
            elif "timed out" in message.lower() or "terminated" in message.lower():
                outcome = "timed_out"
                message = "Recipe exceeded the 2 second execution limit"
            result = automation_failure_result(message)
        with self._lock:
            run = self._finish_automation_run_locked(run_id, result, outcome)
        timed_out = result["timed_out"] or outcome == "timed_out"
        if timed_out:
            if automatic:
                try:
                    self._disarm_automation_recipes(
                        reason="An automatic recipe timed out; automatic triggers were disarmed."
                    )
                except DebuggerBridgeError:
                    pass
            try:
                self._scoped_command(
                    session, "Runtime.terminateExecution", timeout=3.0
                )
            except DebuggerBridgeError:
                pass
            try:
                self._scoped_command(
                    session, "Page.reload", {"ignoreCache": True}, timeout=3.0
                )
            except DebuggerBridgeError:
                pass
        elif automatic and runner_failure:
            try:
                self._disarm_automation_recipes(
                    reason=(
                        "An automatic recipe runner failed; automatic triggers "
                        "were disarmed."
                    )
                )
            except DebuggerBridgeError:
                pass
        return run

    def _run_automation_recipe(self, request: dict[str, Any]) -> dict[str, Any]:
        if request.get("confirmed") is not True:
            raise DebuggerBridgeError(
                "Confirm manual page-context code execution before running a recipe"
            )
        recipe_id = automation_recipe_id(request)
        variables, variable_bytes = normalize_automation_variables(request)
        with self._lock:
            sessions = self._require_automation_target_locked()
            if self._automation_recipes_state["auto_armed"]:
                raise DebuggerBridgeError(
                    "Disarm automatic recipes before starting a manual run"
                )
            recipe = self._automation_recipe_locked(recipe_id)
            self._automation_variables = variables
            self._automation_recipes_state["variable_count"] = len(variables)
            self._automation_recipes_state["variable_bytes"] = variable_bytes
            self._changed()
        runs = []
        for session in sessions:
            run = self._execute_automation_recipe(
                recipe,
                "manual",
                automatic=False,
                target_id=session.target_id if session is not None else None,
                session=session,
            )
            if run is not None:
                runs.append(run)
        with self._lock:
            state = copy.deepcopy(self._automation_recipes_state)
        return {
            "ok": True,
            "run": runs[-1] if runs else None,
            "runs": runs,
            "automation_recipes": state,
            "generation": self.generation(),
        }

    def _queue_automation_trigger(
        self, trigger: str, target_id: Optional[str] = None
    ) -> None:
        with self._lock:
            if not self._automation_recipes_state["auto_armed"]:
                return
            has_recipes = any(
                recipe["enabled"] and recipe["trigger"] == trigger
                for recipe in self._automation_recipes
            )
            if not has_recipes:
                return
            if target_id is None:
                target_id = self._automation_recipes_state.get("target_id")
            if not isinstance(target_id, str) or not target_id:
                return
            if self._action_scope_targets and (
                not self._action_scope_matches_locked(target_id)
                or target_id not in self._action_scope_sessions
            ):
                return
            if self._automation_processing or self._automation_active_run_id is not None:
                pending = (target_id, trigger)
                if pending in self._automation_pending_triggers:
                    return
                if (
                    len(self._automation_pending_triggers)
                    < MAX_ACTION_SCOPE_PENDING_TRIGGERS
                ):
                    self._automation_pending_triggers.append(pending)
                else:
                    self._automation_recipes_state["dropped_triggers"] += 1
                    self._automation_recipes_state["message"] = (
                        "Dropped an automatic trigger batch because the bounded queue was full."
                    )
                    self._changed()
                return
            self._automation_processing = True
            epoch = self._automation_epoch
        worker = threading.Thread(
            target=self._run_automation_trigger_worker,
            args=(target_id, trigger, epoch),
            name="reb-automation-recipes",
            daemon=True,
        )
        try:
            worker.start()
        except RuntimeError as exception:
            with self._lock:
                if epoch == self._automation_epoch:
                    self._automation_processing = False
                    message = truncate_text(
                        f"Automation worker could not start: {exception}", 512
                    )
                    self._automation_recipes_state["state"] = "error"
                    self._automation_recipes_state["last_failure"] = message
                    self._automation_recipes_state["message"] = message
                    self._changed()

    def _run_automation_trigger_worker(
        self, target_id: str, trigger: str, epoch: int
    ) -> None:
        try:
            with self._lock:
                recipes = [
                    copy.deepcopy(recipe)
                    for recipe in self._automation_recipes
                    if recipe["enabled"] and recipe["trigger"] == trigger
                ]
                session = self._action_scope_sessions.get(target_id)
                if self._action_scope_targets and session is None:
                    raise DebuggerBridgeError(
                        "Automatic recipe target disconnected before execution"
                    )
            for recipe in recipes:
                with self._lock:
                    if (
                        epoch != self._automation_epoch
                        or not self._automation_recipes_state["auto_armed"]
                    ):
                        break
                    limit_reached = (
                        self._automation_recipes_state["automatic_runs"]
                        >= MAX_AUTOMATION_AUTO_RUNS
                        or self._automation_recipes_state["total_runs"]
                        >= MAX_AUTOMATION_RUNS
                    )
                if limit_reached:
                    self._disarm_automation_recipes(
                        reason="Automatic recipe run limit reached; recipes were disarmed."
                    )
                    break
                self._execute_automation_recipe(
                    recipe,
                    trigger,
                    automatic=True,
                    target_id=target_id,
                    session=session,
                )
        except BaseException as exception:
            with self._lock:
                if epoch == self._automation_epoch:
                    message = truncate_text(str(exception), 512)
                    self._automation_recipes_state["last_failure"] = message
                    self._automation_recipes_state["message"] = message
                    self._automation_recipes_state["state"] = (
                        "armed"
                        if self._automation_recipes_state["auto_armed"]
                        else "error"
                    )
                    self._changed()
        finally:
            with self._lock:
                if epoch != self._automation_epoch:
                    return
                self._automation_processing = False
                pending = (
                    self._automation_pending_triggers.pop(0)
                    if self._automation_pending_triggers
                    else None
                )
                armed = self._automation_recipes_state["auto_armed"]
            if pending is not None and armed:
                self._queue_automation_trigger(pending[1], pending[0])

    def _arm_automation_recipes(self, request: dict[str, Any]) -> dict[str, Any]:
        if request.get("confirmed") is not True:
            raise DebuggerBridgeError(
                "Confirm automatic page-context code execution before arming recipes"
            )
        variables, variable_bytes = normalize_automation_variables(request)
        with self._lock:
            sessions = self._require_automation_target_locked()
            if self._automation_recipes_state["auto_armed"]:
                raise DebuggerBridgeError("Automation Recipes is already armed")
            auto_recipes = [
                copy.deepcopy(recipe)
                for recipe in self._automation_recipes
                if recipe["enabled"] and recipe["trigger"] != "manual"
            ]
            if not auto_recipes:
                raise DebuggerBridgeError(
                    "Enable at least one created, before-load, or after-load recipe"
                )
            if len(auto_recipes) > MAX_AUTOMATION_AUTO_RECIPES:
                raise DebuggerBridgeError("Automatic recipe limit reached")
            if self._automation_recipes_state["total_runs"] >= MAX_AUTOMATION_RUNS:
                raise DebuggerBridgeError("Automation session run limit reached")
            before_recipes = [
                recipe for recipe in auto_recipes if recipe["trigger"] == "before-load"
            ]
            nonce = os.urandom(16).hex()
            self._automation_recipes_state["state"] = "arming"
            self._automation_recipes_state["message"] = (
                "Installing bounded automatic recipe triggers."
            )
            self._changed()
        installed_scripts: dict[str, str] = {}
        binding_targets: set[str] = set()
        try:
            if before_recipes:
                for session in sessions:
                    target_id = (
                        session.target_id
                        if session is not None
                        else self._automation_recipes_state["target_id"]
                    )
                    self._scoped_command(
                        session,
                        "Runtime.addBinding",
                        {"name": self._automation_binding_name},
                    )
                    binding_targets.add(target_id)
                    installed = self._scoped_command(
                        session,
                        "Page.addScriptToEvaluateOnNewDocument",
                        {
                            "source": self._automation_before_load_source(
                                before_recipes, variables, nonce
                            ),
                            "runImmediately": False,
                        },
                    )
                    script_id = installed.get("identifier")
                    if (
                        not isinstance(script_id, str)
                        or not script_id
                        or len(script_id.encode("utf-8")) > MAX_TARGET_ID_BYTES
                    ):
                        raise ProtocolError(
                            "Debugger returned a malformed automation script identifier"
                        )
                    installed_scripts[target_id] = script_id
        except BaseException as exception:
            session_by_target = {
                (
                    session.target_id
                    if session is not None
                    else self._automation_recipes_state["target_id"]
                ): session
                for session in sessions
            }
            for target_id, script_id in installed_scripts.items():
                try:
                    self._scoped_command(
                        session_by_target.get(target_id),
                        "Page.removeScriptToEvaluateOnNewDocument",
                        {"identifier": script_id},
                    )
                except DebuggerBridgeError:
                    pass
            for target_id in binding_targets:
                try:
                    self._scoped_command(
                        session_by_target.get(target_id),
                        "Runtime.removeBinding", {"name": self._automation_binding_name}
                    )
                except DebuggerBridgeError:
                    pass
            with self._lock:
                message = truncate_text(str(exception), 512)
                self._automation_recipes_state["state"] = "error"
                self._automation_recipes_state["last_failure"] = message
                self._automation_recipes_state["message"] = message
                self._changed()
            raise
        with self._lock:
            self._automation_variables = variables
            self._automation_auto_script_ids = installed_scripts
            self._automation_binding_target_ids = binding_targets
            self._automation_binding_nonce = nonce if before_recipes else None
            self._automation_recipes_state["auto_armed"] = True
            self._automation_recipes_state["state"] = "armed"
            self._automation_recipes_state["variable_count"] = len(variables)
            self._automation_recipes_state["variable_bytes"] = variable_bytes
            self._automation_recipes_state["last_failure"] = None
            self._automation_recipes_state["message"] = (
                "Automatic recipes armed. Created recipes are running now."
            )
            self._changed()
            state = copy.deepcopy(self._automation_recipes_state)
        for session in sessions:
            self._queue_automation_trigger(
                "created",
                session.target_id
                if session is not None
                else self._automation_recipes_state["target_id"],
            )
        return {
            "ok": True,
            "automation_recipes": state,
            "generation": self.generation(),
        }

    def _cancel_automation_watchdog_locked(self) -> None:
        timer = self._automation_auto_watchdog
        self._automation_auto_watchdog = None
        if timer is not None:
            timer.cancel()

    def _disarm_automation_recipes(
        self, reason: str = "Automatic recipes disarmed and session variables erased."
    ) -> dict[str, Any]:
        with self._lock:
            armed = self._automation_recipes_state["auto_armed"]
            active = self._automation_active_run_id
            active_session = self._automation_active_session
            script_ids = dict(self._automation_auto_script_ids)
            binding_target_ids = set(self._automation_binding_target_ids)
            sessions = dict(self._action_scope_sessions)
            if not sessions and self._automation_recipes_state.get("target_id"):
                sessions[self._automation_recipes_state["target_id"]] = None
            if not armed and active is None and not script_ids:
                raise DebuggerBridgeError("Automation Recipes is not armed or running")
            self._automation_recipes_state["state"] = "stopping"
            self._automation_recipes_state["auto_armed"] = False
            self._automation_recipes_state["message"] = (
                "Stopping Automation Recipes and removing automatic triggers."
            )
            self._automation_epoch += 1
            self._automation_processing = False
            self._automation_pending_triggers = []
            if active is not None:
                self._automation_cancel_requested = True
                if self._automation_recipes_state["active_run"] is not None:
                    self._automation_recipes_state["active_run"][
                        "cancel_requested"
                    ] = True
            self._cancel_automation_watchdog_locked()
            self._changed()
        errors = []
        if active is not None:
            try:
                self._scoped_command(
                    active_session, "Runtime.terminateExecution", timeout=3.0
                )
            except DebuggerBridgeError as exception:
                errors.append(str(exception))
        for target_id, script_id in script_ids.items():
            try:
                self._scoped_command(
                    sessions.get(target_id),
                    "Page.removeScriptToEvaluateOnNewDocument",
                    {"identifier": script_id},
                )
            except DebuggerBridgeError as exception:
                errors.append(str(exception))
        for target_id in binding_target_ids:
            try:
                self._scoped_command(
                    sessions.get(target_id),
                    "Runtime.removeBinding", {"name": self._automation_binding_name}
                )
            except DebuggerBridgeError as exception:
                errors.append(str(exception))
        if active is not None:
            try:
                self._scoped_command(
                    active_session,
                    "Page.reload",
                    {"ignoreCache": True},
                    timeout=3.0,
                )
            except DebuggerBridgeError as exception:
                errors.append(str(exception))
        with self._lock:
            self._automation_auto_script_ids = {}
            self._automation_binding_target_ids = set()
            self._automation_binding_nonce = None
            self._automation_variables = {}
            self._automation_recipes_state["variable_count"] = 0
            self._automation_recipes_state["variable_bytes"] = 0
            if active is not None and self._automation_active_run_id == active:
                result = automation_failure_result("Recipe cancelled")
                self._finish_automation_run_locked(active, result, "cancelled")
            self._automation_recipes_state["state"] = "error" if errors else "ready"
            self._automation_recipes_state["message"] = (
                truncate_text("; ".join(errors), 512) if errors else reason
            )
            if errors:
                self._automation_recipes_state["last_failure"] = (
                    self._automation_recipes_state["message"]
                )
            self._changed()
            state = copy.deepcopy(self._automation_recipes_state)
        if errors:
            raise DebuggerBridgeError(state["message"])
        return {
            "ok": True,
            "automation_recipes": state,
            "generation": self.generation(),
        }

    def _cancel_automation_recipe(self) -> dict[str, Any]:
        with self._lock:
            run_id = self._automation_active_run_id
            if run_id is None:
                raise DebuggerBridgeError("No Automation Recipe is running")
            self._automation_cancel_requested = True
            self._automation_recipes_state["state"] = "stopping"
            if self._automation_recipes_state["active_run"] is not None:
                self._automation_recipes_state["active_run"][
                    "cancel_requested"
                ] = True
            self._automation_recipes_state["message"] = (
                "Cancelling the active Automation Recipe."
            )
            automatic = self._automation_recipes_state["auto_armed"]
            session = self._automation_active_session
            self._changed()
        if automatic:
            return self._disarm_automation_recipes(
                reason="The active automatic recipe was cancelled and automatic triggers were disarmed."
            )
        self._scoped_command(session, "Runtime.terminateExecution", timeout=3.0)
        self._scoped_command(
            session, "Page.reload", {"ignoreCache": True}, timeout=3.0
        )
        with self._lock:
            state = copy.deepcopy(self._automation_recipes_state)
        return {
            "ok": True,
            "automation_recipes": state,
            "generation": self.generation(),
        }

    def _clear_automation_runs(self) -> dict[str, Any]:
        with self._lock:
            if (
                self._automation_active_run_id is not None
                or self._automation_processing
                or self._automation_recipes_state["auto_armed"]
            ):
                raise DebuggerBridgeError(
                    "Disarm and finish Automation Recipes before clearing runs"
                )
            self._automation_recipes_state["runs"] = []
            self._automation_recipes_state["run_evictions"] = 0
            self._automation_recipes_state["total_runs"] = 0
            self._automation_recipes_state["automatic_runs"] = 0
            self._automation_recipes_state["dropped_triggers"] = 0
            self._automation_recipes_state["last_failure"] = None
            self._automation_variables = {}
            self._automation_recipes_state["variable_count"] = 0
            self._automation_recipes_state["variable_bytes"] = 0
            self._automation_recipes_state["message"] = (
                "Automation run results, logs, counters, and variables were cleared."
            )
            self._changed()
            state = copy.deepcopy(self._automation_recipes_state)
        return {
            "ok": True,
            "automation_recipes": state,
            "generation": self.generation(),
        }

    def _handle_automation_binding(
        self,
        params: dict[str, Any],
        target_id: Optional[str] = None,
        session: Optional[ActionScopeTargetSession] = None,
    ) -> None:
        name = params.get("name")
        payload = params.get("payload")
        if (
            name != self._automation_binding_name
            or not isinstance(payload, str)
            or len(payload.encode("utf-8")) > MAX_AUTOMATION_BINDING_REPORT_BYTES
        ):
            return
        try:
            value = json.loads(payload)
        except json.JSONDecodeError:
            return
        if not isinstance(value, dict) or value.get("protocolVersion") != 1:
            return
        nonce = value.get("nonce")
        recipe_id = value.get("recipeId")
        kind = value.get("kind")
        document_id = value.get("documentId")
        if (
            not isinstance(nonce, str)
            or not isinstance(recipe_id, int)
            or isinstance(recipe_id, bool)
            or kind not in {"start", "done"}
            or not isinstance(document_id, str)
            or not document_id
            or len(document_id.encode("utf-8")) > 128
        ):
            return
        start_timer: Optional[threading.Timer] = None
        pending: Optional[str] = None
        timed_out = False
        malformed = False
        with self._lock:
            if target_id is None:
                target_id = self._automation_recipes_state.get("target_id")
            if (
                nonce != self._automation_binding_nonce
                or not self._automation_recipes_state["auto_armed"]
                or not isinstance(target_id, str)
                or (
                    self._action_scope_targets
                    and (
                        self._action_scope_sessions.get(target_id) is not session
                        or not self._action_scope_matches_locked(target_id)
                    )
                )
            ):
                return
            recipe = next(
                (
                    recipe
                    for recipe in self._automation_recipes
                    if recipe["id"] == recipe_id
                    and recipe["enabled"]
                    and recipe["trigger"] == "before-load"
                ),
                None,
            )
            if recipe is None:
                return
            if kind == "start":
                if self._automation_active_run_id is not None:
                    self._automation_recipes_state["dropped_triggers"] += 1
                    self._changed()
                    return
                try:
                    run_id = self._start_automation_run_locked(
                        recipe,
                        "before-load",
                        automatic=True,
                        document_id=document_id,
                        target_id=target_id,
                        session=session,
                    )
                except DebuggerBridgeError as exception:
                    self._automation_recipes_state["last_failure"] = str(exception)
                    self._automation_recipes_state["message"] = str(exception)
                    self._changed()
                    return
                start_timer = threading.Timer(
                    (AUTOMATION_EXECUTION_TIMEOUT_MS / 1_000)
                    + AUTOMATION_WATCHDOG_GRACE_SECONDS,
                    self._automation_before_load_timeout,
                    args=(run_id, nonce, document_id),
                )
                start_timer.daemon = True
                self._automation_auto_watchdog = start_timer
            else:
                active = self._automation_recipes_state.get("active_run")
                if (
                    not isinstance(active, dict)
                    or active.get("recipe_id") != recipe_id
                    or self._automation_active_run_id != active.get("id")
                    or self._automation_active_document_id != document_id
                    or self._automation_active_target_id != target_id
                ):
                    return
                self._cancel_automation_watchdog_locked()
                try:
                    result = normalize_automation_result(value.get("result"))
                    timed_out = result["timed_out"]
                    self._finish_automation_run_locked(
                        active["id"], result, "timed_out" if timed_out else None
                    )
                    if timed_out:
                        self._automation_pending_triggers = []
                except ProtocolError as exception:
                    malformed = True
                    result = automation_failure_result(str(exception))
                    self._finish_automation_run_locked(
                        active["id"], result, "failed"
                    )
                pending = (
                    None
                    if timed_out or malformed
                    else self._automation_pending_triggers.pop(0)
                    if self._automation_pending_triggers
                    else None
                )
        if start_timer is not None:
            start_timer.start()
        if timed_out:
            threading.Thread(
                target=self._recover_automation_timeout,
                args=(session,),
                name="reb-automation-timeout-recovery",
                daemon=True,
            ).start()
        elif malformed:
            threading.Thread(
                target=self._disarm_automation_after_failure,
                name="reb-automation-failure-recovery",
                daemon=True,
            ).start()
        if pending is not None:
            self._queue_automation_trigger(pending[1], pending[0])

    def _disarm_automation_after_failure(self) -> None:
        try:
            self._disarm_automation_recipes(
                reason=(
                    "A malformed automatic recipe report was rejected; "
                    "automatic triggers were disarmed."
                )
            )
        except DebuggerBridgeError:
            pass

    def _recover_automation_timeout(
        self, session: Optional[ActionScopeTargetSession] = None
    ) -> None:
        try:
            self._disarm_automation_recipes(
                reason="An automatic recipe timed out; automatic triggers were disarmed."
            )
        except DebuggerBridgeError:
            pass
        try:
            self._scoped_command(
                session, "Runtime.terminateExecution", timeout=3.0
            )
        except DebuggerBridgeError:
            pass
        try:
            self._scoped_command(
                session, "Page.reload", {"ignoreCache": True}, timeout=3.0
            )
        except DebuggerBridgeError:
            pass

    def _automation_before_load_timeout(
        self, run_id: int, nonce: str, document_id: str
    ) -> None:
        with self._lock:
            active = self._automation_recipes_state.get("active_run")
            if (
                self._automation_active_run_id != run_id
                or self._automation_binding_nonce != nonce
                or not isinstance(active, dict)
                or active.get("id") != run_id
            ):
                return
            session = self._automation_active_session
            self._automation_auto_watchdog = None
            result = automation_failure_result(
                "Before-load recipe exceeded the 2 second execution limit"
            )
            self._finish_automation_run_locked(run_id, result, "timed_out")
        self._recover_automation_timeout(session)

    def _action_scope_matches_locked(self, target_id: str) -> bool:
        return self._action_scope_mode == "global" or (
            self._action_scope_target_id == target_id
        )

    def _configure_action_scope_session(
        self, session: ActionScopeTargetSession
    ) -> None:
        with self._lock:
            configured = self._request_interception_configured
            matches = self._action_scope_matches_locked(session.target_id)
            pattern = self._request_interception_rule["url_pattern"]
        if configured and matches:
            session.command(
                "Fetch.enable",
                {
                    "patterns": [
                        {"urlPattern": pattern, "requestStage": "Request"}
                    ],
                    "handleAuthRequests": False,
                },
            )
        else:
            session.command("Fetch.disable")

    def _on_action_scope_event(
        self,
        session: ActionScopeTargetSession,
        method: str,
        params: dict[str, Any],
    ) -> None:
        if method == "Fetch.requestPaused":
            self._handle_request_interception_pause_async(params, session)
            return
        if method == "Page.loadEventFired":
            self._queue_automation_trigger("after-load", session.target_id)
            return
        if method == "Runtime.bindingCalled":
            self._handle_automation_binding(params, session.target_id, session)

    def _on_action_scope_session_closed(
        self, target_id: str, error: BaseException
    ) -> None:
        with self._lock:
            session = self._action_scope_sessions.get(target_id)
            if session is None or session.ready():
                return
            self._action_scope_sessions.pop(target_id, None)
            if (
                self._request_interception_context_id is not None
                and target_id in self._action_scope_targets
            ):
                self._action_scope_last_error = truncate_text(
                    f"Disposable page target disconnected: {error}", 512
                )
            automation_armed = self._automation_recipes_state["auto_armed"]
            self._changed()
        if automation_armed:
            threading.Thread(
                target=self._disarm_automation_after_scope_loss,
                name="reb-automation-scope-recovery",
                daemon=True,
            ).start()

    def _disarm_automation_after_scope_loss(self) -> None:
        try:
            self._disarm_automation_recipes(
                reason=(
                    "A matched page disconnected; automatic recipes were disarmed "
                    "to prevent partial scope coverage."
                )
            )
        except DebuggerBridgeError:
            pass

    def _close_action_scope_sessions(self) -> None:
        with self._lock:
            sessions = list(self._action_scope_sessions.values())
            self._action_scope_sessions = {}
            self._action_scope_targets = {}
            self._action_scope_target_overflow = 0
            self._action_scope_last_error = None
        for session in sessions:
            session.close()

    def _refresh_action_scope_targets(self) -> None:
        with self._lock:
            context_id = self._request_interception_context_id
            previous_public = self._public_action_scope_locked()
        if context_id is None:
            return
        target_result = self._browser_command("Target.getTargets")
        raw_infos = target_result.get("targetInfos")
        if not isinstance(raw_infos, list) or len(raw_infos) > MAX_TARGETS * 4:
            raise ProtocolError("Browser returned a malformed action-scope target list")
        discovered = {target["id"]: target for target in self._discover_targets()}
        candidates: list[dict[str, Any]] = []
        for raw in raw_infos:
            if (
                not isinstance(raw, dict)
                or raw.get("browserContextId") != context_id
                or raw.get("type") not in {"page", "webview"}
            ):
                continue
            target_id = raw.get("targetId")
            target = discovered.get(target_id) if isinstance(target_id, str) else None
            if target is None:
                continue
            candidates.append(target)
        candidates.sort(key=lambda target: target["id"])
        overflow = max(0, len(candidates) - MAX_ACTION_SCOPE_TARGETS)
        candidates = candidates[:MAX_ACTION_SCOPE_TARGETS]
        candidate_ids = {target["id"] for target in candidates}
        with self._lock:
            if self._request_interception_context_id != context_id:
                return
            removed = [
                self._action_scope_sessions.pop(target_id)
                for target_id in list(self._action_scope_sessions)
                if target_id not in candidate_ids
            ]
            self._action_scope_targets = {
                target["id"]: {
                    "id": target["id"],
                    "type": target["type"],
                    "title": target["title"],
                    "url": target["url"],
                    "web_socket_url": target["web_socket_url"],
                }
                for target in candidates
            }
            self._action_scope_target_overflow = overflow
            new_targets = [
                target
                for target in candidates
                if target["id"] not in self._action_scope_sessions
            ]
            self._action_scope_last_error = None
        for session in removed:
            session.close()
        failures = []
        for target in new_targets:
            session: Optional[ActionScopeTargetSession] = None
            try:
                session = ActionScopeTargetSession(
                    target,
                    self._on_action_scope_event,
                    self._on_action_scope_session_closed,
                    self.debugger_transport_binary,
                )
                session.start()
                self._configure_action_scope_session(session)
            except BaseException as exception:
                if session is not None:
                    session.close()
                failures.append(f"{target['id'][:12]}: {exception}")
                continue
            keep_session = False
            with self._lock:
                if (
                    self._request_interception_context_id == context_id
                    and target["id"] in self._action_scope_targets
                    and target["id"] not in self._action_scope_sessions
                ):
                    self._action_scope_sessions[target["id"]] = session
                    keep_session = True
            if not keep_session:
                session.close()
        with self._lock:
            if self._request_interception_context_id != context_id:
                return
            self._action_scope_last_error = (
                truncate_text("; ".join(failures), 512) if failures else None
            )
            if self._public_action_scope_locked() != previous_public:
                self._changed()

    def _set_action_scope(self, request: dict[str, Any]) -> dict[str, Any]:
        mode = request.get("mode")
        target_id = request.get("target_id")
        if mode not in {"global", "target"}:
            raise DebuggerBridgeError("Action scope mode is invalid")
        if mode == "global":
            if target_id is not None:
                raise DebuggerBridgeError("Global action scope cannot include a target ID")
        elif (
            not isinstance(target_id, str)
            or not target_id
            or len(target_id.encode("utf-8")) > MAX_TARGET_ID_BYTES
        ):
            raise DebuggerBridgeError("Targeted action scope requires a valid target ID")
        with self._lock:
            if self._request_interception_context_id is None:
                raise DebuggerBridgeError(
                    "Create an isolated Experiment context before changing action scope"
                )
            if (
                self._request_interception_pending
                or self._request_interception["state"] == "running"
                or self._automation_recipes_state["auto_armed"]
                or self._automation_active_run_id is not None
                or self._automation_processing
            ):
                raise DebuggerBridgeError(
                    "Finish or disarm scoped rules before changing action scope"
                )
            if mode == "target" and target_id not in self._action_scope_targets:
                raise DebuggerBridgeError("Action scope target is unavailable")
            previous_mode = self._action_scope_mode
            previous_target_id = self._action_scope_target_id
            self._action_scope_mode = mode
            self._action_scope_target_id = target_id if mode == "target" else None
            sessions = list(self._action_scope_sessions.values())
        try:
            for session in sessions:
                self._configure_action_scope_session(session)
        except BaseException:
            with self._lock:
                self._action_scope_mode = previous_mode
                self._action_scope_target_id = previous_target_id
            for session in sessions:
                try:
                    self._configure_action_scope_session(session)
                except DebuggerBridgeError:
                    pass
            raise
        with self._lock:
            self._action_scope_revision += 1
            self._action_scope_last_error = None
            self._changed()
            scope = self._public_action_scope_locked()
        return {"ok": True, "action_scope": scope, "generation": self.generation()}

    def _create_experiment_page(self, request: dict[str, Any]) -> dict[str, Any]:
        url = request.get("url", "about:blank")
        if not isinstance(url, str):
            raise DebuggerBridgeError("Disposable page URL is invalid")
        url = url.strip() or "about:blank"
        if url != "about:blank":
            validate_request_interception_url(url)
        with self._lock:
            context_id = self._request_interception_context_id
            if context_id is None:
                raise DebuggerBridgeError(
                    "Create an isolated Experiment context before adding a page"
                )
            if len(self._action_scope_targets) >= MAX_ACTION_SCOPE_TARGETS:
                raise DebuggerBridgeError("Disposable page target limit reached")
            if (
                self._request_interception_pending
                or self._automation_recipes_state["auto_armed"]
                or self._automation_active_run_id is not None
                or self._automation_processing
            ):
                raise DebuggerBridgeError(
                    "Finish scoped rule work before adding a disposable page"
                )
        target_result = self._browser_command(
            "Target.createTarget",
            {
                "url": url,
                "browserContextId": context_id,
                "background": True,
            },
        )
        target_id = required_protocol_identifier(
            target_result.get("targetId"), "experiment target"
        )
        try:
            self._refresh_action_scope_targets()
        except DebuggerBridgeError:
            pass
        with self._lock:
            scope = self._public_action_scope_locked()
        return {
            "ok": True,
            "target_id": target_id,
            "action_scope": scope,
            "generation": self.generation(),
        }

    def _close_experiment_page(self, request: dict[str, Any]) -> dict[str, Any]:
        target_id = required_text(request, "target_id", MAX_TARGET_ID_BYTES)
        with self._lock:
            if self._request_interception_context_id is None:
                raise DebuggerBridgeError("No isolated Experiment context exists")
            if target_id not in self._action_scope_targets:
                raise DebuggerBridgeError("Disposable page target is unavailable")
            if target_id == self._request_interception["target_id"]:
                raise DebuggerBridgeError(
                    "The primary Experiment page remains until the context is disposed"
                )
            if (
                self._request_interception_pending
                or self._automation_recipes_state["auto_armed"]
                or self._automation_active_run_id is not None
                or self._automation_processing
            ):
                raise DebuggerBridgeError(
                    "Finish scoped rule work before closing a disposable page"
                )
        closed = self._browser_command("Target.closeTarget", {"targetId": target_id})
        if closed.get("success") is not True:
            raise ProtocolError("Browser did not confirm the disposable page was closed")
        try:
            self._refresh_action_scope_targets()
        except DebuggerBridgeError:
            pass
        with self._lock:
            scope = self._public_action_scope_locked()
        return {"ok": True, "action_scope": scope, "generation": self.generation()}

    def _create_request_interception_experiment(self) -> dict[str, Any]:
        with self._lock:
            if self._state not in {"running", "paused"} or self._target is None:
                raise DebuggerBridgeError(
                    "Request interception requires a running debugger target"
                )
            if self._request_interception_context_id is not None:
                raise DebuggerBridgeError(
                    "An isolated request interception experiment already exists"
                )
            if self._heap_diff_busy or self._heap_snapshot_collector is not None:
                raise DebuggerBridgeError(
                    "A heap snapshot operation is already running"
                )
            experiment_id = self._next_request_interception_id
            self._next_request_interception_id += 1
            return_target_id = self._target["id"]
            self._request_interception = self._empty_request_interception()
            self._request_interception.update(
                {
                    "experiment_id": experiment_id,
                    "state": "creating",
                    "created_at_ms": int(time.time() * 1_000),
                    "message": "Creating a disposable browser context with no shared cookies or storage.",
                }
            )
            self._request_interception_rule = default_request_interception_rule()
            self._request_interception_configured = False
            self._request_interception_return_target_id = return_target_id
            self._action_scope_mode = "global"
            self._action_scope_target_id = None
            self._action_scope_targets = {}
            self._action_scope_target_overflow = 0
            self._action_scope_last_error = None
            self._action_scope_revision += 1
            self._begin_repeater_session_locked(experiment_id)
            self._begin_object_experiment_session_locked(experiment_id)
            self._begin_runtime_hook_session_locked(experiment_id)
            self._begin_automation_session_locked(experiment_id)
            self._changed()

        context_id: Optional[str] = None
        try:
            context_result = self._browser_command("Target.createBrowserContext")
            context_id = required_protocol_identifier(
                context_result.get("browserContextId"), "browser context"
            )
            target_result = self._browser_command(
                "Target.createTarget",
                {
                    "url": "about:blank",
                    "browserContextId": context_id,
                    "background": True,
                },
            )
            target_id = required_protocol_identifier(
                target_result.get("targetId"), "experiment target"
            )
        except BaseException as exception:
            cleanup_error: Optional[BaseException] = None
            if context_id is not None:
                try:
                    self._browser_command(
                        "Target.disposeBrowserContext",
                        {"browserContextId": context_id},
                    )
                except DebuggerBridgeError as cleanup_exception:
                    cleanup_error = cleanup_exception
            with self._lock:
                self._request_interception_return_target_id = None
                self._request_interception["state"] = "error"
                if cleanup_error is not None:
                    self._request_interception_context_id = context_id
                    self._request_interception["isolated"] = True
                    message = (
                        f"{exception}. The partial disposable context could not be "
                        f"confirmed as deleted: {cleanup_error}"
                    )
                else:
                    message = str(exception)
                self._request_interception["message"] = truncate_text(
                    message, 512
                )
                self._repeater["state"] = "error"
                self._repeater["message"] = truncate_text(message, 512)
                self._object_experiment["state"] = "error"
                self._object_experiment["isolated"] = cleanup_error is not None
                self._object_experiment["message"] = truncate_text(message, 512)
                self._runtime_hooks["state"] = "error"
                self._runtime_hooks["isolated"] = cleanup_error is not None
                self._runtime_hooks["message"] = truncate_text(message, 512)
                self._automation_recipes_state["state"] = "error"
                self._automation_recipes_state["isolated"] = cleanup_error is not None
                self._automation_recipes_state["last_failure"] = truncate_text(
                    message, 512
                )
                self._automation_recipes_state["message"] = truncate_text(
                    message, 512
                )
                self._changed()
            raise

        with self._lock:
            self._request_interception_context_id = context_id
            self._request_interception["isolated"] = True
            self._request_interception["target_id"] = target_id
            self._request_interception["message"] = (
                "Isolated context created. Attaching its disposable page."
            )
            self._object_experiment["isolated"] = True
            self._object_experiment["target_id"] = target_id
            self._object_experiment["message"] = (
                "Isolated context created. Attaching the Object Lab page."
            )
            self._runtime_hooks["isolated"] = True
            self._runtime_hooks["target_id"] = target_id
            self._runtime_hooks["message"] = (
                "Isolated context created. Attaching the Runtime Hooks page."
            )
            self._automation_recipes_state["isolated"] = True
            self._automation_recipes_state["target_id"] = target_id
            self._automation_recipes_state["message"] = (
                "Isolated context created. Attaching the Automation Recipes page."
            )
            self._preferred_target_id = target_id
            connection = self._connection
            self._changed()
        if connection is not None:
            connection.close()
        try:
            self._refresh_action_scope_targets()
        except DebuggerBridgeError as exception:
            with self._lock:
                self._action_scope_last_error = truncate_text(str(exception), 512)
                self._changed()
        with self._lock:
            action_scope = self._public_action_scope_locked()
        return {
            "ok": True,
            "experiment": copy.deepcopy(self._request_interception),
            "action_scope": action_scope,
            "object_experiment": copy.deepcopy(self._object_experiment),
            "runtime_hooks": copy.deepcopy(self._runtime_hooks),
            "automation_recipes": copy.deepcopy(self._automation_recipes_state),
            "repeater": copy.deepcopy(self._repeater),
            "generation": self.generation(),
        }

    def _configure_request_interception(
        self, request: dict[str, Any]
    ) -> dict[str, Any]:
        rule = normalize_request_interception_rule(request)
        with self._lock:
            if (
                self._request_interception_context_id is None
                or self._request_interception["target_id"] is None
                or self._target is None
                or self._target["id"] != self._request_interception["target_id"]
                or self._request_interception["state"] not in {"ready", "error"}
                or self._request_interception_pending
            ):
                raise DebuggerBridgeError(
                    "The isolated request interception target is not ready"
                )
            scoped = bool(self._action_scope_targets)
            matched_sessions = (
                self._require_action_scope_sessions_locked("Request Interception")
                if scoped
                else []
            )
            all_sessions = list(self._action_scope_sessions.values())
            previous_rule = copy.deepcopy(self._request_interception_rule)
            previously_configured = self._request_interception_configured
        patterns = [
            {"urlPattern": rule["url_pattern"], "requestStage": "Request"}
        ]
        configured_sessions: list[ActionScopeTargetSession] = []
        try:
            if scoped:
                matched_ids = {session.target_id for session in matched_sessions}
                for session in all_sessions:
                    if session.target_id in matched_ids:
                        session.command(
                            "Fetch.enable",
                            {"patterns": patterns, "handleAuthRequests": False},
                        )
                        configured_sessions.append(session)
                    else:
                        session.command("Fetch.disable")
            else:
                self._command(
                    "Fetch.enable",
                    {"patterns": patterns, "handleAuthRequests": False},
                )
        except BaseException:
            rollback_pattern = [
                {
                    "urlPattern": previous_rule["url_pattern"],
                    "requestStage": "Request",
                }
            ]
            for session in configured_sessions:
                try:
                    if previously_configured:
                        session.command(
                            "Fetch.enable",
                            {
                                "patterns": rollback_pattern,
                                "handleAuthRequests": False,
                            },
                        )
                    else:
                        session.command("Fetch.disable")
                except DebuggerBridgeError:
                    pass
            raise
        with self._lock:
            self._request_interception_rule = rule
            self._request_interception_configured = True
            self._request_interception["rule"] = self._public_request_interception_rule(
                rule
            )
            self._request_interception["state"] = "ready"
            self._request_interception["result"] = None
            self._request_interception["message"] = (
                "Interception rule armed inside the disposable context."
            )
            self._changed()
            experiment = copy.deepcopy(self._request_interception)
        return {"ok": True, "experiment": experiment, "generation": self.generation()}

    def _run_request_interception(self, request: dict[str, Any]) -> dict[str, Any]:
        replay = normalize_request_interception_request(request)
        with self._lock:
            if (
                self._request_interception_context_id is None
                or self._request_interception["target_id"] is None
                or self._target is None
                or self._target["id"] != self._request_interception["target_id"]
                or self._request_interception["state"] not in {"ready", "error"}
                or self._request_interception_pending
            ):
                raise DebuggerBridgeError(
                    "The isolated request interception target is not ready"
                )
            if self._action_scope_targets:
                sessions = self._require_action_scope_sessions_locked(
                    "Request Interception"
                )
                requested_target_id = request.get("target_id")
                if requested_target_id is not None and (
                    not isinstance(requested_target_id, str)
                    or requested_target_id
                    not in {session.target_id for session in sessions}
                ):
                    raise DebuggerBridgeError(
                        "Experiment request target is outside the active action scope"
                    )
                session = next(
                    (
                        candidate
                        for candidate in sessions
                        if candidate.target_id == requested_target_id
                    ),
                    sessions[0],
                )
                target_id = session.target_id
            else:
                session = None
                target_id = self._request_interception["target_id"]
            self._request_interception["state"] = "running"
            self._request_interception["result"] = None
            self._request_interception["last_request"] = {
                "target_id": target_id,
                "url": redacted_request_url(replay["url"]),
                "method": replay["method"],
                "header_count": len(replay["headers"]),
                "body_bytes": len(replay["body"].encode("utf-8")),
            }
            self._request_interception["message"] = (
                "Sending one credential-free request through the armed rule."
            )
            self._changed()

        configuration = {
            "url": replay["url"],
            "method": replay["method"],
            "headers": {
                header["name"]: header["value"] for header in replay["headers"]
            },
            "body": replay["body"],
            "timeoutMs": int(INTERCEPTION_RUN_TIMEOUT_SECONDS * 1_000),
            "headerLimit": MAX_INTERCEPTION_HEADERS,
            "headerValueLimit": MAX_INTERCEPTION_HEADER_VALUE_BYTES,
            "headerTotalLimit": MAX_INTERCEPTION_HEADER_BYTES,
            "responseByteLimit": MAX_INTERCEPTION_RESPONSE_BYTES,
        }
        expression = (
            f"({REQUEST_INTERCEPTION_FUNCTION})"
            f"({json.dumps(configuration, separators=(',', ':'))})"
        )
        try:
            evaluated = self._scoped_command(
                session,
                "Runtime.evaluate",
                {
                    "expression": expression,
                    "returnByValue": True,
                    "awaitPromise": True,
                    "silent": True,
                    "userGesture": False,
                    "timeout": int(INTERCEPTION_RUN_TIMEOUT_SECONDS * 1_000),
                },
                timeout=INTERCEPTION_RUN_TIMEOUT_SECONDS + 2.0,
            )
            if isinstance(evaluated.get("exceptionDetails"), dict):
                raise DebuggerBridgeError(
                    "The isolated request runner failed before returning a result"
                )
            remote = evaluated.get("result")
            document = remote.get("value") if isinstance(remote, dict) else None
            result = normalize_request_interception_result(document)
        except BaseException as exception:
            with self._lock:
                self._request_interception["state"] = "error"
                self._request_interception["message"] = truncate_text(
                    str(exception), 512
                )
                self._changed()
            raise

        with self._lock:
            self._request_interception["state"] = "ready"
            self._request_interception["result"] = result
            self._request_interception["message"] = (
                f"Experiment request completed with status {result['status']}."
                if result["ok"]
                else f"Experiment request finished with an error: {result['error']}"
            )
            self._changed()
            experiment = copy.deepcopy(self._request_interception)
        return {"ok": True, "experiment": experiment, "generation": self.generation()}

    def _dispose_request_interception_experiment(self) -> dict[str, Any]:
        self._dispose_request_interception_context(preserve_result=True)
        with self._lock:
            experiment = copy.deepcopy(self._request_interception)
            action_scope = self._public_action_scope_locked()
            object_experiment = copy.deepcopy(self._object_experiment)
            runtime_hooks = copy.deepcopy(self._runtime_hooks)
            automation_recipes = copy.deepcopy(self._automation_recipes_state)
            repeater = copy.deepcopy(self._repeater)
        return {
            "ok": True,
            "experiment": experiment,
            "action_scope": action_scope,
            "object_experiment": object_experiment,
            "runtime_hooks": runtime_hooks,
            "automation_recipes": automation_recipes,
            "repeater": repeater,
            "generation": self.generation(),
        }

    def _dispose_request_interception_context(
        self, preserve_result: bool, force: bool = False
    ) -> None:
        self._release_object_experiment_search()
        with self._lock:
            context_id = self._request_interception_context_id
            if context_id is None:
                if not preserve_result:
                    self._request_interception = self._empty_request_interception()
                    self._request_interception_rule = (
                        default_request_interception_rule()
                    )
                    self._request_interception_pending.clear()
                    self._request_interception_configured = False
                    self._action_scope_mode = "global"
                    self._action_scope_target_id = None
                    self._action_scope_revision += 1
                    self._repeater = self._empty_repeater()
                    self._repeater_history_bytes = 0
                    self._repeater_active_execution_id = None
                    self._repeater_cancel_requested = False
                    self._object_experiment = self._empty_object_experiment()
                    self._object_experiment_group = None
                    self._object_experiment_objects_id = None
                    self._object_experiment_result_indices.clear()
                    self._runtime_hooks = self._empty_runtime_hooks()
                    self._runtime_hook_points.clear()
                    self._runtime_hook_processing = False
                    self._runtime_hook_stop_requested = False
                    self._runtime_hook_deferred_pause = None
                    self._runtime_hook_epoch += 1
                    self._automation_recipes_state = self._empty_automation_recipes()
                    self._automation_recipes_state["recipes"] = copy.deepcopy(
                        self._automation_recipes
                    )
                    self._automation_recipes_state[
                        "source_bytes"
                    ] = self._automation_source_bytes
                    self._automation_variables = {}
                    self._automation_auto_script_ids = {}
                    self._automation_binding_target_ids = set()
                    self._automation_binding_nonce = None
                    self._automation_active_run_id = None
                    self._automation_active_document_id = None
                    self._automation_active_target_id = None
                    self._automation_active_session = None
                    self._automation_cancel_requested = False
                    self._automation_pending_triggers = []
                    self._automation_processing = False
                    self._cancel_automation_watchdog_locked()
                    self._automation_epoch += 1
                    self._changed()
                return
            if not force and (
                self._request_interception["state"] == "running"
                or self._request_interception_pending
                or self._repeater_active_execution_id is not None
                or self._runtime_hook_processing
                or self._automation_active_run_id is not None
                or self._automation_processing
            ):
                raise DebuggerBridgeError(
                    "Finish or cancel active request-lab work before disposing its context"
                )
            repeater_session_id = self._repeater["session_id"]
            object_session_id = self._object_experiment["session_id"]
            runtime_hook_session_id = self._runtime_hooks["session_id"]
            automation_session_id = self._automation_recipes_state["session_id"]
            self._request_interception["state"] = "disposing"
            self._request_interception["message"] = (
                "Disposing the isolated browser context and all of its storage."
            )
            target_id = self._request_interception["target_id"]
            self._object_experiment["state"] = "disposing"
            self._object_experiment["message"] = (
                "Disposing Object Lab and releasing all live references."
            )
            self._runtime_hooks["state"] = "disposing"
            self._runtime_hooks["message"] = (
                "Disposing Runtime Hooks and erasing code and captured values."
            )
            self._automation_recipes_state["state"] = "disposing"
            self._automation_recipes_state["message"] = (
                "Disposing Automation Recipes and erasing variables, results, and logs."
            )
            connection = (
                self._connection
                if self._target is not None and self._target["id"] == target_id
                else None
            )
            return_target_id = self._request_interception_return_target_id
            self._changed()
        if connection is not None:
            connection.close()
        try:
            self._browser_command(
                "Target.disposeBrowserContext",
                {"browserContextId": context_id},
            )
        except DebuggerBridgeError as exception:
            with self._lock:
                self._request_interception["state"] = "error"
                self._request_interception["message"] = truncate_text(
                    f"The disposable context could not be confirmed as deleted: {exception}",
                    512,
                )
                self._repeater["state"] = "error"
                self._repeater["message"] = self._request_interception["message"]
                self._object_experiment["state"] = "error"
                self._object_experiment["message"] = self._request_interception[
                    "message"
                ]
                self._runtime_hooks["state"] = "error"
                self._runtime_hooks["message"] = self._request_interception["message"]
                self._automation_recipes_state["state"] = "error"
                self._automation_recipes_state["last_failure"] = (
                    self._request_interception["message"]
                )
                self._automation_recipes_state["message"] = (
                    self._request_interception["message"]
                )
                self._changed()
            if preserve_result:
                raise
            return
        self._close_action_scope_sessions()
        with self._lock:
            self._request_interception_context_id = None
            self._request_interception_return_target_id = None
            self._request_interception_pending.clear()
            self._request_interception_configured = False
            self._action_scope_mode = "global"
            self._action_scope_target_id = None
            self._action_scope_revision += 1
            self._preferred_target_id = return_target_id
            self._request_interception_rule = default_request_interception_rule()
            if preserve_result:
                self._request_interception["state"] = "disposed"
                self._request_interception["isolated"] = False
                self._request_interception["target_id"] = None
                self._request_interception["disposed_at_ms"] = int(time.time() * 1_000)
                self._request_interception["pending_requests"] = 0
                self._request_interception["message"] = (
                    "Disposable context deleted. The ephemeral result and audit remain visible."
                )
                self._dispose_repeater_locked(repeater_session_id)
                self._dispose_object_experiment_locked(object_session_id)
                self._dispose_runtime_hooks_locked(runtime_hook_session_id)
                self._dispose_automation_locked(automation_session_id)
            else:
                self._request_interception = self._empty_request_interception()
                self._repeater = self._empty_repeater()
                self._object_experiment = self._empty_object_experiment()
                self._runtime_hooks = self._empty_runtime_hooks()
                self._runtime_hook_points.clear()
                self._runtime_hook_processing = False
                self._runtime_hook_stop_requested = False
                self._runtime_hook_deferred_pause = None
                self._runtime_hook_epoch += 1
                self._automation_recipes_state = self._empty_automation_recipes()
                self._automation_recipes_state["recipes"] = copy.deepcopy(
                    self._automation_recipes
                )
                self._automation_recipes_state[
                    "source_bytes"
                ] = self._automation_source_bytes
                self._automation_variables = {}
                self._automation_auto_script_ids = {}
                self._automation_binding_target_ids = set()
                self._automation_binding_nonce = None
                self._automation_active_run_id = None
                self._automation_active_document_id = None
                self._automation_active_target_id = None
                self._automation_active_session = None
                self._automation_cancel_requested = False
                self._automation_pending_triggers = []
                self._automation_processing = False
                self._cancel_automation_watchdog_locked()
                self._automation_epoch += 1
                self._repeater_history_bytes = 0
                self._repeater_active_execution_id = None
                self._repeater_cancel_requested = False
            self._changed()

    def _clear_request_interception_result(self) -> dict[str, Any]:
        with self._lock:
            if self._request_interception_context_id is not None:
                raise DebuggerBridgeError(
                    "Dispose the isolated context before clearing its result"
                )
            self._request_interception = self._empty_request_interception()
            self._request_interception_rule = default_request_interception_rule()
            self._request_interception_pending.clear()
            self._request_interception_configured = False
            self._action_scope_mode = "global"
            self._action_scope_target_id = None
            self._action_scope_revision += 1
            self._repeater = self._empty_repeater()
            self._repeater_history_bytes = 0
            self._repeater_active_execution_id = None
            self._repeater_cancel_requested = False
            self._object_experiment = self._empty_object_experiment()
            self._object_experiment_group = None
            self._object_experiment_objects_id = None
            self._object_experiment_result_indices.clear()
            self._runtime_hooks = self._empty_runtime_hooks()
            self._runtime_hook_points.clear()
            self._runtime_hook_processing = False
            self._runtime_hook_stop_requested = False
            self._runtime_hook_deferred_pause = None
            self._runtime_hook_epoch += 1
            self._automation_recipes_state = self._empty_automation_recipes()
            self._automation_recipes_state["recipes"] = copy.deepcopy(
                self._automation_recipes
            )
            self._automation_recipes_state["source_bytes"] = (
                self._automation_source_bytes
            )
            self._automation_variables = {}
            self._automation_auto_script_ids = {}
            self._automation_binding_target_ids = set()
            self._automation_binding_nonce = None
            self._automation_active_run_id = None
            self._automation_active_document_id = None
            self._automation_active_target_id = None
            self._automation_active_session = None
            self._automation_cancel_requested = False
            self._automation_pending_triggers = []
            self._automation_processing = False
            self._cancel_automation_watchdog_locked()
            self._automation_epoch += 1
            self._changed()
        return {"ok": True, "generation": self.generation()}


    def _handle_request_interception_pause_async(
        self,
        params: dict[str, Any],
        session: Optional[ActionScopeTargetSession] = None,
    ) -> None:
        request_id = params.get("requestId")
        request = params.get("request")
        if (
            not isinstance(request_id, str)
            or not request_id
            or len(request_id.encode("utf-8")) > MAX_TARGET_ID_BYTES
        ):
            return
        with self._lock:
            target_id = (
                session.target_id
                if session is not None
                else self._target["id"]
                if self._target is not None
                else self._request_interception["target_id"]
            )
            active = self._request_interception_context_id is not None and (
                self._request_interception["state"]
                in {"ready", "running", "error"}
            )
            if session is not None:
                active = (
                    active
                    and self._request_interception_configured
                    and self._action_scope_sessions.get(target_id) is session
                    and self._action_scope_matches_locked(target_id)
                )
            else:
                active = (
                    active
                    and self._target is not None
                    and self._request_interception["target_id"] == self._target["id"]
                    and not self._action_scope_targets
                )
            pending_key = (target_id or "", request_id)
        if not active:
            self._scoped_command_without_wait(
                session,
                "Fetch.continueRequest", {"requestId": request_id}
            )
            return
        if not isinstance(request, dict):
            continued = self._scoped_command_without_wait(
                session,
                "Fetch.continueRequest", {"requestId": request_id}
            )
            self._append_request_interception_audit(
                request_id,
                {},
                params.get("resourceType"),
                "error",
                "Malformed paused request continued unchanged."
                if continued
                else "Malformed paused request could not be resumed.",
                target_id,
            )
            return
        with self._lock:
            if pending_key in self._request_interception_pending:
                return
            if (
                len(self._request_interception_pending)
                >= MAX_INTERCEPTION_PENDING_REQUESTS
            ):
                overflow = True
            else:
                overflow = False
                self._request_interception_pending.add(pending_key)
                self._request_interception["pending_requests"] = len(
                    self._request_interception_pending
                )
                self._changed()
        if overflow:
            continued = self._scoped_command_without_wait(
                session,
                "Fetch.continueRequest", {"requestId": request_id}
            )
            self._append_request_interception_audit(
                request_id,
                request,
                params.get("resourceType"),
                "overflow_continue" if continued else "error",
                "Pending interception limit reached; request continued unchanged."
                if continued
                else "Pending interception limit reached and the request could not be resumed.",
                target_id,
            )
            return
        thread = threading.Thread(
            target=self._process_request_interception_pause,
            args=(
                request_id,
                request,
                params.get("resourceType"),
                target_id,
                session,
            ),
            name="reb-request-interception",
            daemon=True,
        )
        try:
            thread.start()
        except RuntimeError as exception:
            continued = self._scoped_command_without_wait(
                session,
                "Fetch.continueRequest", {"requestId": request_id}
            )
            with self._lock:
                self._request_interception_pending.discard(pending_key)
                self._request_interception["pending_requests"] = len(
                    self._request_interception_pending
                )
                self._changed()
            self._append_request_interception_audit(
                request_id,
                request,
                params.get("resourceType"),
                "error",
                truncate_text(
                    f"Interception worker could not start: {exception}. "
                    f"Request {'continued unchanged' if continued else 'could not be resumed'}.",
                    512,
                ),
                target_id,
            )

    def _process_request_interception_pause(
        self,
        request_id: str,
        request: dict[str, Any],
        resource_type: Any,
        target_id: Optional[str] = None,
        session: Optional[ActionScopeTargetSession] = None,
    ) -> None:
        method = (
            request.get("method")
            if isinstance(request.get("method"), str)
            else "UNKNOWN"
        )
        with self._lock:
            rule = copy.deepcopy(self._request_interception_rule)
        outcome = "continued"
        detail = "Request continued unchanged."
        command = "Fetch.continueRequest"
        command_params: dict[str, Any] = {"requestId": request_id}
        preflight_headers = request_interception_preflight_headers(request, rule)
        if preflight_headers is not None:
            command = "Fetch.fulfillRequest"
            command_params.update(
                {
                    "responseCode": 204,
                    "responseHeaders": preflight_headers,
                    "body": "",
                }
            )
            outcome = "fulfilled"
            detail = "Synthetic credential-free CORS preflight returned."
        elif rule["method_filter"] and method.upper() != rule["method_filter"]:
            outcome = "bypassed"
            detail = "Request method did not match the armed rule."
        elif rule["mode"] == "block":
            command = "Fetch.failRequest"
            command_params["errorReason"] = "BlockedByClient"
            outcome = "blocked"
            detail = "Request failed with BlockedByClient."
        elif rule["mode"] == "drop":
            command = "Fetch.failRequest"
            command_params["errorReason"] = "Aborted"
            outcome = "dropped"
            detail = "Request failed with Aborted."
        elif rule["mode"] == "rewrite":
            if rule["rewrite_url"]:
                command_params["url"] = rule["rewrite_url"]
            if rule["rewrite_method"]:
                command_params["method"] = rule["rewrite_method"]
            if rule["rewrite_headers"]:
                command_params["headers"] = rule["rewrite_headers"]
            if rule["rewrite_body"]:
                command_params["postData"] = base64.b64encode(
                    rule["rewrite_body"].encode("utf-8")
                ).decode("ascii")
            outcome = "rewritten"
            detail = "Bounded request overrides applied."
        elif rule["mode"] == "fulfill":
            command = "Fetch.fulfillRequest"
            command_params.update(
                {
                    "responseCode": rule["response_code"],
                    "responseHeaders": rule["response_headers"],
                    "body": base64.b64encode(
                        rule["response_body"].encode("utf-8")
                    ).decode("ascii"),
                }
            )
            outcome = "fulfilled"
            detail = f"Synthetic response {rule['response_code']} returned."
        try:
            self._scoped_command(session, command, command_params, timeout=3.0)
        except DebuggerBridgeError as exception:
            outcome = "error"
            detail = truncate_text(str(exception), 512)
            try:
                self._scoped_command(
                    session,
                    "Fetch.continueRequest", {"requestId": request_id}, timeout=1.0
                )
            except DebuggerBridgeError:
                pass
        finally:
            self._append_request_interception_audit(
                request_id, request, resource_type, outcome, detail, target_id
            )
            with self._lock:
                self._request_interception_pending.discard(
                    (target_id or "", request_id)
                )
                self._request_interception["pending_requests"] = len(
                    self._request_interception_pending
                )
                self._changed()


    def _append_request_interception_audit(
        self,
        request_id: str,
        request: dict[str, Any],
        resource_type: Any,
        outcome: str,
        detail: str,
        target_id: Optional[str] = None,
    ) -> None:
        raw_url = request.get("url") if isinstance(request.get("url"), str) else ""
        method = request.get("method") if isinstance(request.get("method"), str) else ""
        with self._lock:
            audit = self._request_interception["audit"]
            if len(audit) >= MAX_INTERCEPTION_AUDIT_ENTRIES:
                audit.pop(0)
                self._request_interception["audit_evictions"] += 1
            audit.append(
                {
                    "id": self._next_request_interception_audit_id,
                    "occurred_at_ms": int(time.time() * 1_000),
                    "request_id": truncate_text(request_id, 256),
                    "target_id": truncate_text(
                        target_id
                        or self._request_interception.get("target_id")
                        or "",
                        MAX_TARGET_ID_BYTES,
                    ),
                    "method": truncate_text(
                        method, MAX_INTERCEPTION_METHOD_BYTES
                    ),
                    "url": redacted_request_url(raw_url),
                    "resource_type": truncate_text(
                        resource_type if isinstance(resource_type, str) else "Other",
                        128,
                    ),
                    "rule_mode": self._request_interception_rule["mode"],
                    "outcome": outcome,
                    "detail": truncate_text(detail, 512),
                }
            )
            self._next_request_interception_audit_id += 1
            self._changed()


    def _heap_snapshot_binary(self) -> Path:
        binary = self.heap_snapshot_binary.resolve()
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise DebuggerBridgeError(
                "Native heap snapshot analysis is unavailable; run make heap-snapshot"
            )
        return binary

    def _capture_heap_snapshot(self) -> HeapSnapshotCapture:
        temporary = tempfile.NamedTemporaryFile(
            mode="wb", prefix="reb-heap-", suffix=".heapsnapshot", delete=False
        )
        collector = HeapSnapshotCollector(Path(temporary.name), temporary)
        with self._lock:
            target_id = self._target["id"] if self._target is not None else None
            if target_id is None:
                collector.close()
                collector.path.unlink(missing_ok=True)
                raise DebuggerBridgeError("Debugger target is unavailable")
            if self._heap_snapshot_collector is not None:
                collector.close()
                collector.path.unlink(missing_ok=True)
                raise DebuggerBridgeError("A heap snapshot capture is already running")
            self._heap_snapshot_collector = collector
        try:
            self._command("HeapProfiler.enable")
            self._command(
                "HeapProfiler.takeHeapSnapshot",
                {
                    "reportProgress": False,
                    "captureNumericValue": True,
                    "exposeInternals": False,
                },
                timeout=HEAP_SNAPSHOT_CAPTURE_TIMEOUT_SECONDS,
            )
        except BaseException:
            collector.close()
            collector.path.unlink(missing_ok=True)
            with self._lock:
                connection = self._connection
            if connection is not None:
                connection.close()
            raise
        finally:
            with self._lock:
                if self._heap_snapshot_collector is collector:
                    self._heap_snapshot_collector = None
            collector.close()

        try:
            if collector.error is not None:
                raise DebuggerBridgeError(collector.error)
            if collector.chunk_count == 0 or collector.byte_count == 0:
                raise ProtocolError("Debugger returned an empty heap snapshot")
            return HeapSnapshotCapture(
                path=collector.path,
                target_id=target_id,
                byte_count=collector.byte_count,
                captured_at_ms=int(time.time() * 1_000),
            )
        except BaseException:
            collector.path.unlink(missing_ok=True)
            raise

    def _run_native_heap_snapshot(
        self, command: list[str], timeout: float, operation: str
    ) -> Any:
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exception:
            raise DebuggerBridgeError(
                f"Native heap snapshot {operation} exceeded its {int(timeout)} second limit"
            ) from exception
        if completed.returncode != 0:
            detail = truncate_text(completed.stderr.strip(), 512)
            raise DebuggerBridgeError(
                detail or f"Native heap snapshot {operation} rejected the snapshot"
            )
        if len(completed.stdout.encode("utf-8")) > 512 * 1024:
            raise ProtocolError(
                f"Native heap snapshot {operation} returned oversized output"
            )
        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError as exception:
            raise ProtocolError(
                f"Native heap snapshot {operation} returned malformed JSON"
            ) from exception

    def _heap_diff_baseline_metadata(self) -> Optional[dict[str, Any]]:
        baseline = self._heap_diff_baseline
        if baseline is None:
            return None
        return {
            "target_id": baseline.target_id,
            "file_bytes": baseline.byte_count,
            "captured_at_ms": baseline.captured_at_ms,
        }

    def _clear_heap_diff_baseline(self, force: bool = False) -> None:
        with self._lock:
            if self._heap_diff_busy and not force:
                raise DebuggerBridgeError("Heap snapshot comparison is running")
            baseline = self._heap_diff_baseline
            self._heap_diff_baseline = None
            if baseline is not None:
                self._changed()
        if baseline is not None:
            baseline.path.unlink(missing_ok=True)

    def _finish_heap_diff_operation(self) -> None:
        with self._lock:
            self._heap_diff_busy = False
            baseline = self._heap_diff_baseline
            target_id = self._target["id"] if self._target is not None else None
            if baseline is not None and baseline.target_id != target_id:
                self._heap_diff_baseline = None
                self._changed()
            else:
                baseline = None
        if baseline is not None:
            baseline.path.unlink(missing_ok=True)

    def _capture_heap_diff_baseline(self) -> dict[str, Any]:
        self._heap_snapshot_binary()
        with self._lock:
            if self._heap_diff_busy:
                raise DebuggerBridgeError("Heap snapshot comparison is running")
            self._heap_diff_busy = True
        capture: Optional[HeapSnapshotCapture] = None
        previous: Optional[HeapSnapshotCapture] = None
        try:
            capture = self._capture_heap_snapshot()
            with self._lock:
                previous = self._heap_diff_baseline
                self._heap_diff_baseline = capture
                metadata = self._heap_diff_baseline_metadata()
                self._changed()
            if previous is not None:
                previous.path.unlink(missing_ok=True)
            return {
                "ok": True,
                "baseline": metadata,
                "generation": self.generation(),
            }
        except BaseException:
            if capture is not None:
                capture.path.unlink(missing_ok=True)
            raise
        finally:
            self._finish_heap_diff_operation()

    def _compare_heap_diff(self) -> dict[str, Any]:
        binary = self._heap_snapshot_binary()
        with self._lock:
            if self._heap_diff_busy:
                raise DebuggerBridgeError("Heap snapshot comparison is running")
            baseline = self._heap_diff_baseline
            target_id = self._target["id"] if self._target is not None else None
            if baseline is None:
                raise DebuggerBridgeError("Capture a heap snapshot baseline first")
            if target_id != baseline.target_id:
                raise DebuggerBridgeError(
                    "Heap snapshot baseline belongs to a different debugger target"
                )
            self._heap_diff_busy = True
        current: Optional[HeapSnapshotCapture] = None
        try:
            current = self._capture_heap_snapshot()
            if current.target_id != baseline.target_id:
                raise DebuggerBridgeError(
                    "Debugger target changed during heap snapshot comparison"
                )
            document = self._run_native_heap_snapshot(
                [
                    str(binary),
                    "--baseline",
                    str(baseline.path),
                    "--current",
                    str(current.path),
                    "--limit",
                    str(MAX_HEAP_SNAPSHOT_RESULTS),
                ],
                HEAP_SNAPSHOT_DIFF_TIMEOUT_SECONDS,
                "comparison",
            )
            return self._normalize_heap_snapshot_diff(document)
        finally:
            if current is not None:
                current.path.unlink(missing_ok=True)
            self._finish_heap_diff_operation()

    def _normalize_heap_snapshot_search(self, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict) or value.get("protocol_version") != 2:
            raise ProtocolError("Native heap snapshot search returned malformed output")
        integer_fields = (
            "file_bytes",
            "total_nodes",
            "analyzed_nodes",
            "matched_nodes",
            "reachable_nodes",
            "total_edges",
            "indexed_edges",
            "total_strings",
            "duration_ms",
            "result_limit",
            "reference_limit",
        )
        if any(
            not isinstance(value.get(field), int)
            or isinstance(value.get(field), bool)
            or value[field] < 0
            or value[field] > 2**53 - 1
            for field in integer_fields
        ):
            raise ProtocolError("Native heap snapshot search returned invalid counts")
        if (
            value["file_bytes"] > MAX_HEAP_SNAPSHOT_BYTES
            or value["analyzed_nodes"] > value["total_nodes"]
            or value["matched_nodes"] > value["analyzed_nodes"]
            or value["reachable_nodes"] > value["analyzed_nodes"]
            or value["indexed_edges"] > value["total_edges"]
            or value["result_limit"] != MAX_HEAP_SNAPSHOT_RESULTS
            or value["reference_limit"] != MAX_HEAP_INCOMING_REFERENCES
            or not isinstance(value.get("scope"), str)
            or value["scope"] not in {"all", "reachable", "unreachable"}
            or value.get("result_limit_reached")
            != (value["matched_nodes"] > value["result_limit"])
        ):
            raise ProtocolError("Native heap snapshot search returned invalid coverage")
        boolean_fields = (
            "result_limit_reached",
            "node_limit_reached",
            "edge_limit_reached",
            "string_limit_reached",
            "retaining_paths_partial",
        )
        if any(not isinstance(value.get(field), bool) for field in boolean_fields):
            raise ProtocolError("Native heap snapshot search returned invalid limits")
        raw_results = value.get("results")
        if (
            not isinstance(raw_results, list)
            or len(raw_results) > MAX_HEAP_SNAPSHOT_RESULTS
            or len(raw_results) != min(value["matched_nodes"], value["result_limit"])
        ):
            raise ProtocolError("Native heap snapshot search returned too many results")
        results = []
        for raw_result in raw_results:
            if not isinstance(raw_result, dict):
                raise ProtocolError("Native heap snapshot search returned a malformed result")
            result_id = raw_result.get("id")
            node_type = raw_result.get("type")
            node_name = raw_result.get("name")
            self_size = raw_result.get("self_size")
            reachable = raw_result.get("reachable")
            incoming_reference_count = raw_result.get("incoming_reference_count")
            incoming_reference_limit_reached = raw_result.get(
                "incoming_reference_limit_reached"
            )
            path_complete = raw_result.get("retaining_path_complete")
            raw_path = raw_result.get("retaining_path")
            raw_references = raw_result.get("incoming_references")
            if (
                not isinstance(result_id, str)
                or not result_id.isascii()
                or not result_id.isdigit()
                or (len(result_id) > 1 and result_id.startswith("0"))
                or len(result_id) > 20
                or not isinstance(node_type, str)
                or not isinstance(node_name, str)
                or not isinstance(self_size, int)
                or isinstance(self_size, bool)
                or self_size < 0
                or self_size > 2**53 - 1
                or not isinstance(reachable, bool)
                or not isinstance(incoming_reference_count, int)
                or isinstance(incoming_reference_count, bool)
                or incoming_reference_count < 0
                or incoming_reference_count > 2**53 - 1
                or not isinstance(incoming_reference_limit_reached, bool)
                or not isinstance(path_complete, bool)
                or not isinstance(raw_path, list)
                or len(raw_path) > MAX_HEAP_RETAINING_PATH
                or not isinstance(raw_references, list)
                or len(raw_references) > MAX_HEAP_INCOMING_REFERENCES
                or incoming_reference_count < len(raw_references)
                or incoming_reference_limit_reached
                != (incoming_reference_count > len(raw_references))
                or (not reachable and (path_complete or raw_path))
                or (value["scope"] == "reachable" and not reachable)
                or (value["scope"] == "unreachable" and reachable)
            ):
                raise ProtocolError("Native heap snapshot search returned a malformed result")
            retaining_path = []
            for raw_step in raw_path:
                if not isinstance(raw_step, dict) or any(
                    not isinstance(raw_step.get(field), str)
                    for field in ("edge_type", "edge", "type", "name")
                ):
                    raise ProtocolError(
                        "Native heap snapshot search returned a malformed retaining path"
                    )
                retaining_path.append(
                    {
                        "edge": truncate_text(raw_step["edge"], 128),
                        "edge_type": truncate_text(raw_step["edge_type"], 32),
                        "type": truncate_text(raw_step["type"], 64),
                        "name": truncate_text(raw_step["name"], 256),
                    }
                )
            incoming_references = []
            for raw_reference in raw_references:
                if not isinstance(raw_reference, dict) or any(
                    not isinstance(raw_reference.get(field), str)
                    for field in (
                        "source_id",
                        "edge_type",
                        "edge",
                        "source_type",
                        "source_name",
                    )
                ):
                    raise ProtocolError(
                        "Native heap snapshot search returned a malformed incoming reference"
                    )
                source_id = raw_reference["source_id"]
                if (
                    not source_id.isascii()
                    or not source_id.isdigit()
                    or (len(source_id) > 1 and source_id.startswith("0"))
                    or len(source_id) > 20
                ):
                    raise ProtocolError(
                        "Native heap snapshot search returned a malformed incoming reference"
                    )
                incoming_references.append(
                    {
                        "source_id": source_id,
                        "edge_type": truncate_text(raw_reference["edge_type"], 32),
                        "edge": truncate_text(raw_reference["edge"], 128),
                        "source_type": truncate_text(raw_reference["source_type"], 64),
                        "source_name": truncate_text(raw_reference["source_name"], 256),
                    }
                )
            results.append(
                {
                    "id": result_id,
                    "type": truncate_text(node_type, 64),
                    "name": truncate_text(node_name, 256),
                    "self_size": self_size,
                    "reachable": reachable,
                    "incoming_reference_count": incoming_reference_count,
                    "incoming_reference_limit_reached": incoming_reference_limit_reached,
                    "retaining_path_complete": path_complete,
                    "retaining_path": retaining_path,
                    "incoming_references": incoming_references,
                }
            )
        return {
            "ok": True,
            "snapshot": {
                field: value[field]
                for field in (
                    "protocol_version",
                    *integer_fields,
                    *boolean_fields,
                    "scope",
                )
            }
            | {"results": results},
            "generation": self.generation(),
        }

    def _normalize_heap_snapshot_diff(self, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict) or value.get("protocol_version") != 1:
            raise ProtocolError("Native heap snapshot comparison returned malformed output")
        integer_fields = (
            "baseline_file_bytes",
            "current_file_bytes",
            "baseline_nodes",
            "current_nodes",
            "baseline_edges",
            "current_edges",
            "baseline_reachable_nodes",
            "current_reachable_nodes",
            "baseline_self_size",
            "current_self_size",
            "duration_ms",
            "result_limit",
        )
        if any(
            not isinstance(value.get(field), int)
            or isinstance(value.get(field), bool)
            or value[field] < 0
            or value[field] > 2**53 - 1
            for field in integer_fields
        ):
            raise ProtocolError("Native heap snapshot comparison returned invalid counts")
        self_size_delta = value.get("self_size_delta")
        if (
            not isinstance(self_size_delta, int)
            or isinstance(self_size_delta, bool)
            or abs(self_size_delta) > 2**53 - 1
            or self_size_delta
            != value["current_self_size"] - value["baseline_self_size"]
        ):
            raise ProtocolError("Native heap snapshot comparison returned invalid totals")
        if (
            value["baseline_file_bytes"] > MAX_HEAP_SNAPSHOT_BYTES
            or value["current_file_bytes"] > MAX_HEAP_SNAPSHOT_BYTES
            or value["baseline_reachable_nodes"] > value["baseline_nodes"]
            or value["current_reachable_nodes"] > value["current_nodes"]
            or value["result_limit"] != MAX_HEAP_SNAPSHOT_RESULTS
        ):
            raise ProtocolError("Native heap snapshot comparison returned invalid coverage")
        boolean_fields = (
            "group_result_limit_reached",
            "dominator_result_limit_reached",
            "aggregation_limit_reached",
            "baseline_node_limit_reached",
            "baseline_edge_limit_reached",
            "baseline_string_limit_reached",
            "current_node_limit_reached",
            "current_edge_limit_reached",
            "current_string_limit_reached",
            "retained_size_saturated",
        )
        if any(not isinstance(value.get(field), bool) for field in boolean_fields):
            raise ProtocolError("Native heap snapshot comparison returned invalid limits")

        raw_groups = value.get("groups")
        if not isinstance(raw_groups, list) or len(raw_groups) > MAX_HEAP_SNAPSHOT_RESULTS:
            raise ProtocolError("Native heap snapshot comparison returned too many groups")
        groups = []
        for raw_group in raw_groups:
            if not isinstance(raw_group, dict):
                raise ProtocolError(
                    "Native heap snapshot comparison returned a malformed group"
                )
            node_type = raw_group.get("type")
            node_name = raw_group.get("name")
            baseline_count = raw_group.get("baseline_count")
            current_count = raw_group.get("current_count")
            count_delta = raw_group.get("count_delta")
            baseline_size = raw_group.get("baseline_self_size")
            current_size = raw_group.get("current_self_size")
            size_delta = raw_group.get("self_size_delta")
            unsigned_values = (
                baseline_count,
                current_count,
                baseline_size,
                current_size,
            )
            signed_values = (count_delta, size_delta)
            if (
                not isinstance(node_type, str)
                or not isinstance(node_name, str)
                or any(
                    not isinstance(item, int)
                    or isinstance(item, bool)
                    or item < 0
                    or item > 2**53 - 1
                    for item in unsigned_values
                )
                or any(
                    not isinstance(item, int)
                    or isinstance(item, bool)
                    or abs(item) > 2**53 - 1
                    for item in signed_values
                )
                or count_delta != current_count - baseline_count
                or size_delta != current_size - baseline_size
                or baseline_count > value["baseline_nodes"]
                or current_count > value["current_nodes"]
            ):
                raise ProtocolError(
                    "Native heap snapshot comparison returned a malformed group"
                )
            groups.append(
                {
                    "type": truncate_text(node_type, 64),
                    "name": truncate_text(node_name, 256),
                    "baseline_count": baseline_count,
                    "current_count": current_count,
                    "count_delta": count_delta,
                    "baseline_self_size": baseline_size,
                    "current_self_size": current_size,
                    "self_size_delta": size_delta,
                }
            )

        raw_dominators = value.get("dominators")
        if (
            not isinstance(raw_dominators, list)
            or len(raw_dominators) > MAX_HEAP_SNAPSHOT_RESULTS
        ):
            raise ProtocolError(
                "Native heap snapshot comparison returned too many dominators"
            )
        dominators = []
        for raw_change in raw_dominators:
            if not isinstance(raw_change, dict):
                raise ProtocolError(
                    "Native heap snapshot comparison returned a malformed dominator"
                )
            node_id = raw_change.get("id")
            node_type = raw_change.get("type")
            node_name = raw_change.get("name")
            baseline_size = raw_change.get("baseline_retained_size")
            current_size = raw_change.get("current_retained_size")
            size_delta = raw_change.get("retained_size_delta")
            if (
                not isinstance(node_id, str)
                or not node_id.isdecimal()
                or len(node_id) > 20
                or not isinstance(node_type, str)
                or not isinstance(node_name, str)
                or any(
                    not isinstance(item, int)
                    or isinstance(item, bool)
                    or item < 0
                    or item > 2**53 - 1
                    for item in (baseline_size, current_size)
                )
                or not isinstance(size_delta, int)
                or isinstance(size_delta, bool)
                or abs(size_delta) > 2**53 - 1
                or size_delta != current_size - baseline_size
            ):
                raise ProtocolError(
                    "Native heap snapshot comparison returned a malformed dominator"
                )
            dominators.append(
                {
                    "id": node_id,
                    "type": truncate_text(node_type, 64),
                    "name": truncate_text(node_name, 256),
                    "baseline_retained_size": baseline_size,
                    "current_retained_size": current_size,
                    "retained_size_delta": size_delta,
                }
            )
        return {
            "ok": True,
            "diff": {
                field: value[field]
                for field in (
                    "protocol_version",
                    *integer_fields,
                    "self_size_delta",
                    *boolean_fields,
                )
            }
            | {"groups": groups, "dominators": dominators},
            "generation": self.generation(),
        }

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                targets = self._discover_targets()
                with self._lock:
                    current_targets = targets[:MAX_TARGETS]
                    if current_targets != self._targets:
                        self._targets = current_targets
                        self._changed()
                pages = [
                    target
                    for target in targets
                    if target["type"] in {"page", "webview"}
                ]
                if not pages:
                    self._set_state("waiting", None)
                    self._stop.wait(0.5)
                    continue
                with self._lock:
                    preferred = self._preferred_target_id
                target = next(
                    (item for item in pages if item["id"] == preferred), pages[0]
                )
                self._serve_target(target)
            except (
                OSError,
                ValueError,
                DebuggerBridgeError,
                json.JSONDecodeError,
            ) as exception:
                if self._stop.is_set():
                    break
                self._set_state("waiting", str(exception))
                self._stop.wait(0.5)

    def _devtools_endpoint(self) -> tuple[int, str]:
        if self.active_port_path is None or not self.active_port_path.is_file():
            raise DebuggerBridgeError("Waiting for the authorized browser debugger")
        with self.active_port_path.open("rb") as active_port_file:
            active_port_body = active_port_file.read(MAX_ACTIVE_PORT_BYTES + 1)
        if len(active_port_body) > MAX_ACTIVE_PORT_BYTES:
            raise DebuggerBridgeError("The browser debugger endpoint is oversized")
        lines = active_port_body.decode("utf-8").splitlines()
        if len(lines) < 2 or not lines[0].isdigit():
            raise DebuggerBridgeError("The browser debugger endpoint is incomplete")
        port = int(lines[0])
        if port <= 0 or port >= 2**16:
            raise DebuggerBridgeError("The browser debugger port is invalid")
        browser_endpoint = lines[1]
        if browser_endpoint.startswith("/"):
            browser_url = f"ws://127.0.0.1:{port}{browser_endpoint}"
        elif browser_endpoint.startswith("ws://"):
            browser_url = browser_endpoint
        else:
            raise DebuggerBridgeError("The browser debugger endpoint is malformed")
        if len(browser_url.encode("utf-8")) > MAX_TARGET_URL_BYTES:
            raise DebuggerBridgeError("The browser debugger endpoint is oversized")
        return port, browser_url

    def _browser_command(
        self, method: str, params: Optional[dict[str, Any]] = None
    ) -> dict[str, Any]:
        _, browser_url = self._devtools_endpoint()
        connection = NativeDebuggerConnection(
            browser_url, self.debugger_transport_binary
        )
        try:
            connection.send_json({"id": 1, "method": method, "params": params or {}})
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                response = connection.receive_json(
                    timeout=min(0.5, max(0.0, deadline - time.monotonic()))
                )
                if response is None or response.get("id") != 1:
                    continue
                error = response.get("error")
                if isinstance(error, dict):
                    message = error.get("message")
                    raise DebuggerBridgeError(
                        truncate_text(
                            message
                            if isinstance(message, str)
                            else f"Browser command {method} failed",
                            512,
                        )
                    )
                result = response.get("result")
                if not isinstance(result, dict):
                    raise ProtocolError(
                        f"Browser command {method} returned malformed output"
                    )
                return result
            raise DebuggerBridgeError(f"Browser command {method} timed out")
        finally:
            connection.close()

    def _discover_targets(self) -> list[dict[str, str]]:
        port, _ = self._devtools_endpoint()
        request = Request(
            f"http://127.0.0.1:{port}/json/list", headers={"Accept": "application/json"}
        )
        with urlopen(request, timeout=2.0) as response:
            target_body = response.read(MAX_TARGET_LIST_BYTES + 1)
        if len(target_body) > MAX_TARGET_LIST_BYTES:
            raise DebuggerBridgeError("The browser target list is oversized")
        body = json.loads(target_body)
        if not isinstance(body, list) or len(body) > MAX_TARGETS * 4:
            raise DebuggerBridgeError("The browser returned a malformed target list")
        targets = []
        for value in body:
            if not isinstance(value, dict):
                continue
            target_id = value.get("id")
            target_type = value.get("type")
            web_socket = value.get("webSocketDebuggerUrl")
            if not all(
                isinstance(item, str) and item
                for item in (target_id, target_type, web_socket)
            ):
                continue
            if (
                len(target_id.encode("utf-8")) > MAX_TARGET_ID_BYTES
                or len(target_type.encode("utf-8")) > MAX_TARGET_TYPE_BYTES
                or len(web_socket.encode("utf-8")) > MAX_TARGET_URL_BYTES
            ):
                continue
            title = value.get("title") if isinstance(value.get("title"), str) else ""
            target_url = value.get("url") if isinstance(value.get("url"), str) else ""
            if (
                len(title.encode("utf-8")) > MAX_TARGET_URL_BYTES
                or len(target_url.encode("utf-8")) > MAX_TARGET_URL_BYTES
            ):
                continue
            targets.append(
                {
                    "id": target_id,
                    "type": target_type,
                    "title": title,
                    "url": target_url,
                    "web_socket_url": web_socket,
                }
            )
        return targets

    def _serve_target(self, target: dict[str, str]) -> None:
        self._set_state("connecting", None)
        connection = NativeDebuggerConnection(
            target["web_socket_url"], self.debugger_transport_binary
        )
        public_target = {key: target[key] for key in ("id", "type", "title", "url")}
        with self._lock:
            self._connection = connection
            self._target = public_target
            self._scripts = {}
            self._paused = None
            self._watch_frame_id = None
            self._pause_serial += 1
            self._changed()
        reader = threading.Thread(
            target=self._read_messages,
            args=(connection,),
            name="reb-debugger-reader",
            daemon=True,
        )
        self._reader_thread = reader
        reader.start()
        try:
            self._command("Runtime.enable")
            self._command("Page.enable")
            self._command(
                "Debugger.enable", {"maxScriptsCacheSize": float(100 * 1024 * 1024)}
            )
            self._command(
                "Debugger.setAsyncCallStackDepth", {"maxDepth": MAX_ASYNC_STACK_DEPTH}
            )
            self._command("Log.enable")
            self._restore_settings()
            self._restore_request_interception(target["id"])
            with self._lock:
                already_paused = self._paused is not None
            if not already_paused:
                self._set_state("running", None)
            next_target_refresh = 0.0
            while reader.is_alive() and not self._stop.wait(0.25):
                if time.monotonic() < next_target_refresh:
                    continue
                next_target_refresh = time.monotonic() + 1.0
                try:
                    targets = self._discover_targets()[:MAX_TARGETS]
                except (OSError, ValueError, DebuggerBridgeError, json.JSONDecodeError):
                    continue
                with self._lock:
                    if targets != self._targets:
                        self._targets = targets
                        current = next(
                            (item for item in targets if item["id"] == target["id"]),
                            None,
                        )
                        if current is not None:
                            self._target = {
                                key: current[key]
                                for key in ("id", "type", "title", "url")
                            }
                        self._changed()
                    refresh_action_scope = (
                        self._request_interception_context_id is not None
                    )
                if refresh_action_scope:
                    try:
                        self._refresh_action_scope_targets()
                    except (
                        OSError,
                        ValueError,
                        DebuggerBridgeError,
                        json.JSONDecodeError,
                    ) as exception:
                        with self._lock:
                            self._action_scope_last_error = truncate_text(
                                str(exception), 512
                            )
                            self._changed()
        finally:
            connection.close()
            reader.join(timeout=1.0)
            with self._lock:
                origin_trace_id = (
                    self._memory_origin_trace["trace_id"]
                    if self._memory_origin_trace_active_locked()
                    else None
                )
                clear_heap_baseline = (
                    self._connection is connection and not self._heap_diff_busy
                )
                if self._object_experiment.get("target_id") == target["id"]:
                    self._object_experiment_group = None
                    self._object_experiment_objects_id = None
                    self._object_experiment_result_indices.clear()
                    self._object_experiment["search_id"] = 0
                    self._object_experiment["search"] = None
                    self._object_experiment["results"] = []
                    self._object_experiment["last_mutation"] = None
                    if self._object_experiment["state"] not in {
                        "disposing",
                        "disposed",
                    }:
                        self._object_experiment["state"] = "error"
                        self._object_experiment["message"] = (
                            "Object Lab target disconnected. Reattach it and run the search again."
                        )
                if self._runtime_hooks.get("target_id") == target["id"]:
                    self._runtime_hook_points.clear()
                    self._runtime_hook_processing = False
                    self._runtime_hook_stop_requested = False
                    self._runtime_hook_deferred_pause = None
                    self._runtime_hook_epoch += 1
                    self._runtime_hooks["active_points"] = 0
                    self._runtime_hooks["definitions"] = []
                    if self._runtime_hooks["state"] not in {
                        "disposing",
                        "disposed",
                    }:
                        self._runtime_hooks["state"] = "error"
                        self._runtime_hooks["last_failure"] = (
                            "The isolated target disconnected. Hook definitions were cleared."
                        )
                        self._runtime_hooks["message"] = (
                            "Runtime Hooks target disconnected. Reattach it and add hooks again."
                        )
                if self._automation_recipes_state.get("target_id") == target["id"]:
                    self._cancel_automation_watchdog_locked()
                    self._automation_auto_script_ids = {}
                    self._automation_binding_target_ids = set()
                    self._automation_binding_nonce = None
                    self._automation_active_run_id = None
                    self._automation_active_document_id = None
                    self._automation_active_target_id = None
                    self._automation_active_session = None
                    self._automation_cancel_requested = False
                    self._automation_pending_triggers = []
                    self._automation_processing = False
                    self._automation_variables = {}
                    self._automation_epoch += 1
                    self._automation_recipes_state["auto_armed"] = False
                    self._automation_recipes_state["active_run"] = None
                    self._automation_recipes_state["variable_count"] = 0
                    self._automation_recipes_state["variable_bytes"] = 0
                    if self._automation_recipes_state["state"] not in {
                        "disposing",
                        "disposed",
                    }:
                        message = (
                            "Automation Recipes target disconnected. Automatic execution, "
                            "variables, and active results were cleared; recipe definitions remain."
                        )
                        self._automation_recipes_state["state"] = "error"
                        self._automation_recipes_state["last_failure"] = message
                        self._automation_recipes_state["message"] = message
                if self._connection is connection:
                    self._connection = None
                    self._target = None
                    self._scripts = {}
                    self._paused = None
                    self._state = "waiting"
                    self._watch_frame_id = None
                    self._pause_serial += 1
                    self._changed()
            if origin_trace_id is not None:
                self._complete_memory_origin_trace(
                    origin_trace_id,
                    "error",
                    "Debugger target disconnected during Memory Origin Trace.",
                    resume=False,
                )
            if clear_heap_baseline:
                self._clear_heap_diff_baseline()

    def _read_messages(self, connection: NativeDebuggerConnection) -> None:
        error: Optional[BaseException] = None
        try:
            while not self._stop.is_set():
                message = connection.receive_json()
                if message is None:
                    continue
                command_id = message.get("id")
                if isinstance(command_id, int):
                    with self._lock:
                        pending = self._pending.pop(command_id, None)
                    if pending is not None:
                        pending.response = message
                        pending.event.set()
                    continue
                method = message.get("method")
                params = message.get("params", {})
                if isinstance(method, str) and isinstance(params, dict):
                    self._handle_event(method, params)
        except (OSError, DebuggerBridgeError, json.JSONDecodeError) as exception:
            error = exception
        finally:
            self._fail_pending(error or WebSocketClosed("Debugger target disconnected"))
            connection.close()

    def _handle_event(self, method: str, params: dict[str, Any]) -> None:
        if method == "Runtime.bindingCalled":
            with self._lock:
                scoped = bool(self._action_scope_targets)
            if not scoped:
                self._handle_automation_binding(params)
            return
        if method == "Page.loadEventFired":
            with self._lock:
                scoped = bool(self._action_scope_targets)
            if not scoped:
                self._queue_automation_trigger("after-load")
            return
        if method == "Fetch.requestPaused":
            with self._lock:
                scoped = bool(self._action_scope_targets)
            if not scoped:
                self._handle_request_interception_pause_async(params)
            return
        if method == "HeapProfiler.addHeapSnapshotChunk":
            with self._lock:
                collector = self._heap_snapshot_collector
            if collector is not None:
                collector.append(params.get("chunk"))
            return
        if method == "Debugger.scriptParsed":
            script = self._parse_script(params)
            if script is not None:
                with self._lock:
                    if (
                        len(self._scripts) >= MAX_SCRIPTS
                        and script["script_id"] not in self._scripts
                    ):
                        oldest = next(iter(self._scripts))
                        self._scripts.pop(oldest, None)
                    self._scripts[script["script_id"]] = script
                    self._changed()
            return
        if method == "Page.frameNavigated":
            frame = params.get("frame")
            if isinstance(frame, dict) and not isinstance(frame.get("parentId"), str):
                self._handle_runtime_hook_navigation()
            return
        if method == "Debugger.paused":
            if self._handle_runtime_hook_pause_async(params):
                return
            paused = self._parse_pause(params)
            with self._lock:
                self._pause_serial += 1
                pause_serial = self._pause_serial
                self._paused = paused
                self._watch_frame_id = (
                    paused["call_frames"][0]["id"] if paused["call_frames"] else None
                )
                self._state = "paused"
                self._error = None
                origin_trace_active = self._memory_origin_trace_active_locked()
                if origin_trace_active:
                    paused["scope_coverage"] = {
                        "status": "partial",
                        "properties": 0,
                        "limit": MAX_TOTAL_SCOPE_PROPERTIES,
                    }
                self._changed()
            if origin_trace_active:
                self._start_memory_origin_trace_pause_async(pause_serial, paused)
            else:
                self._enrich_pause_async(pause_serial)
            return
        if method == "Debugger.resumed":
            with self._lock:
                self._pause_serial += 1
                self._paused = None
                self._watch_frame_id = None
                self._state = "running"
                self._error = None
                self._changed()
            return
        if method == "Debugger.breakpointResolved":
            breakpoint_id = params.get("breakpointId")
            location = self._parse_location(params.get("location"))
            if isinstance(breakpoint_id, str) and location is not None:
                with self._lock:
                    breakpoint = self._breakpoints.get(breakpoint_id)
                    if (
                        breakpoint is not None
                        and location not in breakpoint["locations"]
                    ):
                        if len(breakpoint["locations"]) < MAX_BREAKPOINT_LOCATIONS:
                            breakpoint["locations"].append(location)
                        else:
                            breakpoint["locations_truncated"] = True
                        self._changed()
            return
        if method == "Runtime.consoleAPICalled":
            self._append_console(
                params.get("type", "log"),
                params.get("timestamp"),
                params.get("args"),
                params.get("stackTrace"),
            )
            return
        if method == "Runtime.exceptionThrown":
            details = params.get("exceptionDetails")
            if isinstance(details, dict):
                value = details.get("exception")
                if not isinstance(value, dict):
                    value = {
                        "type": "string",
                        "value": details.get("text", "Exception"),
                    }
                self._append_console(
                    "error", params.get("timestamp"), [value], details.get("stackTrace")
                )
            return
        if method == "Log.entryAdded":
            entry = params.get("entry")
            if isinstance(entry, dict):
                value = {"type": "string", "value": entry.get("text", "")}
                self._append_console(
                    entry.get("level", "info"),
                    entry.get("timestamp"),
                    [value],
                    entry.get("stackTrace"),
                )

    def _command(
        self, method: str, params: Optional[dict[str, Any]] = None, timeout: float = 3.0
    ) -> dict[str, Any]:
        with self._lock:
            connection = self._connection
            if connection is None:
                raise DebuggerBridgeError("The browser debugger is not attached")
            command_id = self._next_command_id
            self._next_command_id += 1
            pending = PendingCommand(threading.Event())
            self._pending[command_id] = pending
        try:
            connection.send_json(
                {"id": command_id, "method": method, "params": params or {}}
            )
        except BaseException:
            with self._lock:
                self._pending.pop(command_id, None)
            raise
        if not pending.event.wait(timeout):
            with self._lock:
                self._pending.pop(command_id, None)
            raise DebuggerBridgeError(f"Debugger command timed out: {method}")
        if pending.error is not None:
            raise DebuggerBridgeError(str(pending.error))
        response = pending.response or {}
        error = response.get("error")
        if isinstance(error, dict):
            message = error.get("message")
            raise ProtocolError(
                message
                if isinstance(message, str)
                else f"Debugger command failed: {method}"
            )
        result = response.get("result", {})
        if not isinstance(result, dict):
            raise ProtocolError(f"Debugger returned malformed command result: {method}")
        return result

    def _command_without_wait(
        self, method: str, params: Optional[dict[str, Any]] = None
    ) -> bool:
        with self._lock:
            connection = self._connection
            if connection is None:
                return False
            command_id = self._next_command_id
            self._next_command_id += 1
        try:
            connection.send_json(
                {"id": command_id, "method": method, "params": params or {}}
            )
        except DebuggerBridgeError:
            return False
        return True

    def _set_breakpoint(
        self, request: dict[str, Any], replacing: Optional[str] = None
    ) -> dict[str, Any]:
        url = required_text(
            request, "url", MAX_BREAKPOINT_TEXT_BYTES, allow_empty=True
        )
        script_id_value = request.get("script_id")
        script_id = None
        if script_id_value == "" and url:
            script_id_value = None
        if script_id_value is not None:
            script_id = required_text(request, "script_id", MAX_TARGET_ID_BYTES)
        if not url and script_id is None:
            raise DebuggerBridgeError("Breakpoint URL or script ID is required")
        line = request.get("line")
        column = request.get("column", 0)
        kind = request.get("kind")
        if kind is None:
            kind = "conditional" if request.get("condition") else "line"
        if kind not in {"line", "conditional", "logpoint"}:
            raise DebuggerBridgeError("Breakpoint kind is invalid")
        expression = request.get("expression", request.get("condition", ""))
        if (
            not isinstance(line, int)
            or isinstance(line, bool)
            or line < 0
            or line >= 2**31
        ):
            raise DebuggerBridgeError("Breakpoint line is invalid")
        if (
            not isinstance(column, int)
            or isinstance(column, bool)
            or column < 0
            or column >= 2**31
        ):
            raise DebuggerBridgeError("Breakpoint column is invalid")
        if (
            not isinstance(expression, str)
            or len(expression.encode("utf-8")) > MAX_BREAKPOINT_TEXT_BYTES
        ):
            raise DebuggerBridgeError("Breakpoint expression is invalid")
        if kind != "line" and not expression:
            raise DebuggerBridgeError("Breakpoint expression is required")
        condition = "" if kind == "line" else expression
        if kind == "logpoint":
            condition = f"console.log({expression}), false"
        if len(condition.encode("utf-8")) > MAX_BREAKPOINT_TEXT_BYTES:
            raise DebuggerBridgeError("Breakpoint condition is invalid")
        with self._lock:
            if (
                len(self._breakpoints) >= MAX_BREAKPOINTS
                and replacing not in self._breakpoints
            ):
                raise DebuggerBridgeError("Breakpoint limit reached")
            if not url and script_id not in self._scripts:
                raise DebuggerBridgeError("Breakpoint script is unavailable")
        if url:
            result = self._command(
                "Debugger.setBreakpointByUrl",
                {
                    "lineNumber": line,
                    "url": url,
                    "columnNumber": column,
                    "condition": condition,
                },
            )
            locations = result.get("locations", [])
        else:
            result = self._command(
                "Debugger.setBreakpoint",
                {
                    "location": {
                        "scriptId": script_id,
                        "lineNumber": line,
                        "columnNumber": column,
                    },
                    "condition": condition,
                },
            )
            actual_location = result.get("actualLocation")
            locations = [actual_location] if actual_location is not None else []
        breakpoint_id = result.get("breakpointId")
        if (
            not isinstance(breakpoint_id, str)
            or len(breakpoint_id.encode("utf-8")) > MAX_BREAKPOINT_TEXT_BYTES
            or not isinstance(locations, list)
        ):
            raise ProtocolError("Debugger returned a malformed breakpoint")
        parsed_locations = []
        locations_truncated = False
        for value in locations:
            location = self._parse_location(value)
            if location is None:
                continue
            if len(parsed_locations) >= MAX_BREAKPOINT_LOCATIONS:
                locations_truncated = True
                break
            parsed_locations.append(location)
        record = {
            "id": breakpoint_id,
            "url": url,
            "script_id": script_id or "",
            "line": line,
            "column": column,
            "condition": condition,
            "kind": kind,
            "expression": expression,
            "locations": parsed_locations,
            "locations_truncated": locations_truncated,
        }
        with self._lock:
            self._breakpoints[breakpoint_id] = record
            self._changed()
        return {
            "ok": True,
            "breakpoint": record,
            "generation": self.snapshot()["generation"],
        }

    def _set_xhr_breakpoint(self, request: dict[str, Any]) -> None:
        pattern = required_text(
            request, "pattern", MAX_BREAKPOINT_TEXT_BYTES, allow_empty=True
        )
        with self._lock:
            if (
                pattern not in self._xhr_breakpoints
                and len(self._xhr_breakpoints) >= MAX_XHR_BREAKPOINTS
            ):
                raise DebuggerBridgeError("XHR breakpoint limit reached")
        self._command("DOMDebugger.setXHRBreakpoint", {"url": pattern})
        with self._lock:
            if pattern not in self._xhr_breakpoints:
                self._xhr_breakpoints.append(pattern)
            self._changed()

    def _restore_settings(self) -> None:
        with self._lock:
            active = self._breakpoints_active
            pause_mode = self._pause_on_exceptions
            breakpoints = list(self._breakpoints.values())
            xhr_breakpoints = list(self._xhr_breakpoints)
            event_breakpoints = list(self._event_breakpoints)
            self._breakpoints = {}
        self._command("Debugger.setBreakpointsActive", {"active": active})
        self._command("Debugger.setPauseOnExceptions", {"state": pause_mode})
        for breakpoint in breakpoints:
            try:
                self._set_breakpoint(breakpoint)
            except DebuggerBridgeError:
                continue
        for pattern in xhr_breakpoints:
            try:
                self._command("DOMDebugger.setXHRBreakpoint", {"url": pattern})
            except DebuggerBridgeError:
                continue
        for event_name in event_breakpoints:
            try:
                self._command(
                    "DOMDebugger.setEventListenerBreakpoint", {"eventName": event_name}
                )
            except DebuggerBridgeError:
                continue

    def _restore_request_interception(self, target_id: str) -> None:
        with self._lock:
            if (
                self._request_interception_context_id is None
                or self._request_interception["target_id"] != target_id
            ):
                return
            pattern = self._request_interception_rule["url_pattern"]
            was_running = self._request_interception["state"] == "running"
            object_was_running = self._object_experiment["state"] in {
                "navigating",
                "searching",
                "mutating",
            }
            scoped_sessions_active = bool(self._action_scope_targets)
        if not scoped_sessions_active:
            self._command(
                "Fetch.enable",
                {
                    "patterns": [
                        {"urlPattern": pattern, "requestStage": "Request"}
                    ],
                    "handleAuthRequests": False,
                },
            )
        with self._lock:
            if self._request_interception["target_id"] != target_id:
                return
            self._request_interception["state"] = "error" if was_running else "ready"
            self._request_interception["message"] = (
                "The experiment target reattached while a request was running; run it again."
                if was_running
                else "Disposable context ready. Configure a bounded interception rule."
            )
            if self._repeater_active_execution_id is None:
                self._repeater["state"] = "ready"
                self._repeater["message"] = (
                    "Repeater is ready inside the disposable credential-free context."
                )
            self._object_experiment["isolated"] = True
            self._object_experiment["target_id"] = target_id
            self._object_experiment["state"] = (
                "error"
                if object_was_running
                else "loaded"
                if self._object_experiment["url"]
                else "ready"
            )
            self._object_experiment["message"] = (
                "The Object Lab target reattached during an action; run that action again."
                if object_was_running
                else "Object Lab page reattached. Run the bounded search again."
                if self._object_experiment["url"]
                else "Object Lab is isolated and ready for an explicit page URL."
            )
            self._runtime_hooks["isolated"] = True
            self._runtime_hooks["target_id"] = target_id
            self._runtime_hook_points.clear()
            self._runtime_hook_processing = False
            self._runtime_hook_stop_requested = False
            self._runtime_hook_deferred_pause = None
            self._runtime_hook_epoch += 1
            self._runtime_hooks["active_points"] = 0
            self._runtime_hooks["definitions"] = []
            self._runtime_hooks["state"] = "ready"
            self._runtime_hooks["message"] = (
                "Runtime Hooks is isolated and ready for a live JavaScript function."
            )
            self._cancel_automation_watchdog_locked()
            self._automation_auto_script_ids = {}
            self._automation_binding_target_ids = set()
            self._automation_binding_nonce = None
            self._automation_active_run_id = None
            self._automation_active_document_id = None
            self._automation_active_target_id = None
            self._automation_active_session = None
            self._automation_cancel_requested = False
            self._automation_pending_triggers = []
            self._automation_processing = False
            self._automation_variables = {}
            self._automation_epoch += 1
            self._automation_recipes_state["isolated"] = True
            self._automation_recipes_state["target_id"] = target_id
            self._automation_recipes_state["auto_armed"] = False
            self._automation_recipes_state["active_run"] = None
            self._automation_recipes_state["variable_count"] = 0
            self._automation_recipes_state["variable_bytes"] = 0
            self._automation_recipes_state["state"] = "ready"
            self._automation_recipes_state["message"] = (
                "Automation Recipes is isolated and ready for explicit page-context code."
            )
            self._sync_automation_library_locked()
            self._changed()

    def _parse_script(self, params: dict[str, Any]) -> Optional[dict[str, Any]]:
        script_id = params.get("scriptId")
        url = params.get("url")
        script_hash = params.get("hash") if isinstance(params.get("hash"), str) else ""
        source_map_url = (
            params.get("sourceMapURL")
            if isinstance(params.get("sourceMapURL"), str)
            else ""
        )
        if (
            not isinstance(script_id, str)
            or not isinstance(url, str)
            or url.startswith("reb-automation-")
            or len(script_id.encode("utf-8")) > MAX_TARGET_ID_BYTES
            or len(url.encode("utf-8")) > MAX_TARGET_URL_BYTES
            or len(script_hash.encode("utf-8")) > MAX_TARGET_URL_BYTES
            or len(source_map_url.encode("utf-8")) > MAX_TARGET_URL_BYTES
        ):
            return None
        return {
            "script_id": script_id,
            "url": url,
            "start_line": bounded_integer(params.get("startLine")),
            "start_column": bounded_integer(params.get("startColumn")),
            "end_line": bounded_integer(params.get("endLine")),
            "end_column": bounded_integer(params.get("endColumn")),
            "execution_context_id": bounded_integer(
                params.get("executionContextId")
            ),
            "hash": script_hash,
            "source_map_url": source_map_url,
            "has_source_url": params.get("hasSourceURL") is True,
            "is_module": params.get("isModule") is True,
            "length": bounded_integer(params.get("length")),
            "language": params.get("scriptLanguage")
            if params.get("scriptLanguage") in {"JavaScript", "WebAssembly"}
            else "JavaScript",
        }

    def _parse_pause(self, params: dict[str, Any]) -> dict[str, Any]:
        raw_frames = params.get("callFrames")
        frames = []
        if isinstance(raw_frames, list):
            frames = [
                frame
                for value in raw_frames[:MAX_CALL_FRAMES]
                if (frame := self._parse_call_frame(value)) is not None
            ]
        reason = (
            params.get("reason") if isinstance(params.get("reason"), str) else "other"
        )
        reason = truncate_text(reason, 256)
        description = None
        data = params.get("data")
        if isinstance(data, dict):
            raw_description = data.get("description") or data.get("message")
            if isinstance(raw_description, str):
                description = truncate_text(raw_description)
        async_stack = self._parse_async_stack(params.get("asyncStackTrace"))
        hit_breakpoints = params.get("hitBreakpoints", [])
        if not isinstance(hit_breakpoints, list):
            hit_breakpoints = []
        bounded_hit_breakpoints = []
        for value in hit_breakpoints:
            if (
                isinstance(value, str)
                and len(value.encode("utf-8")) <= MAX_BREAKPOINT_TEXT_BYTES
            ):
                bounded_hit_breakpoints.append(value)
                if len(bounded_hit_breakpoints) >= MAX_BREAKPOINTS:
                    break
        return {
            "reason": reason,
            "description": description,
            "call_frames": frames,
            "async_stack": async_stack,
            "hit_breakpoints": bounded_hit_breakpoints,
            "scope_coverage": {
                "status": "loading",
                "properties": 0,
                "limit": MAX_TOTAL_SCOPE_PROPERTIES,
            },
        }

    def _parse_call_frame(self, value: Any) -> Optional[dict[str, Any]]:
        if not isinstance(value, dict):
            return None
        frame_id = value.get("callFrameId")
        function_name = value.get("functionName")
        url = value.get("url")
        location = self._parse_location(value.get("location"))
        if (
            not isinstance(frame_id, str)
            or not isinstance(function_name, str)
            or not isinstance(url, str)
            or len(frame_id.encode("utf-8")) > MAX_TARGET_ID_BYTES
            or location is None
        ):
            return None
        scopes = []
        raw_scopes = value.get("scopeChain")
        if isinstance(raw_scopes, list):
            for raw_scope in raw_scopes[:MAX_SCOPES_PER_FRAME]:
                if not isinstance(raw_scope, dict):
                    continue
                scope_type = raw_scope.get("type")
                remote_object = raw_scope.get("object")
                if not isinstance(scope_type, str) or not isinstance(
                    remote_object, dict
                ):
                    continue
                parsed_object = self._remote_object(remote_object)
                if parsed_object is None:
                    continue
                scopes.append(
                    {
                        "type": truncate_text(scope_type, 256),
                        "name": truncate_text(raw_scope.get("name"))
                        if isinstance(raw_scope.get("name"), str)
                        else "",
                        "object": parsed_object,
                        "location": self._parse_location(
                            raw_scope.get("startLocation")
                        ),
                        "properties": [],
                    }
                )
        return {
            "id": frame_id,
            "function_name": truncate_text(function_name) or "(anonymous)",
            "url": truncate_text(url, MAX_TARGET_URL_BYTES),
            "location": location,
            "function_location": self._parse_location(value.get("functionLocation")),
            "this": self._remote_object(value.get("this")),
            "return_value": self._remote_object(value.get("returnValue")),
            "scopes": scopes,
        }

    def _parse_async_stack(self, value: Any) -> list[dict[str, Any]]:
        stacks = []
        depth = 0
        while isinstance(value, dict) and depth < MAX_ASYNC_STACK_DEPTH:
            description = (
                value.get("description")
                if isinstance(value.get("description"), str)
                else "Async"
            )
            description = truncate_text(description)
            raw_frames = value.get("callFrames")
            frames = []
            if isinstance(raw_frames, list):
                for raw_frame in raw_frames[:MAX_CALL_FRAMES]:
                    if not isinstance(raw_frame, dict):
                        continue
                    function_name = raw_frame.get("functionName")
                    url = raw_frame.get("url")
                    script_id = raw_frame.get("scriptId")
                    line = raw_frame.get("lineNumber")
                    column = raw_frame.get("columnNumber")
                    if (
                        all(
                            isinstance(item, str)
                            for item in (function_name, url, script_id)
                        )
                        and all(
                            isinstance(item, int) and not isinstance(item, bool)
                            for item in (line, column)
                        )
                        and (
                            len(script_id.encode("utf-8")) <= MAX_TARGET_ID_BYTES
                            and 0 <= line < 2**31
                            and 0 <= column < 2**31
                        )
                    ):
                        frames.append(
                            {
                                "function_name": truncate_text(function_name)
                                or "(anonymous)",
                                "url": truncate_text(url, MAX_TARGET_URL_BYTES),
                                "location": {
                                    "script_id": script_id,
                                    "line": line,
                                    "column": column,
                                },
                            }
                        )
            stacks.append({"description": description, "call_frames": frames})
            value = value.get("parent")
            depth += 1
        return stacks

    def _parse_location(self, value: Any) -> Optional[dict[str, Any]]:
        if not isinstance(value, dict):
            return None
        script_id = value.get("scriptId")
        line = value.get("lineNumber")
        column = value.get("columnNumber", 0)
        if (
            not isinstance(script_id, str)
            or len(script_id.encode("utf-8")) > MAX_TARGET_ID_BYTES
            or not all(
                isinstance(item, int) and not isinstance(item, bool)
                for item in (line, column)
            )
        ):
            return None
        if line < 0 or line >= 2**31 or column < 0 or column >= 2**31:
            return None
        return {"script_id": script_id, "line": line, "column": column}

    def _enrich_pause_async(self, pause_serial: int) -> None:
        thread = threading.Thread(
            target=self._enrich_pause,
            args=(pause_serial,),
            name="reb-debugger-scopes",
            daemon=True,
        )
        thread.start()

    def _enrich_pause(self, pause_serial: int) -> None:
        with self._lock:
            paused = self._paused
            if paused is None or pause_serial != self._pause_serial:
                return
            enriched = copy.deepcopy(paused)
            frames = enriched["call_frames"]
        total_properties = 0
        partial = False
        for frame in frames:
            for scope in frame["scopes"]:
                object_id = scope["object"].get("object_id")
                if not object_id or total_properties >= MAX_TOTAL_SCOPE_PROPERTIES:
                    partial = partial or total_properties >= MAX_TOTAL_SCOPE_PROPERTIES
                    continue
                try:
                    result = self._command(
                        "Runtime.getProperties",
                        {
                            "objectId": object_id,
                            "ownProperties": True,
                            "accessorPropertiesOnly": False,
                            "generatePreview": True,
                        },
                    )
                except DebuggerBridgeError:
                    partial = True
                    continue
                properties = result.get("result")
                if not isinstance(properties, list):
                    partial = True
                    continue
                remaining = MAX_TOTAL_SCOPE_PROPERTIES - total_properties
                selected = properties[: min(MAX_SCOPE_PROPERTIES, remaining)]
                scope["properties"] = [
                    property_value
                    for value in selected
                    if (property_value := self._parse_property(value)) is not None
                ]
                total_properties += len(scope["properties"])
                partial = partial or len(properties) > len(selected)
        with self._lock:
            watch_frame_id = self._watch_frame_id
        self._evaluate_watches(watch_frame_id)
        with self._lock:
            if self._paused is not paused or pause_serial != self._pause_serial:
                return
            enriched["scope_coverage"] = {
                "status": "partial" if partial else "complete",
                "properties": total_properties,
                "limit": MAX_TOTAL_SCOPE_PROPERTIES,
            }
            self._paused = enriched
            self._changed()

    def _evaluate_watches(self, frame_id: Optional[str]) -> None:
        if frame_id is None:
            return
        with self._lock:
            watches = [dict(watch) for watch in self._watches]
        for watch in watches:
            try:
                result = self._command(
                    "Debugger.evaluateOnCallFrame",
                    {
                        "callFrameId": frame_id,
                        "expression": watch["expression"],
                        "silent": True,
                        "returnByValue": False,
                        "generatePreview": True,
                        "throwOnSideEffect": True,
                        "timeout": 500,
                    },
                )
                exception = result.get("exceptionDetails")
                if isinstance(exception, dict):
                    watch["result"] = None
                    watch["error"] = str(exception.get("text", "Evaluation failed"))[
                        :4_096
                    ]
                else:
                    watch["result"] = self._remote_object(result.get("result"))
                    watch["error"] = None
            except DebuggerBridgeError as exception:
                watch["result"] = None
                watch["error"] = str(exception)[:4_096]
        with self._lock:
            current_by_id = {watch["id"]: watch for watch in self._watches}
            for watch in watches:
                current = current_by_id.get(watch["id"])
                if current is not None:
                    current["result"] = watch["result"]
                    current["error"] = watch["error"]
            self._changed()

    def _evaluate_watches_async(self, frame_id: str) -> None:
        thread = threading.Thread(
            target=self._evaluate_watches,
            args=(frame_id,),
            name="reb-debugger-watches",
            daemon=True,
        )
        thread.start()

    def _parse_property(self, value: Any) -> Optional[dict[str, Any]]:
        if not isinstance(value, dict) or not isinstance(value.get("name"), str):
            return None
        return {
            "name": truncate_text(value["name"]),
            "value": self._remote_object(value.get("value")),
            "get": self._remote_object(value.get("get")),
            "set": self._remote_object(value.get("set")),
            "writable": value.get("writable") is True,
            "enumerable": value.get("enumerable") is True,
            "configurable": value.get("configurable") is True,
        }

    def _remote_object(self, value: Any) -> Optional[dict[str, Any]]:
        if not isinstance(value, dict) or not isinstance(value.get("type"), str):
            return None
        value_type = value["type"]
        if len(value_type.encode("utf-8")) > 256:
            return None
        object_id = value.get("objectId")
        if (
            not isinstance(object_id, str)
            or len(object_id.encode("utf-8")) > MAX_TARGET_ID_BYTES
        ):
            object_id = None
        result = {
            "type": value_type,
            "subtype": truncate_text(value.get("subtype"), 256)
            if isinstance(value.get("subtype"), str)
            else None,
            "class_name": truncate_text(value.get("className"))
            if isinstance(value.get("className"), str)
            else None,
            "description": truncate_text(value.get("description"))
            if isinstance(value.get("description"), str)
            else None,
            "object_id": object_id,
            "unserializable_value": truncate_text(
                value.get("unserializableValue")
            )
            if isinstance(value.get("unserializableValue"), str)
            else None,
            "value": None,
            "value_truncated": False,
        }
        primitive = value.get("value")
        if isinstance(primitive, str):
            result["value_truncated"] = (
                len(primitive.encode("utf-8")) > MAX_REMOTE_TEXT_BYTES
            )
            result["value"] = truncate_text(primitive)
        elif primitive is None or isinstance(primitive, bool):
            result["value"] = primitive
        elif is_finite_protocol_number(primitive):
            result["value"] = primitive
        preview = value.get("preview")
        if isinstance(preview, dict):
            result["preview"] = {
                "description": truncate_text(preview.get("description"))
                if isinstance(preview.get("description"), str)
                else None,
                "overflow": preview.get("overflow") is True,
            }
        return result

    def _append_console(
        self, entry_type: Any, timestamp: Any, raw_arguments: Any, stack_trace: Any
    ) -> None:
        if not isinstance(entry_type, str):
            entry_type = "log"
        arguments = []
        if isinstance(raw_arguments, list):
            arguments = [
                argument
                for value in raw_arguments[:MAX_CONSOLE_ARGUMENTS]
                if (argument := self._remote_object(value)) is not None
            ]
        frames = []
        if isinstance(stack_trace, dict) and isinstance(
            stack_trace.get("callFrames"), list
        ):
            for raw_frame in stack_trace["callFrames"][:MAX_CALL_FRAMES]:
                if not isinstance(raw_frame, dict):
                    continue
                function_name = raw_frame.get("functionName")
                url = raw_frame.get("url")
                line = raw_frame.get("lineNumber")
                column = raw_frame.get("columnNumber")
                if (
                    isinstance(function_name, str)
                    and isinstance(url, str)
                    and all(
                        isinstance(item, int) and not isinstance(item, bool)
                        for item in (line, column)
                    )
                    and 0 <= line < 2**31
                    and 0 <= column < 2**31
                ):
                    frames.append(
                        {
                            "function_name": truncate_text(function_name)
                            or "(anonymous)",
                            "url": truncate_text(url, MAX_TARGET_URL_BYTES),
                            "line": line,
                            "column": column,
                        }
                    )
        with self._lock:
            entry = {
                "id": str(self._next_console_id),
                "type": entry_type[:64],
                "timestamp": timestamp
                if is_finite_protocol_number(timestamp)
                else None,
                "arguments": arguments,
                "stack": frames,
            }
            self._next_console_id += 1
            self._console.append(entry)
            if len(self._console) > MAX_CONSOLE_ENTRIES:
                self._console = self._console[-MAX_CONSOLE_ENTRIES:]
            self._changed()

    def _fail_pending(self, error: BaseException) -> None:
        with self._lock:
            pending_commands = list(self._pending.values())
            self._pending.clear()
        for pending in pending_commands:
            pending.error = error
            pending.event.set()

    def _set_state(self, state: str, error: Optional[str]) -> None:
        with self._lock:
            if self._state == state and self._error == error:
                return
            self._state = state
            self._error = error[:4_096] if error else None
            self._changed()

    def _changed(self) -> None:
        self._generation += 1
        self._condition.notify_all()
