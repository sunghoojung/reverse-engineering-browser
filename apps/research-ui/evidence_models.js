      const eventCategories = new Set([
        'unknown', 'canvas', 'webgl', 'web_audio', 'navigator', 'permissions',
        'storage', 'webrtc', 'wasm', 'network', 'vm', 'artifact'
      ]);
      const fingerprintSignalCategories = new Set([
        'canvas', 'webgl', 'web_audio', 'navigator', 'permissions', 'storage', 'webrtc'
      ]);
      const eventTypes = {
        1: new Set([
          'unknown', 'api_call', 'property_read', 'module_compiled',
          'module_instantiated', 'request_started', 'response_completed', 'gap'
        ]),
        2: new Set([
          'unknown', 'api_call', 'property_read', 'module_compiled',
          'module_instantiated', 'request_started', 'response_completed', 'gap',
          'request_initiated', 'request_redirected', 'response_started',
          'request_completed', 'request_failed', 'vm_finding',
          'artifact_captured', 'artifact_capture_failed'
        ])
      };
      const uint64Fields = [
        'session_id', 'sequence_number', 'monotonic_time_ns', 'navigation_id',
        'frame_id', 'artifact_id', 'parent_event_id', 'request_id'
      ];
      const browserContextFields = ['browser_context_id_high', 'browser_context_id_low'];
      const int64Fields = ['encoded_data_length', 'decoded_body_length'];
      const uint32Fields = ['process_id', 'thread_id', 'initiator_request_id', 'initiator_process_id'];
      const uint16Fields = ['resource_type', 'flags'];
      const uint64Max = 18446744073709551615n;
      const int64Min = -9223372036854775808n;
      const int64Max = 9223372036854775807n;
      const resourceTypeFilters = new Map([
        [0, 'doc'], [1, 'doc'], [2, 'css'], [3, 'js'], [4, 'img'], [5, 'font'],
        [8, 'media'], [11, 'xhr'], [13, 'xhr'], [19, 'doc'], [20, 'doc']
      ]);
      const lifecycleRanks = new Map([
        ['request_initiated', 1], ['request_started', 2], ['request_redirected', 3],
        ['response_started', 4], ['response_completed', 5], ['request_completed', 5],
        ['request_failed', 5]
      ]);
      const networkLifecycleTypes = new Set(lifecycleRanks.keys());
      const artifactKinds = new Set(['javascript', 'wasm', 'source_map', 'response_body']);
      const artifactCaptureOrigins = new Set([
        'unknown', 'network_response', 'dynamic_javascript', 'webassembly_compile',
        'webassembly_module', 'webassembly_instantiate'
      ]);
      const artifactIdentifierFields = [
        'artifact_id', 'session_id', 'navigation_id', 'frame_id', 'parent_artifact_id', 'creator_event_id'
      ];
      const vmKinds = new Map([
        [1, 'interpreter'], [2, 'guest program'], [3, 'invocation'],
        [4, 'host binding'], [5, 'hypothesis'], [6, 'coverage']
      ]);
      const vmHostRuntimes = new Map([[0, 'unknown'], [1, 'JavaScript'], [2, 'WebAssembly'], [3, 'mixed']]);
      const vmConfidences = new Map([[0, 'unknown'], [1, 'observed'], [2, 'inferred'], [3, 'heuristic']]);

      function isPlainObject(value) {
        return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
      }

      function isSafeIntegerInRange(value, minimum, maximum) {
        return Number.isSafeInteger(value) && value >= minimum && value <= maximum;
      }

      function utf8ByteLength(value) {
        utf8ByteLength.encoder ??= new TextEncoder();
        return utf8ByteLength.encoder.encode(value).byteLength;
      }

      function isBoundedText(value, maximumBytes) {
        return typeof value === 'string' && utf8ByteLength(value) <= maximumBytes;
      }

      function isCanonicalInteger(value, minimum, maximum, signed = false) {
        if (typeof value !== 'string') return false;
        const pattern = signed ? /^(?:0|-[1-9][0-9]*|[1-9][0-9]*)$/ : /^(?:0|[1-9][0-9]*)$/;
        if (!pattern.test(value)) return false;
        const integer = BigInt(value);
        return integer >= minimum && integer <= maximum;
      }

      function integerValue(event, field) {
        return BigInt(event[field]);
      }

      function integerText(event, field) {
        return String(event[field]);
      }

      function browserContextToken(event) {
        if (event.protocol_version !== 2 ||
            !browserContextFields.every(field => Object.hasOwn(event, field)) ||
            browserContextFields.every(field => event[field] === '0')) {
          return null;
        }
        return `${event.browser_context_id_high}:${event.browser_context_id_low}`;
      }

      function decodePayload(event) {
        return new TextDecoder().decode(bytesFromHex(event.payload));
      }

      function bytesFromHex(hex) {
        const pairs = hex.match(/.{2}/g) || [];
        return Uint8Array.from(pairs, byte => Number.parseInt(byte, 16));
      }

      function summarizeEventValue(event) {
        const vmFinding = decodeVmFinding(event);
        if (vmFinding) return `${vmFinding.kind} · ${vmFinding.label} · ${vmFinding.confidence}`;
        const values = [];
        const payload = decodePayload(event);
        if (payload) values.push(payload);
        if (event.protocol_version === 2) {
          if (event.status_code !== 0) values.push(`status ${event.status_code}`);
          if (event.error_code !== 0) values.push(`error ${event.error_code}`);
          if (event.encoded_data_length !== '0') values.push(`${event.encoded_data_length} encoded bytes`);
          if (event.decoded_body_length !== '0') values.push(`${event.decoded_body_length} decoded bytes`);
          if (event.flags & 1) values.push('payload truncated');
          if (event.flags & 2) values.push('from cache');
          if (event.flags & 4) values.push('from service worker');
        }
        return values.join(' · ') || 'no inline payload';
      }

      function formatMilliseconds(nanoseconds, prefix = '') {
        const negative = nanoseconds < 0n;
        const absolute = negative ? -nanoseconds : nanoseconds;
        const whole = absolute / 1000000n;
        const fractional = ((absolute % 1000000n) / 1000n).toString().padStart(3, '0');
        return `${negative ? '-' : prefix}${whole}.${fractional} ms`;
      }

      function countSequenceGaps(events) {
        let gaps = 0n;
        const highWaterMarks = new Map();
        for (const event of events) {
          const streamId = `${integerText(event, 'session_id')}:${event.process_id}`;
          const sequence = integerValue(event, 'sequence_number');
          const previous = highWaterMarks.get(streamId);
          const missing = previous !== undefined && sequence > previous + 1n
            ? sequence - previous - 1n
            : 0n;
          gaps += missing > 0n ? missing : event.type === 'gap' ? 1n : 0n;
          highWaterMarks.set(streamId, previous === undefined || sequence > previous ? sequence : previous);
        }
        return gaps;
      }

      function isBrokerEvent(event) {
        if (!isPlainObject(event) || !Number.isInteger(event.protocol_version)) return false;
        const payloadLimit = event.protocol_version === 1 ? 48 : event.protocol_version === 2 ? 128 : null;
        if (payloadLimit === null || !eventTypes[event.protocol_version]?.has(event.type)) return false;
        if (!eventCategories.has(event.category)) return false;
        if (event.protocol_version === 2 && (event.category === 'unknown' || event.type === 'unknown')) return false;
        if (!isSafeIntegerInRange(event.payload_size, 0, payloadLimit)) return false;
        if (event.payload_encoding !== 'hex' || typeof event.payload !== 'string') return false;
        if (event.payload.length !== event.payload_size * 2 || !/^[0-9a-f]*$/i.test(event.payload)) return false;

        if (event.protocol_version === 1) {
          const legacyUint64Fields = [
            'session_id', 'sequence_number', 'monotonic_time_ns', 'navigation_id',
            'frame_id', 'artifact_id', 'parent_event_id'
          ];
          return legacyUint64Fields.every(field => isSafeIntegerInRange(event[field], 0, Number.MAX_SAFE_INTEGER)) &&
            ['process_id', 'thread_id'].every(field => isSafeIntegerInRange(event[field], 0, 0xffffffff));
        }

        if (!uint64Fields.every(field => isCanonicalInteger(event[field], 0n, uint64Max))) return false;
        const contextFieldPresence = browserContextFields.map(field => Object.hasOwn(event, field));
        if (contextFieldPresence[0] !== contextFieldPresence[1]) return false;
        if (contextFieldPresence[0] &&
            !browserContextFields.every(field => isCanonicalInteger(event[field], 0n, uint64Max))) return false;
        if (!int64Fields.every(field => isCanonicalInteger(event[field], int64Min, int64Max, true))) return false;
        if (!uint32Fields.every(field => isSafeIntegerInRange(event[field], 0, 0xffffffff))) return false;
        if (!uint16Fields.every(field => isSafeIntegerInRange(event[field], 0, 0xffff))) return false;
        if ((event.flags & ~0x7) !== 0) return false;
        if (!isSafeIntegerInRange(event.status_code, -0x80000000, 0x7fffffff)) return false;
        if (!isSafeIntegerInRange(event.error_code, -0x80000000, 0x7fffffff)) return false;
        if (typeof event.payload_truncated !== 'boolean') return false;
        return event.payload_truncated === Boolean(event.flags & 1);
      }

      function isBrokerResponse(body) {
        return isPlainObject(body) &&
          Array.isArray(body.events) &&
          isSafeIntegerInRange(body.count, 0, 5000) &&
          body.count === body.events.length &&
          (body.broker_connected === undefined || typeof body.broker_connected === 'boolean') &&
          body.events.every(isBrokerEvent);
      }

      function isArtifact(artifact) {
        if (!isPlainObject(artifact) ||
          (Object.hasOwn(artifact, 'execution_context_id') !== Object.hasOwn(artifact, 'capture_origin'))) {
          return false;
        }
        if (Object.hasOwn(artifact, 'execution_context_id')) {
          if (!isCanonicalInteger(artifact.execution_context_id, 0n, uint64Max) ||
            !artifactCaptureOrigins.has(artifact.capture_origin) ||
            (artifact.capture_origin === 'dynamic_javascript' &&
              (artifact.kind !== 'javascript' || artifact.execution_context_id === '0')) ||
            (artifact.capture_origin.startsWith('webassembly_') &&
              (artifact.kind !== 'wasm' || artifact.execution_context_id === '0'))) return false;
        }
        return artifact.protocol_version === 1 &&
          artifactIdentifierFields.every(field => isCanonicalInteger(artifact[field], 0n, uint64Max)) &&
          artifactKinds.has(artifact.kind) &&
          typeof artifact.url === 'string' && artifact.url.length > 0 &&
          typeof artifact.mime_type === 'string' && artifact.mime_type.length > 0 &&
          isSafeIntegerInRange(artifact.byte_size, 0, Number.MAX_SAFE_INTEGER) &&
          typeof artifact.sha256 === 'string' && /^[0-9a-f]{64}$/.test(artifact.sha256) &&
          typeof artifact.sensitive === 'boolean' &&
          (!artifact.sensitive || artifact.kind === 'response_body');
      }

      function isArtifactResponse(body) {
        return isPlainObject(body) &&
          Array.isArray(body.artifacts) &&
          isSafeIntegerInRange(body.count, 0, 5000) &&
          body.count === body.artifacts.length &&
          body.artifacts.every(isArtifact);
      }

      function isDebuggerLocation(location) {
        return isPlainObject(location) && typeof location.script_id === 'string' &&
          isSafeIntegerInRange(location.line, 0, 0x7fffffff) &&
          isSafeIntegerInRange(location.column, 0, 0x7fffffff);
      }

      function isDebuggerRemoteValue(value) {
        return value === null || (isPlainObject(value) && typeof value.type === 'string' &&
          (value.object_id === null || typeof value.object_id === 'string') &&
          (value.description === null || typeof value.description === 'string') &&
          (value.subtype === null || typeof value.subtype === 'string') &&
          (value.class_name === null || typeof value.class_name === 'string') &&
          (value.unserializable_value === null || typeof value.unserializable_value === 'string') &&
          typeof value.value_truncated === 'boolean' &&
          (value.value === null || ['boolean', 'number', 'string'].includes(typeof value.value)) &&
          (value.preview === undefined || (isPlainObject(value.preview) &&
            (value.preview.description === null || typeof value.preview.description === 'string') &&
            typeof value.preview.overflow === 'boolean')));
      }

      function isDebuggerTarget(target) {
        return isPlainObject(target) && ['id', 'type', 'title', 'url'].every(field =>
          typeof target[field] === 'string');
      }

      function isDebuggerScript(script) {
        return isPlainObject(script) && typeof script.script_id === 'string' && script.script_id.length > 0 &&
          typeof script.url === 'string' && typeof script.hash === 'string' &&
          typeof script.source_map_url === 'string' && ['JavaScript', 'WebAssembly'].includes(script.language) &&
          ['start_line', 'start_column', 'end_line', 'end_column', 'execution_context_id', 'length']
            .every(field => isSafeIntegerInRange(script[field], 0, Number.MAX_SAFE_INTEGER)) &&
          typeof script.has_source_url === 'boolean' && typeof script.is_module === 'boolean';
      }

      function isDebuggerFrame(frame) {
        if (!isPlainObject(frame) || typeof frame.id !== 'string' || typeof frame.function_name !== 'string' ||
            typeof frame.url !== 'string' || !isDebuggerLocation(frame.location) ||
            (frame.function_location !== null && !isDebuggerLocation(frame.function_location)) ||
            !isDebuggerRemoteValue(frame.this) || !isDebuggerRemoteValue(frame.return_value) ||
            !Array.isArray(frame.scopes) || frame.scopes.length > 12) return false;
        return frame.scopes.every(scope => isPlainObject(scope) && typeof scope.type === 'string' &&
          typeof scope.name === 'string' && isDebuggerRemoteValue(scope.object) &&
          (scope.location === null || isDebuggerLocation(scope.location)) &&
          Array.isArray(scope.properties) && scope.properties.length <= 100 &&
          scope.properties.every(property => isPlainObject(property) && typeof property.name === 'string' &&
            isDebuggerRemoteValue(property.value) && isDebuggerRemoteValue(property.get) &&
            isDebuggerRemoteValue(property.set) && ['writable', 'enumerable', 'configurable']
              .every(field => typeof property[field] === 'boolean')));
      }

      function isDebuggerAsyncStack(stack) {
        return isPlainObject(stack) && typeof stack.description === 'string' &&
          Array.isArray(stack.call_frames) && stack.call_frames.length <= 64 &&
          stack.call_frames.every(frame => isPlainObject(frame) && typeof frame.function_name === 'string' &&
            typeof frame.url === 'string' && isDebuggerLocation(frame.location));
      }

      function isDebuggerBreakpoint(breakpoint) {
        return isPlainObject(breakpoint) && ['id', 'url', 'script_id', 'condition', 'expression']
          .every(field => typeof breakpoint[field] === 'string') &&
          ['line', 'conditional', 'logpoint'].includes(breakpoint.kind) &&
          isSafeIntegerInRange(breakpoint.line, 0, 0x7fffffff) &&
          isSafeIntegerInRange(breakpoint.column, 0, 0x7fffffff) &&
          Array.isArray(breakpoint.locations) && breakpoint.locations.length <= 256 &&
          breakpoint.locations.every(isDebuggerLocation) && typeof breakpoint.locations_truncated === 'boolean';
      }

      function isDebuggerWatch(watch) {
        return isPlainObject(watch) && typeof watch.id === 'string' && typeof watch.expression === 'string' &&
          isDebuggerRemoteValue(watch.result) && (watch.error === null || typeof watch.error === 'string');
      }

      function isDebuggerConsoleEntry(entry) {
        return isPlainObject(entry) && typeof entry.id === 'string' && typeof entry.type === 'string' &&
          (entry.timestamp === null || (typeof entry.timestamp === 'number' && Number.isFinite(entry.timestamp))) &&
          Array.isArray(entry.arguments) && entry.arguments.length <= 32 &&
          entry.arguments.every(value => value !== null && isDebuggerRemoteValue(value)) &&
          Array.isArray(entry.stack) && entry.stack.length <= 64 && entry.stack.every(frame =>
            isPlainObject(frame) && typeof frame.function_name === 'string' && typeof frame.url === 'string' &&
            isSafeIntegerInRange(frame.line, 0, 0x7fffffff) && isSafeIntegerInRange(frame.column, 0, 0x7fffffff));
      }

      function isMemoryOriginTraceStep(step) {
        if (!isPlainObject(step) || typeof step.id !== 'string' ||
            !isSafeIntegerInRange(step.step, 1, 32) ||
            !isSafeIntegerInRange(step.captured_at_ms, 1, Number.MAX_SAFE_INTEGER) ||
            !isSafeIntegerInRange(step.capture_bytes, 1, 256 * 1024 * 1024) ||
            !isSafeIntegerInRange(step.duration_ms, 0, Number.MAX_SAFE_INTEGER) ||
            !isSafeIntegerInRange(step.analyzed_nodes, 0, Number.MAX_SAFE_INTEGER) ||
            !isSafeIntegerInRange(step.total_nodes, 0, Number.MAX_SAFE_INTEGER) ||
            step.analyzed_nodes > step.total_nodes ||
            !isSafeIntegerInRange(step.indexed_edges, 0, Number.MAX_SAFE_INTEGER) ||
            !isSafeIntegerInRange(step.total_edges, 0, Number.MAX_SAFE_INTEGER) ||
            step.indexed_edges > step.total_edges ||
            typeof step.matched !== 'boolean' || typeof step.coverage_partial !== 'boolean' ||
            typeof step.is_first_match !== 'boolean' || !isPlainObject(step.location) ||
            typeof step.location.script_id !== 'string' || typeof step.location.url !== 'string' ||
            typeof step.location.function_name !== 'string' ||
            !isSafeIntegerInRange(step.location.line, 0, 0x7fffffff) ||
            !isSafeIntegerInRange(step.location.column, 0, 0x7fffffff) ||
            typeof step.location.framework_filtered !== 'boolean' ||
            step.matched !== (step.match !== null)) return false;
        if (step.match === null) return !step.is_first_match;
        return isPlainObject(step.match) && typeof step.match.id === 'string' &&
          /^(?:0|[1-9][0-9]*)$/.test(step.match.id) && step.match.id.length <= 20 &&
          typeof step.match.type === 'string' && typeof step.match.name === 'string' &&
          isSafeIntegerInRange(step.match.self_size, 0, Number.MAX_SAFE_INTEGER);
      }

      function isMemoryOriginTrace(trace) {
        const states = ['idle', 'armed', 'capturing', 'stepping', 'stopping', 'found', 'not_found', 'aborted', 'error'];
        const activeStates = ['armed', 'capturing', 'stepping', 'stopping'];
        if (!isPlainObject(trace) || trace.protocol_version !== 1 ||
            !isSafeIntegerInRange(trace.trace_id, 0, Number.MAX_SAFE_INTEGER) ||
            !states.includes(trace.state) ||
            (trace.target_id !== null && typeof trace.target_id !== 'string') ||
            typeof trace.query !== 'string' || !['all', 'reachable', 'unreachable'].includes(trace.scope) ||
            typeof trace.case_sensitive !== 'boolean' ||
            !isSafeIntegerInRange(trace.before_steps, 0, 8) ||
            !isSafeIntegerInRange(trace.after_steps, 0, 16) || trace.step_limit !== 32 ||
            !isSafeIntegerInRange(trace.step_count, 0, trace.step_limit) ||
            (trace.first_match_step !== null &&
              !isSafeIntegerInRange(trace.first_match_step, 1, trace.step_count)) ||
            !isSafeIntegerInRange(trace.started_at_ms, 0, Number.MAX_SAFE_INTEGER) ||
            !isSafeIntegerInRange(trace.elapsed_ms, 0, Number.MAX_SAFE_INTEGER) ||
            typeof trace.partial !== 'boolean' ||
            (trace.limit_reason !== null &&
              !['snapshot_coverage', 'step_limit', 'time_limit', 'execution_quiet'].includes(trace.limit_reason)) ||
            typeof trace.message !== 'string' || !Array.isArray(trace.steps) ||
            trace.steps.length > trace.before_steps + trace.after_steps + 1 ||
            !trace.steps.every(isMemoryOriginTraceStep)) return false;
        if (trace.steps.some((step, index) => index > 0 && trace.steps[index - 1].step >= step.step)) return false;
        const firstMatches = trace.steps.filter(step => step.is_first_match);
        if ((trace.first_match_step === null) !== (firstMatches.length === 0) || firstMatches.length > 1 ||
            (firstMatches.length === 1 && firstMatches[0].step !== trace.first_match_step) ||
            (trace.state === 'found' && trace.first_match_step === null) ||
            (trace.state === 'not_found' && trace.first_match_step !== null) ||
            (trace.steps.some(step => step.coverage_partial) && !trace.partial)) return false;
        if (trace.state === 'idle') {
          return trace.trace_id === 0 && trace.target_id === null && trace.query === '' &&
            trace.step_count === 0 && trace.steps.length === 0 && trace.started_at_ms === 0;
        }
        return typeof trace.target_id === 'string' && trace.target_id.length > 0 &&
          trace.trace_id > 0 && trace.query.length > 0 && trace.started_at_ms > 0 &&
          (!activeStates.includes(trace.state) || trace.limit_reason === null || trace.partial);
      }

      function isActionScope(scope) {
        const states = ['idle', 'discovering', 'ready', 'partial', 'disposed', 'error'];
        if (!isPlainObject(scope) || scope.protocol_version !== 1 || !states.includes(scope.state) ||
            !['global', 'target'].includes(scope.mode) ||
            (scope.target_id !== null && !isBoundedText(scope.target_id, 4 * 1024)) ||
            !isSafeIntegerInRange(scope.revision, 0, Number.MAX_SAFE_INTEGER) ||
            !Array.isArray(scope.targets) || scope.targets.length > 8 ||
            !isSafeIntegerInRange(scope.matched_target_count, 0, 8) ||
            !isSafeIntegerInRange(scope.connected_target_count, 0, 8) ||
            scope.connected_target_count > scope.matched_target_count ||
            !isSafeIntegerInRange(scope.target_overflow, 0, Number.MAX_SAFE_INTEGER) ||
            !isBoundedText(scope.message, 512) ||
            !Array.isArray(scope.rule_families) ||
            scope.rule_families.join(',') !== 'request_interception,automation_recipes' ||
            !Array.isArray(scope.target_only_families) ||
            scope.target_only_families.join(',') !== 'object_experiment,runtime_hooks,repeater' ||
            !isPlainObject(scope.limits) || scope.limits.targets !== 8 ||
            scope.limits.pending_triggers !== 16) return false;
        const ids = new Set();
        if (!scope.targets.every(target => {
          if (!isPlainObject(target) || !isBoundedText(target.id, 4 * 1024) ||
              !['page', 'webview'].includes(target.type) || !isBoundedText(target.title, 512) ||
              !isBoundedText(target.url, 8 * 1024) || typeof target.connected !== 'boolean' ||
              typeof target.matched !== 'boolean' || ids.has(target.id)) return false;
          ids.add(target.id);
          return target.matched === (scope.mode === 'global' || target.id === scope.target_id);
        })) return false;
        if (scope.targets.filter(target => target.matched).length !== scope.matched_target_count ||
            scope.targets.filter(target => target.matched && target.connected).length !== scope.connected_target_count) return false;
        if (scope.mode === 'global') return scope.target_id === null;
        return typeof scope.target_id === 'string' && scope.target_id.length > 0;
      }

      function isRequestInterceptionRule(rule) {
        return isPlainObject(rule) && ['continue', 'block', 'drop', 'rewrite', 'fulfill'].includes(rule.mode) &&
          isBoundedText(rule.url_pattern, 2 * 1024) && isBoundedText(rule.method_filter, 32) &&
          isBoundedText(rule.rewrite_url, 8 * 1024) && isBoundedText(rule.rewrite_method, 32) &&
          isSafeIntegerInRange(rule.rewrite_header_count, 0, 64) &&
          isSafeIntegerInRange(rule.rewrite_body_bytes, 0, 64 * 1024) &&
          isSafeIntegerInRange(rule.response_code, 100, 599) &&
          isSafeIntegerInRange(rule.response_header_count, 0, 64) &&
          isSafeIntegerInRange(rule.response_body_bytes, 0, 64 * 1024);
      }

      function isRequestInterceptionResult(result) {
        if (result === null) return true;
        if (!isPlainObject(result) || result.protocol_version !== 1 || typeof result.ok !== 'boolean' ||
            !isSafeIntegerInRange(result.status, 0, 599) || !isBoundedText(result.status_text, 256) ||
            !isBoundedText(result.url, 8 * 1024) || !Array.isArray(result.headers) || result.headers.length > 64 ||
            typeof result.headers_truncated !== 'boolean' ||
            !isBoundedText(result.body, 64 * 1024) || typeof result.body_truncated !== 'boolean' ||
            (result.error !== null && !isBoundedText(result.error, 512))) return false;
        let headerBytes = 0;
        if (!result.headers.every(header => {
          if (!isPlainObject(header) || !isBoundedText(header.name, 128) || !isBoundedText(header.value, 2 * 1024) ||
              ['authorization', 'cookie', 'proxy-authorization', 'set-cookie'].includes(header.name.toLowerCase())) return false;
          headerBytes += utf8ByteLength(header.name) + utf8ByteLength(header.value);
          return headerBytes <= 16 * 1024;
        })) return false;
        return result.ok ? result.status > 0 && result.error === null
          : result.status === 0 && typeof result.error === 'string';
      }

      function isRequestInterception(experiment) {
        const states = ['idle', 'creating', 'ready', 'running', 'disposing', 'disposed', 'error'];
        if (!isPlainObject(experiment) || experiment.protocol_version !== 1 ||
            !isSafeIntegerInRange(experiment.experiment_id, 0, Number.MAX_SAFE_INTEGER) ||
            !states.includes(experiment.state) || typeof experiment.isolated !== 'boolean' ||
            (experiment.target_id !== null && !isBoundedText(experiment.target_id, 4 * 1024)) ||
            !isSafeIntegerInRange(experiment.created_at_ms, 0, Number.MAX_SAFE_INTEGER) ||
            !isSafeIntegerInRange(experiment.disposed_at_ms, 0, Number.MAX_SAFE_INTEGER) ||
            !isRequestInterceptionRule(experiment.rule) ||
            (experiment.last_request !== null && (!isPlainObject(experiment.last_request) ||
              (experiment.last_request.target_id !== undefined && !isBoundedText(experiment.last_request.target_id, 4 * 1024)) ||
              !isBoundedText(experiment.last_request.url, 8 * 1024) || !isBoundedText(experiment.last_request.method, 32) ||
              !isSafeIntegerInRange(experiment.last_request.header_count, 0, 64) ||
              !isSafeIntegerInRange(experiment.last_request.body_bytes, 0, 64 * 1024))) ||
            !isRequestInterceptionResult(experiment.result) || !Array.isArray(experiment.audit) ||
            experiment.audit.length > 128 || !isSafeIntegerInRange(experiment.audit_evictions, 0, Number.MAX_SAFE_INTEGER) ||
            !isSafeIntegerInRange(experiment.pending_requests, 0, 16) || !isBoundedText(experiment.message, 512) ||
            !isPlainObject(experiment.limits) || experiment.limits.audit_entries !== 128 ||
            experiment.limits.pending_requests !== 16 || experiment.limits.headers !== 64 ||
            experiment.limits.body_bytes !== 64 * 1024 || experiment.limits.response_bytes !== 64 * 1024) return false;
        if (!experiment.audit.every(entry => isPlainObject(entry) &&
            isSafeIntegerInRange(entry.id, 1, Number.MAX_SAFE_INTEGER) &&
            isSafeIntegerInRange(entry.occurred_at_ms, 1, Number.MAX_SAFE_INTEGER) &&
            isBoundedText(entry.request_id, 256) &&
            (entry.target_id === undefined || isBoundedText(entry.target_id, 4 * 1024)) && isBoundedText(entry.method, 32) &&
            isBoundedText(entry.url, 8 * 1024) && isBoundedText(entry.resource_type, 128) &&
            isBoundedText(entry.detail, 512) &&
            ['continue', 'block', 'drop', 'rewrite', 'fulfill'].includes(entry.rule_mode) &&
            ['continued', 'bypassed', 'blocked', 'dropped', 'rewritten', 'fulfilled', 'overflow_continue', 'error']
              .includes(entry.outcome))) return false;
        if (experiment.audit.some((entry, index) => index > 0 && experiment.audit[index - 1].id >= entry.id)) return false;
        if (experiment.state === 'idle') {
          return experiment.experiment_id === 0 && !experiment.isolated && experiment.target_id === null &&
            experiment.created_at_ms === 0 && experiment.disposed_at_ms === 0 && experiment.audit.length === 0;
        }
        if (experiment.state === 'disposed') {
          return experiment.experiment_id > 0 && !experiment.isolated && experiment.target_id === null &&
            experiment.created_at_ms > 0 && experiment.disposed_at_ms >= experiment.created_at_ms &&
            experiment.pending_requests === 0;
        }
        return experiment.experiment_id > 0 && experiment.created_at_ms > 0 &&
          (experiment.state === 'creating' || experiment.state === 'error' ||
            (experiment.isolated && typeof experiment.target_id === 'string' && experiment.target_id.length > 0));
      }

      function isLiveObjectResultRecord(result) {
        return isPlainObject(result) && isBoundedText(result.id, 128) &&
          isBoundedText(result.class_name, 256) &&
          isSafeIntegerInRange(result.property_count, 0, 0x7fffffff) &&
          typeof result.properties_truncated === 'boolean' &&
          (result.similarity === null || (typeof result.similarity === 'number' &&
            Number.isFinite(result.similarity) && result.similarity >= 0 && result.similarity <= 1)) &&
          Array.isArray(result.preview) && result.preview.length <= 16 &&
          result.preview.every(property => isPlainObject(property) &&
            isBoundedText(property.name, 4096) && isBoundedText(property.type, 128) &&
            isBoundedText(property.value, 4096));
      }

      function isLiveObjectSearchMetadata(search) {
        return isPlainObject(search) && search.protocol_version === 2 &&
          ['analyzed', 'total_objects', 'result_limit', 'duration_ms'].every(field =>
            isSafeIntegerInRange(search[field], 0, Number.MAX_SAFE_INTEGER)) &&
          search.result_limit === 50 &&
          ['result_limit_reached', 'scan_limit_reached', 'property_limit_reached', 'timed_out'].every(field =>
            typeof search[field] === 'boolean');
      }

      function isObjectExperimentDescriptor(descriptor) {
        return isPlainObject(descriptor) && typeof descriptor.exists === 'boolean' &&
          isBoundedText(descriptor.type, 128) && isBoundedText(descriptor.class_name, 256) &&
          typeof descriptor.writable === 'boolean' && typeof descriptor.configurable === 'boolean' &&
          (descriptor.preview === null || isBoundedText(descriptor.preview, 512));
      }

      function isObjectExperiment(experiment) {
        const states = ['idle', 'attaching', 'ready', 'navigating', 'loaded', 'searching', 'mutating',
          'disposing', 'disposed', 'error'];
        const outcomes = ['created', 'updated', 'deleted', 'missing', 'non_configurable', 'rejected',
          'accessor', 'non_writable', 'non_extensible', 'error'];
        if (!isPlainObject(experiment) || experiment.protocol_version !== 1 ||
            !isSafeIntegerInRange(experiment.session_id, 0, Number.MAX_SAFE_INTEGER) ||
            !states.includes(experiment.state) || typeof experiment.isolated !== 'boolean' ||
            (experiment.target_id !== null && !isBoundedText(experiment.target_id, 4 * 1024)) ||
            !isBoundedText(experiment.url, 8 * 1024) || experiment.url.includes('?') || experiment.url.includes('#') ||
            !isSafeIntegerInRange(experiment.navigation_id, 0, Number.MAX_SAFE_INTEGER) ||
            !isSafeIntegerInRange(experiment.search_id, 0, Number.MAX_SAFE_INTEGER) ||
            (experiment.search !== null && !isLiveObjectSearchMetadata(experiment.search)) ||
            !Array.isArray(experiment.results) || experiment.results.length > 50 ||
            !experiment.results.every(isLiveObjectResultRecord) ||
            !Array.isArray(experiment.audit) || experiment.audit.length > 128 ||
            !isSafeIntegerInRange(experiment.audit_evictions, 0, Number.MAX_SAFE_INTEGER) ||
            !isSafeIntegerInRange(experiment.mutation_attempts, 0, 256) ||
            !isBoundedText(experiment.message, 512) || !isPlainObject(experiment.limits)) return false;
        const limits = {search_results: 50, search_candidates: 25000, search_timeout_ms: 750,
          preview_properties: 16, mutation_attempts: 256, audit_entries: 128, property_bytes: 256,
          value_bytes: 16 * 1024, value_depth: 8, value_entries: 256, value_string_bytes: 4 * 1024};
        if (Object.keys(limits).some(key => experiment.limits[key] !== limits[key])) return false;
        if ((experiment.search === null) !== (experiment.search_id === 0) ||
            (experiment.search === null && experiment.results.length > 0)) return false;
        const last = experiment.last_mutation;
        if (last !== null && (!isPlainObject(last) ||
            !isSafeIntegerInRange(last.audit_id, 1, Number.MAX_SAFE_INTEGER) || typeof last.ok !== 'boolean' ||
            !['set', 'delete'].includes(last.operation) || !isBoundedText(last.property, 256) ||
            !isBoundedText(last.result_id, 128) || !outcomes.includes(last.outcome) ||
            (last.error !== null && !isBoundedText(last.error, 512)) ||
            last.ok !== (last.error === null) || !isObjectExperimentDescriptor(last.before) ||
            !isObjectExperimentDescriptor(last.after) || !isSafeIntegerInRange(last.value_bytes, 0, 16 * 1024) ||
            (last.value_digest !== null && (typeof last.value_digest !== 'string' ||
              !/^[0-9a-f]{64}$/.test(last.value_digest))))) return false;
        if (!experiment.audit.every(entry => isPlainObject(entry) &&
            isSafeIntegerInRange(entry.id, 1, Number.MAX_SAFE_INTEGER) &&
            isSafeIntegerInRange(entry.occurred_at_ms, 1, Number.MAX_SAFE_INTEGER) &&
            isSafeIntegerInRange(entry.session_id, 1, Number.MAX_SAFE_INTEGER) &&
            isSafeIntegerInRange(entry.navigation_id, 1, Number.MAX_SAFE_INTEGER) &&
            isSafeIntegerInRange(entry.search_id, 1, Number.MAX_SAFE_INTEGER) &&
            isBoundedText(entry.result_id, 128) && ['set', 'delete'].includes(entry.operation) &&
            isBoundedText(entry.property, 256) && isBoundedText(entry.target_class, 256) &&
            outcomes.includes(entry.outcome) && typeof entry.success === 'boolean' &&
            isBoundedText(entry.before_type, 128) && isBoundedText(entry.after_type, 128) &&
            isSafeIntegerInRange(entry.value_bytes, 0, 16 * 1024) &&
            (entry.value_digest === null || (typeof entry.value_digest === 'string' &&
              /^[0-9a-f]{64}$/.test(entry.value_digest))) && isBoundedText(entry.url, 8 * 1024) &&
            !entry.url.includes('?') && !entry.url.includes('#'))) return false;
        if (experiment.audit.some((entry, index) => index > 0 && experiment.audit[index - 1].id >= entry.id)) return false;
        if (experiment.state === 'idle') return experiment.session_id === 0 && !experiment.isolated &&
          experiment.target_id === null && experiment.navigation_id === 0 && experiment.search_id === 0 &&
          experiment.audit.length === 0 && experiment.mutation_attempts === 0;
        if (experiment.state === 'disposed') return experiment.session_id > 0 && !experiment.isolated &&
          experiment.target_id === null && experiment.url === '' && experiment.navigation_id === 0 &&
          experiment.search_id === 0 && experiment.results.length === 0 && experiment.audit.length === 0;
        return experiment.session_id > 0 && (experiment.state === 'attaching' || experiment.state === 'error' ||
          (experiment.isolated && typeof experiment.target_id === 'string' && experiment.target_id.length > 0));
      }

      function isRuntimeHookRemote(value) {
        return value === null || (isPlainObject(value) && isBoundedText(value.type, 256) &&
          (value.subtype === null || isBoundedText(value.subtype, 256)) &&
          (value.class_name === null || isBoundedText(value.class_name, 512)) &&
          (value.description === null || isBoundedText(value.description, 512)) &&
          (value.unserializable_value === null || isBoundedText(value.unserializable_value, 512)) &&
          (value.value === null || typeof value.value === 'string' || typeof value.value === 'boolean' ||
            (typeof value.value === 'number' && Number.isFinite(value.value))) &&
          typeof value.value_truncated === 'boolean');
      }

      function isRuntimeHookDefinition(definition) {
        if (!isPlainObject(definition) || !isSafeIntegerInRange(definition.id, 1, Number.MAX_SAFE_INTEGER) ||
            !isBoundedText(definition.label, 128) || !isBoundedText(definition.script_id, 4 * 1024) ||
            !isBoundedText(definition.url, 64 * 1024) ||
            !isSafeIntegerInRange(definition.line, 0, 0x7fffffff) ||
            !isSafeIntegerInRange(definition.column, 0, 0x7fffffff) ||
            typeof definition.entry_enabled !== 'boolean' || typeof definition.return_enabled !== 'boolean' ||
            (!definition.entry_enabled && !definition.return_enabled) ||
            !isBoundedText(definition.condition, 1024) || !isBoundedText(definition.entry_logic, 8 * 1024) ||
            !isBoundedText(definition.return_logic, 8 * 1024) ||
            !['none', 'json', 'expression'].includes(definition.return_mode) ||
            !isBoundedText(definition.return_expression, 8 * 1024) ||
            !isSafeIntegerInRange(definition.return_value_bytes, 0, 8 * 1024)) return false;
        if (definition.return_mode === 'none' &&
            (definition.return_expression !== '' || definition.return_value !== null || definition.return_value_bytes !== 0)) return false;
        if (definition.return_mode === 'expression' &&
            (!definition.return_expression || definition.return_value !== null || definition.return_value_bytes !== 0)) return false;
        if (definition.return_mode === 'json') {
          try {
            if (utf8ByteLength(JSON.stringify(definition.return_value)) > 8 * 1024) return false;
          } catch { return false; }
        }
        return definition.resolved === null || (isPlainObject(definition.resolved) &&
          isSafeIntegerInRange(definition.resolved.entry_points, 0, 1) &&
          isSafeIntegerInRange(definition.resolved.return_points, 0, 32));
      }

      function isRuntimeHooks(hooks) {
        const states = ['idle', 'attaching', 'ready', 'arming', 'armed', 'handling', 'stopping',
          'disarmed', 'disposing', 'disposed', 'error'];
        if (!isPlainObject(hooks) || hooks.protocol_version !== 1 ||
            !isSafeIntegerInRange(hooks.session_id, 0, Number.MAX_SAFE_INTEGER) || !states.includes(hooks.state) ||
            typeof hooks.isolated !== 'boolean' ||
            (hooks.target_id !== null && !isBoundedText(hooks.target_id, 4 * 1024)) ||
            !Array.isArray(hooks.definitions) || hooks.definitions.length > 8 ||
            !hooks.definitions.every(isRuntimeHookDefinition) ||
            !isSafeIntegerInRange(hooks.active_points, 0, 64) ||
            !isSafeIntegerInRange(hooks.total_hits, 0, 512) ||
            !Array.isArray(hooks.hits) || hooks.hits.length > 128 || hooks.hits.length > hooks.total_hits ||
            !isSafeIntegerInRange(hooks.hit_evictions, 0, Number.MAX_SAFE_INTEGER) ||
            (hooks.last_failure !== null && !isBoundedText(hooks.last_failure, 512)) ||
            !isBoundedText(hooks.message, 512) || !isPlainObject(hooks.limits)) return false;
        const limits = {definitions: 8, active_points: 64, return_points_per_definition: 32,
          total_hits: 512, retained_hits: 128, bindings_per_hit: 32, binding_preview_bytes: 512,
          condition_bytes: 1024, logic_bytes: 8 * 1024, return_bytes: 8 * 1024,
          evaluation_timeout_ms: 100};
        if (Object.keys(limits).some(key => hooks.limits[key] !== limits[key])) return false;
        const definitionIds = new Set(hooks.definitions.map(definition => definition.id));
        if (definitionIds.size !== hooks.definitions.length) return false;
        if (!hooks.hits.every(hit => isPlainObject(hit) &&
            isSafeIntegerInRange(hit.id, 1, Number.MAX_SAFE_INTEGER) &&
            isSafeIntegerInRange(hit.occurred_at_ms, 1, Number.MAX_SAFE_INTEGER) &&
            isSafeIntegerInRange(hit.session_id, 1, Number.MAX_SAFE_INTEGER) &&
            isSafeIntegerInRange(hit.hook_id, 1, Number.MAX_SAFE_INTEGER) &&
            isBoundedText(hit.target_id, 4 * 1024) && isBoundedText(hit.label, 128) &&
            isBoundedText(hit.source, 8 * 1024) && isBoundedText(hit.function, 256) &&
            ['entry', 'return'].includes(hit.category) &&
            ['observed', 'skipped', 'logic_run', 'return_overridden', 'failed'].includes(hit.operation) &&
            isSafeIntegerInRange(hit.line, 0, 0x7fffffff) && isSafeIntegerInRange(hit.column, 0, 0x7fffffff) &&
            Array.isArray(hit.bindings) && hit.bindings.length <= 32 &&
            hit.bindings.every(binding => isPlainObject(binding) && isBoundedText(binding.name, 256) &&
              typeof binding.accessor === 'boolean' && isRuntimeHookRemote(binding.value)) &&
            typeof hit.bindings_truncated === 'boolean' && isRuntimeHookRemote(hit.original_return) &&
            isRuntimeHookRemote(hit.replacement_return) &&
            (hit.error === null || isBoundedText(hit.error, 512)))) return false;
        if (hooks.hits.some((hit, index) => index > 0 && hooks.hits[index - 1].id >= hit.id)) return false;
        if (hooks.state === 'idle') return hooks.session_id === 0 && !hooks.isolated && hooks.target_id === null &&
          hooks.definitions.length === 0 && hooks.hits.length === 0;
        if (hooks.state === 'disposed') return hooks.session_id > 0 && !hooks.isolated && hooks.target_id === null &&
          hooks.definitions.length === 0 && hooks.hits.length === 0 && hooks.active_points === 0;
        return hooks.session_id > 0 && (hooks.state === 'attaching' || hooks.state === 'error' ||
          (hooks.isolated && typeof hooks.target_id === 'string' && hooks.target_id.length > 0));
      }

      function isAutomationRecipes(automation) {
        const states = ['idle', 'attaching', 'ready', 'arming', 'armed', 'running', 'stopping',
          'disposing', 'disposed', 'error'];
        const triggers = ['manual', 'created', 'before-load', 'after-load'];
        const outcomes = ['completed', 'failed', 'cancelled', 'timed_out'];
        if (!isPlainObject(automation) || 'variables' in automation || automation.protocol_version !== 1 ||
            !isSafeIntegerInRange(automation.session_id, 0, Number.MAX_SAFE_INTEGER) ||
            !states.includes(automation.state) || typeof automation.isolated !== 'boolean' ||
            (automation.target_id !== null && !isBoundedText(automation.target_id, 4 * 1024)) ||
            !Array.isArray(automation.recipes) || automation.recipes.length > 16 ||
            !isSafeIntegerInRange(automation.source_bytes, 0, 64 * 1024) ||
            typeof automation.auto_armed !== 'boolean' ||
            !isSafeIntegerInRange(automation.total_runs, 0, 256) ||
            !isSafeIntegerInRange(automation.automatic_runs, 0, 64) ||
            automation.automatic_runs > automation.total_runs ||
            !Array.isArray(automation.runs) || automation.runs.length > 64 ||
            automation.runs.length > automation.total_runs ||
            !isSafeIntegerInRange(automation.run_evictions, 0, Number.MAX_SAFE_INTEGER) ||
            !isSafeIntegerInRange(automation.dropped_triggers, 0, Number.MAX_SAFE_INTEGER) ||
            !isSafeIntegerInRange(automation.variable_count, 0, 32) ||
            !isSafeIntegerInRange(automation.variable_bytes, 0, 16 * 1024) ||
            (automation.last_failure !== null && !isBoundedText(automation.last_failure, 512)) ||
            !isBoundedText(automation.message, 512) || !isPlainObject(automation.limits)) return false;
        const limits = {recipes: 16, automatic_recipes: 8, recipe_source_bytes: 16 * 1024,
          total_source_bytes: 64 * 1024, variables: 32, variable_value_bytes: 4 * 1024,
          variable_bytes: 16 * 1024, total_runs: 256, automatic_runs: 64,
          retained_runs: 64, logs_per_run: 32, log_bytes: 1024,
          result_bytes: 16 * 1024, execution_timeout_ms: 2000};
        if (Object.keys(limits).some(key => automation.limits[key] !== limits[key])) return false;
        const recipeIds = new Set();
        let sourceBytes = 0;
        for (const recipe of automation.recipes) {
          if (!isPlainObject(recipe) || !isSafeIntegerInRange(recipe.id, 1, Number.MAX_SAFE_INTEGER) ||
              recipeIds.has(recipe.id) || !isBoundedText(recipe.label, 128) || !recipe.label ||
              !triggers.includes(recipe.trigger) || typeof recipe.enabled !== 'boolean' ||
              !isBoundedText(recipe.source, 16 * 1024) || !recipe.source.trim() ||
              !isSafeIntegerInRange(recipe.source_bytes, 1, 16 * 1024) ||
              utf8ByteLength(recipe.source) !== recipe.source_bytes) return false;
          recipeIds.add(recipe.id);
          sourceBytes += recipe.source_bytes;
        }
        if (sourceBytes !== automation.source_bytes) return false;
        const active = automation.active_run;
        if (active !== null && (!isPlainObject(active) ||
            !isSafeIntegerInRange(active.id, 1, Number.MAX_SAFE_INTEGER) ||
            !isSafeIntegerInRange(active.recipe_id, 1, Number.MAX_SAFE_INTEGER) ||
            !isBoundedText(active.label, 128) || !triggers.includes(active.trigger) ||
            !isBoundedText(active.source, 8 * 1024) ||
            !isSafeIntegerInRange(active.started_at_ms, 1, Number.MAX_SAFE_INTEGER) ||
            typeof active.cancel_requested !== 'boolean')) return false;
        let previousRunId = 0;
        for (const run of automation.runs) {
          if (!isPlainObject(run) || !isSafeIntegerInRange(run.id, 1, Number.MAX_SAFE_INTEGER) ||
              run.id <= previousRunId || !isSafeIntegerInRange(run.session_id, 1, Number.MAX_SAFE_INTEGER) ||
              !isSafeIntegerInRange(run.recipe_id, 1, Number.MAX_SAFE_INTEGER) ||
              !isBoundedText(run.label, 128) ||
              !isSafeIntegerInRange(run.occurred_at_ms, 1, Number.MAX_SAFE_INTEGER) ||
              !isBoundedText(run.source, 8 * 1024) || !triggers.includes(run.category) ||
              !outcomes.includes(run.operation) ||
              !isSafeIntegerInRange(run.duration_ms, 0, 60 * 1000) ||
              !isBoundedText(run.target_id, 4 * 1024) || !isBoundedText(run.result_type, 64) ||
              !isBoundedText(run.result_text, 16 * 1024) || typeof run.result_truncated !== 'boolean' ||
              !Array.isArray(run.logs) || run.logs.length > 32 ||
              !run.logs.every(log => isPlainObject(log) && ['log', 'info', 'warn', 'error'].includes(log.level) &&
                isBoundedText(log.text, 1024)) || typeof run.logs_truncated !== 'boolean' ||
              !isBoundedText(run.error, 512)) return false;
          previousRunId = run.id;
        }
        if (['running', 'stopping'].includes(automation.state) && active === null && !automation.auto_armed) return false;
        if (automation.state === 'idle') return automation.session_id === 0 && !automation.isolated && automation.target_id === null &&
          automation.runs.length === 0 && active === null && !automation.auto_armed;
        if (automation.state === 'disposed') return automation.session_id > 0 && !automation.isolated && automation.target_id === null &&
          automation.runs.length === 0 && active === null && !automation.auto_armed && automation.variable_count === 0;
        return automation.session_id > 0 && (automation.state === 'attaching' || automation.state === 'error' ||
          (automation.isolated && typeof automation.target_id === 'string' && automation.target_id.length > 0));
      }

      function isRepeaterRequest(request, resolved = false) {
        if (!isPlainObject(request) || !isBoundedText(request.url, 8 * 1024) ||
            !isBoundedText(request.method, resolved ? 32 : 256) ||
            !Array.isArray(request.headers) || request.headers.length > 64 ||
            !isBoundedText(request.body, 64 * 1024) ||
            !isSafeIntegerInRange(request.timeout_ms, 100, 30000)) return false;
        let headerBytes = 0;
        const token = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
        const forbidden = new Set(['authorization', 'cookie', 'proxy-authorization', 'set-cookie',
          'connection', 'content-length', 'host', 'transfer-encoding']);
        if (!request.headers.every(header => {
          if (!isPlainObject(header) || !isBoundedText(header.name, 128) ||
              !isBoundedText(header.value, 2 * 1024) || !token.test(header.name) ||
              forbidden.has(header.name.toLowerCase())) return false;
          headerBytes += utf8ByteLength(header.name) + utf8ByteLength(header.value);
          return headerBytes <= 16 * 1024;
        })) return false;
        if (!resolved) return request.url.length > 0 && request.method.length > 0;
        if (!/^[A-Z][!#$%&'*+.^_`|~0-9A-Z-]{0,31}$/.test(request.method)) return false;
        try {
          const url = new URL(request.url);
          return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password && !url.hash &&
            (!['GET', 'HEAD'].includes(request.method) || request.body === '');
        } catch { return false; }
      }

      function isApiCollection(collection) {
        const exactKeys = (value, keys) => isPlainObject(value) &&
          Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
        const validName = value => isBoundedText(value, 128) && value.trim() === value &&
          value.length > 0 && !value.includes('/') && !/[\x00-\x1f\x7f]/u.test(value);
        const validVariables = value => {
          if (!Array.isArray(value) || value.length > 32) return false;
          let bytes = 0;
          const names = new Set();
          return value.every(variable => {
            if (!exactKeys(variable, ['name', 'value']) || !isBoundedText(variable.name, 64) ||
                !/^[A-Za-z_][A-Za-z0-9_.-]*$/u.test(variable.name) || names.has(variable.name) ||
                !isBoundedText(variable.value, 4 * 1024) || /[\x00-\x1f\x7f]/u.test(variable.value)) return false;
            names.add(variable.name);
            bytes += utf8ByteLength(variable.name) + utf8ByteLength(variable.value);
            return bytes <= 32 * 1024;
          });
        };
        const limits = {
          folders: 32, requests: 128, folder_depth: 4, variables_per_scope: 32,
          variable_bytes_per_scope: 32 * 1024, request_body_bytes: 64 * 1024,
          document_bytes: 2 * 1024 * 1024
        };
        if (!exactKeys(collection, ['contract_version', 'document_kind', 'generation', 'updated_at_ms',
          'folders', 'requests', 'limits']) || collection.contract_version !== 1 ||
          collection.document_kind !== 'api-collection' ||
          !isSafeIntegerInRange(collection.generation, 0, Number.MAX_SAFE_INTEGER) ||
          !isSafeIntegerInRange(collection.updated_at_ms, 0, Number.MAX_SAFE_INTEGER) ||
          !isPlainObject(collection.limits) || Object.keys(collection.limits).length !== Object.keys(limits).length ||
          Object.entries(limits).some(([name, limit]) => collection.limits[name] !== limit) ||
          !Array.isArray(collection.folders) || collection.folders.length < 1 || collection.folders.length > 32 ||
          !Array.isArray(collection.requests) || collection.requests.length > 128 ||
          utf8ByteLength(JSON.stringify(collection)) > 2 * 1024 * 1024) return false;
        const folderIds = new Set();
        const folderNames = new Set();
        const folders = new Map();
        for (const folder of collection.folders) {
          if (!exactKeys(folder, ['id', 'name', 'parent_id', 'variables']) ||
              !isSafeIntegerInRange(folder.id, 1, Number.MAX_SAFE_INTEGER) || folderIds.has(folder.id) ||
              !validName(folder.name) || (folder.parent_id !== null &&
                !isSafeIntegerInRange(folder.parent_id, 1, Number.MAX_SAFE_INTEGER)) ||
              !validVariables(folder.variables)) return false;
          folderIds.add(folder.id); folders.set(folder.id, folder);
        }
        const root = folders.get(1);
        if (!root || root.name !== 'API Collection' || root.parent_id !== null ||
            collection.folders.some(folder => folder.id !== 1 && folder.parent_id === null)) return false;
        for (const folder of collection.folders) {
          const siblingKey = `${folder.parent_id ?? 'root'}\u0000${folder.name.toLocaleLowerCase()}`;
          if (folderNames.has(siblingKey)) return false;
          folderNames.add(siblingKey);
          let current = folder;
          const seen = new Set([current.id]);
          let depth = 0;
          while (current.parent_id !== null) {
            if (seen.has(current.parent_id) || !folders.has(current.parent_id) || ++depth > 4) return false;
            seen.add(current.parent_id); current = folders.get(current.parent_id);
          }
        }
        const requestIds = new Set();
        const requestNames = new Set();
        for (const request of collection.requests) {
          if (!exactKeys(request, ['id', 'folder_id', 'name', 'url', 'method', 'headers', 'body',
            'timeout_ms', 'variables', 'created_at_ms', 'updated_at_ms']) ||
              !isSafeIntegerInRange(request.id, 1, Number.MAX_SAFE_INTEGER) || requestIds.has(request.id) ||
              !folderIds.has(request.folder_id) || !validName(request.name) || !isRepeaterRequest(request) ||
              /[\x00-\x1f\x7f]/u.test(request.url) || /[\x00-\x1f\x7f]/u.test(request.method) ||
              !validVariables(request.variables) ||
              !isSafeIntegerInRange(request.created_at_ms, 0, Number.MAX_SAFE_INTEGER) ||
              !isSafeIntegerInRange(request.updated_at_ms, request.created_at_ms, Number.MAX_SAFE_INTEGER)) return false;
          const nameKey = `${request.folder_id}\u0000${request.name.toLocaleLowerCase()}`;
          if (requestNames.has(nameKey)) return false;
          requestNames.add(nameKey); requestIds.add(request.id);
        }
        if (collection.generation === 0) {
          return collection.updated_at_ms === 0 && collection.folders.length === 1 &&
            root.variables.length === 0 && collection.requests.length === 0;
        }
        return collection.updated_at_ms > 0;
      }

      function isRepeaterResult(result) {
        return isRequestInterceptionResult(result) && result !== null &&
          isSafeIntegerInRange(result.duration_ms, 0, 35000) &&
          typeof result.cancelled === 'boolean' && typeof result.timed_out === 'boolean' &&
          !(result.cancelled && result.timed_out) &&
          (!result.ok || !result.cancelled && !result.timed_out) &&
          typeof result.body_sha256 === 'string' && /^[0-9a-f]{64}$/.test(result.body_sha256);
      }

      function isRepeaterHistoryEntry(entry) {
        return isPlainObject(entry) && isSafeIntegerInRange(entry.id, 1, Number.MAX_SAFE_INTEGER) &&
          (entry.collection_request_id === null ||
            isSafeIntegerInRange(entry.collection_request_id, 1, Number.MAX_SAFE_INTEGER)) &&
          isSafeIntegerInRange(entry.started_at_ms, 1, Number.MAX_SAFE_INTEGER) &&
          isSafeIntegerInRange(entry.completed_at_ms, entry.started_at_ms, Number.MAX_SAFE_INTEGER) &&
          ['complete', 'error', 'cancelled', 'timed_out'].includes(entry.state) &&
          Array.isArray(entry.variable_names) && entry.variable_names.length <= 32 &&
          entry.variable_names.every(name => isBoundedText(name, 64) && /^[A-Za-z_][A-Za-z0-9_.-]*$/.test(name)) &&
          new Set(entry.variable_names).size === entry.variable_names.length &&
          isRepeaterRequest(entry.request) && isRepeaterRequest(entry.resolved_request, true) &&
          isRepeaterResult(entry.response) &&
          isSafeIntegerInRange(entry.stored_bytes, 1, 512 * 1024) &&
          (entry.state === 'complete') === entry.response.ok &&
          (entry.state === 'cancelled') === entry.response.cancelled &&
          (entry.state === 'timed_out') === entry.response.timed_out;
      }

      function isRepeaterComparison(comparison, retainedIds) {
        if (comparison === null) return true;
        const headerList = value => Array.isArray(value) && value.length <= 64 &&
          value.every(name => isBoundedText(name, 128) && name === name.toLowerCase());
        return isPlainObject(comparison) && comparison.protocol_version === 1 &&
          isSafeIntegerInRange(comparison.baseline_id, 1, Number.MAX_SAFE_INTEGER) &&
          isSafeIntegerInRange(comparison.current_id, 1, Number.MAX_SAFE_INTEGER) &&
          comparison.baseline_id !== comparison.current_id && retainedIds.has(comparison.baseline_id) &&
          retainedIds.has(comparison.current_id) &&
          isSafeIntegerInRange(comparison.baseline_status, 1, 599) &&
          isSafeIntegerInRange(comparison.current_status, 1, 599) &&
          typeof comparison.status_changed === 'boolean' &&
          Number.isSafeInteger(comparison.duration_delta_ms) && Math.abs(comparison.duration_delta_ms) <= 35000 &&
          isSafeIntegerInRange(comparison.baseline_body_bytes, 0, 64 * 1024) &&
          isSafeIntegerInRange(comparison.current_body_bytes, 0, 64 * 1024) &&
          Number.isSafeInteger(comparison.body_bytes_delta) && Math.abs(comparison.body_bytes_delta) <= 64 * 1024 &&
          typeof comparison.baseline_body_sha256 === 'string' && /^[0-9a-f]{64}$/.test(comparison.baseline_body_sha256) &&
          typeof comparison.current_body_sha256 === 'string' && /^[0-9a-f]{64}$/.test(comparison.current_body_sha256) &&
          typeof comparison.body_changed === 'boolean' && headerList(comparison.headers_added) &&
          headerList(comparison.headers_removed) && headerList(comparison.headers_changed) &&
          typeof comparison.partial === 'boolean';
      }

      function isRepeater(repeater) {
        const states = ['idle', 'attaching', 'ready', 'running', 'cancelling', 'error', 'disposed'];
        if (!isPlainObject(repeater) || repeater.protocol_version !== 1 ||
            !isSafeIntegerInRange(repeater.session_id, 0, Number.MAX_SAFE_INTEGER) ||
            !states.includes(repeater.state) || !Array.isArray(repeater.variables) ||
            repeater.variables.length > 32 || !Array.isArray(repeater.history) ||
            repeater.history.length > 24 || !isSafeIntegerInRange(repeater.history_bytes, 0, 512 * 1024) ||
            !isSafeIntegerInRange(repeater.history_evictions, 0, Number.MAX_SAFE_INTEGER) ||
            !isBoundedText(repeater.message, 512) || !isPlainObject(repeater.limits) ||
            repeater.limits.history_entries !== 24 || repeater.limits.history_bytes !== 512 * 1024 ||
            repeater.limits.variables !== 32 || repeater.limits.variable_bytes !== 32 * 1024 ||
            repeater.limits.request_bytes !== 64 * 1024 || repeater.limits.response_bytes !== 64 * 1024 ||
            repeater.limits.timeout_ms !== 30000) return false;
        let variableBytes = 0;
        const variableNames = new Set();
        if (!repeater.variables.every(variable => {
          if (!isPlainObject(variable) || !isBoundedText(variable.name, 64) ||
              !/^[A-Za-z_][A-Za-z0-9_.-]*$/.test(variable.name) ||
              !isBoundedText(variable.value, 4 * 1024) || variableNames.has(variable.name)) return false;
          variableNames.add(variable.name);
          variableBytes += utf8ByteLength(variable.name) + utf8ByteLength(variable.value);
          return variableBytes <= 32 * 1024;
        })) return false;
        if (!repeater.history.every(isRepeaterHistoryEntry) ||
            repeater.history.some((entry, index) => index > 0 && repeater.history[index - 1].id >= entry.id) ||
            repeater.history_bytes !== repeater.history.reduce((sum, entry) => sum + entry.stored_bytes, 0)) return false;
        const retainedIds = new Set(repeater.history.map(entry => entry.id));
        if (!isRepeaterComparison(repeater.comparison, retainedIds)) return false;
        const active = repeater.active_execution;
        if (active !== null && (!isPlainObject(active) ||
            !isSafeIntegerInRange(active.execution_id, 1, Number.MAX_SAFE_INTEGER) ||
            !isSafeIntegerInRange(active.started_at_ms, 1, Number.MAX_SAFE_INTEGER) ||
            !isRepeaterRequest(active.request) || !isBoundedText(active.resolved_url, 8 * 1024) ||
            !isBoundedText(active.resolved_method, 32) || !Array.isArray(active.variable_names) ||
            active.variable_names.length > 32 || !active.variable_names.every(name => variableNames.has(name)) ||
            (active.collection_request_id !== null &&
              !isSafeIntegerInRange(active.collection_request_id, 1, Number.MAX_SAFE_INTEGER)) ||
            typeof active.cancel_requested !== 'boolean')) return false;
        if (repeater.state === 'idle') {
          return repeater.session_id === 0 && repeater.variables.length === 0 &&
            repeater.history.length === 0 && active === null && repeater.comparison === null;
        }
        if (repeater.state === 'disposed') {
          return repeater.session_id > 0 && repeater.variables.length === 0 &&
            repeater.history.length === 0 && repeater.history_bytes === 0 && active === null && repeater.comparison === null;
        }
        if (repeater.session_id <= 0) return false;
        return ['running', 'cancelling'].includes(repeater.state) ? active !== null : active === null;
      }

      function isDebuggerResponse(body) {
        if (!isPlainObject(body) || body.protocol_version !== 1 ||
            !['unavailable', 'waiting', 'connecting', 'running', 'paused'].includes(body.state) ||
            !isSafeIntegerInRange(body.generation, 0, Number.MAX_SAFE_INTEGER) ||
            (body.error !== null && typeof body.error !== 'string') ||
            !Array.isArray(body.targets) || body.targets.length > 128 || !body.targets.every(isDebuggerTarget) ||
            !Array.isArray(body.scripts) || body.scripts.length > 5000 || !body.scripts.every(isDebuggerScript) ||
            !Array.isArray(body.breakpoints) || body.breakpoints.length > 1000 || !body.breakpoints.every(isDebuggerBreakpoint) ||
            !Array.isArray(body.watches) || body.watches.length > 100 || !body.watches.every(isDebuggerWatch) ||
            !Array.isArray(body.console) || body.console.length > 500 || !body.console.every(isDebuggerConsoleEntry) ||
            !isMemoryOriginTrace(body.memory_origin_trace) ||
            !isActionScope(body.action_scope) ||
            !isRequestInterception(body.request_interception) ||
            !isObjectExperiment(body.object_experiment) ||
            !isRuntimeHooks(body.runtime_hooks) ||
            !isAutomationRecipes(body.automation_recipes) ||
            !isRepeater(body.repeater) ||
            !isPlainObject(body.settings) || !isPlainObject(body.limits)) return false;
        if (body.heap_diff_baseline !== null && (!isPlainObject(body.heap_diff_baseline) ||
            typeof body.heap_diff_baseline.target_id !== 'string' ||
            !isSafeIntegerInRange(body.heap_diff_baseline.file_bytes, 1, 256 * 1024 * 1024) ||
            !isSafeIntegerInRange(body.heap_diff_baseline.captured_at_ms, 0, Number.MAX_SAFE_INTEGER))) return false;
        if (body.target !== null && !isDebuggerTarget(body.target)) return false;
        if (body.paused !== null && (!isPlainObject(body.paused) || typeof body.paused.reason !== 'string' ||
            (body.paused.description !== null && typeof body.paused.description !== 'string') ||
            !Array.isArray(body.paused.call_frames) || body.paused.call_frames.length > 64 ||
            !body.paused.call_frames.every(isDebuggerFrame) || !Array.isArray(body.paused.async_stack) ||
            body.paused.async_stack.length > 32 || !body.paused.async_stack.every(isDebuggerAsyncStack) ||
            !Array.isArray(body.paused.hit_breakpoints) || body.paused.hit_breakpoints.length > 1000 ||
            !body.paused.hit_breakpoints.every(value => typeof value === 'string') ||
            !isPlainObject(body.paused.scope_coverage) ||
            !['loading', 'complete', 'partial'].includes(body.paused.scope_coverage.status) ||
            !isSafeIntegerInRange(body.paused.scope_coverage.properties, 0, 2000) ||
            body.paused.scope_coverage.limit !== 2000)) return false;
        if ((body.state === 'paused') !== (body.paused !== null) ||
            (['running', 'paused'].includes(body.state) && body.target === null)) return false;
        return typeof body.settings.breakpoints_active === 'boolean' &&
          ['none', 'uncaught', 'all'].includes(body.settings.pause_on_exceptions) &&
          Array.isArray(body.settings.xhr_breakpoints) && body.settings.xhr_breakpoints.length <= 100 &&
          body.settings.xhr_breakpoints.every(value => typeof value === 'string') &&
          Array.isArray(body.settings.event_breakpoints) && body.settings.event_breakpoints.length <= 256 &&
          body.settings.event_breakpoints.every(value => typeof value === 'string') &&
          ['scripts', 'call_frames', 'scope_properties', 'console_entries', 'source_bytes']
            .every(field => isSafeIntegerInRange(body.limits[field], 1, Number.MAX_SAFE_INTEGER));
      }

      function isLiveObjectSearchResponse(body) {
        if (!isPlainObject(body) || body.ok !== true ||
            !isSafeIntegerInRange(body.generation, 0, Number.MAX_SAFE_INTEGER) ||
            !isPlainObject(body.search)) return false;
        const search = body.search;
        if (!isLiveObjectSearchMetadata(search) ||
            !Array.isArray(search.results) || search.results.length > search.result_limit) return false;
        return search.results.every(isLiveObjectResultRecord);
      }

      function isHeapSnapshotSearchResponse(body) {
        if (!isPlainObject(body) || body.ok !== true ||
            !isSafeIntegerInRange(body.generation, 0, Number.MAX_SAFE_INTEGER) ||
            !isPlainObject(body.snapshot)) return false;
        const snapshot = body.snapshot;
        const integerFields = [
          'file_bytes', 'total_nodes', 'analyzed_nodes', 'matched_nodes', 'reachable_nodes',
          'total_edges', 'indexed_edges', 'total_strings', 'duration_ms', 'result_limit',
          'reference_limit'
        ];
        const booleanFields = [
          'result_limit_reached', 'node_limit_reached', 'edge_limit_reached',
          'string_limit_reached', 'retaining_paths_partial'
        ];
        if (snapshot.protocol_version !== 2 ||
            !integerFields.every(field => isSafeIntegerInRange(snapshot[field], 0, Number.MAX_SAFE_INTEGER)) ||
            snapshot.file_bytes > 256 * 1024 * 1024 || snapshot.result_limit !== 50 || snapshot.reference_limit !== 12 ||
            !['all', 'reachable', 'unreachable'].includes(snapshot.scope) ||
            snapshot.analyzed_nodes > snapshot.total_nodes || snapshot.matched_nodes > snapshot.analyzed_nodes ||
            snapshot.reachable_nodes > snapshot.analyzed_nodes || snapshot.indexed_edges > snapshot.total_edges ||
            snapshot.result_limit_reached !== (snapshot.matched_nodes > snapshot.result_limit) ||
            !booleanFields.every(field => typeof snapshot[field] === 'boolean') ||
            !Array.isArray(snapshot.results) ||
            snapshot.results.length !== Math.min(snapshot.matched_nodes, snapshot.result_limit)) return false;
        return snapshot.results.every(result => isPlainObject(result) &&
          typeof result.id === 'string' && /^(?:0|[1-9][0-9]*)$/.test(result.id) &&
          result.id.length <= 20 && typeof result.type === 'string' &&
          typeof result.name === 'string' &&
          isSafeIntegerInRange(result.self_size, 0, Number.MAX_SAFE_INTEGER) &&
          typeof result.reachable === 'boolean' &&
          isSafeIntegerInRange(result.incoming_reference_count, 0, Number.MAX_SAFE_INTEGER) &&
          typeof result.incoming_reference_limit_reached === 'boolean' &&
          typeof result.retaining_path_complete === 'boolean' &&
          Array.isArray(result.retaining_path) && result.retaining_path.length <= 12 &&
          (result.reachable || (!result.retaining_path_complete && result.retaining_path.length === 0)) &&
          (snapshot.scope !== 'reachable' || result.reachable) &&
          (snapshot.scope !== 'unreachable' || !result.reachable) &&
          result.retaining_path.every(step => isPlainObject(step) &&
            ['edge_type', 'edge', 'type', 'name'].every(field => typeof step[field] === 'string')) &&
          Array.isArray(result.incoming_references) && result.incoming_references.length <= snapshot.reference_limit &&
          result.incoming_reference_count >= result.incoming_references.length &&
          result.incoming_reference_limit_reached ===
            (result.incoming_reference_count > result.incoming_references.length) &&
          result.incoming_references.every(reference => isPlainObject(reference) &&
            typeof reference.source_id === 'string' && /^(?:0|[1-9][0-9]*)$/.test(reference.source_id) &&
            reference.source_id.length <= 20 &&
            ['edge_type', 'edge', 'source_type', 'source_name']
              .every(field => typeof reference[field] === 'string')));
      }

      function isHeapDiffBaselineResponse(body) {
        return isPlainObject(body) && body.ok === true &&
          isSafeIntegerInRange(body.generation, 0, Number.MAX_SAFE_INTEGER) &&
          isPlainObject(body.baseline) && typeof body.baseline.target_id === 'string' &&
          isSafeIntegerInRange(body.baseline.file_bytes, 1, 256 * 1024 * 1024) &&
          isSafeIntegerInRange(body.baseline.captured_at_ms, 0, Number.MAX_SAFE_INTEGER);
      }

      function isHeapSnapshotDiffResponse(body) {
        if (!isPlainObject(body) || body.ok !== true ||
            !isSafeIntegerInRange(body.generation, 0, Number.MAX_SAFE_INTEGER) ||
            !isPlainObject(body.diff)) return false;
        const diff = body.diff;
        const integerFields = [
          'baseline_file_bytes', 'current_file_bytes', 'baseline_nodes', 'current_nodes',
          'baseline_edges', 'current_edges', 'baseline_reachable_nodes',
          'current_reachable_nodes', 'baseline_self_size', 'current_self_size',
          'duration_ms', 'result_limit'
        ];
        const booleanFields = [
          'group_result_limit_reached', 'dominator_result_limit_reached',
          'aggregation_limit_reached', 'baseline_node_limit_reached',
          'baseline_edge_limit_reached', 'baseline_string_limit_reached',
          'current_node_limit_reached', 'current_edge_limit_reached',
          'current_string_limit_reached', 'retained_size_saturated'
        ];
        if (diff.protocol_version !== 1 ||
            !integerFields.every(field => isSafeIntegerInRange(diff[field], 0, Number.MAX_SAFE_INTEGER)) ||
            !Number.isSafeInteger(diff.self_size_delta) || diff.result_limit !== 50 ||
            diff.baseline_file_bytes > 256 * 1024 * 1024 || diff.current_file_bytes > 256 * 1024 * 1024 ||
            diff.baseline_reachable_nodes > diff.baseline_nodes || diff.current_reachable_nodes > diff.current_nodes ||
            diff.self_size_delta !== diff.current_self_size - diff.baseline_self_size ||
            !booleanFields.every(field => typeof diff[field] === 'boolean') ||
            !Array.isArray(diff.groups) || diff.groups.length > diff.result_limit ||
            !Array.isArray(diff.dominators) || diff.dominators.length > diff.result_limit) return false;
        const validDelta = (baseline, current, delta) =>
          isSafeIntegerInRange(baseline, 0, Number.MAX_SAFE_INTEGER) &&
          isSafeIntegerInRange(current, 0, Number.MAX_SAFE_INTEGER) &&
          Number.isSafeInteger(delta) && delta === current - baseline;
        return diff.groups.every(group => isPlainObject(group) &&
          typeof group.type === 'string' && typeof group.name === 'string' &&
          validDelta(group.baseline_count, group.current_count, group.count_delta) &&
          validDelta(group.baseline_self_size, group.current_self_size, group.self_size_delta)) &&
          diff.dominators.every(change => isPlainObject(change) &&
            typeof change.id === 'string' && /^(?:0|[1-9][0-9]*)$/.test(change.id) &&
            change.id.length <= 20 && typeof change.type === 'string' &&
            typeof change.name === 'string' && validDelta(change.baseline_retained_size,
              change.current_retained_size, change.retained_size_delta));
      }

      function isOriginTraceResponse(body) {
        if (!isPlainObject(body) || body.contract_version !== 1 ||
            body.document_kind !== 'origin-trace' ||
            !isCanonicalInteger(body.request_id, 0n, uint64Max) ||
            !['complete', 'partial', 'empty', 'ambiguous'].includes(body.status) ||
            !Array.isArray(body.steps) || body.steps.length > 32 ||
            !Array.isArray(body.gaps) || body.gaps.length > 32 ||
            !Array.isArray(body.artifacts) ||
            !isPlainObject(body.coverage)) return false;
        const coverage = body.coverage;
        if (!['linked_steps', 'observed_links', 'correlated_links', 'gap_count', 'percent']
          .every(field => isSafeIntegerInRange(coverage[field], 0, field === 'percent' ? 100 : 32)) ||
          coverage.linked_steps !== Math.max(0, body.steps.length - 1) ||
          coverage.observed_links + coverage.correlated_links !== coverage.linked_steps ||
          coverage.gap_count !== body.gaps.length) return false;
        const validStep = step => isPlainObject(step) && isPlainObject(step.event) &&
          isCanonicalInteger(step.event.session_id, 0n, uint64Max) &&
          BigInt(step.event.session_id) > 0n &&
          isSafeIntegerInRange(step.event.process_id, 0, 0xffffffff) &&
          isCanonicalInteger(step.event.sequence_number, 0n, uint64Max) &&
          BigInt(step.event.sequence_number) > 0n &&
          isCanonicalInteger(step.monotonic_time_ns, 0n, uint64Max) &&
          isCanonicalInteger(step.frame_id, 0n, uint64Max) &&
          isCanonicalInteger(step.artifact_id, 0n, uint64Max) &&
          isCanonicalInteger(step.request_id, 0n, uint64Max) &&
          eventCategories.has(step.category) &&
          typeof step.operation === 'string' && step.operation.length > 0 &&
          typeof step.value === 'string' && step.value.length <= 256 &&
          ['trace_target', 'parent_event', 'request_initiator', 'request_lifecycle', 'artifact_request'].includes(step.relation) &&
          ['observed', 'correlated'].includes(step.confidence);
        const validGap = gap => isPlainObject(gap) &&
          ['ambiguous_request', 'missing_event', 'no_predecessor', 'cycle', 'step_limit'].includes(gap.reason) &&
          isSafeIntegerInRange(gap.after_step, 0, 31) &&
          typeof gap.detail === 'string' && gap.detail.length > 0;
        return body.steps.every(validStep) && body.gaps.every(validGap);
      }

      function isSignalEventReference(reference) {
        return isPlainObject(reference) &&
          Object.keys(reference).length === 2 &&
          isSafeIntegerInRange(reference.process_id, 0, 0xffffffff) &&
          isCanonicalInteger(reference.sequence_number, 1n, uint64Max);
      }

      function isRequestSignalProfile(body) {
        if (!isPlainObject(body) || Object.keys(body).length !== 10 ||
            body.protocol_version !== 1 || body.document_kind !== 'request-signal-profile' ||
            !isCanonicalInteger(body.session_id, 1n, uint64Max) ||
            !isCanonicalInteger(body.request_id, 1n, uint64Max) ||
            !isCanonicalInteger(body.navigation_id, 0n, uint64Max) ||
            !isCanonicalInteger(body.frame_id, 0n, uint64Max) ||
            !isSignalEventReference(body.root_event) ||
            (body.initiator_event !== null && !isSignalEventReference(body.initiator_event)) ||
            !Array.isArray(body.signals) || body.signals.length > 7 ||
            !isPlainObject(body.coverage)) return false;
        const categories = new Set();
        const expectedProcessID = (body.initiator_event ?? body.root_event).process_id;
        let hasSaturatedCount = false;
        const validSignals = body.signals.every(signal => {
          if (!isPlainObject(signal) || Object.keys(signal).length !== 6 ||
              !fingerprintSignalCategories.has(signal.category) || categories.has(signal.category) ||
              !['parent_chain', 'same_context'].includes(signal.relation) ||
              !isCanonicalInteger(signal.event_count, 1n, uint64Max) ||
              !isSignalEventReference(signal.first_event) ||
              !isSignalEventReference(signal.last_event) ||
              signal.first_event.process_id !== expectedProcessID ||
              signal.last_event.process_id !== expectedProcessID) return false;
          categories.add(signal.category);
          hasSaturatedCount ||= signal.event_count === String(uint64Max);
          return signal.confidence === (signal.relation === 'parent_chain' ? 'observed' : 'correlated');
        });
        const coverage = body.coverage;
        return validSignals && Object.keys(coverage).length === 6 &&
          isSafeIntegerInRange(coverage.parent_depth, 0, 32) &&
          coverage.parent_depth_limit === 32 &&
          typeof coverage.copied_from_initiator === 'boolean' &&
          typeof coverage.retention_truncated === 'boolean' &&
          typeof coverage.parent_depth_limited === 'boolean' &&
          typeof coverage.count_saturated === 'boolean' &&
          coverage.copied_from_initiator === (body.initiator_event !== null) &&
          (!coverage.count_saturated || hasSaturatedCount) &&
          (!coverage.parent_depth_limited || coverage.parent_depth === 32);
      }

      function legacyBrowserRequestKey(event) {
        const session = integerText(event, 'session_id');
        const requestId = integerText(event, 'request_id');
        if (requestId === '0') return null;
        return event.initiator_process_id > 0
          ? `S${session}:R${event.initiator_process_id}:B${requestId}`
          : `S${session}:P${event.process_id}:F${integerText(event, 'frame_id')}:B${requestId}`;
      }

      function browserRequestKey(event) {
        const session = integerText(event, 'session_id');
        const requestId = integerText(event, 'request_id');
        if (requestId === '0') return null;
        const context = browserContextToken(event);
        return context
          ? `S${session}:P${event.process_id}:C${context}:B${requestId}`
          : legacyBrowserRequestKey(event);
      }

      function rendererRequestIdentity(event) {
        return `S${integerText(event, 'session_id')}:R${event.process_id}:${integerText(event, 'request_id')}`;
      }

      function correlatedRendererIdentity(event) {
        return `S${integerText(event, 'session_id')}:R${event.initiator_process_id}:${event.initiator_request_id}`;
      }

      function buildBrowserRequestKeys(events) {
        const keys = new Map();
        for (const event of events) {
          if (event.protocol_version !== 2 || integerText(event, 'request_id') === '0') continue;
          if (event.type === 'request_initiated') {
            const fallbackKey = legacyBrowserRequestKey(event);
            if (fallbackKey) keys.set(fallbackKey, rendererRequestIdentity(event));
            continue;
          }
          if (event.initiator_process_id === 0) continue;
          const identity = correlatedRendererIdentity(event);
          const primaryKey = browserRequestKey(event);
          const fallbackKey = legacyBrowserRequestKey(event);
          if (primaryKey && !keys.has(primaryKey)) keys.set(primaryKey, identity);
          if (fallbackKey && !keys.has(fallbackKey)) keys.set(fallbackKey, identity);
        }
        return keys;
      }

      function requestIdentity(event, browserRequestKeys) {
        const session = integerText(event, 'session_id');
        if (event.protocol_version === 1) {
          return `S${session}:P${event.process_id}:E${integerText(event, 'sequence_number')}`;
        }

        const requestId = integerText(event, 'request_id');
        if (event.type === 'request_initiated') {
          return rendererRequestIdentity(event);
        }
        const hasInitiator = event.initiator_process_id > 0;
        const correlatedId = hasInitiator
          ? correlatedRendererIdentity(event)
          : requestId !== '0' && browserContextToken(event)
            ? browserRequestKey(event)
            : requestId !== '0'
              ? legacyBrowserRequestKey(event)
            : `S${session}:P${event.process_id}:E${integerText(event, 'sequence_number')}`;
        const requestKey = browserRequestKey(event);
        return requestKey ? browserRequestKeys.get(requestKey) ?? correlatedId : correlatedId;
      }

      function resourceTypeFilter(event, previous, payload) {
        if (/^application\/wasm(?:;|$)/i.test(payload)) return 'wasm';
        if (event.protocol_version === 2 && event.type === 'request_started') {
          return resourceTypeFilters.get(event.resource_type) ?? 'other';
        }
        return previous?.type ?? 'other';
      }

      function requestsFromEvents(events) {
        const requests = new Map();
        const lifecycleEvents = events.filter(event => event.category === 'network' && networkLifecycleTypes.has(event.type));
        const browserRequestKeys = buildBrowserRequestKeys(lifecycleEvents);
        lifecycleEvents.forEach(event => {
          const payload = decodePayload(event);
          const carriesRequestTarget = ['request_initiated', 'request_started', 'request_redirected'].includes(event.type);
          const match = carriesRequestTarget ? payload.match(/^([A-Z]+)\s+(\S+)/) : null;
          const id = requestIdentity(event, browserRequestKeys);
          const previous = requests.get(id);
          const timestamp = integerValue(event, 'monotonic_time_ns');
          const firstTimestamp = previous && previous.firstTimestamp < timestamp ? previous.firstTimestamp : timestamp;
          const lastTimestamp = previous && previous.lastTimestamp > timestamp ? previous.lastTimestamp : timestamp;
          const incomingRank = lifecycleRanks.get(event.type) ?? 0;
          const rank = Math.max(previous?.rank ?? 0, incomingRank);
          const failed = previous?.failed || event.type === 'request_failed' || (event.protocol_version === 2 && event.error_code !== 0);
          const numericStatus = event.protocol_version === 2 ? event.status_code : 0;
          const previousStatusRank = previous?.statusRank ?? 0;
          const hasNewerStatus = numericStatus > 0 && incomingRank >= previousStatusRank;
          const status = failed
            ? 'failed'
            : hasNewerStatus
              ? numericStatus
              : previous?.status ?? 'pending';
          const targetRank = match && incomingRank >= (previous?.targetRank ?? 0)
            ? incomingRank
            : previous?.targetRank ?? 0;
          const updatesTarget = Boolean(match) && targetRank === incomingRank;
          const terminal = rank >= 5;
          requests.set(id, {
            id,
            path: updatesTarget ? match[2] : previous?.path ?? 'network request',
            method: updatesTarget ? match[1] : previous?.method ?? 'EVENT',
            status,
            time: terminal ? formatMilliseconds(lastTimestamp - firstTimestamp) : 'pending',
            type: resourceTypeFilter(event, previous, payload),
            origin: 'live',
            start: 8,
            mid: Math.min(80, 18 + rank * 11),
            end: Math.min(94, 30 + rank * 12),
            event: incomingRank >= (previous?.rank ?? 0) ? event : previous.event,
            events: [...(previous?.events ?? []), event],
            failed,
            rank,
            statusRank: hasNewerStatus ? incomingRank : previousStatusRank,
            targetRank,
            operation: incomingRank >= (previous?.rank ?? 0) ? event.type : previous.operation,
            firstTimestamp,
            lastTimestamp
          });
        });
        return [...requests.values()];
      }

      function decodeVmFinding(event) {
        if (event.protocol_version !== 2 || event.category !== 'vm' ||
            event.type !== 'vm_finding' || event.payload_size !== 128 ||
            event.payload_truncated) return null;
        const bytes = bytesFromHex(event.payload);
        if (bytes.length !== 128) return null;
        const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        const kindCode = bytes[4];
        const runtimeCode = bytes[5];
        const confidenceCode = bytes[6];
        const flags = bytes[7];
        const labelSize = view.getUint16(8, true);
        const observedCount = view.getUint32(12, true);
        const totalCount = view.getUint32(16, true);
        const sourceOffset = view.getBigUint64(56, true);
        const sourceSize = view.getBigUint64(64, true);
        const findingId = view.getBigUint64(24, true);
        const investigationId = view.getBigUint64(32, true);
        if (view.getUint16(0, true) !== 1 || view.getUint16(2, true) !== 128 ||
            !vmKinds.has(kindCode) || !vmHostRuntimes.has(runtimeCode) ||
            !vmConfidences.has(confidenceCode) || (flags & ~0x0f) !== 0 ||
            labelSize === 0 || labelSize > 40 || view.getUint16(10, true) !== 0 ||
            view.getUint32(20, true) !== 0 || findingId === 0n || investigationId === 0n) return null;
        const isCoverage = kindCode === 6;
        if (isCoverage ? totalCount === 0 || observedCount > totalCount : observedCount !== 0 || totalCount !== 0) return null;
        const hasSourceRange = Boolean(flags & 1);
        if (hasSourceRange ? sourceSize === 0n : sourceOffset !== 0n || sourceSize !== 0n) return null;
        if (hasSourceRange && sourceOffset + sourceSize > uint64Max) return null;
        if (hasSourceRange && integerText(event, 'artifact_id') === '0') return null;
        const labelBytes = bytes.slice(72, 72 + labelSize);
        if ([...labelBytes].some(byte => byte < 0x20 || byte > 0x7e) ||
            bytes.slice(72 + labelSize, 112).some(byte => byte !== 0) ||
            bytes.slice(112).some(byte => byte !== 0)) return null;
        const flagNames = [
          [1, 'source range'], [2, 'partial'], [4, 'dynamic'], [8, 'nested']
        ].filter(([mask]) => flags & mask).map(([, name]) => name);
        return {
          findingId: String(findingId),
          investigationId: String(investigationId),
          subjectId: String(view.getBigUint64(40, true)),
          relatedSubjectId: String(view.getBigUint64(48, true)),
          kind: vmKinds.get(kindCode),
          hostRuntime: vmHostRuntimes.get(runtimeCode),
          confidence: vmConfidences.get(confidenceCode),
          flags: flagNames,
          label: String.fromCharCode(...labelBytes),
          observedCount,
          totalCount,
          sourceOffset: String(sourceOffset),
          sourceSize: String(sourceSize),
          sourceArtifactId: integerText(event, 'artifact_id'),
          sequenceNumber: integerText(event, 'sequence_number'),
          parentEventId: integerText(event, 'parent_event_id'),
          monotonicTimeNs: integerText(event, 'monotonic_time_ns'),
          processId: event.process_id,
          threadId: event.thread_id
        };
      }

      function vmFindingsFromEvents(events) {
        const findings = [];
        let malformedCount = 0;
        events.filter(event => event.category === 'vm' && event.type === 'vm_finding').forEach(event => {
          const finding = decodeVmFinding(event);
          if (finding) findings.push(finding); else malformedCount += 1;
        });
        return { findings, malformedCount };
      }

      function isVmAnalysisObservation(observation) {
        return isPlainObject(observation) &&
          typeof observation.rule_id === 'string' && observation.rule_id.length > 0 &&
          typeof observation.family === 'string' && observation.family.length > 0 &&
          isSafeIntegerInRange(observation.weight, 0, 100) &&
          isPlainObject(observation.coordinate) &&
          isSafeIntegerInRange(observation.coordinate.byte_offset, 0, Number.MAX_SAFE_INTEGER) &&
          isSafeIntegerInRange(observation.coordinate.byte_size, 1, Number.MAX_SAFE_INTEGER) &&
          typeof observation.detail === 'string';
      }

      function isVmAnalysisResult(result) {
        if (!isPlainObject(result) || typeof result.artifact_id !== 'string' ||
            !['javascript', 'webassembly', 'unknown'].includes(result.runtime) ||
            !['complete', 'partial', 'failed'].includes(result.status)) return false;
        if (result.status === 'failed') {
          return isPlainObject(result.error) && typeof result.error.code === 'string' &&
            isPlainObject(result.coverage) && result.coverage.complete === false;
        }
        if (!['javascript', 'webassembly'].includes(result.runtime)) return false;
        return typeof result.finding_id === 'string' && /^[0-9a-f]{24}$/.test(result.finding_id) &&
          ['none', 'candidate', 'likely-vm'].includes(result.tier) &&
          isSafeIntegerInRange(result.vm_score, 0, 500) &&
          isSafeIntegerInRange(result.anti_bot_score, 0, 100) &&
          Array.isArray(result.evidence_families) && result.evidence_families.every(value => typeof value === 'string') &&
          Array.isArray(result.observations) && result.observations.every(isVmAnalysisObservation) &&
          Array.isArray(result.related_request_ids) && result.related_request_ids.every(value => isCanonicalInteger(value, 0n, uint64Max)) &&
          isPlainObject(result.coverage) && typeof result.coverage.complete === 'boolean';
      }

      function isVmAnalysisDocument(document) {
        return isPlainObject(document) && document.contract_version === 1 &&
          document.document_kind === 'vm-analysis' &&
          typeof document.document_digest === 'string' && /^[0-9a-f]{64}$/.test(document.document_digest) &&
          typeof document.profile_digest === 'string' && /^[0-9a-f]{64}$/.test(document.profile_digest) &&
          isPlainObject(document.profile) && document.profile.profile_id === 'anti-bot-vm-detection-v1' &&
          isPlainObject(document.input_coverage) && typeof document.input_coverage.complete === 'boolean' &&
          Array.isArray(document.input_coverage.omissions) &&
          Array.isArray(document.results) && document.results.every(isVmAnalysisResult) &&
          Array.isArray(document.mixed_findings) &&
          document.mixed_findings.every(finding => isPlainObject(finding) &&
            typeof finding.finding_id === 'string' && /^[0-9a-f]{24}$/.test(finding.finding_id) &&
            finding.runtime === 'mixed' && ['candidate', 'likely-vm'].includes(finding.tier));
      }

      function vmFindingsFromAnalysis(document) {
        const investigationId = `analysis:${document.document_digest.slice(0, 12)}`;
        const findings = document.results
          .filter(result => result.status !== 'failed' && result.tier !== 'none')
          .map(result => ({
            findingId: `analysis:${result.finding_id}`,
            investigationId,
            kind: 'hypothesis',
            hostRuntime: result.runtime === 'javascript' ? 'JavaScript' : 'WebAssembly',
            confidence: result.tier,
            label: result.tier === 'likely-vm' ? 'Likely VM from deterministic analysis' : 'VM candidate from deterministic analysis',
            sourceArtifactId: result.artifact_id,
            sourceOffset: '0', sourceSize: '0', flags: result.status === 'partial' ? ['partial'] : [],
            subjectId: '0', relatedSubjectId: '0', sequenceNumber: 'derived', parentEventId: '0',
            monotonicTimeNs: 'cold path', processId: 0, threadId: 0,
            analysis: result
          }));
        document.mixed_findings.forEach(result => findings.push({
          findingId: `analysis:${result.finding_id}`,
          investigationId,
          kind: 'hypothesis', hostRuntime: 'mixed', confidence: result.tier,
          label: result.tier === 'likely-vm' ? 'Likely mixed JavaScript/WASM VM' : 'Mixed runtime VM candidate',
          sourceArtifactId: result.artifact_ids[0], sourceOffset: '0', sourceSize: '0', flags: [],
          subjectId: '0', relatedSubjectId: '0', sequenceNumber: 'derived', parentEventId: '0',
          monotonicTimeNs: 'cold path', processId: 0, threadId: 0,
          analysis: result
        }));
        return findings.sort((left, right) => (right.analysis?.vm_score ?? 0) - (left.analysis?.vm_score ?? 0));
      }

      function retainVmAnalysisOnFailure(targetState, status, errorMessage) {
        targetState.vmAnalysisStatus = status;
        targetState.vmAnalysisError = errorMessage;
        targetState.vmFindings = [
          ...targetState.lastValidAnalysisFindings,
          ...targetState.eventVmFindings
        ];
      }
