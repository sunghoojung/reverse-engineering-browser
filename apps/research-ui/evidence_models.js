      const eventCategories = new Set([
        'unknown', 'canvas', 'webgl', 'web_audio', 'navigator', 'permissions',
        'storage', 'webrtc', 'wasm', 'network', 'vm', 'artifact', 'runtime'
      ]);
      const fingerprintSignalCategories = new Set([
        'canvas', 'webgl', 'web_audio', 'navigator', 'permissions', 'storage', 'webrtc',
        'runtime'
      ]);

      function fingerprintEventsFromEvents(events) {
        return events.filter(event => fingerprintSignalCategories.has(event.category));
      }
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
          'vm_dispatch_sample',
          'artifact_captured', 'artifact_capture_failed'
        ]),
        3: new Set([
          'unknown', 'api_call', 'property_read', 'module_compiled',
          'module_instantiated', 'request_started', 'response_completed', 'gap',
          'request_initiated', 'request_redirected', 'response_started',
          'request_completed', 'request_failed', 'vm_finding',
          'vm_dispatch_sample', 'wasm_dispatch_observation', 'wasm_guest_dispatch', 'wasm_guest_invocation',
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
      const artifactKinds = new Set([
        'javascript', 'wasm', 'source_map', 'response_body', 'canvas_data_url',
        'bytecode_buffer', 'wasm_guest_adapter'
      ]);
      const artifactCaptureOrigins = new Set([
        'unknown', 'network_response', 'dynamic_javascript', 'webassembly_compile',
        'webassembly_module', 'webassembly_instantiate', 'canvas_to_data_url',
        'runtime_typed_array',
        'runtime_allocating_script', 'native_wasm_guest'
      ]);
      const canvasReplayProperties = new Set([
        'fillStyle', 'strokeStyle', 'font', 'textBaseline', 'textAlign',
        'globalAlpha', 'lineWidth', 'lineCap', 'lineJoin'
      ]);
      const canvasReplayMethods = new Set([
        'fillRect', 'strokeRect', 'clearRect', 'fillText', 'strokeText',
        'beginPath', 'closePath', 'moveTo', 'lineTo', 'arc', 'rect', 'fill', 'stroke'
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
        if (event.protocol_version < 2 ||
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

      function formatMilliseconds(nanoseconds, prefix = '') {
        const negative = nanoseconds < 0n;
        const absolute = negative ? -nanoseconds : nanoseconds;
        const whole = absolute / 1000000n;
        const fractional = ((absolute % 1000000n) / 1000n).toString().padStart(3, '0');
        return `${negative ? '-' : prefix}${whole}.${fractional} ms`;
      }

      function countSequenceGaps(events) {
        let gaps = 0n;
        const streams = new Map();
        for (const event of events) {
          const streamId = `${integerText(event, 'session_id')}:${event.process_id}`;
          const sequence = integerValue(event, 'sequence_number');
          let stream = streams.get(streamId);
          if (!stream) {
            stream = {low: sequence, high: sequence, seen: new Set()};
            streams.set(streamId, stream);
          }
          if (sequence < stream.low) stream.low = sequence;
          if (sequence > stream.high) stream.high = sequence;
          stream.seen.add(sequence);
        }
        // ACK-delayed original IDs close holes; duplicate arrivals are neutral.
        for (const stream of streams.values()) {
          gaps += stream.high - stream.low - BigInt(stream.seen.size - 1);
        }
        return gaps;
      }

      function countReportedQueueDrops(events) {
        let drops = 0n;
        for (const event of events) {
          if (event.type !== 'gap') continue;
          const payload = decodePayload(event);
          const count = isCaptureTotal(payload) && payload !== '0' ? BigInt(payload) : 1n;
          drops += count <= 18446744073709551615n ? count : 1n;
        }
        return drops;
      }

      function isCaptureTotal(value) {
        return typeof value === 'string' && !/[^0-9]/.test(value) && /^(?:0|[1-9][0-9]{0,19})$/.test(value) && BigInt(value) <= uint64Max;
      }

      function captureWideTotal(value) {
        return isCaptureTotal(value) ? BigInt(value) : null;
      }

      function shownSequenceGaps() {
        return typeof state.sequenceGaps === 'bigint' ? state.sequenceGaps : countSequenceGaps(state.events);
      }

      function shownQueueDrops() {
        return typeof state.queueDrops === 'bigint' ? state.queueDrops : countReportedQueueDrops(state.events);
      }

      function eventCountScopeLabel() {
        return state.eventCountScope === 'bounded_tail' ? 'the scanned tail'
          : state.eventCountScope === 'store' ? 'the stored capture' : 'the visible event window';
      }

      function acceptEventWindow(body) {
        // Missing optional summaries are unknown, not stale totals from a prior poll.
        state.sequenceGaps = captureWideTotal(body.sequence_gaps);
        state.queueDrops = captureWideTotal(body.queue_drops);
        state.sequenceGapsSaturated = body.sequence_gaps_saturated === true;
        state.queueDropsSaturated = body.queue_drops_saturated === true;
        state.eventCountScope = body.event_window?.scope ??
          (state.sequenceGaps !== null && state.queueDrops !== null ? 'store' : 'rendered_window');
        state.eventsLimited = body.event_window?.events_limited ?? body.count >= 5000;
        state.networkEventsAvailable = Array.isArray(body.network_events);
        state.networkEventsLimited = body.event_window?.network_events_limited === true;
      }

      function eventGapLabel(gapCount, reportedDrops) {
        const gaps = `${state.sequenceGapsSaturated ? 'at least ' : ''}${gapCount}`;
        const drops = `${state.queueDropsSaturated ? 'at least ' : ''}${reportedDrops}`;
        return `${gaps} sequence-gap IDs (${eventCountScopeLabel()})` +
          (reportedDrops > 0n ? ` · ${drops} reported queue ${reportedDrops === 1n ? 'drop' : 'drops'} (may overlap)` : '');
      }

      function fingerprintCoverageNotice(eventsLimited, displayLimited, displayLimit, gapCount, reportedDrops, scope = 'the stored capture') {
        const limits = [];
        if (eventsLimited) limits.push('the event window is capped');
        if (displayLimited) limits.push(`only the newest ${displayLimit} matching events are rendered`);
        if (scope === 'the scanned tail') limits.push('only the newest 64 MiB is scanned');
        if (gapCount > 0n) limits.push(`${state.sequenceGapsSaturated ? 'at least ' : ''}${gapCount} sequence-gap IDs were observed in ${scope}`);
        if (reportedDrops > 0n) limits.push(`${state.queueDropsSaturated ? 'at least ' : ''}${reportedDrops} queue drops were reported in ${scope} (may overlap sequence gaps)`);
        return `Fingerprint activity is visible with partial coverage: ${limits.join('; ')}.`;
      }

      function isEventWindow(value) {
        return isPlainObject(value) && ['store', 'bounded_tail'].includes(value.scope) &&
          isCaptureTotal(value.scan_start) && isCaptureTotal(value.scan_end) &&
          BigInt(value.scan_start) <= BigInt(value.scan_end) && value.scan_limit === 64 * 1024 * 1024 &&
          BigInt(value.scan_end) - BigInt(value.scan_start) <= BigInt(value.scan_limit) &&
          (value.scope === 'store') === (value.scan_start === '0') &&
          typeof value.events_limited === 'boolean' && typeof value.network_events_limited === 'boolean';
      }

      function decodeNativeWasmObservation(event) {
        if (event?.type !== 'wasm_dispatch_observation' || event.protocol_version !== 3 || event.category !== 'vm' ||
          event.payload_size !== 128 || event.payload_encoding !== 'hex' || event.payload_truncated !== false ||
          event.flags !== 0 || event.parent_event_id !== '0' || Object.hasOwn(event,'dispatch_provenance') ||
          !['session_id','sequence_number','monotonic_time_ns','frame_id','artifact_id'].every(key => isCanonicalInteger(event[key], 1n, uint64Max)) ||
          !['process_id','thread_id'].every(key => isSafeIntegerInRange(event[key], 1, 0xffffffff)) ||
          typeof event.payload !== 'string' || !/^[0-9a-f]{256}$/i.test(event.payload)) return null;
        const bytes = Uint8Array.from(event.payload.match(/../g), byte => Number.parseInt(byte, 16));
        const view = new DataView(bytes.buffer);
        if (view.getUint16(0,true) !== 1 || view.getUint16(2,true) !== 128 || bytes.slice(24).some(byte => byte !== 0)) return null;
        const row = {function_index:view.getUint32(4,true),module_byte_offset:view.getUint32(8,true),
          selector:view.getUint32(12,true),table_count:view.getUint32(16,true),sample_index:view.getUint32(20,true)};
        return row.function_index < 16777216 && row.module_byte_offset >= 8 && row.module_byte_offset < 16777216 &&
          row.table_count < 16777216 && row.sample_index < 16 ? row : null;
      }

      function decodeNativeGuestRecord(event) {
        if (!['wasm_guest_dispatch','wasm_guest_invocation'].includes(event?.type) || event.protocol_version !== 3 ||
          event.category !== 'vm' || event.flags !== 0 || event.payload_size !== 128 || event.payload_encoding !== 'hex' ||
          event.payload_truncated !== false || Object.hasOwn(event,'dispatch_provenance') ||
          !['session_id','sequence_number','monotonic_time_ns','frame_id','artifact_id'].every(k => isCanonicalInteger(event[k],1n,uint64Max)) ||
          !['process_id','thread_id'].every(k => isSafeIntegerInRange(event[k],1,0xffffffff)) ||
          typeof event.payload !== 'string' || !/^[0-9a-f]{256}$/i.test(event.payload)) return null;
        const bytes = Uint8Array.from(event.payload.match(/../g), b => parseInt(b,16));
        const view = new DataView(bytes.buffer);
        const u64 = n => view.getBigUint64(n,true);
        if (view.getUint16(0,true) !== 1 || view.getUint16(2,true) !== 128 || view.getUint32(4,true) >= 16777216) return null;
        if (event.type === 'wasm_guest_invocation') {
          return event.parent_event_id === '0' && u64(8) > 0n && u64(16) > 0n && u64(24) > 0n &&
            u64(24) !== BigInt(event.artifact_id) && u64(64) !== u64(16) &&
            bytes.slice(32,64).some(b => b !== 0) && bytes.slice(72).every(b => b === 0) ? {} : null;
        }
        const length = view.getUint32(72,true);
        return isCanonicalInteger(event.parent_event_id,1n,uint64Max) && BigInt(event.parent_event_id) < BigInt(event.sequence_number) &&
          view.getUint32(8,true) >= 8 && view.getUint32(8,true) < 16777216 && view.getUint32(16,true) < 16777216 &&
          view.getUint32(20,true) < 256 && u64(24) > 0n && u64(32) > 0n &&
          u64(56) > 0n && u64(56) !== BigInt(event.artifact_id) && length > 0 && length <= 65536 &&
          u64(40) < BigInt(length) && u64(64) + BigInt(length) <= uint64Max && bytes.slice(96).some(b => b !== 0) ? {} : null;
      }

      function isBrokerEvent(event) {
        if (!isPlainObject(event) || !Number.isInteger(event.protocol_version)) return false;
        const payloadLimit = event.protocol_version === 1 ? 48
          : event.protocol_version === 2 || event.protocol_version === 3 ? 128 : null;
        if (payloadLimit === null || !eventTypes[event.protocol_version]?.has(event.type)) return false;
        if (!eventCategories.has(event.category)) return false;
        if (event.protocol_version >= 2 && (event.category === 'unknown' || event.type === 'unknown')) return false;
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
        if (event.protocol_version === 3 && !isSafeIntegerInRange(event.tab_id, 0, 0xffffffff)) return false;
        if (event.protocol_version === 2 && Object.hasOwn(event, 'tab_id')) return false;
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
        return event.payload_truncated === Boolean(event.flags & 1) &&
          (event.type !== 'wasm_dispatch_observation' || decodeNativeWasmObservation(event) !== null) &&
          (!['wasm_guest_dispatch','wasm_guest_invocation'].includes(event.type) || decodeNativeGuestRecord(event) !== null);
      }

      function isBrokerResponse(body) {
        return isPlainObject(body) &&
          Array.isArray(body.events) &&
          isSafeIntegerInRange(body.count, 0, 5000) &&
          body.count === body.events.length &&
          (body.capture_mode === undefined || ['live', 'demo', 'idle'].includes(body.capture_mode)) &&
          (body.broker_connected === undefined || typeof body.broker_connected === 'boolean') &&
          (body.capture_stopped === undefined || typeof body.capture_stopped === 'boolean') &&
          (body.capture_controls_available === undefined || typeof body.capture_controls_available === 'boolean') &&
          (body.stealth_session === undefined || typeof body.stealth_session === 'boolean') &&
          (body.native_stealth === undefined || typeof body.native_stealth === 'boolean') &&
          (body.quiet_mode === undefined || typeof body.quiet_mode === 'boolean') &&
          (body.sequence_gaps === undefined || isCaptureTotal(body.sequence_gaps)) &&
          (body.queue_drops === undefined || isCaptureTotal(body.queue_drops)) &&
          (body.sequence_gaps_saturated === undefined || typeof body.sequence_gaps_saturated === 'boolean') &&
          (body.queue_drops_saturated === undefined || typeof body.queue_drops_saturated === 'boolean') &&
          (body.canvas_render_captures === undefined ||
            (body.capture_mode === 'demo' &&
              Array.isArray(body.canvas_render_captures) &&
              body.canvas_render_captures.length <= 16 &&
              body.canvas_render_captures.every(isCanvasRenderCapture))) &&
          (body.event_window === undefined || isEventWindow(body.event_window)) &&
          (body.network_events === undefined || (Array.isArray(body.network_events) && body.network_events.length <= 5000 &&
            body.network_events.every(event => isBrokerEvent(event) && event.category === 'network' && networkLifecycleTypes.has(event.type)))) &&
          body.events.every(isBrokerEvent);
      }

      function isCanvasRenderArgument(value) {
        return (typeof value === 'number' && Number.isFinite(value) && Math.abs(value) <= 1_000_000) ||
          isBoundedText(value, 1024);
      }

      function isCanvasRenderCall(call) {
        if (!isPlainObject(call) || !Array.isArray(call.arguments) || call.arguments.length > 8 ||
            !call.arguments.every(isCanvasRenderArgument) ||
            (call.property !== undefined && typeof call.property !== 'boolean')) return false;
        if (call.property === true) {
          return canvasReplayProperties.has(call.name) && call.arguments.length === 1;
        }
        return canvasReplayMethods.has(call.name);
      }

      function isCanvasRenderCapture(capture) {
        return isPlainObject(capture) && isBoundedText(capture.id, 128) &&
          capture.context === '2D' && isSafeIntegerInRange(capture.width, 1, 4096) &&
          isSafeIntegerInRange(capture.height, 1, 4096) &&
          capture.width * capture.height <= 16 * 1024 * 1024 &&
          isBoundedText(capture.readback, 64) &&
          (capture.operationHash === null || /^[0-9a-f]{8,64}$/.test(capture.operationHash)) &&
          Array.isArray(capture.calls) && capture.calls.length <= 128 &&
          capture.calls.every(isCanvasRenderCall);
      }

      function isArtifact(artifact) {
        if (!isPlainObject(artifact) ||
          (Object.hasOwn(artifact, 'execution_context_id') !== Object.hasOwn(artifact, 'capture_origin'))) {
          return false;
        }
        if (artifact.kind === 'wasm_guest_adapter' && artifact.capture_origin !== 'native_wasm_guest') return false;
        if (artifact.capture_origin === 'native_wasm_guest' && (!['bytecode_buffer','wasm_guest_adapter'].includes(artifact.kind) ||
          !['frame_id','parent_artifact_id','creator_event_id','execution_context_id'].every(k => isCanonicalInteger(artifact[k],1n,uint64Max)))) return false;
        if (Object.hasOwn(artifact, 'execution_context_id')) {
          if (!isCanonicalInteger(artifact.execution_context_id, 0n, uint64Max) ||
            !artifactCaptureOrigins.has(artifact.capture_origin) ||
            (['dynamic_javascript', 'runtime_allocating_script'].includes(artifact.capture_origin) &&
              (artifact.kind !== 'javascript' || artifact.execution_context_id === '0')) ||
            (artifact.capture_origin.startsWith('webassembly_') &&
              (artifact.kind !== 'wasm' || artifact.execution_context_id === '0')) ||
            (artifact.capture_origin === 'canvas_to_data_url' &&
              (artifact.kind !== 'canvas_data_url' || artifact.execution_context_id !== '0')) ||
            (artifact.capture_origin === 'runtime_typed_array' &&
              (artifact.kind !== 'bytecode_buffer' || artifact.execution_context_id === '0'))) return false;
        }
        return artifact.protocol_version === 1 &&
          artifactIdentifierFields.every(field => isCanonicalInteger(artifact[field], 0n, uint64Max)) &&
          artifactKinds.has(artifact.kind) &&
          typeof artifact.url === 'string' && artifact.url.length > 0 &&
          typeof artifact.mime_type === 'string' && artifact.mime_type.length > 0 &&
          isSafeIntegerInRange(artifact.byte_size, 0, Number.MAX_SAFE_INTEGER) &&
          typeof artifact.sha256 === 'string' && /^[0-9a-f]{64}$/.test(artifact.sha256) &&
          typeof artifact.sensitive === 'boolean' &&
          (!artifact.sensitive || artifact.kind === 'response_body' || artifact.kind === 'canvas_data_url') &&
          (artifact.kind !== 'canvas_data_url' || artifact.sensitive);
      }

      function isArtifactResponse(body) {
        return isPlainObject(body) &&
          Array.isArray(body.artifacts) &&
          isSafeIntegerInRange(body.count, 0, 5000) &&
          body.count === body.artifacts.length &&
          (body.artifact_receiver_configured === undefined || typeof body.artifact_receiver_configured === 'boolean') &&
          (body.artifact_receiver_connected === undefined || typeof body.artifact_receiver_connected === 'boolean') &&
          body.artifacts.every(isArtifact);
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
          ['ambiguous_request', 'missing_event', 'no_predecessor', 'cycle', 'step_limit', 'capture_gap'].includes(gap.reason) &&
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
            !Array.isArray(body.signals) || body.signals.length > 8 ||
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
          if (event.protocol_version < 2 || integerText(event, 'request_id') === '0') continue;
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
        if (event.protocol_version >= 2 && event.type === 'request_started') {
          return resourceTypeFilters.get(event.resource_type) ?? 'other';
        }
        return previous?.type ?? 'other';
      }

      function networkTargetFromPayload(payload, eventType) {
        const source = payload.trim();
        if (!source) return null;
        const methodTarget = source.match(/^([A-Z][A-Z0-9!#$%&'*+.^_`|~-]{0,31})\s+(\S+)$/);
        if (['request_initiated', 'request_started', 'request_redirected'].includes(eventType) && methodTarget) {
          return {method: methodTarget[1], value: methodTarget[2], kind: 'host'};
        }
        // Network payloads intentionally retain only a destination host. A
        // terminal event can arrive without its request-start event, so keep
        // a host-only target when it is independently recognizable. Avoid
        // treating status labels such as "completed" as destinations.
        const host = source.match(/^(?:localhost|(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}|(?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?$/)?.[0];
        return host ? {method: null, value: host, kind: 'host'} : null;
      }

      function requestsFromEvents(events, origin = 'live') {
        const requests = new Map();
        const lifecycleEvents = events.filter(event => event.category === 'network' && networkLifecycleTypes.has(event.type));
        const browserRequestKeys = buildBrowserRequestKeys(lifecycleEvents);
        lifecycleEvents.forEach(event => {
          const payload = decodePayload(event);
          const target = networkTargetFromPayload(payload, event.type);
          const id = requestIdentity(event, browserRequestKeys);
          const previous = requests.get(id);
          const timestamp = integerValue(event, 'monotonic_time_ns');
          const firstTimestamp = previous && previous.firstTimestamp < timestamp ? previous.firstTimestamp : timestamp;
          const lastTimestamp = previous && previous.lastTimestamp > timestamp ? previous.lastTimestamp : timestamp;
          const incomingRank = lifecycleRanks.get(event.type) ?? 0;
          const rank = Math.max(previous?.rank ?? 0, incomingRank);
          // These native proxy dispositions end observation, not the underlying
          // network operation (a redirect may continue in a different loader).
          const interruption = event.protocol_version >= 3 && event.type === 'request_failed' &&
            event.error_code === -3 && ['proxy_destroyed', 'redirect_handoff'].includes(payload);
          const interrupted = previous?.interrupted || interruption;
          const failed = previous?.failed || (!interruption && (event.type === 'request_failed' || (event.protocol_version >= 2 && event.error_code !== 0)));
          const numericStatus = event.protocol_version >= 2 ? event.status_code : 0;
          const previousStatusRank = previous?.statusRank ?? 0;
          const hasNewerStatus = numericStatus > 0 && incomingRank >= previousStatusRank;
          const status = failed
            ? 'failed'
            : interrupted
              ? 'incomplete'
            : hasNewerStatus
              ? numericStatus
              : previous?.status ?? 'pending';
          const targetRank = target && incomingRank >= (previous?.targetRank ?? 0)
            ? incomingRank
            : previous?.targetRank ?? 0;
          const updatesTarget = Boolean(target) && targetRank === incomingRank;
          const terminal = rank >= 5;
          requests.set(id, {
            id,
            path: updatesTarget ? target.value : previous?.path ?? 'Unidentified network event',
            method: updatesTarget && target.method ? target.method : previous?.method ?? 'EVENT',
            status,
            time: terminal ? formatMilliseconds(lastTimestamp - firstTimestamp) : 'pending',
            type: resourceTypeFilter(event, previous, payload),
            origin: ['live', 'demo'].includes(origin) ? origin : 'live',
            targetKind: updatesTarget ? target.kind : previous?.targetKind ?? 'unknown',
            hostOnly: (updatesTarget ? target.kind : previous?.targetKind) === 'host',
            start: 8,
            mid: Math.min(80, 18 + rank * 11),
            end: Math.min(94, 30 + rank * 12),
            event: incomingRank >= (previous?.rank ?? 0) ? event : previous.event,
            events: [...(previous?.events ?? []), event],
            failed,
            interrupted,
            rank,
            statusRank: hasNewerStatus ? incomingRank : previousStatusRank,
            targetRank,
            tabId: event.protocol_version === 3 && event.tab_id > 0
              ? String(event.tab_id) : previous?.tabId ?? '0',
            operation: incomingRank >= (previous?.rank ?? 0) ? event.type : previous.operation,
            firstTimestamp,
            lastTimestamp
          });
        });
        return [...requests.values()];
      }

      function decodeVmFinding(event) {
        if (event.protocol_version < 2 || event.category !== 'vm' ||
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

      function isVmExactEventReference(reference) {
        return vmWorkspaceExact(reference, ['session_id', 'process_id', 'sequence_number']) &&
          isCanonicalInteger(reference.session_id, 1n, uint64Max) &&
          isSafeIntegerInRange(reference.process_id, 1, 0xffffffff) &&
          isCanonicalInteger(reference.sequence_number, 1n, uint64Max);
      }

      function isVmRequestSelection(selection) {
        return vmWorkspaceExact(selection, ['kind', 'request_id', 'root_event', 'edge_semantics']) &&
          selection.kind === 'request' && selection.edge_semantics === 'exact-captured-response-body' &&
          isCanonicalInteger(selection.request_id, 1n, uint64Max) && isVmExactEventReference(selection.root_event);
      }

      function vmRequestSelectionKey(selection) {
        return selection ? JSON.stringify([selection.request_id, selection.root_event.session_id,
          selection.root_event.process_id, selection.root_event.sequence_number]) : null;
      }

      function vmRequestSelection(requests, selectedId) {
        const candidates = requests.filter(request => request.id === selectedId);
        const request = candidates.length === 1 ? candidates[0] : null;
        if (request?.origin !== 'live') return null;
        // Only the actual retained row's unique native start establishes a root.
        // Latest lifecycle events and bare row IDs do not.
        const roots = (request.events ?? []).filter(event => event.type === 'request_started');
        if (roots.length !== 1) return null;
        const root = roots[0];
        if (![2, 3].includes(root.protocol_version) || root.category !== 'network') return null;
        const selection = {kind: 'request', request_id: root.request_id,
          root_event: {session_id: root.session_id, process_id: root.process_id, sequence_number: root.sequence_number},
          edge_semantics: 'exact-captured-response-body'};
        return isVmRequestSelection(selection) ? selection : null;
      }

      function isVmExactRequestLink(link) {
        if (!vmWorkspaceExact(link, ['request_id', 'root_event', 'response_event', 'capture_event', 'relation']) ||
            link.relation !== 'captured-response-body' || !isCanonicalInteger(link.request_id, 1n, uint64Max) ||
            ![link.root_event, link.response_event, link.capture_event].every(isVmExactEventReference)) return false;
        return [link.response_event, link.capture_event].every(event =>
          event.session_id === link.root_event.session_id && event.process_id === link.root_event.process_id) &&
          BigInt(link.root_event.sequence_number) < BigInt(link.response_event.sequence_number) &&
          BigInt(link.response_event.sequence_number) < BigInt(link.capture_event.sequence_number);
      }

      function vmAnalysisMatchesSelection(document, selection) {
        if (!selection) return document.selection === undefined;
        if (!isVmRequestSelection(document.selection) ||
            vmRequestSelectionKey(document.selection) !== vmRequestSelectionKey(selection)) return false;
        // Mixed-runtime conclusions cannot inherit an exact join from one constituent.
        return document.mixed_findings.length === 0 && document.results.every(result =>
          vmWorkspaceDigest(result.artifact_sha256) && result.exact_request_links?.some(link => link.request_id === selection.request_id &&
            vmRequestSelectionKey({request_id: link.request_id, root_event: link.root_event}) === vmRequestSelectionKey(selection)));
      }

      function vmSourceArtifactForFinding(artifacts, finding, selection = null) {
        if (!finding) return null;
        // Sources navigation resolves by artifact ID, so an ID collision must
        // fail before filtering by session/hash could hide the other record.
        const candidates = artifacts.filter(artifact => artifact.artifact_id === finding.sourceArtifactId);
        const artifact = candidates.length === 1 ? candidates[0] : null;
        return artifact && (!selection || (artifact.session_id === selection.root_event.session_id &&
          artifact.sha256 === finding.analysis?.artifact_sha256)) ? artifact : null;
      }

      function vmVisibleFindings(targetState) {
        return [...targetState.lastValidAnalysisFindings,
          ...(targetState.vmAnalysisSelection ? [] : targetState.eventVmFindings)];
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
        if (!isPlainObject(result) || !isCanonicalInteger(result.artifact_id, 0n, uint64Max) ||
            (result.artifact_sha256 !== undefined && !vmWorkspaceDigest(result.artifact_sha256)) ||
            (result.exact_request_links !== undefined && (!Array.isArray(result.exact_request_links) ||
              result.exact_request_links.length > 1 || !result.exact_request_links.every(isVmExactRequestLink))) ||
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
          (document.selection === undefined || isVmRequestSelection(document.selection)) &&
          (document.capture_mode === undefined || vmWorkspaceMode(document.capture_mode)) &&
          (document.inputs?.capture_provenance_digest === undefined ||
            document.inputs.capture_provenance_digest === null ||
            (typeof document.inputs.capture_provenance_digest === 'string' &&
             /^[0-9a-f]{64}$/.test(document.inputs.capture_provenance_digest))) &&
          typeof document.document_digest === 'string' && /^[0-9a-f]{64}$/.test(document.document_digest) &&
          typeof document.profile_digest === 'string' && /^[0-9a-f]{64}$/.test(document.profile_digest) &&
          isPlainObject(document.profile) && document.profile.profile_id === 'anti-bot-vm-detection-v1' &&
          isPlainObject(document.input_coverage) && typeof document.input_coverage.complete === 'boolean' &&
          Array.isArray(document.input_coverage.omissions) &&
          Array.isArray(document.results) && document.results.every(isVmAnalysisResult) &&
          Array.isArray(document.mixed_findings) &&
          document.mixed_findings.every(finding => isPlainObject(finding) &&
            typeof finding.finding_id === 'string' && /^[0-9a-f]{24}$/.test(finding.finding_id) &&
            finding.runtime === 'mixed' && ['candidate', 'likely-vm'].includes(finding.tier) &&
            Array.isArray(finding.artifact_ids) && finding.artifact_ids.length === 2 &&
            finding.artifact_ids.every(id => isCanonicalInteger(id, 0n, uint64Max)));
      }

      function vmFindingsFromAnalysis(document) {
        const investigationId = `analysis:${document.document_digest.slice(0, 12)}`;
        const findings = document.results
          .filter(result => result.status !== 'failed' && result.tier !== 'none')
          .map(result => ({
            findingId: `analysis:${result.finding_id}:artifact:${result.artifact_id}`,
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
          findingId: `analysis:${result.finding_id}:artifacts:${JSON.stringify(result.artifact_ids)}`,
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

      function hasOnlyKeys(value, allowed) {
        return Object.keys(value).every(key => allowed.has(key));
      }

      function isVmOpcodeCoordinate(coordinate) {
        return isPlainObject(coordinate) &&
          hasOnlyKeys(coordinate, new Set(['byte_offset', 'byte_size'])) &&
          isSafeIntegerInRange(coordinate.byte_offset, 0, Number.MAX_SAFE_INTEGER) &&
          isSafeIntegerInRange(coordinate.byte_size, 1, Number.MAX_SAFE_INTEGER);
      }

      // Closed, inert declarations. No string is evaluated or loaded as code.
      function vmWorkspaceExact(value, keys) {
        return isPlainObject(value) && Object.keys(value).length === keys.length &&
          hasOnlyKeys(value, new Set(keys));
      }

      function vmEffectIdentifier(value) {
        return typeof value === 'string' && /^[A-Za-z_][A-Za-z0-9_-]{0,63}$/.test(value);
      }

      function isVmOpcodeEffect(effect) {
        if (!vmWorkspaceExact(effect, ['effect_id', 'evidence_class', 'operation', 'instruction_size',
          'operand_layout', 'reads', 'writes', 'flow', 'atomic_group', 'superoperator']) ||
          !vmEffectIdentifier(effect.effect_id) ||
          !['inferred', 'observed', 'contradicted', 'unknown'].includes(effect.evidence_class) ||
          !['constant', 'add_modulo_2_64', 'add', 'load', 'store', 'branch_zero', 'branch_nonzero',
            'jump', 'call', 'return', 'halt', 'unknown'].includes(effect.operation) ||
          !(effect.instruction_size === null || isSafeIntegerInRange(effect.instruction_size, 1, 65)) ||
          !Array.isArray(effect.operand_layout) || effect.operand_layout.length > 8) return false;
        const operands = new Map();
        for (const operand of effect.operand_layout) {
          if (!vmWorkspaceExact(operand, ['name', 'kind', 'byte_offset', 'byte_size']) ||
            !vmEffectIdentifier(operand.name) || operands.has(operand.name) ||
            !['immediate', 'register', 'stack', 'address', 'target'].includes(operand.kind) ||
            !((operand.byte_offset === null && operand.byte_size === null) ||
              (isSafeIntegerInRange(operand.byte_offset, 1, 64) && [1, 2, 4, 8].includes(operand.byte_size) &&
                effect.instruction_size !== null && operand.byte_offset + operand.byte_size <= effect.instruction_size))) return false;
          operands.set(operand.name, operand);
        }
        const used = new Set();
        for (const operand of operands.values()) {
          if (operand.byte_offset === null) continue;
          for (let offset = operand.byte_offset; offset < operand.byte_offset + operand.byte_size; offset++) {
            if (used.has(offset)) return false;
            used.add(offset);
          }
        }
        const nullableU64 = value => value === null || isCanonicalInteger(value, 0n, uint64Max);
        const cell = value => vmWorkspaceExact(value, ['space', 'index', 'operand', 'value']) &&
          ['register', 'stack', 'memory'].includes(value.space) && nullableU64(value.index) && nullableU64(value.value) &&
          (value.operand === null || operands.has(value.operand)) && !(value.index !== null && value.operand !== null);
        if (![effect.reads, effect.writes].every(rows => Array.isArray(rows) && rows.length <= 16 && rows.every(cell))) return false;
        const flow = effect.flow;
        if (!vmWorkspaceExact(flow, ['kind', 'target_operand', 'target_offset']) ||
          !['next', 'branch', 'jump', 'call', 'return', 'halt', 'unknown'].includes(flow.kind) ||
          !(flow.target_offset === null || isSafeIntegerInRange(flow.target_offset, 0, 0xffffffff)) ||
          !(flow.target_operand === null || ['address', 'target'].includes(operands.get(flow.target_operand)?.kind)) ||
          (flow.target_offset !== null && flow.target_operand !== null) ||
          (!['branch', 'jump', 'call'].includes(flow.kind) && (flow.target_offset !== null || flow.target_operand !== null))) return false;
        const expectedFlow = {constant: 'next', add_modulo_2_64: 'next', add: 'next', load: 'next', store: 'next',
          branch_zero: 'branch', branch_nonzero: 'branch', jump: 'jump', call: 'call', return: 'return', halt: 'halt'};
        if (expectedFlow[effect.operation] && expectedFlow[effect.operation] !== flow.kind) return false;
        const span = value => value === null || (vmWorkspaceExact(value, ['byte_offset', 'byte_size']) &&
          isSafeIntegerInRange(value.byte_offset, 0, 65535) && isSafeIntegerInRange(value.byte_size, 1, 65536) &&
          value.byte_offset + value.byte_size <= 65536);
        return span(effect.atomic_group) && span(effect.superoperator);
      }

      function isVmOpcodeEffects(effects) {
        return Array.isArray(effects) && effects.length <= 8 && effects.every(isVmOpcodeEffect) &&
          new Set(effects.map(effect => effect.effect_id)).size === effects.length;
      }

      function vmUniqueWorkspaceEffect(handler) {
        const effects = handler.effects ?? [];
        const canonical = value => value && typeof value === 'object'
          ? Array.isArray(value) ? value.map(canonical)
            : Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
        const meaning = effect => {
          const {effect_id: ignoredId, evidence_class: ignoredClass, ...body} = effect;
          return JSON.stringify(canonical(body));
        };
        if (effects.some(effect => effect.evidence_class === 'contradicted')) return null;
        const known = effects.filter(effect => ['inferred', 'observed'].includes(effect.evidence_class) && effect.operation !== 'unknown');
        return known.length && known.every(effect => meaning(effect) === meaning(known[0])) ? known[0] : null;
      }

      function isVmByteCoverage(coverage, snapshots, handlers, unknowns) {
        if (!vmWorkspaceExact(coverage, ['complete', 'handler_count', 'retained_snapshot_bytes', 'characterized_bytes',
          'uncharacterized_bytes', 'attributions', 'omissions']) || typeof coverage.complete !== 'boolean' ||
          coverage.handler_count !== handlers.length ||
          !['retained_snapshot_bytes', 'characterized_bytes', 'uncharacterized_bytes'].every(key =>
            isSafeIntegerInRange(coverage[key], 0, 65536)) || !Array.isArray(coverage.attributions) ||
          coverage.attributions.length > 65536 || !Array.isArray(coverage.omissions) || coverage.omissions.length > 256 ||
          !coverage.omissions.every(row => isPlainObject(row) && hasOnlyKeys(row, new Set(['reason', 'detail'])) &&
            isBoundedText(row.reason, 80) && row.reason.length > 0 &&
            (row.detail === undefined || (isBoundedText(row.detail, 240) && row.detail.length > 0)))) return false;
        const previews = new Map();
        let truncated = false;
        for (const snapshot of snapshots) {
          if (previews.has(snapshot.artifact_id)) return false;
          const count = typeof snapshot.preview_hex === 'string' ? snapshot.preview_hex.length / 2 : 0;
          if (count > snapshot.byte_count) return false;
          previews.set(snapshot.artifact_id, {mask: new Uint8Array(count), hex: snapshot.preview_hex});
          truncated ||= snapshot.truncated === true || snapshot.byte_count > count || snapshot.preview_hex === null;
        }
        const starts = new Map(), occupied = new Map();
        const position = (artifact, offset) => `${artifact}:${offset}`;
        for (const range of coverage.attributions) {
          if (!vmWorkspaceExact(range, ['artifact_id', 'byte_offset', 'byte_size', 'opcode', 'kind', 'evidence_class'])) return false;
          const image = previews.get(range.artifact_id);
          const handler = handlers.find(row => row.opcode === range.opcode && row.state !== 'unknown');
          const effect = handler && vmUniqueWorkspaceEffect(handler);
          if (!image || !effect || !isSafeIntegerInRange(range.byte_offset, 0, 4095) ||
            !isSafeIntegerInRange(range.byte_size, 1, 4096) || range.byte_offset + range.byte_size > image.mask.length ||
            !isSafeIntegerInRange(range.opcode, 0, 255) || !['opcode', 'operand'].includes(range.kind) ||
            range.evidence_class !== effect.evidence_class || effect.instruction_size === null) return false;
          if (range.kind !== 'opcode') continue;
          const start = position(range.artifact_id, range.byte_offset);
          if (range.byte_size !== 1 || range.byte_offset + effect.instruction_size > image.mask.length ||
            parseInt(image.hex.slice(range.byte_offset * 2, range.byte_offset * 2 + 2), 16) !== range.opcode) return false;
          if (starts.has(start) && starts.get(start).opcode !== range.opcode) return false;
          starts.set(start, {opcode: range.opcode, effect});
          for (let offset = range.byte_offset; offset < range.byte_offset + effect.instruction_size; offset++) {
            const cell = position(range.artifact_id, offset);
            if (occupied.has(cell) && occupied.get(cell) !== start) return false;
            occupied.set(cell, start);
          }
        }
        for (const range of coverage.attributions) {
          const image = previews.get(range.artifact_id);
          if (range.kind === 'operand') {
            const handler = handlers.find(row => row.opcode === range.opcode && row.state !== 'unknown');
            const effect = vmUniqueWorkspaceEffect(handler);
            if (!effect.operand_layout.some(operand => operand.byte_size === range.byte_size && operand.byte_offset !== null &&
                starts.get(position(range.artifact_id, range.byte_offset - operand.byte_offset))?.opcode === range.opcode)) return false;
          }
          image.mask.fill(1, range.byte_offset, range.byte_offset + range.byte_size);
        }
        let retained = 0, characterized = 0;
        for (const {mask} of previews.values()) {
          retained += mask.length;
          for (const byte of mask) characterized += byte;
        }
        return coverage.retained_snapshot_bytes === retained && coverage.characterized_bytes === characterized &&
          coverage.uncharacterized_bytes === retained - characterized &&
          (!coverage.complete || (retained > 0 && retained === characterized && coverage.omissions.length === 0 &&
            unknowns.length === 0 && !truncated));
      }

      function vmInstructionSuccessors(effect, hex, offset) {
        let target = effect.flow.target_offset;
        if (effect.flow.target_operand !== null) {
          const operand = effect.operand_layout.find(row => row.name === effect.flow.target_operand);
          target = null;
          if (operand?.byte_offset !== null && operand?.byte_size !== null) {
            let value = 0n;
            for (let index = operand.byte_size - 1; index >= 0; index--) {
              const byte = parseInt(hex.slice((offset + operand.byte_offset + index) * 2,
                (offset + operand.byte_offset + index) * 2 + 2), 16);
              if (!Number.isInteger(byte)) return null;
              value = value * 256n + BigInt(byte);
            }
            if (value <= 0xffffffffn) target = Number(value);
          }
        }
        const next = offset + effect.instruction_size;
        switch (effect.flow.kind) {
          case 'next': return [['fallthrough', next]];
          case 'branch': return [['branch_taken', target], ['branch_not_taken', next]];
          case 'jump': return [['jump', target]];
          case 'call': return [['call', target], ['call_continuation', next]];
          case 'halt': return [];
          case 'return': return [['return', null]];
          default: return [['unknown', null]];
        }
      }

      function isVmInstructionTraversal(traversal, snapshots, handlers) {
        if (!vmWorkspaceExact(traversal, ['entry_offsets', 'instructions', 'edges', 'frontier', 'complete']) ||
          typeof traversal.complete !== 'boolean' ||
          !Array.isArray(traversal.entry_offsets) || traversal.entry_offsets.length > 16 ||
          !Array.isArray(traversal.instructions) || traversal.instructions.length > 4096 ||
          !Array.isArray(traversal.edges) || traversal.edges.length > 8192 ||
          !Array.isArray(traversal.frontier) || traversal.frontier.length > 256) return false;
        const images = new Map(snapshots.map(snapshot => [snapshot.artifact_id, snapshot.preview_hex]));
        const key = (artifact, offset) => `${artifact}:${offset}`;
        const instructions = new Map(), occupied = new Set(), expectedEdges = new Set();
        for (const row of traversal.instructions) {
          if (!vmWorkspaceExact(row, ['artifact_id', 'byte_offset', 'byte_size', 'opcode', 'effect_id'])) return false;
          const preview = images.get(row.artifact_id);
          const effect = handlers.filter(handler => handler.opcode === row.opcode)
            .map(vmUniqueWorkspaceEffect).find(candidate => candidate?.effect_id === row.effect_id);
          if (typeof preview !== 'string' || !isSafeIntegerInRange(row.byte_offset, 0, 4095) ||
            !isSafeIntegerInRange(row.byte_size, 1, 65) || row.byte_offset + row.byte_size > preview.length / 2 ||
            !isSafeIntegerInRange(row.opcode, 0, 255) || parseInt(preview.slice(row.byte_offset * 2, row.byte_offset * 2 + 2), 16) !== row.opcode ||
            !effect || effect.instruction_size !== row.byte_size || instructions.has(key(row.artifact_id, row.byte_offset))) return false;
          for (let offset = row.byte_offset; offset < row.byte_offset + row.byte_size; offset++) {
            const cell = key(row.artifact_id, offset);
            if (occupied.has(cell)) return false;
            occupied.add(cell);
          }
          instructions.set(key(row.artifact_id, row.byte_offset), row);
          const successors = vmInstructionSuccessors(effect, preview, row.byte_offset);
          if (successors === null) return false;
          for (const [kind, target] of successors) expectedEdges.add(JSON.stringify([row.artifact_id, row.byte_offset, target, kind]));
        }
        const entries = new Set();
        for (const row of traversal.entry_offsets) {
          if (!vmWorkspaceExact(row, ['artifact_id', 'byte_offset']) || !images.has(row.artifact_id) ||
            !isSafeIntegerInRange(row.byte_offset, 0, 0xffffffff) || entries.has(key(row.artifact_id, row.byte_offset))) return false;
          entries.add(key(row.artifact_id, row.byte_offset));
        }
        const outgoing = new Map();
        for (const row of traversal.edges) {
          if (!vmWorkspaceExact(row, ['artifact_id', 'from_offset', 'to_offset', 'kind']) ||
            !instructions.has(key(row.artifact_id, row.from_offset)) ||
            !(row.to_offset === null || isSafeIntegerInRange(row.to_offset, 0, 0xffffffff)) ||
            !expectedEdges.delete(JSON.stringify([row.artifact_id, row.from_offset, row.to_offset, row.kind]))) return false;
          const from = key(row.artifact_id, row.from_offset);
          if (!outgoing.has(from)) outgoing.set(from, []);
          if (row.to_offset !== null) outgoing.get(from).push(key(row.artifact_id, row.to_offset));
        }
        if (expectedEdges.size) return false;
        const reachable = new Set(), pending = [...entries];
        while (pending.length) {
          const current = pending.pop();
          if (reachable.has(current)) continue;
          reachable.add(current);
          pending.push(...(outgoing.get(current) ?? []));
        }
        if ([...instructions.keys()].some(instruction => !reachable.has(instruction))) return false;
        const reasons = ['snapshot-unavailable', 'static-module-only', 'entry-unavailable', 'effect-unavailable', 'effect-contradiction',
          'unknown-opcode', 'unknown-target', 'snapshot-gap', 'past-snapshot', 'truncated-instruction',
          'overlapping-instruction', 'instruction-limit', 'frontier-limit', 'unsupported-layout'];
        if (!traversal.frontier.every(row => vmWorkspaceExact(row, ['artifact_id', 'byte_offset', 'reason']) &&
          (row.artifact_id === null || isCanonicalInteger(row.artifact_id, 0n, uint64Max)) &&
          (row.byte_offset === null || isSafeIntegerInRange(row.byte_offset, 0, 0xffffffff)) && reasons.includes(row.reason))) return false;
        return !traversal.complete || (entries.size > 0 && traversal.frontier.length === 0 &&
          snapshots.every(snapshot => !snapshot.truncated && typeof snapshot.preview_hex === 'string' &&
            snapshot.byte_count === snapshot.preview_hex.length / 2 &&
            traversal.entry_offsets.some(entry => entry.artifact_id === snapshot.artifact_id)) &&
          [...entries].every(entry => instructions.has(entry)) && traversal.edges.every(row =>
            row.to_offset !== null && instructions.has(key(row.artifact_id, row.to_offset))));
      }

      // Producers before 2.7.0 added physical and guest native counts into
      // sample_count. One br_table execution at an adapter site emits both, so
      // later producers keep each stream separate and sample_count holds only
      // dispatch report records.
      function vmProducerSumsNativeCounts(version) {
        const match = /^([0-9]+)\.([0-9]+)\.[0-9]+$/.exec(version);
        return match !== null && (Number(match[1]) < 2 || (Number(match[1]) === 2 && Number(match[2]) < 7));
      }

      function isVmOpcodeHandler(handler, summed = false) {
        if (!isPlainObject(handler) || !hasOnlyKeys(handler, new Set([
          'opcode', 'handler_index', 'state', 'source', 'label', 'operand_width', 'sample_count', 'notes', 'effects', 'native_wasm_sample_count', 'native_guest_sample_count'
        ])) || !(handler.opcode === null || isSafeIntegerInRange(handler.opcode, 0, 0xffffffff)) ||
          !['observed', 'inferred', 'correlated', 'unknown'].includes(handler.state) ||
          !isVmOpcodeCoordinate(handler.source) || !isVmOpcodeEffects(handler.effects)) return false;
        return (handler.handler_index === undefined || isSafeIntegerInRange(handler.handler_index, 0, 0xffffffff)) &&
          (handler.label === undefined || isBoundedText(handler.label, 80)) &&
          isSafeIntegerInRange(handler.operand_width, 0, 8) &&
          isSafeIntegerInRange(handler.sample_count, 0, Number.MAX_SAFE_INTEGER) && isBoundedText(handler.notes, 240) &&
          (handler.native_guest_sample_count === undefined || isSafeIntegerInRange(handler.native_guest_sample_count,1,summed ? handler.sample_count : Number.MAX_SAFE_INTEGER)) &&
          (handler.native_wasm_sample_count === undefined || isSafeIntegerInRange(handler.native_wasm_sample_count, 1, summed ? handler.sample_count : Number.MAX_SAFE_INTEGER)) &&
          (handler.opcode !== null || (handler.handler_index === undefined && handler.effects.length === 0 &&
            ((handler.state === 'unknown' && handler.sample_count === 0 && handler.native_wasm_sample_count === undefined) ||
             (handler.state === 'observed' && (handler.native_wasm_sample_count ?? 0) + (handler.native_guest_sample_count ?? 0) > 0 &&
              (summed ? (handler.native_wasm_sample_count ?? 0) + (handler.native_guest_sample_count ?? 0) === handler.sample_count : handler.sample_count === 0) &&
              /^br_table(?: f[0-9]+)? default$/.test(handler.label)))));
      }

      function isVmOpcodeSnapshot(snapshot) {
        return isPlainObject(snapshot) && hasOnlyKeys(snapshot, new Set([
          'artifact_id', 'origin', 'sha256', 'byte_count', 'preview_hex', 'truncated', 'unavailable_reason'
        ])) && isCanonicalInteger(snapshot.artifact_id, 0n, uint64Max) && ['runtime-typed-array','native-wasm-guest'].includes(snapshot.origin) &&
          (snapshot.sha256 === undefined || vmWorkspaceDigest(snapshot.sha256)) &&
          isSafeIntegerInRange(snapshot.byte_count, 0, Number.MAX_SAFE_INTEGER) &&
          (snapshot.preview_hex === null || (typeof snapshot.preview_hex === 'string' &&
            /^(?:[0-9a-f]{2})*$/.test(snapshot.preview_hex) && snapshot.preview_hex.length <= 8192)) &&
          typeof snapshot.truncated === 'boolean' && (snapshot.unavailable_reason === null ||
            (isBoundedText(snapshot.unavailable_reason, 240) && snapshot.unavailable_reason.length > 0));
      }

      function isVmCapturedModulePreview(preview, workspace) {
        return workspace.runtime === 'webassembly' && vmWorkspaceExact(preview, [
          'artifact_id', 'byte_offset', 'byte_count', 'preview_hex', 'truncated'
        ]) && preview.artifact_id === workspace.interpreter_artifact_id &&
          isSafeIntegerInRange(preview.byte_offset, 0, Number.MAX_SAFE_INTEGER) &&
          isSafeIntegerInRange(preview.byte_count, 1, Number.MAX_SAFE_INTEGER) &&
          Number.isSafeInteger(preview.byte_offset + preview.byte_count) &&
          workspace.handlers.some(handler => handler.source.byte_offset === preview.byte_offset && handler.source.byte_size === preview.byte_count) &&
          typeof preview.preview_hex === 'string' && /^(?:[0-9a-f]{2})+$/.test(preview.preview_hex) &&
          preview.preview_hex.length <= 8192 && preview.preview_hex.length / 2 <= preview.byte_count &&
          preview.truncated === (preview.preview_hex.length / 2 < preview.byte_count);
      }

      function vmWorkspaceDigest(value) { return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value); }
      function vmWorkspaceMode(value) { return ['native-stealth', 'cdp-attached', 'unknown'].includes(value); }
      function vmSampleEvent(value, caller = false) {
        return vmWorkspaceExact(value, ['session_id', 'process_id', 'sequence_number']) &&
          isCanonicalInteger(value.session_id, 1n, uint64Max) &&
          isCanonicalInteger(value.sequence_number, 1n, uint64Max) && (caller ? value.process_id === 0 : isSafeIntegerInRange(value.process_id, 1, 0xffffffff));
      }
      function vmSampleEventKey(value) { return `${value.session_id}:${value.process_id}:${value.sequence_number}`; }
      function isVmDispatchSample(sample, workspace) {
        const provenance = sample?.provenance;
        return vmWorkspaceExact(sample, ['event', 'instruction_pointer', 'instruction_pointer_units', 'opcode',
          'handler_index', 'sample_index', 'operand_count', 'finding_id', 'investigation_id',
          'interpreter_artifact_id', 'bytecode_artifact_id', 'invocation_id', 'invocation_event',
          ...(provenance === undefined ? [] : ['provenance'])]) &&
          (provenance === undefined || (vmWorkspaceExact(provenance, ['source', 'source_artifact_sha256', 'input_sha256']) &&
            provenance.source === 'caller-supplied' && provenance.source_artifact_sha256 === workspace.source_artifact_sha256 &&
            vmWorkspaceDigest(provenance.input_sha256) && sample.instruction_pointer_units === 'unknown' &&
            sample.invocation_id === null && sample.invocation_event === null && sample.bytecode_artifact_id === '0')) &&
          vmSampleEvent(sample.event, provenance !== undefined) && ['instruction_pointer', 'opcode', 'handler_index', 'sample_index']
            .every(key => isSafeIntegerInRange(sample[key], 0, 0xffffffff)) &&
          isSafeIntegerInRange(sample.operand_count, 0, 255) &&
          ['finding_id', 'investigation_id', 'interpreter_artifact_id'].every(key => isCanonicalInteger(sample[key], 1n, uint64Max)) &&
          isCanonicalInteger(sample.bytecode_artifact_id, 0n, uint64Max) &&
          sample.interpreter_artifact_id === workspace.interpreter_artifact_id &&
          ['byte-offset', 'instruction-index', 'unknown'].includes(sample.instruction_pointer_units) &&
          ((sample.invocation_id === null && sample.invocation_event === null && sample.instruction_pointer_units === 'unknown') ||
            (isCanonicalInteger(sample.invocation_id, 1n, uint64Max) && vmSampleEvent(sample.invocation_event) &&
              sample.invocation_event.session_id === sample.event.session_id && sample.invocation_event.process_id === sample.event.process_id &&
              BigInt(sample.invocation_event.sequence_number) < BigInt(sample.event.sequence_number)));
      }

      function vmStaticSiteEvidenceClass(site) {
        if (site.kind === 'call_indirect') return 'call-indirect-table';
        if (site.kind === 'br_table' && site.arm_count >= 32) return 'handler-table-candidate';
        if (site.kind === 'br_table') return 'cff-helper';
        return null;
      }

      // Samples prove a guest ISA only with real PC units and one handler.
      // Owned effects prove it only when the model is stack or register and a
      // known effect exists. Static arms and identifier spelling do not.
      // Producer 2.9.0 and later: a Wasm arm proves a guest opcode only at a
      // site the structural classification calls an interpreter candidate.
      function vmInterpreterArm(workspace, handler) {
        const classification = workspace.runtime === 'webassembly' ? workspace.dispatch_classification : undefined;
        if (classification === undefined) return true;
        return classification.sites.some(site => site.location.byte_offset === handler.source.byte_offset &&
          site.role === 'interpreter-candidate');
      }

      function vmGuestOpcodeIsaProven(workspace) {
        const uses = new Map();
        for (const handler of workspace.handlers) {
          if (handler.opcode !== null) uses.set(handler.opcode, (uses.get(handler.opcode) ?? 0) + 1);
        }
        if (workspace.samples.some(sample =>
          ['instruction-index', 'byte-offset'].includes(sample.instruction_pointer_units) &&
          uses.get(sample.opcode) === 1 &&
          workspace.handlers.some(handler => handler.opcode === sample.opcode && handler.state === 'observed' &&
            handler.sample_count > 0 && vmInterpreterArm(workspace, handler)))) return true;
        return ['stack', 'register'].includes(workspace.model) &&
          workspace.handlers.some(handler => vmUniqueWorkspaceEffect(handler));
      }

      function vmWorkspaceEvidenceClass(workspace) {
        if (vmGuestOpcodeIsaProven(workspace)) return 'guest-opcode-isa';
        const candidates = workspace.dispatch_inventory?.candidates;
        if (Array.isArray(candidates)) {
          const classes = candidates.map(site => site.evidence_class);
          if (classes.includes('handler-table-candidate')) return 'handler-table-candidate';
          if (classes.includes('call-indirect-table')) return 'call-indirect-table';
          if (classes.includes('cff-helper')) return 'cff-helper';
        }
        if (workspace.handlers.some(handler => handler.opcode !== null)) return 'handler-table-candidate';
        return null;
      }

      function vmSupportedMachineState(workspace) {
        let stack = false;
        let maxRegister = null;
        for (const handler of workspace.handlers) {
          for (const effect of handler.effects ?? []) {
            for (const cell of [...(effect.reads ?? []), ...(effect.writes ?? [])]) {
              if (cell.space === 'stack') stack = true;
              if (cell.space === 'register' && cell.index !== null && isCanonicalInteger(cell.index, 0n, 65535n)) {
                const index = Number(cell.index);
                if (maxRegister === null || index > maxRegister) maxRegister = index;
              }
            }
          }
        }
        if (!stack && maxRegister === null) return null;
        return {register_count: maxRegister === null ? null : maxRegister + 1, stack_observed: stack ? true : null};
      }

      function vmMachineStateMatches(workspace) {
        const supported = vmSupportedMachineState(workspace);
        if (supported === null) return workspace.machine_state === undefined;
        return vmWorkspaceExact(workspace.machine_state, ['register_count', 'stack_observed']) &&
          workspace.machine_state.register_count === supported.register_count &&
          workspace.machine_state.stack_observed === supported.stack_observed;
      }

      function isVmHandlerCluster(cluster) {
        return vmWorkspaceExact(cluster, ['target', 'selector_count', 'selectors']) &&
          isSafeIntegerInRange(cluster.target, 0, 4294967295) &&
          isSafeIntegerInRange(cluster.selector_count, 1, 4294967295) &&
          Array.isArray(cluster.selectors) && cluster.selectors.length <= 32 &&
          cluster.selectors.length <= cluster.selector_count &&
          cluster.selectors.every(value => isSafeIntegerInRange(value, 0, 4294967295)) &&
          new Set(cluster.selectors).size === cluster.selectors.length;
      }

      function isVmHandlerTables(tables) {
        if (!Array.isArray(tables) || tables.length === 0 || tables.length > 12 || !tables.every(isVmHandlerTable)) return false;
        return true;
      }

      // Element rows from producer 2.9.0 and later list each active segment
      // with its evaluated placement; older documents omit the field.
      function isVmElementSegments(segments) {
        return Array.isArray(segments) && segments.length <= 64 && segments.every(segment =>
          vmWorkspaceExact(segment, ['segment_index', 'placement', 'offset', 'global_index', 'entry_count']) &&
          isSafeIntegerInRange(segment.segment_index, 0, 4294967295) &&
          ['placed', 'relative', 'out-of-range', 'unresolved'].includes(segment.placement) &&
          (['placed', 'out-of-range'].includes(segment.placement) ? isSafeIntegerInRange(segment.offset, 0, 4294967295) : segment.offset === null) &&
          (segment.placement === 'relative' ? isSafeIntegerInRange(segment.global_index, 0, 4294967295) : segment.global_index === null) &&
          isSafeIntegerInRange(segment.entry_count, 0, 4294967295));
      }

      function isVmHandlerTable(table) {
        const keys = ['kind', 'evidence_class', 'function_index', 'byte_offset', 'byte_size',
          'table_index', 'arm_count', 'entry_count', 'unique_target_count', 'default_target', 'clusters',
          'omitted_cluster_count'];
        if (isPlainObject(table) && table.segments !== undefined) {
          if (table.kind !== 'element' || !isVmElementSegments(table.segments)) return false;
          keys.push('segments');
        }
        if (!vmWorkspaceExact(table, keys) || !['br_table', 'call_indirect', 'element'].includes(table.kind) ||
          !isSafeIntegerInRange(table.omitted_cluster_count, 0, 4294967295) ||
          !Array.isArray(table.clusters) || table.clusters.length > 1024 ||
          !table.clusters.every(isVmHandlerCluster)) return false;
        const counted = table.clusters.reduce((sum, cluster) => sum + cluster.selector_count, 0);
        if (table.kind === 'br_table') {
          const expected = table.arm_count >= 32 ? 'handler-table-candidate' : 'cff-helper';
          return table.evidence_class === expected &&
            isSafeIntegerInRange(table.function_index, 0, Number.MAX_SAFE_INTEGER) &&
            isSafeIntegerInRange(table.byte_offset, 0, Number.MAX_SAFE_INTEGER) &&
            isSafeIntegerInRange(table.byte_size, 1, 16777216) &&
            table.table_index === null &&
            isSafeIntegerInRange(table.arm_count, 0, 4294967295) &&
            table.entry_count === table.arm_count &&
            isSafeIntegerInRange(table.unique_target_count, 0, 4294967295) &&
            isSafeIntegerInRange(table.default_target, 0, 4294967295) &&
            table.clusters.length + table.omitted_cluster_count === table.unique_target_count &&
            (table.omitted_cluster_count === 0 ? counted === table.arm_count : counted <= table.arm_count);
        }
        if (table.kind === 'call_indirect') {
          return table.evidence_class === 'call-indirect-table' &&
            isSafeIntegerInRange(table.function_index, 0, Number.MAX_SAFE_INTEGER) &&
            isSafeIntegerInRange(table.byte_offset, 0, Number.MAX_SAFE_INTEGER) &&
            isSafeIntegerInRange(table.byte_size, 1, 16777216) &&
            (table.table_index === null || isSafeIntegerInRange(table.table_index, 0, 4294967295)) &&
            table.arm_count === null && table.entry_count === null && table.unique_target_count === null &&
            table.default_target === null && table.clusters.length === 0 && table.omitted_cluster_count === 0;
        }
        return table.evidence_class === 'call-indirect-table' &&
          table.function_index === null && table.byte_offset === null && table.byte_size === null &&
          isSafeIntegerInRange(table.table_index, 0, 4294967295) &&
          table.arm_count === null &&
          isSafeIntegerInRange(table.entry_count, 0, 4294967295) &&
          isSafeIntegerInRange(table.unique_target_count, 0, 4294967295) &&
          table.default_target === null &&
          table.clusters.length + table.omitted_cluster_count === table.unique_target_count &&
          (table.omitted_cluster_count === 0 ? counted === table.entry_count : counted <= table.entry_count);
      }

      const vmDispatchKinds = ['switch_on_value', 'handler_table', 'compare_chain', 'export_per_role', 'threaded', 'unknown'];
      const vmSelectorSources = ['cursor_index', 'cursor_pointer', 'frame_slot', 'call_argument', 'handler_address', 'constant', 'unknown'];
      const vmDispatchInstructions = ['br_table', 'call_indirect', 'return_call_indirect', 'i32.eq ladder', 'export', 'switch', 'indexed call', 'if ladder', 'self call'];

      // The role is derived from the three axes; a document cannot assert it.
      function vmDispatchRole(site) {
        const selects = ['switch_on_value', 'handler_table', 'compare_chain'].includes(site.dispatch_kind);
        if (selects && site.repeats === 'loop' && ['cursor_index', 'cursor_pointer', 'frame_slot'].includes(site.selector_source)) return 'interpreter-candidate';
        if (selects && site.repeats === 'once' && site.selector_source === 'call_argument') return 'multiplexer';
        return 'other';
      }

      function isVmDispatchClassificationSite(site, artifactId, runtime) {
        if (!vmWorkspaceExact(site, ['artifact_id', 'dispatch_kind', 'selector_source', 'repeats', 'role', 'confidence',
          'instruction', 'location', 'selector', 'arm_count', 'loop', 'buffer_kind', 'table']) ||
          site.artifact_id !== artifactId || !vmDispatchKinds.includes(site.dispatch_kind) ||
          !vmSelectorSources.includes(site.selector_source) || !['loop', 'once', 'unknown'].includes(site.repeats) ||
          site.role !== vmDispatchRole(site) || site.confidence !== 'structural' ||
          !vmDispatchInstructions.includes(site.instruction) ||
          !(site.arm_count === null || isSafeIntegerInRange(site.arm_count, 0, 4294967295)) ||
          ![null, 'string', 'typed-array', 'array', 'unknown'].includes(site.buffer_kind)) return false;
        const location = site.location;
        const javascript = runtime === 'javascript';
        if (!vmWorkspaceExact(location, ['function_index', 'function_body_offset', 'byte_offset', 'byte_size', 'line', 'column']) ||
          !isSafeIntegerInRange(location.byte_offset, 0, Number.MAX_SAFE_INTEGER) ||
          !isSafeIntegerInRange(location.byte_size, 1, Number.MAX_SAFE_INTEGER) ||
          !(location.function_body_offset === null || isSafeIntegerInRange(location.function_body_offset, 0, Number.MAX_SAFE_INTEGER)) ||
          (javascript ? location.function_index !== null || !isSafeIntegerInRange(location.line, 1, Number.MAX_SAFE_INTEGER) ||
            !isSafeIntegerInRange(location.column, 1, Number.MAX_SAFE_INTEGER)
            : !(location.function_index === null || isSafeIntegerInRange(location.function_index, 0, 4294967295)) ||
              location.line !== null || location.column !== null)) return false;
        if (!vmWorkspaceExact(site.selector, ['expression', 'byte_offset']) ||
          typeof site.selector.expression !== 'string' || site.selector.expression.length === 0 ||
          !isBoundedText(site.selector.expression, 160) ||
          !(site.selector.byte_offset === null || isSafeIntegerInRange(site.selector.byte_offset, 0, Number.MAX_SAFE_INTEGER))) return false;
        if (site.loop !== null && (!vmWorkspaceExact(site.loop, ['byte_offset', 'byte_size']) ||
          !isSafeIntegerInRange(site.loop.byte_offset, 0, Number.MAX_SAFE_INTEGER) ||
          !isSafeIntegerInRange(site.loop.byte_size, 1, Number.MAX_SAFE_INTEGER))) return false;
        if (site.table === null) return true;
        const table = site.table;
        const count = value => value === null || isSafeIntegerInRange(value, 0, Number.MAX_SAFE_INTEGER);
        return vmWorkspaceExact(table, ['table_index', 'type_index', 'populated_slot_count', 'matching_slot_count', 'matching_slots']) &&
          isSafeIntegerInRange(table.table_index, 0, 4294967295) && isSafeIntegerInRange(table.type_index, 0, 4294967295) &&
          count(table.populated_slot_count) && count(table.matching_slot_count) &&
          (table.matching_slots === null || (Array.isArray(table.matching_slots) && table.matching_slots.length <= 32 &&
            table.matching_slots.every(slot => isSafeIntegerInRange(slot, 0, 4294967295)) &&
            new Set(table.matching_slots).size === table.matching_slots.length));
      }

      function isVmDispatchClassification(classification, workspace) {
        if (!vmWorkspaceExact(classification, ['classification_version', 'site_count', 'omitted_site_count', 'role_counts', 'kind_counts', 'sites', 'omissions']) ||
          !Array.isArray(classification.omissions) || classification.omissions.length > 16 ||
          !classification.omissions.every(omission => isPlainObject(omission) &&
            hasOnlyKeys(omission, new Set(['reason', 'detail', 'omitted_records'])) &&
            ['classification-work-limit', 'classification-region-limit', 'classification-unavailable'].includes(omission.reason) &&
            typeof omission.detail === 'string' && omission.detail.length > 0 && isBoundedText(omission.detail, 240) &&
            (omission.omitted_records === undefined || isSafeIntegerInRange(omission.omitted_records, 1, Number.MAX_SAFE_INTEGER))) ||
          classification.classification_version !== 1 ||
          !isSafeIntegerInRange(classification.site_count, 0, 4294967295) ||
          !Array.isArray(classification.sites) || classification.sites.length > 256 ||
          classification.omitted_site_count !== classification.site_count - classification.sites.length ||
          !vmWorkspaceExact(classification.role_counts, ['interpreter-candidate', 'multiplexer', 'other']) ||
          !vmWorkspaceExact(classification.kind_counts, vmDispatchKinds)) return false;
        const sum = counts => Object.values(counts).reduce((total, value) =>
          isSafeIntegerInRange(value, 0, 4294967295) && total !== null ? total + value : null, 0);
        if (sum(classification.role_counts) !== classification.site_count ||
          sum(classification.kind_counts) !== classification.site_count) return false;
        return classification.sites.every(site =>
          isVmDispatchClassificationSite(site, workspace.interpreter_artifact_id, workspace.runtime));
      }

      function isVmDispatchInventory(inventory) {
        if (!vmWorkspaceExact(inventory, ['ranking_version', 'site_count', 'br_table_count', 'call_indirect_count',
          'omitted_site_count', 'selected_byte_offset', 'candidates']) || inventory.ranking_version !== 1 ||
          !['site_count', 'br_table_count', 'call_indirect_count', 'omitted_site_count'].every(key =>
            isSafeIntegerInRange(inventory[key], 0, 1000000)) ||
          inventory.site_count !== inventory.br_table_count + inventory.call_indirect_count ||
          !Array.isArray(inventory.candidates) || inventory.candidates.length > 256 ||
          inventory.site_count !== inventory.candidates.length + inventory.omitted_site_count) return false;
        const offsets = new Set();
        for (const site of inventory.candidates) {
          if (!vmWorkspaceExact(site, ['kind', 'function_index', 'byte_offset', 'byte_size', 'function_body_offset',
            'function_body_size', 'arm_count', 'unique_target_count', 'element_fanout', 'loop_depth', 'ip_like',
            'structural_score', 'classification', 'evidence_class']) ||
            !['br_table', 'call_indirect'].includes(site.kind) || typeof site.ip_like !== 'boolean' ||
            !['function_index', 'byte_offset', 'function_body_offset', 'loop_depth', 'structural_score'].every(key =>
              isSafeIntegerInRange(site[key], 0, Number.MAX_SAFE_INTEGER)) ||
            !['byte_size', 'function_body_size'].every(key => isSafeIntegerInRange(site[key], 1, 16777216)) ||
            site.byte_offset < site.function_body_offset ||
            !Number.isSafeInteger(site.byte_offset + site.byte_size) ||
            !Number.isSafeInteger(site.function_body_offset + site.function_body_size) ||
            site.byte_offset + site.byte_size > site.function_body_offset + site.function_body_size ||
            (site.kind === 'br_table'
              ? !isSafeIntegerInRange(site.arm_count, 0, 4294967295) || site.element_fanout !== null ||
                !isSafeIntegerInRange(site.unique_target_count, 1, site.arm_count + 1)
              : site.arm_count !== null || site.unique_target_count !== null ||
                (site.element_fanout !== null && !isSafeIntegerInRange(site.element_fanout, 0, 4294967295))) ||
            site.classification !== (site.kind === 'call_indirect' ? 'indirect-handler-candidate'
              : site.kind === 'br_table' && site.arm_count < 32 ? 'cff-helper-candidate' : 'dispatch-candidate') ||
            site.evidence_class !== vmStaticSiteEvidenceClass(site) ||
            offsets.has(site.byte_offset)) return false;
          offsets.add(site.byte_offset);
        }
        return inventory.selected_byte_offset === null ||
          inventory.candidates.some(site => site.byte_offset === inventory.selected_byte_offset && site.loop_depth > 0);
      }

      // Producers since 2.8.0 copy the accepted event's monotonic time onto each
      // native row; older documents omit it.
      function vmNativeRowKeys(row, keys) {
        return row?.monotonic_time_ns === undefined ? keys : [...keys, 'monotonic_time_ns'];
      }
      function vmNativeRowTimeValid(row) {
        return row.monotonic_time_ns === undefined || isCanonicalInteger(row.monotonic_time_ns, 0n, uint64Max);
      }
      function isNativeWasmObservation(row, workspace) {
        if (!vmWorkspaceExact(row, vmNativeRowKeys(row, ['event','function_index','module_byte_offset','selector','table_count','sample_index','selected_arm','is_default'])) ||
          !vmSampleEvent(row.event) || !vmNativeRowTimeValid(row) || !isSafeIntegerInRange(row.function_index,0,16777215) ||
          !isSafeIntegerInRange(row.module_byte_offset,8,16777215) || !isSafeIntegerInRange(row.selector,0,0xffffffff) ||
          !isSafeIntegerInRange(row.table_count,0,16777215) || !isSafeIntegerInRange(row.sample_index,0,15) ||
          row.selected_arm !== Math.min(row.selector,row.table_count) || row.is_default !== (row.selector >= row.table_count)) return false;
        const site = workspace.dispatch_inventory?.candidates.find(site => site.byte_offset === row.module_byte_offset);
        return site ? site.kind === 'br_table' && site.function_index === row.function_index && site.arm_count === row.table_count
          : (workspace.dispatch_inventory?.omitted_site_count ?? 0) > 0;
      }
      function isNativeGuestSample(row, workspace) {
        const keys = ['event','invocation_event','invocation_id','instance_id','parent_invocation_id','function_index',
          'module_byte_offset','selector','table_count','selected_arm','is_default','sample_index','instruction_pointer',
          'instruction_pointer_units','raw_pc_bits','pc_local_index','pc_adjustment','pc_value_type','pc_subtract_memory_base',
          'memory_index','memory_base','memory_length','opcode','opcode_width','opcode_endian','adapter_artifact_id',
          'adapter_sha256','bytecode_artifact_id','bytecode_sha256','interpretation','host_import_call_offsets'];
        if (!vmWorkspaceExact(row,vmNativeRowKeys(row,keys)) || !vmNativeRowTimeValid(row) || !vmSampleEvent(row.event) || !vmSampleEvent(row.invocation_event) ||
          row.event.session_id !== row.invocation_event.session_id || row.event.process_id !== row.invocation_event.process_id ||
          BigInt(row.invocation_event.sequence_number) >= BigInt(row.event.sequence_number) ||
          !['instance_id','invocation_id','adapter_artifact_id','bytecode_artifact_id'].every(k => isCanonicalInteger(row[k],1n,uint64Max)) ||
          !isCanonicalInteger(row.parent_invocation_id,0n,uint64Max) || row.parent_invocation_id === row.invocation_id ||
          !isCanonicalInteger(row.raw_pc_bits,0n,uint64Max) || !isCanonicalInteger(row.memory_base,0n,uint64Max) ||
          !isCanonicalInteger(row.pc_adjustment,int64Min,int64Max,true) ||
          !['i32','i64'].includes(row.pc_value_type) || typeof row.pc_subtract_memory_base !== 'boolean' ||
          !['pc_local_index','memory_index','selector','opcode'].every(k => isSafeIntegerInRange(row[k],0,0xffffffff)) ||
          !isSafeIntegerInRange(row.function_index,0,16777215) || !isSafeIntegerInRange(row.module_byte_offset,8,16777215) ||
          !isSafeIntegerInRange(row.table_count,0,16777215) || !isSafeIntegerInRange(row.sample_index,0,255) ||
          row.selected_arm !== Math.min(row.selector,row.table_count) || row.is_default !== (row.selector >= row.table_count) ||
          !isSafeIntegerInRange(row.memory_length,1,65536) || !isSafeIntegerInRange(row.instruction_pointer,0,65535) ||
          row.instruction_pointer_units !== 'byte-offset' || ![1,2,4].includes(row.opcode_width) ||
          !['little','big'].includes(row.opcode_endian) || row.opcode > 2 ** (8 * row.opcode_width) - 1 || row.instruction_pointer + row.opcode_width > row.memory_length ||
          !vmWorkspaceDigest(row.adapter_sha256) || !vmWorkspaceDigest(row.bytecode_sha256) ||
          !['explicit-adapter','verified-dataflow'].includes(row.interpretation) ||
          new Set([row.adapter_artifact_id,row.bytecode_artifact_id,workspace.interpreter_artifact_id]).size !== 3 ||
          !Array.isArray(row.host_import_call_offsets) || row.host_import_call_offsets.length > 64 ||
          !row.host_import_call_offsets.every(n => isSafeIntegerInRange(n,8,16777215)) ||
          new Set(row.host_import_call_offsets).size !== row.host_import_call_offsets.length) return false;
        const raw = BigInt(row.raw_pc_bits), base = BigInt(row.memory_base), adjusted = raw + BigInt(row.pc_adjustment);
        if ((row.pc_value_type === 'i32' && raw > 0xffffffffn) || adjusted < 0n || adjusted > uint64Max ||
          base + BigInt(row.memory_length) > uint64Max ||
          adjusted - (row.pc_subtract_memory_base ? base : 0n) !== BigInt(row.instruction_pointer) ||
          (row.interpretation === 'verified-dataflow' && row.selector !== row.opcode)) return false;
        const site = workspace.dispatch_inventory?.candidates.find(s => s.byte_offset === row.module_byte_offset);
        return site ? site.kind === 'br_table' && site.function_index === row.function_index && site.arm_count === row.table_count
          : (workspace.dispatch_inventory?.omitted_site_count ?? 0) > 0;
      }

      function nativeWasmMatchesHandler(row, handler) {
        return row.module_byte_offset === handler.source.byte_offset &&
          (row.is_default ? handler.opcode === null && /^br_table(?: f[0-9]+)? default$/.test(handler.label)
            : handler.opcode === row.selector);
      }

      function isVmOpcodeWorkspace(workspace, summed = false) {
        if (!isPlainObject(workspace) || !hasOnlyKeys(workspace, new Set([
          'interpreter_artifact_id', 'bytecode_artifact_id', 'finding_id', 'model', 'handlers', 'snapshots', 'coverage',
          'unknowns', 'runtime', 'source_artifact_sha256', 'capture_mode', 'samples', 'sample_count', 'traversal', 'captured_module_preview', 'dispatch_inventory',
          'dispatch_classification', 'evidence_class', 'machine_state', 'handler_tables', 'native_wasm_observations', 'native_wasm_observation_count', 'native_guest_samples', 'native_guest_sample_count'
        ])) || !isCanonicalInteger(workspace.interpreter_artifact_id, 0n, uint64Max) ||
          (workspace.bytecode_artifact_id !== undefined && !isCanonicalInteger(workspace.bytecode_artifact_id, 0n, uint64Max)) ||
          typeof workspace.finding_id !== 'string' || !/^[0-9a-f]{24}$/.test(workspace.finding_id) ||
          !['stack', 'register', 'unknown'].includes(workspace.model) ||
          !['javascript', 'webassembly'].includes(workspace.runtime) || !vmWorkspaceDigest(workspace.source_artifact_sha256) ||
          !vmWorkspaceMode(workspace.capture_mode) || !Array.isArray(workspace.handlers) || workspace.handlers.length > 1024 ||
          !workspace.handlers.every(handler => isVmOpcodeHandler(handler, summed)) || !Array.isArray(workspace.snapshots) || workspace.snapshots.length > 16 ||
          !workspace.snapshots.every(isVmOpcodeSnapshot) ||
          (workspace.dispatch_inventory !== undefined && (workspace.runtime !== 'webassembly' ||
            !isVmDispatchInventory(workspace.dispatch_inventory))) ||
          (workspace.handler_tables !== undefined && (workspace.runtime !== 'webassembly' ||
            !isVmHandlerTables(workspace.handler_tables))) ||
          (workspace.dispatch_classification !== undefined &&
            !isVmDispatchClassification(workspace.dispatch_classification, workspace)) ||
          !vmMachineStateMatches(workspace) ||
          (workspace.evidence_class ?? null) !== vmWorkspaceEvidenceClass(workspace) ||
          (workspace.captured_module_preview !== undefined && !isVmCapturedModulePreview(workspace.captured_module_preview, workspace)) ||
          !Array.isArray(workspace.unknowns) || workspace.unknowns.length > 256 ||
          !workspace.unknowns.every(value => isBoundedText(value, 240) && value.length > 0) ||
          new Set(workspace.unknowns).size !== workspace.unknowns.length ||
          !Array.isArray(workspace.samples) || workspace.samples.length > 4096 ||
          !workspace.samples.every(sample => isVmDispatchSample(sample, workspace)) ||
          new Set(workspace.samples.map(sample => vmSampleEventKey(sample.event))).size !== workspace.samples.length ||
          !isSafeIntegerInRange(workspace.sample_count, workspace.samples.length, Number.MAX_SAFE_INTEGER) ||
          !isVmByteCoverage(workspace.coverage, workspace.snapshots, workspace.handlers, workspace.unknowns) ||
          !isVmInstructionTraversal(workspace.traversal, workspace.snapshots, workspace.handlers)) return false;
        const guestRows = workspace.native_guest_samples ?? [];
        const guestCount = workspace.native_guest_sample_count ?? 0;
        if ((workspace.native_guest_samples === undefined) !== (workspace.native_guest_sample_count === undefined) ||
          (workspace.native_guest_samples !== undefined && workspace.runtime !== 'webassembly') ||
          !Array.isArray(guestRows) || guestRows.length > 4096 || !guestRows.every(row => isNativeGuestSample(row,workspace)) ||
          !isSafeIntegerInRange(guestCount,guestRows.length,summed ? workspace.sample_count : Number.MAX_SAFE_INTEGER)) return false;
        const guestTruncated = guestCount > guestRows.length;
        if (guestTruncated !== workspace.coverage.omissions.some(row => row.reason === 'native-guest-sample-limit') ||
          (guestTruncated && guestRows.length !== 4096)) return false;
        const nativeRows = workspace.native_wasm_observations ?? [];
        const nativeCount = workspace.native_wasm_observation_count ?? 0;
        if ((workspace.native_wasm_observations === undefined) !== (workspace.native_wasm_observation_count === undefined) ||
          (workspace.native_wasm_observations !== undefined && workspace.runtime !== 'webassembly') ||
          !Array.isArray(nativeRows) || nativeRows.length > 4096 || !nativeRows.every(row => isNativeWasmObservation(row,workspace)) ||
          !isSafeIntegerInRange(nativeCount,nativeRows.length,summed ? workspace.sample_count : Number.MAX_SAFE_INTEGER) ||
          new Set([...workspace.samples,...nativeRows,...guestRows].map(row => vmSampleEventKey(row.event))).size !== workspace.samples.length + nativeRows.length + guestRows.length) return false;
        if (nativeRows.some(row => workspace.handlers.filter(handler => nativeWasmMatchesHandler(row,handler)).length > 1)) return false;
        const nativeTruncated = nativeCount > nativeRows.length;
        if (nativeTruncated !== workspace.coverage.omissions.some(row => row.reason === 'native-wasm-observation-limit') ||
          (nativeTruncated && nativeRows.length !== 4096)) return false;
        const legacyCount = summed ? workspace.sample_count - nativeCount - guestCount : workspace.sample_count;
        if (legacyCount < workspace.samples.length) return false;
        const truncated = legacyCount > workspace.samples.length;
        if (truncated !== workspace.coverage.omissions.some(row => row.reason === 'sample-limit') ||
          (truncated && workspace.samples.length !== 4096)) return false;
        const opcodeUses = new Map();
        for (const handler of workspace.handlers) {
          if (handler.opcode !== null) opcodeUses.set(handler.opcode, (opcodeUses.get(handler.opcode) ?? 0) + 1);
        }
        const opcodes = new Set();
        let total = 0;
        for (const handler of workspace.handlers) {
          if (workspace.runtime === 'javascript' && handler.opcode !== null && opcodes.has(handler.opcode)) return false;
          if (handler.opcode !== null) opcodes.add(handler.opcode);
          const retained = workspace.samples.filter(sample => sample.opcode === handler.opcode).length;
          const repeatedSelector = workspace.runtime === 'webassembly' && handler.opcode !== null &&
            opcodeUses.get(handler.opcode) > 1;
          // A br_table selector index is local to that instruction. One sample does not
          // prove that every site with the same number handled the guest opcode.
          const nativeRetained = nativeRows.filter(row => nativeWasmMatchesHandler(row,handler)).length;
          const handlerNative = handler.native_wasm_sample_count ?? 0;
          const guestRetained = guestRows.filter(row => nativeWasmMatchesHandler(row,handler)).length;
          const handlerGuest = handler.native_guest_sample_count ?? 0;
          if (handlerGuest > guestCount || handlerGuest < guestRetained || (!guestTruncated && handlerGuest !== guestRetained) ||
            (handlerGuest > 0 && (workspace.runtime !== 'webassembly' || handler.state !== 'observed'))) return false;
          if (handlerNative > nativeCount || handlerNative < nativeRetained || (!nativeTruncated && handlerNative !== nativeRetained) ||
            (handlerNative > 0 && (workspace.runtime !== 'webassembly' || handler.state !== 'observed'))) return false;
          const handlerLegacy = summed ? handler.sample_count - handlerNative - handlerGuest : handler.sample_count;
          if (repeatedSelector) {
            if (handlerLegacy !== 0 || (handlerNative === 0 && handlerGuest === 0 && handler.state === 'observed')) return false;
          } else if (handlerLegacy < retained || (!truncated && handlerLegacy !== retained)) return false;
          if (!truncated && handlerNative === 0 && handlerGuest === 0 && handler.state === 'observed' && retained > 0 &&
            !workspace.samples.some(sample => sample.opcode === handler.opcode && sample.provenance === undefined)) return false;
          total += handler.sample_count;
        }
        if (workspace.samples.some(sample => sample.provenance !== undefined) &&
          !workspace.coverage.omissions.some(row => row.reason === 'caller-samples-unverified')) return false;
        if (!truncated && nativeCount === 0 && guestCount === 0 && workspace.samples.length > 0 && workspace.samples.every(sample => sample.provenance !== undefined) &&
          !workspace.coverage.omissions.some(row => ['sampler-unavailable', 'dispatch-sample-budget'].includes(row.reason))) return false;
        return total <= workspace.sample_count;
      }

      function isVmOpcodeWorkspaceDocument(document) {
        if (!vmWorkspaceExact(document, ['contract_version', 'document_kind', 'producer', 'profile_digest',
          'analysis_digest', 'inputs', 'workspaces', 'summary', 'document_digest', 'capture_mode']) ||
          document.contract_version !== 2 || document.document_kind !== 'vm-opcode-workspace' ||
          !vmWorkspaceExact(document.producer, ['id', 'version']) || document.producer.id !== 'origin-trace-vm-opcode' ||
          !isBoundedText(document.producer.version, 32) || document.producer.version.length === 0 ||
          !vmWorkspaceMode(document.capture_mode) || !vmWorkspaceDigest(document.profile_digest) ||
          !vmWorkspaceDigest(document.analysis_digest) || !vmWorkspaceDigest(document.document_digest) ||
          !vmWorkspaceExact(document.inputs, ['artifact_manifest_digest', 'event_store_digest', 'capture_provenance_digest']) ||
          !Object.values(document.inputs).every(value => value === null || vmWorkspaceDigest(value)) ||
          !Array.isArray(document.workspaces) || document.workspaces.length > 256 || !document.workspaces.every(workspace => isVmOpcodeWorkspace(workspace, vmProducerSumsNativeCounts(document.producer.version))) ||
          !vmWorkspaceExact(document.summary, ['workspace_count', 'handler_count', 'snapshot_count', 'sample_count', 'unknown_count'])) return false;
        const counts = {workspace_count: document.workspaces.length, handler_count: 0, snapshot_count: 0, sample_count: 0, unknown_count: 0};
        for (const workspace of document.workspaces) {
          counts.handler_count += workspace.handlers.length; counts.snapshot_count += workspace.snapshots.length;
          counts.sample_count += workspace.sample_count; counts.unknown_count += workspace.unknowns.length;
        }
        return Object.entries(counts).every(([key, value]) => Number.isSafeInteger(value) && document.summary[key] === value);
      }

      function vmOpcodeWorkspaceForFinding(document, finding) {
        if (!document || !finding) return null;
        const analysis = finding.analysis;
        const sourceHash = analysis?.artifact_sha256 ?? finding.sourceArtifactSha256;
        const matches = document.workspaces.filter(workspace =>
          workspace.interpreter_artifact_id === finding.sourceArtifactId &&
          (sourceHash === undefined || workspace.source_artifact_sha256 === sourceHash));
        if (analysis && analysis.runtime !== 'mixed') {
          if (analysis.artifact_id !== finding.sourceArtifactId) return null;
          const exact = matches.filter(workspace => workspace.finding_id === analysis.finding_id);
          return exact.length === 1 ? exact[0] : null;
        }
        if (analysis?.runtime === 'mixed') {
          // A mixed row explicitly selects its primary artifact, not the mixed finding hash.
          return analysis.artifact_ids?.[0] === finding.sourceArtifactId && matches.length === 1 ? matches[0] : null;
        }
        if (finding.findingId?.startsWith('analysis:')) {
          // Legacy authored projections may omit the analysis object; never fall back by hash alone.
          const key = /^analysis:([0-9a-f]{24})(?::artifact:([0-9]+))?$/.exec(finding.findingId);
          if (!key || (key[2] !== undefined && key[2] !== finding.sourceArtifactId)) return null;
          const exact = matches.filter(workspace => workspace.finding_id === key[1]);
          return exact.length === 1 ? exact[0] : null;
        }
        // Native findings carry an explicit source artifact but a separate finding identity.
        return matches.length === 1 ? matches[0] : null;
      }

      function vmNativeWasmPositionText(row) {
        return `Native Wasm byte ${row.module_byte_offset} · function ${row.function_index} · selector ${row.selector} · ${row.is_default ? 'default arm' : `arm ${row.selected_arm}`} · guest PC unknown`;
      }
      function vmNativeGuestPositionText(row) {
        return `PC ${row.instruction_pointer} bytes · opcode ${row.opcode} · instance ${row.instance_id} · ${row.interpretation}`;
      }
      function vmNativeIsGuestRow(row) {
        return row?.instance_id !== undefined && row?.instruction_pointer !== undefined;
      }
      // Workspace rows carry the exact native event identity but not its time.
      // Time comes only from the same retained event; it is never estimated.
      function vmNativeRowIdentityText(row, events = []) {
        const operation = vmNativeIsGuestRow(row) ? 'wasm_guest_dispatch' : 'wasm_dispatch_observation';
        const event = row?.event;
        if (!isPlainObject(event)) return `native probe · vm/${operation} · event identity unavailable`;
        const key = [event.session_id, event.process_id, event.sequence_number].map(String);
        const retained = Array.isArray(events) ? events.find(candidate => candidate &&
          [candidate.session_id, candidate.process_id, candidate.sequence_number].map(String).every((value, index) => value === key[index])) : null;
        // Prefer the producer-recorded time; older documents only have it while
        // the event is still in the retained window.
        const time = typeof row.monotonic_time_ns === 'string' ? row.monotonic_time_ns : retained?.monotonic_time_ns;
        return `${time === undefined ? 'time outside retained event window' : `time ${time} ns`} · session ${key[0]} · process ${key[1]} · seq ${key[2]} · native probe · vm/${operation}`;
      }
      // Older documents may omit a per-kind count; never subtract a malformed one.
      function vmNativeAcceptedCount(value, retained) {
        return Number.isSafeInteger(value) && value >= retained ? value : retained;
      }
      function vmOpcodeSamplePositions(samples) {
        return samples.slice(0, 4).map(sample => sample.instruction_pointer_units === 'byte-offset' && sample.instance_id !== undefined ? `PC ${sample.instruction_pointer} bytes · instance ${sample.instance_id}` : sample.module_byte_offset !== undefined ? vmNativeWasmPositionText(sample) :
          `${sample.provenance ? 'Caller-reported ' : ''}PC ${sample.instruction_pointer} (${sample.instruction_pointer_units}) · handler ${sample.handler_index} · bytecode ${sample.bytecode_artifact_id}`);
      }

      // Physical and guest records can describe the same execution, so the
      // displayed count is the largest single stream, never their sum.
      function vmHandlerExecutionCount(handler) {
        return Math.max(handler.sample_count, handler.native_wasm_sample_count ?? 0, handler.native_guest_sample_count ?? 0);
      }

      function vmOpcodeHandlerRow(workspace, handler) {
        const retainedSamples = [...workspace.samples.filter(sample => sample.opcode === handler.opcode),
          ...(workspace.native_guest_samples ?? []).filter(row => nativeWasmMatchesHandler(row,handler)),
          ...(workspace.native_wasm_observations ?? []).filter(row => nativeWasmMatchesHandler(row,handler))];
        return {
          key: `${handler.opcode}:${handler.handler_index ?? ''}:${handler.source.byte_offset}`,
          opcode: handler.opcode === null ? 'unknown' : `0x${handler.opcode.toString(16).padStart(2, '0')}`,
          label: handler.label || (handler.opcode === null ? 'Unbound dispatch arm' : `handler ${handler.handler_index ?? handler.opcode}`),
          state: handler.state,
          samples: vmHandlerExecutionCount(handler),
          operandWidth: handler.operand_width,
          retainedSamples,
          positions: vmOpcodeSamplePositions(retainedSamples),
          retainedPositions: retainedSamples.length,
          notes: handler.notes || 'No handler notes recorded.',
          source: `${handler.source.byte_offset} + ${handler.source.byte_size} bytes`
        };
      }

      // Several WASM selectors can cite one dispatch instruction. The workspace
      // still keeps every selector; only the visible row collapses.
      function vmSharedDispatchRow(workspace, handlers) {
        const first = handlers[0];
        const offset = first.source.byte_offset;
        const size = first.source.byte_size;
        const opcodes = new Set(handlers.map(handler => handler.opcode));
        const retainedSamples = [...workspace.samples.filter(sample => opcodes.has(sample.opcode)),
          ...(workspace.native_guest_samples ?? []).filter(row => handlers.some(handler => nativeWasmMatchesHandler(row,handler))),
          ...(workspace.native_wasm_observations ?? []).filter(row => handlers.some(handler => nativeWasmMatchesHandler(row,handler)))];
        const notes = first.notes || 'No handler notes recorded.';
        const sameWidth = handlers.every(handler => handler.operand_width === first.operand_width);
        const brTable = handlers.every(handler => typeof handler.label === 'string' && handler.label.startsWith('br_table'));
        const selectorCount = handlers.filter(handler => handler.opcode !== null).length;
        const defaultCount = handlers.length - selectorCount;
        const countLabel = brTable && defaultCount ? `${selectorCount} selectors + default` : `${handlers.length} selectors`;
        return {
          key: `span:${offset}:${size}`,
          opcode: 'shared',
          label: `${brTable ? 'br_table' : 'Shared dispatch'} · ${countLabel}`,
          state: handlers.every(handler => handler.state === 'inferred') ? 'inferred' : 'unknown',
          samples: handlers.reduce((total, handler) => total + vmHandlerExecutionCount(handler), 0),
          operandWidth: sameWidth ? first.operand_width : 0,
          retainedSamples,
          positions: vmOpcodeSamplePositions(retainedSamples),
          retainedPositions: retainedSamples.length,
          notes: `${notes} ${countLabel} share this instruction and are not separate handler bodies.`,
          source: `${offset} + ${size} bytes`
        };
      }

      function vmOpcodeRows(workspace) {
        if (workspace.runtime !== 'webassembly') return workspace.handlers.map(handler => vmOpcodeHandlerRow(workspace, handler));
        const groups = new Map();
        for (const handler of workspace.handlers) {
          const span = `${handler.source.byte_offset}:${handler.source.byte_size}`;
          const group = groups.get(span);
          if (group) group.push(handler);
          else groups.set(span, [handler]);
        }
        return [...groups.values()].map(handlers =>
          handlers.length > 1 ? vmSharedDispatchRow(workspace, handlers) : vmOpcodeHandlerRow(workspace, handlers[0]));
      }

      function retainVmOpcodeWorkspaceOnFailure(targetState, status, errorMessage) {
        targetState.vmOpcodeWorkspaceStatus = status;
        targetState.vmOpcodeWorkspaceError = errorMessage;
        targetState.vmOpcodeWorkspace = targetState.lastValidVmOpcodeWorkspace;
      }

      function isWasmInspection(value, source) {
        return value?.schema === 'wasm-inspection-v1' && value.artifact_id === source.artifact_id &&
          value.sha256 === source.sha256 && value.byte_size === source.byte_size &&
          ['decoded', 'partial'].includes(value.status) && Array.isArray(value.rows) && value.rows.length <= 8192 &&
          typeof value.notice === 'string' && value.notice.length <= 512 &&
          Array.isArray(value.omissions) && value.omissions.length <= 128 && value.omissions.every(v => typeof v === 'string' && v.length <= 512) &&
          ['sections', 'defined_functions', 'imported_functions', 'instructions'].every(key => Number.isSafeInteger(value[key]) && value[key] >= 0) &&
          value.rows.every(row => row && typeof row.kind === 'string' && row.kind.length <= 32 &&
            typeof row.text === 'string' && row.text.length <= 540 && !/[\r\n\u2028\u2029]/u.test(row.text) && typeof row.text_truncated === 'boolean' &&
            Number.isSafeInteger(row.byte_offset) && row.byte_offset >= 0 && row.byte_offset <= value.byte_size &&
            Number.isSafeInteger(row.byte_end) && row.byte_end >= row.byte_offset && row.byte_end <= value.byte_size &&
            (row.function_index === null || (Number.isSafeInteger(row.function_index) && row.function_index >= 0)));
      }

      function retainVmAnalysisOnFailure(targetState, status, errorMessage) {
        targetState.vmAnalysisStatus = status;
        targetState.vmAnalysisError = errorMessage;
        targetState.vmFindings = vmVisibleFindings(targetState);
      }

      function isVmOwnedExperimentRecord(row) {
        const exact = vmWorkspaceExact;
        const dec = value => isCanonicalInteger(value, 0n, uint64Max);
        const id = value => typeof value === 'string' && /^[A-Za-z0-9_:-]{1,128}$/.test(value);
        const digest = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
        const inputs = value => exact(value, ['left','right']) && dec(value.left) && dec(value.right);
        const effect = value => exact(value,['operation','value','next_pc','branch_taken']) &&
          ['constant','add_modulo_2_64','load','store','branch_zero','branch_nonzero','jump','halt','unknown'].includes(value.operation) &&
          dec(value.value) && dec(value.next_pc) && (value.branch_taken === null || typeof value.branch_taken === 'boolean');
        if (!exact(row,['request','effect_digest','fixture_revision','status','independent','observed','reason']) ||
            !digest(row.effect_digest) || row.fixture_revision !== 1 ||
            !['pending','confirmed','mismatch','unsupported','unknown'].includes(row.status) ||
            !['execution-not-yet-complete','completion-unverified','fixed-owned-inputs-only','agreement-for-listed-inputs-only',
              'expected-or-observed-effect-differs','native-execution-or-disposal-unconfirmed'].includes(row.reason)) return false;
        const r=row.request;
        if (!exact(r,['command_id','fixture','workspace_digest','source_artifact_sha256','interpreter_artifact_id','finding_id','opcode','effect_id','inputs','expected']) ||
            !id(r.command_id) || !['stack','register'].includes(r.fixture) || !digest(r.workspace_digest) || !digest(r.source_artifact_sha256) ||
            !isCanonicalInteger(r.interpreter_artifact_id,1n,uint64Max) || !id(r.finding_id) || ![2,7].includes(r.opcode) || !id(r.effect_id) || !inputs(r.inputs) || !effect(r.expected)) return false;
        const same = (a,b) => a && b && a.operation === b.operation && a.value === b.value && a.next_pc === b.next_pc && a.branch_taken === b.branch_taken;
        const prediction = r.inputs.left === '7' && r.inputs.right === '5' ? {operation:r.opcode===2?'add_modulo_2_64':'branch_nonzero',value:'12',next_pc:r.opcode===2?'3':'10',branch_taken:r.opcode===2?null:true} : null;
        if (prediction === null ? row.independent !== null : !effect(row.independent) || !same(prediction,row.independent)) return false;
        const o=row.observed;
        if (o !== null && (!exact(o,['backend_instance_id','session_id','run_id','run_generation','invocation_id','record_sequence','build_id','program_sha256','opcode','handler_index','pc_before','instruction_pointer_units','inputs','effect']) ||
            !['backend_instance_id','session_id','run_id'].every(k=>id(o[k])) || !['run_generation','invocation_id','record_sequence','pc_before'].every(k=>dec(o[k])) ||
            !digest(o.build_id) || !digest(o.program_sha256) || o.opcode!==r.opcode || o.handler_index!==r.opcode ||
            o.pc_before!==(r.opcode===2?'2':'8') || o.instruction_pointer_units!=='instruction-index' || !inputs(o.inputs) || !effect(o.effect))) return false;
        return row.status !== 'confirmed' || Boolean(o && same(r.expected,prediction) && same(o.effect,prediction) && o.inputs.left===r.inputs.left && o.inputs.right===r.inputs.right);
      }

      function sameVmOwnedExperimentRequest(left, right) {
        const fields=['command_id','fixture','workspace_digest','source_artifact_sha256','interpreter_artifact_id','finding_id','opcode','effect_id'];
        return Boolean(left && right && fields.every(key=>left[key]===right[key]) && left.inputs && right.inputs &&
          ['left','right'].every(key=>left.inputs[key]===right.inputs[key]) && left.expected && right.expected &&
          ['operation','value','next_pc','branch_taken'].every(key=>left.expected[key]===right.expected[key]));
      }

      function isVmHostLinksDocument(document, workspaceDocument) {
        if (!vmWorkspaceExact(document, ['contract_version', 'document_kind', 'workspace_document_digest', 'workspaces', 'document_digest']) ||
          document.contract_version !== 1 || document.document_kind !== 'vm-host-links' ||
          !vmWorkspaceDigest(document.document_digest) || !vmWorkspaceDigest(document.workspace_document_digest) ||
          document.workspace_document_digest !== workspaceDocument?.document_digest ||
          !Array.isArray(document.workspaces) || document.workspaces.length > 256) return false;
        const categories = ['canvas', 'webgl', 'web_audio', 'navigator', 'permissions', 'storage', 'webrtc', 'network', 'runtime'];
        const types = ['api_call', 'property_read', 'request_started', 'request_initiated', 'request_redirected', 'response_started', 'response_completed', 'request_completed', 'request_failed'];
        const omissions = ['dispatch-samples-unavailable', 'dispatch-sample-retention-limit', 'host-link-limit', 'host-events-unavailable'];
        const sources = new Set(); let total = 0;
        for (const row of document.workspaces) {
          if (!vmWorkspaceExact(row, ['interpreter_artifact_id', 'source_artifact_sha256', 'links', 'omissions']) ||
            sources.has(row.interpreter_artifact_id) || !Array.isArray(row.links) || row.links.length > 256 ||
            !Array.isArray(row.omissions) || row.omissions.length > 4 || new Set(row.omissions).size !== row.omissions.length ||
            !row.omissions.every(reason => omissions.includes(reason))) return false;
          sources.add(row.interpreter_artifact_id);
          const workspace = workspaceDocument.workspaces.find(item => item.interpreter_artifact_id === row.interpreter_artifact_id &&
            item.source_artifact_sha256 === row.source_artifact_sha256);
          if (!workspace) return false;
          const hosts = new Set();
          for (const link of row.links) {
            if (!vmWorkspaceExact(link, ['host_event', 'category', 'type', 'state', 'reason', 'guest_position']) ||
              !vmSampleEvent(link.host_event) || !categories.includes(link.category) || !types.includes(link.type) ||
              !['observed', 'correlated', 'unknown'].includes(link.state)) return false;
            const key = vmSampleEventKey(link.host_event);
            if (hosts.has(key)) return false;
            hosts.add(key);
            const position = link.guest_position;
            if (link.state !== 'observed') {
              if (position !== null || !['dispatch-samples-unavailable', 'guest-position-unproven'].includes(link.reason)) return false;
              continue;
            }
            if (link.reason !== 'direct-dispatch-parent' || !vmWorkspaceExact(position, ['sample_event', 'invocation_event',
              'invocation_id', 'instruction_pointer', 'instruction_pointer_units']) || !vmSampleEvent(position.sample_event) ||
              !vmSampleEvent(position.invocation_event) || !isCanonicalInteger(position.invocation_id, 1n, uint64Max) ||
              !['byte-offset', 'instruction-index'].includes(position.instruction_pointer_units) ||
              !isSafeIntegerInRange(position.instruction_pointer, 0, 0xffffffff) ||
              position.sample_event.session_id !== link.host_event.session_id || position.sample_event.process_id !== link.host_event.process_id ||
              BigInt(position.sample_event.sequence_number) >= BigInt(link.host_event.sequence_number) ||
              ![...workspace.samples,...(workspace.native_guest_samples ?? [])].some(sample => sample.provenance === undefined && (sample.interpretation === undefined || sample.interpretation === 'verified-dataflow') && (sample.host_import_call_offsets === undefined || sample.host_import_call_offsets.length > 0) && vmSampleEventKey(sample.event) === vmSampleEventKey(position.sample_event) &&
                sample.invocation_event && vmSampleEventKey(sample.invocation_event) === vmSampleEventKey(position.invocation_event) &&
                sample.invocation_id === position.invocation_id && sample.instruction_pointer === position.instruction_pointer &&
                sample.instruction_pointer_units === position.instruction_pointer_units)) return false;
          }
          total += row.links.length;
        }
        return total <= 4096;
      }

      function vmBrowserInternalSourceUrl(url) {
        return typeof url === 'string' && /^(?:about|brave|chrome|chrome-extension|chrome-search|chrome-untrusted|devtools|edge):/i.test(url);
      }

      function vmBoundedSourceUrl(url) {
        return typeof url === 'string' ? url.slice(0, 2048) : '';
      }

      function vmHostLinkOmissionText(reason) {
        return {
          'dispatch-samples-unavailable': 'No retained native dispatch samples. guest_position stays null. Static handlers can still be listed. This is the missing sampler, not an empty workspace.',
          'dispatch-sample-retention-limit': 'Accepted samples were dropped from the retained set, so those samples cannot prove a guest position.',
          'host-link-limit': 'Host-link retention reached its cap. Further same-scope events are omitted.',
          'host-events-unavailable': 'No host event shared this interpreter session, navigation, and frame.'
        }[reason] ?? String(reason ?? '');
      }

      function vmHostLinkLine(link) {
        const event = link?.host_event ?? {};
        const position = link?.guest_position;
        const positionText = position && typeof position === 'object' && Number.isInteger(position.instruction_pointer)
          ? `guest_position PC ${position.instruction_pointer} (${position.instruction_pointer_units})`
          : 'guest_position null';
        return `${link?.category}/${link?.type} · event ${event.session_id}:${event.process_id}:${event.sequence_number} · state ${link?.state} · reason ${link?.reason} · ${positionText}`;
      }

      function vmHostLinksView(row) {
        if (!row) {
          return {
            bound: false,
            staticOnly: false,
            headline: 'Guest position unknown: no proven host-to-dispatch link is available.',
            omissionLines: [],
            lines: []
          };
        }
        const omissions = Array.isArray(row.omissions) ? row.omissions : [];
        const links = Array.isArray(row.links) ? row.links : [];
        const staticOnly = omissions.includes('dispatch-samples-unavailable') && links.every(link =>
          link?.state === 'unknown' && link?.reason === 'dispatch-samples-unavailable' &&
          (link.guest_position === null || link.guest_position === undefined));
        let headline;
        if (staticOnly && links.length > 0) {
          headline = 'Static only. Reason dispatch-samples-unavailable. guest_position is null on every row. Same session, navigation, and frame is correlation, not a proven Wasm loader and not request-value provenance. Static handlers stay listed. This is the missing sampler, not an empty workspace. Session sources lists stored artifacts only.';
        } else if (staticOnly) {
          headline = 'Static only. Reason dispatch-samples-unavailable. guest_position is null because no native dispatch samples were retained, and no host event shared this session, navigation, and frame (host-events-unavailable). This is not an empty workspace.';
        } else if (links.length === 0) {
          headline = 'Guest position unknown: no proven host-to-dispatch link is available.';
        } else {
          headline = 'A guest position is shown only for an exact retained dispatch parent. Other rows stay guest_position null. Shared scope is correlation, not request-value provenance.';
        }
        return {
          bound: true,
          staticOnly,
          headline,
          omissionLines: omissions.map(reason => ({reason, detail: vmHostLinkOmissionText(reason)})),
          lines: links.map(vmHostLinkLine)
        };
      }

      function vmStaticSampleNoticeText(workspace) {
        if (!workspace || !Array.isArray(workspace.coverage?.omissions)) return null;
        if (workspace.coverage.omissions.some(row => row?.reason === 'caller-samples-unverified')) {
          return 'Caller-supplied dispatch reports are unverified, not native runtime observations. They do not confirm handlers, guest PC units or host-call causality. Native sampler omissions remain where no native samples were retained.';
        }
        if ((workspace.native_guest_sample_count ?? 0) > 0) return 'Native guest state observed. Actual local values and bytecode snapshots are interpreted by the retained adapter. Only verified guest semantics and exact synchronous host parents resolve guest positions; asynchronous causality and request-value provenance remain unproven.';
        if ((workspace.native_wasm_observation_count ?? 0) > 0) return 'Native Wasm dispatch observed. Exact physical br_table site and selector are retained; guest PC, guest opcode ISA and host-call causality remain unknown.';
        if (workspace.sample_count !== 0) return null;
        if (!workspace.coverage.omissions.some(row => row?.reason === 'sampler-unavailable')) return null;
        return 'Static only. sampler-unavailable. No dispatch samples were retained, so host links stay reason dispatch-samples-unavailable and guest_position null. Static handlers remain listed. This is the missing sampler, not an empty workspace. Real samples without rebuilding the browser come from reb-native-vm-fixture --emit-dispatch-events-v1.';
      }

      function vmSessionSourceGapText() {
        return 'No page or challenge JavaScript artifact is stored for this session. /api/artifacts lists receiver blobs only. A response is stored as JavaScript when the network tee sees a script resource type or a JavaScript MIME type. application/wasm and compile, module, or instantiate hooks store Wasm, often at a synthetic wasm:// URL, without copying the loader script. Fetch or XHR bodies with another MIME type, and generated source that misses the allocating-script hook, stay out of the store. chrome:// and other browser-UI scripts are noise, not the challenge loader.';
      }

      function vmSessionSourceJoin({artifacts, interpreterArtifactId, sessionId} = {}) {
        const scoped = sessionId !== undefined && sessionId !== null && String(sessionId).length > 0;
        const wanted = String(sessionId ?? '');
        const stored = [];
        if (scoped && Array.isArray(artifacts)) {
          for (const artifact of artifacts) {
            if (!artifact || String(artifact.session_id) !== wanted || typeof artifact.artifact_id !== 'string' || artifact.artifact_id.length === 0) continue;
            const url = vmBoundedSourceUrl(artifact.url);
            const kind = typeof artifact.kind === 'string' ? artifact.kind : 'unknown';
            const internal = kind === 'javascript' && vmBrowserInternalSourceUrl(url);
            const role = artifact.artifact_id === interpreterArtifactId ? 'interpreter'
              : kind === 'wasm' ? 'wasm'
              : kind === 'javascript' && !internal ? 'page-javascript'
              : internal ? 'browser-noise'
              : 'other';
            stored.push({
              record: 'artifact',
              role,
              artifact_id: artifact.artifact_id,
              kind,
              url,
              capture_origin: typeof artifact.capture_origin === 'string' ? artifact.capture_origin.slice(0, 64) : 'unknown',
              byte_size: artifact.byte_size,
              relation: role === 'interpreter'
                ? 'Selected interpreter module. Stored artifact bytes. Not a guest position.'
                : 'Same evidence session. Shared session is correlation, not proof this file loaded or called the interpreter, and not a guest position.'
            });
          }
        }
        const pageJavaScriptCount = stored.filter(row => row.role === 'page-javascript' ||
          (row.role === 'interpreter' && row.kind === 'javascript' && !vmBrowserInternalSourceUrl(row.url))).length;
        return {
          scoped,
          stored,
          pageJavaScriptCount,
          omission: scoped && pageJavaScriptCount === 0 ? 'no-page-javascript-artifact' : null,
          gapText: scoped && pageJavaScriptCount === 0 ? vmSessionSourceGapText() : null
        };
      }
