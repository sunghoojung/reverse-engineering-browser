// Browser instrumentation is native-only. This viewer never attaches a debugger.
const sourceFactsPanel = createSourceFactsPanel({
  getSource: selectedSource, onNavigate: revealSourceFactRange,
  openSidebar() { state.sourceSidebarOpen = true; renderSourceSidebar(); }
});
const capturedExportPanel = installCapturedExportDialog({
  getRun: () => null, contextKey: () => null, getRunCapture: () => null,
  notice: message => investigationNotice(message)
});
      const evidencePackagePanel = createEvidencePackagePanel({getContext: () => ({
        requestId: evidenceRequestKey(state.requests.find(request => request.id === state.selectedRequestId)),
        requestEvents: state.requests.find(request => request.id === state.selectedRequestId)?.events ?? [],
        events: state.events, artifacts: state.artifacts, eventsLimited: state.eventsLimited
      })});

      const evidenceWorkspace = createEvidenceWorkspace({
        getContext: () => ({request: state.requests.find(request => request.id === state.selectedRequestId),
          events: state.events, artifacts: state.artifacts, eventsLimited: state.eventsLimited,
          error: state.eventFailureKind, mode: state.sessionMode}),
        packagePanel: evidencePackagePanel,
        onTrace: () => typeof openInvestigation === 'function'
          ? openInvestigation({kind: 'trace', identity: investigationRequestIdentity(state.requests.find(request => request.id === state.selectedRequestId))})
          : showScreen('backtrace'),
        onRequest: () => typeof openInvestigation === 'function'
          ? openInvestigation({kind: 'request', identity: investigationRequestIdentity(state.requests.find(request => request.id === state.selectedRequestId))})
          : showScreen('traffic'),
        onSource: identity => typeof openInvestigation === 'function'
          ? openInvestigation({kind: 'artifact', identity, relation: 'Exact artifact referenced by the selected native record. Producer and value flow are not established.'})
          : false,
        canOpenSource: () => typeof openInvestigation === 'function'
      });

      // Ordinary refresh/navigation keeps file drafts in the owned component.
      // A departing document disposes it; BFCache suspension only retires work.
      window.addEventListener('pagehide', event => {
        evidenceWorkspace.setVisible(false);
        if (!event.persisted) evidenceWorkspace.disposeComparison();
      });
      window.addEventListener('pageshow', () => {
        evidenceWorkspace.setVisible(!document.querySelector('#screen-evidence').hidden);
      });

      function acceptVmOpcodeWorkspace(document, requestId, etag = null, embedded = false) {
        if (!isVmOpcodeWorkspaceDocument(document)) {
          retainVmOpcodeWorkspaceOnFailure(state, 'malformed', 'Malformed opcode workspace response');
          return false;
        }
        state.vmOpcodeWorkspace = document;
        state.lastValidVmOpcodeWorkspace = document;
        state.vmOpcodeWorkspaceStatus = 'ready';
        state.vmOpcodeWorkspaceError = null;
        state.vmOpcodeWorkspaceRequestId = requestId;
        state.vmOpcodeWorkspaceEtag = etag;
        state.vmOpcodeWorkspaceEmbedded = embedded;
        return true;
      }

      async function refreshVmOpcodeWorkspace(analysisDocument, requestId, current = () => true) {
        const embedded = analysisDocument?.opcode_workspace;
        if (embedded !== undefined) {
          state.vmOpcodeWorkspaceRequestId = requestId;
          state.vmOpcodeWorkspaceEmbedded = true;
          acceptVmOpcodeWorkspace(embedded, requestId, null, true);
          return;
        }
        if (analysisDocument === null && requestId === state.vmOpcodeWorkspaceRequestId &&
            state.vmOpcodeWorkspaceEmbedded) return;
        const sameSelection = requestId === state.vmOpcodeWorkspaceRequestId;
        const headers = sameSelection && state.vmOpcodeWorkspaceEtag
          ? { 'If-None-Match': state.vmOpcodeWorkspaceEtag }
          : {};
        if (!sameSelection) state.vmOpcodeWorkspaceEtag = null;
        state.vmOpcodeWorkspaceEmbedded = false;
        state.vmOpcodeWorkspaceStatus = 'loading';
        try {
          const response = await fetch('/api/analysis/vm/opcodes', { cache: 'no-store', headers });
          if (!current()) return;
          if (response.status === 304) {
            state.vmOpcodeWorkspaceStatus = 'ready';
            state.vmOpcodeWorkspaceError = null;
            return;
          }
          if (!response.ok) throw new Error(`Opcode workspace returned ${response.status}`);
          const document = await response.json();
          if (!current()) return;
          acceptVmOpcodeWorkspace(document, requestId, response.headers.get('ETag'));
        } catch (error) {
          if (!current()) return;
          retainVmOpcodeWorkspaceOnFailure(
            state,
            error instanceof SyntaxError ? 'malformed' : 'unavailable',
            error.message
          );
          state.vmOpcodeWorkspaceRequestId = requestId;
          if (state.vmOpcodeWorkspaceStatus === 'unavailable') state.vmOpcodeWorkspaceEtag = null;
        }
      }

      async function refreshVmHostLinks() {
        const workspace = state.vmOpcodeWorkspace;
        if (!workspace || state.vmOpcodeWorkspaceEmbedded) return;
        const generation = ++state.vmHostLinksGeneration;
        try {
          const response = await fetch('/api/analysis/vm/host-links', {cache: 'no-store'});
          if (!response.ok) throw new Error(`Host links returned ${response.status}`);
          const document = await response.json();
          if (generation !== state.vmHostLinksGeneration || state.vmOpcodeWorkspace?.document_digest !== workspace.document_digest) return;
          if (!isVmHostLinksDocument(document, workspace)) throw new TypeError('Malformed or stale host links');
          state.vmHostLinks = document;
          state.vmHostLinksStatus = 'ready';
        } catch {
          if (generation === state.vmHostLinksGeneration && state.vmOpcodeWorkspace?.document_digest === workspace.document_digest) {
            state.vmHostLinksStatus = 'unavailable';
          }
        }
      }

      async function refreshVmAnalysis(selection = state.vmAnalysisSelection ?? null) {
        if (location.protocol === 'file:') return;
        if (selection !== null && !isVmRequestSelection(selection)) return;
        const key = vmRequestSelectionKey(selection);
        const sameSelection = key === vmRequestSelectionKey(state.vmAnalysisSelection);
        const generation = state.vmAnalysisGeneration = (state.vmAnalysisGeneration ?? 0) + 1;
        const current = () => generation === state.vmAnalysisGeneration &&
          key === vmRequestSelectionKey(state.vmAnalysisSelection);
        state.vmAnalysisSelection = selection;
        state.vmAnalysisRequestId = selection?.request_id ?? null;
        if (!sameSelection) {
          state.vmAnalysisEtag = null;
          state.vmAnalysisDocument = null;
          state.lastValidAnalysisFindings = [];
          state.selectedVmFindingId = null;
          state.vmFindings = vmVisibleFindings(state);
          state.vmOpcodeWorkspace = state.lastValidVmOpcodeWorkspace = null;
          state.vmOpcodeWorkspaceRequestId = null;
          state.vmOpcodeWorkspaceEtag = null;
          state.vmOpcodeWorkspaceEmbedded = false;
          state.vmOpcodeWorkspaceStatus = 'loading';
          state.vmOpcodeWorkspaceError = null;
          state.vmHostLinks = null;
          state.vmHostLinksStatus = 'loading';
          state.vmHostLinksGeneration += 1;
          state.selectedVmHandlerKey = null;
        }
        const query = selection ? `?${new URLSearchParams({request_id: selection.request_id,
          session_id: selection.root_event.session_id, root_process_id: String(selection.root_event.process_id),
          root_sequence_number: selection.root_event.sequence_number})}` : '';
        const headers = state.vmAnalysisEtag ? {'If-None-Match': state.vmAnalysisEtag} : {};
        state.vmAnalysisStatus = 'loading';
        state.vmAnalysisError = null;
        if (!sameSelection) renderVmLab();
        try {
          const response = await fetch(`/api/analysis/vm${query}`, {cache: 'no-store', headers});
          if (!current()) return;
          if (response.status === 304) {
            if (selection && (!state.vmAnalysisDocument || !vmAnalysisMatchesSelection(state.vmAnalysisDocument, selection))) {
              throw new TypeError('VM analysis cache has no matching selection');
            }
            state.vmAnalysisStatus = 'ready';
            await refreshVmOpcodeWorkspace(null, key, current);
          } else {
            if (!response.ok) {
              const failure = await response.json().catch(() => null);
              throw new Error(failure?.code === 'dependency_unavailable' && typeof failure.error === 'string'
                ? failure.error.slice(0, 1024) : `Analyzer returned ${response.status}`);
            }
            const document = await response.json();
            if (!current()) return;
            if (!isVmAnalysisDocument(document) || !vmAnalysisMatchesSelection(document, selection)) {
              throw new TypeError('Malformed or mismatched VM analysis response');
            }
            state.vmAnalysisEtag = response.headers.get('ETag');
            state.vmAnalysisStatus = 'ready';
            state.vmAnalysisDocument = document;
            state.lastValidAnalysisFindings = vmFindingsFromAnalysis(document);
            state.vmFindings = vmVisibleFindings(state);
            await refreshVmOpcodeWorkspace(document, key, current);
          }
          if (!current()) return;
          await refreshVmHostLinks();
        } catch (error) {
          if (!current()) return;
          retainVmAnalysisOnFailure(state,
            error instanceof TypeError || error instanceof SyntaxError ? 'malformed' : 'unavailable', error.message);
        }
        if (current()) renderVmLab();
      }

      function setNetworkNotice(kind, message) {
        if (elements.networkNotice.dataset.kind !== kind) elements.networkNotice.dataset.kind = kind;
        if (elements.networkNotice.textContent !== message) elements.networkNotice.textContent = message;
        elements.networkNotice.hidden = false;
      }

      // Both refresh paths project the same status so neither can erase the other's gaps.
      // Summaries describe the scanned store/tail, independently of either rendered window.
      // A healthy capture leaves this line hidden. Window, target-mode, and
      // Network.enable explanations stay in the README; only gaps and failures show here.
      function renderNetworkNotice() {
        const gapCount = shownSequenceGaps();
        const reportedDrops = shownQueueDrops();
        const messages = [];
        let kind = 'empty';
        if (state.eventFailureKind === 'malformed') {
          kind = 'malformed';
          messages.push('The broker returned malformed event data.');
        } else if (state.broker === 'unavailable') {
          kind = 'disconnected';
          messages.push('The local evidence broker is disconnected.');
        }
        if (state.eventsLimited) {
          if (kind === 'empty') kind = 'gap';
          messages.push('Showing the last 5,000 evidence events; older events remain recorded on disk.');
        }
        if (state.networkEventsLimited) messages.push('The network event window is capped; older request lifecycle evidence may be incomplete.');
        if (state.eventCountScope === 'bounded_tail') {
          if (kind === 'empty') kind = 'gap';
          messages.push('Only the newest 64 MiB of stored evidence is scanned; counts and both windows exclude the older prefix.');
        }
        if (gapCount > 0n) {
          if (kind === 'empty') kind = 'gap';
          messages.push(`${state.sequenceGapsSaturated ? 'at least ' : ''}${gapCount} sequence-gap IDs were observed in ${eventCountScopeLabel()}; late arrivals may overlap. Native evidence may be incomplete.`);
        }
        if (reportedDrops > 0n) {
          if (kind === 'empty') kind = 'gap';
          messages.push(`The queue reports ${state.queueDropsSaturated ? 'at least ' : ''}${reportedDrops} dropped ${reportedDrops === 1n ? 'event' : 'events'}${gapCount > 0n ? '; counts may overlap sequence gaps' : `; no sequence jump is visible in ${eventCountScopeLabel()}`}.`);
        }

        const failedNotice = trafficFailedRequestNotice(state.requests);
        if (failedNotice) messages.push(failedNotice);
        if (messages.length) setNetworkNotice(kind, messages.join(' '));
        else {
          elements.networkNotice.hidden = true;
          if (elements.networkNotice.textContent) elements.networkNotice.textContent = '';
        }
      }

      function textElement(tag, className, value) {
        const element = document.createElement(tag);
        if (className) element.className = className;
        element.textContent = String(value);
        return element;
      }
      function counted(count, singular, plural = `${singular}s`) { return `${count} ${count === 1 ? singular : plural}`; }

      function emptyListboxOption(className, value) {
        const element = textElement('div', className, value);
        element.setAttribute('role', 'option');
        element.setAttribute('aria-disabled', 'true');
        element.setAttribute('aria-selected', 'false');
        return element;
      }

      function setVmNotice(kind, message) {
        elements.vmNotice.dataset.kind = kind;
        elements.vmNotice.textContent = message;
        elements.vmNotice.hidden = false;
      }

      function requestOriginLabel(origin) {
        return origin === 'live' ? 'Live' : origin === 'demo' ? 'Demo' : 'Sample';
      }

      const fingerprintSignalLabels = new Map([
        ['canvas', 'Canvas'], ['webgl', 'WebGL'], ['web_audio', 'Web Audio'],
        ['navigator', 'Device, layout & WebGPU'], ['permissions', 'Permissions'],
        ['storage', 'Storage'], ['webrtc', 'WebRTC'], ['runtime', 'Runtime']
      ]);
      const signalEventDisplayLimit = 500;
      const nativeCanvasCaptureDisplayLimit = 24;
      const canvasPreviewByteLimit = 8 * 1024 * 1024; // Reserved/retained UTF-16 text bytes, not decoded pixels.
      const canvasPreviewReadLimit = 2;
      const canvasPreviewAxisLimit = 4096;
      const canvasPreviewPixelLimit = 4 * 1024 * 1024;
      const canvasGalleryPixelLimit = 16 * 1024 * 1024; // Mounted declared pixels, not decoder/RSS memory.
      const nativeCanvasDrawingMethods = new Set([
        'save', 'restore', 'scale', 'rotate', 'translate', 'transform',
        'setTransform', 'resetTransform', 'beginPath', 'closePath', 'moveTo',
        'lineTo', 'quadraticCurveTo', 'bezierCurveTo', 'arcTo', 'arc',
        'ellipse', 'rect', 'roundRect', 'fill', 'stroke', 'fillRect',
        'strokeRect', 'clearRect', 'drawImage', 'fillText', 'strokeText',
        'clip', 'putImageData', 'createConicGradient', 'createImageData',
        'createLinearGradient', 'createPattern', 'createRadialGradient',
        'addColorStop', 'setLineDash', 'getContext'
      ]);
      const nativeCanvasCallLimit = 128;
      const canvasDataUrlPattern = /^data:image\/[A-Za-z0-9.+-]+;base64,[A-Za-z0-9+/]+={0,2}$/;
      const canvasPngCrcTable = Uint32Array.from({length: 256}, (_, value) => {
        for (let bit = 0; bit < 8; bit++) value = (value >>> 1) ^ ((value & 1) ? 0xedb88320 : 0);
        return value >>> 0;
      });

      // Deliberately narrow PNG admission, not a decoder or a general PNG validator.
      // https://www.w3.org/TR/png-3/ sections 5 and 11. No compressed data is inflated.
      function inspectCanvasPng(content) {
        const reject = reason => ({reason: `${reason} Original evidence is unchanged.`});
        if (typeof content !== 'string' || content.length > 2097152 || !canvasDataUrlPattern.test(content)) {
          return reject('The retained bytes do not pass the bounded image data URL validator.');
        }
        if (!content.startsWith('data:image/png;base64,')) return reject('Preview format is unsupported: only static PNG is admitted.');
        const encoded = content.slice('data:image/png;base64,'.length);
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        if (encoded.length % 4 || (encoded.endsWith('==') && (alphabet.indexOf(encoded.at(-3)) & 15)) ||
            (encoded.endsWith('=') && !encoded.endsWith('==') && (alphabet.indexOf(encoded.at(-2)) & 3))) {
          return reject('PNG base64 encoding is not canonical.');
        }
        let bytes;
        try { bytes = atob(encoded); } catch { return reject('PNG base64 encoding is malformed.'); }
        const byte = offset => bytes.charCodeAt(offset);
        const uint32 = offset => ((byte(offset) * 0x1000000) + (byte(offset + 1) << 16) +
          (byte(offset + 2) << 8) + byte(offset + 3));
        if (bytes.slice(0, 8) !== '\x89PNG\r\n\x1a\n') return reject('PNG signature is invalid.');
        let offset = 8, chunks = 0, width = 0, height = 0, colorType = 0, idatBytes = 0, hasIdat = false;
        const ancillary = new Set();
        while (offset < bytes.length) {
          if (++chunks > 256) return reject('PNG exceeds the 256-chunk preview limit.');
          if (bytes.length - offset < 12) return reject('PNG chunk is truncated.');
          const length = uint32(offset), type = bytes.slice(offset + 4, offset + 8), data = offset + 8;
          if (length > bytes.length - offset - 12) return reject('PNG chunk length is invalid or truncated.');
          if (!/^[A-Za-z]{2}[A-Z][A-Za-z]$/.test(type)) return reject('PNG chunk type is invalid.');
          let crc = 0xffffffff;
          for (let index = offset + 4; index < data + length; index++) crc = (crc >>> 8) ^ canvasPngCrcTable[(crc ^ byte(index)) & 255];
          if (((crc ^ 0xffffffff) >>> 0) !== uint32(data + length)) return reject('PNG chunk CRC does not match.');
          if (chunks === 1 && type !== 'IHDR') return reject('PNG must begin with IHDR.');
          if (type === 'IHDR') {
            if (chunks !== 1 || length !== 13) return reject('PNG has a duplicate or malformed IHDR.');
            width = uint32(data); height = uint32(data + 4); colorType = byte(data + 9);
            if (!width || !height || width > canvasPreviewAxisLimit || height > canvasPreviewAxisLimit) {
              return reject('PNG dimensions exceed the 4096-pixel axis limit or are zero.');
            }
            if (width * height > canvasPreviewPixelLimit) return reject('PNG exceeds the 4 Mi-pixel preview limit.');
            if (byte(data + 8) !== 8 || ![2, 6].includes(colorType) || byte(data + 10) !== 0 ||
                byte(data + 11) !== 0 || byte(data + 12) !== 0) {
              return reject('PNG preview supports only non-interlaced 8-bit RGB or RGBA with standard compression and filtering.');
            }
          } else if (type === 'IDAT') {
            hasIdat = true; idatBytes += length;
          } else if (type === 'IEND') {
            if (length || !hasIdat || !idatBytes || data + 4 !== bytes.length) return reject('PNG is incomplete or has trailing data.');
            return {width, height, pixels: width * height};
          } else if (['acTL', 'fcTL', 'fdAT'].includes(type)) {
            return reject('Animated PNG previews are unsupported.');
          } else {
            // Only fixed-size sRGB, sBIT and pHYs metadata is admitted. Refusing other
            // chunks also excludes embedded compressed profiles/text and extensions.
            if (!['sRGB', 'sBIT', 'pHYs'].includes(type)) return reject(`PNG chunk ${type} is unsupported for previews.`);
            if (hasIdat || ancillary.has(type)) return reject('PNG metadata is duplicated or follows image data.');
            ancillary.add(type);
            if ((type === 'sRGB' && (length !== 1 || byte(data) > 3)) ||
                (type === 'sBIT' && (length !== (colorType === 2 ? 3 : 4) ||
                  [...bytes.slice(data, data + length)].some(value => value.charCodeAt(0) < 1 || value.charCodeAt(0) > 8))) ||
                (type === 'pHYs' && (length !== 9 || uint32(data) > 0x7fffffff ||
                  uint32(data + 4) > 0x7fffffff || byte(data + 8) > 1))) return reject('PNG metadata is malformed.');
          }
          offset = data + length + 4;
        }
        return reject('PNG is missing IEND.');
      }

      function canvasReadbackName(operation) {
        const match = /^(toDataURL|toBlob|getImageData)$/.exec(operation) ??
          /^(?:canvas|HTMLCanvasElement)\.(toDataURL|toBlob)$/.exec(operation) ??
          /^(?:canvas|CanvasRenderingContext2D|OffscreenCanvasRenderingContext2D)\.(getImageData)$/.exec(operation) ??
          /^(?:OffscreenCanvas)\.(convertToBlob)$/.exec(operation);
        return match?.[1] ?? null;
      }

      function requestSignalRoot(request) {
        if (!request || request.origin === 'sample') return null;
        const candidates = request.events ?? [];
        return candidates.find(event => event.type === 'request_started' && integerText(event, 'request_id') !== '0') ??
          candidates.find(event => event.type === 'request_initiated' && integerText(event, 'request_id') !== '0') ??
          candidates.find(event => integerText(event, 'request_id') !== '0') ?? null;
      }

      function signalEventKey(event) {
        return `S${integerText(event, 'session_id')}:P${event.process_id}:E${integerText(event, 'sequence_number')}`;
      }

      function signalTypeLabel(type) {
        return type.split('_').map(part => part[0].toUpperCase() + part.slice(1)).join(' ');
      }

      function formatSignalOffset(nanoseconds) {
        return nanoseconds < 1000000n ? `+${nanoseconds} ns` : formatMilliseconds(nanoseconds, '+');
      }

      function matchingSignalProfileFamily(event) {
        const profile = state.signalProfile;
        if (!profile || integerText(event, 'session_id') !== profile.session_id ||
            integerText(event, 'navigation_id') !== profile.navigation_id ||
            integerText(event, 'frame_id') !== profile.frame_id) return null;
        const sequence = integerValue(event, 'sequence_number');
        return profile.signals.find(signal => signal.category === event.category && [
          signal.first_event, signal.last_event
        ].some(reference => event.process_id === reference.process_id &&
          sequence === BigInt(reference.sequence_number))) ?? null;
      }

      function signalCoverageLabel() {
        if (state.signalProfileStatus === 'loading') return 'Building profile';
        if (state.signalProfileStatus === 'error') return 'Profile unavailable';
        const coverage = state.signalProfile?.coverage;
        if (!coverage) return 'No request profile';
        return coverage.retention_truncated || coverage.parent_depth_limited || coverage.count_saturated
          ? 'Partial' : 'Bounded';
      }

      function setSignalNotice(kind, message) {
        elements.signalNotice.dataset.kind = kind;
        elements.signalNotice.textContent = message;
      }

      function canvasCallLabel(call) {
        const parameters = call.arguments.map(value => typeof value === 'string'
          ? JSON.stringify(value) : String(value)).join(', ');
        return `${call.name}(${parameters})`;
      }

      function replayCanvasCalls(canvas, calls) {
        const context = canvas.getContext('2d');
        if (!context) return;
        context.clearRect(0, 0, canvas.width, canvas.height);
        calls.forEach(call => {
          try {
            if (call.property && canvasReplayProperties.has(call.name) && call.arguments.length === 1) {
              context[call.name] = call.arguments[0];
            } else if (!call.property && canvasReplayMethods.has(call.name)) {
              context[call.name](...call.arguments);
            }
          } catch {}
        });
      }

      function canvasRenderCaptures(signalEvents) {
        const canvasEvents = signalEvents.filter(event => event.category === 'canvas');
        const readbacks = canvasEvents.filter(event => canvasReadbackName(decodePayload(event)));
        if (state.sessionMode === 'demo' && state.canvasRenderCaptures.length > 0 && readbacks.length > 0) {
          return state.canvasRenderCaptures.map((capture, index) => ({
            ...capture, evidenceEvent: readbacks[Math.min(index, readbacks.length - 1)], demo: true
          }));
        }
        const streams = new Map();
        const captures = [];
        const orderedCanvasEvents = [...canvasEvents].sort((left, right) => {
          const sessionOrder = integerValue(left, 'session_id') - integerValue(right, 'session_id');
          if (sessionOrder !== 0n) return sessionOrder < 0n ? -1 : 1;
          if (left.process_id !== right.process_id) return left.process_id - right.process_id;
          const sequenceOrder = integerValue(left, 'sequence_number') - integerValue(right, 'sequence_number');
          return sequenceOrder < 0n ? -1 : sequenceOrder > 0n ? 1 : 0;
        });
        orderedCanvasEvents.forEach(event => {
          const operation = decodePayload(event);
          const streamId = `${integerText(event, 'session_id')}:${event.process_id}:${integerText(event, 'frame_id')}`;
          const stream = streams.get(streamId) ?? {calls: [], observed: 0};
          streams.set(streamId, stream);
          const readback = canvasReadbackName(operation);
          if (readback) {
            captures.push({
              id: `canvas#${captures.length + 1}`, context: '2D', width: null, height: null,
              readback, operationHash: null, calls: [...stream.calls],
              callsTruncated: stream.observed > stream.calls.length,
              evidenceEvent: event, demo: false
            });
            return;
          }
          const call = /^(?:canvas|HTMLCanvasElement|CanvasRenderingContext2D|OffscreenCanvasRenderingContext2D|CanvasGradient|CanvasPattern)\.([A-Za-z][A-Za-z0-9]*)$/.exec(operation);
          if (event.type !== 'api_call' || !call || !nativeCanvasDrawingMethods.has(call[1])) return;
          stream.observed += 1;
          stream.calls.push({
            name: operation.startsWith('canvas.') ? call[1] : operation,
            arguments: [], observedOnly: true
          });
          if (stream.calls.length > nativeCanvasCallLimit) stream.calls.shift();
        });
        const artifacts = (state.artifacts ?? []).filter(artifact =>
          artifact.kind === 'canvas_data_url' && artifact.capture_origin === 'canvas_to_data_url');
        const claimed = new Set();
        captures.forEach(capture => {
          const sessionId = integerText(capture.evidenceEvent, 'session_id');
          const sequence = integerText(capture.evidenceEvent, 'sequence_number');
          const index = artifacts.findIndex((artifact, artifactIndex) =>
            !claimed.has(artifactIndex) && artifact.session_id === sessionId &&
            artifact.creator_event_id === sequence);
          if (index === -1) return;
          claimed.add(index);
          capture.artifact = artifacts[index];
        });
        return captures.sort((left, right) => {
          const delta = integerValue(left.evidenceEvent, 'monotonic_time_ns') -
            integerValue(right.evidenceEvent, 'monotonic_time_ns');
          return delta < 0n ? -1 : delta > 0n ? 1 : 0;
        }).slice(-nativeCanvasCaptureDisplayLimit).reverse();
      }

      function canvasGalleryVisible() {
        return !document.querySelector('#screen-signals').hidden && state.signalView === 'rendering';
      }

      function releaseCanvasPreview(artifact, reason) {
        const error = artifact.loadError;
        const owner = state.canvasPreviewOwners?.get(sourceIdentity(artifact));
        if (owner?.artifact === artifact) {
          owner.image?.removeAttribute('src');
          delete owner.image; delete owner.imageInfo; delete owner.imageError; delete owner.mounted;
        }
        releaseSourcePreview(artifact);
        if (error) artifact.loadError = error;
        // A removed catalog object may no longer be found by releaseSourcePreview.
        artifact.controller?.abort();
        for (const field of ['content', 'contentTruncated', 'loading', 'controller', 'previewUsed', 'contentVerified', 'contentLossy']) delete artifact[field];
        artifact.canvasPreviewNotice = reason;
      }

      function retireCanvasPreviews(reason = 'Preview released while the Rendering gallery is closed.') {
        for (const owner of state.canvasPreviewOwners?.values() ?? []) releaseCanvasPreview(owner.artifact, reason);
        state.canvasPreviewOwners?.clear();
        for (const artifact of state.artifacts) {
          if (artifact.kind === 'canvas_data_url') releaseCanvasPreview(artifact, reason);
        }
        // Remove src before detaching: hidden/detached gallery nodes must not own image data.
        elements.signalRenderList.querySelectorAll('img').forEach(image => image.removeAttribute('src'));
        elements.signalRenderList.replaceChildren();
        delete elements.signalRenderList.canvasRender;
      }

      function syncCanvasPreviews(captures) {
        if (!canvasGalleryVisible() || state.artifactReceiverError) {
          retireCanvasPreviews(state.artifactReceiverError
            ? 'Canvas previews released because the artifact catalog is unavailable.' : undefined);
          return;
        }
        const previous = state.canvasPreviewOwners ?? new Map();
        const owners = new Map();
        let reservedBytes = 0;
        for (const capture of captures.slice(0, nativeCanvasCaptureDisplayLimit)) {
          const artifact = capture.artifact;
          if (!artifact || artifact.kind !== 'canvas_data_url') continue;
          const identity = sourceIdentity(artifact);
          if (owners.has(identity)) continue;
          let reason = '';
          if (!sourceIsCurrent(artifact)) reason = 'The exact Canvas artifact identity is unavailable or ambiguous.';
          else if (!Number.isSafeInteger(artifact.byte_size) || artifact.byte_size <= 0 || artifact.byte_size > 2097152) {
            reason = 'Canvas preview exceeds the 2 MiB encoded-byte limit or has an invalid size.';
          } else if (reservedBytes + artifact.byte_size * 2 > canvasPreviewByteLimit) {
            reason = 'Canvas preview evicted by the 8 MiB gallery text budget. Original evidence is unchanged.';
          }
          if (reason) { releaseCanvasPreview(artifact, reason); continue; }
          // Reserve the maximum UTF-16 cost before reading, so completion order
          // cannot overcommit the cache or evict/reload the same 24 cards forever.
          reservedBytes += artifact.byte_size * 2;
          const prior = previous.get(identity);
          owners.set(identity, prior?.artifact === artifact ? prior : {artifact, identity});
          delete artifact.canvasPreviewNotice;
        }
        for (const [identity, owner] of previous) {
          if (owners.get(identity) !== owner) releaseCanvasPreview(owner.artifact,
            'Canvas preview evicted from the visible gallery. Original evidence is unchanged.');
        }
        state.canvasPreviewOwners = owners;
        for (const artifact of state.artifacts) {
          if (artifact.kind === 'canvas_data_url' && !owners.has(sourceIdentity(artifact)) &&
              (artifact.content !== undefined || artifact.loading)) releaseCanvasPreview(artifact,
            'Canvas preview evicted from the visible gallery. Original evidence is unchanged.');
        }
        pumpCanvasPreviews();
      }

      function pumpCanvasPreviews() {
        if (!canvasGalleryVisible() || state.artifactReceiverError) return;
        const reads = state.canvasPreviewReads ??= new Set();
        for (const owner of state.canvasPreviewOwners?.values() ?? []) {
          if (reads.size >= canvasPreviewReadLimit) break;
          const artifact = owner.artifact;
          if (reads.has(owner) || artifact.content !== undefined || artifact.loading || artifact.loadError) continue;
          reads.add(owner);
          // Keep the slot until the actual operation settles, even when an
          // aborted fetch ignores cancellation. Late headers are never read.
          void loadArtifactContent(artifact, {canvasOwner: owner}).finally(() => {
            reads.delete(owner);
            if (canvasGalleryVisible()) renderFingerprintActivity();
          });
        }
      }

      function retryCanvasPreview(identity) {
        const owner = state.canvasPreviewOwners?.get(identity);
        if (!owner || !canvasGalleryVisible() || state.artifactReceiverError) return;
        delete owner.artifact.loadError;
        renderFingerprintActivity();
      }

      function canvasPreview(capture, label, replayLabel, capturedOutput = false) {
        const preview = document.createElement('figure');
        preview.className = 'signal-canvas-preview';
        preview.append(textElement('figcaption', '', label));
        const frame = document.createElement('div');
        frame.className = 'signal-canvas-frame';
        const artifact = capture.artifact;
        const owner = artifact && state.canvasPreviewOwners?.get(sourceIdentity(artifact));
        if (capturedOutput && owner && owner.artifact === artifact && owner.mounted && owner.imageInfo &&
            !owner.imageError && artifact.content !== undefined && !artifact.contentTruncated &&
            sourceIsCurrent(artifact) && canvasGalleryVisible() && !state.artifactReceiverError) {
          const image = document.createElement('img');
          owner.image = image;
          image.alt = replayLabel;
          image.decoding = 'async';
          image.addEventListener('error', () => {
            if (state.canvasPreviewOwners?.get(owner.identity) !== owner || owner.image !== image ||
                !canvasGalleryVisible() || !sourceIsCurrent(artifact)) return;
            image.removeAttribute('src');
            owner.imageError = 'The browser could not decode this PNG preview. Original evidence is unchanged.';
            delete owner.imageInfo; delete owner.mounted;
            renderFingerprintActivity();
          });
          // Header/structure and aggregate admission both precede the first src assignment.
          image.src = artifact.content;
          frame.append(image);
        } else if (capture.calls.length === 0 || !capture.width || !capture.height || !capture.demo) {
          frame.classList.add('unavailable');
          const explanation = capturedOutput && !state.canvasImageCaptureEnabled
            ? 'Image capture is off for this session. Restart with REB_CAPTURE_CANVAS_IMAGES=1 to retain sensitive Canvas output.'
            : capturedOutput && capture.artifact
              ? capture.artifact.canvasPreviewNotice || owner?.imageError || capture.previewReason || capture.artifact.loadError || (capture.artifact.loading
                ? 'Loading the retained Canvas preview…' : 'Canvas preview is waiting for a bounded read slot.')
              : capture.calls.length
                ? 'Operation names were retained, but arguments were not, so a faithful local replay cannot be generated.'
                : 'This capture retained the readback call, but no supported earlier drawing operations.';
          frame.append(
            textElement('strong', '', 'Preview unavailable'),
            textElement('span', '', explanation)
          );
          if (capturedOutput && capture.artifact?.loadError && !capture.artifact.canvasPreviewNotice) {
            const retry = textElement('button', 'secondary-button', 'Retry preview');
            retry.type = 'button';
            retry.addEventListener('click', retryCanvasPreview.bind(null, sourceIdentity(capture.artifact)));
            frame.append(retry);
          }
        } else {
          const canvas = document.createElement('canvas');
          canvas.width = capture.width;
          canvas.height = capture.height;
          canvas.setAttribute('role', 'img');
          canvas.setAttribute('aria-label', replayLabel);
          frame.append(canvas);
          requestAnimationFrame(() => replayCanvasCalls(canvas, capture.calls));
        }
        preview.append(frame);
        return preview;
      }

      function renderCanvasCapture(capture) {
        const card = document.createElement('article');
        card.className = 'signal-render-card';
        const header = document.createElement('header');
        header.className = 'signal-render-card-head';
        const title = document.createElement('div');
        title.append(
          textElement('span', 'signal-render-icon', '▱'),
          textElement('h3', '', capture.id),
          textElement('p', '', `${capture.context}${capture.width ? ` · ${capture.width} × ${capture.height}` : ''} · ${capture.readback} · ${capture.calls.length} observed drawing ${capture.calls.length === 1 ? 'call' : 'calls'}`)
        );
        const badges = document.createElement('div');
        badges.className = 'signal-render-badges';
        badges.append(textElement('span', capture.demo ? 'demo' : 'live', capture.demo ? 'DEMO REPLAY' : 'NATIVE EVENT'));

        header.append(title, badges);

        const comparison = document.createElement('div');
        comparison.className = 'signal-canvas-comparison';
        comparison.append(
          canvasPreview(capture, capture.demo ? 'DEMO OUTPUT' : 'CAPTURED OUTPUT', `${capture.id} captured output`, true)
        );
        const replay = document.createElement('details');
        replay.className = 'signal-capture-disclosure';
        replay.dataset.captureKey = `${signalEventKey(capture.evidenceEvent)}:replay`;
        replay.append(textElement('summary', '', 'Compare with local replay'),
          canvasPreview(capture, 'LOCAL REPLAY', `${capture.id} local replay`));

        const body = document.createElement('div');
        body.className = 'signal-render-body';
        const calls = document.createElement('section');
        calls.className = 'signal-draw-calls';
        const callsHead = document.createElement('div');
        callsHead.className = 'signal-draw-calls-head';
        callsHead.append(
          textElement('h4', '', 'Drawing functions'),
          textElement('span', '', capture.calls.length
            ? `${capture.calls.length} ${capture.callsTruncated ? 'newest ' : ''}observed in renderer order`
            : 'None observed')
        );
        calls.append(callsHead);
        if (capture.calls.length) {
          const list = document.createElement('ol');
          capture.calls.forEach(call => {
            const item = document.createElement('li');
            item.append(textElement('code', '', canvasCallLabel(call)));
            list.append(item);
          });
          calls.append(list);
        } else {
          calls.append(textElement(
            'p', 'signal-draw-empty',
            `${capture.readback} was observed without a supported drawing operation earlier in the same renderer stream.`
          ));
        }

        const evidence = document.createElement('aside');
        evidence.className = 'signal-render-evidence';
        evidence.append(textElement('h4', '', 'Evidence'));
        const profileFamily = matchingSignalProfileFamily(capture.evidenceEvent);
        [
          ['event', signalEventKey(capture.evidenceEvent)],
          ['relationship', profileFamily?.confidence ?? 'not linked'],
          ['drawing scope', capture.demo ? 'deterministic demo' : 'same renderer stream'],
          ['readback', capture.readback],
          ['canvas artifact', capture.artifact?.artifact_id ?? 'not captured'],
          ['operation hash', capture.operationHash ?? 'not retained']
        ].forEach(([label, value]) => {
          const row = document.createElement('div');
          row.append(textElement('span', '', label), textElement('strong', '', value));
          evidence.append(row);
        });
        evidence.append(textElement(
          'p', '', capture.demo
            ? 'This demo image is generated locally from visible calls and is not production evidence.'
            : capture.artifact && sourceIsCurrent(capture.artifact)
              ? 'Sensitive Canvas output was captured locally for this session and linked to the native readback event.'
              : 'Operation metadata remains available even when sensitive Canvas image capture is off.'
        ));
        body.append(calls, evidence);
        const detail = document.createElement('details');
        detail.className = 'signal-capture-disclosure';
        detail.dataset.captureKey = `${signalEventKey(capture.evidenceEvent)}:evidence`;
        detail.append(textElement('summary', '', `Drawing calls & evidence · ${capture.calls.length} calls`), body);
        card.append(header, comparison, replay, detail);
        return card;
      }

      function renderFingerprintRendering(signalEvents) {
        const captures = canvasRenderCaptures(signalEvents);
        syncCanvasPreviews(captures);
        if (!canvasGalleryVisible()) return;
        renderSignalSurfaceOverview(signalEvents);
        // Count only the exact current owners and prioritize newest captures.
        // Old DOM sources are removed below before any new source is assigned.
        for (const owner of state.canvasPreviewOwners?.values() ?? []) {
          delete owner.mounted;
        }
        let pixels = 0;
        for (const capture of captures) {
          const owner = capture.artifact && state.canvasPreviewOwners?.get(sourceIdentity(capture.artifact));
          if (!owner || owner.artifact !== capture.artifact || !owner.imageInfo || owner.imageError) continue;
          if (pixels + owner.imageInfo.pixels > canvasGalleryPixelLimit) {
            capture.previewReason = 'Preview omitted by the 16 Mi-pixel gallery budget. Original evidence is unchanged.';
            continue;
          }
          pixels += owner.imageInfo.pixels;
          owner.mounted = true;
          capture.width = owner.imageInfo.width; capture.height = owner.imageInfo.height;
        }
        const readbackCount = signalEvents.filter(event => event.category === 'canvas' &&
          canvasReadbackName(decodePayload(event))).length;
        elements.signalRenderCount.textContent = String(captures.length);
        elements.signalRenderSummary.textContent = readbackCount
          ? captures.length < readbackCount
            ? `${captures.length} newest of ${readbackCount} canvas readbacks`
            : `${captures.length} canvas ${captures.length === 1 ? 'readback' : 'readbacks'}`
          : 'No canvas readbacks';
        // Keep the native activation target alive across unchanged polling,
        // including a refresh between pointer-down and pointer-up. The stamp
        // contains only bounded render inputs, never another copy of image text.
        // Owner/object identity also matters: a replaced source must retire its
        // old image and handlers even when its visible metadata is unchanged.
        const owners = captures.map(capture => capture.artifact &&
          state.canvasPreviewOwners?.get(sourceIdentity(capture.artifact)));
        const stamp = JSON.stringify([state.canvasImageCaptureEnabled, state.artifactReceiverError, captures.map((capture, index) => {
          const artifact = capture.artifact, owner = owners[index];
          return [capture.id, capture.context, capture.width, capture.height, capture.readback,
            capture.demo, capture.calls, capture.callsTruncated, capture.operationHash,
            signalEventKey(capture.evidenceEvent), matchingSignalProfileFamily(capture.evidenceEvent)?.confidence,
            capture.previewReason, artifact && sourceIdentity(artifact), artifact && sourceIsCurrent(artifact),
            artifact?.artifact_id, artifact?.content !== undefined, artifact?.contentTruncated,
            artifact?.loading, artifact?.loadError, artifact?.canvasPreviewNotice,
            owner?.mounted, owner?.imageInfo, owner?.imageError];
        })]);
        const previous = elements.signalRenderList.canvasRender;
        if (captures.length && previous?.stamp === stamp &&
            owners.every((owner, index) => owner === previous.owners[index] &&
              captures[index].artifact === previous.artifacts[index])) return;
        delete elements.signalRenderList.canvasRender;
        for (const owner of state.canvasPreviewOwners?.values() ?? []) delete owner.image;
        if (!captures.length) {
          elements.signalRenderList.querySelectorAll('img').forEach(image => image.removeAttribute('src'));
          elements.signalRenderList.replaceChildren(textElement(
            'div', 'signal-render-empty',
            'No Canvas readback has been captured. Activity from other fingerprint-relevant surfaces remains available.'
          ));
          return;
        }
        // Refreshing evidence must not close a researcher's expanded details or lose focus.
        const expanded = new Set([...elements.signalRenderList.querySelectorAll('details[open]')]
          .map(detail => detail.dataset.captureKey));
        const focused = document.activeElement?.matches('summary')
          ? document.activeElement.parentElement.dataset.captureKey : null;
        elements.signalRenderList.querySelectorAll('img').forEach(image => image.removeAttribute('src'));
        elements.signalRenderList.replaceChildren(...captures.map(renderCanvasCapture));
        elements.signalRenderList.querySelectorAll('details').forEach(detail => {
          detail.open = expanded.has(detail.dataset.captureKey);
          if (focused && detail.dataset.captureKey === focused) detail.querySelector('summary').focus({preventScroll: true});
        });
        elements.signalRenderList.canvasRender = {stamp, owners, artifacts: captures.map(capture => capture.artifact)};
      }

      function renderSignalSurfaceOverview(signalEvents) {
        const uniqueOperations = new Set(signalEvents.map(event =>
          `${event.category}:${decodePayload(event) || event.type}`));
        elements.signalOperationSummary.textContent = signalEvents.length
          ? `${uniqueOperations.size} unique operations` : 'No operations';
        const cards = [];
        fingerprintSignalLabels.forEach((label, category) => {
          const familyEvents = signalEvents.filter(event => event.category === category);
          const operations = new Map();
          familyEvents.forEach(event => {
            const operation = decodePayload(event) || signalTypeLabel(event.type);
            operations.set(operation, (operations.get(operation) ?? 0) + 1);
          });
          const top = [...operations.entries()].sort((left, right) =>
            right[1] - left[1] || left[0].localeCompare(right[0]))[0];
          const card = document.createElement('button');
          card.type = 'button';
          card.className = 'signal-surface-card';
          card.dataset.present = String(familyEvents.length > 0);
          card.title = `${operations.size} unique operations${top ? ` · ${top[0]} × ${top[1]}` : ' · Not observed'}`;
          card.setAttribute('aria-label', `${label}, ${familyEvents.length} events. Open activity.`);
          card.append(
            textElement('span', 'signal-surface-name', label),
            textElement('strong', '', String(familyEvents.length))
          );
          card.addEventListener('click', () => {
            state.signalCategoryFilter = category;
            state.signalView = 'activity';
            renderFingerprintActivity();
          });
          cards.push(card);
        });
        elements.signalSurfaceOverview.replaceChildren(...cards);
      }

      function renderSignalRequestProfile() {
        const selectedRequest = state.requests.find(request => request.id === state.selectedRequestId);
        if (state.signalProfileStatus === 'loading') {
          elements.signalRequestProfile.replaceChildren(textElement('div', 'signal-render-empty', 'Building the selected request profile...'));
          return;
        }
        if (!state.signalProfile || !selectedRequest) {
          elements.signalRequestProfile.replaceChildren(textElement(
            'div', 'signal-render-empty', 'Select a captured request to inspect its fingerprint-surface relationships.'
          ));
          return;
        }
        const summary = document.createElement('article');
        summary.className = 'signal-request-card';
        const head = document.createElement('header');
        const identity = document.createElement('div');
        identity.append(
          textElement('span', '', 'SELECTED REQUEST'),
          textElement('h3', '', `${selectedRequest.method} ${selectedRequest.path}`),
          textElement('p', '', `${state.signalProfile.signals.length} linked surface ${state.signalProfile.signals.length === 1 ? 'family' : 'families'} · ${signalCoverageLabel().toLowerCase()} coverage`)
        );
        const open = textElement('button', 'secondary-button', 'Open in Traffic');
        open.type = 'button';
        open.addEventListener('click', () => {
          state.inspectorTab = 'signals';
          state.trafficDetailOpen = true;
          showScreen('traffic', open);
          renderInspector();
        });
        head.append(identity, open);
        const grid = document.createElement('div');
        grid.className = 'signal-request-grid';
        fingerprintSignalLabels.forEach((label, category) => {
          const family = state.signalProfile.signals.find(signal => signal.category === category);
          const item = document.createElement('div');
          item.className = 'signal-request-family';
          item.dataset.present = String(Boolean(family));
          item.append(
            textElement('span', '', label),
            textElement('strong', '', family ? family.event_count : '0'),
            textElement('small', '', family
              ? `${family.confidence} · ${family.relation === 'parent_chain' ? 'parent chain' : 'same context'}`
              : 'not observed')
          );
          grid.append(item);
        });
        summary.append(head, grid);
        elements.signalRequestProfile.replaceChildren(summary);
      }

      function renderFingerprintDetail(event) {
        if (!event) {
          elements.signalDetail.replaceChildren(textElement(
            'div', 'signal-detail-empty',
            'Select a captured operation to inspect its evidence identifiers and request context.'
          ));
          return;
        }

        const familyLabel = fingerprintSignalLabels.get(event.category) ?? event.category;
        const payload = decodePayload(event) || signalTypeLabel(event.type);
        const profileFamily = matchingSignalProfileFamily(event);
        const selectedRequest = state.requests.find(request => request.id === state.selectedRequestId);
        const eyebrow = textElement('div', 'signal-detail-eyebrow', 'Fingerprint-relevant surface');
        const title = textElement('h2', '', payload);
        const subtitle = textElement('p', 'signal-detail-subtitle', `${familyLabel} · ${signalTypeLabel(event.type)}`);
        const badges = document.createElement('div');
        badges.className = 'signal-detail-badges';
        badges.append(textElement('span', '', 'Native event'));
        if (event.payload_truncated) badges.append(textElement('span', 'correlated', 'Payload truncated'));
        if (profileFamily) {
          badges.append(textElement(
            'span', profileFamily.confidence === 'observed' ? 'observed' : 'correlated',
            `${profileFamily.confidence === 'observed' ? 'Observed' : 'Correlated'} request profile`
          ));
        }

        const snapshot = document.createElement('section');
        snapshot.className = 'signal-detail-snapshot';
        snapshot.append(textElement('h3', '', 'What was observed'));
        const summaryFacts = document.createElement('dl');
        const tabId = signalTabKey(event);
        [
          ['Surface', familyLabel],
          ['Access', signalTypeLabel(event.type)],
          ['Browser tab', tabId === 'unattributed' ? 'Unattributed' : `Tab ID ${tabId}`],
          ['Arguments / return value', 'Not retained in event']
        ].forEach(([label, value]) => {
          summaryFacts.append(textElement('dt', '', label), textElement('dd', '', value));
        });
        snapshot.append(summaryFacts);

        const disclosure = document.createElement('details');
        disclosure.className = 'signal-evidence-disclosure';
        disclosure.append(textElement('summary', '', 'Evidence identifiers'));
        const facts = document.createElement('dl');
        facts.className = 'signal-facts';
        [
          ['event', signalEventKey(event)],
          ['tab', tabId],
          ['category', event.category],
          ['operation', event.type],
          ['monotonic time', `${integerText(event, 'monotonic_time_ns')} ns`],
          ['navigation', integerText(event, 'navigation_id')],
          ['frame', integerText(event, 'frame_id')],
          ['thread', String(event.thread_id)],
          ['artifact', integerText(event, 'artifact_id')],
          ['parent event', integerText(event, 'parent_event_id')]
        ].forEach(([label, value]) => {
          facts.append(textElement('dt', '', label), textElement('dd', '', value));
        });
        disclosure.append(facts);

        const content = [eyebrow, title, subtitle, badges, snapshot, disclosure];
        if (profileFamily && selectedRequest) {
          const context = document.createElement('section');
          context.className = 'signal-request-context';
          context.append(
            textElement('h3', '', 'Selected request profile'),
            textElement('p', '', `${selectedRequest.method} ${selectedRequest.path} · ${profileFamily.event_count} ${familyLabel} event${profileFamily.event_count === '1' ? '' : 's'} · ${profileFamily.relation === 'parent_chain' ? 'explicit parent chain' : 'same browser context'}`)
          );
          const openRequest = textElement('button', 'secondary-button', 'Open request Signals');
          openRequest.type = 'button';
          openRequest.addEventListener('click', () => {
            state.inspectorTab = 'signals';
            state.trafficDetailOpen = true;
            showScreen('traffic', openRequest);
            renderInspector();
            refreshRequestSignalProfile();
            requestAnimationFrame(() => document.querySelector('#inspector-tab-signals').focus({preventScroll: true}));
          });
          context.append(openRequest);
          content.push(context);
        }
        content.push(textElement(
          'p', 'signal-interpretation',
          'This records access to a fingerprint-relevant browser surface. It does not prove that a value was transmitted or identify a particular fingerprinting vendor.'
        ));
        elements.signalDetail.replaceChildren(...content);
      }

      function signalTabKey(event) {
        const id = event.protocol_version >= 3 ? integerText(event, 'tab_id') : '0';
        return id === '0' ? 'unattributed' : id;
      }

      function renderFingerprintTabScopes(allEvents) {
        const focusedTabId = elements.signalTabScopes.contains(document.activeElement)
          ? document.activeElement.dataset.signalTabId : null;
        const counts = new Map();
        allEvents.forEach(event => {
          const id = signalTabKey(event);
          counts.set(id, (counts.get(id) ?? 0) + 1);
        });
        if (state.signalTabId !== 'all' && !counts.has(state.signalTabId)) {
          state.signalTabId = 'all';
        }
        const ids = [...counts.keys()].sort((left, right) =>
          left === 'unattributed' ? 1 : right === 'unattributed' ? -1 : Number(left) - Number(right));
        const requestTabLabels = new Map(requestTabGroups()
          .filter(group => group.id !== 'unattributed')
          .map((group, index) => [group.id, `Tab ${index + 1}`]));
        const scopes = [['all', 'All tabs', allEvents.length], ...ids.map(id =>
          [id, id === 'unattributed' ? 'Unattributed' : requestTabLabels.get(id) ?? `Tab ${id}`, counts.get(id)])];
        const buttons = scopes.map(([id, label, count]) => {
          const button = document.createElement('button');
          button.type = 'button';
          button.className = 'signal-tab-scope';
          button.dataset.signalTabId = id;
          button.setAttribute('role', 'tab');
          button.setAttribute('aria-selected', String(state.signalTabId === id));
          button.tabIndex = state.signalTabId === id ? 0 : -1;
          button.append(textElement('strong', '', label), textElement('span', '', count));
          button.title = id === 'all' ? 'Show every captured browser tab'
            : id === 'unattributed' ? 'Events without a browser tab identifier'
              : `Browser tab ID ${id}`;
          button.addEventListener('click', () => {
            state.signalSelectedKeysByTab.set(state.signalTabId, state.selectedSignalEventKey);
            state.signalTabId = id;
            state.selectedSignalEventKey = state.signalSelectedKeysByTab.get(id) ?? null;
            renderFingerprintActivity();
            elements.signalTabScopes.querySelector('[aria-selected="true"]')?.focus({preventScroll: true});
          });
          button.addEventListener('keydown', event => {
            if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
            event.preventDefault();
            const tabs = [...elements.signalTabScopes.querySelectorAll('.signal-tab-scope')];
            const current = tabs.indexOf(button);
            const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1
              : (current + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
            tabs[next].click();
          });
          return button;
        });
        elements.signalTabScopes.replaceChildren(...buttons);
        if (focusedTabId) {
          const restored = buttons.find(button => button.dataset.signalTabId === focusedTabId) ??
            buttons.find(button => button.dataset.signalTabId === state.signalTabId);
          restored?.focus({preventScroll: true});
        }
      }

      function renderLiveBrowserTabCount() { elements.signalLiveTabs.textContent = 'Captured tabs'; elements.signalLiveTabs.dataset.live = 'false'; elements.signalLiveTabs.title = 'Tab identifiers come from retained native evidence, not a live browser inventory.'; }

      function renderFingerprintActivity() {
        const allSignalEvents = fingerprintEventsFromEvents(state.events);
        renderFingerprintTabScopes(allSignalEvents);
        renderLiveBrowserTabCount();
        const signalEvents = state.signalTabId === 'all' ? allSignalEvents
          : allSignalEvents.filter(event => signalTabKey(event) === state.signalTabId);
        const familyCounts = new Map();
        signalEvents.forEach(event => familyCounts.set(event.category, (familyCounts.get(event.category) ?? 0) + 1));
        const visibleEvents = signalEvents.filter(event =>
          state.signalCategoryFilter === 'all' || event.category === state.signalCategoryFilter);
        const orderedEvents = [...visibleEvents].sort((left, right) => {
          const delta = integerValue(right, 'monotonic_time_ns') - integerValue(left, 'monotonic_time_ns');
          if (delta !== 0n) return delta < 0n ? -1 : 1;
          const sequenceDelta = integerValue(right, 'sequence_number') - integerValue(left, 'sequence_number');
          return sequenceDelta < 0n ? -1 : sequenceDelta > 0n ? 1 : 0;
        }).slice(0, signalEventDisplayLimit);
        if (!orderedEvents.some(event => signalEventKey(event) === state.selectedSignalEventKey)) {
          state.selectedSignalEventKey = orderedEvents[0] ? signalEventKey(orderedEvents[0]) : null;
        }
        state.signalSelectedKeysByTab.set(state.signalTabId, state.selectedSignalEventKey);

        const newCount = orderedEvents.filter(event => state.signalNewKeys.has(signalEventKey(event))).length;
        elements.signalFeedStatus.textContent = newCount > 0
          ? `${newCount} new ${newCount === 1 ? 'operation' : 'operations'} at the top`
          : 'Newest first · all caught up';
        elements.signalFeedStatus.dataset.new = String(newCount > 0);
        elements.signalLatest.disabled = orderedEvents.length === 0;
        elements.signalLayout.dataset.detailOpen = String(state.signalDetailOpen);
        elements.signalDetailToggle.setAttribute('aria-expanded', String(state.signalDetailOpen));
        elements.signalDetailToggle.textContent = state.signalDetailOpen ? 'Hide details' : 'Details';
        elements.signalDetailToggle.disabled = orderedEvents.length === 0;
        elements.signalStopCapture.disabled = !state.captureControlsAvailable || state.captureStopped ||
          state.broker !== 'connected' || state.sessionMode !== 'live';
        elements.signalClearEvents.disabled = !state.captureControlsAvailable ||
          (state.broker === 'connected' && !state.captureStopped) || state.events.length === 0;

        elements.signalFamilyCount.textContent = String(familyCounts.size);
        elements.signalEventCount.textContent = String(signalEvents.length);
        elements.signalActivityCount.textContent = String(signalEvents.length);
        elements.signalLinkedCount.textContent = state.signalProfile
          ? String(state.signalProfile.signals.length)
          : state.signalProfileStatus === 'loading' ? '…' : '0';
        elements.signalCoverage.textContent = `${signalCoverageLabel()} coverage`;
        const displayLimited = visibleEvents.length > signalEventDisplayLimit;
        elements.signalVisibleCount.textContent = displayLimited
          ? `${orderedEvents.length} of ${visibleEvents.length} shown` : `${orderedEvents.length} shown`;
        const offline = state.broker === 'unavailable' || state.eventFailureKind === 'disconnected';
        elements.signalSessionBadge.textContent = state.captureStopped ? 'Probes stopped'
          : offline ? (signalEvents.length ? 'Evidence retained' : 'Disconnected')
          : state.sessionMode === 'demo' ? 'Demo evidence'
            : state.sessionMode === 'live' ? 'Live native capture' : 'No capture';
        elements.signalSessionBadge.dataset.kind = state.captureStopped ? 'stopped' : offline ? 'offline' : state.sessionMode;

        elements.signalViewTabs.forEach(button => {
          const selected = button.dataset.signalView === state.signalView;
          button.setAttribute('aria-selected', String(selected));
          button.tabIndex = selected ? 0 : -1;
        });
        elements.signalPanels.forEach(panel => {
          panel.hidden = panel.id !== `signal-panel-${state.signalView}`;
        });

        const gapCount = shownSequenceGaps();
        const reportedDrops = shownQueueDrops();
        if (state.eventFailureKind === 'malformed') {
          setSignalNotice('error', signalEvents.length
            ? 'The broker returned malformed event data. The last understandable fingerprint evidence remains visible.'
            : 'The broker returned malformed event data. No fingerprint evidence is available.');
        } else if (state.captureStopped) {
          setSignalNotice('stopped', signalEvents.length
            ? 'Native probes are stopped. Current-session evidence is retained until you clear it.'
            : 'Native probes are stopped. No fingerprint events remain in this session.');
        } else if (offline) {
          setSignalNotice('disconnected', signalEvents.length
            ? 'The broker is disconnected. The last understandable fingerprint evidence remains visible.'
            : 'The broker is disconnected and no fingerprint evidence is available.');
        } else if (state.signalProfileStatus === 'error') {
          setSignalNotice('error', `${state.signalProfileError || 'The selected request profile is unavailable.'} Raw fingerprint events remain visible.`);
        } else if (signalEvents.length === 0) {
          setSignalNotice('empty', state.sessionMode === 'demo'
            ? 'Deterministic fingerprint evidence is not available in this build.'
            : 'No fingerprint-relevant browser activity has been captured yet.');
        } else if (state.eventsLimited || state.eventCountScope === 'bounded_tail' || displayLimited || gapCount > 0n || reportedDrops > 0n) {
          setSignalNotice('partial', fingerprintCoverageNotice(
            state.eventsLimited, displayLimited, signalEventDisplayLimit, gapCount, reportedDrops, eventCountScopeLabel()
          ));
        } else if (state.sessionMode === 'demo') {
          setSignalNotice('demo', 'Demo mode: both Canvas images are reconstructed locally from the visible calls. They are not native-captured pixels.');
        } else {
          setSignalNotice('live', 'Native fingerprint surface activity is streaming from the local browser capture.');
        }

        elements.signalFilters.forEach(button => {
          const category = button.dataset.signalFilter;
          const count = category === 'all' ? signalEvents.length : familyCounts.get(category) ?? 0;
          const label = category === 'all' ? 'All' : fingerprintSignalLabels.get(category) ?? category;
          button.textContent = `${label} ${count}`;
          button.dataset.empty = String(count === 0);
          button.setAttribute('aria-pressed', String(category === state.signalCategoryFilter));
          button.setAttribute('aria-label', `${label}, ${count} ${count === 1 ? 'event' : 'events'}`);
        });

        renderFingerprintRendering(signalEvents);
        renderSignalRequestProfile();

        if (orderedEvents.length === 0) {
          elements.signalRows.replaceChildren(emptyListboxOption(
            'signal-empty', signalEvents.length
              ? 'No captured operations match this tab or surface filter.'
              : 'Capture a page that reads Canvas, WebGL, Web Audio, device, layout, WebGPU, Permissions, Storage, WebRTC, or runtime APIs.'
          ));
          renderFingerprintDetail(null);
          return;
        }

        const firstTime = signalEvents.reduce((minimum, event) => {
          const timestamp = integerValue(event, 'monotonic_time_ns');
          return minimum === null || timestamp < minimum ? timestamp : minimum;
        }, null);
        const priorScrollTop = elements.signalRows.scrollTop;
        const anchor = priorScrollTop > 8
          ? [...elements.signalRows.querySelectorAll('.signal-event-row')]
              .find(row => row.offsetTop + row.offsetHeight > priorScrollTop) : null;
        const anchorKey = anchor?.dataset.signalEventKey;
        const anchorOffset = anchor ? anchor.offsetTop - priorScrollTop : 0;
        const rows = orderedEvents.map(event => {
          const row = document.createElement('button');
          row.type = 'button';
          row.className = 'signal-event-row';
          row.dataset.signalEventKey = signalEventKey(event);
          row.dataset.new = String(state.signalNewKeys.has(row.dataset.signalEventKey));
          row.setAttribute('role', 'option');
          row.setAttribute('aria-selected', String(row.dataset.signalEventKey === state.selectedSignalEventKey));
          const primary = document.createElement('span');
          primary.className = 'signal-event-primary';
          primary.append(
            textElement('span', 'signal-category-badge', fingerprintSignalLabels.get(event.category) ?? event.category),
            textElement('span', 'signal-event-operation', decodePayload(event) || signalTypeLabel(event.type)),
            textElement('span', 'signal-event-time', formatSignalOffset(integerValue(event, 'monotonic_time_ns') - firstTime))
          );
          if (row.dataset.new === 'true') primary.append(textElement('span', 'signal-new-badge', 'NEW'));
          const meta = document.createElement('span');
          meta.className = 'signal-event-meta';
          meta.append(textElement('span', '', `${signalTypeLabel(event.type)} · ${signalTabKey(event) === 'unattributed' ? 'unattributed' : `tab ${signalTabKey(event)}`} · frame ${integerText(event, 'frame_id')} · event ${integerText(event, 'sequence_number')}`));
          const profileFamily = matchingSignalProfileFamily(event);
          if (profileFamily) {
            meta.append(textElement(
              'span', `signal-profile-relation${profileFamily.confidence === 'correlated' ? ' correlated' : ''}`,
              `${profileFamily.confidence === 'observed' ? 'Observed' : 'Correlated'} to selected request`
            ));
          }
          row.append(primary, meta);
          row.addEventListener('click', () => {
            state.selectedSignalEventKey = row.dataset.signalEventKey;
            state.signalDetailOpen = true;
            renderFingerprintActivity();
          });
          return row;
        });
        elements.signalRows.replaceChildren(...rows);
        if (anchorKey) {
          const restored = rows.find(row => row.dataset.signalEventKey === anchorKey);
          if (restored) elements.signalRows.scrollTop = restored.offsetTop - anchorOffset;
        }
        renderFingerprintDetail(orderedEvents.find(event => signalEventKey(event) === state.selectedSignalEventKey) ?? null);
      }

      function rebuildTrafficRequests() {
        // Hidden Traffic must not keep the previous request snapshot alive.
        state.trafficRenderedView = null;
        state.requests = state.nativeRequests;
      }

      function renderShellStatus() {
        const live = state.sessionMode === 'live';
        const preview = state.sessionMode === 'preview';
        const idle = state.sessionMode === 'idle';
        const brokerOffline = live && state.broker === 'unavailable';
        const artifactOffline = live && state.artifactReceiverConfigured &&
          (!state.artifactReceiverConnected || state.artifactReceiverError);
        const offline = brokerOffline;
        const connecting = live && state.broker === 'connecting';
        const modeLabel = live ? (offline ? 'Live offline'
          : artifactOffline ? 'Live degraded' : 'Live session')
          : idle ? 'Ready' : preview ? 'Preview' : 'Demo evidence';
        const captureLabel = connecting ? 'Connecting' : offline ? 'Offline' : artifactOffline ? 'Artifacts offline'
          : live ? 'Capturing' : idle ? 'No session' : preview ? 'Preview' : 'Demo';
        elements.sessionMode.textContent = modeLabel;
        elements.sessionMode.dataset.kind = state.sessionMode;
        elements.sessionMode.title = live
          ? 'Only native broker evidence is shown; sample rows are hidden.'
          : idle
            ? 'No evidence is bundled. Start a live capture to populate the workspace.'
            : preview
              ? 'No evidence is bundled. Start a live capture to populate the workspace.'
              : 'Deterministic developer evidence is loaded.';
        elements.capture.classList.toggle('offline', offline || artifactOffline);
        elements.capture.classList.toggle('demo', state.sessionMode === 'demo');
        elements.capture.classList.toggle('preview', preview);
        elements.capture.querySelector('span:last-child').textContent = captureLabel;
        elements.capture.setAttribute('aria-label', `${modeLabel}: ${captureLabel}`);
        elements.broker.classList.toggle('offline', offline);
        elements.broker.textContent = connecting ? 'connecting to evidence'
          : offline ? 'broker unavailable'
            : live ? 'broker connected' : idle ? 'no capture session'
              : preview ? 'standalone preview' : 'demo evidence loaded';
        elements.sampleStatus.textContent = live
          ? offline
            ? state.requests.length ? 'last requests retained' : state.events.length ? 'last live evidence retained' : 'no live evidence'
            : artifactOffline ? 'artifact capture offline'
            : 'sample rows hidden'
          : idle || preview ? 'no bundled evidence' : 'developer evidence';
        if (!state.lastUpdatedLabel) {
          elements.updated.textContent = connecting ? 'waiting for evidence'
            : offline ? state.events.length ? 'last valid evidence retained' : 'no live evidence'
              : artifactOffline ? 'artifact capture unavailable'
              : live ? 'waiting for live evidence' : idle || preview ? 'start a live capture' : 'deterministic evidence loaded';
        } else {
          elements.updated.textContent = state.lastUpdatedLabel;
        }
        document.title = live ? 'Origin Trace - Live Session'
          : idle ? 'Origin Trace' : preview ? 'Origin Trace - Preview' : 'Origin Trace - Demo Evidence';
      }

      function resetRequestSelection() {
        state.trafficRenderedView = null;
        state.originTraceController?.abort();
        state.trafficSelectionNotice = state.selectedRequestId === null ? '' : 'The selected request left the retained capture window. Choose another request.';
        state.selectedRequestId = null;
        state.selectedField = null;
        state.originTrace = null;
        state.selectedTraceRow = null;
        state.originTraceStatus = 'idle';
        state.originTraceError = null;
        state.originTraceKey = null;
        state.originTraceEtag = null;
        state.originTraceGeneration += 1;
        state.signalProfile = null;
        state.signalProfileStatus = 'idle';
        state.signalProfileError = null;
        state.signalProfileKey = null;
        state.signalProfileEtag = null;
        state.signalProfileGeneration += 1;
        evidencePackagePanel.sync();
      }

      function renderRequestCount(visibleCount, loadedCount) {
        elements.requestCount.textContent = String(visibleCount);
        const loadedLabel = loadedCount === 1 ? 'request loaded' : 'requests loaded';
        const suffix = state.eventsLimited ? ' · event window capped' : '';
        elements.requestCountLabel.textContent = visibleCount === loadedCount
          ? `${loadedLabel}${suffix}`
          : `of ${loadedCount} ${loadedCount === 1 ? 'request' : 'requests'} loaded${suffix}`;
      }

      function vmField(label, value) {
        const field = document.createElement('div'); field.className = 'vm-field';
        field.append(textElement('span', '', label), textElement('strong', '', value));
        return field;
      }

      function vmSessionPresentation(targetState) {
        const analysis = targetState.vmAnalysisDocument;
        const finding = targetState.vmFindings?.find(item => item.findingId === targetState.selectedVmFindingId);
        const workspaceDocument = targetState.vmOpcodeWorkspace;
        const workspace = finding && workspaceDocument?.analysis_digest === analysis?.document_digest
          ? vmOpcodeWorkspaceForFinding(workspaceDocument, finding) : null;
        const mode = workspace?.capture_mode ?? analysis?.capture_mode ?? 'unknown';
        if (mode === 'native-stealth') {
          return {
            mode: 'stealth',
            label: 'Native stealth',
            copy: 'This capture was launched without the DevTools endpoint. This records launch mode; it does not establish that the session was undetectable.'
          };
        }
        if (mode === 'cdp-attached') {
          return {
            mode: 'cdp',
            label: 'CDP attached',
            copy: 'This capture was launched with a DevTools endpoint for CDP. This does not establish which inspector domains were enabled.'
          };
        }
        return {
          mode: 'recorded',
          label: 'Recorded evidence',
          copy: 'Stored findings do not prove which live session mode produced them.'
        };
      }

      function renderVmSessionStatus() {
        if (!elements.vmSessionStatus) return;
        const presentation = vmSessionPresentation(state);
        const chip = textElement('span', 'vm-session-chip', presentation.label);
        chip.dataset.mode = presentation.mode;
        elements.vmSessionStatus.replaceChildren(
          chip,
          textElement('span', 'vm-session-copy', presentation.copy)
        );
      }

      function vmWorkspaceNotice(workspace) {
        const notice = document.createElement('div');
        notice.className = 'vm-workspace-notice';
        let kind = state.vmOpcodeWorkspaceStatus;
        let message = '';
        if (kind === 'malformed') {
          message = `Malformed opcode workspace was rejected. Detection findings remain visible.${workspace ? ' The last valid workspace is retained.' : ''}`;
        } else if (kind === 'unavailable') {
          message = `Opcode workspace unavailable. Detection findings remain visible.${workspace ? ' The last valid workspace is retained.' : ''}`;
        } else if (kind === 'loading') {
          message = workspace ? 'Refreshing opcode workspace. The last valid workspace remains visible.'
            : 'Loading opcode workspace.';
        } else if (!workspace) {
          kind = 'empty';
          message = 'Workspace unavailable for this finding. Detection evidence remains visible without synthesized VM semantics.';
        }
        if (!message) return null;
        notice.dataset.kind = kind;
        notice.setAttribute('role', 'status');
        notice.textContent = message;
        return notice;
      }

      function formatVmHexPreview(hex) {
        if (!hex) return '';
        const bytes = hex.match(/.{2}/g) ?? [];
        const lines = [];
        for (let offset = 0; offset < bytes.length; offset += 16) {
          lines.push(bytes.slice(offset, offset + 16).join(' '));
        }
        return lines.join('\n');
      }

      function vmModelLabel(workspace) {
        if (workspace.model === 'stack') return 'stack model';
        if (workspace.model === 'register') return 'register model';
        return 'stack or registers unproven';
      }

      function vmEvidenceClassText(workspace) {
        switch (workspace.evidence_class) {
          case 'guest-opcode-isa':
            return 'Guest opcode ISA. Samples or owned effects bind an opcode to one handler with guest PC units.';
          case 'handler-table-candidate':
            return 'Handler table candidate. Static selector arms map to entries. This is not a proven guest opcode ISA.';
          case 'call-indirect-table':
            return 'Call-indirect table. Funcref or element entries are handlers. Targets are not guest opcodes.';
          case 'cff-helper':
            return 'CFF helper. Small branch table, demoted when a larger dispatch site is present. Not a guest opcode ISA.';
          default:
            return 'No handler table was recovered. Missing arms are not a guest opcode ISA.';
        }
      }

      function vmDispatchEvidenceText(site) {
        switch (site.evidence_class) {
          case 'cff-helper': return 'CFF helper';
          case 'handler-table-candidate': return 'Handler table candidate';
          case 'call-indirect-table': return 'Call-indirect table';
          default: return 'Static dispatch candidate';
        }
      }

      // Structural dispatch classification, inserted as text only. A router
      // never supplies guest opcodes, whatever its arm count.
      function vmDispatchShapeSite(workspace, byteOffset) {
        return workspace.dispatch_classification?.sites.find(site => site.location.byte_offset === byteOffset) ?? null;
      }

      function vmCountText(count, singular, plural = `${singular}s`) {
        return `${count} ${count === 1 ? singular : plural}`;
      }

      // Older documents carry no classification; their rows stay unchanged.
      function vmDispatchShapeSuffix(workspace, byteOffset) {
        return workspace.dispatch_classification ? ` · ${vmDispatchShapeText(vmDispatchShapeSite(workspace, byteOffset))}` : '';
      }

      function vmDispatchShapeText(site) {
        if (!site) return 'structure not classified';
        const axes = `${site.dispatch_kind} / ${site.selector_source} / ${site.repeats}`;
        if (site.role === 'multiplexer') return `${axes} · router, no guest opcodes claimed`;
        const helper = site.selector.through_helper ? ', fetched through a helper' : '';
        if (site.role === 'interpreter-candidate') return `${axes} · cursor-loop interpreter candidate${helper}`;
        if (['string', 'arguments'].includes(site.buffer_kind)) return `${axes} · ${site.buffer_kind} scan, no guest opcodes claimed`;
        if (site.selector.through_lookup) return `${axes} · second-level lookup, no guest opcodes claimed`;
        return `${axes} · not an interpreter loop`;
      }

      function renderVmDispatchStructure(workspace) {
        const section = document.createElement('section'); section.className = 'vm-workspace-card';
        section.append(textElement('h4', '', 'Dispatch structure'));
        const classification = workspace.dispatch_classification;
        if (!classification) {
          section.append(textElement('p', '', 'No structural dispatch classification is retained in this document.'));
          return section;
        }
        const roles = classification.role_counts;
        section.append(textElement('p', '', `${vmCountText(classification.site_count, 'classified site')}: ${vmCountText(roles['interpreter-candidate'], 'cursor-loop interpreter candidate')}, ${vmCountText(roles.multiplexer, 'router')}, ${roles.other} other. ${classification.sites.length} listed; ${classification.omitted_site_count} omitted from this bounded list.`));
        for (const omission of classification.omissions) {
          const count = omission.omitted_records === undefined ? '' : ` ${vmCountText(omission.omitted_records, 'record')} omitted.`;
          section.append(textElement('p', 'vm-workspace-notice', `${omission.reason}: ${omission.detail}${count}`));
        }
        section.append(textElement('p', '', 'Structural classification only: kind / selector source / repeats. A router dispatches once on a call argument; its arms and constants are routing labels and no guest opcodes are claimed. Only a cursor-loop interpreter candidate supplies opcode handlers.'));
        appendVmPagedRows(section, classification.sites, 'dispatch sites', site => {
          const row = document.createElement('details'); row.className = 'vm-effect-row';
          const where = site.location.line !== null
            ? `line ${site.location.line}:${site.location.column}`
            : `${site.location.function_index === null ? 'module' : `f${site.location.function_index}`} · byte ${site.location.byte_offset}`;
          row.append(textElement('summary', '', `${site.instruction} · ${where} · ${vmDispatchShapeText(site)}`));
          const loop = site.loop ? `loop bytes [${site.loop.byte_offset}, ${site.loop.byte_offset + site.loop.byte_size})` : 'no enclosing loop';
          const arms = site.arm_count === null ? 'arm count unknown' : `${site.arm_count} ${site.dispatch_kind === 'compare_chain' ? 'comparisons' : 'arms'}`;
          const buffer = site.buffer_kind === null ? '' : ` · buffer ${site.buffer_kind}`;
          row.append(textElement('p', 'vm-effect-detail', `Selector ${site.selector.expression} · ${arms} · ${loop}${buffer}`));
          if (site.table) {
            const slots = site.table.matching_slots === null ? 'table layout unknown'
              : `${site.table.matching_slot_count} of ${site.table.populated_slot_count} placed slots match type ${site.table.type_index}: ${site.table.matching_slots.join(', ') || 'none'}`;
            row.append(textElement('p', 'vm-effect-detail', `Table ${site.table.table_index} · ${slots}`));
          }
          return row;
        });
        return section;
      }

      function renderVmHandlerTables(workspace) {
        const section = document.createElement('section'); section.className = 'vm-workspace-card';
        section.append(textElement('h4', '', 'Handler tables'));
        const tables = Array.isArray(workspace.handler_tables) ? workspace.handler_tables : [];
        if (!tables.length) {
          section.append(textElement('p', '', 'No clustered handler table is retained. Static arms are not a guest opcode ISA.'));
          return section;
        }
        section.append(textElement('p', '', 'Duplicate targets are clustered. selector_count is exact. A listed selector prefix is not a shorter table. These rows do not prove a guest PC, stack, or registers.'));
        appendVmPagedRows(section, tables, 'handler tables', table => {
          const row = document.createElement('details'); row.className = 'vm-effect-row';
          const count = table.kind === 'br_table'
            ? `${table.arm_count} arms, ${table.unique_target_count} unique targets`
            : table.kind === 'element'
              ? `${table.entry_count} slots, ${table.unique_target_count} unique functions`
              : 'dynamic target';
          const shape = table.byte_offset === null ? '' : vmDispatchShapeSuffix(workspace, table.byte_offset);
          row.append(textElement('summary', '', `${table.kind} · ${table.evidence_class} · ${count}${shape}`));
          const clusters = table.clusters.map(cluster => {
            const noun = table.kind === 'element' ? 'function' : 'label depth';
            const more = cluster.selectors.length < cluster.selector_count ? ` · listed ${cluster.selectors.length} of ${cluster.selector_count}` : '';
            return `${noun} ${cluster.target} · selectors ${cluster.selectors.join(', ') || 'none'}${more}`;
          });
          if (table.omitted_cluster_count) clusters.push(`${table.omitted_cluster_count} additional target clusters omitted`);
          row.append(textElement('p', 'vm-effect-detail', clusters.join('; ') || 'No static targets.'));
          if (Array.isArray(table.segments) && table.segments.length) {
            row.append(textElement('p', 'vm-effect-detail', table.segments.map(segment => segment.placement === 'placed'
              ? `segment ${segment.segment_index} at slot ${segment.offset} · ${segment.entry_count} entries`
              : segment.placement === 'relative'
                ? `segment ${segment.segment_index} relative to imported global ${segment.global_index} · ${segment.entry_count} entries, slots unknown`
                : segment.placement === 'out-of-range'
                  ? `segment ${segment.segment_index} at slot ${segment.offset} ends past the declared table size · ${segment.entry_count} entries, not placed`
                  : segment.placement === 'unreached'
                    ? `segment ${segment.segment_index} at slot ${segment.offset} follows an out-of-range segment · ${segment.entry_count} entries, never applied`
                    : `segment ${segment.segment_index} offset unresolved · ${segment.entry_count} entries, slots unknown`).join('; ') +
              (table.omitted_segment_count ? `; ${vmCountText(table.omitted_segment_count, 'more segment')} not listed` : '')));
          }
          return row;
        });
        return section;
      }

      function renderVmDispatchSites(workspace) {
        const panel = document.createElement('div');
        panel.append(renderVmDispatchInventory(workspace));
        if (workspace.dispatch_classification) panel.append(renderVmDispatchStructure(workspace));
        return panel;
      }

      function renderVmDispatchInventory(workspace) {
        const section = document.createElement('section'); section.className = 'vm-workspace-card';
        section.append(textElement('h4', '', 'Static dispatch inventory'));
        const inventory = workspace.dispatch_inventory;
        if (!inventory) {
          section.append(textElement('p', '', 'No module-wide dispatch inventory is retained in this document.'));
          return section;
        }
        section.append(textElement('p', '', `${vmCountText(inventory.site_count, 'module site')}: ${inventory.br_table_count} br_table, ${inventory.call_indirect_count} call_indirect. ${vmCountText(inventory.candidates.length, 'ranked site')} retained; ${inventory.omitted_site_count} omitted from this bounded list.`));
        section.append(textElement('p', '', 'Candidate dispatchers are ranked by loop shape, then by br_table arm count or call_indirect element fanout. Arm counts exclude the default. Unique branch targets cluster repeated Wasm labels. A small br_table is a CFF/relooper candidate, a large br_table is a handler-table candidate, and call_indirect is an indirect funcref candidate. None of these is a proven guest opcode ISA. This inventory does not invent registers, a stack, or a guest PC.'));
        const retainedRows = vmOpcodeRows(workspace);
        const classificationLabel = classification => classification === 'cff-helper-candidate' ? 'CFF / relooper candidate'
          : classification === 'indirect-handler-candidate' ? 'indirect funcref candidate' : 'handler-table candidate';
        appendVmPagedRows(section, inventory.candidates, 'dispatch candidates', site => {
          const row = document.createElement('details'); row.className = 'vm-effect-row';
          const selected = site.byte_offset === inventory.selected_byte_offset;
          const count = site.kind === 'call_indirect'
            ? (site.element_fanout === null ? 'element fanout unknown' : counted(site.element_fanout, 'static element entry', 'static element entries'))
            : `${counted(site.arm_count, 'arm')} + default · ${counted(site.unique_target_count, 'unique branch target')}`;
          const rank = inventory.candidates.indexOf(site) + 1;
          const classification = classificationLabel(site.classification);
          const honesty = site.kind === 'call_indirect'
            ? 'Static funcref initializers only. No arm index, guest opcode, guest PC, register, or stack is inferred.'
            : site.classification === 'dispatch-candidate'
              ? 'Selector index to Wasm branch target. Samples are absent, so this is a handler-table candidate, not a proven guest opcode ISA. No guest PC, register, or stack is inferred.'
              : 'Static CFF or relooper arms. No guest opcode, guest PC, register, or stack is inferred.';
          // Rank and the heuristic label stay in the collapsed summary. Opening
          // every row is not usable once the bounded list reaches 256 sites.
          row.append(textElement('summary', '', `#${rank} · ${selected ? 'Default · ' : ''}f${site.function_index} · ${site.kind} · ${count} · byte ${site.byte_offset} · ${classification}${vmDispatchShapeSuffix(workspace, site.byte_offset)}`));
          if (selected) row.open = true;
          row.append(textElement('p', 'vm-effect-detail', `${classification} · ${vmDispatchEvidenceText(site)} · body ${site.function_body_size} bytes · loop depth ${site.loop_depth} · IP-like read/write pattern ${site.ip_like ? 'present' : 'absent'}. ${honesty}`));
          const retained = retainedRows.find(candidate => candidate.source === `${site.byte_offset} + ${site.byte_size} bytes`);
          if (retained) {
            const select = textElement('button', 'secondary-button', 'Select retained site'); select.type = 'button';
            const chooseRetainedSite = () => {
              const handler = [...document.querySelectorAll('.vm-handler-row')].find(item => item.dataset.handlerKey === retained.key);
              if (!handler) return;
              // An excluding filter hides the row. Clear it before activation so
              // the analyst lands on the site instead of a hidden selection.
              if (handler.hidden) {
                const scope = handler.closest('.vm-workspace') || handler.closest('.vm-workspace-card') || document;
                const filter = scope.querySelector('input[aria-label="Filter retained handlers"], input[type="search"]');
                if (filter) { filter.value = ''; filter.dispatchEvent(new Event('input')); }
              }
              handler.click(); revealVmHandler(handler); handler.focus({preventScroll: true});
            };
            select.addEventListener('click', chooseRetainedSite);
            // Own Enter and Space here. A keydown without the browser's default
            // button activation must still clear an excluding filter.
            select.addEventListener('keydown', event => {
              if (event.repeat || event.altKey || event.ctrlKey || event.metaKey || event.shiftKey) return;
              if (event.key !== 'Enter' && event.key !== ' ') return;
              event.preventDefault();
              chooseRetainedSite();
            });
            row.append(select);
          } else {
            row.append(textElement('p', 'vm-effect-detail', 'Not in the retained handler neighborhood. This inventory does not expand or execute it.'));
          }
          return row;
        });
        return section;
      }

      function renderVmHandlers(workspace, onSelection = null) {
        const section = document.createElement('section'); section.className = 'vm-workspace-card';
        const rows = vmOpcodeRows(workspace);
        const heading = document.createElement('div'); heading.className = 'vm-workspace-heading';
        const listingCount = workspace.runtime !== 'webassembly'
          ? counted(workspace.handlers.length, 'candidate handler')
          : rows.length === workspace.handlers.length
            ? counted(workspace.handlers.length, 'dispatch-arm candidate', 'dispatch-arm candidates')
            : `${counted(rows.length, 'dispatch site')} · ${counted(workspace.handlers.length, 'retained arm')}`;
        heading.append(textElement('h4', '', 'Handler listing'), textElement('span', '', listingCount));
        section.append(heading);
        if (!rows.some(row => row.key === state.selectedVmHandlerKey)) {
          state.selectedVmHandlerKey = rows[0]?.key ?? null;
        }
        if (rows.length === 0) {
          section.append(textElement('div', 'vm-workspace-empty', 'No handler candidates were characterized. Missing samples do not suppress inferred handlers.'));
          return section;
        }
        const header = document.createElement('div'); header.className = 'vm-handler-head';
        header.setAttribute('aria-hidden', 'true');
        ['source offset', 'opcode', 'operation / handler', 'evidence', 'samples'].forEach(label => header.append(textElement('span', '', label)));
        const list = document.createElement('div'); list.className = 'vm-handler-list';
        list.setAttribute('role', 'listbox'); list.setAttribute('aria-label', 'Opcode handlers');
        const selectRow = (row, focus = true) => {
          state.selectedVmHandlerKey = row.dataset.handlerKey;
          [...list.querySelectorAll('.vm-handler-row')].forEach(candidate => {
            const selected = candidate === row;
            candidate.setAttribute('aria-selected', String(selected));
            candidate.tabIndex = selected ? 0 : -1;
          });
          if (focus) row.focus({ preventScroll: true });
          if (onSelection) onSelection(row.dataset.handlerKey);
          document.querySelectorAll('[data-vm-symbol-key]').forEach(symbol => symbol.setAttribute('aria-pressed', String(symbol.dataset.vmSymbolKey === row.dataset.handlerKey)));
        };
        rows.forEach(rowData => {
          const row = document.createElement('button'); row.className = 'vm-handler-row'; row.type = 'button';
          row.dataset.handlerKey = rowData.key;
          row.setAttribute('role', 'option');
          row.setAttribute('aria-selected', String(rowData.key === state.selectedVmHandlerKey));
          row.tabIndex = rowData.key === state.selectedVmHandlerKey ? 0 : -1;
          const label = document.createElement('span'); label.className = 'vm-handler-label';
          label.append(textElement('strong', '', rowData.label), textElement('small', '', `source ${rowData.source}`));
          for (const position of rowData.positions) label.append(textElement('small', '', position));
          if (!rowData.positions.length) label.append(textElement('small', '', 'PC unknown · sampled handler unknown · bytecode unknown'));
          if (rowData.samples > rowData.positions.length) label.append(textElement('small', '',
            `${rowData.samples - rowData.positions.length} additional accepted samples; ${rowData.retainedPositions} positions retained in the workspace.`));
          const epistemic = textElement('span', 'vm-handler-state', rowData.state);
          epistemic.dataset.state = rowData.state;
          row.append(
            textElement('span', 'vm-handler-source', rowData.source),
            textElement('strong', 'vm-handler-opcode', rowData.opcode),
            label,
            epistemic,
            textElement('span', 'vm-handler-samples', String(rowData.samples)),
            textElement('span', 'vm-handler-notes', rowData.notes)
          );
          row.addEventListener('click', () => selectRow(row));
          row.addEventListener('keydown', event => {
            if (!['ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) return;
            event.preventDefault();
            const options = [...list.querySelectorAll('.vm-handler-row')].filter(option => !option.hidden);
            const current = options.indexOf(row);
            const next = event.key === 'Home' ? 0 : event.key === 'End' ? options.length - 1
              : (current + (event.key === 'ArrowDown' ? 1 : -1) + options.length) % options.length;
            selectRow(options[next]);
          });
          list.append(row);
        });
        const toolbar = document.createElement('div'); toolbar.className = 'vm-listing-toolbar';
        toolbar.setAttribute('role', 'group'); toolbar.setAttribute('aria-label', 'Handler navigation');
        for (const [label, direction, glyph] of [['Previous handler', -1, '↑'], ['Next handler', 1, '↓']]) {
          const button = textElement('button', 'secondary-button', glyph); button.type = 'button';
          button.title = label; button.setAttribute('aria-label', label);
          button.addEventListener('click', () => {
            const visible = [...list.children].filter(row => !row.hidden);
            if (!visible.length) return;
            const index = visible.findIndex(row => row.dataset.handlerKey === state.selectedVmHandlerKey);
            const nextIndex = index < 0 ? (direction < 0 ? visible.length - 1 : 0) : (index + direction + visible.length) % visible.length;
            const next = visible[nextIndex];
            selectRow(next); next.scrollIntoView({block: 'nearest'});
          });
          toolbar.append(button);
        }
        const search = document.createElement('input'); search.type = 'search'; search.placeholder = 'Filter handlers';
        search.setAttribute('aria-label', 'Filter retained handlers'); search.maxLength = 256;
        const count = textElement('span', 'vm-listing-count', counted(rows.length, 'handler'));
        count.setAttribute('role', 'status');
        search.addEventListener('input', () => {
          const query = search.value.trim().toLowerCase();
          const visible = [...list.children].filter((row, index) => {
            row.hidden = !`${rows[index].source} ${rows[index].opcode} ${rows[index].label}`.toLowerCase().includes(query);
            return !row.hidden;
          });
          [...list.children].forEach(row => { row.tabIndex = -1; });
          const selected = visible.find(row => row.dataset.handlerKey === state.selectedVmHandlerKey) ?? visible[0];
          if (selected) selected.tabIndex = 0;
          count.textContent = `${visible.length} / ${counted(rows.length, 'handler')}`;
          [...toolbar.querySelectorAll('button')].forEach(button => { button.disabled = !visible.length; });
          updateVmNavigationMenus();
        });
        toolbar.append(search, count);
        section.append(toolbar, header, list);
        return section;
      }

      function appendVmPagedRows(target, items, label, renderRow, pageSize = 32) {
        const controls = document.createElement('div'); controls.className = 'vm-evidence-pager';
        controls.setAttribute('role', 'group'); controls.setAttribute('aria-label', `${label} pages`);
        const previous = textElement('button', 'secondary-button', `Previous ${label}`); previous.type = 'button';
        const next = textElement('button', 'secondary-button', `Next ${label}`); next.type = 'button';
        const status = textElement('span', 'vm-listing-count', ''); status.setAttribute('role', 'status');
        const rows = document.createElement('div'); rows.dataset.vmPagedRows = label;
        let page = 0;
        const draw = () => {
          const start = page * pageSize;
          rows.replaceChildren(...items.slice(start, start + pageSize).map(renderRow));
          status.textContent = `${items.length ? start + 1 : 0}–${Math.min(items.length, start + pageSize)} of ${items.length} ${label}`;
          previous.disabled = page === 0; next.disabled = start + pageSize >= items.length;
        };
        previous.addEventListener('click', () => { if (previous.disabled) return; page--; draw(); (previous.disabled ? next : previous).focus(); });
        next.addEventListener('click', () => { if (next.disabled) return; page++; draw(); (next.disabled ? previous : next).focus(); });
        controls.append(previous, status, next); target.append(controls, rows); draw();
      }

      function vmEffectCellText(cell) {
        const location = cell.index ?? (cell.operand === null ? 'unknown' : `operand ${cell.operand}`);
        return `${cell.space}[${location}] = ${cell.value ?? 'unknown'}`;
      }

      function renderVmEffects(workspace) {
        const section = document.createElement('section'); section.className = 'vm-workspace-card';
        section.setAttribute('aria-label', 'Declarative opcode effects');
        const heading = document.createElement('div'); heading.className = 'vm-workspace-heading';
        heading.append(textElement('h4', '', 'Declarative effects'), textElement('span', '', 'owned declarations · no execution'));
        section.append(heading);
        const effects = workspace.handlers.flatMap(handler => handler.effects.map(effect => ({handler, effect})));
        appendVmPagedRows(section, effects, 'effects', ({handler, effect}) => {
            const row = document.createElement('details'); row.className = 'vm-effect-row';
            const summary = document.createElement('summary');
            summary.textContent = `Opcode ${handler.opcode ?? 'unknown'} · ${effect.operation} · ${effect.evidence_class}`;
            row.append(summary);
            const fields = document.createElement('div'); fields.className = 'vm-fields';
            const span = value => value === null ? 'unknown' : `${value.byte_offset} + ${value.byte_size} bytes`;
            const target = effect.flow.target_operand === null ? effect.flow.target_offset ?? 'unknown' : `operand ${effect.flow.target_operand}`;
            fields.append(vmField('effect', effect.effect_id), vmField('instruction bytes', effect.instruction_size ?? 'unknown'),
              vmField('flow', `${effect.flow.kind}${['branch', 'jump', 'call'].includes(effect.flow.kind) ? ` → ${target}` : ''}`),
              vmField('atomic group', span(effect.atomic_group)), vmField('superoperator', span(effect.superoperator)));
            row.append(fields);
            const body = document.createElement('div'); body.className = 'vm-effect-detail';
            body.append(textElement('div', '', `Operands: ${effect.operand_layout.length ? effect.operand_layout.map(operand => `${operand.name} (${operand.kind}): ${operand.byte_offset === null ? 'byte location unknown' : `+${operand.byte_offset}, ${operand.byte_size} bytes, little-endian`}`).join('; ') : 'none declared'}`),
              textElement('div', '', `Reads: ${effect.reads.length ? effect.reads.map(vmEffectCellText).join('; ') : 'none declared'}`),
              textElement('div', '', `Writes: ${effect.writes.length ? effect.writes.map(vmEffectCellText).join('; ') : 'none declared'}`));
            row.append(body);
            if (handler.effects.length > 1 && !vmUniqueWorkspaceEffect(handler)) row.append(textElement('p', 'vm-workspace-notice', 'Conflicting declarations. None is selected for traversal.'));
            return row;
        });
        if (effects.length === 0) section.append(textElement('div', 'vm-workspace-empty', 'No source-bound declarative effects are available. Observed changed cells do not establish reads or causes.'));
        return section;
      }

      function renderVmReachability(workspace) {
        const traversal = workspace.traversal;
        const section = document.createElement('section'); section.className = 'vm-workspace-card';
        section.setAttribute('aria-label', 'Reachable guest instructions');
        const heading = document.createElement('div'); heading.className = 'vm-workspace-heading';
        heading.append(textElement('h4', '', 'Reachable instructions'), textElement('span', '', `${traversal.instructions.length} positions · ${traversal.complete ? 'walk complete' : 'frontier remains'}`));
        section.append(heading);
        section.append(textElement('div', 'vm-effect-detail', 'Declared static possibilities. Both branch edges are followed without executing captured source or modules.'));
        const rows = document.createElement('div'); rows.className = 'vm-reachable-list';
        const outgoing = new Map();
        for (const edge of traversal.edges) {
          const key = `${edge.artifact_id}:${edge.from_offset}`;
          if (!outgoing.has(key)) outgoing.set(key, []);
          outgoing.get(key).push(edge);
        }
        appendVmPagedRows(rows, traversal.instructions, 'reachable instructions', instruction => {
          const row = document.createElement('details'); row.className = 'vm-effect-row';
          const title = document.createElement('summary');
          title.textContent = `Artifact ${instruction.artifact_id} · byte ${instruction.byte_offset} · opcode ${instruction.opcode} · ${instruction.byte_size} bytes`;
          const edges = outgoing.get(`${instruction.artifact_id}:${instruction.byte_offset}`) ?? [];
          row.append(title, textElement('div', 'vm-effect-detail', `${instruction.effect_id}: ${edges.length ? edges.map(edge => `${edge.kind} → ${edge.to_offset ?? 'unknown'}`).join('; ') : 'halt, no successor'}`));
          return row;
        });
        section.append(rows);
        const frontier = document.createElement('ul'); frontier.className = 'vm-coverage-omissions';
        if (traversal.frontier.length === 0) frontier.append(textElement('li', '', 'No unresolved reachable edge. This does not prove runtime termination or semantics.'));
        for (const stop of traversal.frontier) frontier.append(textElement('li', '', `Artifact ${stop.artifact_id ?? 'unknown'} · byte ${stop.byte_offset ?? 'unknown'}: ${stop.reason}`));
        section.append(frontier);
        return section;
      }

      function renderVmBytecode(workspace) {
        const section = document.createElement('section'); section.className = 'vm-workspace-card';
        const heading = document.createElement('div'); heading.className = 'vm-workspace-heading';
        heading.append(textElement('h4', '', 'Bytecode'), textElement('span', '', 'bounded evidence preview'));
        section.append(heading);
        const previews = [...workspace.snapshots];
        if (workspace.captured_module_preview) previews.push({...workspace.captured_module_preview, origin: 'captured-module'});
        const selector = document.createElement('select'); selector.className = 'vm-snapshot-selector'; selector.setAttribute('aria-label', 'Retained byte evidence');
        previews.forEach((snapshot, index) => { const option = document.createElement('option'); option.value = String(index); option.textContent = `Artifact ${snapshot.artifact_id} · ${snapshot.origin === 'captured-module' ? `dispatch at byte ${snapshot.byte_offset} · ` : ''}${snapshot.byte_count} bytes`; selector.append(option); });
        const initial = Math.max(0, previews.findIndex(snapshot => snapshot.artifact_id === workspace.bytecode_artifact_id));
        selector.value = String(initial); selector.disabled = previews.length === 0;
        const label = document.createElement('label'); label.append(document.createTextNode('Retained evidence '), selector);
        const previewPanel = document.createElement('div'); section.append(label, previewPanel);
        const draw = () => {
          const snapshot = previews[Number(selector.value)] ?? null;
          previewPanel.replaceChildren();
          const fields = document.createElement('div'); fields.className = 'vm-fields vm-bytecode-fields';
          fields.append(
            vmField('artifact', snapshot?.artifact_id ?? workspace.bytecode_artifact_id ?? 'not captured'),
            vmField('digest', snapshot?.sha256 ?? 'not recorded'),
            vmField('origin', snapshot?.origin ?? 'unavailable'),
            vmField(snapshot?.origin === 'captured-module' ? 'instruction bytes' : 'snapshot bytes', snapshot?.byte_count ?? 0),
            vmField('truncation', snapshot?.truncated === true ? 'preview truncated' : snapshot?.truncated === false ? 'complete preview' : 'not recorded'),
            vmField('unavailable reason', snapshot?.unavailable_reason ?? 'none')
          );
          if (snapshot?.origin === 'captured-module') fields.append(vmField('module byte offset', snapshot.byte_offset));
          previewPanel.append(fields);
          const preview = formatVmHexPreview(snapshot?.preview_hex);
          if (preview) {
            const bytes = textElement('pre', 'vm-bytecode-preview', preview);
            bytes.setAttribute('aria-label', snapshot?.origin === 'captured-module' ? 'Captured module instruction hex preview' : 'Bytecode hex preview');
            previewPanel.append(bytes);
            if (snapshot?.origin === 'captured-module') {
              previewPanel.append(textElement('p', 'vm-effect-detail', 'Dispatch instruction bytes from the captured module. This is not a runtime memory snapshot.'));
            }
          } else {
            previewPanel.append(textElement('div', 'vm-workspace-empty', snapshot?.unavailable_reason || 'No bytecode preview was retained.'));
          }
        };
        selector.addEventListener('change', draw); draw();
        return section;
      }

      function renderVmWorkspaceCoverage(workspace) {
        const section = document.createElement('section'); section.className = 'vm-workspace-card';
        const heading = document.createElement('div'); heading.className = 'vm-workspace-heading';
        heading.append(textElement('h4', '', 'Coverage'), textElement('span', '', workspace.coverage.complete ? 'complete' : 'partial'));
        const coverage = workspace.coverage;
        const percent = coverage.retained_snapshot_bytes > 0
          ? Math.max(0, Math.min(100, coverage.characterized_bytes * 100 / coverage.retained_snapshot_bytes))
          : 0;
        const panel = document.createElement('div'); panel.className = 'vm-coverage';
        const line = document.createElement('div'); line.className = 'vm-coverage-line';
        line.append(
          textElement('span', '', 'characterized bytes / retained snapshot bytes'),
          textElement('strong', '', `${coverage.characterized_bytes} / ${coverage.retained_snapshot_bytes}`)
        );
        const bar = document.createElement('div'); bar.className = 'vm-coverage-bar';
        bar.setAttribute('role', 'progressbar'); bar.setAttribute('aria-valuemin', '0');
        bar.setAttribute('aria-valuemax', '100'); bar.setAttribute('aria-valuenow', String(percent));
        const fill = document.createElement('span'); fill.style.width = `${percent}%`; bar.append(fill);
        panel.append(line, bar, textElement('div', 'vm-coverage-counts',
          `${coverage.uncharacterized_bytes} uncharacterized bytes · ${coverage.handler_count} handler candidates`));
        const omissions = document.createElement('ul'); omissions.className = 'vm-coverage-omissions';
        if (coverage.omissions.length === 0) {
          omissions.append(textElement('li', '', coverage.complete ? 'No named omissions.' : 'Partial coverage has no named omission.'));
        } else {
          coverage.omissions.forEach(omission => {
            const item = document.createElement('li');
            item.append(textElement('strong', '', omission.reason));
            if (omission.detail) item.append(document.createTextNode(`: ${omission.detail}`));
            omissions.append(item);
          });
        }
        section.append(heading, panel, omissions);
        section.append(textElement('h4', '', 'Characterized byte ranges'), textElement('p', 'vm-effect-detail', 'Source-bound attributed bytes, not execution coverage. Ranges may overlap; totals count their union.'));
        appendVmPagedRows(section, coverage.attributions, 'byte attributions', attribution =>
          textElement('p', 'vm-effect-detail', `Artifact ${attribution.artifact_id} · bytes [${attribution.byte_offset}, ${attribution.byte_offset + attribution.byte_size}) · ${attribution.byte_size} bytes · opcode ${attribution.opcode} · ${attribution.kind} · ${attribution.evidence_class}`));
        return section;
      }

      function renderVmWorkspaceUnknowns(workspace) {
        const section = document.createElement('section'); section.className = 'vm-workspace-card';
        const heading = document.createElement('div'); heading.className = 'vm-workspace-heading';
        heading.append(textElement('h4', '', 'Residual unknowns'), textElement('span', '', `${workspace.unknowns.length} unresolved`));
        const evidence = document.createElement('div'); evidence.className = 'vm-analysis-evidence vm-workspace-unknowns';
        if (workspace.unknowns.length === 0) {
          const row = document.createElement('div'); row.className = 'vm-analysis-rule';
          row.append(textElement('strong', '', 'unknowns'), textElement('span', '', 'No residual unknowns were reported.'), textElement('b', '', '0'));
          evidence.append(row);
        } else {
          workspace.unknowns.forEach(unknown => {
            const row = document.createElement('div'); row.className = 'vm-analysis-rule';
            row.append(textElement('strong', '', 'unknown'), textElement('span', '', unknown), textElement('b', '', '?'));
            evidence.append(row);
          });
        }
        section.append(heading, evidence);
        return section;
      }

      const ownedExperimentDrafts = new Map();
      const ownedExperimentResults = new Map();
      let ownedExperimentPending = false;
      function renderVmOwnedExperiment(workspace) {
        const section = document.createElement('section'); section.className = 'vm-workspace-card';
        section.append(textElement('h4', '', 'Isolated owned opcode experiment'));
        section.append(textElement('p', '', 'Opt-in native fixture only. This disposable process does not use a baseline tab. Confirmation applies only to the listed inputs and does not generalize.'));
        const references = {'32f42d2408c8b2b77539c49ad458f3923d819fedc323e6529bbff7e83b14a52e':'register', 'e757c3029fdbf8ef0c77845e99c9270ad70d533c76a5625fb4d64129543c0812':'stack'};
        const fixture = references[workspace.source_artifact_sha256];
        const candidates = workspace.handlers.flatMap(h => [2,7].includes(h.opcode) ? h.effects.filter(e =>
          ['inferred','observed'].includes(e.evidence_class) && e.operation === (h.opcode === 2 ? 'add_modulo_2_64' : 'branch_nonzero')).map(e=>({opcode:h.opcode,effect:e})) : []);
        if (!fixture || candidates.length === 0) { section.append(textElement('p', '', 'Unavailable: an exact owned reference source and supported effect declaration are required.')); return section; }
        const key = `${state.vmOpcodeWorkspace.document_digest}:${workspace.source_artifact_sha256}:${workspace.interpreter_artifact_id}`;
        const workspaceDigest = state.vmOpcodeWorkspace.document_digest;
        let draft = ownedExperimentDrafts.get(key);
        if (!draft) { if(ownedExperimentDrafts.size>=64) ownedExperimentDrafts.delete(ownedExperimentDrafts.keys().next().value); draft={opcode:String(candidates[0].opcode),left:'7',right:'5',value:'12',next_pc:candidates[0].opcode===2?'3':'10',branch:'true'}; ownedExperimentDrafts.set(key,draft); }
        const form = document.createElement('form'); form.className='vm-experiment-form';
        const select = document.createElement('select'); select.setAttribute('aria-label','Owned opcode');
        candidates.forEach(c=>{ const option=document.createElement('option'); option.value=String(c.opcode); option.textContent=`${c.opcode}: ${c.effect.operation}`;select.append(option); }); select.value=draft.opcode;
        const label = (name,node) => { const l=document.createElement('label');l.append(document.createTextNode(`${name} `),node);form.append(l); };
        label('Opcode',select);
        const fields={};
        for (const [name,title] of [['left','Left input (fixed 7)'],['right','Right input (fixed 5)'],['value','Expected selected value'],['next_pc','Expected next instruction index']]) {
          const input=document.createElement('input');input.type='text';input.inputMode='numeric';input.maxLength=20;input.value=draft[name];
          input.addEventListener('input',()=>{draft[name]=input.value;});fields[name]=input;label(title,input);
        }
        select.addEventListener('change',()=>{draft.opcode=select.value;draft.next_pc=select.value==='2'?'3':'10';fields.next_pc.value=draft.next_pc;});
        const branch=document.createElement('select'); for(const [value,title] of [['true','Taken'],['false','Not taken']]) {const option=document.createElement('option');option.value=value;option.textContent=title;branch.append(option);} branch.value=draft.branch;branch.addEventListener('change',()=>{draft.branch=branch.value;});label('Expected branch (opcode 7)',branch);
        form.append(textElement('p','',fixture==='register'?'Selected state: register 0 for add; unchanged register 2 for branch.':'Selected state: stack slot 0 for add or branch.'));
        const run=document.createElement('button');run.type='submit';run.textContent='Run isolated native experiment';run.disabled=ownedExperimentPending;
        const load=document.createElement('button');load.type='button';load.textContent='Read saved results';
        const output=document.createElement('div');output.setAttribute('role','status');
        const retain = rows => { if(!ownedExperimentResults.has(key) && ownedExperimentResults.size>=64) ownedExperimentResults.delete(ownedExperimentResults.keys().next().value); ownedExperimentResults.set(key,rows); };
        const show = rows => { output.replaceChildren(); if(rows.length===0) output.append(textElement('p','','No saved result for this exact workspace and selected effect.')); rows.forEach(row=>output.append(textElement('p','',`${row.status}: opcode ${row.request.opcode}, inputs ${row.request.inputs.left}, ${row.request.inputs.right}; expected ${row.request.expected.value}, next PC ${row.request.expected.next_pc}; observed ${row.observed?.effect.value ?? 'unknown'}, handler ${row.observed?.handler_index ?? 'unknown'}, PC ${row.observed?.pc_before ?? 'unknown'} → next PC ${row.observed?.effect.next_pc ?? 'unknown'}. ${row.reason}. These inputs only; does not generalize.`))); };
        show(ownedExperimentResults.get(key) ?? []);
        form.addEventListener('submit',async event=>{
          event.preventDefault(); if(ownedExperimentPending) return;
          const candidate=candidates.find(c=>String(c.opcode)===select.value); if(!candidate) return;
          const request={command_id:crypto.randomUUID(),fixture,workspace_digest:workspaceDigest,
            source_artifact_sha256:workspace.source_artifact_sha256,interpreter_artifact_id:workspace.interpreter_artifact_id,finding_id:workspace.finding_id,
            opcode:candidate.opcode,effect_id:candidate.effect.effect_id,inputs:{left:fields.left.value,right:fields.right.value},
            expected:{operation:candidate.effect.operation,value:fields.value.value,next_pc:fields.next_pc.value,branch_taken:candidate.opcode===7?branch.value==='true':null}};
          ownedExperimentPending=true;run.disabled=true;output.textContent='Running the disposable owned fixture. No automatic retry.';
          try {const response=await fetch('/api/analysis/vm/experiments',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(request),signal:AbortSignal.timeout(30000)});
            const row=await response.json();if(!response.ok || !isVmOwnedExperimentRecord(row) || !sameVmOwnedExperimentRequest(row.request,request)) throw new Error('Outcome unknown or refused. Read saved results before trying another experiment.');
            const rows=[...(ownedExperimentResults.get(key) ?? []),row].slice(-64);retain(rows);show(rows);
          } catch(error) {output.textContent=error.message;} finally {ownedExperimentPending=false;document.querySelectorAll('.vm-experiment-form button[type=submit]').forEach(button=>{button.disabled=false;});}
        });
        load.addEventListener('click',async()=>{load.disabled=true;try {const response=await fetch('/api/analysis/vm/experiments',{cache:'no-store',signal:AbortSignal.timeout(5000)});const doc=await response.json();
          if(!response.ok || doc.schema!=='reb-owned-opcode-experiments-v1' || !Array.isArray(doc.records) || doc.records.length>64 || !doc.records.every(isVmOwnedExperimentRecord)) throw new Error('Saved experiment results are unavailable or malformed.');
          const rows=doc.records.filter(r=>r.request.workspace_digest===workspaceDigest && r.request.finding_id===workspace.finding_id && r.request.source_artifact_sha256===workspace.source_artifact_sha256 && r.request.interpreter_artifact_id===workspace.interpreter_artifact_id && candidates.some(c=>c.opcode===r.request.opcode && c.effect.effect_id===r.request.effect_id));retain(rows);show(rows);
        }catch(error){output.textContent=error.message;}finally{load.disabled=false;}});
        form.append(run,load);section.append(form,output);return section;
      }

      function renderVmHostLinks(workspace) {
        const section = document.createElement('section'); section.className = 'vm-workspace-card';
        section.append(textElement('h4', '', 'Host event positions'));
        section.append(textElement('p', '', 'A linked dispatch position does not establish exact request-value provenance.'));
        const report = state.vmHostLinks;
        const bound = report?.workspace_document_digest === state.vmOpcodeWorkspace?.document_digest;
        const row = bound && report.workspaces.find(item => item.interpreter_artifact_id === workspace.interpreter_artifact_id &&
          item.source_artifact_sha256 === workspace.source_artifact_sha256);
        if (state.vmHostLinksStatus === 'unavailable') {
          section.append(textElement('p', 'vm-workspace-empty', 'Host links unavailable. Any matching last valid links are retained.'));
        }
        const view = vmHostLinksView(row || null);
        const banner = document.createElement('p');
        banner.className = view.staticOnly ? 'vm-workspace-notice' : 'vm-workspace-empty';
        if (view.staticOnly) {
          banner.dataset.kind = 'static-only';
          banner.setAttribute('role', 'status');
        }
        banner.textContent = view.headline;
        section.append(banner);
        if (row) {
          for (const omission of view.omissionLines) {
            const item = document.createElement('p');
            item.className = 'vm-workspace-empty';
            item.append(textElement('strong', '', omission.reason), document.createTextNode(`: ${omission.detail}`));
            section.append(item);
          }
          appendVmPagedRows(section, row.links, 'host links', link => {
            const item = textElement('details', 'vm-effect-row', '');
            item.append(textElement('summary', '', vmHostLinkLine(link)), textElement('pre', 'vm-effect-detail vm-evidence-audit', JSON.stringify(link, null, 2)));
            return item;
          });
        }
        return section;
      }

      function renderVmSessionSources(workspace) {
        const section = document.createElement('section'); section.className = 'vm-workspace-card';
        section.setAttribute('aria-label', 'Session sources');
        section.append(textElement('h4', '', 'Session sources'));
        section.append(textElement('p', '', 'Stored artifacts from this native evidence session. Shared session or target is correlation, not loader provenance and not a guest position.'));
        const finding = (state.vmFindings ?? []).find(item => item.findingId === state.selectedVmFindingId);
        const interpreter = vmSourceArtifactForFinding(state.artifacts ?? [], finding, state.vmAnalysisSelection);
        const sessionId = interpreter?.session_id;
        const join = vmSessionSourceJoin({
          artifacts: state.artifacts,
          interpreterArtifactId: workspace.interpreter_artifact_id,
          sessionId
        });
        if (!join.scoped) {
          section.append(textElement('p', 'vm-workspace-empty', 'Interpreter artifact is not in the retained catalog, so same-session JavaScript cannot be listed. /api/artifacts is unchanged.'));
          return section;
        }
        if (join.gapText) {
          const gap = document.createElement('p');
          gap.className = 'vm-workspace-notice';
          gap.dataset.kind = 'static-only';
          gap.setAttribute('role', 'status');
          gap.textContent = join.gapText;
          section.append(gap);
        }
        section.append(textElement('h4', '', 'Stored artifacts'));
        if (join.stored.length === 0) {
          section.append(textElement('p', 'vm-workspace-empty', 'No stored artifact in this session matched the interpreter record.'));
        } else {
          appendVmPagedRows(section, join.stored, 'stored sources', entry => {
            const item = document.createElement('div'); item.className = 'vm-effect-row';
            item.append(textElement('p', 'vm-effect-detail', `${entry.role} · artifact ${entry.artifact_id} · ${entry.kind} · ${entry.capture_origin} · ${entry.url || '(no URL)'}`));
            item.append(textElement('p', 'vm-effect-detail', entry.relation));
            const open = textElement('button', 'secondary-button', 'Open stored artifact'); open.type = 'button';
            open.addEventListener('click', () => { showScreen('sources', open); selectArtifact(entry.artifact_id); });
            item.append(open);
            return item;
          });
        }
        return section;
      }

      function renderNativeWasmObservations(workspace) {
        const panel = document.createElement('section'); panel.className = 'vm-workspace-card';
        panel.append(textElement('h4', '', 'Native Wasm dispatch observations'),
          textElement('p', 'vm-workspace-notice', 'Physical module offsets and selectors are not guest-interpreter PCs or recovered guest opcodes. No host causality is inferred from physical-only rows.'));
        const nativeRow = (row, position) => {
          const item = document.createElement('details'); item.className = 'vm-effect-row';
          const summary = document.createElement('summary');
          summary.append(textElement('span', 'vm-native-row-identity', vmNativeRowIdentityText(row, state.events)), document.createElement('br'),
            textElement('span', 'vm-native-row-position', position));
          item.append(summary, textElement('pre', 'vm-effect-detail vm-evidence-audit', JSON.stringify(row, null, 2)));
          return item;
        };
        const rows = Array.isArray(workspace.native_wasm_observations) ? workspace.native_wasm_observations : [];
        appendVmPagedRows(panel, rows, 'native Wasm observations', row => nativeRow(row, vmNativeWasmPositionText(row)));
        if (!rows.length) panel.append(textElement('p', 'vm-selection-empty', 'No native Wasm dispatch observations retained.'));
        const physicalCount = vmNativeAcceptedCount(workspace.native_wasm_observation_count, rows.length);
        if (physicalCount > rows.length) panel.append(textElement('p', 'vm-workspace-notice',
          `${physicalCount - rows.length} accepted observations are outside the retained window.`));
        const guestRows = Array.isArray(workspace.native_guest_samples) ? workspace.native_guest_samples : [];
        panel.append(textElement('h4', '', 'Native guest state (adapter interpreted)'),
          textElement('p', 'vm-workspace-notice', 'Actual typed local values and memory bytes are retained. Explicit adapters interpret those values; verified-dataflow labels require a reviewed exact module binding. Guest positions on host links require verified guest semantics plus an exact synchronous retained parent.'));
        appendVmPagedRows(panel, guestRows, 'native guest samples', row => nativeRow(row, vmNativeGuestPositionText(row)));
        if (!guestRows.length) panel.append(textElement('p','vm-selection-empty','No native guest samples retained.'));
        const guestCount = vmNativeAcceptedCount(workspace.native_guest_sample_count, guestRows.length);
        if (guestCount > guestRows.length) panel.append(textElement('p', 'vm-workspace-notice',
          `${guestCount - guestRows.length} accepted guest samples are outside the retained window.`));
        return panel;
      }

      const vmObservedStreamLabels = {'native-guest': 'Native guest', 'native-wasm': 'Native br_table', 'dispatch-sample': 'Native dispatch sample'};
      const vmObservedOmission = reason => /^(?:observed-claim|nested-guest)/.test(reason);
      function vmHasRuntimeClaims(workspace) {
        return workspace.observed_claims !== undefined || workspace.nested_guests !== undefined ||
          workspace.coverage.omissions.some(row => vmObservedOmission(row.reason));
      }
      function vmObservedSiteText(claim) {
        if (claim.site === null) return 'site not recorded, artifact scope';
        if (claim.site.line !== null) return `line ${claim.site.line}:${claim.site.column}, sole interpreter candidate`;
        return `f${claim.site.function_index} · byte ${claim.site.byte_offset}`;
      }
      function vmObservedHandlerText(claim) {
        if (claim.handler.kind === 'handler-index') return `handler ${claim.handler.handler_index}`;
        return claim.handler.is_default ? `default arm ${claim.handler.arm}` : `arm ${claim.handler.arm}`;
      }
      function vmObservedStaticText(claim) {
        const comparison = claim.static_claim;
        const javascript = claim.stream === 'dispatch-sample';
        if (comparison.state === 'agrees') return javascript
          ? `Static claim agrees: recovery names handler ${comparison.handler_index ?? comparison.opcode} for opcode ${comparison.opcode}.`
          : `Static claim agrees: this arm is labeled selector ${comparison.opcode}.`;
        if (comparison.state === 'disagrees') return javascript
          ? `Static claim disagrees: recovery names handler ${comparison.handler_index ?? comparison.opcode} for opcode ${comparison.opcode}. Both are kept.`
          : `Static claim disagrees: this arm is labeled opcode ${comparison.opcode}, but guest opcode ${claim.opcode} ran here. Both are kept.`;
        if (comparison.state === 'withheld') return `Static claim withheld: recovery found opcode ${comparison.opcode}, but no interpreter-candidate site ties it to a table or switch.`;
        return 'No static claim: only runtime evidence names this handler.';
      }
      function vmObservedEventsText(events, total) {
        const listed = events.map(event => `process ${event.process_id} seq ${event.sequence_number}`).join(', ');
        return `Events ${listed}${total > events.length ? `, and ${total - events.length} more retained rows` : ''}`;
      }
      function vmGuestBufferText(side) {
        return `memory ${side.memory_index} at ${side.memory_base}, ${side.memory_length} bytes, snapshot ${side.bytecode_artifact_id}`;
      }

      function renderVmRuntimeClaims(workspace) {
        const panel = document.createElement('section'); panel.className = 'vm-workspace-card';
        panel.append(textElement('h4', '', 'Observed dispatch claims'),
          textElement('p', 'vm-workspace-notice', 'Runtime claims from retained native rows at interpreter-candidate sites. They sit beside the static handler list and never replace it. Each claim names its supporting events and how it compares with the static claim.'));
        const claims = workspace.observed_claims ?? [];
        appendVmPagedRows(panel, claims, 'observed claims', claim => {
          const row = document.createElement('details'); row.className = 'vm-effect-row';
          row.dataset.staticClaim = claim.static_claim.state;
          const summary = document.createElement('summary');
          const opcode = claim.opcode === null ? 'guest opcode not observed' : `opcode ${claim.opcode}`;
          const selector = claim.selector === null ? '' : `selector ${claim.selector} to `;
          summary.append(textElement('span', 'vm-native-row-identity', `${vmObservedStreamLabels[claim.stream]} · ${vmObservedSiteText(claim)}`), document.createElement('br'),
            textElement('span', 'vm-native-row-position', `${opcode} · ${selector}${vmObservedHandlerText(claim)} · ${vmCountText(claim.sample_count, 'sample')}`));
          row.append(summary, textElement('p', 'vm-effect-detail vm-observed-static', vmObservedStaticText(claim)),
            textElement('p', 'vm-effect-detail', vmObservedEventsText(claim.events, claim.sample_count)),
            textElement('pre', 'vm-effect-detail vm-evidence-audit', JSON.stringify(claim, null, 2)));
          return row;
        });
        if (!claims.length) panel.append(textElement('p', 'vm-selection-empty', 'No observed claims. Retained native rows at an interpreter-candidate site would appear here.'));
        for (const omission of workspace.coverage.omissions.filter(row => vmObservedOmission(row.reason))) {
          panel.append(textElement('p', 'vm-workspace-notice', `${omission.reason}: ${omission.detail}`));
        }
        if (workspace.runtime !== 'webassembly') return panel;
        panel.append(textElement('h4', '', 'Nested guests'),
          textElement('p', 'vm-workspace-notice', 'An inner interpreter is a guest activation that names a parent invocation, runs at another interpreter-candidate site and reads another guest buffer. Its outer handler is the parent dispatch retained last before it began.'));
        const nested = workspace.nested_guests ?? [];
        appendVmPagedRows(panel, nested, 'nested guests', guest => {
          const {outer, inner} = guest;
          const row = document.createElement('details'); row.className = 'vm-effect-row';
          const summary = document.createElement('summary');
          const arm = outer.is_default ? `default arm ${outer.selected_arm}` : `arm ${outer.selected_arm}`;
          summary.append(textElement('span', 'vm-native-row-identity', `Inner f${inner.function_index} · byte ${inner.module_byte_offset} · invocation ${inner.invocation_id}`), document.createElement('br'),
            textElement('span', 'vm-native-row-position', `Driven by outer f${outer.function_index} · byte ${outer.module_byte_offset} · opcode ${outer.opcode}, selector ${outer.selector} to ${arm}`));
          const opcodes = inner.observed_opcodes.map(entry => `${entry.opcode} (${vmCountText(entry.sample_count, 'sample')})`).join(', ');
          const omitted = inner.omitted_opcode_count ? `, and ${inner.omitted_opcode_count} more opcodes` : '';
          const basis = outer.basis === 'contiguous-sequence'
            ? 'Every renderer event between the outer dispatch and the inner invocation is retained, so no other outer dispatch ran in between.'
            : 'Events between the outer dispatch and the inner invocation are missing or include a gap, so this is the nearest retained outer dispatch, not proof of the exact one.';
          row.append(summary,
            textElement('p', 'vm-effect-detail', `Inner guest opcodes: ${opcodes || 'none'}${omitted} · ${vmCountText(inner.sample_count, 'retained sample')}`),
            textElement('p', 'vm-effect-detail', `Inner buffer ${vmGuestBufferText(inner)}. Outer buffer ${vmGuestBufferText(outer)}.`),
            textElement('p', 'vm-effect-detail', `Outer dispatch process ${outer.dispatch_event.process_id} seq ${outer.dispatch_event.sequence_number}, invocation ${outer.invocation_id}. ${basis}`),
            textElement('p', 'vm-effect-detail', vmObservedEventsText(inner.events, inner.sample_count)),
            textElement('pre', 'vm-effect-detail vm-evidence-audit', JSON.stringify(guest, null, 2)));
          return row;
        });
        if (!nested.length) panel.append(textElement('p', 'vm-selection-empty', 'No nested guest retained. Live capture does not assert parent invocations yet.'));
        return panel;
      }

      function renderVmOpcodeWorkspace(selected) {
        const workspace = vmOpcodeWorkspaceForFinding(state.vmOpcodeWorkspace, selected);
        const container = document.createElement('section'); container.className = 'vm-workspace';
        container.setAttribute('aria-label', 'Opcode workspace');
        const notice = vmWorkspaceNotice(workspace);
        if (notice) container.append(notice);
        const staticSampleText = vmStaticSampleNoticeText(workspace);
        if (staticSampleText) {
          const staticNotice = document.createElement('div');
          staticNotice.className = 'vm-workspace-notice';
          staticNotice.dataset.kind = 'static-only';
          staticNotice.setAttribute('role', 'status');
          staticNotice.textContent = staticSampleText;
          container.append(staticNotice);
        }
        if (!workspace) return container;
        const head = document.createElement('div'); head.className = 'vm-workspace-title';
        head.append(
          textElement('div', '', 'Opcode workspace'),
          textElement('span', '', `${workspace.runtime === 'webassembly' ? 'WebAssembly · ' : ''}${vmModelLabel(workspace)} · interpreter artifact ${workspace.interpreter_artifact_id}`)
        );
        const evidence = textElement('p', 'vm-workspace-notice', vmEvidenceClassText(workspace));
        evidence.dataset.kind = workspace.evidence_class || 'unclassified';
        const machine = workspace.machine_state;
        const machineText = !machine ? '' : [
          machine.stack_observed === true ? 'stack observed in effects' : '',
          machine.register_count === null ? '' : `${machine.register_count} registers named by effects`
        ].filter(Boolean).join(' · ');
        const body = document.createElement('div'); body.className = 'vm-workbench-body';
        body.id = 'vm-analysis-handlers';
        const selectedInspector = document.createElement('aside'); selectedInspector.className = 'vm-selection-inspector';
        selectedInspector.setAttribute('aria-label', 'Selected handler');
        const updateSelection = key => {
          const row = vmOpcodeRows(workspace).find(item => item.key === key);
          const heading = textElement('div', 'vm-pane-label', 'Selected handler');
          if (!row) { selectedInspector.replaceChildren(heading, textElement('p', 'vm-selection-empty', 'Select a retained handler to inspect its evidence.')); return; }
          const title = textElement('h3', '', row.label);
          const identity = document.createElement('div'); identity.className = 'vm-selection-fields';
          for (const [label, value] of [['Opcode', row.opcode], ['Source byte range', row.source], ['Evidence', row.state], ['Samples', String(row.samples)], ['Operand width', row.operandWidth ? `${row.operandWidth} bytes (characterized)` : 'unknown']]) {
            identity.append(textElement('span', '', label), textElement('strong', '', value));
          }
          const observations = document.createElement('div'); observations.className = 'vm-selection-observations';
          observations.append(textElement('h4', '', 'Retained positions'));
          appendVmPagedRows(observations, row.retainedSamples, 'retained samples', sample => {
            const item = document.createElement('details'); item.className = 'vm-effect-row';
            const position = vmNativeIsGuestRow(sample) ? vmNativeGuestPositionText(sample) : sample.module_byte_offset !== undefined ? vmNativeWasmPositionText(sample) : `${sample.provenance ? 'Caller-reported ' : ''}PC ${sample.instruction_pointer} (${sample.instruction_pointer_units}) · handler ${sample.handler_index} · bytecode ${sample.bytecode_artifact_id}`;
            item.append(textElement('summary', '', sample.module_byte_offset !== undefined ? `${vmNativeRowIdentityText(sample, state.events)} · ${position}` : position), textElement('pre', 'vm-effect-detail vm-evidence-audit', JSON.stringify(sample, null, 2)));
            return item;
          });
          if (!row.retainedSamples.length) observations.append(textElement('p', 'vm-selection-empty', 'No retained PC or guest-byte position.'));
          if (row.samples > row.retainedSamples.length) observations.append(textElement('p', 'vm-workspace-notice', `${row.samples - row.retainedSamples.length} accepted samples are not retained. Missing positions remain unknown.`));
          const notes = document.createElement('div'); notes.className = 'vm-selection-notes';
          notes.append(textElement('h4', '', 'Evidence notes'), textElement('p', '', row.notes));
          selectedInspector.replaceChildren(heading, title, identity, observations, notes);
        };
        const handlers = renderVmHandlers(workspace, updateSelection); handlers.classList.add('vm-workbench-listing');
        updateSelection(state.selectedVmHandlerKey);
        const inspector = document.createElement('section'); inspector.className = 'vm-workbench-inspector';
        inspector.setAttribute('aria-label', 'Finding analysis tools');
        const navigation = document.createElement('nav'); navigation.className = 'vm-workbench-tabs';
        navigation.setAttribute('aria-label', 'Finding analysis panels');
        const panels = document.createElement('div'); panels.className = 'vm-workbench-panels';
        const definitions = [
          ['effects', 'Effects', renderVmEffects],
          ...(workspace.runtime === 'webassembly' ? [['dispatch', 'Dispatch sites', renderVmDispatchSites], ['tables', 'Handler tables', renderVmHandlerTables], ['native-wasm', 'Native observations', renderNativeWasmObservations]]
            : workspace.dispatch_classification ? [['dispatch', 'Dispatch sites', renderVmDispatchStructure]] : []),
          ...(vmHasRuntimeClaims(workspace) ? [['runtime', 'Runtime claims', renderVmRuntimeClaims]] : []),
          ['bytecode', 'Bytes', renderVmBytecode],
          ['reachability', 'Reachability', renderVmReachability],
          ['coverage', 'Coverage', renderVmWorkspaceCoverage],
          ['unknowns', 'Unknowns', renderVmWorkspaceUnknowns],
          ['experiment', 'Experiment', renderVmOwnedExperiment],
          ['host-links', 'Host links', renderVmHostLinks],
          ['sources', 'Sources', renderVmSessionSources]
        ];
        const active = definitions.some(([key]) => key === state.vmWorkspacePanel) ? state.vmWorkspacePanel : 'effects';
        const entries = definitions.map(([key, label, renderPanel]) => {
          const button = textElement('button', 'secondary-button', label); button.type = 'button';
          button.dataset.vmPanel = key;
          button.setAttribute('aria-pressed', String(key === active));
          const panel = renderPanel(workspace); panel.hidden = key !== active;
          panel.dataset.vmPanelContent = key;
          button.addEventListener('click', () => {
            state.vmWorkspacePanel = key;
            entries.forEach(entry => { entry.panel.hidden = entry.key !== key; entry.button.setAttribute('aria-pressed', String(entry.key === key)); });
          });
          navigation.append(button); panels.append(panel);
          return {key, button, panel};
        });
        inspector.append(navigation, panels);
        body.append(handlers, selectedInspector);
        container.append(head, evidence);
        if (machineText) container.append(textElement('p', 'vm-effect-detail', machineText));
        container.append(body, inspector);
        return container;
      }

      function vmWorkspaceCommand(action, invoke = false) {
        const active = document.querySelector('.vm-workspace-switch [aria-pressed="true"]');
        const root = document.getElementById(active?.getAttribute('aria-controls') || 'vm-findings-workspace');
        if (!root) return false;
        if (root.id === 'vm-findings-workspace') {
          const label = action === 'search' ? 'Filter retained handlers' : action === 'next' ? 'Next handler' : 'Previous handler';
          const target = root.querySelector(`[aria-label="${label}"]`);
          if (!target || target.disabled) return false;
          if (invoke) {
            setVmAnalysisExpanded(true);
            if (action === 'search') target.focus(); else target.click();
          }
          return true;
        }
        const capabilities = {search: false, previous: false, next: false};
        root.dispatchEvent(new CustomEvent('vm-workspace-query', {detail: capabilities}));
        if (!capabilities[action]) return false;
        if (invoke) root.dispatchEvent(new CustomEvent(`vm-workspace-${action}`));
        return true;
      }

      function setVmAnalysisExpanded(expanded) {
        document.querySelector('#vm-analysis-toggle').setAttribute('aria-expanded', String(expanded));
        document.querySelector('#vm-findings-workspace > .vm-grid').scrollTop = 0;
        // Reopen the compact navigator on complete rows. A prior selection can
        // leave its nested scroller partway through the first finding.
        if (expanded) document.querySelector('#vm-list').scrollTop = 0;
      }

      function revealVmHandler(handler) {
        setVmAnalysisExpanded(true);
        handler.scrollIntoView({block: 'nearest'});
        if (window.matchMedia('(max-width: 900px), (max-height: 650px)').matches) {
          const grid = document.querySelector('#vm-findings-workspace > .vm-grid');
          const detail = document.querySelector('#vm-detail');
          // Native navigation can reveal the row while leaving a thin tree
          // fragment above the evidence. Start at the complete detail pane.
          grid.scrollTop += Math.max(0, detail.getBoundingClientRect().top - grid.getBoundingClientRect().top);
        }
      }

      function updateVmNavigationMenus() {
        const menuBar = document.querySelector('.vm-menu-bar');
        if (!menuBar) return;
        menuBar.querySelectorAll('[data-vm-command^="vm-handler-"]').forEach(button => {
          const action = button.dataset.vmCommand === 'vm-handler-filter' ? 'search' : button.dataset.vmCommand === 'vm-handler-next' ? 'next' : 'previous';
          button.disabled = !vmWorkspaceCommand(action);
        });
      }

      function renderVmOpcodeWorkspaceInPlace(selected) {
        const host = [...elements.vmDetail.querySelectorAll('.vm-workspace-host')][0]
          ?? (() => {
            const node = document.createElement('div');
            node.className = 'vm-workspace-host';
            elements.vmDetail.append(node);
            return node;
          })();
        host.replaceChildren(...(selected ? [renderVmOpcodeWorkspace(selected)] : []));
        updateVmNavigationMenus();
        const symbols = document.querySelector('#vm-symbol-list');
        if (symbols) {
          const workspace = selected && vmOpcodeWorkspaceForFinding(state.vmOpcodeWorkspace, selected);
          const rows = workspace ? vmOpcodeRows(workspace) : [];
          symbols.replaceChildren();
          for (const row of rows) {
            const button = textElement('button', 'vm-symbol-row', row.label); button.type = 'button';
            button.dataset.vmSymbolKey = row.key;
            button.setAttribute('aria-pressed', String(row.key === state.selectedVmHandlerKey));
            button.title = `Opcode ${row.opcode} · source ${row.source}`;
            button.addEventListener('click', () => {
              const target = [...host.querySelectorAll('.vm-handler-row')].find(item => item.dataset.handlerKey === row.key);
              if (!target) return;
              const filter = host.querySelector('input[aria-label="Filter retained handlers"]');
              if (filter && target.hidden) { filter.value = ''; filter.dispatchEvent(new Event('input')); }
              target.click(); revealVmHandler(target);
            });
            symbols.append(button);
          }
          if (!rows.length) symbols.append(textElement('p', '', 'No retained handler symbols for this finding.'));
        }
      }

      function renderVmDetail() {
        const selected = state.vmFindings.find(finding => finding.findingId === state.selectedVmFindingId);
        if (!selected) {
          document.querySelector('#vm-symbol-list')?.replaceChildren(textElement('p', '', 'Select a finding to browse its retained handlers.'));
          elements.vmDetail.replaceChildren(textElement('div', 'vm-empty', 'No valid VM findings have been captured. Capture stays separate from interpretation, so the lab does not synthesize sample conclusions.'));
          return;
        }
        if (selected.analysis) {
          const result = selected.analysis;
          const summary = document.createElement('div'); summary.className = 'vm-summary';
          [
            ['VM score', result.vm_score],
            ['anti-bot relevance', result.anti_bot_score],
            ['signal families', result.evidence_families?.length ?? 0],
            ['coverage', result.status ?? 'complete']
          ].forEach(([label, value]) => {
            const metric = document.createElement('div'); metric.className = 'vm-metric';
            metric.append(textElement('span', '', label), textElement('strong', '', value));
            summary.append(metric);
          });
          const card = document.createElement('article'); card.className = 'vm-detail-card';
          const head = document.createElement('header'); head.className = 'vm-detail-head';
          const title = document.createElement('div');
          title.append(textElement('h2', '', 'VM patterns in source'), textElement('p', '', `${selected.hostRuntime} · code analysis · artifact ${selected.sourceArtifactId}`));
          const actions = document.createElement('div'); actions.className = 'vm-detail-actions';
          actions.append(textElement('span', 'vm-confidence', selected.confidence));
          const sourceArtifact = vmSourceArtifactForFinding(state.artifacts, selected, state.vmAnalysisSelection);
          if (sourceArtifact) {
            const openSource = textElement('button', 'secondary-button', 'Open in Sources'); openSource.type = 'button';
            const identity = state.vmAnalysisSelection ? {type: 'captured-artifact', session: sourceArtifact.session_id,
              artifact: sourceArtifact.artifact_id, sha256: sourceArtifact.sha256, bytes: sourceArtifact.byte_size} : null;
            openSource.addEventListener('click', () => {
              showScreen('sources', openSource);
              selectArtifact(sourceArtifact.artifact_id, null, {identity});
            });
            actions.append(openSource);
          }
          head.append(title, actions);
          const fields = document.createElement('div'); fields.className = 'vm-fields';
          fields.append(
            vmField('tier', selected.confidence),
            vmField('source artifact', selected.sourceArtifactId),
            vmField('correlated requests (session context only)', result.related_request_ids?.join(', ') || 'none observed'),
            vmField('exact response-body links', result.exact_request_links?.map(link =>
              `${link.request_id} · session ${link.root_event.session_id} · process ${link.root_event.process_id} · root ${link.root_event.sequence_number} → response ${link.response_event.sequence_number} → capture ${link.capture_event.sequence_number}`).join('; ') || 'unlinked'),
            vmField('evidence families', result.evidence_families?.join(', ') || 'none'),
            vmField('bytecode snapshot', result.bytecode_snapshot?.snapshot_hex || result.bytecode_snapshot?.unavailable_reason || 'not applicable'),
            vmField('edge semantics', 'observed · inferred · correlated · unknown')
          );
          const evidence = document.createElement('div'); evidence.className = 'vm-analysis-evidence';
          const observations = [...(result.observations ?? []), ...(result.anti_bot_observations ?? [])];
          if (observations.length === 0) {
            evidence.append(textElement('div', 'vm-analysis-rule', 'Mixed finding uses the evidence from both linked artifacts.'));
          } else {
            observations.forEach(observation => {
              const row = document.createElement('div'); row.className = 'vm-analysis-rule';
              row.append(
                textElement('strong', '', observation.rule_id),
                textElement('span', '', observation.detail),
                textElement('b', '', `+${observation.weight}`)
              );
              evidence.append(row);
            });
          }
          (result.coverage?.residual_unknowns ?? []).forEach(unknown => {
            const row = document.createElement('div'); row.className = 'vm-analysis-rule';
            row.append(textElement('strong', '', 'unknown'), textElement('span', '', unknown), textElement('b', '', '?'));
            evidence.append(row);
          });
          const provenance = document.createElement('details'); provenance.className = 'vm-finding-provenance';
          provenance.append(textElement('summary', '', 'Detection evidence & provenance'), fields, evidence);
          card.append(head);
          elements.vmDetail.replaceChildren(card, summary);
          renderVmOpcodeWorkspaceInPlace(selected);
          elements.vmDetail.append(provenance);
          return;
        }
        const investigation = state.vmFindings.filter(finding => finding.investigationId === selected.investigationId);
        const coverage = investigation.find(finding => finding.kind === 'coverage');
        const coveragePercent = coverage ? Math.round(coverage.observedCount * 100 / coverage.totalCount) : null;
        const summary = document.createElement('div'); summary.className = 'vm-summary';
        [
          ['investigation findings', investigation.length],
          ['interpreters', investigation.filter(finding => finding.kind === 'interpreter').length],
          ['guest programs', investigation.filter(finding => finding.kind === 'guest program').length],
          ['coverage', coveragePercent === null ? 'unknown' : `${coveragePercent}%`]
        ].forEach(([label, value]) => {
          const metric = document.createElement('div'); metric.className = 'vm-metric';
          metric.append(textElement('span', '', label), textElement('strong', '', value));
          summary.append(metric);
        });

        const card = document.createElement('article'); card.className = 'vm-detail-card';
        const head = document.createElement('header'); head.className = 'vm-detail-head';
        const title = document.createElement('div');
        title.append(textElement('h2', '', selected.label), textElement('p', '', `finding ${selected.findingId} · investigation ${selected.investigationId}`));
        const actions = document.createElement('div'); actions.className = 'vm-detail-actions';
        actions.append(textElement('span', 'vm-confidence', selected.confidence));
        const fields = document.createElement('div'); fields.className = 'vm-fields';
        fields.append(
          vmField('evidence kind', selected.kind),
          vmField('host runtime', selected.hostRuntime),
          vmField('subject', selected.subjectId === '0' ? 'not assigned' : selected.subjectId),
          vmField('related subject', selected.relatedSubjectId === '0' ? 'none' : selected.relatedSubjectId),
          vmField('flags', selected.flags.join(', ') || 'none'),
          vmField('event link', `sequence ${selected.sequenceNumber} · parent ${selected.parentEventId}`),
          vmField('source artifact', selected.sourceArtifactId === '0' ? 'not captured' : selected.sourceArtifactId),
          vmField('source range', selected.flags.includes('source range') ? `${selected.sourceOffset} + ${selected.sourceSize} bytes` : 'not captured')
        );
        const sourceArtifact = vmSourceArtifactForFinding(state.artifacts, selected, state.vmAnalysisSelection);
        if (sourceArtifact) {
          const openSource = textElement('button', 'secondary-button', 'Open in Sources');
          openSource.type = 'button';
          openSource.addEventListener('click', () => {
            showScreen('sources', openSource);
            selectArtifact(sourceArtifact.artifact_id);
          });
          actions.append(openSource);
        }
        head.append(title, actions);
        const provenance = document.createElement('details'); provenance.className = 'vm-finding-provenance';
        provenance.append(textElement('summary', '', 'Finding metadata & provenance'), fields);
        card.append(head);
        if (coverage) {
          const coveragePanel = document.createElement('div'); coveragePanel.className = 'vm-coverage';
          const line = document.createElement('div'); line.className = 'vm-coverage-line';
          line.append(textElement('span', '', coverage.label), textElement('strong', '', `${coverage.observedCount} / ${coverage.totalCount}`));
          const bar = document.createElement('div'); bar.className = 'vm-coverage-bar';
          const fill = document.createElement('span'); fill.style.width = `${coveragePercent}%`; bar.append(fill);
          coveragePanel.append(line, bar); provenance.append(coveragePanel);
        }
        elements.vmDetail.replaceChildren(card, summary);
        renderVmOpcodeWorkspaceInPlace(selected);
        elements.vmDetail.append(provenance);
      }

      let renderedVmFindings = null;
      let renderedVmWorkspace = null;
      function vmSessionSourceRefreshKey() { const finding=(state.vmFindings??[]).find(item=>item.findingId===state.selectedVmFindingId); const artifact=vmSourceArtifactForFinding(state.artifacts??[],finding,state.vmAnalysisSelection); const sessionId=artifact?.session_id??''; return [sessionId,(state.artifacts??[]).filter(item=>String(item.session_id)===String(sessionId)).map(item=>item.artifact_id).join(',')]; }
      function renderVmLab() {
        const focusedFindingId = document.activeElement?.classList.contains('vm-row')
          ? document.activeElement.dataset.findingId
          : null;
        const focusedHandlerKey = document.activeElement?.classList.contains('vm-handler-row')
          ? document.activeElement.dataset.handlerKey
          : null;
        elements.vmCount.textContent = String(state.vmFindings.length);
        if (!state.vmFindings.some(finding => finding.findingId === state.selectedVmFindingId)) {
          state.selectedVmFindingId = state.vmFindings[0]?.findingId ?? null;
        }
        renderVmSessionStatus();
        const gapCount = shownSequenceGaps();
        if (state.broker === 'connecting') {
          setVmNotice('loading', 'Waiting for VM findings from the local evidence broker.');
        } else if (state.vmAnalysisStatus === 'loading' && state.vmAnalysisSelection) {
          setVmNotice('loading', 'Loading candidates for this exact captured response body. Session-wide findings are excluded.');
        } else if (state.vmAnalysisStatus === 'malformed') {
          setVmNotice('malformed', `Malformed or mismatched VM analysis was rejected. ${state.vmAnalysisSelection ? 'Only the last valid evidence for this exact request may remain visible.' : 'Valid timeline summaries remain visible.'}`);
        } else if (state.vmAnalysisStatus === 'unavailable') {
          setVmNotice('disconnected', `The cold analyzer is unavailable. ${state.vmAnalysisError ? `${state.vmAnalysisError} ` : ''}${state.vmFindings.length ? 'Last valid VM evidence remains visible.' : 'No VM evidence is available.'}`);
        } else if (state.broker === 'unavailable') {
          setVmNotice('disconnected', state.vmFindings.length ? 'Broker disconnected. Last valid VM findings remain visible.' : 'Broker disconnected. No VM findings are available.');
        } else if (state.malformedVmFindings > 0) {
          setVmNotice('malformed', `${state.malformedVmFindings} malformed VM ${state.malformedVmFindings === 1 ? 'finding was' : 'findings were'} rejected.`);
        } else if (state.vmFindings.length === 0) {
          setVmNotice('empty', state.vmAnalysisSelection ? 'No VM candidates are linked to this exact captured response body. Unlinked, legacy and session-wide findings are not shown.' : 'No VM findings yet. The lab waits for observed or explicitly inferred evidence.');
        } else if (gapCount > 0n) {
          setVmNotice('gap', `${gapCount} event ${gapCount === 1n ? 'gap may' : 'gaps may'} make VM coverage incomplete (observed sequence jumps in ${eventCountScopeLabel()}).`);
        } else if (state.vmAnalysisSelection) {
          const selection = state.vmAnalysisSelection;
          setVmNotice('ready', `Exact captured response body · request ${selection.request_id} · session ${selection.root_event.session_id} · process ${selection.root_event.process_id} · root ${selection.root_event.sequence_number}. This link does not establish execution or guest semantics.`);
        } else {
          elements.vmNotice.hidden = true;
        }
        // Poll errors and identical snapshots change the notice, not the owned
        // finding DOM. Keep focus and scroll even when a poll settles in another
        // VM mode. Source availability is part of the selected detail's input.
        const selectedFinding = state.vmFindings.find(finding => finding.findingId === state.selectedVmFindingId);
        const renderKey = JSON.stringify([state.vmFindings, state.selectedVmFindingId,
          Boolean(vmSourceArtifactForFinding(state.artifacts, selectedFinding, state.vmAnalysisSelection))]);
        const workspaceKey = JSON.stringify([
          state.vmOpcodeWorkspaceStatus, state.vmOpcodeWorkspace?.document_digest ?? null,
          state.vmHostLinksStatus, state.vmHostLinks?.document_digest ?? null,
          vmSessionSourceRefreshKey()
        ]);
        if (renderKey === renderedVmFindings && workspaceKey === renderedVmWorkspace) return;
        if (renderKey !== renderedVmFindings) {
        const selectedExists = state.vmFindings.some(finding => finding.findingId === state.selectedVmFindingId);
        elements.vmList.replaceChildren(...state.vmFindings.map((finding, index) => {
          const row = document.createElement('button'); row.className = 'vm-row'; row.type = 'button';
          row.dataset.findingId = finding.findingId;
          row.setAttribute('role', 'option');
          row.setAttribute('aria-selected', String(finding.findingId === state.selectedVmFindingId));
          row.tabIndex = finding.findingId === state.selectedVmFindingId || !selectedExists && index === 0 ? 0 : -1;
          row.append(
            textElement('span', 'vm-row-title', finding.analysis ? 'VM patterns in source' : finding.label),
            textElement('span', 'vm-kind', finding.analysis ? 'Code analysis' : finding.kind),
            textElement('span', 'vm-row-meta', finding.analysis ? `Code analysis · artifact ${finding.sourceArtifactId}` : `t ${finding.monotonicTimeNs} ns · source p${finding.processId}:t${finding.threadId} · category vm`),
            textElement('span', 'vm-row-correlation', `operation ${finding.kind} · finding ${finding.findingId} · investigation ${finding.investigationId} · ${finding.hostRuntime} · ${finding.confidence}`)
          );
          row.addEventListener('click', () => {
            state.selectedVmFindingId = finding.findingId;
            renderVmLab();
            [...elements.vmList.querySelectorAll('.vm-row')]
              .find(candidate => candidate.dataset.findingId === finding.findingId)?.focus();
          });
          row.addEventListener('keydown', event => {
            if (!['ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) return;
            event.preventDefault();
            const rows = [...elements.vmList.querySelectorAll('.vm-row')];
            const current = rows.indexOf(row);
            const next = event.key === 'Home' ? 0 : event.key === 'End' ? rows.length - 1
              : (current + (event.key === 'ArrowDown' ? 1 : -1) + rows.length) % rows.length;
            rows[next].click();
          });
          return row;
        }));
        if (focusedFindingId) {
          [...elements.vmList.querySelectorAll('.vm-row')]
            .find(row => row.dataset.findingId === focusedFindingId)?.focus({ preventScroll: true });
        }
        renderVmDetail();
        } else {
          renderVmOpcodeWorkspaceInPlace(state.vmFindings.find(finding => finding.findingId === state.selectedVmFindingId));
        }
        if (focusedHandlerKey) {
          [...elements.vmDetail.querySelectorAll('.vm-handler-row')]
            .find(row => row.dataset.handlerKey === focusedHandlerKey)?.focus({ preventScroll: true });
        }
        renderedVmFindings = renderKey;
        renderedVmWorkspace = workspaceKey;
      }

      function requestDomain(request) {
        if (!request) return 'unknown';
        if (request.origin === 'sample') return 'checkout.acme.test';
        const target = String(request.path ?? '').trim();
        if (!target || target === 'Unidentified network event') return 'unknown';
        try {
          return new URL(target).host || 'unknown';
        } catch {
          return target.replace(/^\/\//, '').split('/')[0] || 'unknown';
        }
      }

      function requestTabGroups() {
        const groups = new Map();
        state.requests.forEach(request => {
          const id = request.tabId && request.tabId !== '0' ? request.tabId : 'unattributed';
          const group = groups.get(id) ?? {id, requests: [], firstTimestamp: request.firstTimestamp};
          group.requests.push(request);
          if (request.firstTimestamp < group.firstTimestamp) group.firstTimestamp = request.firstTimestamp;
          groups.set(id, group);
        });
        return [...groups.values()].sort((left, right) => {
          if (left.id === 'unattributed') return 1;
          if (right.id === 'unattributed') return -1;
          return left.firstTimestamp < right.firstTimestamp ? -1 : left.firstTimestamp > right.firstTimestamp ? 1 : 0;
        });
      }

      function renderRequestScopes() {
        const groups = requestTabGroups();
        const availableTabs = new Set(groups.map(group => group.id));
        if (state.requestTabId !== 'all' && !availableTabs.has(state.requestTabId)) state.requestTabId = 'all';
        const oldScopes = new Map([...elements.requestTabScopes.children].map(button => [button.dataset.scopeId, button]));
        const focusedScope = elements.requestTabScopes.contains(document.activeElement) ? document.activeElement : null;
        const buttons = [{id: 'all', label: 'All tabs', count: state.requests.length}, ...groups.map((group, index) => {
          const domains = [...new Set(group.requests.map(requestDomain))];
          const title = group.requests.map(request => String(request.tabTitle ?? '').trim()).find(Boolean);
          const domain = domains.find(value => value && value !== 'unknown');
          const fallback = `Tab ${index + 1}`;
          const label = group.id === 'unattributed' ? 'Unattributed'
            : title ? (title.length > 42 ? `${title.slice(0, 41)}…` : title)
            : domain || fallback;
          return {
            id: group.id,
            label,
            count: group.requests.length,
            domains
          };
        })].map(scope => {
          let button = oldScopes.get(scope.id);
          const created = !button;
          if (!button) {
            button = document.createElement('button');
            button.type = 'button';
            button.className = 'request-tab-scope';
            button.dataset.scopeId = scope.id;
            button.append(document.createElement('strong'), document.createElement('span'));
          }
          button.setAttribute('role', 'tab');
          button.setAttribute('aria-selected', String(state.requestTabId === scope.id));
          button.tabIndex = state.requestTabId === scope.id ? 0 : -1;
          if (button.children[0].textContent !== scope.label) button.children[0].textContent = scope.label;
          if (button.children[1].textContent !== String(scope.count)) button.children[1].textContent = String(scope.count);
          button.title = scope.id === 'all' ? 'Show requests from every captured browser tab'
            : scope.id === 'unattributed' ? 'Events without a browser tab identifier'
              : `${scope.label} · ${scope.domains.join(', ')} · tab id ${scope.id}`;
          if (created) button.addEventListener('click', () => {
            state.requestTabId = scope.id;
            state.requestDomain = 'all';
            renderRequests();
            elements.requestTabScopes.querySelector('[aria-selected="true"]')?.focus();
          });
          if (created) button.addEventListener('keydown', event => {
            if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
            event.preventDefault();
            const tabs = [...elements.requestTabScopes.querySelectorAll('.request-tab-scope')];
            const current = tabs.indexOf(button);
            const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1
              : (current + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
            tabs[next].click();
          });
          return button;
        });
        buttons.forEach((button, index) => {
          if (elements.requestTabScopes.children[index] !== button) elements.requestTabScopes.insertBefore(button, elements.requestTabScopes.children[index] ?? null);
        });
        while (elements.requestTabScopes.children.length > buttons.length) elements.requestTabScopes.lastElementChild.remove();
        if (focusedScope && document.activeElement !== focusedScope) (buttons.includes(focusedScope) ? focusedScope : buttons[0])?.focus({preventScroll: true});

        const scoped = state.requestTabId === 'all' ? state.requests
          : state.requests.filter(request => (request.tabId && request.tabId !== '0' ? request.tabId : 'unattributed') === state.requestTabId);
        const domainCounts = new Map();
        for (const request of scoped) { const domain = requestDomain(request); domainCounts.set(domain, (domainCounts.get(domain) ?? 0) + 1); }
        const domains = [...domainCounts.keys()].sort((left, right) => left.localeCompare(right));
        if (state.requestDomain !== 'all' && !domains.includes(state.requestDomain)) state.requestDomain = 'all';
        const oldOptions = new Map([...elements.requestDomain.children].map(option => [option.value, option]));
        const options = [['all', `All domains (${scoped.length})`], ...domains.map(domain => [domain, `${domain} (${domainCounts.get(domain)})`])]
          .map(([value, label]) => {
            const option = oldOptions.get(value) ?? document.createElement('option'); option.value = value;
            if (option.textContent !== label) option.textContent = label;
            return option;
          });
        options.forEach((option, index) => {
          if (elements.requestDomain.children[index] !== option) elements.requestDomain.insertBefore(option, elements.requestDomain.children[index] ?? null);
        });
        while (elements.requestDomain.children.length > options.length) elements.requestDomain.lastElementChild.remove();
        elements.requestDomain.value = state.requestDomain;
      }

      function trafficRequestFilterKey() {
        return JSON.stringify([state.requestTabId, state.requestDomain, state.requestType,
          elements.requestFilter.value.trim().toLowerCase(),
          state.trafficSort, state.trafficSortDirection]);
      }

      function renderTrafficWindowStatus(start, rowCount, visibleCount) {
        const selectedFiltered = state.selectedRequestId !== null && !state.trafficSearchMatches.has(state.selectedRequestId);
        const message = `${visibleCount ? start + 1 : 0}–${start + rowCount} of ${visibleCount} matching · ${state.requests.length} retained${selectedFiltered ? ' · Selection outside filter' : ''}`;
        const status = document.querySelector('#request-window-status');
        if (status.textContent !== message) status.textContent = message;
      }

      function renderRequests(selectionOnly = false) {
        const previous = state.trafficRenderedView;
        // Producers replace the retained request array on refresh. Reuse only
        // this exact rendered snapshot and filter/window; all other entry
        // points (polls, search, sort, paging and history) take the full path.
        if (selectionOnly === true && previous?.requests === state.requests && previous.retainedCount === state.requests.length &&
            previous.filterKey === trafficRequestFilterKey() &&
            previous.start === state.trafficWindowStart && previous.anchor === state.trafficWindowAnchor) {
          renderTrafficRowSelection(elements.requestRows, state.selectedRequestId);
          renderTrafficWindowStatus(previous.start, previous.rowCount, previous.visibleCount);
          return;
        }
        state.trafficRenderedView = null;
        renderRequestScopes();
        const needle = elements.requestFilter.value.trim().toLowerCase();
        const scoped = state.requests.filter(request =>
          (state.requestTabId === 'all' ||
            (request.tabId && request.tabId !== '0' ? request.tabId : 'unattributed') === state.requestTabId) &&
          (state.requestDomain === 'all' || requestDomain(request) === state.requestDomain) &&
          (state.requestType === 'all' || request.type === state.requestType)
        );
        const search = trafficSearchRequests(scoped, needle);
        state.trafficSearchMatches = search.matches;
        const visible = trafficSortedRequests(scoped.filter(request => search.matches.has(request.id)), state.trafficSort, state.trafficSortDirection);
        const filterKey = trafficRequestFilterKey();
        const filterChanged = filterKey !== state.trafficFilterKey;
        if (filterChanged) { state.trafficNewIds.clear(); state.trafficWindowStart = 0; state.trafficWindowAnchor = null; }
        state.trafficFilterKey = filterKey;
        const selectedIsVisible = visible.some(request => request.id === state.selectedRequestId);
        const selectionCleared = state.selectedRequestId !== null && !state.requests.some(request => request.id === state.selectedRequestId);
        if (selectionCleared) resetRequestSelection();
        // Only a live capture can deliver new requests. Stored, demo and idle
        // evidence is a fixed set loaded at once, so none of it is "new".
        const knownIds = state.trafficKnownIds, live = state.sessionMode === 'live';
        const newIds = new Set(live && knownIds ? visible.filter(request => !knownIds.has(request.id)).map(request => request.id) : []);
        state.trafficKnownIds = new Set(state.requests.map(request => request.id));
        if (!live) state.trafficNewIds.clear();
        if (!filterChanged) newIds.forEach(id => state.trafficNewIds.add(id));
        for (const id of state.trafficNewIds) if (!state.trafficKnownIds.has(id)) state.trafficNewIds.delete(id);
        const window = trafficWindow(visible, state.trafficWindowStart, state.trafficWindowAnchor);
        state.trafficWindowStart = window.start;
        state.trafficWindowAnchor = window.rows[0]?.id ?? null;
        renderTrafficWindowStatus(window.start, window.rows.length, visible.length);
        const renderedView = {requests: state.requests, retainedCount: state.requests.length, filterKey, start: window.start, anchor: state.trafficWindowAnchor,
          rowCount: window.rows.length, visibleCount: visible.length};
        document.querySelector('#request-window-prev').disabled = window.start === 0;
        document.querySelector('#request-window-next').disabled = window.start + TRAFFIC_ROW_LIMIT >= visible.length;
        document.querySelectorAll('[data-request-sort]').forEach(button => {
          const active = button.dataset.requestSort === state.trafficSort;
          button.setAttribute('aria-pressed', String(active));
          button.setAttribute('aria-label', `${button.dataset.requestSort}: ${active ? state.trafficSortDirection === 1 ? 'ascending' : 'descending' : 'not sorted'}. Activate to sort.`);
          button.querySelector('span').textContent = active ? state.trafficSortDirection === 1 ? ' ↑' : ' ↓' : '';
        });
        elements.requestRows.setAttribute('role', 'listbox');
        if (visible.length === 0) {
          const empty = document.createElement('div');
          empty.className = 'request-empty';
          empty.setAttribute('role', 'status');
          empty.textContent = state.requests.length === 0
            ? state.sessionMode === 'live' ? 'No live requests yet. Start a capture in the attached browser.'
              : state.sessionMode === 'demo' ? 'No developer evidence is available.' : 'No capture session is running.'
            : 'No requests match the current filters. Clear the filter or choose another type.';
          const hadFocus = elements.requestRows.contains(document.activeElement);
          elements.requestRows.replaceChildren(empty);
          elements.requestRows.tabIndex = 0;
          if (hadFocus) elements.requestRows.focus({preventScroll: true});
          state.trafficPendingCount = 0;
          elements.requestLatest.hidden = true;
          renderRequestCount(0, state.requests.length);
          state.trafficRenderedView = renderedView;
          if (selectionCleared) {
            updateSelectionSummary(null);
            renderInspector();
            renderEvidence();
          }
          return;
        }
        renderTrafficRows(elements.requestRows, window.rows, {
          selectedId: state.selectedRequestId, newIds,
          onSelect: id => { selectRequest(id); focusRequestRow(id); }, onKey: moveRequestSelection
        });
        state.trafficPendingCount = state.trafficNewIds.size;
        elements.requestLatest.hidden = state.trafficPendingCount === 0;
        elements.requestLatest.textContent = `${state.trafficPendingCount} new ${state.trafficPendingCount === 1 ? 'request' : 'requests'}`;
        renderRequestCount(visible.length, state.requests.length);
        state.trafficRenderedView = renderedView;
        if (selectionCleared) {
          updateSelectionSummary(null);
          renderInspector();
          renderEvidence();
        } else if (filterChanged && selectedIsVisible) renderInspector();
      }

      function updateSelectionSummary(request) {
        if (!request) {
          elements.selectedMethod.textContent = '-';
          elements.selectedStatus.textContent = '-';
          elements.selectedStatus.classList.remove('status-error');
          elements.selectedStatus.classList.add('status-neutral');
          elements.selectedUrl.textContent = state.trafficSelectionNotice || (state.requests.length ? 'Select a request to inspect its evidence.' : 'No request selected');
          elements.selectedUrl.title = '';
          elements.requestCopyUrl.disabled = true;
          return;
        }
        elements.selectedMethod.textContent = request.method;
        elements.selectedStatus.textContent = request.status;
        const numericStatus = Number(request.status);
        const failed = Boolean(request.failed) || Number.isFinite(numericStatus) && numericStatus >= 400;
        elements.selectedStatus.classList.toggle('status-error', failed);
        elements.selectedStatus.classList.toggle('status-neutral', !failed && (!Number.isFinite(numericStatus) || request.status === 'pending'));
        elements.selectedUrl.textContent = request.origin === 'sample'
          ? `https://checkout.acme.test${request.path}`
          : request.hostOnly ? `${request.path} (host only metadata)` : request.path;
        elements.selectedUrl.title = elements.selectedUrl.textContent;
        elements.requestCopyUrl.disabled = request.hostOnly;
      }

      function selectRequest(id, expectedIdentity = null) {
        if (expectedIdentity) {
          const candidates = state.requests.filter(candidate => candidate.id === id);
          if (candidates.length !== 1 || !investigationSame(expectedIdentity, investigationRequestIdentity(candidates[0]))) {
            investigationNotice('The exact request cannot be selected: its row identifier is missing, changed or ambiguous.', 'ambiguous'); return false;
          }
        }
        investigationBeforeSelection();
        state.originTraceController?.abort();
        const request = state.requests.find(candidate => candidate.id === id);
        if (!request) return;
        state.selectedRequestId = id;
        state.trafficDetailOpen = true;
        state.trafficSelectionNotice = null;
        state.originTrace = null;
        state.selectedTraceRow = null;
        state.originTraceStatus = 'idle';
        state.originTraceError = null;
        state.originTraceKey = null;
        state.originTraceEtag = null;
        state.originTraceGeneration += 1;
        state.signalProfile = null;
        state.signalProfileStatus = 'idle';
        state.signalProfileError = null;
        state.signalProfileKey = null;
        state.signalProfileEtag = null;
        state.signalProfileGeneration += 1;
        updateSelectionSummary(request);
        if (request.traceable) {
          elements.prompt.textContent = 'Choose a request value and trace where it came from.';
          state.fieldTab = 'body';
          state.selectedField = fieldSets.body.find(field => field.traceable);
        } else {
          elements.prompt.textContent = request.origin === 'live'
            ? 'This live event has no captured field structure yet.'
            : request.origin === 'demo'
              ? 'This demo event has no captured field structure.'
              : 'This sample request has no trace target in the proof of concept.';
          state.selectedField = null;
        }
        renderRequests(true);
        renderInspector();
        renderEvidence();
        refreshRequestSignalProfile();
      }

      function moveRequestSelection(event) {
        if (!['ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) return;
        const rows = [...elements.requestRows.querySelectorAll('.request-row')];
        const current = rows.indexOf(event.currentTarget);
        if (current < 0) return;
        event.preventDefault();
        const next = event.key === 'Home'
          ? 0
          : event.key === 'End'
            ? rows.length - 1
            : Math.max(0, Math.min(rows.length - 1, current + (event.key === 'ArrowDown' ? 1 : -1)));
        const id = rows[next].dataset.requestId;
        selectRequest(id);
        focusRequestRow(id);
        rows[next].scrollIntoView({block: 'nearest'});
      }

      function focusRequestRow(id) {
        [...elements.requestRows.querySelectorAll('.request-row')]
          .find(row => row.dataset.requestId === id)?.focus({ preventScroll: true });
      }

      function requestTraceRoot(request) {
        if (request?.origin !== 'live') return null;
        const candidates = request.events ?? [];
        return candidates.find(event => event.type === 'request_started' && integerText(event, 'request_id') !== '0') ??
          candidates.find(event => event.type === 'request_initiated' && integerText(event, 'request_id') !== '0') ??
          candidates.find(event => integerText(event, 'request_id') !== '0') ?? null;
      }

      function requestSignalProfileSelection() {
        const candidates = state.requests.filter(candidate => candidate.id === state.selectedRequestId);
        const request = candidates.length === 1 ? candidates[0] : null;
        const root = requestSignalRoot(request);
        if (!request || !root) return null;
        const requestID = integerText(root, 'request_id');
        const sessionID = integerText(root, 'session_id');
        const rootProcessID = root.process_id;
        const rootSequenceNumber = integerText(root, 'sequence_number');
        return {
          requestID, sessionID, rootProcessID, rootSequenceNumber,
          key: JSON.stringify([request.id, sessionID, requestID, rootProcessID, rootSequenceNumber])
        };
      }

      async function refreshRequestSignalProfile() {
        const generation = ++state.signalProfileGeneration;
        const selection = requestSignalProfileSelection();
        const render = () => {
          if (state.inspectorTab === 'signals') renderInspector();
          if (!document.querySelector('#screen-signals').hidden) renderFingerprintActivity();
        };
        if (state.signalProfileKey !== selection?.key || location.protocol === 'file:') {
          state.signalProfile = null;
          state.signalProfileKey = null;
          state.signalProfileEtag = null;
        }
        if (!selection || location.protocol === 'file:') {
          state.signalProfile = null;
          state.signalProfileStatus = 'empty';
          state.signalProfileError = null;
          render();
          return;
        }
        const ownsSelection = () => {
          if (generation !== state.signalProfileGeneration) return false;
          if (requestSignalProfileSelection()?.key === selection.key) return true;
          state.signalProfileGeneration += 1;
          state.signalProfile = null;
          state.signalProfileKey = null;
          state.signalProfileEtag = null;
          state.signalProfileStatus = 'error';
          state.signalProfileError = 'The selected request event changed while reading its signal profile. Select the request again.';
          render();
          return false;
        };
        state.signalProfileStatus = 'loading';
        state.signalProfileError = null;
        render();
        try {
          const headers = state.signalProfileKey === selection.key && state.signalProfileEtag
            ? { 'If-None-Match': state.signalProfileEtag }
            : {};
          const parameters = new URLSearchParams({
            session_id: selection.sessionID,
            request_id: selection.requestID,
            root_process_id: String(selection.rootProcessID),
            root_sequence_number: selection.rootSequenceNumber
          });
          const response = await fetch(`/api/request-signal-profile?${parameters}`, { cache: 'no-store', headers });
          if (!ownsSelection()) return;
          if (response.status === 304) {
            if (!headers['If-None-Match'] || state.signalProfileKey !== selection.key) {
              throw new TypeError('Request signal profile returned an unowned cached response');
            }
            state.signalProfileStatus = state.signalProfile ? 'ready' : 'empty';
          } else if (response.status === 404) {
            state.signalProfile = null;
            state.signalProfileStatus = 'empty';
            state.signalProfileKey = selection.key;
            state.signalProfileEtag = response.headers.get('ETag');
          } else {
            if (!response.ok) throw new Error(`Request signal profile store returned ${response.status}`);
            const body = await response.json();
            if (!ownsSelection()) return;
            if (!isRequestSignalProfile(body)) throw new TypeError('Malformed request signal profile');
            if (body.session_id !== selection.sessionID || body.request_id !== selection.requestID ||
                body.root_event.process_id !== selection.rootProcessID || body.root_event.sequence_number !== selection.rootSequenceNumber) {
              throw new TypeError('Signal profile belongs to a different captured request or event. Exact linkage is unavailable.');
            }
            state.signalProfile = body;
            state.signalProfileStatus = 'ready';
            state.signalProfileKey = selection.key;
            state.signalProfileEtag = response.headers.get('ETag');
          }
        } catch (error) {
          if (!ownsSelection()) return;
          state.signalProfileEtag = null;
          state.signalProfileStatus = 'error';
          state.signalProfileError = error.message;
        }
        render();
      }

      function renderFields() {
        document.querySelectorAll('.field-tab').forEach(tab => {
          const selected = tab.dataset.fieldTab === state.fieldTab;
          tab.setAttribute('aria-selected', String(selected));
          tab.tabIndex = selected ? 0 : -1;
        });
        const request = state.requests.find(candidate => candidate.id === state.selectedRequestId);
        if (state.inspectorTab === 'evidence' && request?.traceable) {
          elements.fieldTree.setAttribute('role', 'tabpanel');
          elements.fieldTree.setAttribute('aria-labelledby', `field-tab-${state.fieldTab}`);
          elements.fieldTree.tabIndex = 0;
        } else {
          elements.fieldTree.removeAttribute('role');
          elements.fieldTree.removeAttribute('aria-labelledby');
          elements.fieldTree.tabIndex = -1;
        }
        if (!request?.traceable) {
          const empty = document.createElement('div');
          empty.className = 'field-empty';
          empty.textContent = request?.origin === 'live'
            ? 'Structured fields were not captured. Request-level origin evidence is still available.'
            : request?.origin === 'demo'
              ? 'Demo request fields are not traceable. Select a live request for broker-backed origin evidence.'
              : request
                ? 'This sample request has no trace target in the proof of concept.'
                : 'Select a request to inspect its fields.';
          elements.fieldTree.replaceChildren(empty);
          const root = requestTraceRoot(request);
          elements.traceTarget.textContent = root
            ? `${request.method} ${request.path} · request ${integerText(root, 'request_id')}`
            : 'No broker-backed trace target selected';
          elements.traceButton.disabled = !root;
          elements.requestDecoderPivot.disabled = true;
          return;
        }

        const fields = fieldSets[state.fieldTab];
        elements.fieldTree.replaceChildren(...fields.map(field => {
          const row = document.createElement(field.traceable ? 'button' : 'div');
          if (field.traceable) row.type = 'button';
          row.className = `field-row${field.traceable ? ' selectable' : ''}`;
          if (field.traceable) row.setAttribute('aria-pressed', String(state.selectedField?.path === field.path));
          const key = document.createElement('span'); key.className = `field-key${field.group ? ' group' : ''}${field.traceable ? ' traceable' : ''}`; key.style.setProperty('--depth', field.depth); key.textContent = field.key;
          const value = document.createElement('span'); value.className = 'field-value'; value.textContent = field.value;
          const type = document.createElement('span'); type.className = 'field-type'; type.textContent = field.type;
          row.append(key, value, type);
          if (field.traceable) row.addEventListener('click', () => { state.selectedField = field; renderFields(); renderEvidence(); });
          return row;
        }));
        const selected = state.selectedField;
        elements.traceTarget.textContent = selected
          ? `request-${state.selectedRequestId} · ${selected.label} · ${selected.path}`
          : 'Select a traceable field';
        elements.traceButton.disabled = !selected;
        elements.requestDecoderPivot.disabled = !selected;
      }

      function renderInspectorMessage(message) {
        const empty = document.createElement('div');
        empty.className = 'field-empty';
        empty.textContent = message;
        elements.fieldTree.replaceChildren(empty);
      }

      function renderInspectorDetails(rows) {
        elements.fieldTree.replaceChildren(...rows.map(detail => {
          const row = document.createElement('div');
          row.className = 'field-row';
          const key = document.createElement('span'); key.className = 'field-key'; key.textContent = detail.key;
          const value = document.createElement('span'); value.className = 'field-value'; value.textContent = String(detail.value);
          const type = document.createElement('span'); type.className = 'field-type'; type.textContent = detail.type;
          row.append(key, value, type);
          return row;
        }));
      }

      function renderInspector() {
        evidencePackagePanel.sync();
        // History and notebook entries can name inspector tabs that no longer exist.
        if (![...document.querySelectorAll('.inspector-tab')].some(tab => tab.dataset.inspectorTab === state.inspectorTab)) state.inspectorTab = 'general';
        document.querySelector('#request-package-entry').hidden = state.inspectorTab !== 'evidence';
        document.querySelectorAll('.inspector-tab').forEach(tab => {
          const selected = tab.dataset.inspectorTab === state.inspectorTab;
          tab.setAttribute('aria-selected', String(selected));
          tab.tabIndex = selected ? 0 : -1;
        });
        const exchangeInspector = document.querySelector('#exchange-inspector');
        const showingGeneral = state.inspectorTab === 'general' || state.selectedRequestId === null;
        const request = state.requests.find(candidate => candidate.id === state.selectedRequestId);
        updateSelectionSummary(request);

        document.querySelector('.traffic-grid').dataset.detailOpen = String(state.trafficDetailOpen);
        document.querySelector('.detail-pane').hidden = !state.trafficDetailOpen;
        exchangeInspector.hidden = !showingGeneral;
        exchangeInspector.setAttribute('aria-labelledby', `inspector-tab-${state.inspectorTab}`);
        const evidenceToggle = document.querySelector('#request-evidence-toggle');
        evidenceToggle.textContent = state.inspectorTab === 'evidence' ? 'General' : 'Evidence';
        evidenceToggle.setAttribute('aria-expanded', String(state.inspectorTab === 'evidence'));
        evidenceToggle.disabled = !request;
        elements.requestCollectionPivot.disabled = !request;
        elements.requestInspector.hidden = showingGeneral;
        document.querySelector('.detail-pane').classList.toggle('showing-exchange', showingGeneral);
        if (showingGeneral) {
          renderTrafficDetails(exchangeInspector, request, state.trafficSelectionNotice);
          return;
        }
        elements.requestInspector.setAttribute('aria-labelledby', `inspector-tab-${state.inspectorTab}`);
        if (state.inspectorTab !== 'evidence') {
          elements.fieldTree.removeAttribute('role');
          elements.fieldTree.removeAttribute('aria-labelledby');
          elements.fieldTree.tabIndex = -1;
        }
        if (state.inspectorTab === 'evidence') {
          const traceable = Boolean(request?.traceable);
          const requestTraceable = Boolean(requestTraceRoot(request));
          elements.prompt.textContent = traceable
            ? 'Choose a request value and trace where it came from.'
            : requestTraceable
              ? 'Trace this request backward through observed event relationships.'
              : 'No structured request payload was captured.';
          elements.fieldTabs.hidden = !traceable;
          elements.traceDock.hidden = !traceable && !requestTraceable;
          renderFields();
          return;
        }
        if (state.inspectorTab === 'signals') {
          elements.prompt.textContent = 'Fingerprint activity before this request';
          elements.fieldTabs.hidden = true;
          elements.traceDock.hidden = !requestTraceRoot(request);
          if (state.signalProfileStatus === 'loading') {
            renderInspectorMessage('Building a bounded profile from retained browser-signal evidence.');
            return;
          }
          if (state.signalProfileStatus === 'error') {
            renderInspectorMessage(state.signalProfileError || 'The signal profile is unavailable.');
            return;
          }
          if (!state.signalProfile) {
            renderInspectorMessage('No request signal profile was retained for this request.');
            return;
          }
          if (state.signalProfile.signals.length === 0) {
            renderInspectorMessage('No fingerprint-relevant browser signals were retained for this request.');
            return;
          }
          const details = state.signalProfile.signals.map(signal => ({
            key: fingerprintSignalLabels.get(signal.category) ?? signal.category,
            value: `${signal.event_count} event${signal.event_count === '1' ? '' : 's'} · process ${signal.last_event.process_id} · event ${signal.last_event.sequence_number}`,
            type: signal.confidence === 'observed' ? 'Observed' : 'Correlated'
          }));
          const coverage = state.signalProfile.coverage;
          details.push({
            key: 'coverage',
            value: `${coverage.parent_depth}/${coverage.parent_depth_limit} parent steps${coverage.copied_from_initiator ? ' · renderer initiator bridged' : ''}`,
            type: coverage.retention_truncated || coverage.parent_depth_limited || coverage.count_saturated ? 'Partial' : 'Bounded'
          });
          renderInspectorDetails(details);
          return;
        }
        if (state.inspectorTab === 'initiator') {
          elements.prompt.textContent = 'Initiator';
          elements.fieldTabs.hidden = true;
          elements.traceDock.hidden = true;
          const lifecycleEvents = request?.events ?? [];
          const correlated = lifecycleEvents.find(event => event.protocol_version >= 2 && event.initiator_process_id > 0);
          const initiated = lifecycleEvents.find(event => event.type === 'request_initiated');
          const contextEvent = lifecycleEvents.find(event => browserContextToken(event));
          if (correlated || initiated || contextEvent) {
            const source = correlated ?? initiated ?? contextEvent;
            const details = [{ key: 'correlation', value: request.id, type: 'id' }];
            if (contextEvent) {
              details.push({ key: 'browser context', value: browserContextToken(contextEvent), type: 'token' });
            }
            if (correlated || initiated) {
              details.push(
                { key: 'renderer process', value: correlated?.initiator_process_id ?? initiated.process_id, type: 'pid' },
                { key: 'renderer request', value: correlated?.initiator_request_id ?? integerText(initiated, 'request_id'), type: 'id' }
              );
            } else {
              details.push(
                { key: 'browser process', value: contextEvent.process_id, type: 'pid' },
                { key: 'browser request', value: integerText(contextEvent, 'request_id'), type: 'id' }
              );
            }
            details.push({ key: 'frame', value: integerText(source, 'frame_id'), type: 'id' });
            renderInspectorDetails(details);
          } else {
            renderInspectorMessage(request?.origin === 'sample'
              ? 'Sample initiator evidence is available in the request field backtrace.'
              : request?.origin === 'demo'
                ? 'Demo initiator evidence is available in the retained event payload.'
                : 'No renderer initiator was captured for this browser request.');
          }
          return;
        }
        if (state.inspectorTab === 'timing') {
          elements.prompt.textContent = 'Timing';
          elements.fieldTabs.hidden = true;
          elements.traceDock.hidden = true;
          if (request?.origin === 'live') {
            renderInspectorDetails([
              { key: 'first event', value: request.firstTimestamp, type: 'ns' },
              { key: 'last event', value: request.lastTimestamp, type: 'ns' },
              { key: 'duration', value: trafficTimeLabel(request.time), type: 'time' },
              { key: 'lifecycle', value: request.operation, type: 'state' },
              { key: 'events', value: request.events.length, type: 'count' },
              { key: 'phase breakdown', value: 'DNS, connection, TLS, waiting and download phases were not captured.', type: 'unavailable' }
            ]);
          } else if (request) {
            renderInspectorDetails([
              { key: 'duration', value: trafficTimeLabel(request.time), type: 'time' },
              { key: 'source', value: request.origin === 'demo' ? 'demo evidence' : 'sample workspace data', type: 'source' }
            ]);
          } else {
            renderInspectorMessage('No request timing is available.');
          }
          return;
        }

      }

      function renderEvidence() {
        evidencePackagePanel.sync();
        evidenceWorkspace.sync();
        const currentTrace = state.originTraceKey === originTraceSelection()?.key ? state.originTrace : null;
        elements.evidenceLinkCount.textContent = String(currentTrace?.steps?.length ?? 0);
        if (!document.querySelector('#screen-backtrace').hidden) renderBacktrace();
      }

      function originTraceSelection() {
        const candidates = state.requests.filter(candidate => candidate.id === state.selectedRequestId);
        const request = candidates.length === 1 ? candidates[0] : null;
        const root = requestTraceRoot(request);
        if (!request || !root) return null;
        const requestID = investigationId(root.request_id), sessionID = investigationId(root.session_id);
        const rootSequenceNumber = investigationId(root.sequence_number), rootProcessID = root.process_id;
        if (!requestID || !sessionID || sessionID === '0' || !rootSequenceNumber || rootSequenceNumber === '0' ||
            !Number.isSafeInteger(rootProcessID) || rootProcessID < 0 || rootProcessID > 4294967295) return null;
        return {
          request, root, requestID, sessionID, rootProcessID, rootSequenceNumber,
          key: `${request.id}:${sessionID}:${rootProcessID}:${rootSequenceNumber}`
        };
      }

      async function refreshOriginTrace() {
        state.originTraceController?.abort();
        const generation = ++state.originTraceGeneration;
        const selection = originTraceSelection();
        if (!selection || location.protocol === 'file:') {
          state.originTraceStatus = 'empty';
          state.originTraceError = 'An unambiguous retained request with exact session and event identifiers is required for origin tracing.';
          renderBacktrace();
          return;
        }
        const controller = new AbortController();
        state.originTraceController = controller;
        const timer = setTimeout(() => controller.abort(), 10000);
        const ownsSelection = () => {
          if (generation !== state.originTraceGeneration) return false;
          if (originTraceSelection()?.key === selection.key) return true;
          state.originTraceGeneration += 1;
          state.originTrace = null; state.originTraceKey = null; state.originTraceEtag = null;
          state.selectedTraceRow = null; state.originTraceStatus = 'error';
          state.originTraceError = 'The selected request event changed while reading its trace. Load the current trace explicitly.';
          renderBacktrace(); return false;
        };
        state.originTraceStatus = 'loading';
        state.originTraceError = null;
        renderBacktrace();
        try {
          const headers = state.originTraceKey === selection.key && state.originTraceEtag
            ? { 'If-None-Match': state.originTraceEtag }
            : {};
          const parameters = new URLSearchParams({
            request_id: selection.requestID,
            session_id: selection.sessionID,
            root_process_id: String(selection.rootProcessID),
            root_sequence_number: selection.rootSequenceNumber
          });
          const response = await fetch(`/api/origin-trace?${parameters}`, { cache: 'no-store', headers, signal: controller.signal });
          if (!ownsSelection()) return;
          if (response.status === 304 && state.originTrace && state.originTraceKey === selection.key) {
            state.originTraceStatus = 'ready';
            renderBacktrace();
            return;
          }
          if (!response.ok) throw new Error(`Origin trace store returned ${response.status}`);
          const bytes = await sourceFactsReadBytes(response, 1024 * 1024, controller.signal);
          const body = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes));
          if (!ownsSelection()) return;
          if (!isOriginTraceResponse(body)) throw new TypeError('Malformed origin trace response');
          if (body.request_id !== selection.requestID || body.steps.length && !investigationSame(investigationEventIdentity(body.steps[0].event), investigationEventIdentity(selection.root))) {
            throw new TypeError('Trace root belongs to a different captured session or event. Exact linkage is unavailable.');
          }
          state.originTrace = body;
          state.originTraceStatus = 'ready';
          state.originTraceKey = selection.key;
          state.originTraceEtag = response.headers.get('ETag');
        } catch (error) {
          if (!ownsSelection()) return;
          state.originTraceStatus = 'error';
          state.originTraceError = controller.signal.aborted ? 'The trace read timed out or was cancelled. Load the current trace explicitly.' : error.message.replace(/source-facts/gi, 'trace');
        } finally {
          clearTimeout(timer);
          controller.abort();
          if (state.originTraceController === controller) state.originTraceController = null;
        }
        renderBacktrace();
        renderEvidence();
      }

      function traceStepDetails(model) {
        const panel = elements.traceStepDetails;
        panel.replaceChildren(textElement('h3', '', model.title), textElement('p', 'trace-detail-relation', model.kind));
        if (!model.step) {
          panel.append(textElement('p', 'trace-detail-message', model.meta));
          return;
        }
        const step = model.step;
        const facts = document.createElement('dl'); facts.className = 'trace-facts';
        const identifierLabels = new Set(['Session', 'Process', 'Event', 'Frame', 'Request', 'Artifact']);
        const identifiers = document.createElement('dl'); identifiers.className = 'trace-facts';
        const traceFactValue = (label, value) => {
          if (!identifierLabels.has(label)) return textElement('dd', '', String(value));
          const dd = document.createElement('dd'); dd.className = 'trace-fact-id';
          const raw = String(value);
          const valueElement = textElement('span', 'trace-fact-id-value', raw); valueElement.title = raw;
          const copy = document.createElement('button'); copy.type = 'button'; copy.className = 'trace-copy-id';
          copy.textContent = 'Copy'; copy.title = `Copy ${label} ID`;
          copy.setAttribute('aria-label', `Copy ${label} identifier`);
          copy.addEventListener('click', async () => {
            try {
              await navigator.clipboard.writeText(raw);
              copy.textContent = 'Copied'; copy.dataset.kind = 'success';
            } catch {
              copy.textContent = 'Copy failed'; copy.dataset.kind = 'error';
            }
          });
          dd.append(valueElement, copy);
          return dd;
        };
        [
          ['Relationship', step.relation.replaceAll('_', ' ')],
          ['Link type', step.confidence === 'observed' ? 'Recorded event link' : 'Matched by shared identifiers'],
          ['Time (monotonic ns)', step.monotonic_time_ns],
          ['Session', step.event.session_id], ['Process', step.event.process_id],
          ['Event', step.event.sequence_number], ['Frame', step.frame_id],
          ['Request', step.request_id], ['Artifact', step.artifact_id]
        ].forEach(([label, value]) => {
          const target = identifierLabels.has(label) ? identifiers : facts;
          target.append(textElement('dt', '', label), traceFactValue(label, value));
        });
        const metadata = document.createElement('details'); metadata.className = 'workspace-disclosure';
        metadata.append(textElement('summary', '', 'Evidence identifiers'), identifiers);
        panel.append(facts, metadata);
        if (step.value) panel.append(textElement('h4', '', 'Captured value'), textElement('pre', 'trace-value', step.value));
        const sourceLink = investigationTraceArtifact(step);
        const open = textElement('button', 'secondary-button', 'Open retained source'); open.type = 'button';
        open.dataset.investigationSource = 'true'; open.disabled = sourceLink.status !== 'ready';
        open.addEventListener('click', () => openInvestigation({kind: 'artifact', identity: sourceLink.identity,
          relation: `Trace step S${step.event.session_id}:P${step.event.process_id}:E${step.event.sequence_number} records this artifact. Trace relationship: ${step.confidence === 'observed' ? 'recorded link' : 'shared identifiers only'}. No value flow is implied.`}));
        panel.append(open);
        if (sourceLink.status !== 'ready') panel.append(textElement('p', 'trace-detail-message', sourceLink.message));
      }

      function traceStepElement(model) {
        const item = document.createElement('li'); item.className = `trace-step${model.gap ? ' gap' : ''}`;
        const row = document.createElement('button'); row.type = 'button'; row.className = 'trace-row';
        row.dataset.traceKey = model.key;
        row.setAttribute('aria-pressed', String(state.selectedTraceRow === model.key));
        row.tabIndex = state.selectedTraceRow === model.key ? 0 : -1;
        const copy = document.createElement('span'); copy.className = 'trace-row-copy';
        copy.append(textElement('span', 'step-title', model.title), textElement('span', 'step-kind', model.kind));
        row.append(textElement('span', 'step-index', model.index), copy,
          textElement('span', `trace-link-type ${model.style}`, model.confidence));
        row.addEventListener('click', () => {
          state.selectedTraceRow = model.key;
          elements.backtraceSteps.querySelectorAll('.trace-row').forEach(candidate => {
            const active = candidate === row;
            candidate.setAttribute('aria-pressed', String(active)); candidate.tabIndex = active ? 0 : -1;
          });
          traceStepDetails(model);
        });
        row.addEventListener('keydown', event => {
          if (!['ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) return;
          event.preventDefault();
          const rows = [...elements.backtraceSteps.querySelectorAll('.trace-row')];
          const current = rows.indexOf(row);
          const next = event.key === 'Home' ? 0 : event.key === 'End' ? rows.length - 1
            : (current + (event.key === 'ArrowDown' ? 1 : -1) + rows.length) % rows.length;
          rows[next].click(); rows[next].focus();
        });
        item.append(row); return item;
      }

      function renderBacktrace() {
        const selection = originTraceSelection();
        const request = state.requests.find(candidate => candidate.id === state.selectedRequestId);
        const captured = state.requests.filter(candidate => requestTraceRoot(candidate));
        const choices = request && !requestTraceRoot(request) ? [request, ...captured] : captured;
        const choiceKey = JSON.stringify(choices.map(candidate => [candidate.id, candidate.method, candidate.path]));
        if (elements.traceRequest.dataset.choices !== choiceKey) {
          elements.traceRequest.replaceChildren(...choices.map(candidate => {
          const option = document.createElement('option'); option.value = candidate.id;
          option.textContent = `${candidate.method} ${candidate.path}${requestTraceRoot(candidate) ? '' : candidate.origin === 'sample' ? ' (sample, no predecessor evidence)' : candidate.origin === 'demo' ? ' (demo, no predecessor evidence)' : ' (no request identifier)'}`;
          option.selected = candidate.id === state.selectedRequestId;
          return option;
          }));
          elements.traceRequest.dataset.choices = choiceKey;
        }
        elements.traceRequest.value = state.selectedRequestId || '';
        elements.traceRequest.disabled = !choices.length;
        elements.traceLoad.disabled = !selection || state.originTraceStatus === 'loading';
        elements.traceLoad.textContent = state.originTrace ? 'Refresh trace' : 'Load trace';
        elements.backtraceSubtitle.textContent = selection
          ? `${request.method} ${request.path}`
          : 'Request events and their recorded predecessors';
        const trace = selection && state.originTraceKey === selection.key ? state.originTrace : null;
        const hasSteps = Boolean(trace?.steps.length);
        elements.traceContent.hidden = !hasSteps;
        elements.traceEmpty.hidden = hasSteps;
        elements.traceEvidence.hidden = !hasSteps;
        elements.traceFirstRequest.hidden = Boolean(selection) || !captured.length;
        const loading = state.originTraceStatus === 'loading';
        const failed = state.originTraceStatus === 'error';
        elements.traceNotice.hidden = !hasSteps || !(loading || failed);
        elements.traceNotice.textContent = loading ? 'Refreshing trace…' : `Refresh failed. Showing the previous trace. ${state.originTraceError || ''}`;
        elements.traceEmptyTitle.textContent = loading ? 'Loading trace…' : failed ? 'Could not load this trace'
          : !selection ? (request?.origin === 'sample' ? 'This sample request has no trace' : request?.origin === 'demo' ? 'This demo event has no trace' : request ? 'This event has no request identifier' : captured.length ? 'Choose a captured request' : 'No captured requests yet')
          : trace?.status === 'ambiguous' ? 'Choose a concrete request event' : trace ? 'No predecessor evidence was retained' : 'Ready to load';
        elements.traceEmptyMessage.textContent = loading ? 'Reading the recorded events for this request.'
          : failed ? (state.originTraceError || 'Try loading the trace again.')
          : !selection ? (captured.length ? 'Choose a captured request above, or open the first one below.' : 'Capture a request in a live session, then return here to inspect its events.')
          : trace?.status === 'ambiguous' ? (trace.gaps[0]?.detail || 'Select the request row with the matching process and event identifiers.')
          : trace ? (trace.gaps[0]?.detail || 'The request was captured, but no earlier predecessor event was retained.') : 'Choose Load trace to inspect this request.';
        const models = [];
        const labels = {trace_target: 'Selected request', parent_event: 'Previous event', request_initiator: 'Request initiator', request_lifecycle: 'Request lifecycle', artifact_request: 'Related artifact'};
        const gapLabels = {
          ambiguous_request: 'Ambiguous request identifier',
          missing_event: 'Missing event · predecessor not retained',
          no_predecessor: 'Missing predecessor · no recorded link',
          cycle: 'Trace stopped · correlation cycle',
          step_limit: 'Trace stopped · step limit reached',
          capture_gap: 'Capture incomplete · native queue drops'
        };
        (trace?.steps ?? []).forEach((step, index) => {
          models.push({key: `${step.event.process_id}:${step.event.sequence_number}`, index: String(index + 1),
            title: `${step.category} · ${step.operation}`, kind: labels[step.relation] || step.relation,
            confidence: step.confidence === 'observed' ? 'Recorded link' : 'Shared identifiers',
            style: step.confidence === 'observed' ? 'exact' : 'correlation', step});
          trace.gaps.filter(gap => gap.after_step === index).forEach((gap, gapIndex) => models.push({
            key: `gap:${index}:${gapIndex}`, index: '!', title: gapLabels[gap.reason] || gap.reason.replaceAll('_', ' '),
            kind: gap.reason === 'missing_event' ? 'Missing event · retained evidence gap' : 'Trace gap',
            confidence: 'Gap', style: 'unknown', meta: gap.detail, gap: true
          }));
        });
        if (!models.some(model => model.key === state.selectedTraceRow)) state.selectedTraceRow = models[0]?.key ?? null;
        const focusedKey = document.activeElement?.dataset?.traceKey;
        elements.backtraceSteps.replaceChildren(...models.map(traceStepElement));
        if (focusedKey) {
          [...elements.backtraceSteps.querySelectorAll('.trace-row')]
            .find(row => row.dataset.traceKey === focusedKey)?.focus({preventScroll: true});
        }
        const active = models.find(model => model.key === state.selectedTraceRow);
        if (active) traceStepDetails(active); else elements.traceStepDetails.replaceChildren();
        if (hasSteps) {
          const {linked_steps: linked, gap_count: gaps} = trace.coverage;
          const links = `${linked} recorded predecessor link${linked === 1 ? '' : 's'}`;
          const gapsText = `${gaps} reported gap${gaps === 1 ? '' : 's'}`;
          elements.coverageValue.textContent = `${trace.coverage.percent}% trace coverage · ${links} · ${gapsText}`;
          elements.coverageValue.title = 'Coverage counts recorded predecessor links against named gaps. Queue-drop markers describe retained streams and do not identify missing links or prove value flow.';
        } else {
          elements.coverageValue.textContent = '';
          elements.coverageValue.removeAttribute?.('title');
        }
      }

      function collectionFolder(folderId) {
        return state.apiCollection.folders.find(folder => folder.id === folderId) ?? null;
      }

      function collectionRequest(requestId = state.collectionSelectedRequestId) {
        return state.apiCollection.requests.find(request => request.id === requestId) ?? null;
      }

      function collectionFolderLineage(folderId) {
        const lineage = [];
        const seen = new Set();
        let folder = collectionFolder(folderId);
        while (folder && !seen.has(folder.id)) {
          lineage.unshift(folder);
          seen.add(folder.id);
          folder = folder.parent_id === null ? null : collectionFolder(folder.parent_id);
        }
        return lineage;
      }

      function collectionFolderDepth(folderId) {
        return Math.max(0, collectionFolderLineage(folderId).length - 1);
      }

      function collectionDescendantIds(folderId) {
        const descendants = new Set();
        const visit = parentId => state.apiCollection.folders
          .filter(folder => folder.parent_id === parentId)
          .forEach(folder => { descendants.add(folder.id); visit(folder.id); });
        visit(folderId);
        return descendants;
      }

      function collectionNextId(values) {
        return values.reduce((maximum, value) => Math.max(maximum, value.id), 0) + 1;
      }

      function collectionNextRequestId() { return collectionNextId(state.apiCollection.requests); }

      function collectionVariablesFromText(value, label) {
        const source = value.trim();
        if (!source) return [];
        let variables;
        try { variables = JSON.parse(source); }
        catch { throw new TypeError(`${label} must be a JSON object.`); }
        if (!isPlainObject(variables) || Object.values(variables).some(item => typeof item !== 'string')) {
          throw new TypeError(`${label} must map variable names to text values.`);
        }
        const entries = Object.entries(variables).sort(([left], [right]) => left.localeCompare(right));
        let bytes = 0;
        if (entries.length > 32 || entries.some(([name, value]) => {
          bytes += utf8ByteLength(name) + utf8ByteLength(value);
          return !/^[A-Za-z_][A-Za-z0-9_.-]*$/u.test(name) || utf8ByteLength(name) > 64 ||
            utf8ByteLength(value) > 4 * 1024 || /[\x00-\x1f\x7f]/u.test(value) || bytes > 32 * 1024;
        })) throw new TypeError(`${label} exceeds the 32-variable or 32 KiB scope limit.`);
        return entries.map(([name, value]) => ({name, value}));
      }

      function collectionVariablesText(variables) {
        return variables.length ? JSON.stringify(Object.fromEntries(
          variables.map(variable => [variable.name, variable.value])
        ), null, 2) : '';
      }

      function collectionHeadersFromText(value) {
        let headers;
        try { headers = value.trim() ? JSON.parse(value) : {}; }
        catch { throw new TypeError('Request headers must be a JSON object.'); }
        if (!isPlainObject(headers) || Object.values(headers).some(item => typeof item !== 'string')) {
          throw new TypeError('Request headers must map names to text values.');
        }

        const forbidden = new Set(['authorization', 'connection', 'content-length', 'cookie', 'host',
          'proxy-authorization', 'set-cookie', 'transfer-encoding']);
        const entries = Object.entries(headers);
        let bytes = 0;
        if (entries.length > 64 || entries.some(([name, headerValue]) => {
          bytes += utf8ByteLength(name) + utf8ByteLength(headerValue);
          return !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u.test(name) || forbidden.has(name.toLowerCase()) ||
            utf8ByteLength(name) > 128 || utf8ByteLength(headerValue) > 2 * 1024 ||
            /[\x00-\x1f\x7f]/u.test(headerValue) || bytes > 16 * 1024;
        })) throw new TypeError('Request headers are forbidden, invalid, or exceed 16 KiB.');
        return entries.map(([name, headerValue]) => ({name, value: headerValue}));
      }

      function collectionRequestDraft() {
        const request = collectionRequest();
        if (!request) throw new TypeError('Select a saved request first.');
        if (state.apiCollectionNeedsReload || state.collectionRequestDraftId !== request.id ||
            state.collectionRequestDraftCreatedAt !== request.created_at_ms) {
          throw new TypeError('The request draft owner changed. Discard these edits and retry load before saving.');
        }
        const timeout = Number(elements.collectionRequestTimeout.value);
        if (!Number.isInteger(timeout) || timeout < 100 || timeout > 30000) {
          throw new TypeError('Timeout must be between 100 and 30000 ms.');
        }
        return {
          id: request.id,
          folder_id: Number(elements.collectionRequestFolder.value),
          name: elements.collectionRequestName.value.trim(),
          url: elements.collectionRequestUrl.value.trim(),
          method: elements.collectionRequestMethod.value.trim(),
          headers: collectionHeadersFromText(elements.collectionRequestHeaders.value),
          body: elements.collectionRequestBody.value,
          timeout_ms: timeout,
          variables: collectionVariablesFromText(elements.collectionRequestVariables.value, 'Request variables')
        };
      }

      function collectionReplacement(folders = state.apiCollection.folders, requests = state.apiCollection.requests) {
        return {
          action: 'replace_api_collection',
          expected_generation: state.apiCollection.generation,
          folders: folders.map(folder => ({
            id: folder.id, name: folder.name, parent_id: folder.parent_id, variables: folder.variables
          })),
          requests: requests.map(request => ({
            id: request.id, folder_id: request.folder_id, name: request.name, url: request.url,
            method: request.method, headers: request.headers, body: request.body,
            timeout_ms: request.timeout_ms, variables: request.variables
          }))
        };
      }

      function setCollectionNotice(kind, message) {
        state.apiCollectionStatus = kind;
        state.apiCollectionMessage = message;
        elements.collectionNotice.dataset.kind = kind;
        elements.collectionNotice.textContent = message;
      }

      async function refreshApiCollection(force = false) {
        if (state.apiCollectionRefreshing || state.apiCollectionSaving || location.protocol === 'file:') return false;
        state.apiCollectionRefreshing = true;
        const version = state.apiCollectionVersion;
        const controller = new AbortController();
        const deadline = setTimeout(() => controller.abort(), 15000);
        if (!state.apiCollectionLoaded) setCollectionNotice('loading', 'Loading your local collection…');
        try {
          const headers = !force && state.apiCollectionEtag ? {'If-None-Match': state.apiCollectionEtag} : {};
          const response = await fetch('/api/api-collection', {cache: 'no-store', headers, signal: controller.signal});
          if (version !== state.apiCollectionVersion) return false;
          if (response.status === 304) return true;
          if (!response.ok) throw new Error(`Collection store returned ${response.status}`);
          const body = await response.json();
          if (version !== state.apiCollectionVersion) return false;
          if (!isApiCollection(body)) throw new TypeError('Malformed Collection response');
          if (body.generation < state.apiCollection.generation) return false;
          const missingRequest = state.collectionDraftDirty && !body.requests.some(item => item.id === state.collectionRequestDraftId &&
            item.created_at_ms === state.collectionRequestDraftCreatedAt);
          const missingFolder = state.collectionFolderDirty && !body.folders.some(item => item.id === state.collectionFolderDraftId);
          if (missingRequest || missingFolder) {
            state.apiCollectionEtag = null;
            state.apiCollectionNeedsReload = true;
            setCollectionNotice('conflict', 'The edited item was removed or replaced in another window. Your edits remain here. Discard them, then retry load to see the current collection.');
            return false;
          }
          state.apiCollection = body;
          state.apiCollectionNeedsReload = false;
          state.apiCollectionLoaded = true;
          state.apiCollectionEtag = response.headers.get('ETag');
          if (!collectionFolder(state.collectionSelectedFolderId)) state.collectionSelectedFolderId = 1;
          if (!collectionRequest()) state.collectionSelectedRequestId = null;
          else state.collectionSelectedFolderId = collectionRequest().folder_id;
          setCollectionNotice(body.requests.length ? 'ready' : 'empty', body.requests.length
            ? `${body.requests.length} saved ${body.requests.length === 1 ? 'request' : 'requests'} · local collection loaded.`
            : 'Create a saved request, or import a method and query-free URL from Requests.');
          return true;
        } catch (error) {
          if (version !== state.apiCollectionVersion) return false;
          state.apiCollectionEtag = null;
          setCollectionNotice('error', `Collection load failed: ${controller.signal.aborted ? 'timed out' : error.message}. The last valid collection and your edits remain visible.`);
          return false;
        } finally {
          clearTimeout(deadline);
          state.apiCollectionRefreshing = false;
          renderApiCollection();
        }
      }

      async function replaceApiCollection(folders, requests, successMessage) {
        if (state.apiCollectionSaving) return false;
        if (state.apiCollectionNeedsReload) {
          setCollectionNotice('conflict', 'Discard the stale edits and retry load before changing this collection.'); return false;
        }
        state.apiCollectionSaving = true;
        state.apiCollectionVersion += 1;
        const controller = new AbortController();
        const deadline = setTimeout(() => controller.abort(), 15000);
        setCollectionNotice('saving', 'Saving collection changes locally…');
        renderApiCollection();
        try {
          const response = await fetch('/api/api-collection/actions', {
            method: 'POST', cache: 'no-store', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(collectionReplacement(folders, requests)), signal: controller.signal
          });
          const body = await response.json();
          if (response.status === 409) {
            state.apiCollectionEtag = null;
            state.apiCollectionSaving = false;
            const refreshed = await refreshApiCollection(true);
            if (refreshed || state.apiCollectionStatus === 'saving') setCollectionNotice('conflict', `${body.error || 'The collection changed in another window.'} Your edits are retained; retry load and review them before saving again.`);
            return false;
          }
          if (!response.ok) throw new Error(body.error || `API Collection store returned ${response.status}`);
          if (!isApiCollection(body)) throw new TypeError('Malformed API Collection response');
          state.apiCollection = body;
          state.apiCollectionLoaded = true;
          state.apiCollectionEtag = `"api-collection-${body.generation}"`;
          setCollectionNotice('ready', successMessage);
          return true;
        } catch (error) {
          state.apiCollectionEtag = null;
          setCollectionNotice('error', `Save could not be confirmed: ${controller.signal.aborted ? 'timed out' : error.message}. Your edits are retained. Retry load before saving again.`);
          return false;
        } finally {
          clearTimeout(deadline);
          state.apiCollectionSaving = false;
          renderApiCollection();
        }
      }

      function collectionFolderOptions(selectedId, excludedIds = new Set()) {
        const options = state.apiCollection.folders
          .filter(folder => !excludedIds.has(folder.id))
          .sort((left, right) => collectionFolderLineage(left.id).map(item => item.name).join('/').localeCompare(
            collectionFolderLineage(right.id).map(item => item.name).join('/')
          ))
          .map(folder => {
            const option = document.createElement('option'); option.value = String(folder.id);
            option.textContent = collectionFolderLineage(folder.id).map(item => item.name).join(' / ');
            option.selected = folder.id === selectedId;
            return option;
          });
        if (selectedId && !options.some(option => option.value === String(selectedId))) {
          const unavailable = document.createElement('option'); unavailable.value = String(selectedId);
          unavailable.textContent = `Unavailable folder #${selectedId}`; unavailable.selected = true; unavailable.disabled = true;
          options.push(unavailable);
        }
        return options;
      }

      function collectionMayLeaveDraft() {
        if (state.apiCollectionSaving) return false;
        if (!state.apiCollectionLoaded) { setCollectionNotice('error', 'Load the local collection before changing it.'); return false; }
        if (state.apiCollectionNeedsReload) { setCollectionNotice('conflict', 'Discard stale edits and retry load before changing the selected item.'); return false; }
        if (state.collectionDraftDirty || state.collectionFolderDirty) {
          setCollectionNotice('conflict', 'Unsaved edits remain with the selected item. Save or discard them before switching, creating, duplicating or deleting.');
          return false;
        }
        return true;
      }

      function selectCollectionFolder(folderId, focus = false) {
        if (!collectionFolder(folderId)) return false;
        if (folderId === state.collectionSelectedFolderId && state.collectionSelectedRequestId === null) return true;
        if (!collectionMayLeaveDraft()) return false;
        state.collectionSelectedFolderId = folderId;
        state.collectionSelectedRequestId = null;
        state.collectionFolderDraftId = null;
        state.collectionDeleteFolderId = null;
        state.collectionSelectionVersion += 1;
        renderApiCollection();
        if (focus) elements.collectionTree.querySelector(`[data-folder-id="${folderId}"]`)?.focus({preventScroll: true});
        return true;
      }

      function selectCollectionRequest(requestId, focus = false) {
        const request = collectionRequest(requestId);
        if (!request) return false;
        if (requestId === state.collectionSelectedRequestId) return true;
        if (!collectionMayLeaveDraft()) return false;
        state.collectionSelectedRequestId = requestId;
        state.collectionSelectedFolderId = request.folder_id;
        collectionFolderLineage(request.folder_id).forEach(folder => state.collectionExpandedFolderIds.add(folder.id));
        state.collectionRequestDraftId = null;
        state.collectionDeleteRequestId = null;
        state.collectionSelectedHistoryId = null;
        state.collectionSelectionVersion += 1;
        renderApiCollection();
        if (focus) elements.collectionTree.querySelector(`[data-request-id="${requestId}"]`)?.focus({preventScroll: true});
        return true;
      }

      function moveCollectionTreeSelection(event) {
        if (!['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
        const row = event.currentTarget;
        const rows = [...elements.collectionTree.querySelectorAll('.collection-tree-row')];
        const index = rows.indexOf(row);
        if (index < 0) return;
        event.preventDefault();
        if (['ArrowLeft', 'ArrowRight'].includes(event.key)) {
          const folderId = Number(row.dataset.folderId);
          if (!folderId) {
            if (event.key === 'ArrowLeft') selectCollectionFolder(collectionRequest(Number(row.dataset.requestId))?.folder_id, true);
            return;
          }
          const expanded = folderId === 1 || state.collectionExpandedFolderIds.has(folderId);
          if (event.key === 'ArrowRight' && !expanded) state.collectionExpandedFolderIds.add(folderId);
          else if (event.key === 'ArrowLeft' && expanded && folderId !== 1) state.collectionExpandedFolderIds.delete(folderId);
          else if (event.key === 'ArrowLeft') {
            selectCollectionFolder(collectionFolder(folderId)?.parent_id, true); return;
          } else if (rows[index + 1]) { rows[index + 1].focus(); return; }
          renderCollectionTree();
          elements.collectionTree.querySelector(`[data-folder-id="${folderId}"]`)?.focus();
          return;
        }
        const next = event.key === 'Home' ? 0 : event.key === 'End' ? rows.length - 1
          : Math.max(0, Math.min(rows.length - 1, index + (event.key === 'ArrowDown' ? 1 : -1)));
        const target = rows[next];
        if (target.dataset.requestId) selectCollectionRequest(Number(target.dataset.requestId), true);
        else selectCollectionFolder(Number(target.dataset.folderId), true);
      }

      function selectCollectionContent(tab, response = false, focus = false) {
        const allowed = response ? ['body', 'headers'] : ['headers', 'body', 'variables'];
        if (!allowed.includes(tab)) return;
        state[response ? 'collectionResponseTab' : 'collectionRequestTab'] = tab;
        const attribute = response ? 'collection-response-tab' : 'collection-tab';
        document.querySelectorAll(`[data-${attribute}]`).forEach(button => {
          const selected = button.getAttribute(`data-${attribute}`) === tab;
          button.setAttribute('aria-selected', String(selected)); button.tabIndex = selected ? 0 : -1;
          if (!response) document.getElementById(button.getAttribute('aria-controls')).hidden = !selected;
          if (selected && focus) button.focus({preventScroll: true});
        });
        if (response) {

        }
      }

      function renderCollectionTree() {
        const focused = elements.collectionTree.contains(document.activeElement) ? document.activeElement?.dataset : null;
        const scrollTop = elements.collectionTree.scrollTop;
        const rows = [];
        const appendFolder = (folder, level) => {
          const children = state.apiCollection.folders.filter(candidate => candidate.parent_id === folder.id)
            .sort((left, right) => left.name.localeCompare(right.name));
          const requests = state.apiCollection.requests.filter(request => request.folder_id === folder.id)
            .sort((left, right) => left.name.localeCompare(right.name));
          const hasChildren = children.length > 0 || requests.length > 0;
          const expanded = folder.id === 1 || state.collectionExpandedFolderIds.has(folder.id);
          const row = document.createElement('button'); row.type = 'button'; row.className = 'collection-tree-row';
          row.disabled = state.apiCollectionSaving;
          row.title = collectionFolderLineage(folder.id).map(item => item.name).join(' / ');
          row.dataset.folderId = String(folder.id); row.style.setProperty('--collection-depth', String(level - 1));
          row.setAttribute('role', 'treeitem'); row.setAttribute('aria-level', String(level));
          row.setAttribute('aria-selected', String(!state.collectionSelectedRequestId && state.collectionSelectedFolderId === folder.id));
          if (hasChildren) row.setAttribute('aria-expanded', String(expanded));
          row.tabIndex = !state.collectionSelectedRequestId && state.collectionSelectedFolderId === folder.id ? 0 : -1;
          row.append(textElement('span', 'collection-tree-glyph', hasChildren ? expanded ? '▾' : '▸' : '·'),
            textElement('span', 'collection-tree-name', folder.name),
            textElement('span', 'collection-tree-meta', `${requests.length}`));
          row.addEventListener('click', () => selectCollectionFolder(folder.id, true));
          row.addEventListener('dblclick', () => { if (!state.apiCollectionSaving && hasChildren && folder.id !== 1) {
            if (expanded) state.collectionExpandedFolderIds.delete(folder.id); else state.collectionExpandedFolderIds.add(folder.id);
            renderApiCollection();
          }});
          row.addEventListener('keydown', moveCollectionTreeSelection);
          rows.push(row);
          if (!expanded) return;
          children.forEach(child => appendFolder(child, level + 1));
          requests.forEach(request => {
            const requestRow = document.createElement('button'); requestRow.type = 'button'; requestRow.className = 'collection-tree-row';
            requestRow.disabled = state.apiCollectionSaving;
            requestRow.title = `${request.name} · ${request.method} ${request.url}`;
            requestRow.dataset.requestId = String(request.id); requestRow.style.setProperty('--collection-depth', String(level));
            requestRow.setAttribute('role', 'treeitem'); requestRow.setAttribute('aria-level', String(level + 1));
            requestRow.setAttribute('aria-selected', String(state.collectionSelectedRequestId === request.id));
            requestRow.tabIndex = state.collectionSelectedRequestId === request.id ? 0 : -1;
            requestRow.append(textElement('span', 'collection-tree-glyph', '↗'),
              textElement('span', 'collection-tree-name', request.name),
              textElement('span', 'collection-tree-meta', request.method));
            requestRow.addEventListener('click', () => selectCollectionRequest(request.id, true));
            requestRow.addEventListener('keydown', moveCollectionTreeSelection);
            rows.push(requestRow);
          });
        };
        appendFolder(collectionFolder(1), 1);
        elements.collectionTree.replaceChildren(...rows);
        elements.collectionTree.scrollTop = scrollTop;
        if (focused?.requestId) elements.collectionTree.querySelector(`[data-request-id="${focused.requestId}"]`)?.focus({preventScroll: true});
        else if (focused?.folderId) elements.collectionTree.querySelector(`[data-folder-id="${focused.folderId}"]`)?.focus({preventScroll: true});
      }

      function renderCollectionFolderForm() {
        const folder = collectionFolder(state.collectionFolderDirty ? state.collectionFolderDraftId : state.collectionSelectedFolderId) ?? collectionFolder(1);
        const keepDraft = state.collectionFolderDraftId === folder.id && state.collectionFolderDirty;
        const parentId = keepDraft ? Number(elements.collectionFolderParent.value) : folder.parent_id ?? 1;
        if (!keepDraft) {
          state.collectionFolderDraftId = folder.id;
          elements.collectionFolderName.value = folder.name;
          elements.collectionFolderVariables.value = collectionVariablesText(folder.variables);
        }
        const excluded = collectionDescendantIds(folder.id); excluded.add(folder.id);
        elements.collectionFolderParent.replaceChildren(...collectionFolderOptions(parentId, excluded));
        elements.collectionFolderParent.value = String(parentId);
        const root = folder.id === 1;
        elements.collectionFolderName.disabled = root || state.apiCollectionSaving;
        elements.collectionFolderParent.disabled = root || state.apiCollectionSaving;
        elements.collectionFolderVariables.disabled = state.apiCollectionSaving;
        elements.collectionSaveFolder.disabled = state.apiCollectionSaving || state.apiCollectionNeedsReload;
        elements.collectionDiscardFolder.disabled = state.apiCollectionSaving || !state.collectionFolderDirty;
        elements.collectionFolderDraftStatus.textContent = state.collectionFolderDirty ? `· ${folder.name} · Unsaved` : '';
        elements.collectionDeleteFolder.disabled = root || state.apiCollectionSaving;
        elements.collectionDeleteFolder.textContent = state.collectionDeleteFolderId === folder.id ? 'Confirm delete' : 'Delete folder';
      }

      function renderCollectionVariableStatus() {
        const request = collectionRequest();
        if (!request) return;
        const scopes = new Map();
        let invalid = false;
        collectionFolderLineage(Number(elements.collectionRequestFolder.value) || request.folder_id).forEach(folder =>
          folder.variables.forEach(variable => scopes.set(variable.name, {value: variable.value, scope: 'folder'})));
        try {
          collectionVariablesFromText(elements.collectionRequestVariables.value, 'Request variables')
            .forEach(variable => scopes.set(variable.name, {value: variable.value, scope: 'request'}));
        } catch { invalid = true; }
        const source = [elements.collectionRequestUrl.value, elements.collectionRequestMethod.value,
          elements.collectionRequestHeaders.value, elements.collectionRequestBody.value].join('\n');
        const names = new Set();
        for (const match of source.matchAll(/\{\{(=)?([^{}]+)\}\}/g)) if (!match[1]) names.add(match[2]);
        const chips = [];
        if (invalid) {
          const chip = textElement('span', 'collection-variable-chip', 'Invalid request variable JSON');
          chip.dataset.kind = 'missing'; chips.push(chip);
        }
        [...names].sort().forEach(name => {
          const resolution = scopes.get(name);
          const chip = textElement('span', 'collection-variable-chip', resolution
            ? `${resolution.scope} · {{${name}}}` : `missing · {{${name}}}`);
          if (resolution) chip.dataset.scope = resolution.scope; else chip.dataset.kind = 'missing';
          chips.push(chip);
        });
        if (!chips.length) chips.push(textElement('span', 'collection-variable-chip', 'No variables used'));
        elements.collectionVariableStatus.replaceChildren(...chips);
      }

      function renderCollectionRequestForm() {
        const request = collectionRequest();
        elements.collectionEditorEmpty.hidden = Boolean(request);
        elements.collectionRequestForm.hidden = !request;
        elements.collectionRequestBadge.dataset.kind = request ? '' : 'offline';
        elements.collectionRequestBadge.textContent = request ? `#${request.id}` : 'No request';
        elements.collectionEditorTitle.textContent = request?.name ?? 'Request';
        elements.collectionDraftStatus.textContent = !request ? 'Select a saved request to edit.' : state.collectionDraftDirty
          ? 'Unsaved edits · Save or discard before switching.' : `${collectionFolderLineage(request.folder_id).map(folder => folder.name).join(' / ')} · Saved`;
        if (!request) return;
        const keepDraft = state.collectionRequestDraftId === request.id &&
          state.collectionRequestDraftCreatedAt === request.created_at_ms && state.collectionDraftDirty;
        const folderId = keepDraft ? Number(elements.collectionRequestFolder.value) : request.folder_id;
        if (!keepDraft) {
          state.collectionRequestDraftId = request.id;
          state.collectionRequestDraftCreatedAt = request.created_at_ms;
          elements.collectionRequestName.value = request.name;
          elements.collectionRequestFolder.value = String(request.folder_id);
          elements.collectionRequestUrl.value = request.url;
          elements.collectionRequestMethod.value = request.method;
          elements.collectionRequestTimeout.value = String(request.timeout_ms);

          elements.collectionRequestBody.value = request.body;
          elements.collectionRequestVariables.value = collectionVariablesText(request.variables);
        }
        elements.collectionRequestFolder.replaceChildren(...collectionFolderOptions(folderId));
        elements.collectionRequestFolder.value = String(folderId);
        elements.collectionRequestForm.querySelectorAll('input, textarea, select').forEach(field => {
          field.disabled = state.apiCollectionSaving;
        });
        elements.collectionSaveRequest.disabled = state.apiCollectionSaving || state.apiCollectionNeedsReload;
        elements.collectionDiscardRequest.disabled = state.apiCollectionSaving || !state.collectionDraftDirty;
        elements.collectionDuplicateRequest.disabled = state.apiCollectionSaving || state.apiCollection.requests.length >= 128;
        elements.collectionDeleteRequest.disabled = state.apiCollectionSaving;
        elements.collectionDeleteRequest.textContent = state.collectionDeleteRequestId === request.id ? 'Confirm delete' : 'Delete request';
        renderCollectionVariableStatus();
      }

      function renderApiCollection() {
        if (!elements.collectionTree) return;
        const firstUse = state.apiCollection.requests.length === 0 && state.apiCollection.folders.length === 1;
        elements.collectionEditorEmpty.parentElement?.parentElement?.setAttribute('data-state', firstUse ? 'empty' : 'ready');
        if (state.apiCollectionLoaded && state.apiCollectionStatus === 'loading') {
          state.apiCollectionStatus = state.apiCollection.requests.length ? 'ready' : 'empty';
          state.apiCollectionMessage = state.apiCollection.requests.length
            ? `${state.apiCollection.requests.length} saved ${state.apiCollection.requests.length === 1 ? 'request' : 'requests'} loaded from the permission-restricted local store.`
            : 'Start by creating a saved request or importing one from Traffic.';
        }

        elements.collectionCount.textContent = `${state.apiCollection.requests.length} / 128`;
        elements.collectionNewFolder.disabled = !state.apiCollectionLoaded || state.apiCollectionNeedsReload || state.apiCollectionSaving || state.apiCollection.folders.length >= 32 ||
          collectionFolderDepth(state.collectionSelectedFolderId) >= 4;
        elements.collectionNewRequest.disabled = !state.apiCollectionLoaded || state.apiCollectionNeedsReload || state.apiCollectionSaving || state.apiCollection.requests.length >= 128;
        elements.collectionNotice.dataset.kind = state.apiCollectionStatus;
        elements.collectionNotice.textContent = state.apiCollectionMessage;
        elements.collectionRetry.hidden = !['error', 'conflict'].includes(state.apiCollectionStatus);
        elements.collectionRetry.disabled = state.apiCollectionRefreshing || state.apiCollectionSaving;
        renderCollectionTree();
        renderCollectionFolderForm();
        renderCollectionRequestForm();

      }

      async function createCollectionFolder() {
        if (!collectionMayLeaveDraft()) return;
        const name = elements.collectionNewFolderName.value.trim();
        if (!name) { setCollectionNotice('error', 'Enter a folder name.'); return; }
        const parentId = state.collectionSelectedFolderId;
        const folder = {id: collectionNextId(state.apiCollection.folders), name, parent_id: parentId, variables: []};
        if (await replaceApiCollection([...state.apiCollection.folders, folder], state.apiCollection.requests, `Folder “${name}” created.`)) {
          selectCollectionFolder(folder.id);
          state.collectionExpandedFolderIds.add(parentId);
          elements.collectionNewFolderForm.hidden = true;
          elements.collectionNewFolderName.value = '';
          renderApiCollection();
        }
      }

      async function saveCollectionFolder() {
        const folder = collectionFolder(state.collectionFolderDraftId);
        if (!folder) return;
        try {
          const replacement = {
            ...folder,
            name: folder.id === 1 ? folder.name : elements.collectionFolderName.value.trim(),
            parent_id: folder.id === 1 ? null : Number(elements.collectionFolderParent.value),
            variables: collectionVariablesFromText(elements.collectionFolderVariables.value, 'Folder variables')
          };
          const folders = state.apiCollection.folders.map(candidate => candidate.id === folder.id ? replacement : candidate);
          if (await replaceApiCollection(folders, state.apiCollection.requests, `Folder “${replacement.name}” saved.`)) {
            state.collectionFolderDirty = false;
            state.collectionExpandedFolderIds.add(replacement.parent_id ?? 1);
            renderApiCollection();
          }
        } catch (error) { setCollectionNotice('error', error.message); renderApiCollection(); }
      }

      async function saveCollectionRequest() {
        try {
          const request = collectionRequest();
          const draft = collectionRequestDraft();
          if (state.collectionFolderDirty && draft.folder_id !== state.collectionFolderDraftId) {
            setCollectionNotice('conflict', 'Save or discard the current folder edits before moving this request.');
            return false;
          }
          const requests = state.apiCollection.requests.map(candidate => candidate.id === request.id ? draft : candidate);
          if (await replaceApiCollection(state.apiCollection.folders, requests, `Request “${draft.name}” saved.`)) {
            state.collectionSelectedFolderId = draft.folder_id;
            state.collectionDraftDirty = false;
            state.collectionRequestDraftId = null;
            state.collectionExpandedFolderIds.add(draft.folder_id);
            renderApiCollection();
            return true;
          }
        } catch (error) { setCollectionNotice('error', error.message); renderApiCollection(); }
        return false;
      }

      async function createCollectionRequest(template = null, {focus = true} = {}) {
        if (!collectionMayLeaveDraft()) return null;
        const folderId = state.collectionSelectedFolderId;
        const base = template?.name || 'New request';
        const siblingNames = new Set(state.apiCollection.requests.filter(request => request.folder_id === folderId)
          .map(request => request.name.toLocaleLowerCase()));
        let name = base;
        for (let suffix = 2; siblingNames.has(name.toLocaleLowerCase()); suffix += 1) name = `${base} ${suffix}`;
        const request = {
          id: collectionNextRequestId(), folder_id: folderId, name,
          url: template?.url || 'https://example.test/', method: template?.method || 'GET', headers: [], body: '',
          timeout_ms: 15000, variables: []
        };
        if (await replaceApiCollection(state.apiCollection.folders, [...state.apiCollection.requests, request], `Request “${name}” created.`)) {
          state.collectionSelectionVersion += 1;
          state.collectionSelectedRequestId = request.id;
          state.collectionExpandedFolderIds.add(folderId);
          state.collectionRequestDraftId = null;
          state.collectionDraftDirty = false;
          renderApiCollection();
          if (focus) requestAnimationFrame(() => elements.collectionRequestName.focus({preventScroll: true}));
          return request.id;
        }
        return null;
      }

      async function duplicateCollectionRequest() {
        if (!collectionMayLeaveDraft()) return;
        const source = collectionRequest();
        if (!source) return;
        const id = collectionNextRequestId();
        const siblingNames = new Set(state.apiCollection.requests.filter(request => request.folder_id === source.folder_id)
          .map(request => request.name.toLocaleLowerCase()));
        let name = `${source.name} copy`;
        for (let suffix = 2; siblingNames.has(name.toLocaleLowerCase()); suffix += 1) name = `${source.name} copy ${suffix}`;
        const duplicate = {...source, id, name};
        delete duplicate.created_at_ms; delete duplicate.updated_at_ms;
        if (await replaceApiCollection(state.apiCollection.folders, [...state.apiCollection.requests, duplicate], `Request “${name}” duplicated.`)) {
          state.collectionSelectionVersion += 1;
          state.collectionSelectedRequestId = id; state.collectionRequestDraftId = null; state.collectionDraftDirty = false;
          renderApiCollection();
        }
      }

      async function deleteCollectionRequest() {
        if (!collectionMayLeaveDraft()) return;
        const request = collectionRequest();
        if (!request) return;
        if (state.collectionDeleteRequestId !== request.id) {
          state.collectionDeleteRequestId = request.id; setCollectionNotice('ready', 'Select Delete again to remove this saved request.');
          renderApiCollection(); return;
        }
        if (await replaceApiCollection(state.apiCollection.folders,
          state.apiCollection.requests.filter(candidate => candidate.id !== request.id), `Request “${request.name}” deleted.`)) {
          state.collectionSelectionVersion += 1;
          state.collectionSelectedRequestId = null; state.collectionDeleteRequestId = null;
          state.collectionRequestDraftId = null; state.collectionDraftDirty = false;
          renderApiCollection();
        }
      }

      async function deleteCollectionFolder() {
        if (!collectionMayLeaveDraft()) return;
        const folder = collectionFolder(state.collectionSelectedFolderId);
        if (!folder || folder.id === 1) return;
        const hasContents = state.apiCollection.folders.some(candidate => candidate.parent_id === folder.id) ||
          state.apiCollection.requests.some(request => request.folder_id === folder.id);
        if (hasContents) { setCollectionNotice('error', 'Move or delete this folder’s contents first.'); renderApiCollection(); return; }
        if (state.collectionDeleteFolderId !== folder.id) {
          state.collectionDeleteFolderId = folder.id; setCollectionNotice('ready', 'Select Delete folder again to confirm.');
          renderApiCollection(); return;
        }
        if (await replaceApiCollection(state.apiCollection.folders.filter(candidate => candidate.id !== folder.id),
          state.apiCollection.requests, `Folder “${folder.name}” deleted.`)) {
          state.collectionSelectedFolderId = folder.parent_id ?? 1; state.collectionDeleteFolderId = null;
          state.collectionFolderDraftId = null; state.collectionFolderDirty = false; renderApiCollection();
        }
      }

      const analystExactKeys = (value, keys) => isPlainObject(value) &&
        Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));

      // Accept legacy results and only the bounded failure annotation this API emits.
      function resultHasOptionalReason(value, keys, code, phase = null) {
        const annotated = isPlainObject(value) && (Object.hasOwn(value, 'code') || Object.hasOwn(value, 'details'));
        if (!annotated) return analystExactKeys(value, keys);
        return value.ok === false && value.code === code &&
          analystExactKeys(value, [...keys, 'code', 'details']) &&
          analystExactKeys(value.details, phase === null ? [] : ['phase']) &&
          (phase === null || value.details.phase === phase);
      }

      function isLocalAnalystWorkspace(workspace) {
        const expectedLimits = emptyLocalAnalystWorkspace().limits;
        if (!analystExactKeys(workspace, ['contract_version', 'document_kind', 'generation', 'updated_at_ms',
          'folders', 'files', 'limits']) || workspace.contract_version !== 1 ||
          workspace.document_kind !== 'local-analyst-workspace' ||
          !isSafeIntegerInRange(workspace.generation, 0, Number.MAX_SAFE_INTEGER) ||
          !isSafeIntegerInRange(workspace.updated_at_ms, 0, Number.MAX_SAFE_INTEGER) ||
          !isPlainObject(workspace.limits) || Object.keys(workspace.limits).length !== Object.keys(expectedLimits).length ||
          Object.keys(expectedLimits).some(key => workspace.limits[key] !== expectedLimits[key]) ||
          !Array.isArray(workspace.folders) || workspace.folders.length < 1 || workspace.folders.length > 32 ||
          !Array.isArray(workspace.files) || workspace.files.length > 64) return false;
        const validName = name => isBoundedText(name, 128) && name.trim() === name && name.length > 0 &&
          !name.includes('/') && !/[\x00-\x1f\x7f]/u.test(name);
        const folders = new Map();
        for (const folder of workspace.folders) {
          if (!analystExactKeys(folder, ['id', 'name', 'parent_id']) ||
            !isSafeIntegerInRange(folder.id, 1, Number.MAX_SAFE_INTEGER) || folders.has(folder.id) ||
            !validName(folder.name) || (folder.parent_id !== null &&
              !isSafeIntegerInRange(folder.parent_id, 1, Number.MAX_SAFE_INTEGER))) return false;
          folders.set(folder.id, folder);
        }
        const root = folders.get(1);
        if (!root || root.name !== 'Analyst Workspace' || root.parent_id !== null ||
          [...folders.values()].some(folder => folder.id !== 1 && folder.parent_id === null)) return false;
        for (const folder of folders.values()) {
          const seen = new Set([folder.id]);
          let current = folder;
          let depth = 0;
          while (current.parent_id !== null) {
            if (seen.has(current.parent_id) || !folders.has(current.parent_id) || ++depth > 4) return false;
            seen.add(current.parent_id);
            current = folders.get(current.parent_id);
          }
        }
        const siblingNames = new Set();
        for (const folder of folders.values()) {
          const key = `${folder.parent_id ?? 'root'}\u0000${folder.name.toLocaleLowerCase()}`;
          if (siblingNames.has(key)) return false;
          siblingNames.add(key);
        }
        const fileIds = new Set();
        let totalBytes = 0;
        for (const file of workspace.files) {
          if (!analystExactKeys(file, ['id', 'folder_id', 'name', 'kind', 'language', 'content',
            'content_bytes', 'created_at_ms', 'updated_at_ms']) ||
            !isSafeIntegerInRange(file.id, 1, Number.MAX_SAFE_INTEGER) || fileIds.has(file.id) ||
            !folders.has(file.folder_id) || !validName(file.name) ||
            !['analyst-script', 'scratchpad'].includes(file.kind) ||
            !['javascript', 'json', 'markdown', 'text'].includes(file.language) ||
            (file.kind === 'analyst-script' && file.language !== 'javascript') ||
            !isBoundedText(file.content, 32 * 1024) || /[\x00-\x08\x0b\x0c\x0e-\x1f]/u.test(file.content) ||
            file.content_bytes !== utf8ByteLength(file.content) ||
            !isSafeIntegerInRange(file.created_at_ms, 0, Number.MAX_SAFE_INTEGER) ||
            !isSafeIntegerInRange(file.updated_at_ms, file.created_at_ms, Number.MAX_SAFE_INTEGER)) return false;
          const key = `${file.folder_id}\u0000${file.name.toLocaleLowerCase()}`;
          if (siblingNames.has(key)) return false;
          siblingNames.add(key);
          fileIds.add(file.id);
          totalBytes += file.content_bytes;
        }
        if (totalBytes > 512 * 1024) return false;
        return workspace.generation !== 0 || (workspace.updated_at_ms === 0 && workspace.files.length === 0 &&
          workspace.folders.length === 1);
      }

      function isLocalAnalystRunner(runner) {
        const limits = emptyLocalAnalystWorkspace().limits;
        return analystExactKeys(runner, ['protocol_version', 'available', 'active_run_id', 'limits']) &&
          runner.protocol_version === 1 && typeof runner.available === 'boolean' &&
          (runner.active_run_id === null || isSafeIntegerInRange(runner.active_run_id, 1, Number.MAX_SAFE_INTEGER)) &&
          isPlainObject(runner.limits) && Object.keys(runner.limits).length === Object.keys(limits).length &&
          Object.keys(limits).every(key => runner.limits[key] === limits[key]);
      }

      function isLocalAnalystResult(result, run) {
        const code = result?.outcome === 'cancelled' ? 'cancelled' : result?.outcome === 'timed_out' ? 'timeout' : 'application_failed';
        if (!resultHasOptionalReason(result, ['protocol_version', 'run_id', 'script_id', 'library_generation', 'ok',
          'outcome', 'result_type', 'result_text', 'result_truncated', 'logs', 'logs_truncated',
          'duration_ms', 'error'], code, 'worker') || result.protocol_version !== 1 || result.run_id !== run.run_id ||
          result.script_id !== run.script_id || result.library_generation !== run.library_generation ||
          typeof result.ok !== 'boolean' || !['completed', 'failed', 'cancelled', 'timed_out'].includes(result.outcome) ||
          result.ok !== (result.outcome === 'completed') || !isBoundedText(result.result_type, 64) ||
          !isBoundedText(result.result_text, 32 * 1024) || typeof result.result_truncated !== 'boolean' ||
          !Array.isArray(result.logs) || result.logs.length > 64 || typeof result.logs_truncated !== 'boolean' ||
          !isSafeIntegerInRange(result.duration_ms, 0, 7000) || !isBoundedText(result.error, 512) ||
          (result.ok ? result.error.length !== 0 : result.error.length === 0)) return false;
        return result.logs.every(log => analystExactKeys(log, ['level', 'text']) &&
          ['log', 'info', 'warn', 'error'].includes(log.level) && isBoundedText(log.text, 1024));
      }

      function analystFolder(folderId = state.analystSelectedFolderId) {
        return state.localAnalyst.folders.find(folder => folder.id === folderId) ?? null;
      }

      function analystFile(fileId = state.analystSelectedFileId) {
        return state.localAnalyst.files.find(file => file.id === fileId) ?? null;
      }

      function analystFolderLineage(folderId) {
        const lineage = [];
        const seen = new Set();
        let folder = analystFolder(folderId);
        while (folder && !seen.has(folder.id)) {
          lineage.unshift(folder);
          seen.add(folder.id);
          folder = folder.parent_id === null ? null : analystFolder(folder.parent_id);
        }
        return lineage;
      }

      function analystFolderDepth(folderId) {
        return Math.max(0, analystFolderLineage(folderId).length - 1);
      }

      function analystDescendantIds(folderId) {
        const descendants = new Set();
        const visit = parentId => state.localAnalyst.folders
          .filter(folder => folder.parent_id === parentId)
          .forEach(folder => { descendants.add(folder.id); visit(folder.id); });
        visit(folderId);
        return descendants;
      }

      function analystNextId(values) {
        return values.reduce((maximum, value) => Math.max(maximum, value.id), 0) + 1;
      }

      function analystUniqueName(folderId, base) {
        const names = new Set([
          ...state.localAnalyst.folders.filter(folder => folder.parent_id === folderId).map(folder => folder.name.toLocaleLowerCase()),
          ...state.localAnalyst.files.filter(file => file.folder_id === folderId).map(file => file.name.toLocaleLowerCase())
        ]);
        let name = base;
        for (let suffix = 2; names.has(name.toLocaleLowerCase()); suffix += 1) name = `${base} ${suffix}`;
        return name;
      }

      function setAnalystNotice(kind, message) {
        state.localAnalystNoticeRevision = (state.localAnalystNoticeRevision ?? 0) + 1;
        state.localAnalystStatus = kind;
        state.localAnalystMessage = message;
        analystElements.notice.dataset.kind = kind;
        analystElements.notice.textContent = message;
      }

      function analystReplacement(folders = state.localAnalyst.folders, files = state.localAnalyst.files) {
        return {
          action: 'replace_local_analyst_workspace',
          expected_generation: state.localAnalyst.generation,
          folders: folders.map(folder => ({id: folder.id, name: folder.name, parent_id: folder.parent_id})),
          files: files.map(file => ({
            id: file.id, folder_id: file.folder_id, name: file.name, kind: file.kind,
            language: file.language, content: file.content
          }))
        };
      }

      function analystFileInput(file) {
        return file ? {id: file.id, folder_id: file.folder_id, name: file.name, kind: file.kind,
          language: file.language, content: file.content} : null;
      }

      function analystWorkspaceContents(workspace) {
        return JSON.stringify({
          folders: workspace.folders.map(folder => ({id: folder.id, name: folder.name, parent_id: folder.parent_id}))
            .sort((left, right) => left.id - right.id),
          files: workspace.files.map(analystFileInput).sort((left, right) => left.id - right.id)
        });
      }

      function analystFileDraft() {
        const file = analystFile();
        return file ? {...analystFileInput(file), folder_id: Number(analystElements.folder.value),
          name: analystElements.name.value.trim(), kind: analystElements.kind.value,
          language: analystElements.kind.value === 'analyst-script' ? 'javascript' : analystElements.language.value,
          content: analystElements.content.value} : null;
      }

      function analystFolderDraft() {
        const folder = analystFolder();
        return folder ? {...folder, name: analystElements.folderName.value.trim(),
          parent_id: folder.id === 1 ? null : Number(analystElements.folderParent.value)} : null;
      }

      function analystHasUnsavedWork() {
        return state.analystDraftDirty || state.analystFolderDirty || state.localAnalystSaving ||
          Boolean(state.localAnalystPendingSave);
      }

      function guardAnalystUnload(event) {
        if (!analystHasUnsavedWork()) return;
        event.preventDefault();
        event.returnValue = '';
      }

      // A deadline covers both headers and bounded body reads, even if transport
      // cancellation cannot stop a server commit. Such writes must be reconciled.
      async function analystReadJSON(path, options = {}) {
        const controller = new AbortController();
        let timer;
        const deadline = new Promise((_, reject) => {
          timer = setTimeout(() => { controller.abort(); reject(new Error('timed out')); }, 15000);
        });
        try {
          return await Promise.race([deadline, (async () => {
            const response = await fetch(path, {...options, signal: controller.signal});
            if (response.status === 304) return {response, body: null};
            const bytes = await sourceFactsReadBytes(response, 4 * 1024 * 1024, controller.signal);
            return {response, body: JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes))};
          })()]);
        } finally { clearTimeout(timer); }
      }

      function admitAnalystWorkspace(body, confirmed = false) {
        if (body.generation < state.localAnalyst.generation) throw new Error('An older workspace generation was returned');
        const file = body.files.find(item => item.id === state.analystSelectedFileId);
        const folder = body.folders.find(item => item.id === state.analystSelectedFolderId);
        const savedFileDraft = confirmed && state.analystDraftDirty &&
          JSON.stringify(analystFileDraft()) === JSON.stringify(analystFileInput(file));
        const savedFolderDraft = confirmed && state.analystFolderDirty &&
          JSON.stringify(analystFolderDraft()) === JSON.stringify(folder);
        const changedFile = state.analystDraftDirty && !savedFileDraft && (!file ||
          file.created_at_ms !== state.analystDraftBase?.created_at_ms ||
          JSON.stringify(analystFileInput(file)) !== JSON.stringify(analystFileInput(state.analystDraftBase)));
        const changedFolder = state.analystFolderDirty && !savedFolderDraft && JSON.stringify(folder) !== JSON.stringify(state.analystFolderBase);
        if (changedFile || changedFolder) {
          state.localAnalystNeedsReload = true;
          state.localAnalystEtag = null;
          setAnalystNotice('conflict', 'The edited file or folder changed in another window. Your draft and its original saved version remain here. Copy any edits you need, then choose Discard changes and Retry load before saving.');
          return false;
        }
        if (savedFileDraft) state.analystDraftDirty = false;
        if (savedFolderDraft) state.analystFolderDirty = false;
        state.localAnalyst = body;
        state.localAnalystLoaded = true;
        state.localAnalystNeedsReload = false;
        state.localAnalystEtag = `"local-analyst-${body.generation}"`;
        if (!analystFolder()) state.analystSelectedFolderId = 1;
        if (!analystFile()) state.analystSelectedFileId = null;
        return true;
      }

      function reconcileAnalystSave(body) {
        const pending = state.localAnalystPendingSave;
        if (!pending) return null;
        if (body.generation < pending.request.expected_generation) throw new Error('Recovery returned an older generation');
        const contents = analystWorkspaceContents(body);
        if (contents === pending.contents && (body.generation > pending.request.expected_generation ||
            pending.contents === pending.baseContents)) {
          state.localAnalystPendingSave = null;
          const admitted = admitAnalystWorkspace(body, true);
          if (admitted) setAnalystNotice('ready', `${pending.message} Saved contents verified by reloading generation ${body.generation}.`);
          return admitted;
        }
        if (body.generation === pending.request.expected_generation && contents === pending.baseContents) {
          // A delayed original write and a deliberate retry still use this same
          // expected generation. Compare-and-swap can commit only one of them.
          state.localAnalystPendingSave = null;
          const admitted = admitAnalystWorkspace(body);
          if (admitted) setAnalystNotice('error', `Save could not be confirmed: ${pending.reason || 'acknowledgement unavailable'}. Reload still shows the original generation; your draft is retained. An explicit retry will use the same generation check.`);
          return false;
        }
        state.localAnalystPendingSave = null;
        state.localAnalystNeedsReload = true;
        state.localAnalystEtag = null;
        setAnalystNotice('conflict', 'The workspace changed while this save was unconfirmed. Your draft and its original saved version remain here. Copy any edits you need, then discard changes and Retry load. Nothing was retried.');
        return false;
      }

      async function refreshLocalAnalyst(force = false) {
        if (state.localAnalystRefreshing || state.localAnalystSaving || location.protocol === 'file:') return false;
        state.localAnalystRefreshing = true;
        const version = state.localAnalystVersion;
        if (!state.localAnalystLoaded) setAnalystNotice('loading', 'Loading the local analyst workspace…');
        const noticeRevision = state.localAnalystNoticeRevision ?? 0;
        let loaded = false;
        try {
          try {
            const headers = !force && !state.localAnalystPendingSave && !state.localAnalystNeedsReload && state.localAnalystEtag
              ? {'If-None-Match': state.localAnalystEtag} : {};
            const {response, body} = await analystReadJSON('/api/local-analyst', {cache: 'no-store', headers});
            if (version !== state.localAnalystVersion) return false;
            if (response.status === 304) {
              if (!headers['If-None-Match']) throw new Error('Recovery returned no workspace contents');
              loaded = true;
            } else {
              if (!response.ok) throw new Error(`Analyst workspace store returned ${response.status}`);
              if (!isLocalAnalystWorkspace(body)) throw new TypeError('Malformed analyst workspace response');
              if (state.localAnalystPendingSave) loaded = reconcileAnalystSave(body);
              else if (admitAnalystWorkspace(body)) {
                const count = body.files.length;
                // Admit fresh data, but a routine load receipt must not erase a
                // newer interaction warning. Conflicts and recovery errors above
                // still publish their actionable outcome through their own path.
                if (noticeRevision === (state.localAnalystNoticeRevision ?? 0)) {
                  setAnalystNotice(count ? 'ready' : 'empty', count
                    ? `${count} saved ${count === 1 ? 'file' : 'files'} loaded from the permission-restricted local workspace.`
                    : 'Start by saving a script or note.');
                }
                loaded = true;
              }
            }
          } catch (error) {
            if (version !== state.localAnalystVersion) return false;
            state.localAnalystEtag = null;
            setAnalystNotice('error', state.localAnalystPendingSave
              ? `Save outcome remains uncertain: ${error.message}. Your draft is retained. Retry load before another write; nothing is retried automatically.`
              : `Analyst workspace unavailable: ${error.message}. The last valid generation and your drafts remain visible.`);
          }
          if (version !== state.localAnalystVersion) return loaded;
          // The visible form and its base must follow admitted data before the
          // independent runner request yields to another user edit.
          renderLocalAnalyst();
          try {
            const {response, body: runner} = await analystReadJSON('/api/local-analyst/runner', {cache: 'no-store'});
            if (version !== state.localAnalystVersion) return loaded;
            if (!response.ok) throw new Error(`runner returned ${response.status}`);
            if (!isLocalAnalystRunner(runner)) throw new TypeError('malformed runner state');
            state.localAnalystRunner = runner;
          } catch (error) {
            if (version !== state.localAnalystVersion) return loaded;
            state.localAnalystRunner = {protocol_version: 1, available: false, active_run_id: null,
              limits: emptyLocalAnalystWorkspace().limits, error: error.message};
          }
          return loaded;
        } finally {
          state.localAnalystRefreshing = false;
          renderLocalAnalyst();
        }
      }

      async function replaceLocalAnalyst(folders, files, successMessage) {
        if (state.localAnalystSaving) return false;
        if (!state.localAnalystLoaded || state.localAnalystNeedsReload || state.localAnalystPendingSave) {
          setAnalystNotice('conflict', 'Resolve the current draft and Retry load before changing this workspace.'); return false;
        }
        const request = analystReplacement(folders, files);
        const pending = {request, contents: analystWorkspaceContents(request),
          baseContents: analystWorkspaceContents(state.localAnalyst), message: successMessage};
        state.localAnalystPendingSave = pending;
        state.localAnalystSaving = true;
        state.localAnalystVersion += 1;
        setAnalystNotice('saving', 'Saving one atomic analyst workspace generation…');
        renderLocalAnalyst();
        try {
          const {response, body} = await analystReadJSON('/api/local-analyst/actions', {
            method: 'POST', cache: 'no-store', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(request)
          });
          // A transport may replay a request after losing its acknowledgement.
          // Even a 409 can follow the first attempt's commit. Reconcile the exact
          // submitted contents instead of assuming this generation never saved.
          if (!response.ok) throw new Error(body?.error || `Analyst workspace store returned ${response.status}`);
          const expectedGeneration = pending.contents === pending.baseContents
            ? request.expected_generation : request.expected_generation + 1;
          if (!isLocalAnalystWorkspace(body) || body.generation !== expectedGeneration ||
              analystWorkspaceContents(body) !== pending.contents) throw new TypeError('The save acknowledgement did not match the submitted generation and contents');
          state.localAnalystPendingSave = null;
          if (!admitAnalystWorkspace(body, true)) return false;
          setAnalystNotice('ready', successMessage);
          return true;
        } catch (error) {
          state.localAnalystEtag = null;
          pending.reason = String(error.message).slice(0, 512);
          setAnalystNotice('error', `Save outcome is uncertain: ${pending.reason}. Your draft is retained; checking the saved generation without retrying the write…`);
          try {
            const {response, body} = await analystReadJSON('/api/local-analyst', {cache: 'no-store'});
            if (!response.ok || !isLocalAnalystWorkspace(body)) throw new Error('Recovery did not return a valid workspace');
            return reconcileAnalystSave(body);
          } catch (recoveryError) {
            setAnalystNotice('error', `Save outcome remains uncertain: ${recoveryError.message}. Your draft is retained. Retry load before another write; nothing is retried automatically.`);
            return false;
          }
        } finally {
          state.localAnalystSaving = false;
          renderLocalAnalyst();
        }
      }

      function analystMayLeaveDraft() {
        if (state.localAnalystSaving) return false;
        if (!state.localAnalystLoaded || state.localAnalystNeedsReload || state.localAnalystPendingSave) {
          setAnalystNotice('conflict', 'Resolve the current draft and Retry load before changing the selected item.'); return false;
        }
        if (state.analystDraftDirty || state.analystFolderDirty) {
          setAnalystNotice('conflict', 'Unsaved edits remain with the selected item. Save or choose Discard changes before switching, creating or deleting.');
          return false;
        }
        return true;
      }

      function discardAnalystDraft(folder = false) {
        if (state.localAnalystSaving) return;
        state[folder ? 'analystFolderDirty' : 'analystDraftDirty'] = false;
        state.analystDeleteFileId = null;
        state.analystDeleteFolderId = null;
        renderLocalAnalyst();
        (folder ? analystElements.folderName : analystElements.content).focus({preventScroll: true});
        if (state.localAnalystNeedsReload || state.localAnalystPendingSave) {
          setAnalystNotice('conflict', 'Draft changes discarded. Retry load to review the current saved workspace before editing or saving.');
        }
      }

      function selectAnalystFolder(folderId, focus = false) {
        if (!analystFolder(folderId)) return false;
        if (folderId === state.analystSelectedFolderId && state.analystSelectedFileId === null) return true;
        if (!analystMayLeaveDraft()) return false;
        state.analystSelectedFolderId = folderId;
        state.analystSelectedFileId = null;
        state.analystFolderDraftId = null;
        state.analystDeleteFolderId = null;
        renderLocalAnalyst();
        if (focus) analystElements.tree.querySelector(`[data-folder-id="${folderId}"]`)?.focus({preventScroll: true});
        return true;
      }

      function selectAnalystFile(fileId, focus = false) {
        const file = analystFile(fileId);
        if (!file) return false;
        if (fileId === state.analystSelectedFileId) return true;
        if (!analystMayLeaveDraft()) return false;
        state.analystSelectedFileId = fileId;
        state.analystSelectedFolderId = file.folder_id;
        analystFolderLineage(file.folder_id).forEach(folder => state.analystExpandedFolderIds.add(folder.id));
        state.analystDeleteFileId = null;
        renderLocalAnalyst();
        if (focus) analystElements.tree.querySelector(`[data-file-id="${fileId}"]`)?.focus({preventScroll: true});
        return true;
      }

      function moveAnalystTreeSelection(event) {
        if (!['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
        const row = event.currentTarget;
        const rows = [...analystElements.tree.querySelectorAll('.analyst-tree-row')];
        const index = rows.indexOf(row);
        if (index < 0) return;
        event.preventDefault();
        if (row.dataset.folderId && ['ArrowLeft', 'ArrowRight'].includes(event.key)) {
          const folderId = Number(row.dataset.folderId);
          const expanded = state.analystExpandedFolderIds.has(folderId);
          if (event.key === 'ArrowRight' && !expanded) state.analystExpandedFolderIds.add(folderId);
          else if (event.key === 'ArrowLeft' && expanded && folderId !== 1) state.analystExpandedFolderIds.delete(folderId);
          else if (event.key === 'ArrowLeft') {
            const parentId = analystFolder(folderId)?.parent_id;
            if (parentId !== null && parentId !== undefined) selectAnalystFolder(parentId, true);
          }
          renderLocalAnalyst();
          analystElements.tree.querySelector(`[data-folder-id="${folderId}"]`)?.focus({preventScroll: true});
          return;
        }
        const next = event.key === 'Home' ? 0 : event.key === 'End' ? rows.length - 1
          : Math.max(0, Math.min(rows.length - 1, index + (event.key === 'ArrowDown' ? 1 : -1)));
        const target = rows[next];
        if (target.dataset.fileId) selectAnalystFile(Number(target.dataset.fileId), true);
        else selectAnalystFolder(Number(target.dataset.folderId), true);
      }

      function renderAnalystTree() {
        const focused = analystElements.tree.contains(document.activeElement) ? document.activeElement?.dataset : null;
        const scrollTop = analystElements.tree.scrollTop;
        const nodes = [];
        const appendFolder = (folder, depth) => {
          const children = state.localAnalyst.folders.filter(candidate => candidate.parent_id === folder.id)
            .sort((left, right) => left.name.localeCompare(right.name));
          const files = state.localAnalyst.files.filter(file => file.folder_id === folder.id)
            .sort((left, right) => left.name.localeCompare(right.name));
          const expanded = state.analystExpandedFolderIds.has(folder.id);
          const row = document.createElement('button'); row.type = 'button'; row.className = 'analyst-tree-row';
          row.dataset.folderId = String(folder.id); row.style.setProperty('--analyst-depth', String(depth));
          row.setAttribute('role', 'treeitem'); row.setAttribute('aria-level', String(depth + 1));
          row.setAttribute('aria-expanded', String(expanded));
          row.setAttribute('aria-selected', String(state.analystSelectedFileId === null && state.analystSelectedFolderId === folder.id));
          row.append(textElement('span', 'analyst-tree-glyph', expanded ? '▾' : '▸'),
            textElement('span', 'analyst-tree-name', folder.name),
            textElement('span', 'analyst-tree-meta', String(children.length + files.length)));
          row.addEventListener('click', () => {
            const alreadySelected = state.analystSelectedFileId === null && state.analystSelectedFolderId === folder.id;
            if (!selectAnalystFolder(folder.id)) return;
            if (alreadySelected && folder.id !== 1) {
              if (expanded) state.analystExpandedFolderIds.delete(folder.id); else state.analystExpandedFolderIds.add(folder.id);
            } else state.analystExpandedFolderIds.add(folder.id);
            renderLocalAnalyst();
          });
          row.addEventListener('keydown', moveAnalystTreeSelection);
          nodes.push(row);
          if (!expanded) return;
          children.forEach(child => appendFolder(child, depth + 1));
          files.forEach(file => {
            const fileRow = document.createElement('button'); fileRow.type = 'button'; fileRow.className = 'analyst-tree-row';
            fileRow.dataset.fileId = String(file.id); fileRow.style.setProperty('--analyst-depth', String(depth + 1));
            fileRow.setAttribute('role', 'treeitem'); fileRow.setAttribute('aria-level', String(depth + 2));
            fileRow.setAttribute('aria-selected', String(state.analystSelectedFileId === file.id));
            fileRow.append(textElement('span', 'analyst-tree-glyph', file.kind === 'analyst-script' ? 'JS' : '·'),
              textElement('span', 'analyst-tree-name', file.name),
              textElement('span', 'analyst-tree-meta', file.kind === 'analyst-script' ? 'script' : file.language));
            fileRow.addEventListener('click', () => selectAnalystFile(file.id, true));
            fileRow.addEventListener('keydown', moveAnalystTreeSelection);
            nodes.push(fileRow);
          });
        };
        const root = analystFolder(1);
        if (root) appendFolder(root, 0);
        analystElements.tree.replaceChildren(...nodes);
        analystElements.tree.scrollTop = scrollTop;
        const focusKey = focused?.fileId ? `[data-file-id="${focused.fileId}"]`
          : focused?.folderId ? `[data-folder-id="${focused.folderId}"]` : null;
        if (focusKey) analystElements.tree.querySelector(focusKey)?.focus({preventScroll: true});
      }

      function analystFolderOptions(selectedId, excludedIds = new Set()) {
        const options = state.localAnalyst.folders.filter(folder => !excludedIds.has(folder.id))
          .sort((left, right) => analystFolderLineage(left.id).map(item => item.name).join('/').localeCompare(
            analystFolderLineage(right.id).map(item => item.name).join('/')))
          .map(folder => {
            const option = document.createElement('option'); option.value = String(folder.id);
            option.textContent = analystFolderLineage(folder.id).map(item => item.name).join(' / ');
            option.selected = folder.id === selectedId;
            return option;
          });
        if (selectedId && !options.some(option => option.value === String(selectedId))) {
          const option = document.createElement('option'); option.value = String(selectedId);
          option.textContent = `Unavailable folder #${selectedId}`; option.disabled = true; option.selected = true;
          options.push(option);
        }
        return options;
      }

      function renderAnalystFolderForm() {
        const folder = analystFolder();
        if (!folder) return;
        const draftParentId = state.analystFolderDirty ? Number(analystElements.folderParent.value) : folder.parent_id ?? 1;
        if (state.analystFolderDraftId !== folder.id || !state.analystFolderDirty) {
          state.analystFolderDraftId = folder.id;
          state.analystFolderBase = folder;
          analystElements.folderName.value = folder.name;
        }
        const excluded = folder.id === 1 ? new Set(state.localAnalyst.folders.map(item => item.id))
          : new Set([folder.id, ...analystDescendantIds(folder.id)]);
        analystElements.folderParent.replaceChildren(...analystFolderOptions(draftParentId, excluded));
        if (folder.id !== 1) analystElements.folderParent.value = String(draftParentId);
        analystElements.folderName.disabled = folder.id === 1 || state.localAnalystSaving;
        analystElements.folderParent.disabled = folder.id === 1 || state.localAnalystSaving;
        analystElements.saveFolder.disabled = folder.id === 1 || state.localAnalystSaving || state.localAnalystNeedsReload || Boolean(state.localAnalystPendingSave) || !state.analystFolderDirty;
        analystElements.revertFolder.disabled = state.localAnalystSaving || !state.analystFolderDirty;
        const hasContents = state.localAnalyst.folders.some(item => item.parent_id === folder.id) ||
          state.localAnalyst.files.some(file => file.folder_id === folder.id);
        analystElements.deleteFolder.disabled = folder.id === 1 || hasContents || state.localAnalystSaving;
        analystElements.deleteFolder.textContent = state.analystDeleteFolderId === folder.id ? 'Confirm delete' : 'Delete empty folder';
      }

      function renderAnalystEditor() {
        const file = analystFile();
        analystElements.editorEmpty.hidden = Boolean(file);
        analystElements.editorForm.hidden = !file;
        analystElements.editorBadge.dataset.kind = file ? '' : 'offline';
        analystElements.editorBadge.textContent = file ? file.kind === 'analyst-script' ? 'Runnable' : 'Note only' : 'No file';
        if (!file) return;
        if (!state.analystDraftDirty || analystElements.editorForm.dataset.fileId !== String(file.id)) {
          analystElements.editorForm.dataset.fileId = String(file.id);
          state.analystDraftBase = file;
          analystElements.name.value = file.name;
          analystElements.kind.value = file.kind;
          analystElements.language.value = file.language;
          analystElements.content.value = file.content;
        }
        const draftFolderId = state.analystDraftDirty ? Number(analystElements.folder.value) : file.folder_id;
        analystElements.folder.replaceChildren(...analystFolderOptions(draftFolderId));
        analystElements.folder.value = String(draftFolderId);
        const script = analystElements.kind.value === 'analyst-script';
        if (script) analystElements.language.value = 'javascript';
        analystElements.language.disabled = script || state.localAnalystSaving;
        analystElements.editorForm.querySelectorAll('input, textarea, select').forEach(field => {
          if (field !== analystElements.language) field.disabled = state.localAnalystSaving;
        });
        analystElements.save.disabled = state.localAnalystSaving || state.localAnalystNeedsReload || Boolean(state.localAnalystPendingSave) || !state.analystDraftDirty;
        analystElements.revert.disabled = state.localAnalystSaving || !state.analystDraftDirty;
        analystElements.deleteFile.disabled = state.localAnalystSaving;
        analystElements.deleteFile.textContent = state.analystDeleteFileId === file.id ? 'Confirm delete' : 'Delete';
        analystElements.draftStatus.dataset.kind = state.analystDraftDirty ? 'dirty' : 'saved';
        analystElements.draftStatus.textContent = state.analystDraftDirty
          ? 'Unsaved changes cannot run. Save or discard this draft before choosing another item. Save before closing the app.'
          : `${formatByteSize(file.content_bytes)} saved · file ${file.id} · ${new Date(file.updated_at_ms).toLocaleString()}`;
      }

      function selectedAnalystArtifact() {
        const source = selectedSource();
        if (source?.source_type !== 'artifact' || typeof source.content !== 'string') return null;
        return source;
      }

      function analystVariables() {
        const source = analystElements.variables.value.trim();
        if (!source) return {};
        let variables;
        try { variables = JSON.parse(source); }
        catch { throw new TypeError('Private variables must be a JSON object.'); }
        if (!isPlainObject(variables) || Object.keys(variables).length > 32) {
          throw new TypeError('Private variables must be an object with at most 32 entries.');
        }
        let bytes = 0;
        for (const [name, value] of Object.entries(variables)) {
          if (!/^[A-Za-z_][A-Za-z0-9_.-]*$/u.test(name) || utf8ByteLength(name) > 128 ||
            typeof value !== 'string' || utf8ByteLength(value) > 4 * 1024) {
            throw new TypeError('Variable names and text values exceed the local runner contract.');
          }
          bytes += utf8ByteLength(name) + utf8ByteLength(value);
        }
        if (bytes > 16 * 1024) throw new TypeError('Private variables exceed 16 KiB.');
        return variables;
      }

      function analystArtifactMetadata(artifact) {
        const metadata = {};
        ['protocol_version', 'artifact_id', 'session_id', 'navigation_id', 'frame_id', 'parent_artifact_id',
          'creator_event_id', 'execution_context_id', 'capture_origin', 'kind', 'origin', 'url',
          'mime_type', 'byte_size', 'sha256', 'sensitive']
          .forEach(key => { if (artifact[key] !== undefined) metadata[key] = artifact[key]; });
        return metadata;
      }

      function buildAnalystEvidence() {
        const selected = analystElements.includeSelected.checked ? selectedAnalystArtifact() : null;
        if (analystElements.includeSelected.checked && !selected) {
          throw new TypeError('Load one captured artifact before including its bytes.');
        }
        if (selected?.sensitive && !analystElements.confirmSensitive.checked) {
          throw new TypeError('Separately confirm inclusion of sensitive selected artifact bytes.');
        }
        const events = analystElements.includeEvents.checked ? state.events.slice(-500) : [];
        const artifacts = analystElements.includeArtifacts.checked
          ? state.artifacts.slice(-500).map(analystArtifactMetadata) : [];
        const traceEdges = analystElements.includeTrace.checked ? (state.originTrace?.steps ?? []).slice(-1000) : [];
        const signalProfiles = analystElements.includeSignals.checked && state.signalProfile ? [state.signalProfile] : [];
        const vmAnalysis = analystElements.includeVm.checked ? {
          status: state.vmAnalysisStatus,
          request_id: state.vmAnalysisRequestId,
          selection: state.vmAnalysisSelection,
          findings: state.vmFindings.slice(0, 256),
          malformed_findings: state.malformedVmFindings
        } : null;
        const selectedArtifact = selected ? {...analystArtifactMetadata(selected), content: selected.content} : null;
        const original = {events: events.length, artifacts: artifacts.length, trace_edges: traceEdges.length,
          signal_profiles: signalProfiles.length};
        const evidence = {
          events, artifacts, trace_edges: traceEdges, signal_profiles: signalProfiles, vm_analysis: vmAnalysis,
          selected_artifact: selectedArtifact,
          summary: {
            captured_at_ms: Date.now(),
            workspace_generation: state.localAnalyst.generation,
            selected_request_id: state.selectedRequestId,
            original,
            included: {...original},
            dropped: {events: 0, artifacts: 0, trace_edges: 0, signal_profiles: 0}
          }
        };
        const byteSize = () => utf8ByteLength(JSON.stringify(evidence));
        const collections = [['events', evidence.events], ['artifacts', evidence.artifacts],
          ['trace_edges', evidence.trace_edges], ['signal_profiles', evidence.signal_profiles]];
        let guard = 0;
        while (byteSize() > 768 * 1024 && ++guard < 128) {
          const entry = collections.reduce((largest, candidate) => candidate[1].length > largest[1].length ? candidate : largest,
            collections[0]);
          if (!entry[1].length) break;
          const remove = Math.max(1, Math.ceil(entry[1].length / 8));
          entry[1].splice(0, remove);
          evidence.summary.dropped[entry[0]] += remove;
          evidence.summary.included[entry[0]] = entry[1].length;
        }
        if (byteSize() > 768 * 1024) throw new TypeError('The selected evidence exceeds the 768 KiB snapshot limit.');
        return evidence;
      }

      function renderAnalystExecution() {
        const file = analystFile();
        const selected = selectedAnalystArtifact();
        const runnerAvailable = state.localAnalystRunner?.available === true;
        const runnerBusy = state.localAnalystRunner?.active_run_id !== null && state.localAnalystRunner?.active_run_id !== undefined &&
          state.localAnalystRunner?.active_run_id !== state.analystActiveRunId;
        analystElements.runnerBadge.textContent = runnerAvailable ? runnerBusy ? 'Runner busy' : 'Runner ready' : 'Runner unavailable';
        analystElements.runnerBadge.style.color = runnerAvailable ? '' : 'var(--red)';
        analystElements.includeSelected.disabled = !selected || state.analystRunPending;
        if (!selected) analystElements.includeSelected.checked = false;
        analystElements.sensitiveRow.hidden = !(selected?.sensitive && analystElements.includeSelected.checked);
        if (analystElements.sensitiveRow.hidden) analystElements.confirmSensitive.checked = false;
        const snapshotCount = (analystElements.includeEvents.checked ? Math.min(500, state.events.length) : 0) +
          (analystElements.includeArtifacts.checked ? Math.min(500, state.artifacts.length) : 0) +
          (analystElements.includeTrace.checked ? Math.min(1000, state.originTrace?.steps?.length ?? 0) : 0) +
          (analystElements.includeSignals.checked && state.signalProfile ? 1 : 0) +
          (analystElements.includeVm.checked && state.vmAnalysisStatus === 'ready' ? state.vmFindings.length : 0);
        analystElements.snapshotBadge.textContent = `${snapshotCount} records`;
        const runnable = file?.kind === 'analyst-script' && !state.analystDraftDirty && !state.localAnalystNeedsReload &&
          !state.localAnalystPendingSave && runnerAvailable && !runnerBusy &&
          !state.analystRunPending && state.analystTotalRuns < 256;
        analystElements.run.disabled = !runnable;
        analystElements.cancel.disabled = !state.analystRunPending;
        analystElements.clearHistory.disabled = state.analystRunPending || state.analystRuns.length === 0;
        analystElements.variables.disabled = state.analystRunPending;
        analystElements.includeEvents.disabled = state.analystRunPending;
        analystElements.includeArtifacts.disabled = state.analystRunPending;
        analystElements.includeTrace.disabled = state.analystRunPending;
        analystElements.includeSignals.disabled = state.analystRunPending;
        analystElements.includeVm.disabled = state.analystRunPending;
        analystElements.includeSelected.disabled = !selected || state.analystRunPending;
        analystElements.confirm.disabled = state.analystRunPending;
        analystElements.confirmSensitive.disabled = state.analystRunPending;
      }

      function renderAnalystResult(run) {
        if (!run || run.pending) {
          analystElements.resultMeta.textContent = run ? `run ${run.run_id} is executing in a fresh helper process` : 'Select a completed run.';
          analystElements.resultBadge.dataset.kind = 'offline';
          analystElements.resultBadge.textContent = run ? 'Running' : 'No result';
          analystElements.result.replaceChildren(textElement('div', 'analyst-empty', run ? 'Waiting for the bounded runner result…' : 'No run selected.'));
          return;
        }
        const included = run.evidence_summary ? Object.values(run.evidence_summary.included).reduce((sum, value) => sum + value, 0) : 0;
        const dropped = run.evidence_summary ? Object.values(run.evidence_summary.dropped).reduce((sum, value) => sum + value, 0) : 0;
        analystElements.resultMeta.textContent = `run ${run.run_id} · script ${run.script_id} · generation ${run.library_generation} · ${run.duration_ms} ms · ${included} evidence records${dropped ? ` · ${dropped} dropped by snapshot limit` : ''}`;
        analystElements.resultBadge.dataset.kind = run.ok ? '' : 'error';
        analystElements.resultBadge.textContent = run.outcome.replaceAll('_', ' ');
        const nodes = [];
        const result = document.createElement('pre');
        result.textContent = run.ok ? run.result_text || '(undefined)' : run.error;
        nodes.push(result);
        if (run.logs.length) {
          const logs = document.createElement('div'); logs.className = 'analyst-log-list';
          run.logs.forEach(log => {
            const row = document.createElement('div'); row.className = 'analyst-log-row'; row.dataset.level = log.level;
            row.textContent = `${log.level}: ${log.text}`; logs.append(row);
          });
          nodes.push(logs);
        }
        if (run.result_truncated || run.logs_truncated) nodes.push(textElement('p', 'experiment-privacy',
          `${run.result_truncated ? 'Result' : 'Logs'} reached the visible retention limit.`));
        analystElements.result.replaceChildren(...nodes);
      }

      function renderAnalystHistory() {
        if (!state.analystRuns.some(run => run.run_id === state.analystSelectedRunId)) {
          state.analystSelectedRunId = state.analystRuns[0]?.run_id ?? null;
        }
        analystElements.historyBadge.textContent = `${state.analystRuns.length} / 64`;
        analystElements.historyBadge.dataset.kind = state.analystRuns.length ? '' : 'offline';
        if (!state.analystRuns.length) analystElements.history.replaceChildren(
          emptyListboxOption('analyst-empty', state.analystHistoryEvictions
            ? `${state.analystHistoryEvictions} older runs were evicted; history is now clear.`
            : 'Run a saved script to see results and logs.')
        );
        else analystElements.history.replaceChildren(...state.analystRuns.map(run => {
          const row = document.createElement('button'); row.type = 'button'; row.className = 'analyst-history-row';
          row.setAttribute('role', 'option'); row.setAttribute('aria-selected', String(run.run_id === state.analystSelectedRunId));
          row.tabIndex = run.run_id === state.analystSelectedRunId ? 0 : -1;
          const outcome = textElement('strong', '', run.pending ? 'running' : run.outcome.replaceAll('_', ' '));
          if (!run.pending && !run.ok) outcome.dataset.kind = 'error';
          const included = run.evidence_summary ? Object.values(run.evidence_summary.included).reduce((sum, value) => sum + value, 0) : 0;
          const dropped = run.evidence_summary ? Object.values(run.evidence_summary.dropped).reduce((sum, value) => sum + value, 0) : 0;
          row.append(textElement('span', '', run.file_name), outcome,
            textElement('small', '', `run ${run.run_id} · script ${run.script_id} · generation ${run.library_generation} · ${included} records${dropped ? ` · ${dropped} dropped` : ''}${run.completed_at_ms ? ` · ${new Date(run.completed_at_ms).toLocaleTimeString()}` : ''}`));
          row.addEventListener('click', () => { state.analystSelectedRunId = run.run_id; renderAnalystHistory(); });
          row.addEventListener('keydown', event => {
            if (!['ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) return;
            event.preventDefault();
            const rows = [...analystElements.history.querySelectorAll('.analyst-history-row')];
            const index = rows.indexOf(row);
            const next = event.key === 'Home' ? 0 : event.key === 'End' ? rows.length - 1
              : Math.max(0, Math.min(rows.length - 1, index + (event.key === 'ArrowDown' ? 1 : -1)));
            rows[next].click(); rows[next].focus();
          });
          return row;
        }));
        renderAnalystResult(state.analystRuns.find(run => run.run_id === state.analystSelectedRunId) ?? null);
      }

      function renderLocalAnalyst() {
        if (!analystElements.tree) return;
        const firstUse = state.localAnalyst.files.length === 0 && state.localAnalyst.folders.length === 1;
        analystElements.editorEmpty.parentElement?.parentElement?.setAttribute('data-state', firstUse ? 'empty' : 'ready');
        analystElements.reload.disabled = state.localAnalystSaving || state.localAnalystRefreshing;
        analystElements.generation.textContent = `Generation ${state.localAnalyst.generation}`;
        analystElements.fileCount.textContent = `${state.localAnalyst.files.length} / 64`;
        analystElements.folderUsage.textContent = `${state.localAnalyst.folders.length} / 32`;
        analystElements.contentUsage.textContent = `${formatByteSize(state.localAnalyst.files.reduce((sum, file) => sum + file.content_bytes, 0))} / 512 KiB`;
        analystElements.notice.dataset.kind = state.localAnalystStatus;
        analystElements.notice.textContent = state.localAnalystMessage;
        analystElements.newFolder.disabled = state.localAnalystSaving || state.localAnalyst.folders.length >= 32 ||
          analystFolderDepth(state.analystSelectedFolderId) >= 4;
        analystElements.newScript.disabled = state.localAnalystSaving || state.localAnalyst.files.length >= 64;
        analystElements.newNote.disabled = state.localAnalystSaving || state.localAnalyst.files.length >= 64;
        renderAnalystTree();
        renderAnalystFolderForm();
        renderAnalystEditor();
        renderAnalystExecution();
        renderAnalystHistory();
      }

      const decoderNativeOperations = new Set([
        'base64-encode', 'base64-decode', 'base64url-encode', 'base64url-decode',
        'hex-encode', 'hex-decode', 'url-encode', 'url-decode', 'base36-encode',
        'base36-decode', 'gzip-compress', 'gzip-decompress', 'zlib-compress',
        'zlib-decompress', 'deflate-compress', 'deflate-decompress', 'json-pretty',
        'json-minify', 'protobuf-inspect', 'grpc-web-inspect', 'grpc-web-text-inspect',
        'magic-inspect', 'sha256', 'sha384', 'sha512'
      ]);
      const decoderAlgorithms = new Set(['HS256', 'HS384', 'HS512', 'none']);

      function decoderHasExactKeys(value, keys) {
        return isPlainObject(value) && Object.keys(value).length === keys.length &&
          keys.every(key => Object.hasOwn(value, key));
      }

      function isDecoderEngine(value) {
        if (!decoderHasExactKeys(value, ['protocol_version', 'available', 'busy', 'limits']) ||
            value.protocol_version !== 1 || typeof value.available !== 'boolean' || typeof value.busy !== 'boolean') return false;
        const limits = value.limits;
        if (!decoderHasExactKeys(limits, ['input_bytes', 'output_bytes', 'pipeline_steps', 'retained_bytes',
          'jwt_bytes', 'secret_bytes', 'json_depth', 'json_tokens', 'timeout_ms', 'operations', 'jwt_algorithms'])) return false;
        if (limits.input_bytes !== 1048576 || limits.output_bytes !== 1048576 || limits.pipeline_steps !== 16 ||
            limits.retained_bytes !== 4194304 || limits.jwt_bytes !== 65536 || limits.secret_bytes !== 4096 ||
            limits.json_depth !== 64 || limits.json_tokens !== 100000 || limits.timeout_ms !== 2000) return false;
        return Array.isArray(limits.operations) && limits.operations.length === decoderNativeOperations.size &&
          limits.operations.every(operation => decoderNativeOperations.has(operation)) &&
          new Set(limits.operations).size === decoderNativeOperations.size &&
          Array.isArray(limits.jwt_algorithms) && limits.jwt_algorithms.length === decoderAlgorithms.size &&
          limits.jwt_algorithms.every(algorithm => decoderAlgorithms.has(algorithm)) &&
          new Set(limits.jwt_algorithms).size === decoderAlgorithms.size;
      }

      function isDecoderTransform(value, request) {
        if (!decoderHasExactKeys(value, ['protocol_version', 'ok', 'operation_id', 'operation', 'input_bytes',
          'output_bytes', 'output_base64', 'utf8_text', 'hex_preview', 'preview_truncated', 'duration_us'])) return false;
        if (value.protocol_version !== 1 || value.ok !== true || value.operation_id !== request.operation_id ||
            value.operation !== request.operation || !isSafeIntegerInRange(value.input_bytes, 0, 1048576) ||
            !isSafeIntegerInRange(value.output_bytes, 0, 1048576) ||
            !isSafeIntegerInRange(value.duration_us, 1, Number.MAX_SAFE_INTEGER) ||
            (value.utf8_text !== null && typeof value.utf8_text !== 'string') || typeof value.hex_preview !== 'string' ||
            !/^(?:[0-9a-f]{2})*$/u.test(value.hex_preview) || typeof value.preview_truncated !== 'boolean') return false;
        try {
          const output = decoderBase64ToBytes(value.output_base64);
          return output.byteLength === value.output_bytes && value.hex_preview === decoderBytesToHex(output.slice(0, 256)) &&
            value.preview_truncated === (output.byteLength > 256);
        } catch {
          return false;
        }
      }

      function isJwtInspection(value) {
        return resultHasOptionalReason(value, ['protocol_version', 'ok', 'algorithm', 'signature_status', 'header_json',
          'payload_json', 'token_bytes', 'signature_bytes', 'error', 'duration_us'], 'application_failed') && value.protocol_version === 1 &&
          typeof value.ok === 'boolean' && typeof value.algorithm === 'string' && value.algorithm.length <= 128 &&
          ['not_checked', 'verified', 'invalid', 'unsigned', 'unsupported'].includes(value.signature_status) &&
          typeof value.header_json === 'string' && utf8ByteLength(value.header_json) <= 65536 &&
          typeof value.payload_json === 'string' && utf8ByteLength(value.payload_json) <= 65536 &&
          isSafeIntegerInRange(value.token_bytes, 0, 65536) && isSafeIntegerInRange(value.signature_bytes, 0, 65536) &&
          (value.error === null || (typeof value.error === 'string' && utf8ByteLength(value.error) <= 4096)) &&
          isSafeIntegerInRange(value.duration_us, 1, Number.MAX_SAFE_INTEGER);
      }

      function isJwtCreation(value) {
        return resultHasOptionalReason(value, ['protocol_version', 'ok', 'token', 'error', 'duration_us'], 'application_failed') &&
          value.protocol_version === 1 && typeof value.ok === 'boolean' && typeof value.token === 'string' &&
          utf8ByteLength(value.token) <= 65536 &&
          (value.error === null || (typeof value.error === 'string' && utf8ByteLength(value.error) <= 4096)) &&
          isSafeIntegerInRange(value.duration_us, 1, Number.MAX_SAFE_INTEGER);
      }

      function decoderBytesToBase64(bytes) {
        let binary = '';
        for (let offset = 0; offset < bytes.byteLength; offset += 32768) {
          binary += String.fromCharCode(...bytes.subarray(offset, Math.min(bytes.byteLength, offset + 32768)));
        }
        return btoa(binary);
      }

      function decoderBase64ToBytes(value) {
        if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)) {
          throw new TypeError('Base64 input must be canonical and contain no whitespace.');
        }
        let binary;
        try { binary = atob(value); } catch { throw new TypeError('Base64 input is malformed.'); }
        const bytes = Uint8Array.from(binary, character => character.charCodeAt(0));
        if (decoderBytesToBase64(bytes) !== value) throw new TypeError('Base64 input must use canonical padding.');
        return bytes;
      }

      function decoderBytesToHex(bytes) {
        return [...bytes].map(byte => byte.toString(16).padStart(2, '0')).join('');
      }

      function decoderHexToBytes(value) {
        let normalized = value.trim().replaceAll(/(?:\s|:|-)+/gu, '');
        if (normalized.startsWith('0x') || normalized.startsWith('0X')) normalized = normalized.slice(2);
        if (normalized.length % 2 !== 0 || !/^[0-9a-f]*$/iu.test(normalized)) {
          throw new TypeError('Hex input must contain complete byte pairs.');
        }
        return Uint8Array.from(normalized.match(/.{2}/gu) ?? [], pair => Number.parseInt(pair, 16));
      }

      function decoderParseInput() {
        let bytes;
        if (toolsElements.inputEncoding.value === 'text') bytes = new TextEncoder().encode(toolsElements.input.value);
        else if (toolsElements.inputEncoding.value === 'base64') bytes = decoderBase64ToBytes(toolsElements.input.value.trim());
        else bytes = decoderHexToBytes(toolsElements.input.value);
        if (bytes.byteLength > 1048576) throw new TypeError('Input exceeds the 1 MiB decoder limit.');
        return bytes;
      }

      function decoderCurrentInputKey() {
        return `${toolsElements.inputEncoding.value}\u0000${toolsElements.input.value}`;
      }

      function decoderSelectedBytes() {
        if (state.decoderSelectedStepId !== null) {
          const step = state.decoderSteps.find(candidate => candidate.id === state.decoderSelectedStepId);
          if (step) return decoderBase64ToBytes(step.output_base64);
        }
        if (state.decoderInputSnapshot) return decoderBase64ToBytes(state.decoderInputSnapshot.base64);
        return decoderParseInput();
      }

      function decoderRetainedBytes() {
        return (state.decoderInputSnapshot?.bytes ?? 0) + state.decoderSteps.reduce((sum, step) => sum + step.output_bytes, 0);
      }

      function setToolsNotice(kind, message) {
        state.decoderStatus = kind;
        state.decoderMessage = message;
      }

      async function refreshDecoderEngine(force = false) {
        if (state.decoderRefreshing || location.protocol === 'file:' || (!force && state.decoderStatus === 'ready')) return;
        state.decoderRefreshing = true;
        if (state.decoderStatus !== 'ready') setToolsNotice('loading', 'Checking the native decoder engine…');
        renderTools();
        try {
          const response = await fetch('/api/decoder', {cache: 'no-store'});
          if (!response.ok) throw new Error(`Decoder service returned ${response.status}`);
          const body = await response.json();
          if (!isDecoderEngine(body)) throw new TypeError('Decoder service returned a malformed capability contract.');
          state.decoderEngine = body;
          setToolsNotice(body.available ? 'ready' : 'error', body.available
            ? 'Native C++ decoder ready. Every transform runs only when requested.'
            : 'The native decoder executable is unavailable. Rebuild the application to restore local tools.');
        } catch (error) {
          state.decoderEngine = emptyDecoderEngine();
          setToolsNotice('error', `Decoder service unavailable: ${error.message}`);
        } finally {
          state.decoderRefreshing = false;
          renderTools();
        }
      }

      function decoderHtmlTransform(operation, input) {
        const started = performance.now();
        const text = new TextDecoder('utf-8', {fatal: true}).decode(input);
        const transformed = operation === 'html-encode'
          ? text.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
            .replaceAll('"', '&quot;').replaceAll("'", '&#39;')
          : new DOMParser().parseFromString(
            `<textarea>${text.replaceAll('<', '&#60;').replaceAll('>', '&#62;')}</textarea>`, 'text/html'
          ).body.firstElementChild.textContent;
        const output = new TextEncoder().encode(transformed);
        if (output.byteLength > 1048576) throw new TypeError('HTML entity output exceeds the 1 MiB limit.');
        return {
          protocol_version: 1, ok: true, operation_id: state.decoderNextOperationId,
          operation, input_bytes: input.byteLength, output_bytes: output.byteLength,
          output_base64: decoderBytesToBase64(output), utf8_text: new TextDecoder().decode(output),
          hex_preview: decoderBytesToHex(output.slice(0, 256)), preview_truncated: output.byteLength > 256,
          duration_us: Math.max(1, Math.round((performance.now() - started) * 1000))
        };
      }

      async function appendDecoderTransform() {
        if (state.decoderPending) return;
        try {
          if (state.decoderSteps.length >= 16) throw new TypeError('The 16-step chain limit was reached.');
          if (state.decoderInputSnapshot && state.decoderInputSnapshot.key !== decoderCurrentInputKey()) {
            throw new TypeError('Input changed. Reset the chain before using the new bytes.');
          }
          let input;
          let branchIndex = state.decoderSteps.length - 1;
          if (state.decoderSelectedStepId !== null) {
            branchIndex = state.decoderSteps.findIndex(step => step.id === state.decoderSelectedStepId);
            input = branchIndex >= 0 ? decoderBase64ToBytes(state.decoderSteps[branchIndex].output_base64) : null;
          }
          if (!input) {
            input = state.decoderInputSnapshot ? decoderBase64ToBytes(state.decoderInputSnapshot.base64) : decoderParseInput();
            branchIndex = -1;
          }
          if (!state.decoderInputSnapshot) {
            state.decoderInputSnapshot = {key: decoderCurrentInputKey(), base64: decoderBytesToBase64(input), bytes: input.byteLength};
          }
          const operation = toolsElements.operation.value;
          const operationId = state.decoderNextOperationId;
          state.decoderPending = true;
          setToolsNotice('running', `${operation.replaceAll('-', ' ')} is running locally…`);
          renderTools();
          const request = {protocol_version: 1, action: 'transform', operation_id: operationId,
            operation, input_base64: decoderBytesToBase64(input)};
          let result;
          if (operation === 'html-encode' || operation === 'html-decode') result = decoderHtmlTransform(operation, input);
          else {
            if (!state.decoderEngine.available) throw new TypeError('The native decoder engine is unavailable.');
            const response = await fetch('/api/decoder/actions', {method: 'POST', cache: 'no-store',
              headers: {'Content-Type': 'application/json'}, body: JSON.stringify(request)});
            const body = await response.json();
            if (!response.ok) throw new Error(body.error || `Decoder service returned ${response.status}`);
            if (!isDecoderTransform(body, request)) throw new TypeError('Decoder service returned a malformed or mismatched result.');
            result = body;
          }
          const prefix = state.decoderSteps.slice(0, branchIndex + 1);
          const retained = (state.decoderInputSnapshot?.bytes ?? 0) + prefix.reduce((sum, step) => sum + step.output_bytes, 0) + result.output_bytes;
          if (retained > 4194304) throw new TypeError('This result would exceed the 4 MiB retained-chain limit.');
          const step = {...result, id: operationId};
          state.decoderSteps = [...prefix, step];
          state.decoderNextOperationId += 1;
          state.decoderSelectedStepId = step.id;
          setToolsNotice('ready', `${operation.replaceAll('-', ' ')} completed: ${formatByteSize(result.input_bytes)} to ${formatByteSize(result.output_bytes)}.`);
        } catch (error) {
          setToolsNotice('error', error.message);
        } finally {
          state.decoderPending = false;
          renderTools();
        }
      }

      function decoderHexDump(bytes, maximum = 4096) {
        const rows = [];
        const visible = bytes.slice(0, maximum);
        for (let offset = 0; offset < visible.length; offset += 16) {
          const chunk = visible.slice(offset, offset + 16);
          const hex = [...chunk].map(byte => byte.toString(16).padStart(2, '0')).join(' ').padEnd(47, ' ');
          const ascii = [...chunk].map(byte => byte >= 32 && byte < 127 ? String.fromCharCode(byte) : '.').join('');
          rows.push(`${offset.toString(16).padStart(8, '0')}  ${hex}  |${ascii}|`);
        }
        if (bytes.byteLength > maximum) rows.push(`\n… ${formatByteSize(bytes.byteLength - maximum)} omitted from this preview`);
        return rows.join('\n');
      }

      function decoderVisibleOutput(bytes) {
        if (state.decoderView === 'hex') return decoderHexDump(bytes);
        if (state.decoderView === 'base64') {
          const visible = bytes.slice(0, 262144);
          const encoded = decoderBytesToBase64(visible);
          return bytes.byteLength > visible.byteLength ? `${encoded}\n\n… ${formatByteSize(bytes.byteLength - visible.byteLength)} omitted from this preview` : encoded;
        }
        try {
          const text = new TextDecoder('utf-8', {fatal: true}).decode(bytes.slice(0, 262144));
          return bytes.byteLength > 262144 ? `${text}\n\n… ${formatByteSize(bytes.byteLength - 262144)} omitted from this preview` : text;
        } catch {
          return 'These bytes are not valid UTF-8. Select Hex dump or Base64 to inspect them safely.';
        }
      }

      function renderDecoder() {
        toolsElements.engineBadge.textContent = state.decoderEngine.available ? (state.decoderEngine.busy ? 'Engine busy' : 'Native engine ready') : 'Engine unavailable';
        toolsElements.engineBadge.dataset.kind = state.decoderEngine.available ? '' : 'offline';
        let parsedInput = null;
        let inputError = null;
        try { parsedInput = state.decoderInputSnapshot ? decoderBase64ToBytes(state.decoderInputSnapshot.base64) : decoderParseInput(); }
        catch (error) { inputError = error.message; }
        toolsElements.inputBadge.textContent = inputError ? 'Invalid input' : formatByteSize(parsedInput.byteLength);
        toolsElements.inputBadge.dataset.kind = inputError ? 'error' : '';
        toolsElements.pipelineBadge.textContent = `${state.decoderSteps.length} / 16`;
        toolsElements.append.disabled = state.decoderPending || state.decoderSteps.length >= 16 || Boolean(inputError) ||
          (!state.decoderEngine.available && !toolsElements.operation.value.startsWith('html-'));
        toolsElements.useField.disabled = !state.selectedField || state.decoderPending;
        toolsElements.reset.disabled = state.decoderPending || (!state.decoderInputSnapshot && !state.decoderSteps.length);
        toolsElements.removeAfter.disabled = state.decoderPending || state.decoderSelectedStepId === null;
        const rows = [];
        const root = document.createElement('button'); root.type = 'button'; root.className = 'decoder-step'; root.setAttribute('role', 'option');
        root.setAttribute('aria-selected', String(state.decoderSelectedStepId === null)); root.tabIndex = state.decoderSelectedStepId === null ? 0 : -1;
        root.append(textElement('strong', '', 'Input bytes'), textElement('span', '', state.decoderInputSnapshot
          ? `${formatByteSize(state.decoderInputSnapshot.bytes)} · immutable chain root` : inputError ? inputError : `${formatByteSize(parsedInput.byteLength)} · current input`));
        root.addEventListener('click', () => { state.decoderSelectedStepId = null; renderDecoder(); });
        rows.push(root);
        state.decoderSteps.forEach((step, index) => {
          const row = document.createElement('button'); row.type = 'button'; row.className = 'decoder-step'; row.setAttribute('role', 'option');
          row.setAttribute('aria-selected', String(step.id === state.decoderSelectedStepId)); row.tabIndex = step.id === state.decoderSelectedStepId ? 0 : -1;
          row.append(textElement('strong', '', `${index + 1}. ${step.operation.replaceAll('-', ' ')}`),
            textElement('span', '', `${formatByteSize(step.input_bytes)} → ${formatByteSize(step.output_bytes)} · ${step.duration_us.toLocaleString()} µs`));
          row.addEventListener('click', () => { state.decoderSelectedStepId = step.id; renderDecoder(); });
          rows.push(row);
        });
        toolsElements.pipeline.replaceChildren(...rows);
        let selected = null;
        try { selected = decoderSelectedBytes(); } catch { selected = null; }
        const step = state.decoderSteps.find(candidate => candidate.id === state.decoderSelectedStepId);
        toolsElements.output.textContent = selected ? decoderVisibleOutput(selected) : 'Input could not be parsed.';
        toolsElements.outputMeta.textContent = selected ? (step
          ? `Step ${state.decoderSteps.indexOf(step) + 1}: ${step.operation.replaceAll('-', ' ')}` : 'Original input bytes') : (inputError ?? 'No bytes selected.');
        toolsElements.outputBadge.textContent = selected ? formatByteSize(selected.byteLength) : 'No output';
        toolsElements.outputBadge.dataset.kind = selected ? '' : 'offline';
        toolsElements.selectedBytes.textContent = selected ? formatByteSize(selected.byteLength) : '0 B';
        toolsElements.retainedBytes.textContent = `${formatByteSize(decoderRetainedBytes())} / 4 MiB`;
        toolsElements.duration.textContent = step ? `${step.duration_us.toLocaleString()} µs` : 'Not run';
        toolsElements.copyOutput.disabled = !selected;
        toolsElements.viewButtons.forEach(button => button.setAttribute('aria-pressed', String(button.dataset.decoderView === state.decoderView)));
      }

      function renderJwt() {
        const result = state.jwtResult;
        const statusLabels = {not_checked: 'Signature not checked', verified: 'Signature verified', invalid: 'Signature invalid',
          unsigned: 'Unsigned token', unsupported: 'Unsupported algorithm'};
        toolsElements.jwtInspect.disabled = state.jwtPending;
        toolsElements.jwtVerify.disabled = state.jwtPending;
        toolsElements.jwtCreate.disabled = state.jwtPending;
        toolsElements.jwtUnsignedRow.hidden = toolsElements.jwtAlgorithm.value !== 'none';
        toolsElements.jwtCreateSecret.disabled = toolsElements.jwtAlgorithm.value === 'none';
        toolsElements.jwtExpiry.disabled = false;
        if (!result) {
          toolsElements.jwtResultBadge.textContent = 'Not inspected'; toolsElements.jwtResultBadge.dataset.kind = 'offline';
          toolsElements.jwtResultMessage.textContent = 'Inspect a token to decode its header and claims.';
          toolsElements.jwtStatus.replaceChildren(textElement('span', '', 'Signature not checked'));
          toolsElements.jwtClaims.replaceChildren(textElement('div', 'analyst-empty', 'Decoded claims remain untrusted until a supported signature is explicitly verified.'));
          toolsElements.jwtHeader.textContent = 'No header decoded.'; toolsElements.jwtPayloadOutput.textContent = 'No payload decoded.';
          return;
        }
        const status = statusLabels[result.signature_status] ?? 'Invalid result';
        toolsElements.jwtResultBadge.textContent = status;
        toolsElements.jwtResultBadge.dataset.kind = result.signature_status === 'verified' ? '' : result.signature_status === 'not_checked' ? 'offline' : 'error';
        toolsElements.jwtResultMessage.textContent = result.error || (result.signature_status === 'verified'
          ? 'The HMAC signature is valid. Claim times are evaluated separately below.'
          : result.signature_status === 'not_checked' ? 'Header and payload decoded only. Treat all claims as untrusted.'
            : result.signature_status === 'unsigned' ? 'This token has no signature and provides no authenticity.'
              : result.signature_status === 'unsupported' ? 'The algorithm is not supported for local verification.'
                : 'The signature or compact token structure is invalid.');
        const algorithm = textElement('span', '', `Algorithm ${result.algorithm || 'unknown'}`);
        const signature = textElement('span', '', status); signature.dataset.kind = result.signature_status;
        toolsElements.jwtStatus.replaceChildren(algorithm, signature,
          textElement('span', '', `${formatByteSize(result.token_bytes)} · ${result.duration_us.toLocaleString()} µs`));
        toolsElements.jwtHeader.textContent = result.header_json || 'No header decoded.';
        toolsElements.jwtPayloadOutput.textContent = result.payload_json || 'No payload decoded.';
        const claims = [];
        try {
          const payload = JSON.parse(result.payload_json);
          if (isPlainObject(payload)) {
            ['iss', 'sub', 'aud', 'jti'].forEach(key => {
              if (Object.hasOwn(payload, key)) claims.push([key, typeof payload[key] === 'string' ? payload[key] : JSON.stringify(payload[key]), '']);
            });
            const now = Math.floor(Date.now() / 1000);
            [['exp', 'expires'], ['nbf', 'valid after'], ['iat', 'issued']].forEach(([key, label]) => {
              if (!Object.hasOwn(payload, key)) return;
              const value = payload[key];
              const valid = typeof value === 'number' && Number.isFinite(value);
              let note = 'not a numeric date';
              if (valid) {
                const date = new Date(value * 1000);
                note = Number.isNaN(date.valueOf()) ? 'date out of range' : date.toLocaleString();
                if (key === 'exp' && value <= now) note += ' · expired';
                if (key === 'nbf' && value > now) note += ' · not active yet';
                if (key === 'iat' && value > now + 60) note += ' · in the future';
              }
              claims.push([key, String(value), `${label}: ${note}`]);
            });
          }
        } catch { /* Native validation reports malformed payloads before this point. */ }
        if (!claims.length) toolsElements.jwtClaims.replaceChildren(textElement('div', 'analyst-empty', 'No standard identity or time claims were present.'));
        else toolsElements.jwtClaims.replaceChildren(...claims.map(([key, value, note]) => {
          const row = document.createElement('div'); row.className = 'jwt-claim';
          row.append(textElement('span', '', key), textElement('strong', '', value), textElement('small', '', note)); return row;
        }));
      }

      const float32Panel = mountFloat32Inspector(document.querySelector('#tools-panel-float32'), {getArtifacts: () => state.artifacts});

      function syncFloat32Panel() {
        if (state.toolsTab === 'float32' && !document.querySelector('#screen-tools').hidden) float32Panel.refresh();
      }

      function renderTools() {
        if (!toolsElements.notice) return;
        toolsElements.notice.dataset.kind = state.decoderStatus;
        toolsElements.notice.textContent = state.decoderMessage;
        toolsElements.tabs.forEach(tab => {
          const selected = tab.dataset.toolsTab === state.toolsTab;
          tab.setAttribute('aria-selected', String(selected)); tab.tabIndex = selected ? 0 : -1;
        });
        toolsElements.decoderPanel.hidden = state.toolsTab !== 'decoder';
        toolsElements.jwtPanel.hidden = state.toolsTab !== 'jwt';
        document.querySelector('#tools-panel-float32').hidden = state.toolsTab !== 'float32';
        if (state.toolsTab === 'float32') { toolsElements.notice.dataset.kind = 'ready'; toolsElements.notice.textContent = 'Read-only float32 diagnostics. Explicit local input; no target capture or execution.'; }
        toolsElements.engineBadge.hidden = state.toolsTab === 'float32';
        syncFloat32Panel();
        renderDecoder();
        renderInvestigationDecoder();
        renderJwt();
      }

      function setToolsTab(tab) {
        const next = ['jwt', 'float32'].includes(tab) ? tab : 'decoder';
        if (next !== 'float32') float32Panel.cancel();
        if (next !== state.toolsTab && !state.decoderPending && !state.jwtPending && state.decoderEngine.available) {
          setToolsNotice('ready', next === 'jwt'
            ? 'Paste a JWT to inspect its claims. Verify its signature separately before trusting them.'
            : 'Enter a value, choose a transformation, then inspect the result or add another step.');
        }
        state.toolsTab = next;
        renderTools();
      }

      function resetDecoderChain(message = 'Decoder chain cleared. Input was preserved.') {
        investigationDecoderOrigin = null;
        state.decoderInputSnapshot = null;
        state.decoderSteps = [];
        state.decoderSelectedStepId = null;
        state.decoderNextOperationId = 1;
        if (message) setToolsNotice(state.decoderEngine.available ? 'ready' : 'error', message);
        renderTools();
      }

      function useSelectedFieldInDecoder() {
        const selected = state.selectedField;
        if (!selected) return;
        let value = String(selected.value ?? '').trim();
        if (selected.type === 'str') {
          try { const decoded = JSON.parse(value); if (typeof decoded === 'string') value = decoded; } catch { /* Keep captured display text. */ }
        }
        const identity = investigationRequestIdentity(state.requests.find(request => request.id === state.selectedRequestId));
        investigationDecode(value, {route: identity ? {kind: 'request', identity, inspectorTab: 'evidence'} : null,
          description: `Selected request field ${selected.path}. This is the displayed field value; raw HTTP byte offsets are unavailable.`});
      }

      async function runJwtAction(action) {
        if (state.jwtPending) return;
        try {
          const token = toolsElements.jwtToken.value.trim();
          if (!token) throw new TypeError('Enter a compact JWT first.');
          state.jwtPending = true;
          setToolsNotice('running', action === 'jwt_verify' ? 'Verifying the HMAC signature locally…' : 'Decoding the JWT locally…');
          renderTools();
          if (action === 'jwt_verify' && toolsElements.jwtSecret.value.length === 0) {
            throw new TypeError('HMAC verification needs a secret. The previous inspection is unchanged.');
          }
          const request = action === 'jwt_verify'
            ? {protocol_version: 1, action, token, secret: toolsElements.jwtSecret.value}
            : {protocol_version: 1, action, token};
          const response = await fetch('/api/decoder/actions', {method: 'POST', cache: 'no-store',
            headers: {'Content-Type': 'application/json'}, body: JSON.stringify(request)});
          const body = await response.json();
          if (!response.ok) throw new Error(body.error || `Decoder service returned ${response.status}`);
          if (!isJwtInspection(body)) throw new TypeError('Decoder service returned a malformed JWT result.');
          state.jwtResult = body;
          setToolsNotice(body.ok ? 'ready' : 'error', body.ok
            ? (action === 'jwt_verify' ? 'JWT signature check completed locally.' : 'JWT decoded without checking its signature.')
            : (body.error || 'JWT inspection failed.'));
        } catch (error) {
          setToolsNotice('error', error.message);
        } finally {
          toolsElements.jwtSecret.value = '';
          state.jwtPending = false;
          renderTools();
        }
      }

      async function createJwtToken() {
        if (state.jwtPending) return;
        try {
          const algorithm = toolsElements.jwtAlgorithm.value;
          let expiration = null;
          if (toolsElements.jwtExpiry.value.trim()) {
            expiration = Number(toolsElements.jwtExpiry.value);
            if (!Number.isInteger(expiration) || expiration < 1 || expiration > 604800) throw new TypeError('Expiry must be between one second and seven days.');
          }
          const request = {protocol_version: 1, action: 'jwt_create', payload_json: toolsElements.jwtPayload.value,
            algorithm, secret: algorithm === 'none' ? '' : toolsElements.jwtCreateSecret.value,
            expires_in_seconds: expiration, allow_unsigned_confirmed: algorithm === 'none' && toolsElements.jwtConfirmUnsigned.checked};
          state.jwtPending = true;
          setToolsNotice('running', 'Creating the test JWT locally…');
          renderTools();
          const response = await fetch('/api/decoder/actions', {method: 'POST', cache: 'no-store',
            headers: {'Content-Type': 'application/json'}, body: JSON.stringify(request)});
          const body = await response.json();
          if (!response.ok) throw new Error(body.error || `Decoder service returned ${response.status}`);
          if (!isJwtCreation(body) || !body.ok || !body.token) throw new TypeError(body.error || 'Decoder service returned a malformed created token.');
          toolsElements.jwtToken.value = body.token;
          toolsElements.jwtConfirmUnsigned.checked = false;
          setToolsNotice('ready', `${algorithm} test token created locally. Its signature has not been trusted automatically.`);
        } catch (error) {
          setToolsNotice('error', error.message);
          toolsElements.jwtCreateSecret.value = '';
          state.jwtPending = false;
          renderTools();
          return;
        }
        toolsElements.jwtCreateSecret.value = '';
        state.jwtPending = false;
        await runJwtAction('jwt_inspect');
      }

      async function createAnalystFolder() {
        if (!analystMayLeaveDraft()) return false;
        const parentId = state.analystSelectedFolderId;
        const name = analystUniqueName(parentId, 'New folder');
        const folder = {id: analystNextId(state.localAnalyst.folders), name, parent_id: parentId};
        if (await replaceLocalAnalyst([...state.localAnalyst.folders, folder], state.localAnalyst.files, `Folder “${name}” created.`)) {
          state.analystSelectedFolderId = folder.id;
          state.analystSelectedFileId = null;
          state.analystExpandedFolderIds.add(parentId);
          state.analystExpandedFolderIds.add(folder.id);
          state.analystFolderDraftId = null;
          renderLocalAnalyst();
          requestAnimationFrame(() => { analystElements.folderName.focus(); analystElements.folderName.select(); });
        }
      }

      async function createAnalystFile(kind) {
        if (!analystMayLeaveDraft()) return false;
        const folderId = state.analystSelectedFolderId;
        const script = kind === 'analyst-script';
        const name = analystUniqueName(folderId, script ? 'inspect evidence.js' : 'research notes.md');
        const file = {
          id: analystNextId(state.localAnalyst.files), folder_id: folderId, name, kind,
          language: script ? 'javascript' : 'markdown',
          content: script ? "const events = WB.Node.Evidence.events();\nconsole.info('events', events.length);\nreturn {event_count: events.length};" : ''
        };
        if (await replaceLocalAnalyst(state.localAnalyst.folders, [...state.localAnalyst.files, file], `${script ? 'Script' : 'Scratchpad'} “${name}” created.`)) {
          state.analystSelectedFileId = file.id;
          state.analystExpandedFolderIds.add(folderId);
          state.analystDraftDirty = false;
          renderLocalAnalyst();
          requestAnimationFrame(() => { analystElements.name.focus(); analystElements.name.select(); });
        }
      }

      async function saveAnalystFolder() {
        if (!state.analystFolderDirty) return false;
        const folder = analystFolder();
        if (!folder || folder.id === 1) return;
        if (JSON.stringify(folder) !== JSON.stringify(state.analystFolderBase)) {
          state.localAnalystNeedsReload = true;
          setAnalystNotice('conflict', 'The folder draft no longer matches its saved owner. Copy any edits you need, discard changes and Retry load.');
          return false;
        }
        const replacement = {...folder, name: analystElements.folderName.value.trim(),
          parent_id: Number(analystElements.folderParent.value)};
        const folders = state.localAnalyst.folders.map(candidate => candidate.id === folder.id ? replacement : candidate);
        if (await replaceLocalAnalyst(folders, state.localAnalyst.files, `Folder “${replacement.name}” saved.`)) {
          state.analystFolderDirty = false;
          state.analystFolderDraftId = null;
          state.analystExpandedFolderIds.add(replacement.parent_id);
          renderLocalAnalyst();
        }
      }

      async function saveAnalystFile() {
        if (!state.analystDraftDirty) return false;
        const file = analystFile();
        if (!file) return false;
        if (analystElements.editorForm.dataset.fileId !== String(file.id) ||
            file.created_at_ms !== state.analystDraftBase?.created_at_ms ||
            JSON.stringify(analystFileInput(file)) !== JSON.stringify(analystFileInput(state.analystDraftBase))) {
          state.localAnalystNeedsReload = true;
          setAnalystNotice('conflict', 'The file draft no longer matches its saved owner. Copy any edits you need, discard changes and Retry load.');
          return false;
        }
        if (state.analystFolderDirty && Number(analystElements.folder.value) !== state.analystSelectedFolderId) {
          setAnalystNotice('conflict', 'Save or discard the folder changes before moving this file. Both drafts remain here.');
          return false;
        }
        const kind = analystElements.kind.value;
        const replacement = {
          ...file,
          folder_id: Number(analystElements.folder.value),
          name: analystElements.name.value.trim(),
          kind,
          language: kind === 'analyst-script' ? 'javascript' : analystElements.language.value,
          content: analystElements.content.value
        };
        const files = state.localAnalyst.files.map(candidate => candidate.id === file.id ? replacement : candidate);
        if (await replaceLocalAnalyst(state.localAnalyst.folders, files, `File “${replacement.name}” saved.`)) {
          state.analystSelectedFolderId = replacement.folder_id;
          state.analystExpandedFolderIds.add(replacement.folder_id);
          state.analystDraftDirty = false;
          renderLocalAnalyst();
          return true;
        }
        return false;
      }

      async function deleteAnalystFile() {
        if (!analystMayLeaveDraft()) return false;
        const file = analystFile();
        if (!file) return;
        if (state.analystDeleteFileId !== file.id) {
          state.analystDeleteFileId = file.id;
          setAnalystNotice('ready', 'Select Delete again to remove this local file.');
          renderLocalAnalyst();
          return;
        }
        if (await replaceLocalAnalyst(state.localAnalyst.folders,
          state.localAnalyst.files.filter(candidate => candidate.id !== file.id), `File “${file.name}” deleted.`)) {
          state.analystSelectedFileId = null;
          state.analystDeleteFileId = null;
          state.analystDraftDirty = false;
          renderLocalAnalyst();
        }
      }

      async function deleteAnalystFolder() {
        if (!analystMayLeaveDraft()) return false;
        const folder = analystFolder();
        if (!folder || folder.id === 1) return;
        const hasContents = state.localAnalyst.folders.some(candidate => candidate.parent_id === folder.id) ||
          state.localAnalyst.files.some(file => file.folder_id === folder.id);
        if (hasContents) { setAnalystNotice('error', 'Move or delete this folder’s contents first.'); renderLocalAnalyst(); return; }
        if (state.analystDeleteFolderId !== folder.id) {
          state.analystDeleteFolderId = folder.id;
          setAnalystNotice('ready', 'Select Delete empty folder again to confirm.');
          renderLocalAnalyst();
          return;
        }
        if (await replaceLocalAnalyst(state.localAnalyst.folders.filter(candidate => candidate.id !== folder.id),
          state.localAnalyst.files, `Folder “${folder.name}” deleted.`)) {
          state.analystSelectedFolderId = folder.parent_id ?? 1;
          state.analystDeleteFolderId = null;
          state.analystFolderDirty = false;
          renderLocalAnalyst();
        }
      }

      async function runLocalAnalystScript() {
        const file = analystFile();
        if (!file || file.kind !== 'analyst-script' || state.analystRunPending) return;
        try {
          if (state.analystDraftDirty || state.localAnalystNeedsReload || state.localAnalystPendingSave) throw new TypeError('Resolve the draft and reload any uncertain save before running this script.');
          if (!analystElements.confirm.checked) throw new TypeError('Confirm access to the selected evidence snapshot before running.');
          if (state.analystTotalRuns >= 256) throw new TypeError('The 256-run session limit was reached. Clear history to begin a fresh session.');
          const run = {
            action: 'run_local_analyst_script', protocol_version: 1,
            run_id: state.analystNextRunId++, script_id: file.id,
            library_generation: state.localAnalyst.generation, source: file.content,
            variables: analystVariables(), evidence: buildAnalystEvidence(), confirmed: true,
            confirmed_sensitive: Boolean(selectedAnalystArtifact()?.sensitive && analystElements.includeSelected.checked &&
              analystElements.confirmSensitive.checked)
          };
          state.analystTotalRuns += 1;
          state.analystRunPending = true;
          state.analystActiveRunId = run.run_id;
          const pending = {
            run_id: run.run_id,
            script_id: run.script_id,
            library_generation: run.library_generation,
            evidence_summary: run.evidence.summary,
            file_name: file.name,
            pending: true
          };
          state.analystRuns.unshift(pending);
          if (state.analystRuns.length > 64) {
            state.analystRuns.length = 64;
            state.analystHistoryEvictions += 1;
          }
          state.analystSelectedRunId = run.run_id;
          setAnalystNotice('running', `Run ${run.run_id} is executing in a fresh isolated helper process.`);
          renderLocalAnalyst();
          const response = await fetch('/api/local-analyst/actions', {
            method: 'POST', cache: 'no-store', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(run)
          });
          const body = await response.json();
          if (!response.ok) throw new Error(body.error || `Analyst runner returned ${response.status}`);
          if (!isLocalAnalystResult(body, run)) throw new TypeError('The analyst runner returned a malformed or mismatched result.');
          Object.assign(pending, body, {pending: false, file_name: file.name, completed_at_ms: Date.now()});
          setAnalystNotice(body.ok ? 'ready' : 'error', body.ok
            ? `Run ${body.run_id} completed in ${body.duration_ms} ms without changing captured evidence.`
            : `Run ${body.run_id} ${body.outcome.replaceAll('_', ' ')}: ${body.error}`);
        } catch (error) {
          const pending = state.analystRuns.find(run => run.run_id === state.analystActiveRunId);
          if (pending) Object.assign(pending, {
            pending: false, ok: false, outcome: 'failed', result_type: 'error', result_text: '',
            result_truncated: false, logs: [], logs_truncated: false, duration_ms: 0,
            error: error.message, completed_at_ms: Date.now()
          });
          setAnalystNotice('error', `Analyst run failed: ${error.message}`);
        } finally {
          state.analystRunPending = false;
          state.analystActiveRunId = null;
          analystElements.confirm.checked = false;
          analystElements.confirmSensitive.checked = false;
          await refreshLocalAnalyst();
          renderLocalAnalyst();
        }
      }

      async function cancelLocalAnalystScript() {
        const runId = state.analystActiveRunId;
        if (!runId) return;
        analystElements.cancel.disabled = true;
        setAnalystNotice('running', `Cancelling analyst run ${runId}…`);
        try {
          const response = await fetch('/api/local-analyst/actions', {
            method: 'POST', cache: 'no-store', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({action: 'cancel_local_analyst_script', run_id: runId})
          });
          const body = await response.json();
          if (!response.ok || body.ok !== true || body.run_id !== runId || body.cancel_requested !== true) {
            throw new Error(body.error || 'The runner rejected cancellation.');
          }
        } catch (error) {
          setAnalystNotice('error', `Cancellation failed: ${error.message}`);
          analystElements.cancel.disabled = false;
        }
      }

      // Source ownership never comes from a URL. Captured documents reuse the
      // Facts identity of their immutable stored artifact.
      function sourceIdentity(source) {
        return source ? sourceFactsIdentity({...source, source_type: 'artifact'}) : null;
      }

      function sourceIsCurrent(source) {
        const candidates = state.artifacts.filter(value => value.artifact_id === source.artifact_id);
        return candidates.length === 1 && sourceIdentity(candidates[0]) === sourceIdentity(source);
      }

      function sourceReference(source) {
        // Navigator/tab/Quick Open handlers must not keep an evicted document
        // alive through a hidden DOM closure. Keep descriptors, never payloads.
        return Object.fromEntries(Object.entries(source).filter(([key]) => !['content', 'deobfuscation', 'controller'].includes(key)));
      }

      function retireSourceAnalysis(except = null) {
        for (const [key, payload] of state.deobfuscationCache ?? []) {
          if (!except || !key.startsWith(`${except}|`)) retireDeobfuscationReveal(payload.inspectorView);
        }
        for (const request of state.deobfuscationRequests?.values() ?? []) {
          if (request.status !== 'loading' || request.identity === except) continue;
          request.status = 'error';
          request.error = 'Analysis was cancelled when its source changed. Retry explicitly.';
          request.controller?.abort();
          delete request.controller;
        }
      }

      function releaseSourcePreview(source) {
        const identity = sourceIdentity(source);
        const preview = state.artifacts.find(value => sourceIdentity(value) === identity);
        if (preview) {
          preview.controller?.abort();
          for (const field of ['content', 'sourceTextLength', 'contentTruncated', 'loading', 'loadError', 'controller', 'previewUsed', 'contentVerified', 'contentLossy']) delete preview[field];
        }
        for (const cache of [state.deobfuscationRequests, state.deobfuscationCache, state.sourceFormatCache]) {
          for (const [key, value] of cache ?? []) {
            if (!key.startsWith(`${identity}|`)) continue;
            retireDeobfuscationReveal(value.inspectorView);
            value.controller?.abort(); cache.delete(key);
          }
        }
        if (state.sourceEditorView?.identity === identity) state.sourceEditorView = null;
      }

      function boundSourcePreviews(protectedSource = null) {
        const protectedIdentity = sourceIdentity(selectedSource() ?? protectedSource);
        const entries = (state.artifacts ?? []).filter(source => source.kind !== 'canvas_data_url').map(source => ({source, preview: source}))
          .filter(({preview}) => preview && (preview.loading || preview.content !== undefined));
        entries.sort((a, b) => (a.preview.previewUsed ?? 0) - (b.preview.previewUsed ?? 0));
        let characters = entries.reduce((sum, {preview}) => sum + (preview.content?.length ?? 0), 0);
        let documents = entries.length;
        // Metadata/open tabs remain. Reopening an evicted preview reloads it.
        // Text is at most 16 MiB of UTF-16 units across eight preview owners.
        for (const {source, preview} of entries) {
          if (documents <= 8 && characters <= 8 * 1024 * 1024) break;
          if (sourceIdentity(source) === protectedIdentity) continue;
          characters -= preview.content?.length ?? 0; documents -= 1;
          releaseSourcePreview(source);
        }
      }

      function boundSourceAnalysis(cache, maximum, characterLimit, segmentLimit) {
        let characters = 0, segments = 0, wireBytes = 0;
        for (const value of cache.values()) {
          wireBytes += value.sourceDocumentBytes ?? 0;
          characters += (value.original_source?.length ?? value.sourceInput?.length ?? 0) + (value.representation?.text?.length ?? value.text?.length ?? 0);
          segments += value.representation?.segments?.length ?? value.segments?.length ?? 0;
        }
        for (const [key, value] of cache) {
          if (cache.size <= maximum && characters <= characterLimit && segments <= segmentLimit && wireBytes <= 32 * 1024 * 1024) break;
          wireBytes -= value.sourceDocumentBytes ?? 0;
          characters -= (value.original_source?.length ?? value.sourceInput?.length ?? 0) + (value.representation?.text?.length ?? value.text?.length ?? 0);
          segments -= value.representation?.segments?.length ?? value.segments?.length ?? 0;
          retireDeobfuscationReveal(value.inspectorView);
          cache.delete(key);
        }
      }

      function capturedSources() {
        return state.artifacts
          .filter(artifact => artifact.kind !== 'canvas_data_url')
          .map(artifact => {
            const key = `artifact:${artifact.artifact_id}`;
            return { ...artifact, source_type: 'artifact', key, deobfuscation: state.deobfuscationCache?.get(deobfuscationKey({...artifact, key})) ?? null };
          });
      }

      function sourceOrigin(source) {
        try { return source.url ? new URL(source.url).origin : '(anonymous)'; } catch { return '(generated)'; }
      }

      function sourceDisplayName(source) {
        return `${sourceName(source)} · artifact ${source.artifact_id}`;
      }

      // Every artifact kind the evidence contract admits, labeled by what its
      // bytes are. Only javascript artifacts are JavaScript.
      function sourceKindLabel(kind) {
        return {javascript: ['JS', 'JavaScript'], wasm: ['W', 'WebAssembly'], source_map: ['{}', 'source map'],
          response_body: ['R', 'response body'], wasm_guest_adapter: ['AD', 'guest adapter JSON'],
          bytecode_buffer: ['BC', 'guest bytecode']}[kind] ?? null;
      }

      function sourceDisplayMeta(source) {
        return `${source.origin === 'sample' ? 'sample' : source.origin === 'demo' ? 'demo' : 'evidence'} · ${sourceKindLabel(source.kind)?.[1] ?? source.kind}`;
      }

      function sourcePathParts(source) {
        try { return source.url ? new URL(source.url).pathname.split('/').filter(Boolean) : [sourceName(source)]; } catch { return [sourceName(source)]; }
      }

      function sourceIcon(source) {
        return sourceKindLabel(source.kind)?.[0] ?? '?';
      }

      function selectedSource() {
        const matches = capturedSources().filter(source => source.artifact_id === state.selectedArtifactId);
        return matches.length === 1 ? matches[0] : null;
      }

      // The navigator owns metadata and focus only. It never owns source bytes,
      // editor state, analysis, or fetches. These caps also bound hostile paths.
      const SOURCE_TREE_LIMITS = Object.freeze({catalog: 5000, nodes: 10000, visible: 1000, depth: 16, url: 4096, identity: 8192});

      function sourceTreeModel(collection) {
        const catalog = state.artifacts;
        const nodes = new Map();
        const rootKey = JSON.stringify([collection, 'root']);
        const root = {key: rootKey, kind: 'root', label: 'top', depth: 0, parent: null, children: [], count: 0};
        nodes.set(rootKey, root);
        const limits = {catalog: Math.max(0, catalog.length - SOURCE_TREE_LIMITS.catalog), omitted: 0, deep: 0, ambiguous: 0};
        const files = new Map();
        const branch = (key, label, kind, parent) => {
          if (!nodes.has(key)) {
            const node = {key, label, kind, depth: parent.depth + 1, parent: parent.key, children: [], count: 0};
            nodes.set(key, node); parent.children.push(key);
          }
          return nodes.get(key);
        };
        for (let index = 0; index < Math.min(catalog.length, SOURCE_TREE_LIMITS.catalog); index++) {
          const raw = catalog[index];
          if (raw.kind === 'canvas_data_url') continue;
          // Refuse an overlong path before URL parsing or identity serialization.
          if (typeof raw.url !== 'string' || raw.url.length > SOURCE_TREE_LIMITS.url) {limits.omitted++; continue;}
          const source = {...sourceReference(raw), source_type: 'artifact'};
          const identity = sourceIdentity(source);
          if (!identity || identity.length > SOURCE_TREE_LIMITS.identity) {limits.omitted++; continue;}
          const key = JSON.stringify([collection, 'source', identity]);
          // Duplicate exact identities must never become two apparent choices.
          if (files.has(key)) {files.get(key).ambiguous = true; limits.ambiguous++; continue;}
          let origin = '(anonymous)', originIdentity = ['anonymous'], parts = [];
          if (source.url) {
            try {
              const url = new URL(source.url);
              origin = url.origin === 'null' ? url.protocol : url.origin;
              originIdentity = ['url', origin];
              parts = url.pathname.split('/');
              if (url.pathname.startsWith('/')) parts.shift();
            } catch {origin = '(generated)'; originIdentity = ['generated'];}
          }
          const directories = parts.slice(0, -1);
          const bounded = directories.slice(0, SOURCE_TREE_LIMITS.depth);
          const originKey = JSON.stringify([collection, 'origin', originIdentity]);
          const directoryKeys = bounded.map((_, index) => JSON.stringify([collection, 'folder', originIdentity, bounded.slice(0, index + 1)]));
          const newBranches = [originKey, ...directoryKeys].filter(value => !nodes.has(value)).length;
          if (nodes.size + newBranches + 1 > SOURCE_TREE_LIMITS.nodes) {limits.omitted++; continue;}
          if (directories.length > SOURCE_TREE_LIMITS.depth) limits.deep++;
          let parent = branch(originKey, origin.replace(/^https?:\/\//, ''), 'origin', root);
          const ancestors = [root, parent];
          bounded.forEach((label, index) => {
            parent = branch(directoryKeys[index], label || '(empty path segment)', 'folder', parent); ancestors.push(parent);
          });
          const node = {key, identity, kind: 'file', label: sourceDisplayName(source), source,
            parent: parent.key, depth: parent.depth + 1, children: null};
          nodes.set(key, node); files.set(key, node); parent.children.push(key);
          for (const ancestor of ancestors) ancestor.count++;
        }
        for (const node of nodes.values()) {
          if (!node.children) continue;
          node.children.sort((a, b) => {
            const left = nodes.get(a), right = nodes.get(b);
            return Number(left.kind === 'file') - Number(right.kind === 'file') || left.label.localeCompare(right.label) || a.localeCompare(b);
          });
          node.children.forEach((key, index) => {const child = nodes.get(key); child.position = index + 1; child.size = node.children.length;});
        }
        root.position = 1; root.size = 1;
        return {collection, rootKey, nodes, limits};
      }

      function sourceTreeVisible(model, collapsed) {
        const visible = [], stack = model.nodes.get(model.rootKey).count ? [model.rootKey] : [];
        while (stack.length && visible.length < SOURCE_TREE_LIMITS.visible) {
          const node = model.nodes.get(stack.pop()); visible.push(node);
          if (node.children && !collapsed.has(node.key)) {
            for (let index = node.children.length - 1; index >= 0; index--) stack.push(node.children[index]);
          }
        }
        return {visible, limited: stack.length > 0};
      }

      function sourceTreeState() {
        return state.sourceNavigator ??= {scopes: new Map(), rows: new Map(), serial: 0, model: null, visible: []};
      }

      function sourceTreeScope(nav, collection) {
        if (!nav.scopes.has(collection)) nav.scopes.set(collection, {collapsed: new Set(), focus: null, scrollTop: 0, scrollLeft: 0});
        return nav.scopes.get(collection);
      }

      function sourceTreeFocus(key, reveal = false) {
        const nav = sourceTreeState(), scope = sourceTreeScope(nav, nav.model.collection);
        const entry = nav.rows.get(key);
        if (!entry) return;
        scope.focus = key;
        for (const [rowKey, value] of nav.rows) value.row.tabIndex = rowKey === key ? 0 : -1;
        entry.row.focus({preventScroll: true});
        if (reveal) {
          // Scroll only the navigator, never the editor or an outer workspace.
          const row = entry.row.getBoundingClientRect(), pane = elements.sourceTree.getBoundingClientRect();
          if (row.top < pane.top) elements.sourceTree.scrollTop += row.top - pane.top;
          else if (row.bottom > pane.bottom) elements.sourceTree.scrollTop += row.bottom - pane.bottom;
        }
      }

      function toggleSourceTree(key, expanded = null) {
        const nav = sourceTreeState(), node = nav.model?.nodes.get(key);
        if (!node?.children?.length) return;
        const scope = sourceTreeScope(nav, nav.model.collection);
        const open = expanded ?? scope.collapsed.has(key);
        if (open) scope.collapsed.delete(key); else scope.collapsed.add(key);
        renderSourceTree(false);
      }

      function sourceTreeKeydown(event, key) {
        // Leave browser/history/OS chords and native button Enter/Space alone.
        if (event.altKey || event.ctrlKey || event.metaKey || event.shiftKey) return;
        const nav = sourceTreeState(), node = nav.model?.nodes.get(key);
        if (!node) return;
        const scope = sourceTreeScope(nav, nav.model.collection);
        const index = nav.visible.findIndex(value => value.key === key);
        let next;
        if (event.key === 'ArrowDown') next = nav.visible[Math.min(index + 1, nav.visible.length - 1)]?.key;
        else if (event.key === 'ArrowUp') next = nav.visible[Math.max(0, index - 1)]?.key;
        else if (event.key === 'Home') next = nav.visible[0]?.key;
        else if (event.key === 'End') next = nav.visible.at(-1)?.key;
        else if (event.key === 'ArrowRight') {
          if (node.children?.length && scope.collapsed.has(key)) toggleSourceTree(key, true);
          else if (node.children?.length) next = node.children[0];
        } else if (event.key === 'ArrowLeft') {
          if (node.children?.length && !scope.collapsed.has(key)) toggleSourceTree(key, false);
          else next = node.parent;
        } else return;
        event.preventDefault(); event.stopPropagation();
        if (next) sourceTreeFocus(next, true);
      }

      function sourceTreeRow(node, nav) {
        const row = document.createElement('button');
        row.type = 'button'; row.className = 'source-tree-row';
        row.dataset.sourceTreeKey = node.key;
        row.dataset.sourceTreeKind = node.kind;
        row.setAttribute('role', 'treeitem');
        const icon = document.createElement('span'); icon.setAttribute('aria-hidden', 'true');
        const name = document.createElement('span'); name.className = 'source-tree-name';
        const detail = document.createElement('span'); detail.className = 'source-tree-meta';
        row.append(icon, name, detail);
        let group = null;
        if (node.children) {
          group = document.createElement('div'); group.setAttribute('role', 'group');
          group.id = `source-tree-group-${++nav.serial}`;
          // A button cannot contain interactive descendants. Own the adjacent
          // group so the accessibility tree still has the real hierarchy.
          row.setAttribute('aria-owns', group.id);
        }
        row.addEventListener('focus', () => {
          const scope = sourceTreeScope(nav, nav.model.collection); scope.focus = node.key;
          for (const [key, entry] of nav.rows) entry.row.tabIndex = key === node.key ? 0 : -1;
        });
        row.addEventListener('keydown', event => sourceTreeKeydown(event, node.key));
        row.addEventListener('click', () => {
          const current = nav.model?.nodes.get(node.key);
          if (!current) return;
          sourceTreeScope(nav, nav.model.collection).focus = node.key;
          if (current.children) toggleSourceTree(node.key);
          else if (sourceIsCurrent(current.source)) selectArtifact(current.source.artifact_id);
          else {
            state.sourceNoticeKind = 'warning';
            state.sourceNotice = 'This exact source changed or is no longer available. Refresh the catalog before opening it.';
            renderSourceHealth();
          }
        });
        return {row, icon, name, detail, group};
      }

      function renderSourceTree(refresh = true) {
        const nav = sourceTreeState(), tree = elements.sourceTree, previous = nav.model;
        const activeKey = document.activeElement?.dataset?.sourceTreeKey;
        const hadFocus = tree.contains(document.activeElement);
        const previousScope = previous && sourceTreeScope(nav, previous.collection);
        let anchor = null;
        if (refresh && previous?.collection === state.sourceCollection && tree.scrollTop > 0 && tree.clientHeight > 0) {
          const pane = tree.getBoundingClientRect();
          for (const node of nav.visible) {
            const bounds = nav.rows.get(node.key).row.getBoundingClientRect();
            if (bounds.bottom > pane.top && bounds.top < pane.bottom) {anchor = {key: node.key, offset: bounds.top - pane.top}; break;}
          }
        }
        if (previousScope) {previousScope.scrollTop = tree.scrollTop; previousScope.scrollLeft = tree.scrollLeft;}
        if (refresh || !previous || previous.collection !== state.sourceCollection) nav.model = sourceTreeModel(state.sourceCollection);
        const model = nav.model, scope = sourceTreeScope(nav, model.collection);
        // Deleted branches cannot grow an unbounded preference history.
        for (const key of scope.collapsed) if (!model.nodes.get(key)?.children) scope.collapsed.delete(key);
        const {visible, limited} = sourceTreeVisible(model, scope.collapsed);
        const keys = new Set(visible.map(node => node.key));
        const nearest = key => {
          for (let count = 0; key && count <= SOURCE_TREE_LIMITS.depth + 3; count++) {
            if (keys.has(key)) return key;
            key = (model.nodes.get(key) ?? previous?.nodes.get(key))?.parent;
          }
          return null;
        };
        const selectedCandidates = [...model.nodes.values()].filter(node => node.source && node.source.artifact_id === state.selectedArtifactId);
        // Selection must agree with the authoritative raw catalog, including
        // records omitted by path/node limits. Never scan beyond the catalog cap
        // merely to decorate a row: an incomplete catalog cannot prove uniqueness.
        const selected = !model.limits.catalog && selectedCandidates.length === 1 && !selectedCandidates[0].ambiguous &&
          keys.has(selectedCandidates[0].key) && sourceIsCurrent(selectedCandidates[0].source) ? selectedCandidates[0] : null;
        scope.focus = nearest(hadFocus ? activeKey : scope.focus) ?? selected?.key ?? visible[0]?.key ?? null;
        const containers = new Map([[tree, []]]);
        for (const node of visible) {
          let entry = nav.rows.get(node.key);
          if (!entry) {entry = sourceTreeRow(node, nav); nav.rows.set(node.key, entry);}
          const {row, icon, name, detail, group} = entry;
          row.style.setProperty('--source-depth', String(Math.min(node.depth, 6)));
          row.setAttribute('aria-level', String(node.depth + 1));
          row.setAttribute('aria-posinset', String(node.position)); row.setAttribute('aria-setsize', String(node.size));
          row.tabIndex = scope.focus === node.key ? 0 : -1;
          const label = node.label.length > 512 ? node.label.slice(0, 509) + '…' : node.label;
          if (name.textContent !== label) name.textContent = label;
          name.title = node.source?.url || node.label;
          row.setAttribute('aria-label', label);
          icon.className = node.source ? `source-file-icon ${node.source.kind}` : 'tree-glyph';
          icon.textContent = node.source ? sourceIcon(node.source) : scope.collapsed.has(node.key) ? '›' : '⌄';
          icon.title = node.source ? sourceKindLabel(node.source.kind)?.[1] ?? node.source.kind : '';
          detail.textContent = node.children ? String(node.count) : sourceDisplayMeta(node.source);
          if (node.source) {
            row.dataset.artifactId = node.source.artifact_id;
            row.setAttribute('aria-selected', String(node === selected));
          } else {
            row.setAttribute('aria-expanded', String(!scope.collapsed.has(node.key)));
            group.hidden = scope.collapsed.has(node.key); containers.set(group, []);
          }
          const container = node.parent ? nav.rows.get(node.parent).group : tree;
          containers.get(container).push(row);
          if (group) containers.get(container).push(group);
        }
        const notices = [];
        if (model.limits.catalog) notices.push(`Only the first ${SOURCE_TREE_LIMITS.catalog.toLocaleString()} catalog records were inspected; ${model.limits.catalog.toLocaleString()} more records are outside this navigator. Selection markers are withheld until the full catalog fits this limit.`);
        if (model.limits.omitted) notices.push(`${model.limits.omitted} sources exceed the navigator path, identity or node limit and are not listed.`);
        if (model.limits.ambiguous) notices.push(`${model.limits.ambiguous} duplicate source identities are not shown twice; ambiguous sources cannot be opened.`);
        if (model.limits.deep) notices.push(`${model.limits.deep} paths are shortened after ${SOURCE_TREE_LIMITS.depth} folders; file tooltips retain their full URLs.`);
        if (limited) notices.push(`Showing the first ${SOURCE_TREE_LIMITS.visible.toLocaleString()} expanded rows. Collapse branches to see later rows, or use Open file.`);
        if (!visible.length || notices.length) {
          nav.notice ??= document.createElement('div'); nav.notice.className = 'source-tree-empty'; nav.notice.setAttribute('role', 'status');
          nav.notice.textContent = notices.join(' ') || 'No source artifacts captured. Canvas images are shown in Fingerprinting.';
          // Keep limit disclosures above the rows, including when the navigator
          // itself is empty after filtering or rejecting over-limit paths.
          containers.get(tree).unshift(nav.notice);
        }
        for (const [container, children] of containers) {
          const wanted = new Set(children);
          for (const child of [...container.children]) if (!wanted.has(child)) child.remove();
          children.forEach((child, index) => {if (container.children[index] !== child) container.insertBefore(child, container.children[index] ?? null);});
        }
        for (const [key, entry] of nav.rows) if (!keys.has(key)) {entry.row.remove(); entry.group?.remove(); nav.rows.delete(key);}
        nav.visible = visible;
        tree.tabIndex = visible.length ? -1 : 0;
        tree.scrollTop = scope.scrollTop; tree.scrollLeft = scope.scrollLeft;
        if (anchor && nav.rows.has(anchor.key)) {
          const bounds = nav.rows.get(anchor.key).row.getBoundingClientRect();
          tree.scrollTop += bounds.top - tree.getBoundingClientRect().top - anchor.offset;
        }
        if (hadFocus) {
          if (scope.focus) sourceTreeFocus(scope.focus, Boolean(activeKey && activeKey !== scope.focus));
          else tree.focus({preventScroll: true});
        }
      }

      function renderSourceHealth() {
        const notices = [];
        if (state.artifactReceiverConfigured && !state.artifactReceiverConnected) {
          const retained = state.artifacts.filter(artifact => artifact.origin !== 'sample').length;
          notices.push(`Artifact capture is unavailable: the receiver socket is missing. ${retained} captured artifact${retained === 1 ? '' : 's'} remain readable; new artifacts will not appear until the receiver reconnects.`);
        } else if (state.artifactReceiverError) {
          notices.push(`Artifact capture health could not be checked: ${state.artifactReceiverError}`);
        }
        if (state.sourceNotice) notices.push(state.sourceNotice);
        elements.sourceHealth.hidden = notices.length === 0;
        elements.sourceHealth.dataset.kind = state.sourceNoticeKind === 'error' ||
          (state.artifactReceiverConfigured && !state.artifactReceiverConnected) ? 'error' : 'warning';
        elements.sourceHealth.textContent = notices.join(' ');
      }

      function renderSourceTabs() {
        const focusedIdentity = elements.sourceEditorTabs.contains(document.activeElement) ? document.activeElement.dataset.sourceIdentity : null;
        const index = (sources, field) => {
          const result = new Map();
          for (const source of sources) result.set(source[field], result.has(source[field]) ? null : sourceReference(source));
          return result;
        };
        const captured = index(capturedSources(), 'artifact_id');
        const sources = state.openArtifactIds.map(id => captured.get(id)).filter(Boolean);
        if (sources.length === 0) {
          const placeholder = document.createElement('span');
          placeholder.className = 'source-tab-placeholder';
          placeholder.textContent = 'No file open';
          elements.sourceEditorTabs.replaceChildren(placeholder);
          return;
        }
        const tabs = sources.map((source, index) => {
          const tab = document.createElement('button');
          tab.type = 'button';
          tab.className = 'source-editor-tab';
          tab.setAttribute('role', 'tab');
          tab.setAttribute('aria-label', `${sourceDisplayName(source)}. Press Delete to close.`);
          tab.setAttribute('aria-keyshortcuts', 'Delete');
          tab.dataset.sourceIdentity = sourceIdentity(source);
          tab.title = source.url || sourceDisplayName(source);
          const selected = source.artifact_id === state.selectedArtifactId;
          tab.setAttribute('aria-selected', String(selected));
          tab.tabIndex = selected ? 0 : -1;
          const icon = document.createElement('span');
          icon.className = `source-file-icon ${source.kind}`;
          icon.textContent = sourceIcon(source);
          icon.title = sourceKindLabel(source.kind)?.[1] ?? source.kind;
          const name = document.createElement('span');
          name.textContent = sourceDisplayName(source);
          name.title = source.url || sourceDisplayName(source);
          const close = document.createElement('span');
          close.className = 'source-tab-close';
          close.textContent = '×';
          close.setAttribute('aria-hidden', 'true');
          const kind = document.createElement('span'); kind.className = 'source-tab-kind'; kind.textContent = 'captured';
          tab.append(icon, name, kind, close);
          tab.addEventListener('click', event => {
            if (event.target === close) {
              closeSource(source);
              return;
            }
            selectArtifact(source.artifact_id);
          });
          tab.addEventListener('keydown', event => {
            const keys = ['ArrowLeft', 'ArrowRight', 'Home', 'End', 'Delete'];
            if (!keys.includes(event.key)) return;
            event.preventDefault();
            if (event.key === 'Delete') {
              closeSource(source);
              (elements.sourceEditorTabs.querySelector('[aria-selected="true"]') ?? elements.sourceTree.querySelector('button'))?.focus({preventScroll: true});
              return;
            }
            const next = event.key === 'Home' ? 0 : event.key === 'End' ? sources.length - 1
              : (index + (event.key === 'ArrowRight' ? 1 : -1) + sources.length) % sources.length;
            selectArtifact(sources[next].artifact_id);
            elements.sourceEditorTabs.querySelector('[aria-selected="true"]')?.focus({preventScroll: true});
          });
          return tab;
        });
        elements.sourceEditorTabs.replaceChildren(...tabs);
        if (focusedIdentity) tabs.find(tab => tab.dataset.sourceIdentity === focusedIdentity)?.focus({preventScroll: true});
        const selectedTab = tabs.find(tab => tab.getAttribute('aria-selected') === 'true');
        if (selectedTab) {
          const tabBounds = selectedTab.getBoundingClientRect();
          const stripBounds = elements.sourceEditorTabs.getBoundingClientRect();
          if (tabBounds.left < stripBounds.left) elements.sourceEditorTabs.scrollLeft += tabBounds.left - stripBounds.left;
          else if (tabBounds.right > stripBounds.right) elements.sourceEditorTabs.scrollLeft += tabBounds.right - stripBounds.right;
        }
      }

      function renderSourceFacts(source) {
        if (!source) {
          elements.artifactFacts.textContent = 'Select a source to inspect capture or runtime metadata.';
          return;
        }
        const list = document.createElement('dl');
        list.className = 'artifact-facts';
        const facts = [
          ['Artifact', source.artifact_id], ['Kind', source.kind], ['Session', source.session_id],
          ['Navigation', source.navigation_id], ['Frame', source.frame_id], ['Creator', source.creator_event_id],
          ['Context', source.execution_context_id ?? 'unreported'],
          ['Origin', source.capture_origin?.replaceAll('_', ' ') ?? 'legacy capture'],
          ['Parent', source.parent_artifact_id], ['MIME', source.mime_type], ['SHA-256', source.sha256],
          ['Sensitive', source.sensitive ? 'approved' : 'no']
        ];
        const wasm = source.kind === 'wasm' ? state.wasmCache.get(wasmKey(source)) : null;
        if (wasm) facts.push(['Inspection', wasm.notice], ['Coverage', wasm.status === 'partial' ? wasm.omissions.join(' ') : 'All sections and function bodies decoded.'], ['Limits', '2 MiB input, 8,192 rows, 128 sections, 2 seconds.']);
        facts.forEach(([label, value]) => {
          const term = document.createElement('dt'); term.textContent = label;
          const detail = document.createElement('dd'); detail.textContent = String(value);
          list.append(term, detail);
        });
        elements.artifactFacts.replaceChildren(list);
      }

      function appendSourceSyntax(container, tokens) {
        const fragment = document.createDocumentFragment();
        tokens.forEach(token => {
          if (token.type === 'plain') fragment.append(document.createTextNode(token.text));
          else {
            const span = document.createElement('span');
            span.className = `syntax-${token.type}`;
            span.textContent = token.text;
            fragment.append(span);
          }
        });
        container.replaceChildren(fragment);
      }

      function sourceOccurrenceRange(text, match) {
        const walker = document.createTreeWalker(text, NodeFilter.SHOW_TEXT);
        const range = document.createRange();
        let offset = 0;
        let started = false;
        while (walker.nextNode()) {
          const node = walker.currentNode;
          const end = offset + node.textContent.length;
          if (!started && match.column < end) {
            range.setStart(node, match.column - offset);
            started = true;
          }
          if (started && match.column + match.length <= end) {
            range.setEnd(node, match.column + match.length - offset);
            return range;
          }
          offset = end;
        }
        return null;
      }

      function applySourceSearch(reset = true, direction = 0, {reveal = true} = {}) {
        const query = elements.sourceSearch.value;
        let editor = state.sourceEditorView;
        const source = selectedSource();
        const status = message => {if (elements.sourceSearchStatus) elements.sourceSearchStatus.textContent = message;};
        globalThis.CSS?.highlights?.delete('source-search-match');
        if (!editor || editor.identity !== sourceIdentity(source) || elements.sourceCode.hidden) {
          state.sourceSearchIndex = 0;
          if (query) elements.sourcePosition.textContent = 'Source text unavailable; nothing searched.';
          status('Load or explicitly retry this source to search its retained text.');
          return;
        }
        const coverage = editor.view.searchCoverage ?? 'Retained source text';
        const incomplete = Boolean(editor.view.searchIncomplete || !editor.index.complete);
        if (!query) {
          state.sourceSearchIndex = 0;
          elements.sourceCode.querySelectorAll('.source-line[data-line]').forEach(row => row.classList.toggle('search-match', false));
          elements.sourcePosition.textContent = `Line ${editor.window.line + 1}, Column ${editor.window.column + 1}`;
          status(`${coverage}. Find is a case-insensitive, single-line literal; no source is fetched.`);
          return;
        }
        if (editor.search?.query !== query) {
          editor.search = {query, ...sourceDocumentMatches(editor.index, query, 1000,
            editor.view.wasmRows ? line => editor.view.wasmRows[line]?.byte_offset != null : null)};
        }
        const {matches, truncated, error} = editor.search;
        if (error) {elements.sourcePosition.textContent = error; status(coverage); return;}
        const matchingLines = new Set(matches.map(match => match.line));
        const highlightRows = () => elements.sourceCode.querySelectorAll('.source-line[data-line]').forEach(row =>
          row.classList.toggle('search-match', matchingLines.has(Number(row.dataset.localLine))));
        if (!matches.length) {
          state.sourceSearchIndex = 0; highlightRows();
          elements.sourcePosition.textContent = editor.view.wasmRows ? `0 matches in retained inspection rows; original module bytes were not searched.${incomplete ? ' Inspection coverage is incomplete.' : ''}`
            : incomplete ? '0 matches in the searched display; source coverage is incomplete.' : '0 matches in complete retained text.';
          status(`${coverage}.${editor.index.complete ? '' : ' Search stopped at the 8 Mi UTF-16-unit bound.'}`);
          return;
        }
        state.sourceSearchIndex = reset ? 0 : (state.sourceSearchIndex + direction + matches.length) % matches.length;
        const match = matches[state.sourceSearchIndex];
        if (reveal) {
          // Mount only the matched line/column window. Never enter the full
          // Sources route, which can start explicitly selected analysis.
          renderSourceContent(source, editor.view, {line: match.line, column: match.column, search: false});
          editor = state.sourceEditorView;
        }
        highlightRows();
        const row = elements.sourceCode.querySelector(`[data-local-line="${match.line}"]`);
        const line = match.line;
        const column = match.column;
        elements.sourcePosition.textContent = `${state.sourceSearchIndex + 1} of ${matches.length}${truncated ? '+' : ''} matches · ${editor.view.wasmRows ? 'Inspection row' : 'Line'} ${line + 1}, Column ${column + 1}`;
        status(`${coverage}.${truncated ? ' First 1,000 matches; refine Find for later matches.' : ''}${editor.index.complete ? '' : ' Search stopped at the 8 Mi UTF-16-unit bound.'}`);
        if (!row) return;
        const localColumn = match.column - Number(row.dataset.columnStart ?? 0);
        if (localColumn < 0 || localColumn + match.length > row.querySelector('.source-text').textContent.length) return;
        const range = sourceOccurrenceRange(row.querySelector('.source-text'), {...match, column: localColumn});
        if (!range) return;
        if (globalThis.Highlight && globalThis.CSS?.highlights) CSS.highlights.set('source-search-match', new Highlight(range));
        if (!reveal) return;
        const rect = range.getBoundingClientRect();
        const viewport = elements.sourceCodeWrap.getBoundingClientRect();
        elements.sourceCodeWrap.scrollLeft += rect.left - viewport.left - Math.min(120, viewport.width / 4);
        elements.sourceCodeWrap.scrollTop += rect.top - viewport.top - viewport.height / 2;
      }

      function revealSourceColumn(row, column, focus = false) {
        if (!row) return;
        if (focus) {row.tabIndex = -1; row.focus({preventScroll: true});}
        row.scrollIntoView({block: 'center', inline: 'nearest'});
        const text = row.querySelector('.source-text');
        if (!text?.textContent.length) return;
        const offset = column - Number(row.dataset.columnStart ?? 0);
        if (offset < 0 || offset > text.textContent.length) return;
        // The final column is an empty caret after the last scalar. Reveal its
        // neighboring glyph without changing the requested absolute location.
        const visible = Math.min(offset, text.textContent.length - 1);
        const range = sourceOccurrenceRange(text, {column: visible, length: 1});
        if (!range) return;
        const bounds = range.getBoundingClientRect(), viewport = elements.sourceCodeWrap.getBoundingClientRect();
        elements.sourceCodeWrap.scrollLeft += bounds.left - viewport.left - Math.min(120, viewport.width / 4);
      }

      function renderSourceWindowControls(editor = state.sourceEditorView) {
        if (!elements.sourceWindow) return;
        elements.sourceWindow.hidden = !editor;
        if (!editor) return;
        const {window: window, index} = editor;
        elements.sourceWindowLabel.textContent = `Lines ${window.start + 1}–${window.end} of ${index.lineCount}${index.complete ? '' : '+'}`;
        elements.sourceWindowPrevious.disabled = window.start === 0;
        elements.sourceWindowNext.disabled = window.end === index.lineCount;
        if (document.activeElement !== elements.sourceWindowLine) elements.sourceWindowLine.value = String(window.line + 1);
        if (document.activeElement !== elements.sourceWindowColumn) elements.sourceWindowColumn.value = String(Math.max(0, window.column) + 1);
        elements.sourceWindowLine.max = String(index.lineCount);
      }

      function moveSourceWindow(line, column = 0) {
        const editor = state.sourceEditorView, source = selectedSource();
        if (!editor || editor.identity !== sourceIdentity(source) || !Number.isSafeInteger(line) || line < 0 || line >= editor.index.lineCount ||
            !Number.isSafeInteger(column) || column < 0 || column > (sourceDocumentLine(editor.index, line)?.length ?? 0)) return false;
        renderSourceContent(source, editor.view, {line, column, search: false});
        applySourceSearch(false, 0, {reveal: false});
        elements.sourcePosition.textContent = `Line ${line + 1}, Column ${column + 1} · Retained display location`;
        const row = elements.sourceCode.querySelector(`[data-local-line="${line}"]`);
        revealSourceColumn(row, column, true);
        return true;
      }

      function sourceFormattedView(source, value, variant) {
        const key = `${sourceIdentity(source)}|${variant}`;
        const prior = state.sourceFormatCache.get(key);
        if (prior?.sourceInput === value) return prior;
        const formatted = {...prettyPrintSource(source, value), sourceInput: value};
        state.sourceFormatCache.set(key, formatted);
        boundSourceAnalysis(state.sourceFormatCache, 2, 6 * 1024 * 1024, 500000);
        return formatted;
      }

      function sourceDisplayView(source) {
        if (state.sourceWasm && source.kind === 'wasm' && source.source_type === 'artifact') {
          const report = state.wasmCache.get(wasmKey(source));
          if (report) {
            const headings = ['Static inspection. The module is never executed.', `${report.status === 'partial' ? 'Partial' : 'Decoded'} · ${report.sections} sections · ${report.imported_functions} imported · ${report.defined_functions} defined · ${report.instructions} instructions`, ...report.omissions];
            const rows = [...headings.map(text => ({text, byte_offset: null})), ...report.rows];
            return {content: rows.map(row => row.byte_offset === null ? `;; ${row.text}` : `${row.kind === 'instruction' ? `func ${row.function_index}`.padEnd(11) : row.kind.padEnd(11)} ${row.text}`).join('\n'), lineMap: null, wasmRows: rows,
              searchCoverage: 'Retained static inspection rows with original byte offsets; headings and omissions excluded; not original source text', searchIncomplete: report.status === 'partial'};
          }
        }
        const verifiedOriginal = sourceFactsPanel.original(source);
        const preview = source.content ?? '';
        const original = verifiedOriginal ?? (Number.isSafeInteger(source.sourceTextLength) ? preview.slice(0, source.sourceTextLength) : preview);
        const derived = state.sourceDeobfuscated && source.kind === 'javascript' ? sourceDerivedView(source) : null;
        const active = derived?.text ?? original;
        const formatResult = state.sourceFormatted
          ? sourceFormattedView(source, active, derived ? `derived:${deobfuscationKey(source)}` : 'original')
          : null;
        const formatted = formatResult && !formatResult.error ? formatResult : null;
        return {
          original,
          derived,
          active,
          formatted,
          formatError: formatResult?.error ?? null,
          content: formatted?.text ?? active,
          mapOriginal: derived ? source.deobfuscation.original_source : original,
          sourceVersion: derived ? source.deobfuscation.sourceWindowVersion : null,
          searchIncomplete: verifiedOriginal === undefined && !derived && Boolean(source.contentTruncated || source.contentLossy),
          searchCoverage: derived ? 'Complete retained derived text; transformation coverage is separate'
            : verifiedOriginal !== undefined ? 'Complete hash-verified original text'
              : source.contentLossy ? 'Lossy retained display only; absence in original bytes is unproven'
                : source.contentTruncated ? 'Retained prefix only; the rest of the source was not searched'
                  : 'Complete retained source text'
        };
      }

      function retrySourcePreview(source) {
        const identity = sourceIdentity(source);
        if (sourceIdentity(selectedSource()) !== identity || !sourceIsCurrent(source)) return;
        if (source.source_type === 'artifact') loadArtifactContent(state.artifacts.find(value => sourceIdentity(value) === identity), {retry: true});
      }

      function renderSourceContent(source, view = null, target = {}) {
        const identity = sourceIdentity(source);
        const resetEditor = () => {state.sourceEditorView = null; elements.sourceCode.replaceChildren(); renderSourceWindowControls(null);
          if (elements.sourceSearchStatus) elements.sourceSearchStatus.textContent = 'Source text unavailable; nothing searched.';
          if (elements.sourcePosition) elements.sourcePosition.textContent = '';};
        if (!source) {
          resetEditor();
          elements.sourceLanguage.textContent = 'Plain text';
          elements.sourceCode.hidden = true;
          elements.sourceCodeEmpty.hidden = false;
          elements.sourceCodeEmpty.textContent = 'Select a JavaScript file, WASM module, source map, or approved response body.';
          return;
        }
        if (state.sourceWasm && source.kind === 'wasm' && source.source_type === 'artifact' && !state.wasmCache.has(wasmKey(source))) {
          const request = state.wasmRequests.get(wasmKey(source));
          resetEditor();
          elements.sourceLanguage.textContent = 'WebAssembly';
          elements.sourceCode.hidden = true;
          elements.sourceCodeEmpty.hidden = false;
          const pending = request?.status === 'loading';
          const message = request?.status === 'error' ? request.error : pending ? 'Inspecting immutable module bytes…'
            : 'This inspection preview was released to keep Sources memory bounded. Inspect the immutable module again.';
          elements.sourceCodeEmpty.textContent = message;
          if (!pending) {
            const retry = textElement('button', 'secondary-button', 'Retry inspection');
            retry.type = 'button';
            retry.addEventListener('click', loadWasmInspection.bind(null, sourceReference(source), true));
            const panel = document.createElement('div');
            panel.className = 'wasm-inspection-error';
            panel.setAttribute('role', 'alert');
            panel.append(textElement('p', '', message), retry);
            elements.sourceCodeEmpty.replaceChildren(panel);
          }
          return;
        }
        if (source.loading && sourceFactsPanel.original(source) === undefined) {
          resetEditor();
          elements.sourceLanguage.textContent = 'Detecting syntax';
          elements.sourceCode.hidden = true;
          elements.sourceCodeEmpty.hidden = false;
          elements.sourceCodeEmpty.textContent = 'Loading immutable artifact bytes…';
          return;
        }
        if ((source.loadError || source.content === undefined) && sourceFactsPanel.original(source) === undefined) {
          resetEditor();
          elements.sourceLanguage.textContent = 'Unavailable';
          elements.sourceCode.hidden = true;
          elements.sourceCodeEmpty.hidden = false;
          const retry = textElement('button', 'secondary-button', 'Retry source');
          retry.type = 'button';
          retry.addEventListener('click', retrySourcePreview.bind(null, sourceReference(source)));
          elements.sourceCodeEmpty.replaceChildren(document.createTextNode(source.loadError || 'This preview was released to keep Sources memory bounded. Reopen its immutable bytes.'), retry);
          if (source.loadError) elements.sourcePosition.textContent = 'Preview unavailable. The previous caret does not apply to this file.';
          return;
        }
        view ??= sourceDisplayView(source);
        const content = view.content;
        const representation = JSON.stringify([identity, state.sourceWasm, state.sourceDeobfuscated, state.sourceFormatted,
          state.sourceDeobfuscated ? deobfuscationKey(source) : null]);
        const mapping = view.wasmRows ? state.wasmCache.get(wasmKey(source)) : view.derived ?? null;
        const formatting = view.formatted ?? null;
        const previous = state.sourceEditorView;
        const sameDocument = previous?.representation === representation && previous.content === content && previous.mapping === mapping && previous.formatting === formatting;
        const index = sameDocument ? previous.index : sourceDocumentIndex(content);
        const savedWindow = state.sourceWindow?.identity === identity && state.sourceWindow.representation === representation ? state.sourceWindow : null;
        const requestedLine = target.line ?? savedWindow?.line ?? 0;
        const requestedColumn = target.column ?? savedWindow?.column ?? 0;
        const clampedLine = Math.max(0, Math.min(index.lineCount - 1, Number.isSafeInteger(requestedLine) ? requestedLine : 0));
        const window = sameDocument && previous.window.line === clampedLine && previous.window.column === requestedColumn
          ? previous.window : sourceDocumentWindow(index, clampedLine, requestedColumn);
        state.sourceWindow = {identity, representation, line: window.line, column: window.column};
        const sameWindow = sameDocument && previous.window.line === window.line && previous.window.column === window.column;
        if (sameWindow) {
          const coverageChanged = previous.view.searchCoverage !== view.searchCoverage || previous.view.searchIncomplete !== view.searchIncomplete;
          previous.view = view;
          renderSourceWindowControls(previous);
          if (coverageChanged && target.search !== false) applySourceSearch(false, 0, {reveal: false});
          return;
        }
        elements.sourceCodeEmpty.replaceChildren();
        const sameOwner = sameDocument && previous.window.start === window.start;
        const scroll = {top: elements.sourceCodeWrap.scrollTop, left: elements.sourceCodeWrap.scrollLeft};
        const focused = elements.sourceCode.contains(document.activeElement)
          ? {line: document.activeElement.closest('.source-line')?.dataset.line, gutter: document.activeElement.classList.contains('source-gutter')} : null;
        const mappingContext = sameDocument ? previous.mappingContext : view.lineMap ? null : sourceWindowMapping(view.mapOriginal ?? '', view.active ?? '', view.derived, view.formatted);
        const mappedLines = mappingContext?.(window.rows);
        if (!sameDocument) state.sourceSearchIndex = 0;
        state.sourceEditorView = {identity, representation, content, mapping, formatting, index, window, view, mappingContext,
          search: sameDocument ? previous.search : null};
        const lineMap = view.lineMap;
        // Later/column-clipped windows cannot assume the lexical state of an omitted prefix.
        const plainWindow = window.start > 0 || window.rows.some(row => row.columnStart > 0 || row.columnEnd < row.fullLength);
        const tokenizer = createSourceTokenizer(view.wasmRows || plainWindow ? {kind: 'plain', mime_type: 'text/plain'} : source);

        const nodes = window.rows.map((excerpt, rowIndex) => {
          const {text: line, line: index} = excerpt;
          const mapped = lineMap ? lineMap[index] ?? null : mappedLines?.[rowIndex] ?? null;
          const mappedLine = mapped?.originalLine ?? null;
          const row = document.createElement('span');
          row.className = 'source-line';
          row.dataset.line = String(index + 1);
          row.dataset.localLine = String(index);
          row.dataset.columnStart = String(excerpt.columnStart);
          const gutter = document.createElement('button');
          gutter.type = 'button';
          gutter.className = 'source-gutter';
          gutter.textContent = String((mappedLine ?? index) + 1);
          gutter.disabled = mappedLine === null;
          gutter.title = mappedLine === null ? 'Retained source line' : `Show original source at line ${mappedLine + 1}`;
          gutter.setAttribute('aria-label', gutter.title);
          gutter.addEventListener('click', event => {
            event.stopPropagation();
            if (!view.wasmRows && mappedLine !== null) revealOriginalLine(source, mappedLine, mapped?.originalColumn ?? 0);
          });
          if (view.wasmRows) {
            const offset = view.wasmRows[index]?.byte_offset;
            gutter.textContent = offset == null ? '' : offset.toString(16).padStart(6, '0');
            const hexLimit = source.wasmHexBytes ?? wasmHexByteLimit();
            gutter.disabled = offset == null || offset >= hexLimit;
            gutter.setAttribute('aria-label', offset == null ? 'Inspection notice' : `Show original bytes at offset ${offset}`);
            gutter.title = offset == null ? '' : offset >= hexLimit ? `Byte offset ${offset} is beyond the ${hexLimit} hex bytes formatted in Sources` : `Original byte offset ${offset} (0x${offset.toString(16)})`;
            gutter.addEventListener('click', () => {
              if (offset == null) return;
              state.sourceWasm = false;
              renderSources();
              moveSourceWindow(Math.floor(offset / 16));
              const hexRow = elements.sourceCode.querySelector(`[data-local-line="${Math.floor(offset / 16)}"]`);
              if (hexRow) { hexRow.tabIndex = -1; hexRow.focus({preventScroll: true}); hexRow.scrollIntoView({block: 'center'}); }
            });
          }
          const text = document.createElement('span');
          text.className = 'source-text';
          appendSourceSyntax(text, line ? sourceSyntaxTokens(line, tokenizer) : []);
          const displayed = document.createElement('span'); displayed.className = 'source-excerpt';
          if (excerpt.columnStart) displayed.append(textElement('span', 'source-excerpt-notice', `⟪ columns 1–${excerpt.columnStart} omitted ⟫ `));
          displayed.append(text);
          if (excerpt.columnEnd < excerpt.fullLength) displayed.append(textElement('span', 'source-excerpt-notice', ` ⟪ columns ${excerpt.columnEnd + 1}–${excerpt.fullLength} omitted; use Find or Go to column ⟫`));
          row.append(gutter, displayed);
          return row;
        });
        elements.sourceCode.replaceChildren(...nodes);
        elements.sourceLanguage.textContent = view.wasmRows ? 'WASM disassembly · byte offsets' : `${sourceSyntaxLabel(tokenizer.language)}${plainWindow ? ' · bounded excerpt; omitted lexical context' : tokenizer.truncated ? ' · color limit reached' : ''}`;
        elements.sourceCode.hidden = false;
        elements.sourceCodeEmpty.hidden = true;
        renderSourceWindowControls();
        if (sameOwner) {
          elements.sourceCodeWrap.scrollTop = scroll.top;
          elements.sourceCodeWrap.scrollLeft = scroll.left;
          const row = [...elements.sourceCode.children].find(value => value.dataset.line === focused?.line);
          const target = focused?.gutter ? row?.querySelector('.source-gutter') : row;
          if (target) {target.tabIndex = -1; target.focus({preventScroll: true});}
        } else {
          elements.sourceCodeWrap.scrollTop = 0;
          elements.sourceCodeWrap.scrollLeft = 0;
          if (target.search !== false) applySourceSearch(false, 0, {reveal: false});
        }
      }

      function renderSources() {
        const source = selectedSource();
        sourceFactsPanel.sync(source);
        syncInvestigationRange(source);
        const view = source?.content !== undefined ? sourceDisplayView(source) : null;
        document.querySelectorAll('[data-source-collection]').forEach(tab => {
          const selected = tab.dataset.sourceCollection === state.sourceCollection;
          tab.setAttribute('aria-selected', String(selected));
          tab.tabIndex = selected ? 0 : -1;
        });
        elements.sourceTree.setAttribute('aria-labelledby', `source-tab-${state.sourceCollection}`);
        renderSourceHealth();
        renderSourceTree();
        renderSourceTabs();
        renderSourceFacts(source);
        elements.sourceLocation.textContent = source?.url || (source ? sourceDisplayName(source) : 'Select a source');
        elements.sourceLocation.title = source?.url || (source ? sourceDisplayName(source) : '');
        elements.sourceSize.textContent = source ? formatByteSize(source.byte_size) : '0 bytes';
        elements.sourceHash.textContent = source?.sha256 ? `sha256 ${source.sha256}` : '';
        syncSourceDisplayControls(source, view);
        renderSourceContent(source, view);
        if (!investigationPassiveSource && state.sourceDeobfuscated && source?.kind === 'javascript' && !document.querySelector('#screen-sources').hidden) loadDeobfuscation(source);
        renderDeobfuscationReport(source);
        resumeInvestigationReturn();
      }

      function syncSourceDisplayControls(source, view) {
        elements.sourceViewKind.textContent = sourceViewLabel(source, view);
        elements.sourceWasm.hidden = source?.kind !== 'wasm' || source?.source_type !== 'artifact';
        elements.sourceWasm.setAttribute('aria-pressed', String(state.sourceWasm));
        elements.sourceWasm.setAttribute('aria-label', state.sourceWasm ? 'Show original WASM hex' : 'Inspect WebAssembly module');
        elements.sourceWasm.textContent = state.sourceWasm ? 'Hex' : 'Inspect';
        elements.sourceCode.classList.toggle('wasm-inspection', Boolean(view?.wasmRows));
        elements.sourcePretty.disabled = !source?.content || !sourcePrettySupported(source);
        elements.sourcePretty.setAttribute('aria-pressed', String(state.sourceFormatted));
        elements.sourcePretty.setAttribute('aria-label', state.sourceFormatted ? 'Show source without pretty printing' : 'Pretty print source');
        elements.sourcePretty.title = state.sourceFormatted ? 'Show source without pretty printing' : `Pretty print ${sourceSyntaxLabel(sourceSyntaxLanguage(source))}`;
        elements.sourceDeob.disabled = source?.kind !== 'javascript' || !source.content;
        elements.sourceDeob.setAttribute('aria-pressed', String(state.sourceDeobfuscated));
        elements.sourceDeob.setAttribute('aria-label', state.sourceDeobfuscated ? 'Show original evidence' : 'Run local static cleanup');
        elements.sourceDeob.title = state.sourceDeobfuscated ? 'Show original evidence' : 'Run local static cleanup';
        elements.sourceDeob.textContent = state.sourceDeobfuscated ? 'Original' : 'Static cleanup';

      }

      function sourceViewLabel(source, view = null) {
        if (source && source.content === undefined && source.loadError) return 'Preview unavailable';
        if (source && source.content === undefined && source.loading) return 'Preview loading';
        if (state.sourceWasm && source?.kind === 'wasm' && source.source_type === 'artifact') {
          const report = state.wasmCache.get(wasmKey(source));
          const request = state.wasmRequests.get(wasmKey(source));
          return report ? `${report.status === 'partial' ? 'Partial' : 'Static'} inspection · original byte offsets` : request?.status === 'error' ? 'Inspection failed · original bytes preserved' : request?.status === 'loading' ? 'Inspection pending' : 'Inspection preview released';
        }
        view ??= source?.content !== undefined ? sourceDisplayView(source) : null;
        const original = sourceFactsPanel.original(source) !== undefined ? 'Verified original evidence'
          : `Original evidence preview${source?.contentLossy ? ' · lossy UTF-8 display' : ''}${source?.contentTruncated ? ' · truncated' : ''}`;
        if (view?.formatError) return `${original} · ${view.formatError}`;
        if (state.sourceDeobfuscated && sourceDerivedView(source)) {
          const status = state.deobfuscationRequests.get(deobfuscationKey(source))?.status;
          return `${state.sourceFormatted ? 'Pretty printed derived' : 'Derived'} · mapped to original source${status === 'error' ? ' · last successful analysis' : status === 'loading' ? ' · reanalyzing' : status === 'cancelled' ? ' · analysis cancelled' : ''}`;
        }
        if (!state.sourceDeobfuscated || !source) {
          return state.sourceFormatted && source ? `Pretty printed ${original.toLowerCase()} · mapped to original source` : original;
        }
        const request = state.deobfuscationRequests.get(deobfuscationKey(source));
        const prefix = state.sourceFormatted ? `Pretty printed ${original.toLowerCase()}` : original;
        return `${prefix} · ${request?.status === 'error' ? 'analysis failed' : request?.status === 'cancelled' ? 'analysis cancelled' : 'analysis pending'}`;
      }

      function sourceDerivedView(source) {
        return source?.deobfuscation?.representation ?? null;
      }

      function revealOriginalLine(source, line, column) {
        if (sourceIdentity(selectedSource()) !== sourceIdentity(source)) return;
        state.sourceDeobfuscated = false;
        state.sourceFormatted = false;
        const view = sourceDisplayView(source);
        renderSourceContent(source, view, {line, column: column ?? 0, search: false});
        syncSourceDisplayControls(source, view);
        renderDeobfuscationReport(source);
        applySourceSearch(false, 0, {reveal: false});
        const row = [...elements.sourceCode.querySelectorAll('.source-line')].find(candidate => Number(candidate.dataset.line) === line + 1);
        if (row) {
          revealSourceColumn(row, column ?? 0, true);
          elements.sourcePosition.textContent = `Original line ${line + 1}, Column ${(column ?? 0) + 1}`;
        } else {
          elements.sourcePosition.textContent = `Original line ${line + 1} is outside the displayed preview. Facts can read verified original-byte ranges.`;
        }
      }

      function revealSourceFactRange(source, range, position) {
        if (sourceFactsIdentity(selectedSource()) !== sourceFactsIdentity(source)) return;
        // This uses separately hash-verified, strict UTF-8 original bytes, never
        // a lossy preview or derived text.
        if (getComputedStyle(elements.sourceSidebar).position === 'absolute') {
          state.sourceSidebarOpen = false;
          renderSourceSidebar();
        }
        revealOriginalLine(source, position.line, position.column);
        const row = elements.sourceCode.querySelector(`[data-line="${position.line + 1}"]`);
        if (!row) throw new Error('This original range is outside the current source view.');
        const text = row.querySelector('.source-text');
        const displayColumn = position.column - Number(row.dataset.columnStart ?? 0);
        const highlight = sourceOccurrenceRange(text, {column: displayColumn,
          length: Math.min(position.length, text.textContent.length - displayColumn)});
        if (highlight && globalThis.Highlight && globalThis.CSS?.highlights) CSS.highlights.set('source-search-match', new Highlight(highlight));
        rememberInvestigationRange(source, range);
        elements.sourcePosition.textContent = `Original UTF-8 bytes [${range.start}, ${range.end}) · Line ${position.line + 1}, Column ${position.column + 1}${position.multiline ? ' · range continues on following lines' : ''}${position.length > text.textContent.length - displayColumn ? ' · highlight limited to displayed columns' : ''}`;
        if (highlight) {
          const bounds = highlight.getBoundingClientRect();
          const viewport = elements.sourceCodeWrap.getBoundingClientRect();
          elements.sourceCodeWrap.scrollLeft += bounds.left - viewport.left - Math.min(120, viewport.width / 4);
        }
      }

      function deobfuscationKey(source) {
        return `${sourceIdentity(source)}|intrinsics:${Boolean(state.deobfuscationAssumeIntrinsics)}`;
      }

      async function validateSourceAnalysis(payload, source, assumeIntrinsics) {
        const original = payload?.original_source;
        const representation = payload?.representation;
        const expectedAssumptions = assumeIntrinsics ? ['standard-intrinsics'] : [];
        if (payload?.schema !== 'deobfuscation-analysis-v1' || !['rust-oxc', 'python-lexical'].includes(payload.engine) || payload.mode !== 'derived' || payload.source_truncated !== false ||
            source.source_type !== 'artifact' || payload.artifact_id !== source.artifact_id || payload.script_id !== null ||
            typeof original !== 'string' || original.length > 4 * 1024 * 1024 ||
            !/^[0-9a-f]{64}$/.test(payload.analysis?.source?.sha256) ||
            !/^[0-9a-f]{64}$/.test(source.sha256) || payload.analysis.source.sha256 !== source.sha256 ||
            JSON.stringify(payload.analysis?.assumptions) !== JSON.stringify(expectedAssumptions) ||
            typeof representation?.text !== 'string' || representation.text.length > 4 * 1024 * 1024 + 512 * 1024 ||
            !Array.isArray(representation.segments) || representation.segments.length > 250000 ||
            !['utf-8-byte', 'unicode-code-point', undefined].includes(representation.offset_unit)) {
          throw new Error('The analyzer response does not match the submitted source and representation.');
        }
        const boundedText = (value, maximum = 4096) => typeof value === 'string' && value.length <= maximum;
        const rows = (value, check, maximum = 64) => value === undefined || (Array.isArray(value) && value.length <= maximum && value.every(check));
        const analysis = payload.analysis;
        if (!rows(analysis.omissions, value => boundedText(value)) ||
            !rows(analysis.classification?.evidence, value => value && boundedText(value.id, 128) && boundedText(value.detail)) ||
            (analysis.classification?.label !== undefined && !boundedText(analysis.classification.label, 128)) ||
            (analysis.source.lines !== undefined && (!Number.isSafeInteger(analysis.source.lines) || analysis.source.lines < 0 || analysis.source.lines > 4194305)) ||
            (analysis.representation?.status !== undefined && !boundedText(analysis.representation.status, 128)) ||
            (analysis.representation?.truncated !== undefined && typeof analysis.representation.truncated !== 'boolean') ||
            (representation.truncated !== undefined && typeof representation.truncated !== 'boolean') ||
            (analysis.representation?.segment_count !== undefined && analysis.representation.segment_count !== representation.segments.length) ||
            !rows(analysis.representation?.transformations, value => value && boundedText(value.id, 128) && boundedText(value.detail) && Number.isSafeInteger(value.count) && value.count >= 0 && value.count <= 4096) ||
            !rows(representation.transformations, value => value && boundedText(value.id, 128) && boundedText(value.detail) && Number.isSafeInteger(value.count) && value.count >= 0 && value.count <= 4096) ||
            (analysis.limits !== undefined && (!analysis.limits || Array.isArray(analysis.limits) || typeof analysis.limits !== 'object' ||
              Object.keys(analysis.limits).length > 32 || !Object.entries(analysis.limits).every(([key, value]) => boundedText(key, 128) && Number.isSafeInteger(value) && value >= 0))) ||
            !rows(analysis.string_tables, value => value && boundedText(value.kind, 128) && Number.isSafeInteger(value.offset) && value.offset >= 0 &&
              value.offset <= original.length && Number.isSafeInteger(value.entry_count) && value.entry_count >= 0 && value.entry_count <= 2048 && rows(value.encodings, entry => boundedText(entry, 128)) &&
              (value.decoded_preview === undefined || boundedText(value.decoded_preview)))) {
          throw new Error('The analyzer returned malformed or oversized report metadata.');
        }
        const bytes = new TextEncoder().encode(original);
        if (new TextDecoder('utf-8', {fatal: true, ignoreBOM: true}).decode(bytes) !== original ||
            bytes.length > 4 * 1024 * 1024 || payload.analysis.source.byte_size !== bytes.length ||
            (source.source_type === 'artifact' && bytes.length !== source.byte_size)) throw new Error('The analyzer source byte size changed.');
        if (!globalThis.crypto?.subtle) throw new Error('SHA-256 verification is unavailable in this workspace.');
        const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), byte => byte.toString(16).padStart(2, '0')).join('');
        if (hash !== payload.analysis.source.sha256 || (source.source_type === 'artifact' && hash !== source.sha256)) {
          throw new Error('The analyzer original bytes do not match their UTF-8 SHA-256.');
        }
        const segments = sourceSegmentsUTF16(original, representation.text, representation.segments, representation.offset_unit);
        const derivedBytes = new TextEncoder().encode(representation.text);
        if (new TextDecoder('utf-8', {fatal: true, ignoreBOM: true}).decode(derivedBytes) !== representation.text ||
            derivedBytes.length > 4 * 1024 * 1024 + 512 * 1024 ||
            (analysis.representation?.derived_bytes !== undefined && analysis.representation.derived_bytes !== derivedBytes.length) ||
            (payload.engine === 'rust-oxc' && representation.offset_unit !== 'utf-8-byte')) {
          throw new Error('The analyzer returned an invalid derived encoding or byte size.');
        }
        let end = 0, originalEnd = 0, synthetic = 0;
        const changes = [];
        for (const [index, segment] of segments.entries()) {
          if (!['verbatim', 'synthetic', 'replacement'].includes(segment.kind) ||
              ![segment.original_start, segment.original_end, segment.derived_start, segment.derived_end].every(Number.isSafeInteger) ||
              segment.derived_start !== end || segment.derived_end <= end || segment.derived_end > representation.text.length ||
              segment.original_start < originalEnd || (payload.engine === 'rust-oxc' && segment.original_start !== originalEnd) ||
              segment.original_end < segment.original_start || segment.original_end > original.length ||
              (segment.kind === 'synthetic' && segment.original_start !== segment.original_end) ||
              (segment.kind !== 'synthetic' && segment.original_start === segment.original_end) ||
              (segment.kind === 'verbatim' && original.slice(segment.original_start, segment.original_end) !== representation.text.slice(segment.derived_start, segment.derived_end))) {
            throw new Error('The analyzer returned an invalid original-source map.');
          }
          if (segment.kind === 'replacement') changes.push({index, original_start: segment.original_start, original_end: segment.original_end, derived_start: segment.derived_start, derived_end: segment.derived_end});
          if (segment.kind === 'synthetic') synthetic++;
          end = segment.derived_end; originalEnd = segment.original_end;
        }
        if (end !== representation.text.length || (payload.engine === 'rust-oxc' && originalEnd !== original.length) || changes.length > 4096) {
          throw new Error('The analyzer source map is incomplete or exceeds the change limit.');
        }
        if (payload.engine === 'rust-oxc') {
          for (const summary of [analysis.representation?.transformations, representation.transformations]) {
            if (summary && summary.reduce((total, entry) => total + entry.count, 0) !== changes.length) {
              throw new Error('The analyzer transformation counts do not match its mapped replacements.');
            }
          }
        }
        // Local admission metadata, never an analyzer-provided proof or duplicate source.
        const derivedSha256 = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', derivedBytes)), byte => byte.toString(16).padStart(2, '0')).join('');
        return {changes, synthetic, originalBytes: bytes.length, derivedBytes: derivedBytes.length, derivedSha256,
          byteRanges: payload.engine === 'rust-oxc' && representation.offset_unit === 'utf-8-byte'};
      }

      async function loadDeobfuscation(source, {retry = false} = {}) {
        const sourceId = source?.source_type === 'artifact' ? source.artifact_id : null;
        if (!sourceId || !sourceIsCurrent(source)) return;
        const key = deobfuscationKey(source);
        const identity = sourceIdentity(source);
        const assumeIntrinsics = Boolean(state.deobfuscationAssumeIntrinsics);
        const previous = state.deobfuscationRequests.get(key);
        if (previous?.status === 'loading' || (!retry && (['error', 'cancelled'].includes(previous?.status) || state.deobfuscationCache.has(key)))) return;
        retireSourceAnalysis();
        const controller = new AbortController();
        const request = {status: 'loading', error: null, identity, controller};
        state.deobfuscationRequests.set(key, request);
        renderSources();
        while (state.deobfuscationRequests.size > 128) state.deobfuscationRequests.delete(state.deobfuscationRequests.keys().next().value);
        const current = () => state.deobfuscationRequests.get(key) === request && request.status === 'loading' &&
          !controller.signal.aborted && sourceIsCurrent(source) && deobfuscationKey(source) === key;
        const timeout = setTimeout(() => {
          if (state.deobfuscationRequests.get(key) !== request || request.status !== 'loading') return;
          request.status = 'error'; request.error = 'Analysis timed out. Retry explicitly; original bytes are preserved.';
          controller.abort();
          if (sourceIdentity(selectedSource()) === identity) renderSources();
        }, 10000);
        try {
          const response = await fetch(`/api/deobfuscation?artifact_id=${encodeURIComponent(sourceId)}&mode=derived&assume_intrinsics=${assumeIntrinsics ? 1 : 0}`, {cache: 'no-store', signal: controller.signal});
          const bytes = await sourceFactsReadBytes(response, 33 * 1024 * 1024, controller.signal);
          if (!current()) return;
          if (bytes.length > 32 * 1024 * 1024) throw new Error('The analyzer response exceeds the retained-document budget.');
          const payload = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes));
          if (!response.ok) throw new Error(payload.error || `Deobfuscation analysis returned ${response.status}`);
          const inspection = await validateSourceAnalysis(payload, source, assumeIntrinsics);
          if (!current()) return;
          state.sourceAnalysisVersion = (state.sourceAnalysisVersion ?? 0) + 1;
          payload.sourceWindowVersion = state.sourceAnalysisVersion;
          payload.sourceInspection = inspection;
          payload.inspectorView = {change: 0, pages: {}, open: {}, notice: ''};
          payload.sourceDocumentBytes = bytes.length;
          if (payload.original_source.length + payload.representation.text.length > 8 * 1024 * 1024) {
            throw new Error('The analysis exceeds the retained-source budget.');
          }
          state.deobfuscationCache.delete(key);
          state.deobfuscationCache.set(key, payload);
          boundSourceAnalysis(state.deobfuscationCache, 8, 8 * 1024 * 1024, 250000);
          request.status = 'ready';
        } catch (error) {
          if (!current()) return;
          request.status = 'error';
          request.error = `Analysis unavailable: ${String(error.message).slice(0, 1024)} Original bytes are preserved.`;
        } finally {
          clearTimeout(timeout);
          delete request.controller;
          if (state.deobfuscationRequests.get(key) === request && request.status === 'loading') {
            request.status = 'error'; request.error = 'The source changed before analysis completed. Retry explicitly.';
          }
          if (sourceIdentity(selectedSource()) === identity) renderSources();
        }
      }

      function deobfuscationRow(label, value) {
        const row = document.createElement('div');
        row.className = 'deobfuscation-row';
        const name = document.createElement('strong');
        name.textContent = label;
        const detail = document.createElement('span');
        detail.textContent = value;
        row.append(name, ' ', detail);
        return row;
      }

      function deobfuscationOwner(reference, view = null) {
        const source = selectedSource();
        if (!source || !sourceIsCurrent(source) || sourceIdentity(source) !== sourceIdentity(reference) ||
            (reference.deobfuscationAssumption !== undefined && reference.deobfuscationAssumption !== Boolean(state.deobfuscationAssumeIntrinsics))) return null;
        const payload = source.deobfuscation;
        if (view && payload?.inspectorView !== view) return null;
        return {source, payload, key: deobfuscationKey(source)};
      }

      function cancelDeobfuscation(reference, pending = null) {
        const owner = deobfuscationOwner(reference);
        if (!owner) return;
        const request = state.deobfuscationRequests.get(owner.key);
        if (request?.status !== 'loading' || (pending && pending !== request)) return;
        request.status = 'cancelled';
        request.error = 'Analysis cancelled. A bounded worker may still finish; its late result will not be applied.';
        request.controller?.abort();
        delete request.controller;
        renderSources();
      }

      function retryDeobfuscation(reference) {
        const owner = deobfuscationOwner(reference);
        if (owner) return loadDeobfuscation(owner.source, {retry: true});
      }

      function discardStaticCleanup(reference, view) {
        const owner = deobfuscationOwner(reference, view);
        if (!owner) return;
        const request = state.deobfuscationRequests.get(owner.key);
        if (request) {
          request.status = 'cancelled';
          request.error = 'Cleaned result discarded. Original evidence is unchanged. Retry explicitly to create another result.';
          request.controller?.abort();
          delete request.controller;
        }
        retireDeobfuscationReveal(view);
        state.deobfuscationCache.delete(owner.key);
        state.sourceDeobfuscated = false;
        state.sourceFormatted = false;
        renderSources();
      }

      function toggleStaticCleanupComparison(reference, view) {
        const owner = deobfuscationOwner(reference, view);
        if (!owner) return;
        view.compare = !view.compare;
        renderDeobfuscationReport(owner.source);
      }

      function retireDeobfuscationReveal(view) {
        if (!view?.revealToken) return;
        sourceFactsPanel.cancelOwned?.(view.revealToken, 'Original range request cancelled because its analysis selection changed.');
        view.revealing = false;
        view.revealGeneration = (view.revealGeneration ?? 0) + 1;
        delete view.revealToken;
      }

      function updateDeobfuscationView(reference, view, section, delta) {
        const owner = deobfuscationOwner(reference, view);
        if (!owner) return;
        if (section === 'changes') {
          retireDeobfuscationReveal(view);
          const count = owner.payload.sourceInspection?.changes.length ?? 0;
          view.change = Math.max(0, Math.min(count - 1, view.change + delta));
          view.notice = ''; view.revealing = false;
          view.revealGeneration = (view.revealGeneration ?? 0) + 1;
        } else view.pages[section] = Math.max(0, (view.pages[section] ?? 0) + delta);
        renderDeobfuscationReport(owner.source);
      }

      function setDeobfuscationDisclosure(reference, view, section, event) {
        if (deobfuscationOwner(reference, view) && elements.deobfuscationReport.contains(event.currentTarget)) {
          view.open[section] = event.currentTarget.open;
        }
      }

      async function revealDeobfuscationChange(reference, view) {
        const owner = deobfuscationOwner(reference, view);
        const change = owner?.payload.sourceInspection?.changes[view.change];
        if (!change || !owner.payload.sourceInspection.byteRanges || view.revealing) return;
        const wire = owner.payload.representation.segments[change.index];
        const unavailable = sourceFactsUnavailable(owner.source, location.protocol);
        if (unavailable) {view.notice = unavailable; renderDeobfuscationReport(owner.source); return;}
        if (['loading', 'loading-source'].includes(sourceFactsPanel.model.status)) {
          view.notice = 'Original-byte verification is busy. Try revealing this change again when it finishes.';
          renderDeobfuscationReport(owner.source); return;
        }
        view.revealing = true;
        const generation = view.revealGeneration = (view.revealGeneration ?? 0) + 1;
        const token = view.revealToken = {};
        renderDeobfuscationReport(owner.source);
        let failure = '';
        try {
          await sourceFactsPanel.navigate({start: wire.original_start, end: wire.original_end}, {
            owner: token,
            isCurrent: () => Boolean(deobfuscationOwner(reference, view)) && view.revealGeneration === generation && view.revealToken === token,
          });
        }
        catch (error) { failure = `Original range unavailable: ${String(error.message).slice(0, 1024)}`; }
        if (view.revealGeneration !== generation) return;
        view.revealing = false;
        delete view.revealToken;
        const current = deobfuscationOwner(reference, view);
        if (!current) return;
        view.notice = failure || sourceFactsPanel.model.error || '';
        renderDeobfuscationReport(current.source);
      }

      function deobfuscationButton(key, label, action, disabled = false) {
        const button = textElement('button', 'secondary-button', label);
        button.type = 'button'; button.dataset.deobControl = key; button.disabled = disabled;
        button.addEventListener('click', action);
        return button;
      }

      function deobfuscationDisclosure(reference, view, section, label, rows, pageSize = 4) {
        const details = document.createElement('details');
        details.className = 'deobfuscation-disclosure'; details.open = Boolean(view.open[section]);
        const summary = textElement('summary', '', `${label} (${rows.length})`);
        summary.dataset.deobControl = `disclosure-${section}`; details.append(summary);
        details.addEventListener('toggle', setDeobfuscationDisclosure.bind(null, reference, view, section));
        const page = Math.min(view.pages[section] ?? 0, Math.max(0, Math.ceil(rows.length / pageSize) - 1));
        view.pages[section] = page;
        const start = page * pageSize;
        if (!rows.length) { details.append(textElement('p', 'deobfuscation-note', 'None reported.')); return details; }
        details.append(textElement('p', 'deobfuscation-note', `Showing ${start + 1}–${Math.min(start + pageSize, rows.length)} of ${rows.length}`));
        details.append(...rows.slice(start, start + pageSize));
        if (rows.length > pageSize) {
          const controls = document.createElement('div'); controls.className = 'deobfuscation-controls';
          for (const [key, label, delta, disabled] of [['previous', 'Previous page', -1, page === 0], ['next', 'Next page', 1, start + pageSize >= rows.length]]) {
            controls.append(deobfuscationButton(`${section}-${key}`, label,
              updateDeobfuscationView.bind(null, reference, view, section, delta), disabled));
          }
          details.append(controls);
        }
        return details;
      }

      function renderDeobfuscationReport(source) {
        elements.deobfuscationIntrinsics.checked = Boolean(state.deobfuscationAssumeIntrinsics);
        const container = elements.deobfuscationReport;
        if (!container) return;
        const target = source ?? selectedSource();
        if (!target || target.kind !== 'javascript') {
          container.deobfuscationRender = null;
          container.textContent = 'Select a JavaScript source to analyze.';
          return;
        }
        const key = deobfuscationKey(target), request = state.deobfuscationRequests.get(key);
        const payload = target.deobfuscation;
        const inspection = payload?.sourceInspection;
        const view = payload?.inspectorView;
        const stamp = JSON.stringify([key, request?.status, request?.error, view?.change, view?.pages, view?.notice, view?.revealing, view?.compare]);
        if (container.deobfuscationRender?.stamp === stamp && container.deobfuscationRender?.view === view) return;
        const sameOwner = container.deobfuscationRender?.key === key;
        if (sameOwner && container.deobfuscationRender?.view === view && view) {
          // Native `toggle` events are queued; preserve the actual disclosure
          // state even if a page/control action runs before that event arrives.
          for (const details of container.querySelectorAll('details')) {
            const section = details.querySelector('summary')?.dataset.deobControl?.replace(/^disclosure-/, '');
            if (section) view.open[section] = details.open;
          }
        }
        const focused = sameOwner && container.contains(document.activeElement) ? document.activeElement?.dataset?.deobControl : null;
        const scroller = container.closest('.debug-panes') ?? container;
        const scroll = sameOwner ? scroller.scrollTop : 0;
        const snippetScroll = sameOwner && container.deobfuscationRender?.view === view && container.deobfuscationRender?.change === view?.change
          ? [...container.querySelectorAll('pre')].map(node => [node.dataset.deobControl, node.scrollTop, node.scrollLeft]) : [];
        // Only small view metadata is retained by the DOM. Source bytes stay in
        // the bounded analysis cache and event handlers receive descriptors only.
        container.deobfuscationRender = {key, view, stamp, change: view?.change};
        const reference = {...sourceReference(target), deobfuscationAssumption: Boolean(state.deobfuscationAssumeIntrinsics)}, nodes = [];
        if (request?.status === 'loading') {
          const status = textElement('p', 'deobfuscation-notice', payload ? 'Reanalyzing. Last successful report remains below.' : 'Analyzing source without executing it…');
          status.setAttribute('role', 'status'); nodes.push(status);
          nodes.push(deobfuscationButton('cancel', 'Cancel analysis', cancelDeobfuscation.bind(null, reference, request)));
        } else if (['error', 'cancelled'].includes(request?.status)) {
          const status = textElement('p', 'deobfuscation-notice', `${request.error}${payload ? ' Last successful report remains below.' : ''}`);
          status.setAttribute('role', 'status'); nodes.push(status);
          nodes.push(deobfuscationButton('retry', 'Retry analysis', retryDeobfuscation.bind(null, reference)));
        } else if (payload) {
          nodes.push(deobfuscationButton('reanalyze', 'Reanalyze', retryDeobfuscation.bind(null, reference)));
        }
        if (!payload || !view || !inspection) {
          nodes.push(textElement('p', 'deobfuscation-note', payload ? 'This retained report has no validated change-inspection metadata. Retry analysis to inspect exact ranges.' : 'No successful analysis is loaded for this source.'));
        } else {
          const analysis = payload.analysis, summary = analysis.representation ?? {};
          const changes = inspection.changes;
          nodes.push(textElement('strong', 'deobfuscation-title', `Static cleanup · ${changes.length ? `${changes.length} changed spans` : 'No safe rewrites found'}`));
          nodes.push(deobfuscationRow('Bytes', `${formatByteSize(inspection.originalBytes)} → ${formatByteSize(inspection.derivedBytes)}`));
          nodes.push(deobfuscationRow('Source', `Captured artifact ${target.artifact_id}`));
          nodes.push(deobfuscationRow('Original SHA-256', analysis.source.sha256));
          nodes.push(deobfuscationRow('Cleaned SHA-256', inspection.derivedSha256));
          nodes.push(textElement('p', 'deobfuscation-note', 'Original bytes are unchanged. Cleanup runs locally without executing the input or uploading it to a third-party service. SHA-256 identifies each complete UTF-8 text, not its preview. Static reconstruction does not prove equivalent runtime behavior. Pretty printing is a separate display layer.'));
          nodes.push(textElement('p', 'deobfuscation-notice', 'Recovery is partial in scope: unsupported decoding and runtime-dependent behavior remain unresolved. No safe rewrites does not mean the source is unobfuscated.'));
          if (summary.truncated || payload.representation.truncated) nodes.push(textElement('p', 'deobfuscation-notice', 'Partial result: a transformation budget was reached. Unreduced source remains.'));
          if (!inspection.byteRanges) nodes.push(textElement('p', 'deobfuscation-notice', 'Legacy code-point map. Exact UTF-8 change inspection is unavailable for this report.'));
          if (inspection.synthetic) nodes.push(textElement('p', 'deobfuscation-note', `${inspection.synthetic} synthetic insertion segments are separate from replacement spans. Verbatim segments preserve identical source slices.`));
          if (changes.length && inspection.byteRanges) {
            view.change = Math.max(0, Math.min(view.change, changes.length - 1));
            const change = changes[view.change], wire = payload.representation.segments[change.index];
            const controls = document.createElement('div'); controls.className = 'deobfuscation-controls';
            controls.append(deobfuscationButton('change-previous', 'Previous change', updateDeobfuscationView.bind(null, reference, view, 'changes', -1), view.change === 0));
            const position = textElement('span', 'deobfuscation-change-position', `Change ${view.change + 1} of ${changes.length}`);
            position.setAttribute('role', 'status'); position.tabIndex = -1; position.dataset.deobControl = 'change-position'; controls.append(position);
            controls.append(deobfuscationButton('change-next', 'Next change', updateDeobfuscationView.bind(null, reference, view, 'changes', 1), view.change + 1 === changes.length));
            nodes.push(controls);
            for (const [label, text, start, end, byteStart, byteEnd] of [
              ['Original', payload.original_source, change.original_start, change.original_end, wire.original_start, wire.original_end],
              ['Derived', payload.representation.text, change.derived_start, change.derived_end, wire.derived_start, wire.derived_end],
            ]) {
              const block = document.createElement('section'); block.className = 'deobfuscation-snippet';
              block.append(textElement('strong', '', `${label} · UTF-8 [${byteStart}, ${byteEnd})`));
              let limit = Math.min(end, start + 2048);
              if (limit < end && /[\uD800-\uDBFF]/.test(text[limit - 1])) limit--;
              const code = textElement('pre', '', text.slice(start, limit));
              code.tabIndex = 0; code.dataset.deobControl = `snippet-${label.toLowerCase()}`;
              code.setAttribute('aria-label', `${label} replacement span`); block.append(code);
              if (limit < end) block.append(textElement('p', 'deobfuscation-note', `Snippet shows ${limit - start} of ${end - start} UTF-16 units. The exact range above covers the full span.`));
              nodes.push(block);
            }
            nodes.push(textElement('p', 'deobfuscation-note', 'Mapped replacement. Per-change rule and assumption details were not provided; the summaries below describe the whole analysis.'));
            const unavailable = target.source_type === 'artifact' ? sourceFactsUnavailable(target, location.protocol) : '';
            nodes.push(deobfuscationButton('reveal', view.revealing ? 'Verifying original bytes…' : 'Reveal original range', revealDeobfuscationChange.bind(null, reference, view), Boolean(view.revealing || unavailable)));
            if (unavailable) nodes.push(textElement('p', 'deobfuscation-note', `Original range navigation: ${unavailable}`));
          }
          const cleanupControls = document.createElement('div'); cleanupControls.className = 'deobfuscation-controls';
          const compare = deobfuscationButton('compare', view.compare ? 'Hide comparison' : 'Compare original / cleaned', toggleStaticCleanupComparison.bind(null, reference, view));
          compare.setAttribute('aria-expanded', String(Boolean(view.compare)));
          cleanupControls.append(compare, deobfuscationButton('discard', 'Discard cleaned result', discardStaticCleanup.bind(null, reference, view)));
          nodes.push(cleanupControls);
          if (view.compare) {
            const comparison = document.createElement('div'); comparison.className = 'static-cleanup-comparison';
            for (const [label, text] of [['Original', payload.original_source], ['Cleaned', payload.representation.text]]) {
              let end = Math.min(text.length, 8192);
              if (end < text.length && /[\uD800-\uDBFF]/.test(text[end - 1])) end--;
              const block = document.createElement('section'); block.className = 'deobfuscation-snippet';
              block.append(textElement('strong', '', `${label} · ${end < text.length ? 'prefix preview' : 'complete text'}`));
              const code = textElement('pre', '', text.slice(0, end)); code.tabIndex = 0;
              code.dataset.deobControl = `comparison-${label.toLowerCase()}`;
              code.setAttribute('aria-label', `${label} static cleanup comparison`); block.append(code);
              if (end < text.length) block.append(textElement('p', 'deobfuscation-note', `Preview shows ${end} of ${text.length} UTF-16 units. Use the source editor and changed-span inspector for the remaining text.`));
              comparison.append(block);
            }
            nodes.push(comparison);
          }
          if (view.notice) {const notice = textElement('p', 'deobfuscation-notice', view.notice); notice.setAttribute('role', 'status'); nodes.push(notice);}
          const transformations = summary.transformations ?? [];
          const total = transformations.reduce((sum, entry) => sum + entry.count, 0);
          const transformRows = transformations.map(entry => deobfuscationRow(entry.id, `${entry.count} rewrites · ${entry.detail}`));
          nodes.push(deobfuscationDisclosure(reference, view, 'transformations', `Transformation summary · ${Array.isArray(summary.transformations) ? `${total} reported rewrites` : 'not supplied'}`, transformRows));
          const classificationRows = [deobfuscationRow('Heuristic label', analysis.classification?.label ?? 'unclassified'),
            deobfuscationRow('Meaning', 'Source-shape signals, not a probability or a semantic guarantee.'),
            ...(analysis.classification?.evidence ?? []).map(entry => deobfuscationRow(entry.id, entry.detail))];
          nodes.push(deobfuscationDisclosure(reference, view, 'classification', 'Why this classification', classificationRows));
          const tableRows = (analysis.string_tables ?? []).map(table => deobfuscationRow(`${table.kind} · code-point offset ${table.offset}`,
            `${table.entry_count} reported entries · ${(table.encodings ?? []).join(', ')}${table.decoded_preview ? ` · preview: ${table.decoded_preview}` : ''}`));
          nodes.push(deobfuscationDisclosure(reference, view, 'tables', 'Recovered tables', tableRows));
          const limits = [deobfuscationRow('Engine', payload.engine === 'rust-oxc' ? 'Rust / Oxc static rewriting' : 'Legacy lexical analysis'),
            deobfuscationRow('Assumption', analysis.assumptions.length ? 'Standard intrinsics requested. Visible conflicts may suppress the model; this is not evidence of pristine runtime prototypes.' : 'Standard-intrinsics modeling is off.'),
            deobfuscationRow('UI retention', 'Up to 8 analysis documents, 8 Mi UTF-16 units of original and derived text, 250,000 map segments and 32 MiB of response data combined.'),
            ...(analysis.omissions ?? []).map(message => deobfuscationRow('Unresolved', message)),
            ...Object.entries(analysis.limits ?? {}).map(([name, value]) => deobfuscationRow(name.replaceAll('_', ' '), String(value)))];
          nodes.push(deobfuscationDisclosure(reference, view, 'limits', 'Assumptions and limits', limits));
        }
        container.replaceChildren(...nodes);
        container.deobfuscationRender.stamp = JSON.stringify([key, request?.status, request?.error, view?.change, view?.pages, view?.notice, view?.revealing, view?.compare]);
        scroller.scrollTop = scroll;
        for (const node of container.querySelectorAll('pre')) {
          const previous = snippetScroll.find(([key]) => key === node.dataset.deobControl);
          if (previous) {node.scrollTop = previous[1]; node.scrollLeft = previous[2];}
        }
        if (focused) {
          const controls = [...container.querySelectorAll('[data-deob-control]')];
          const neighbor = focused.endsWith('-next') ? focused.replace(/-next$/, '-previous')
            : focused.endsWith('-previous') ? focused.replace(/-previous$/, '-next')
            : ['retry', 'reanalyze'].includes(focused) ? 'cancel' : focused === 'cancel' ? 'retry' : '';
          const control = controls.find(node => node.dataset.deobControl === focused && !node.disabled)
            ?? controls.find(node => node.dataset.deobControl === neighbor && !node.disabled)
            ?? controls.find(node => ['change-position', 'cancel'].includes(node.dataset.deobControl)) ?? container;
          control?.focus({preventScroll: true});
        }
      }

      async function loadArtifactContent(artifact, {retry = false, canvasOwner = null} = {}) {
        if (artifact?.kind === 'canvas_data_url' && (!canvasOwner ||
            state.canvasPreviewOwners?.get(sourceIdentity(artifact)) !== canvasOwner || !canvasGalleryVisible() || state.artifactReceiverError)) return;
        if (!sourceIsCurrent(artifact) || artifact.content !== undefined || artifact.loading || (artifact.loadError && !retry)) return;
        const identity = sourceIdentity(artifact);
        const controller = new AbortController();
        artifact.loading = true; artifact.loadError = null; artifact.controller = controller;
        artifact.previewUsed = state.sourcePreviewSequence = (state.sourcePreviewSequence ?? 0) + 1;
        if (!canvasOwner) boundSourcePreviews(artifact);
        const current = () => sourceIsCurrent(artifact) && state.artifacts.includes(artifact) && artifact.controller === controller && !controller.signal.aborted &&
          (!canvasOwner || (state.canvasPreviewOwners?.get(identity) === canvasOwner && canvasGalleryVisible() && !state.artifactReceiverError));
        const timeout = setTimeout(() => {
          if (artifact.controller !== controller) return;
          artifact.loading = false; artifact.loadError = 'Artifact loading timed out. Retry explicitly.';
          delete artifact.controller; controller.abort();
          if (canvasOwner && canvasGalleryVisible()) renderFingerprintActivity();
          else if (sourceIdentity(selectedSource()) === identity) renderSources();
        }, 10000);
        if (!canvasOwner) renderSources();
        let responseCancellation = null;
        try {
          const response = await fetch(`/api/artifacts/${encodeURIComponent(artifact.artifact_id)}/content?limit=2097152`, {cache: 'no-store', signal: controller.signal});
          if (!current()) { responseCancellation = response.body?.cancel().catch(() => {}); return; }
          if (!response.ok) { responseCancellation = response.body?.cancel().catch(() => {}); throw new Error(`Artifact store returned ${response.status}`); }
          // Sources may retire without waiting for a producer's cleanup. Canvas
          // additionally owns a read credit until any body/reader cancellation
          // settles, including the bounded reader's abort and error paths.
          const ownedResponse = canvasOwner && response.body?.getReader ? {body: {getReader() {
            const reader = response.body.getReader();
            return {read: () => reader.read(), releaseLock: () => reader.releaseLock(), cancel: () => {
              responseCancellation = reader.cancel().catch(() => {});
              return responseCancellation;
            }};
          }}} : response;
          const buffer = await sourceFactsReadBytes(ownedResponse, 2097152, controller.signal);
          if (!current()) return;
          if (buffer.length !== Math.min(artifact.byte_size, 2097152)) throw new Error('The artifact preview byte size changed.');
          const total = response.headers.get('X-Artifact-Total-Bytes');
          if (total !== null && Number(total) !== artifact.byte_size) throw new Error('The artifact total byte size changed.');
          if (artifact.byte_size <= 2097152 && globalThis.crypto?.subtle) {
            const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', buffer)), byte => byte.toString(16).padStart(2, '0')).join('');
            if (!current()) return;
            if (hash !== artifact.sha256) throw new Error('The artifact bytes do not match the selected SHA-256.');
            artifact.contentVerified = true;
          }
          if (!sourceHexArtifact(artifact)) {
            try {new TextDecoder('utf-8', {fatal: true}).decode(buffer); artifact.contentLossy = false;}
            catch {artifact.contentLossy = true;}
          }
          // Hex is only a view. Format every byte whose rows fit in the editor
          // index (about 1.6 MiB). The immutable blob is untouched.
          const hexBytes = sourceHexArtifact(artifact) ? Math.min(buffer.length, wasmHexByteLimit()) : buffer.length;
          const content = sourceHexArtifact(artifact)
            ? formatWasmHex(buffer.subarray(0, hexBytes))
            : new TextDecoder('utf-8', {fatal: false, ignoreBOM: true}).decode(buffer);
          if (canvasOwner && (artifact.contentLossy || !canvasDataUrlPattern.test(content))) {
            throw new Error('The retained bytes do not pass the bounded image data URL validator.');
          }
          if (canvasOwner) {
            const inspection = inspectCanvasPng(content);
            if (inspection.reason) canvasOwner.imageError = inspection.reason;
            else canvasOwner.imageInfo = inspection;
          }
          artifact.sourceTextLength = content.length;
          artifact.content = content;
          artifact.wasmHexBytes = sourceHexArtifact(artifact) ? hexBytes : undefined;
          artifact.contentTruncated = artifact.byte_size > buffer.length || (sourceHexArtifact(artifact) && buffer.length > hexBytes);
          if (artifact.contentTruncated) artifact.content += sourceHexArtifact(artifact)
            ? `\n\n[Hex preview limited to the first ${hexBytes} bytes; original bytes are unchanged]`
            : '\n\n[Viewer preview limited to the first 2 MiB; original bytes are unchanged]';
          if (!canvasOwner) boundSourcePreviews();
        } catch (error) {
          if (current()) {
            if (canvasOwner) for (const field of ['content', 'sourceTextLength', 'contentVerified', 'contentLossy', 'contentTruncated']) delete artifact[field];
            artifact.loadError = `Artifact bytes are unavailable: ${String(error.message).slice(0, 1024)}`;
          }
        } finally {
          clearTimeout(timeout);
          if (artifact.controller === controller) {artifact.loading = false; delete artifact.controller;}
          if (canvasOwner && responseCancellation) {
            // Expose the failure/retirement now, but do not refund its credit.
            try { if (canvasGalleryVisible()) renderFingerprintActivity(); }
            finally { await responseCancellation; }
          } else if (!canvasOwner && sourceIdentity(selectedSource()) === identity) renderSources();
        }
      }

      function wasmKey(source) {
        return `${source.artifact_id}:${source.sha256}`;
      }

      async function loadWasmInspection(source, retry = false) {
        const key = wasmKey(source);
        if (state.wasmRequests.get(key)?.status === 'loading' || (!retry && state.wasmCache.has(key))) return;
        state.wasmRequests.set(key, {status: 'loading'});
        while (state.wasmRequests.size > 128) {
          const retired = [...state.wasmRequests].find(([id, request]) => id !== key && request.status !== 'loading');
          if (!retired) break;
          state.wasmRequests.delete(retired[0]);
        }
        renderSources();
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 10000);
        try {
          const response = await fetch(`/api/wasm?artifact_id=${encodeURIComponent(source.artifact_id)}`, {cache: 'no-store', signal: controller.signal});
          const report = await response.json();
          if (!response.ok) throw new Error(report.error || `Inspection returned ${response.status}`);
          if (!isWasmInspection(report, source)) throw new Error('The WASM inspector returned an invalid document.');
          state.wasmCache.delete(key);
          state.wasmCache.set(key, report);
          while (state.wasmCache.size > 4) state.wasmCache.delete(state.wasmCache.keys().next().value);
          state.wasmRequests.set(key, {status: 'ready'});
        } catch (error) {
          state.wasmRequests.set(key, {status: 'error', error: error.name === 'AbortError' ? 'Inspection timed out. Original bytes are preserved.' : error.message});
        } finally {
          clearTimeout(timeout);
          if (wasmKey(selectedSource() ?? {}) === key) renderSources();
        }
      }

      // Same exact tuple as investigation-navigation v1. Kept here so a
      // standalone Evidence pivot can verify the receiving selection boundary.
      function sourceArtifactIdentityMatches(source, identity) {
        return identity?.type === 'captured-artifact' && identity.session !== '0' && identity.artifact !== '0' && identity.session === source?.session_id &&
          identity.artifact === source?.artifact_id && identity.sha256 === source?.sha256 &&
          /^[0-9a-f]{64}$/.test(identity.sha256) && Number.isSafeInteger(identity.bytes) &&
          identity.bytes >= 0 && identity.bytes === source?.byte_size;
      }

      function selectArtifact(artifactId, line = null, {identity: expectedIdentity = null, passive = false} = {}) {
        const matches = state.artifacts.filter(candidate => candidate.artifact_id === artifactId);
        if (matches.length !== 1 || (expectedIdentity && !sourceArtifactIdentityMatches(matches[0], expectedIdentity))) {
          state.sourceNoticeKind = 'warning';
          state.sourceNotice = 'This exact artifact is missing, changed or ambiguous across retained sessions. No source was opened.';
          renderSourceHealth();
          return false;
        }
        const artifact = matches[0];
        investigationPassiveSource = passive;
        state.sourceNotice = null;
        const identity = sourceIdentity(artifact);
        retireSourceAnalysis(identity);
        investigationBeforeSelection();
        sourceFactsPanel.cancel();
        state.selectedArtifactId = artifactId;
        state.sourceDeobfuscated = false;
        state.sourceFormatted = false;
        state.sourceWasm = false;
        if (!state.openArtifactIds.includes(artifactId)) state.openArtifactIds.push(artifactId);
        renderSources();
        loadArtifactContent(artifact).then(() => {
          if (line !== null && state.sourceCollection === 'captured' && state.selectedArtifactId === artifactId && sourceIdentity(selectedSource()) === identity) {
            const source = selectedSource();
            if (source?.content !== undefined) revealOriginalLine(source, line, 0);
          }
        });
        return true;
      }

      function closeSource(source) {
        if (!sourceIsCurrent(source)) return;
        releaseSourcePreview(source);
        const closedIndex = state.openArtifactIds.indexOf(source.artifact_id);
        state.openArtifactIds = state.openArtifactIds.filter(id => id !== source.artifact_id);
        if (state.selectedArtifactId === source.artifact_id) {
          state.selectedArtifactId = state.openArtifactIds[Math.max(0, closedIndex - 1)] ?? null;
        }
        state.sourceDeobfuscated = false;
        state.sourceFormatted = false;
        state.sourceWasm = false;
        renderSources();
        const selected = selectedSource();

        if (selected?.source_type === 'artifact') loadArtifactContent(state.artifacts.find(value => sourceIdentity(value) === sourceIdentity(selected)));
      }

      function renderQuickOpen() {
        const needle = elements.quickOpenInput.value.trim().toLowerCase();
        const matches = capturedSources().map(sourceReference).filter(source =>
          !needle || `${sourceDisplayName(source)} ${source.url}`.toLowerCase().includes(needle)
        );
        const rows = matches.map(source => {
          const row = document.createElement('button');
          row.type = 'button';
          row.className = 'quick-open-row';
          const name = document.createElement('span'); name.textContent = sourceDisplayName(source);
          const path = document.createElement('small'); path.textContent = `Captured · ${source.url || '(anonymous)'}`;
          row.append(name, path);
          row.addEventListener('click', () => {
            elements.quickOpen.hidden = true;
            selectArtifact(source.artifact_id);
          });
          return row;
        });
        elements.quickOpenResults.replaceChildren(...rows);
      }

      function openQuickOpen() {
        elements.quickOpen.hidden = false;
        elements.quickOpenInput.value = '';
        renderQuickOpen();
        requestAnimationFrame(() => elements.quickOpenInput.focus());
      }

      function renderSourceSidebar() { const open = Boolean(state.sourceSidebarOpen); elements.sourceSidebar.hidden = !open; document.querySelector('#screen-sources').dataset.sidebarOpen = String(open); elements.sourceSidebarToggle.setAttribute('aria-expanded', String(open)); }

      async function refreshArtifacts() {
        if (state.artifactRefreshing || location.protocol === 'file:') return;
        state.artifactRefreshing = true;
        try {
          const headers = state.artifactEtag ? { 'If-None-Match': state.artifactEtag } : {};
          const response = await fetch('/api/artifacts?limit=500', { cache: 'no-store', headers });
          if (response.status === 304) return;
          if (!response.ok) throw new Error(`Artifact store returned ${response.status}`);
          const body = await response.json();
          if (!isArtifactResponse(body)) throw new TypeError('Malformed artifact response');
          state.artifactEtag = response.headers.get('ETag');
          if (typeof body.artifact_receiver_configured === 'boolean') {
            state.artifactReceiverConfigured = body.artifact_receiver_configured;
          }
          if (typeof body.artifact_receiver_connected === 'boolean') {
            state.artifactReceiverConnected = body.artifact_receiver_connected;
          }
          state.artifactReceiverError = null;
          renderShellStatus();
          const catalogSignature = JSON.stringify(body.artifacts);
          if (catalogSignature === state.artifactCatalogSignature) {
            if (canvasGalleryVisible()) renderFingerprintActivity();
            renderSourceHealth();
            return;
          }
          state.artifactCatalogSignature = catalogSignature;
          if (body.artifacts.length === 0) {
            if (state.sessionMode === 'live') {
              retireCanvasPreviews('Canvas previews released because the artifact catalog is empty.');
              for (const artifact of state.artifacts) releaseSourcePreview(artifact);
              state.artifacts = [];
              state.openArtifactIds = [];
              state.selectedArtifactId = null;
              renderSources();
            } else {
              renderSourceHealth();
            }
            return;
          }
          const existing = new Map(state.artifacts.map(artifact => [sourceIdentity(artifact), artifact]));
          const incoming = new Set(body.artifacts.map(sourceIdentity));
          for (const artifact of state.artifacts) if (!incoming.has(sourceIdentity(artifact))) releaseSourcePreview(artifact);
          state.artifacts = body.artifacts.map(artifact => {
            const prior = existing.get(sourceIdentity(artifact));
            // Preserve the pending operation's owner, never clone loading state.
            const descriptor = Object.fromEntries(sourceFactsFields.filter(field => Object.hasOwn(artifact, field)).map(field => [field, artifact[field]]));
            return Object.assign(prior ?? {}, descriptor, {origin: state.sessionMode === 'live' ? 'live' : 'demo'});
          });
          if (!canvasGalleryVisible()) retireCanvasPreviews();
          state.openArtifactIds = state.openArtifactIds.filter(id => state.artifacts.some(artifact => artifact.artifact_id === id));
          if (!state.artifacts.some(artifact => artifact.artifact_id === state.selectedArtifactId)) {
            state.selectedArtifactId = state.artifacts[0].artifact_id;
            state.openArtifactIds = [state.selectedArtifactId];
          }
          renderSources();
          const selected = state.artifacts.find(artifact => artifact.artifact_id === state.selectedArtifactId);
          if (selected) {
            loadArtifactContent(selected);
            if (!investigationPassiveSource && state.sourceWasm && selected.kind === 'wasm') loadWasmInspection(selected);
          }
          if (!document.querySelector('#screen-signals').hidden) renderFingerprintActivity();
        } catch (error) {
          if (!state.artifactReceiverConfigured && state.artifacts.every(artifact => artifact.origin === 'sample')) {
            renderSourceHealth();
            return;
          }
          state.artifactReceiverError = error.message;
          state.artifactEtag = null;
          retireCanvasPreviews('Canvas previews released because the artifact catalog is unavailable.');
          if (canvasGalleryVisible()) renderFingerprintActivity();
          renderShellStatus();
          renderSources();
        } finally {
          state.artifactRefreshing = false;
          evidencePackagePanel.sync();
          evidenceWorkspace.sync();
          syncFloat32Panel();
        }
      }

      function showScreen(name, trigger = null) {
        const screenName = name === 'backtraces' ? 'backtrace' : name;
        if (!document.getElementById(`screen-${screenName}`)) return;
        investigationBeforeScreen(screenName);
        if (screenName !== 'signals') retireCanvasPreviews();
        if (screenName !== 'backtrace' && state.originTraceStatus === 'loading') {
          state.originTraceController?.abort();
          state.originTraceGeneration += 1;
          state.originTraceStatus = state.originTrace ? 'ready' : 'idle';
        }

        evidenceWorkspace.setVisible(screenName === 'evidence');
        if (screenName !== 'sources') sourceFactsPanel.cancel();
        if (screenName !== 'tools') float32Panel.cancel();

        document.querySelectorAll('.screen').forEach(screen => { screen.hidden = screen.id !== `screen-${screenName}`; });
        if (typeof vmExecutionWorkspace !== 'undefined') vmExecutionWorkspace?.setVisible(screenName === 'vm');
        document.querySelectorAll('.nav-button').forEach(button => {
          const active = button.dataset.screen === screenName || (button.dataset.screen === 'backtrace' && screenName === 'evidence') || (button.dataset.screen === 'traffic' && screenName === 'field-provenance');
          if (active) button.setAttribute('aria-current', 'page');
          else button.removeAttribute('aria-current');
        });
        // Advanced is a floating chooser at every width. Finish the choice
        // without leaving focus on a menu item that is about to be hidden.
        const navigation = document.querySelector('#advanced-navigation');
        if (navigation.contains(document.activeElement)) navigation.querySelector('summary').focus({ preventScroll: true });
        navigation.open = false;
        if (screenName === 'signals') renderFingerprintActivity();
        if (screenName === 'traffic') {
          // Hidden evidence refreshes update the model without painting Traffic.
          // A quiet backend may return 304 indefinitely after we return here.
          renderRequests();
          updateSelectionSummary(state.requests.find(request => request.id === state.selectedRequestId) ?? null);
          renderInspector();

        }
        if (screenName === 'backtrace') renderBacktrace();

        if (screenName === 'api-collection') {
          renderApiCollection();
          refreshApiCollection();
        }
        if (screenName === 'analyst') {
          renderLocalAnalyst();
          refreshLocalAnalyst();
        }
        if (screenName === 'tools') {
          renderTools();
          refreshDecoderEngine();
        }
        if (screenName === 'sources') {

          renderSources();
          const source = selectedSource();

          if (source?.source_type === 'artifact') loadArtifactContent(state.artifacts.find(candidate => candidate.artifact_id === source.artifact_id));
        }

        if (screenName === 'vm') {
          if (trigger === elements.requestVmCandidates && typeof vmExecutionWorkspace !== 'undefined') vmExecutionWorkspace?.showWorkspace('findings');
          if (trigger?.id === 'nav-vm' && state.vmAnalysisRequestId !== null) refreshVmAnalysis(null);
          renderVmLab();
        }
        if (!trigger?.classList.contains('nav-button')) {
          const revision = investigationRevision;
          requestAnimationFrame(() => {
            if (revision !== investigationRevision || investigationScreen() !== screenName) return;
            if (screenName === 'traffic') {
              const selectedRow = [...elements.requestRows.querySelectorAll('.request-row')]
                .find(row => row.dataset.requestId === state.selectedRequestId);
              (selectedRow ?? elements.requestFilter).focus({ preventScroll: true });
              return;
            }
            document.querySelector(`#screen-${screenName} .back-button`)?.focus({ preventScroll: true });
          });
        }
      }

      async function refresh() {
        if (state.refreshing) return;
        state.refreshing = true;
        try {
          const headers = state.eventEtag ? { 'If-None-Match': state.eventEtag } : {};
          const response = await fetch('/api/events?limit=5000', { cache: 'no-store', headers });
          if (response.status === 304) {
            await refreshRequestSignalProfile();
            await refreshArtifacts();
            await refreshVmAnalysis();
            return;
          }
          if (!response.ok) throw new Error(`Broker returned ${response.status}`);
          const rawBody = await response.text();
          let body;
          try { body = JSON.parse(rawBody); } catch { throw new TypeError('Malformed broker response'); }
          if (!isBrokerResponse(body)) throw new TypeError('Malformed broker response');
          state.eventEtag = response.headers.get('ETag');
          const brokerConnected = body.broker_connected !== false;
          state.captureStopped = body.capture_stopped === true;
          state.captureControlsAvailable = body.capture_controls_available === true;
          state.sessionMode = ['demo', 'idle'].includes(body.capture_mode)
            ? body.capture_mode : 'live';
          state.vmStealthSession = body.stealth_session === true ||
            body.native_stealth === true || body.quiet_mode === true;
          state.canvasRenderCaptures = body.canvas_render_captures ?? [];
          state.events = body.events;
          const currentSignalKeys = new Set(fingerprintEventsFromEvents(state.events).map(signalEventKey));
          if (state.signalKnownKeys !== null) {
            currentSignalKeys.forEach(key => {
              if (!state.signalKnownKeys.has(key)) state.signalNewKeys.add(key);
            });
          }
          state.signalKnownKeys = currentSignalKeys;
          for (const key of state.signalNewKeys) {
            if (!currentSignalKeys.has(key)) state.signalNewKeys.delete(key);
          }
          acceptEventWindow(body);
          const vmModel = vmFindingsFromEvents(state.events);
          state.eventVmFindings = vmModel.findings;
          state.vmFindings = vmVisibleFindings(state);
          state.malformedVmFindings = vmModel.malformedCount;
          const eventOrigin = state.sessionMode === 'demo' ? 'demo' : 'live';
          state.nativeRequests = requestsFromEvents(body.network_events ?? state.events, eventOrigin);
          rebuildTrafficRequests();
          let selectedRequest = state.requests.find(request => request.id === state.selectedRequestId);
          if (!selectedRequest && state.selectedRequestId !== null) resetRequestSelection();
          updateSelectionSummary(selectedRequest);
          state.broker = brokerConnected ? 'connected' : 'unavailable';
          state.eventFailureKind = null;
          state.lastUpdatedLabel = brokerConnected
            ? state.sessionMode === 'live'
              ? `updated ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}`
              : state.sessionMode === 'demo' ? 'deterministic developer evidence loaded' : 'start a live capture'
            : (state.events.length > 0 ? 'last valid evidence retained' : 'no live evidence');
          renderShellStatus();
          elements.gaps.textContent = eventGapLabel(shownSequenceGaps(), shownQueueDrops());
          renderNetworkNotice();
          renderRequests();
          renderInspector();
          renderEvidence();
          if (!document.querySelector('#screen-signals').hidden) renderFingerprintActivity();
          await refreshRequestSignalProfile();
          await refreshArtifacts();
          await refreshVmAnalysis();
          renderVmLab();
        } catch (error) {
          state.broker = 'unavailable';
          state.eventEtag = null;
          const malformed = error instanceof TypeError && error.message === 'Malformed broker response';
          state.eventFailureKind = malformed ? 'malformed' : 'disconnected';
          const retainedEvidence = state.events.length > 0;
          state.lastUpdatedLabel = retainedEvidence ? 'last valid evidence retained' : 'no live evidence';
          renderShellStatus();
          renderNetworkNotice();
          renderRequests();
          renderInspector();
          renderEvidence();
          if (!document.querySelector('#screen-signals').hidden) renderFingerprintActivity();
          renderVmLab();
        } finally {
          state.refreshing = false;
        }
      }

      function useStandalonePreview() {
        state.trafficRenderedView = null;
        state.broker = 'preview';
        state.eventFailureKind = null;
        state.sessionMode = 'preview';
        state.events = [];
        state.canvasRenderCaptures = [];
        state.eventsLimited = false;
        state.sequenceGaps = 0n;
        state.queueDrops = 0n;
        state.eventCountScope = 'rendered_window';
        state.networkEventsAvailable = false;
        state.networkEventsLimited = false;
        state.sequenceGapsSaturated = false;
        state.queueDropsSaturated = false;
        state.requests = [];
        state.artifacts = [];
        state.openArtifactIds = [];
        state.selectedArtifactId = null;
        state.artifactReceiverConfigured = false;
        state.artifactReceiverConnected = false;
        state.artifactReceiverError = null;
        state.sourceNotice = null;
        state.selectedRequestId = null;
        state.selectedField = null;
        state.lastUpdatedLabel = 'start a live capture';
        renderShellStatus();
        elements.gaps.textContent = eventGapLabel(0n, 0n);
        setNetworkNotice('empty', 'No evidence is bundled. Start a live capture to populate the workspace.');
        renderRequests();
        renderEvidence();

        renderSources();
        renderVmLab();
        state.apiCollectionStatus = 'empty';
        state.apiCollectionLoaded = true;
        state.apiCollectionMessage = 'Standalone preview. Open the local app to save an API Collection.';
        renderApiCollection();
        state.localAnalystStatus = 'empty';
        state.localAnalystLoaded = true;
        state.localAnalystMessage = 'Standalone preview. Open the local app to save and run analyst scripts.';
        state.localAnalystRunner = {protocol_version: 1, available: false, active_run_id: null,
          limits: emptyLocalAnalystWorkspace().limits};
        renderLocalAnalyst();
        state.decoderEngine = emptyDecoderEngine();
        setToolsNotice('error', 'Standalone preview. Open the local app to run native decoder and JWT tools.');
        renderTools();
      }

      function enableTabKeyboardNavigation(selector) {
        document.querySelectorAll(selector).forEach(tab => tab.addEventListener('keydown', event => {
          if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
          const tabs = [...tab.closest('[role="tablist"]').querySelectorAll(selector)];
          const current = tabs.indexOf(tab);
          if (current < 0) return;
          event.preventDefault();
          const next = event.key === 'Home'
            ? 0
            : event.key === 'End'
              ? tabs.length - 1
              : (current + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
          tabs[next].click();
          tabs[next].focus();
        }));
      }

      document.querySelector('#vm-analysis-toggle').addEventListener('click', event => {
        setVmAnalysisExpanded(event.currentTarget.getAttribute('aria-expanded') !== 'true');
      });
      document.querySelectorAll('[data-screen]').forEach(button => button.addEventListener('click', async () => {
        if (button.classList.contains('back-button') && investigationNavigation?.back()) return;
        showScreen(button.dataset.screen, button);
        if (button.dataset.screen === 'backtrace' && originTraceSelection()) await refreshOriginTrace();
        if (button.dataset.screen === 'signals') await refreshRequestSignalProfile();
      }));

      elements.signalFilters.forEach(button => button.addEventListener('click', () => {
        state.signalCategoryFilter = button.dataset.signalFilter;
        renderFingerprintActivity();
        elements.signalRows.querySelector('.signal-event-row')?.focus({preventScroll: true});
      }));
      elements.signalLatest.addEventListener('click', () => {
        const visible = fingerprintEventsFromEvents(state.events).filter(event =>
          state.signalTabId === 'all' || signalTabKey(event) === state.signalTabId);
        visible.forEach(event => state.signalNewKeys.delete(signalEventKey(event)));
        renderFingerprintActivity();
        elements.signalRows.scrollTop = 0;
        elements.signalRows.querySelector('.signal-event-row')?.focus({preventScroll: true});
      });
      elements.signalDetailToggle.addEventListener('click', () => {
        state.signalDetailOpen = !state.signalDetailOpen;
        renderFingerprintActivity();
      });
      async function performCaptureAction(action) {
        const button = action === 'stop' ? elements.signalStopCapture : elements.signalClearEvents;
        if (button.disabled) return;
        if (action === 'clear' && !window.confirm(
          'Clear all recorded events, traces, and request signal profiles from this capture session? Canvas artifacts and other saved files will remain on disk. This cannot be undone.'
        )) return;
        button.disabled = true;
        try {
          const response = await fetch('/api/capture/actions', {
            method: 'POST', cache: 'no-store',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(action === 'clear' ? {action, confirm: true} : {action})
          });
          const result = await response.json();
          if (!response.ok) throw new Error(result.error || `Capture action failed (${response.status})`);
          state.captureStopped = result.capture_stopped === true;
          if (action === 'clear') {
            state.signalKnownKeys = null;
            state.signalNewKeys.clear();
            state.selectedSignalEventKey = null;
            state.signalSelectedKeysByTab.clear();
            state.signalProfile = null;
            state.signalProfileEtag = null;
            state.signalProfileKey = null;
          }
          state.eventEtag = null;
          await refresh();
        } catch (error) {
          setSignalNotice('error', error.message);
        } finally {
          renderFingerprintActivity();
        }
      }
      elements.signalStopCapture.addEventListener('click', () => performCaptureAction('stop'));
      elements.signalClearEvents.addEventListener('click', () => performCaptureAction('clear'));
      elements.signalViewTabs.forEach(button => button.addEventListener('click', () => {
        state.signalView = button.dataset.signalView;
        renderFingerprintActivity();
      }));
      enableTabKeyboardNavigation('[data-signal-view]');
      elements.signalRows.addEventListener('keydown', event => {
        if (!['ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) return;
        const rows = [...elements.signalRows.querySelectorAll('.signal-event-row')];
        if (!rows.length) return;
        event.preventDefault();
        const current = Math.max(0, rows.indexOf(document.activeElement));
        const next = event.key === 'Home' ? 0 : event.key === 'End' ? rows.length - 1
          : Math.max(0, Math.min(rows.length - 1, current + (event.key === 'ArrowDown' ? 1 : -1)));
        const targetKey = rows[next].dataset.signalEventKey;
        rows[next].click();
        [...elements.signalRows.querySelectorAll('.signal-event-row')]
          .find(row => row.dataset.signalEventKey === targetKey)?.focus({preventScroll: true});
      });
      document.addEventListener('keydown', event => {
        if (event.key !== 'Escape') return;
        const disclosure = document.activeElement?.closest('#advanced-navigation');
        if (!disclosure?.open) return;
        disclosure.open = false;
        disclosure.querySelector('summary').focus();
        event.preventDefault();
      });
      // Keep an explicitly opened chooser from covering the workspace after
      // resizing into the narrow layout.
      window.matchMedia('(max-width: 800px)').addEventListener('change', event => {
        if (!event.matches) return;
        const navigation = document.querySelector('#advanced-navigation');
        if (navigation.contains(document.activeElement)) navigation.querySelector('summary').focus();
        navigation.open = false;
      });
      document.querySelectorAll('.type-filter').forEach(button => button.addEventListener('click', () => {
        state.requestType = button.dataset.filter;
        state.requestDomain = 'all';
        document.querySelectorAll('.type-filter').forEach(candidate => candidate.setAttribute('aria-pressed', String(candidate === button)));
        renderRequests();
      }));
      document.querySelectorAll('.field-tab').forEach(button => button.addEventListener('click', () => {
        state.fieldTab = button.dataset.fieldTab;
        state.selectedField = fieldSets[state.fieldTab].find(field => field.traceable) || null;
        renderInspector();
        renderEvidence();
      }));
      document.querySelectorAll('.inspector-tab').forEach(button => button.addEventListener('click', () => {
        state.inspectorTab = button.dataset.inspectorTab;
        if (state.inspectorTab === 'evidence' && state.fieldTab === 'headers') {
          state.fieldTab = 'body';
          const request = state.requests.find(candidate => candidate.id === state.selectedRequestId);
          state.selectedField = request?.traceable ? fieldSets.body.find(field => field.traceable) : null;
        }
        renderInspector();
        renderEvidence();
        if (state.inspectorTab === 'signals') refreshRequestSignalProfile();
      }));
      document.querySelector('#request-evidence-toggle').addEventListener('click', () => {
        state.inspectorTab = state.inspectorTab === 'evidence' ? 'general' : 'evidence';
        renderInspector();
      });
      enableTabKeyboardNavigation('.inspector-tab');
      enableTabKeyboardNavigation('.field-tab');
      enableTabKeyboardNavigation('.source-side-tab:not(:disabled)');
      elements.traceRequest.addEventListener('change', async () => {
        selectRequest(elements.traceRequest.value);
        await refreshOriginTrace();
      });
      elements.traceLoad.addEventListener('click', refreshOriginTrace);
      elements.traceFirstRequest.addEventListener('click', async () => {
        const first = state.requests.find(candidate => requestTraceRoot(candidate));
        if (!first) return;
        selectRequest(first.id);
        await refreshOriginTrace();
        elements.backtraceSteps.querySelector('.trace-row')?.focus();
      });
      elements.requestFilter.addEventListener('input', renderRequests);
      function closeRequestDetails() {
        state.trafficDetailOpen = false;
        renderInspector();
        const row = [...elements.requestRows.querySelectorAll('.request-row')].find(node => node.dataset.requestId === state.selectedRequestId);
        (row ?? elements.requestRows.querySelector('.request-row') ?? elements.requestRows).focus({preventScroll: true});
      }
      document.querySelector('#request-detail-close').addEventListener('click', closeRequestDetails);
      document.querySelector('#screen-traffic').addEventListener('keydown', event => {
        if (event.key !== 'Escape' || event.defaultPrevented) return;
        const disclosure = event.target.closest?.('details');
        if (disclosure?.open) { disclosure.open = false; disclosure.querySelector('summary')?.focus(); }
        else if (event.target.matches?.('input, textarea, select')) return;
        else if (state.trafficDetailOpen) closeRequestDetails();
        else return;
        event.preventDefault(); event.stopPropagation();
      });
      document.querySelectorAll('[data-request-sort]').forEach(button => button.addEventListener('click', () => {
        state.trafficSortDirection = state.trafficSort === button.dataset.requestSort ? -state.trafficSortDirection : 1;
        state.trafficSort = button.dataset.requestSort;
        renderRequests();
      }));
      document.querySelector('#request-order').addEventListener('click', () => {
        state.trafficSort = 'capture'; state.trafficSortDirection = 1; renderRequests();
      });
      for (const [id, direction] of [['request-window-prev', -1], ['request-window-next', 1]]) {
        document.getElementById(id).addEventListener('click', () => {
          state.trafficWindowAnchor = null;
          state.trafficWindowStart += TRAFFIC_ROW_LIMIT * direction;
          renderRequests(); elements.requestRows.scrollTop = 0;
        });
      }
      elements.requestLatest.addEventListener('click', () => {
        state.trafficSort = 'capture'; state.trafficSortDirection = 1;
        renderRequests();
        state.trafficWindowAnchor = null; state.trafficWindowStart = TRAFFIC_RETAINED_LIMIT;
        state.trafficNewIds.clear(); renderRequests();
        elements.requestRows.scrollTop = elements.requestRows.scrollHeight;
      });
      elements.requestCopyUrl.addEventListener('click', async () => {
        const selected = state.requests.find(request => request.id === state.selectedRequestId);
        if (!selected || selected.hostOnly) return;
        try {
          const url = selected.origin === 'sample' ? `https://checkout.acme.test${selected.path}` : selected.path;
          await navigator.clipboard.writeText(url);
          elements.requestCopyUrl.textContent = 'Copied';
        } catch {
          elements.requestCopyUrl.textContent = 'Copy unavailable';
        }
        setTimeout(() => { elements.requestCopyUrl.textContent = 'Copy URL'; }, 1800);
      });
      elements.requestDomain.addEventListener('change', () => {
        state.requestDomain = elements.requestDomain.value;
        state.requestType = 'all';
        document.querySelectorAll('.type-filter').forEach(candidate =>
          candidate.setAttribute('aria-pressed', String(candidate.dataset.filter === 'all')));
        renderRequests();
      });
      elements.traceButton.addEventListener('click', () => {
        const request = state.requests.find(candidate => candidate.id === state.selectedRequestId);
        openInvestigation({kind: 'trace', identity: investigationRequestIdentity(request), relation: 'Captured request → recorded trace. Shared-identifier relationships and missing predecessors remain explicit.'});
      });

      elements.requestCollectionPivot.addEventListener('click', copyInvestigationRequestToCollection);
      elements.requestDecoderPivot.addEventListener('click', useSelectedFieldInDecoder);

      elements.requestVmCandidates.addEventListener('click', async () => {
        const selection = vmRequestSelection(state.requests, state.selectedRequestId);
        if (!selection) {
          investigationNotice('Unlinked: this Traffic row has no unique retained native request start with exact session, process and sequence identifiers. Legacy rows cannot establish a captured-response-body link. Choose another native row, or use VM navigation separately for session-wide findings.',
            'unavailable');
          return;
        }
        const refresh = refreshVmAnalysis(selection);
        showScreen('vm', elements.requestVmCandidates);
        await refresh;
      });
      elements.sourceWindowPrevious.addEventListener('click', () => {
        const current = state.sourceEditorView?.window;
        if (current) moveSourceWindow(Math.max(0, current.start - SOURCE_WINDOW_LINES));
      });
      elements.sourceWindowNext.addEventListener('click', () => {
        const current = state.sourceEditorView?.window;
        if (current) moveSourceWindow(current.end);
      });
      elements.sourceWindow.addEventListener('submit', event => {
        event.preventDefault();
        if (!moveSourceWindow(Number(elements.sourceWindowLine.value) - 1, Number(elements.sourceWindowColumn.value) - 1)) {
          elements.sourcePosition.textContent = 'Choose a retained line and column within that line.';
        }
      });
      elements.sourceSearch.addEventListener('paste', event => {
        const pasted = event.clipboardData?.getData('text/plain');
        if (typeof pasted === 'string' && /[\r\n\u2028\u2029]/u.test(pasted)) {
          event.preventDefault();
          elements.sourcePosition.textContent = 'Multiline paste refused. Find accepts a single-line literal; the existing query is unchanged.';
        }
      });
      elements.sourceSearch.addEventListener('beforeinput', event => {
        if (typeof event.data === 'string' && /[\r\n\u2028\u2029]/u.test(event.data)) {
          event.preventDefault();
          elements.sourcePosition.textContent = 'Line separators are not supported in Find; the existing query is unchanged.';
        }
      });
      elements.sourceSearch.addEventListener('input', () => applySourceSearch());
      elements.sourceSearch.addEventListener('keydown', event => {
        if (event.key !== 'Enter') return;
        event.preventDefault();
        applySourceSearch(false, event.shiftKey ? -1 : 1);
      });
      document.querySelectorAll('[data-source-collection]').forEach(button => button.addEventListener('click', () => {
        state.sourceCollection = button.dataset.sourceCollection;
        const artifact = state.artifacts.find(candidate => candidate.artifact_id === state.selectedArtifactId) ?? state.artifacts[0];
        if (artifact) selectArtifact(artifact.artifact_id);
        else renderSources();
      }));
      elements.deobfuscationIntrinsics.addEventListener('change', () => {
        retireSourceAnalysis();
        state.deobfuscationAssumeIntrinsics = elements.deobfuscationIntrinsics.checked;
        renderSources();
      });
      elements.sourceDeob.addEventListener('click', () => {
        investigationPassiveSource = false;
        sourceFactsPanel.cancel();
        state.sourceDeobfuscated = !state.sourceDeobfuscated;
        // Keep the editor's reading area and the user's Details preference.
        // At narrow widths Details is an overlay, so opening it here hides code.
        if (state.sourceDeobfuscated) document.querySelector('#deobfuscation-details').open = true;
        renderSources();
      });
      elements.sourceWasm.addEventListener('click', () => {
        const source = selectedSource();
        if (source?.kind !== 'wasm' || source.source_type !== 'artifact') return;
        sourceFactsPanel.cancel();
        state.sourceWasm = !state.sourceWasm;
        if (state.sourceWasm) loadWasmInspection(source);
        renderSources();
      });
      elements.sourcePretty.addEventListener('click', () => {
        sourceFactsPanel.cancel();
        state.sourceFormatted = !state.sourceFormatted;
        renderSources();
      });
      document.querySelector('#source-quick-open').addEventListener('click', openQuickOpen);
      elements.quickOpenInput.addEventListener('input', renderQuickOpen);
      elements.quickOpenInput.addEventListener('keydown', event => {
        if (event.key === 'Escape') {
          elements.quickOpen.hidden = true;
          document.querySelector('#source-quick-open').focus();
        }
        if (event.key === 'Enter') elements.quickOpenResults.querySelector('button')?.click();
      });


      elements.sourceSidebarToggle.addEventListener('click', () => {
        state.sourceSidebarOpen = elements.sourceSidebar.hidden;
        renderSourceSidebar();
      });


      elements.collectionRetry.addEventListener('click', () => refreshApiCollection(true));
      elements.collectionDiscardRequest.addEventListener('click', () => {
        if (state.apiCollectionSaving) return;
        state.collectionDraftDirty = false; state.collectionRequestDraftId = null;
        setCollectionNotice(state.apiCollectionNeedsReload ? 'conflict' : 'ready', state.apiCollectionNeedsReload
          ? 'Request edits discarded. Retry load to inspect the current collection.' : 'Request edits discarded. The saved request is unchanged.'); renderApiCollection();
      });
      elements.collectionDiscardFolder.addEventListener('click', () => {
        if (state.apiCollectionSaving) return;
        state.collectionFolderDirty = false; state.collectionFolderDraftId = null;
        setCollectionNotice(state.apiCollectionNeedsReload ? 'conflict' : 'ready', state.apiCollectionNeedsReload
          ? 'Folder edits discarded. Retry load to inspect the current collection.' : 'Folder edits discarded. Saved variables are unchanged.'); renderApiCollection();
      });
      for (const response of [false, true]) {
        const attribute = response ? 'collection-response-tab' : 'collection-tab';
        const tabs = [...document.querySelectorAll(`[data-${attribute}]`)];
        tabs.forEach((tab, index) => {
          tab.addEventListener('click', () => selectCollectionContent(tab.getAttribute(`data-${attribute}`), response));
          tab.addEventListener('keydown', event => {
            if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
            event.preventDefault();
            const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1
              : (index + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
            selectCollectionContent(tabs[next].getAttribute(`data-${attribute}`), response, true);
          });
        });
      }
      elements.collectionNewFolder.addEventListener('click', () => {
        if (!collectionMayLeaveDraft()) return;
        elements.collectionNewFolderForm.hidden = false;
        elements.collectionNewFolderName.value = '';
        requestAnimationFrame(() => elements.collectionNewFolderName.focus());
      });
      elements.collectionCancelFolder.addEventListener('click', () => {
        elements.collectionNewFolderForm.hidden = true;
        elements.collectionNewFolderName.value = '';
        elements.collectionNewFolder.focus();
      });
      elements.collectionConfirmFolder.addEventListener('click', createCollectionFolder);
      elements.collectionNewFolderName.addEventListener('keydown', event => {
        if (event.key === 'Enter') { event.preventDefault(); createCollectionFolder(); }
        if (event.key === 'Escape') elements.collectionCancelFolder.click();
      });
      elements.collectionNewRequest.addEventListener('click', () => createCollectionRequest());
      elements.collectionEditorEmpty.querySelector('#collection-empty-new-request')?.addEventListener('click', () => {
        elements.collectionNewRequest.click();
      });
      elements.collectionFolderForm.addEventListener('submit', event => {
        event.preventDefault(); saveCollectionFolder();
      });

      elements.collectionDeleteFolder.addEventListener('click', deleteCollectionFolder);
      elements.collectionRequestForm.addEventListener('submit', event => {
        event.preventDefault(); saveCollectionRequest();
      });

      elements.collectionDuplicateRequest.addEventListener('click', duplicateCollectionRequest);
      elements.collectionDeleteRequest.addEventListener('click', deleteCollectionRequest);

      analystElements.newFolder.addEventListener('click', createAnalystFolder);
      analystElements.newScript.addEventListener('click', () => createAnalystFile('analyst-script'));
      analystElements.newNote.addEventListener('click', () => createAnalystFile('scratchpad'));
      analystElements.editorEmpty.querySelector('#analyst-empty-new-script')?.addEventListener('click', () => {
        analystElements.newScript.click();
      });
      analystElements.editorEmpty.querySelector('#analyst-empty-new-note')?.addEventListener('click', () => {
        analystElements.newNote.click();
      });
      analystElements.folderForm.addEventListener('submit', event => {
        event.preventDefault();
        saveAnalystFolder();
      });
      analystElements.folderForm.querySelectorAll('input, select').forEach(field => field.addEventListener('input', () => {
        state.analystFolderDirty = true;
        state.analystDeleteFolderId = null;
        renderAnalystFolderForm();
      }));
      analystElements.deleteFolder.addEventListener('click', deleteAnalystFolder);
      analystElements.editorForm.addEventListener('submit', event => {
        event.preventDefault();
        saveAnalystFile();
      });
      analystElements.editorForm.querySelectorAll('input, textarea, select').forEach(field => field.addEventListener('input', () => {
        state.analystDraftDirty = true;
        state.analystDeleteFileId = null;
        if (field === analystElements.kind && field.value === 'analyst-script') analystElements.language.value = 'javascript';
        renderAnalystEditor();
        renderAnalystExecution();
      }));
      analystElements.revert.addEventListener('click', () => discardAnalystDraft());
      analystElements.revertFolder.addEventListener('click', () => discardAnalystDraft(true));
      analystElements.reload.addEventListener('click', () => refreshLocalAnalyst(true));
      window.addEventListener('beforeunload', guardAnalystUnload);
      analystElements.deleteFile.addEventListener('click', deleteAnalystFile);
      analystElements.runForm.addEventListener('submit', event => {
        event.preventDefault();
        runLocalAnalystScript();
      });
      [analystElements.includeEvents, analystElements.includeArtifacts, analystElements.includeTrace,
        analystElements.includeSignals, analystElements.includeVm, analystElements.includeSelected,
        analystElements.confirm, analystElements.confirmSensitive].forEach(field => field.addEventListener('change', () => {
          renderAnalystExecution();
        }));
      analystElements.cancel.addEventListener('click', cancelLocalAnalystScript);
      analystElements.clearHistory.addEventListener('click', () => {
        if (state.analystRunPending) return;
        state.analystRuns = [];
        state.analystSelectedRunId = null;
        state.analystTotalRuns = 0;
        state.analystHistoryEvictions = 0;
        state.analystNextRunId = 1;
        setAnalystNotice(state.localAnalyst.files.length ? 'ready' : 'empty', 'Ephemeral analyst run history was cleared. Saved files were not changed.');
        renderLocalAnalyst();
      });
      toolsElements.tabs.forEach(tab => tab.addEventListener('click', () => setToolsTab(tab.dataset.toolsTab)));
      enableTabKeyboardNavigation('[data-tools-tab]');
      toolsElements.form.addEventListener('submit', event => {
        event.preventDefault();
        appendDecoderTransform();
      });
      let decoderInputRenderFrame = 0;
      const scheduleDecoderInputRender = () => {
        if (decoderInputRenderFrame) return;
        decoderInputRenderFrame = requestAnimationFrame(() => {
          decoderInputRenderFrame = 0;
          if (state.decoderSteps.length) setToolsNotice('ready', 'Input changed. Reset the chain to use the new bytes.');
          renderTools();
        });
      };
      toolsElements.input.addEventListener('input', scheduleDecoderInputRender);
      toolsElements.inputEncoding.addEventListener('change', scheduleDecoderInputRender);
      toolsElements.operation.addEventListener('change', renderTools);
      toolsElements.useField.addEventListener('click', useSelectedFieldInDecoder);
      toolsElements.removeAfter.addEventListener('click', () => {
        const index = state.decoderSteps.findIndex(step => step.id === state.decoderSelectedStepId);
        if (index < 0) return;
        state.decoderSteps = state.decoderSteps.slice(0, index);
        state.decoderSelectedStepId = state.decoderSteps.at(-1)?.id ?? null;
        setToolsNotice('ready', 'Selected transform and every later transform were removed.');
        renderTools();
      });
      toolsElements.reset.addEventListener('click', () => resetDecoderChain());
      toolsElements.pipeline.addEventListener('keydown', event => {
        if (!['ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) return;
        const rows = [...toolsElements.pipeline.querySelectorAll('.decoder-step')];
        const current = rows.indexOf(document.activeElement);
        if (current < 0 || !rows.length) return;
        event.preventDefault();
        const next = event.key === 'Home' ? 0 : event.key === 'End' ? rows.length - 1
          : Math.max(0, Math.min(rows.length - 1, current + (event.key === 'ArrowDown' ? 1 : -1)));
        rows[next].click();
        rows[next].focus();
      });
      toolsElements.viewButtons.forEach(button => button.addEventListener('click', () => {
        state.decoderView = button.dataset.decoderView;
        renderTools();
      }));
      toolsElements.copyOutput.addEventListener('click', async () => {
        try {
          await navigator.clipboard.writeText(toolsElements.output.textContent);
          setToolsNotice('ready', 'Visible output copied. Truncated previews stay visibly marked.');
        } catch (error) {
          setToolsNotice('error', `Output could not be copied: ${error.message}`);
        }
        renderTools();
      });
      toolsElements.jwtInspectForm.addEventListener('submit', event => {
        event.preventDefault();
        runJwtAction('jwt_inspect');
      });
      toolsElements.jwtVerify.addEventListener('click', () => runJwtAction('jwt_verify'));
      toolsElements.jwtClear.addEventListener('click', () => {
        toolsElements.jwtToken.value = '';
        toolsElements.jwtSecret.value = '';
        state.jwtResult = null;
        setToolsNotice(state.decoderEngine.available ? 'ready' : 'error', 'JWT input and ephemeral result cleared.');
        renderTools();
      });
      toolsElements.jwtCreateForm.addEventListener('submit', event => {
        event.preventDefault();
        createJwtToken();
      });
      toolsElements.jwtAlgorithm.addEventListener('change', () => {
        toolsElements.jwtConfirmUnsigned.checked = false;
        toolsElements.jwtCreateSecret.value = '';
        renderTools();
      });

      const consoleTraffic = new Map();
      document.querySelector('#console-traffic-back').addEventListener('click', () => {
        delete document.querySelector('#screen-traffic').dataset.consoleTraffic;
        document.querySelector('#console-experiment-traffic').hidden = true;
      });
      document.addEventListener('reb-console-traffic', event => {
        const {session, target, events, dropped} = event.detail;
        if (!/^[1-9][0-9]{0,19}$/.test(session) || !/^[1-9][0-9]{0,19}$/.test(target) || !Array.isArray(events) || events.length > 64) return;
        for (const record of events) {
          if (!/^[1-9][0-9]{0,19}$/.test(record.event_id) || record.document_id !== target || typeof record.origin !== 'string' || record.origin.length > 256 || typeof record.method !== 'string' || record.method.length > 16 || !Number.isInteger(record.status) || !Number.isFinite(record.time)) continue;
          consoleTraffic.set(`${session}:${target}:${record.event_id}`, {...record, session});
        }
        if (investigationScreen() === 'traffic') investigationNavigation?.record();
        while (consoleTraffic.size > 128) consoleTraffic.delete(consoleTraffic.keys().next().value);
        showScreen('traffic'); document.querySelector('#screen-traffic').dataset.consoleTraffic = 'true';
        document.querySelector('#console-experiment-traffic').hidden = false;
        document.querySelector('#console-experiment-traffic').dataset.session = session;
        document.querySelector('#console-experiment-traffic').dataset.document = target;
        document.querySelector('#console-traffic-title').textContent = `Console experiment · document ${target}`;
        document.querySelector('#console-traffic-notice').textContent = `Session ${session}. Metadata only; paths, queries, headers and bodies are excluded. “After evaluation request” indicates observation order, not proven causation.${dropped ? ` ${dropped} events dropped before delivery.` : ''}`;
        const container = document.querySelector('#console-traffic-events'); container.replaceChildren();
        const records = [...consoleTraffic.values()].filter(record => record.session === session && record.document_id === target);
        if (!records.length) container.textContent = 'No completed resources observed in this document since connection. Run a request, then open Experiment activity again.';
        for (const record of records) {
          const row = document.createElement('article'); row.className = 'console-traffic-event';
          const overview = document.createElement('div'); overview.className = 'console-traffic-overview';
          for (const text of [record.method, record.status || `error ${record.network_error}`, record.origin]) { const item = document.createElement('span'); item.textContent = String(text); overview.append(item); }
          const command = document.createElement('button'); command.type = 'button'; command.className = 'native-console-location'; command.textContent = record.after_request_id === '0' ? 'Background activity' : `After evaluation request ${record.after_request_id}`;
          command.disabled = record.after_request_id === '0';
          command.addEventListener('click', () => {
            if (!/^[1-9][0-9]{0,19}$/.test(record.after_request_id)) return;
            const candidates = [...document.querySelectorAll('#native-console-output [data-request-id]')].filter(row =>
              row.dataset.requestId === record.after_request_id && row.dataset.consoleSession === session && row.dataset.consoleDocument === target);
            const result = candidates.find(row => row.classList.contains('native-console-command')) ?? candidates[0];
            if (!result) {investigationNotice('This evaluation belongs to a Console session or document whose output is no longer retained.', 'stale'); return;}
            if (document.querySelector('#native-console-panel').hidden) document.querySelector('#native-console-toggle').click();
            result.tabIndex = -1; result.focus({preventScroll: true}); result.scrollIntoView({block: 'center'});
            investigationNotice(`Console session ${session} · document ${target} · evaluation request ${record.after_request_id}${result.dataset.commandNumber ? ` · displayed command #${result.dataset.commandNumber}` : ''}. Observation order is not proof of causation.`);
          });
          overview.append(command);
          const details = document.createElement('details'); const summary = document.createElement('summary'); summary.textContent = `Event #${record.event_id} · resource ${record.resource_id}`;
          const metadata = document.createElement('pre'); metadata.textContent = JSON.stringify(record, null, 2); details.append(summary, metadata); row.append(overview, details); container.append(row);
        }
      });
      document.addEventListener('reb-console-location', event => {
        if (!investigationSourceSearch(event.detail ?? {})) event.detail.unavailable = true;
      });

      document.querySelector('#theme-toggle').addEventListener('click', () => {
        const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
        document.documentElement.dataset.theme = next;
        try { localStorage.setItem('reb-theme', next); } catch { /* Native private mode may not persist preferences. */ }
      });
      let savedTheme = null;
      try { savedTheme = localStorage.getItem('reb-theme'); } catch { /* Keep the system theme. */ }
      if (savedTheme === 'light' || savedTheme === 'dark') document.documentElement.dataset.theme = savedTheme;

      renderRequests();
      renderInspector();
      renderEvidence();

      renderSources();
      renderVmLab();
      renderApiCollection();
      renderLocalAnalyst();
      renderTools();
      if (location.protocol === 'file:') {
        useStandalonePreview();
      } else {
        refresh();
        refreshApiCollection();
        refreshLocalAnalyst();
        refreshDecoderEngine();

        setInterval(refresh, 2000);
      }

      initializeInvestigationNavigation();
      const investigationNotebook = RebInvestigationNotebook.mount({
        button: document.querySelector('#open-investigation-notebook'),
        validateLibrary: isLocalAnalystWorkspace,
        getContext: () => ({events: state.events, artifacts: state.artifacts}),
        getSelection: () => {
          if (investigationScreen() === 'sources') {
            const artifact = selectedSource();
            if (artifact?.source_type !== 'artifact') return null;
            const identity = investigationArtifactIdentity(artifact);
            const range = investigationSame(investigationRange?.identity, identity) ? investigationRange : null;
            return {kind: 'artifact', artifact, range};
          }
          let event = investigationScreen() === 'evidence' ? evidenceWorkspace.selectedEvent() : null;
          if (investigationScreen() === 'traffic') event = requestTraceRoot(state.requests.find(item => item.id === state.selectedRequestId));
          if (!event) return null;
          const identity = investigationEventIdentity(event);
          const retained = state.events.filter(value => investigationSame(identity, investigationEventIdentity(value)));
          return retained.length === 1 ? {kind: 'event', event} : null;
        },
        openReference: (reference, token) => {
          if (reference.type === 'captured-artifact') return openInvestigation({kind: 'artifact', identity: reference,
            range: reference.range, relation: 'Opened a saved exact artifact reference. The note is researcher interpretation.'});
          const matches = state.events.filter(event => String(event.session_id) === reference.session &&
            String(event.process_id) === reference.process && String(event.sequence_number) === reference.sequence);
          if (matches.length !== 1) return false;
          try {if (RebInvestigationNotebook.eventCanonical(matches[0]) !== token) return false;} catch {return false;}
          const key = `${reference.session}:${reference.process}:${reference.sequence}`;
          showScreen('evidence');
          return evidenceWorkspace.openEvent(key);
        }
      });
      initializePaneLayout();

      // Native disclosures keep the application menus keyboard-accessible without
      // claiming an ARIA menubar's separate arrow-key interaction model.
      const vmMenus = [...document.querySelectorAll('.vm-menu')];
      const closeVmMenus = () => vmMenus.forEach(menu => { menu.open = false; });
      vmMenus.forEach(menu => {
        menu.addEventListener('toggle', () => {
          if (menu.open) {
            vmMenus.forEach(other => { if (other !== menu) other.open = false; });
            updateVmNavigationMenus();
          }
        });
        menu.addEventListener('keydown', event => {
          if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); menu.open = false; menu.querySelector('summary').focus(); }
        });
      });
      document.addEventListener('pointerdown', event => { if (!event.target.closest('.vm-menu')) closeVmMenus(); });
      document.querySelectorAll('[data-vm-command]').forEach(button => {
        button.addEventListener('click', () => {
          const command = button.dataset.vmCommand;
          const summary = button.closest('.vm-menu').querySelector('summary');
          closeVmMenus(); summary.focus();
          if (command === 'vm-return-traffic') { document.querySelector('#screen-vm .back-button').click(); return; }
          if (command.startsWith('vm-handler-')) {
            vmWorkspaceCommand(command === 'vm-handler-filter' ? 'search' : command === 'vm-handler-next' ? 'next' : 'previous', true);
            return;
          }
          const target = document.getElementById(command);
          if (target) { target.click(); target.focus(); }
        });
      });
