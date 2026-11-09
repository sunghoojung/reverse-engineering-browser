// Browser instrumentation is native-only. This viewer never attaches a debugger.
const sourceFactsPanel = createSourceFactsPanel({
  getSource: selectedSource, onNavigate: revealSourceFactRange,
  openSidebar() { state.sourceSidebarOpen = true; renderSourceSidebar(); }
});
const capturedExportPanel = installCapturedExportDialog({
  getRun: () => null, contextKey: () => null, getRunCapture: () => null,
  notice: message => investigationNotice(message)
});
const invocationSitesPanel = createInvocationSitesPanel({
  root: document.querySelector('#invocation-sites-panel'),
  chip: document.querySelector('#invocation-tracking'),
  trackButton: document.querySelector('#source-track-calls'),
  getSource: selectedSource, positionProblem: invocationSitePositionProblem, getPosition: invocationSitePosition,
  onReveal: candidate => revealOriginalLine(selectedSource(), candidate.line - 1, candidate.column - 1),
  onShow: showInvocationSites
});
invocationSitesPanel.refresh();
const sourceFormatClient = createSourceFormatClient({
  onChange: source => { if (state.sourceFormatted && sourceIdentity(selectedSource()) === sourceIdentity(source)) renderSources(); }
});
const sourceTreeView = createSourceTree({
  tree: elements.sourceTree, filter: document.querySelector('#source-tree-filter'),
  expand: document.querySelector('#source-tree-expand'), collapse: document.querySelector('#source-tree-collapse'),
  helpers: {isSource: isSourceArtifact, identity: sourceIdentity, reference: sourceReference, name: sourceDisplayName, isCurrent: sourceIsCurrent},
  catalog: () => state.artifacts, collection: () => state.sourceCollection, selectedId: () => state.selectedArtifactId,
  catalogLimit: () => state.artifactCatalogLimit, consoleDocuments: () => state.consoleDocuments,
  hideInternal: () => state.hideBrowserInternal, internalToggle: internal => sourceInternalToggle(internal),
  kindLabel: source => sourceKindLabel(source.kind),
  researcherName(source) {
    const names = globalThis.RebEvidenceNames?.controller?.() ?? null;
    return names?.has('captured-artifact') ? names.nameFor('artifact', source) : null;
  },
  open: artifactId => selectArtifact(artifactId),
  stale() {
    state.sourceNoticeKind = 'warning';
    state.sourceNotice = 'This exact source changed or is no longer available. Refresh the catalog before opening it.';
    renderSourceHealth();
  }
});
// The Console's document listing names frames and marks the top-level ones.
document.addEventListener('reb:console-documents', event => { state.consoleDocuments = event.detail; renderSourceTree(); });
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
          messages.push(state.connection === 'unresponsive'
            ? 'The local evidence broker did not answer within 10 seconds.'
            : 'The local evidence broker is disconnected.');
        }
        // The request index lists the whole session, so window caps do not limit Traffic rows.
        const indexed = state.trafficIndex?.answer?.() ?? null;
        if (state.eventsLimited && !indexed) {
          if (kind === 'empty') kind = 'gap';
          messages.push('Showing the last 5,000 evidence events; older events remain recorded on disk.');
        }
        if (state.networkEventsLimited && !indexed) messages.push('The network event window is capped; older request lifecycle evidence may be incomplete.');
        if (state.eventCountScope === 'bounded_tail') {
          if (kind === 'empty') kind = 'gap';
          messages.push(indexed ? 'Gap and drop counts cover only the newest 64 MiB of stored evidence; the request list covers the whole session.'
            : 'Only the newest 64 MiB of stored evidence is scanned; counts and both windows exclude the older prefix.');
        }
        if (gapCount > 0n) {
          if (kind === 'empty') kind = 'gap';
          messages.push(`${state.sequenceGapsSaturated ? 'at least ' : ''}${gapCount} sequence-gap IDs were observed in ${eventCountScopeLabel()}; late arrivals may overlap. Native evidence may be incomplete.`);
        }
        if (reportedDrops > 0n) {
          if (kind === 'empty') kind = 'gap';
          messages.push(`The queue reports ${state.queueDropsSaturated ? 'at least ' : ''}${reportedDrops} dropped ${reportedDrops === 1n ? 'event' : 'events'}${gapCount > 0n ? '; counts may overlap sequence gaps' : `; no sequence jump is visible in ${eventCountScopeLabel()}`}.`);
        }
        if (state.eventMalformedLines > 0) {
          if (kind === 'empty') kind = 'gap';
          messages.push(`${state.eventMalformedLines} unreadable ${state.eventMalformedLines === 1 ? 'line was' : 'lines were'} skipped in ${eventCountScopeLabel()}.`);
        }
        const networkLimits = namedGapNotice(namedGapsIn(shownNamedGaps(), networkGapCategories), eventCountScopeLabel());
        if (networkLimits) {
          if (kind === 'empty') kind = 'gap';
          messages.push(networkLimits);
        }

        const failedNotice = indexed ? indexed.document.failed > 0 ? `Failed requests: ${indexed.document.failed}.` : ''
          : trafficFailedRequestNotice(state.requests);
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
        const label = type.split('_').map(part => part === 'api' ? 'API' : part).join(' ');
        return label.charAt(0).toUpperCase() + label.slice(1);
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
          textElement('h3', '', capture.id),
          textElement('p', '', `${capture.context}${capture.width ? ` · ${capture.width} × ${capture.height}` : ''} · ${capture.readback} · ${capture.calls.length} observed drawing ${capture.calls.length === 1 ? 'call' : 'calls'}`)
        );
        const badges = document.createElement('div');
        badges.className = 'signal-render-badges';
        badges.append(textElement('span', capture.demo ? 'demo' : 'live', capture.demo ? 'Demo replay' : 'Native event'));

        header.append(title, badges);

        const comparison = document.createElement('div');
        comparison.className = 'signal-canvas-comparison';
        comparison.append(
          canvasPreview(capture, capture.demo ? 'Demo output' : 'Captured output', `${capture.id} captured output`, true)
        );
        const replay = document.createElement('details');
        replay.className = 'signal-capture-disclosure';
        replay.dataset.captureKey = `${signalEventKey(capture.evidenceEvent)}:replay`;
        replay.append(textElement('summary', '', 'Compare with local replay'),
          canvasPreview(capture, 'Local replay', `${capture.id} local replay`));

        const body = document.createElement('div');
        body.className = 'signal-render-body';
        const calls = document.createElement('section');
        calls.className = 'signal-draw-calls';
        const callsHead = document.createElement('div');
        callsHead.className = 'signal-draw-calls-head';
        callsHead.append(
          textElement('h4', '', 'Drawing calls'),
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
          elements.signalRequestProfile.replaceChildren(textElement('div', 'signal-render-empty', 'Building the selected request profile…'));
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
          textElement('span', '', 'Selected request'),
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
        const requestTabLabels = new Map(requestTabGroups().map((group, index) => [group.id, `Tab ${index + 1}`]));
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
        elements.signalStopCapture.disabled = Boolean(state.captureAction) || !state.captureControlsAvailable ||
          state.captureStopped || state.broker !== 'connected' || state.sessionMode !== 'live';
        elements.signalClearEvents.disabled = Boolean(state.captureAction) || !state.captureControlsAvailable ||
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
        // A failed poll leaves the last reported capture state unknown, so it
        // outranks Probes stopped. A broker that is merely offline (as after
        // Stop) still answers, and its stopped state stays visible.
        const failed = state.eventFailureKind !== null;
        const offline = state.broker === 'unavailable' || failed;
        const retainedLabel = signalEvents.length ? 'Evidence retained' : 'Disconnected';
        elements.signalSessionBadge.textContent = failed ? retainedLabel
          : state.captureStopped ? 'Probes stopped'
          : offline ? retainedLabel
          : state.sessionMode === 'demo' ? 'Demo evidence'
            : state.sessionMode === 'live' ? 'Live native capture' : 'No capture';
        elements.signalSessionBadge.dataset.kind = failed ? 'offline' : state.captureStopped ? 'stopped' : offline ? 'offline' : state.sessionMode;

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
        const signalLimits = namedGapsIn(shownNamedGaps(), fingerprintSignalCategories);
        if (state.captureAction) {
          setSignalNotice('loading', state.captureAction === 'stop'
            ? 'Stopping native probes…' : 'Clearing this session’s events…');
        } else if (state.eventFailureKind === 'malformed') {
          setSignalNotice('error', signalEvents.length
            ? 'The broker returned malformed event data. The last understandable fingerprint evidence remains visible.'
            : 'The broker returned malformed event data. No fingerprint evidence is available.');
        } else if (failed) {
          const reason = state.connection === 'unresponsive' ? 'The broker did not answer within 10 seconds' : 'The broker is disconnected';
          setSignalNotice('disconnected', signalEvents.length
            ? `${reason}. The last understandable fingerprint evidence remains visible.`
            : `${reason} and no fingerprint evidence is available.`);
        } else if (state.captureActionError) {
          setSignalNotice('error', state.captureActionError);
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
        } else if (state.eventsLimited || state.eventCountScope === 'bounded_tail' || displayLimited || gapCount > 0n || reportedDrops > 0n || signalLimits.length) {
          setSignalNotice('partial', fingerprintCoverageNotice(
            state.eventsLimited, displayLimited, signalEventDisplayLimit, gapCount, reportedDrops, eventCountScopeLabel(), signalLimits
          ));
        } else if (state.sessionMode === 'demo') {
          setSignalNotice('demo', 'Demo mode: both Canvas images are reconstructed locally from the visible calls. They are not native-captured pixels.');
        } else if (state.sessionMode === 'idle') {
          setSignalNotice('idle', 'Showing stored native fingerprint evidence. No capture session is running.');
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
          if (row.dataset.new === 'true') primary.append(textElement('span', 'signal-new-badge', 'New'));
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
        const loaded = state.trafficLoaded;
        // The selection keeps its last window copy, so it survives leaving the window (#437).
        const selected = state.selectedRequestId === null ? null : state.nativeRequests.find(request => request.id === state.selectedRequestId);
        if (loaded && selected && trafficRecordCount(selected) >= trafficRecordCount(loaded.get(selected.id))) loaded.set(selected.id, selected);
        // Without an index answer this list is state.requests itself, so only the selection may stay.
        if (loaded && !trafficIndexActive()) for (const id of loaded.keys()) if (id !== state.selectedRequestId) loaded.delete(id);
        if (!loaded?.size) {
          state.requests = state.nativeRequests;
          return;
        }
        // Rows read on selection stay selectable and replace a window copy with fewer records.
        const merged = state.nativeRequests.map(request => {
          const read = loaded.get(request.id);
          return read && trafficRecordCount(read) > trafficRecordCount(request) ? read : request;
        });
        const windowIds = new Set(state.nativeRequests.map(request => request.id));
        for (const [id, request] of loaded) if (!windowIds.has(id)) merged.push(request);
        state.requests = merged;
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
        // Sensitive capture is labeled for the whole session, not only in the
        // rows it fills, because the packaged app turns it on without a dialog.
        const retained = [state.requestContentCaptureEnabled && 'request paths, queries and bodies, and response bodies, up to 16 MiB each, request and response headers, cookies',
          state.canvasImageCaptureEnabled && 'Canvas images'].filter(Boolean);
        elements.sessionContent.hidden = !live || !retained.length;
        // The launch turned these on; a browser built before them ignores the
        // switch, so each row and body still says what was actually captured.
        elements.sessionContent.title = `Content capture is on for this session: ${retained.join(' and ')}, kept locally. Each Traffic row and body shows what was actually captured. A Metadata only session keeps request hosts and body digests instead.`;
        elements.sessionContent.setAttribute('aria-label', `Content capture: ${retained.join(' and ')}`);
        elements.capture.classList.toggle('offline', offline || artifactOffline);
        elements.capture.classList.toggle('demo', state.sessionMode === 'demo');
        elements.capture.classList.toggle('preview', preview);
        elements.capture.querySelector('span:last-child').textContent = captureLabel;
        elements.capture.setAttribute('aria-label', `${modeLabel}: ${captureLabel}`);
        elements.broker.classList.toggle('offline', offline);
        elements.broker.textContent = connecting ? 'connecting to evidence'
          : offline ? state.connection === 'unresponsive' ? 'broker not responding' : 'broker unavailable'
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

      function renderRequestCount(visibleCount, loadedCount, scope = 'loaded') {
        if (visibleCount === null) {
          elements.requestCount.textContent = 'No';
          elements.requestCountLabel.textContent = 'requests read yet';
          return;
        }
        elements.requestCount.textContent = visibleCount.toLocaleString('en-US');
        if (scope === 'session') {
          elements.requestCountLabel.textContent = visibleCount === loadedCount ? loadedCount === 1 ? 'request' : 'requests'
            : `of ${loadedCount.toLocaleString('en-US')} ${loadedCount === 1 ? 'request' : 'requests'}`;
          return;
        }
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
        const names = globalThis.RebEvidenceNames?.controller?.() ?? null;
        const nameOf = row => names?.nameFor('handler', row, workspace) ?? null;
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
        ['Source offset', 'Opcode', 'Operation / handler', 'Evidence', 'Samples'].forEach(label => header.append(textElement('span', '', label)));
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
          // A researcher name leads the cell; the analyzer label, opcode and
          // source offsets stay visible beside it.
          const researcher = textElement('span', 'researcher-name', nameOf(rowData) ?? '');
          researcher.hidden = !researcher.textContent;
          label.append(researcher, textElement('strong', '', rowData.label), textElement('small', '', `source ${rowData.source}`));
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
            row.hidden = !`${rows[index].source} ${rows[index].opcode} ${rows[index].label} ${nameOf(rows[index]) ?? ''}`.toLowerCase().includes(query);
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
        if (!previews.length) selector.append(Object.assign(textElement('option', '', 'No retained byte evidence'), {value: '0'}));
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
      // Running and failure text per workspace key. Polls rebuild the form while
      // a request runs, so its outcome cannot live in the form's own DOM node.
      const ownedExperimentNotices = new Map();
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
        const output=document.createElement('div');output.className='vm-experiment-output';output.dataset.experimentKey=key;output.setAttribute('role','status');
        const retain = rows => { if(!ownedExperimentResults.has(key) && ownedExperimentResults.size>=64) ownedExperimentResults.delete(ownedExperimentResults.keys().next().value); ownedExperimentResults.set(key,rows); };
        const note = text => { ownedExperimentNotices.delete(key); if(text!==null){ if(ownedExperimentNotices.size>=64) ownedExperimentNotices.delete(ownedExperimentNotices.keys().next().value); ownedExperimentNotices.set(key,text);} };
        // A finished request paints the form now on screen for this key.
        const show = (target = [...document.querySelectorAll('.vm-experiment-output')].find(node=>node.dataset.experimentKey===key) ?? output) => { const text=ownedExperimentNotices.get(key); target.replaceChildren(); if(text!==undefined){target.textContent=text;return;} const rows=ownedExperimentResults.get(key) ?? []; if(rows.length===0) target.append(textElement('p','','No saved result for this exact workspace and selected effect.')); rows.forEach(row=>target.append(textElement('p','',`${row.status}: opcode ${row.request.opcode}, inputs ${row.request.inputs.left}, ${row.request.inputs.right}; expected ${row.request.expected.value}, next PC ${row.request.expected.next_pc}; observed ${row.observed?.effect.value ?? 'unknown'}, handler ${row.observed?.handler_index ?? 'unknown'}, PC ${row.observed?.pc_before ?? 'unknown'} → next PC ${row.observed?.effect.next_pc ?? 'unknown'}. ${row.reason}. These inputs only; does not generalize.`))); };
        show(output);
        form.addEventListener('submit',async event=>{
          event.preventDefault(); if(ownedExperimentPending) return;
          const candidate=candidates.find(c=>String(c.opcode)===select.value); if(!candidate) return;
          const request={command_id:crypto.randomUUID(),fixture,workspace_digest:workspaceDigest,
            source_artifact_sha256:workspace.source_artifact_sha256,interpreter_artifact_id:workspace.interpreter_artifact_id,finding_id:workspace.finding_id,
            opcode:candidate.opcode,effect_id:candidate.effect.effect_id,inputs:{left:fields.left.value,right:fields.right.value},
            expected:{operation:candidate.effect.operation,value:fields.value.value,next_pc:fields.next_pc.value,branch_taken:candidate.opcode===7?branch.value==='true':null}};
          ownedExperimentPending=true;run.disabled=true;note('Running the disposable owned fixture. No automatic retry.');show();
          try {const response=await fetch('/api/analysis/vm/experiments',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(request),signal:AbortSignal.timeout(30000)});
            const row=await response.json();if(!response.ok || !isVmOwnedExperimentRecord(row) || !sameVmOwnedExperimentRequest(row.request,request)) throw new Error('Outcome unknown or refused. Read saved results before trying another experiment.');
            const rows=[...(ownedExperimentResults.get(key) ?? []),row].slice(-64);retain(rows);note(null);
          } catch(error) {note(error.message);} finally {ownedExperimentPending=false;show();document.querySelectorAll('.vm-experiment-form button[type=submit]').forEach(button=>{button.disabled=false;});}
        });
        load.addEventListener('click',async()=>{load.disabled=true;try {const response=await fetch('/api/analysis/vm/experiments',{cache:'no-store',signal:AbortSignal.timeout(5000)});const doc=await response.json();
          if(!response.ok || doc.schema!=='reb-owned-opcode-experiments-v1' || !Array.isArray(doc.records) || doc.records.length>64 || !doc.records.every(isVmOwnedExperimentRecord)) throw new Error('Saved experiment results are unavailable or malformed.');
          const rows=doc.records.filter(r=>r.request.workspace_digest===workspaceDigest && r.request.finding_id===workspace.finding_id && r.request.source_artifact_sha256===workspace.source_artifact_sha256 && r.request.interpreter_artifact_id===workspace.interpreter_artifact_id && candidates.some(c=>c.opcode===r.request.opcode && c.effect.effect_id===r.request.effect_id));retain(rows);note(null);
        }catch(error){note(error.message);}finally{load.disabled=false;show();}});
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
          textElement('p', 'vm-workspace-notice', 'Physical module offsets and selectors are not guest-interpreter PCs or recovered guest opcodes. A direct caller is the live Liftoff function of the same instance when the record walked the stack; a host, other-instance, or non-Liftoff caller is unknown. The parent event id stays unset.'));
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
        const indirectRows = Array.isArray(workspace.native_wasm_indirect_observations) ? workspace.native_wasm_indirect_observations : [];
        panel.append(textElement('h4', '', 'Native call_indirect observations'),
          textElement('p', 'vm-workspace-notice', 'A slot is the dynamic table index of one indirect call and the callee is the table entry it was about to use. Neither is a guest opcode or guest PC.'));
        appendVmPagedRows(panel, indirectRows, 'native call_indirect observations', row => nativeRow(row, vmNativeWasmIndirectPositionText(row)));
        if (!indirectRows.length) panel.append(textElement('p', 'vm-selection-empty', 'No native call_indirect observations retained.'));
        const indirectCount = vmNativeAcceptedCount(workspace.native_wasm_indirect_observation_count, indirectRows.length);
        if (indirectCount > indirectRows.length) panel.append(textElement('p', 'vm-workspace-notice',
          `${indirectCount - indirectRows.length} accepted call_indirect observations are outside the retained window.`));
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

      const vmObservedStreamLabels = {'native-guest': 'Native guest', 'native-wasm': 'Native br_table',
        'native-wasm-indirect': 'Native call_indirect', 'native-js': 'Native JS dispatch', 'dispatch-sample': 'Native dispatch sample'};
      const vmObservedOmission = reason => /^(?:observed-claim|nested-guest|native-js-)/.test(reason);
      function vmHasRuntimeClaims(workspace) {
        return workspace.observed_claims !== undefined || workspace.nested_guests !== undefined ||
          workspace.js_dispatch_arming !== undefined || workspace.coverage.omissions.some(row => vmObservedOmission(row.reason));
      }
      function vmObservedSiteText(claim) {
        if (claim.site === null) return 'site not recorded, artifact scope';
        if (claim.stream === 'native-js') return `line ${claim.site.line}:${claim.site.column} · anchor byte ${claim.site.anchor_offset}`;
        if (claim.site.line !== null) return `line ${claim.site.line}:${claim.site.column}, sole interpreter candidate`;
        return `f${claim.site.function_index} · byte ${claim.site.byte_offset}`;
      }
      function vmObservedHandlerText(claim) {
        if (claim.handler.kind === 'handler-index') return `handler ${claim.handler.handler_index}`;
        if (claim.handler.kind === 'table-entry') return `function ${claim.handler.callee_function_index}`;
        if (claim.handler.kind === 'switch-case') return `case ${claim.handler.case_value}`;
        if (claim.handler.kind === 'handler-span') return claim.handler.byte_offset === null
          ? 'handler outside this script' : `handler bytes ${claim.handler.byte_offset} + ${claim.handler.byte_size}`;
        return claim.handler.is_default ? `default arm ${claim.handler.arm}` : `arm ${claim.handler.arm}`;
      }
      function vmObservedStaticText(claim) {
        const comparison = claim.static_claim;
        if (claim.stream === 'native-js') {
          if (comparison.state === 'agrees') return `Static claim agrees: recovery at this site names opcode ${comparison.opcode} at byte ${comparison.byte_offset}.`;
          if (comparison.state === 'disagrees') return `Static claim disagrees: recovery names another handler for opcode ${comparison.opcode} at byte ${comparison.byte_offset}. Both are kept.`;
        }
        const javascript = claim.stream === 'dispatch-sample' || claim.stream === 'native-js';
        if (claim.stream === 'native-wasm-indirect') {
          const placed = comparison.handler_index === null ? 'leave this slot empty' : `place function ${comparison.handler_index} in this slot`;
          if (comparison.state === 'agrees') return `Static claim agrees: the element segments ${placed}.`;
          if (comparison.state === 'disagrees') return `Static claim disagrees: the element segments ${placed}, but function ${claim.handler.callee_function_index} ran. The table changed at run time. Both are kept.`;
          if (comparison.state === 'withheld') return `Static claim withheld: table ${claim.handler.table_index} is filled at run time, so its element segments make no claim for slot ${comparison.opcode}.`;
          return 'No static claim: no element segment fills this slot.';
        }
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
          const selector = claim.selector === null ? '' : `${claim.handler.kind === 'table-entry' ? 'slot' : 'selector'} ${claim.selector} to `;
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
        if (workspace.runtime === 'javascript') {
          if (workspace.js_dispatch_arming) renderVmJsDispatchArming(workspace.js_dispatch_arming, panel);
          return renderVmJavaScriptNestedGuests(workspace, panel);
        }
        if (workspace.runtime !== 'webassembly') return panel;
        panel.append(textElement('h4', '', 'Nested guests'),
          textElement('p', 'vm-workspace-notice', 'An inner interpreter is a guest activation that names a parent invocation, runs at another interpreter-candidate site and reads another guest buffer. Its outer handler is the parent dispatch its invocation names exactly, or for older evidence the parent dispatch retained last before it began.'));
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
          const basis = outer.basis === 'exact-parent-dispatch'
            ? 'The inner invocation names this outer dispatch: it was the outer activation\'s current dispatch on the native stack when the inner one began.'
            : outer.basis === 'contiguous-sequence'
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
        if (!nested.length) panel.append(textElement('p', 'vm-selection-empty', 'No nested guest retained. An inner interpreter is linked only when it runs at another configured adapter site than its parent; an activation reentering its parent\'s site names that parent but is not a nested guest.'));
        return panel;
      }

      // The native-js-dispatch-sites-v1 file text is shown inert, to save
      // and pass with REB_NATIVE_JS_DISPATCH_SITES; nothing here arms a probe.
      function renderVmJsDispatchArming(arming, panel) {
        panel.append(textElement('h4', '', 'Native probe sites'),
          textElement('p', 'vm-workspace-notice', `${vmCountText(arming.sites.length, 'interpreter-candidate site')} can be armed for the native JavaScript dispatch probe (at most 8). A rebuilt browser reads the file below only from an explicit launch setting.`));
        for (const site of arming.sites) {
          panel.append(textElement('p', 'vm-effect-detail', `${site.shape} · byte ${site.byte_offset} · UTF-16 anchor ${site.anchor_offset}`));
        }
        for (const row of arming.refused) {
          panel.append(textElement('p', 'vm-effect-detail', `Not armed: ${row.instruction} at byte ${row.byte_offset} (${row.reason})`));
        }
        if (arming.omitted_refused_count) panel.append(textElement('p', 'vm-workspace-notice', `${arming.omitted_refused_count} more refused sites are not listed.`));
        if (arming.file !== null) panel.append(textElement('pre', 'vm-effect-detail vm-evidence-audit', arming.file));
      }

      function renderVmJavaScriptNestedGuests(workspace, panel) {
        panel.append(textElement('h4', '', 'Nested guests'),
          textElement('p', 'vm-workspace-notice', 'An inner interpreter is a native JavaScript activation whose first dispatch named a parent activation that had already dispatched at another interpreter-candidate site. The parent is a call-stack relation, not proof of which outer handler ran it.'));
        const nested = workspace.nested_guests ?? [];
        appendVmPagedRows(panel, nested, 'nested guests', guest => {
          const {outer, inner} = guest;
          const row = document.createElement('details'); row.className = 'vm-effect-row';
          const summary = document.createElement('summary');
          const selector = outer.selector === null ? `${outer.selector_kind} selector` : `selector ${outer.selector}`;
          summary.append(textElement('span', 'vm-native-row-identity', `Inner line ${inner.site.line}:${inner.site.column} · activation ${inner.activation_id}`), document.createElement('br'),
            textElement('span', 'vm-native-row-position', `Driven by outer line ${outer.site.line}:${outer.site.column} · activation ${outer.activation_id}, ${selector}`));
          const opcodes = inner.observed_opcodes.map(entry => `${entry.opcode} (${vmCountText(entry.sample_count, 'sample')})`).join(', ');
          const omitted = inner.omitted_opcode_count ? `, and ${inner.omitted_opcode_count} more opcodes` : '';
          const basis = outer.basis === 'contiguous-sequence'
            ? 'Every renderer event between the outer dispatch and the inner activation is retained, so no other outer dispatch ran in between.'
            : 'Events between the outer dispatch and the inner activation are missing or include a gap, so this is the nearest retained outer dispatch, not proof of the exact one.';
          row.append(summary,
            textElement('p', 'vm-effect-detail', `Inner opcodes: ${opcodes || 'none'}${omitted} · ${vmCountText(inner.sample_count, 'retained sample')}`),
            textElement('p', 'vm-effect-detail', `Outer dispatch process ${outer.dispatch_event.process_id} seq ${outer.dispatch_event.sequence_number}. ${basis}`),
            textElement('p', 'vm-effect-detail', vmObservedEventsText(inner.events, inner.sample_count)),
            textElement('pre', 'vm-effect-detail vm-evidence-audit', JSON.stringify(guest, null, 2)));
          return row;
        });
        if (!nested.length) panel.append(textElement('p', 'vm-selection-empty', 'No nested guest retained. An activation needs a parent that dispatched first at another interpreter-candidate site.'));
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
          const heading = document.createElement('div'); heading.className = 'vm-pane-label vm-selection-head';
          const names = globalThis.RebEvidenceNames?.controller?.() ?? null;
          const identity = row ? names?.identityFor('handler', row, workspace) ?? null : null;
          const rename = textElement('button', 'secondary-button', 'Rename'); rename.type = 'button'; rename.id = 'vm-handler-rename';
          rename.setAttribute('aria-keyshortcuts', 'F2');
          rename.disabled = !identity;
          rename.title = identity ? 'Rename this handler (F2)' : row ? 'This handler has no exact retained program identity to name.' : 'Select a handler to name it.';
          heading.append(textElement('span', '', 'Selected handler'), rename);
          const editorHost = document.createElement('div'); editorHost.className = 'evidence-name-host'; editorHost.id = 'vm-handler-name-host';
          if (!row) { selectedInspector.replaceChildren(heading, editorHost, textElement('p', 'vm-selection-empty', 'Select a retained handler to inspect its evidence.')); return; }
          const title = document.createElement('h3');
          const researcherName = identity ? names.nameOf(identity) : null;
          if (researcherName) title.append(textElement('span', 'researcher-name', researcherName), document.createTextNode(' '));
          title.append(textElement('span', 'vm-selection-raw', row.label));
          const fields = document.createElement('div'); fields.className = 'vm-selection-fields';
          for (const [label, value] of [['Opcode', row.opcode], ['Source byte range', row.source], ['Evidence', row.state], ['Samples', String(row.samples)], ['Operand width', row.operandWidth ? `${row.operandWidth} bytes (characterized)` : 'unknown']]) {
            fields.append(textElement('span', '', label), textElement('strong', '', value));
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
          selectedInspector.replaceChildren(heading, editorHost, title, fields, observations, notes);
        };
        // Names change without a new workspace; redraw only this inspector.
        selectedInspector.addEventListener('evidence-names-changed', () => updateSelection(state.selectedVmHandlerKey));
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
          const names = globalThis.RebEvidenceNames?.controller?.() ?? null;
          for (const row of rows) {
            const button = textElement('button', 'vm-symbol-row', ''); button.type = 'button';
            const researcherName = names?.nameFor('handler', row, workspace) ?? null;
            if (researcherName) button.append(textElement('span', 'researcher-name', researcherName), document.createTextNode(' '));
            button.append(textElement('span', 'vm-symbol-raw', row.label));
            button.dataset.vmSymbolKey = row.key;
            button.setAttribute('aria-pressed', String(row.key === state.selectedVmHandlerKey));
            button.title = `${researcherName ? `${researcherName} (researcher name) · ` : ''}${row.label} · opcode ${row.opcode} · source ${row.source}`;
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
        const vmLimits = namedGapNotice(namedGapsIn(shownNamedGaps(), vmGapCategories), eventCountScopeLabel());
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
          const empty = state.vmAnalysisSelection ? 'No VM candidates are linked to this exact captured response body. Unlinked, legacy and session-wide findings are not shown.' : 'No VM findings yet. The lab waits for observed or explicitly inferred evidence.';
          setVmNotice(vmLimits ? 'gap' : 'empty', vmLimits ? `${empty} ${vmLimits}` : empty);
        } else if (gapCount > 0n || vmLimits) {
          setVmNotice('gap', [
            gapCount > 0n ? `${gapCount} event ${gapCount === 1n ? 'gap may' : 'gaps may'} make VM coverage incomplete (observed sequence jumps in ${eventCountScopeLabel()}).` : '',
            vmLimits
          ].filter(Boolean).join(' '));
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

      function requestDomain(request) { return trafficRequestDomain(request); }

      function requestTabGroups() {
        const groups = new Map();
        state.requests.forEach(request => requestTabsOf(request).forEach(id => {
          const group = groups.get(id) ?? {id, requests: [], firstTimestamp: request.firstTimestamp};
          group.requests.push(request);
          if (request.firstTimestamp < group.firstTimestamp) group.firstTimestamp = request.firstTimestamp;
          groups.set(id, group);
        }));
        return [...groups.values()].sort((left, right) =>
          left.firstTimestamp < right.firstTimestamp ? -1 : left.firstTimestamp > right.firstTimestamp ? 1 : 0);
      }

      function trafficLocalScopes() {
        const groups = requestTabGroups().map(group => ({id: group.id, count: group.requests.length,
          domains: [...new Set(group.requests.map(requestDomain))],
          title: group.requests.map(request => String(request.tabTitle ?? '').trim()).find(Boolean),
          page: globalThis.RebRequestTabs?.tabPageLabel(group.requests, requestDomain) ?? null}));
        const scoped = state.requests.filter(requestInScope);
        const domainCounts = new Map();
        for (const request of scoped) { const domain = requestDomain(request); domainCounts.set(domain, (domainCounts.get(domain) ?? 0) + 1); }
        return {total: state.requests.length, groups, scopedCount: scoped.length,
          domains: [...domainCounts.keys()].sort((left, right) => left.localeCompare(right)).map(domain => [domain, domainCounts.get(domain)])};
      }

      function trafficIndexScopes(answer) {
        // Rows with no tab are a capture error listed from the footer, not a tab.
        const groups = answer.facets.tabs.filter(tab => tab.tab_id !== '0').map(tab => ({id: tab.tab_id,
          count: tab.count, domains: tab.domains, title: null, page: null}));
        const unresolved = answer.facets.tabs.find(tab => tab.tab_id === '0')?.count ?? 0;
        return {total: answer.through, groups, unresolved, domains: answer.facets.domains.map(entry => [entry.domain, entry.count]),
          scopedCount: state.requestTabId === 'all' ? answer.through
            : state.requestTabId === 'unresolved' ? unresolved : groups.find(group => group.id === state.requestTabId)?.count ?? 0};
      }

      // `countsKnown` is false until anything has been read; zero would misstate the session.
      function renderRequestScopes(scopes = trafficLocalScopes(), countsKnown = true) {
        const groups = scopes.groups;
        const availableTabs = new Set(groups.map(group => group.id));
        if (state.requestTabId !== 'all' && !availableTabs.has(state.requestTabId) &&
            !(state.requestTabId === 'unresolved' && (scopes.unresolved === undefined
              ? state.requests.some(request => !requestTabsOf(request).length) : scopes.unresolved > 0))) state.requestTabId = 'all';
        const oldScopes = new Map([...elements.requestTabScopes.children].map(button => [button.dataset.scopeId, button]));
        const focusedScope = elements.requestTabScopes.contains(document.activeElement) ? document.activeElement : null;
        const buttons = [{id: 'all', label: 'All tabs', count: scopes.total}, ...groups.map((group, index) => {
          const title = group.title;
          const page = group.page ?? group.domains.find(value => value && value !== 'unknown');
          const fallback = `Tab ${index + 1}`;
          const label = globalThis.RebRequestTabs?.scopeLabel(group.id) ??
            (title ? (title.length > 42 ? `${title.slice(0, 41)}…` : title) : page || fallback);
          return {
            id: group.id,
            label,
            count: group.count,
            domains: group.domains
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
          const count = countsKnown ? String(scope.count) : '';
          if (button.children[1].textContent !== count) button.children[1].textContent = count;
          button.title = scope.id === 'all' ? 'Show requests from every captured browser tab, each once'
            : scope.id.startsWith('extension:') ? `Extension ${scope.id.slice(10)} · ${scope.domains.join(', ')}`
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
        fitRequestTabScopes();
        if (focusedScope && document.activeElement !== focusedScope) (buttons.includes(focusedScope) ? focusedScope : buttons[0])?.focus({preventScroll: true});

        const domains = scopes.domains.map(([domain]) => domain);
        if (state.requestDomain !== 'all' && !domains.includes(state.requestDomain)) state.requestDomain = 'all';
        const oldOptions = new Map([...elements.requestDomain.children].map(option => [option.value, option]));
        const options = [['all', countsKnown ? `All domains (${scopes.scopedCount})` : 'All domains'], ...scopes.domains.map(([domain, count]) => [domain, `${domain} (${count})`])]
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
        // A long domain truncates in the closed control; the tooltip holds the full value.
        elements.requestDomain.title = elements.requestDomain.selectedOptions?.[0]?.textContent ?? '';
      }

      // The strip shows whole chips only, never one cut at its edge. Chips past
      // its width are hidden and listed in the "+N tabs" menu after it, which
      // selects them; the selected chip always stays in the strip. Widths are
      // read only when the chips or the selection change, or the row resizes.
      function fitRequestTabScopes(force = false) {
        const strip = elements.requestTabScopes, more = strip?.nextElementSibling;
        if (!more?.classList?.contains('request-tab-more')) return;
        const chips = [...strip.children];
        const key = JSON.stringify(chips.map(chip => [chip.dataset.scopeId, chip.textContent, chip.getAttribute('aria-selected')]));
        if (!more.fitObserver && typeof ResizeObserver === 'function') {
          more.fitObserver = new ResizeObserver(() => fitRequestTabScopes(true));
          more.fitObserver.observe(strip.parentElement);
        }
        if (!more.fitWired) {
          more.fitWired = true;
          more.addEventListener('change', () => {
            const chip = [...strip.children].find(node => node.dataset.scopeId === more.value);
            more.value = '';
            chip?.click();
          });
        }
        if (!force && more.fitKey === key) return;
        const width = strip.parentElement.clientWidth;
        // Off screen there is nothing to fit; the observer fits it once shown.
        if (!(width > 0)) { more.fitKey = null; return; }
        more.fitKey = key;
        for (const chip of chips) chip.hidden = false;
        more.hidden = true;
        strip.dataset.measuring = 'true';
        const widths = chips.map(chip => chip.getBoundingClientRect().width);
        delete strip.dataset.measuring;
        const gap = parseFloat(getComputedStyle(strip).columnGap) || 0;
        if (widths.reduce((sum, value) => sum + value, 0) + gap * Math.max(0, chips.length - 1) <= width + 0.5) return;
        // The menu is measured at its widest label before the chips are fitted,
        // and keeps that width: a closed select otherwise widens to its longest option.
        more.hidden = false;
        more.style.width = '';
        more.replaceChildren(new Option(`+${chips.length - 1} tabs`, ''));
        const menuWidth = more.getBoundingClientRect().width;
        more.style.width = `${menuWidth}px`;
        const budget = width - menuWidth - gap;
        const selected = chips.findIndex(chip => chip.getAttribute('aria-selected') === 'true');
        let used = selected >= 0 ? widths[selected] : -gap, full = false;
        const hidden = chips.filter((chip, index) => {
          if (index === selected) return false;
          if (!full && used + gap + widths[index] <= budget) { used += gap + widths[index]; return false; }
          full = true;
          return true;
        });
        for (const chip of hidden) chip.hidden = true;
        const label = `+${hidden.length} ${hidden.length === 1 ? 'tab' : 'tabs'}`;
        more.replaceChildren(new Option(label, ''), ...hidden.map(chip =>
          new Option(`${chip.children[0].textContent}${chip.children[1].textContent ? ` (${chip.children[1].textContent})` : ''}`, chip.dataset.scopeId)));
        more.value = '';
        more.title = `${hidden.length} more browser ${hidden.length === 1 ? 'tab' : 'tabs'}: ${hidden.map(chip => chip.children[0].textContent).join(', ')}`;
      }

      // A row linked to several tabs is in each of them; no tab is a capture error.
      function requestTabsOf(request) {
        return globalThis.RebRequestTabs?.rowTabs(request) ?? (request.tabId && request.tabId !== '0' ? [request.tabId] : []);
      }

      function requestInScope(request) {
        if (state.requestTabId === 'all') return true;
        const tabs = requestTabsOf(request);
        return state.requestTabId === 'unresolved' ? tabs.length === 0 : tabs.includes(state.requestTabId);
      }

      function trafficRequestFilterKey() {
        const range = state.trafficRange;
        return JSON.stringify([state.requestTabId, state.requestDomain, state.requestType,
          elements.requestFilter.value.trim().toLowerCase(),
          state.trafficSort, state.trafficSortDirection, state.trafficFlags, range && `${range.from}:${range.to}`]);
      }

      // A null visible count is a query the request index has not answered yet.
      // `totals`: the index's matching sizes, hidden browser-internal rows and rows without a tab.
      function renderTrafficWindowStatus(visibleCount, totalCount, outside, note = '', totals = null) {
        const bytes = value => trafficBytesLabel(value).replace(' ', '\u00a0');
        const sizes = totals ? ` · ${bytes(totals.sizes.transferred)} transferred · ${bytes(totals.sizes.resources)} resources` : '';
        const hidden = totals?.hiddenInternal ? ` · ${totals.hiddenInternal.toLocaleString('en-US')} browser-internal hidden` : '';
        const excluded = globalThis.RebNetworkScope?.captureExclusionNotice(state.captureExclusions) ?? '';
        // A null total is a session nothing has been read from yet: no counts, the note leads.
        const counts = totalCount === null ? '' : `${visibleCount === null ? '' : `${visibleCount.toLocaleString('en-US')} / `}${totalCount.toLocaleString('en-US')} requests${sizes}${hidden}`;
        const rest = `${excluded ? ` · ${excluded}` : ''}${outside ? ' · Selection outside filter' : ''}${note ? ` · ${note}` : ''}`;
        const message = counts ? counts + rest : rest.slice(3).replace(/^./, letter => letter.toUpperCase());
        const status = document.querySelector('#request-window-status');
        if (status.textContent !== message) status.textContent = message;
        const unresolved = totals?.unresolved ?? state.requests.filter(request => globalThis.RebRequestTabs?.isUnresolved(request)).length;
        const errors = document.querySelector('#request-unresolved');
        errors.hidden = unresolved === 0;
        errors.textContent = globalThis.RebRequestTabs?.unresolvedNotice(unresolved) ?? '';
        errors.setAttribute('aria-pressed', String(state.requestTabId === 'unresolved'));
      }

      // The waterfall spans the selected time range, else the timeline of every matching start.
      function trafficScale(timeline) {
        if (!timeline || timeline.first === null) return null;
        const range = state.trafficRange;
        const [start, end] = range ? [range.from, range.to] : [timeline.first, timeline.last];
        return {start, end: end > start ? end : start + 1n, origin: timeline.first};
      }

      function renderTrafficSortButtons() {
        document.querySelectorAll('[data-request-sort]').forEach(button => {
          const active = button.dataset.requestSort === state.trafficSort;
          button.setAttribute('aria-pressed', String(active));
          button.setAttribute('aria-label', `${button.dataset.column ?? button.dataset.requestSort}: ${active ? state.trafficSortDirection === 1 ? 'ascending' : 'descending' : 'not sorted'}. Activate to sort.`);
          button.querySelector('span').textContent = active ? state.trafficSortDirection === 1 ? ' ↑' : ' ↓' : '';
        });
      }

      function renderTrafficEmpty(text) {
        const empty = document.createElement('div');
        empty.className = 'request-empty';
        empty.setAttribute('role', 'status');
        empty.textContent = text;
        const hadFocus = elements.requestRows.contains(document.activeElement);
        // A later resize must not remount rows this empty state replaced.
        elements.requestRows.trafficBlock = null;
        elements.requestRows.replaceChildren(empty);
        elements.requestRows.tabIndex = 0;
        if (hadFocus) elements.requestRows.focus({preventScroll: true});
      }

      function trafficEmptyText(total) {
        return total === 0
          ? state.sessionMode === 'live' ? 'No live requests yet. Start a capture in the attached browser.'
            : state.sessionMode === 'demo' ? 'No developer evidence is available.' : 'No capture session is running.'
          : 'No requests match the current filters. Clear the filter or choose another type.';
      }

      // Until a poll or an index read answers, the session's requests are
      // unknown, not zero: say so with the connection reason and show no counts.
      function trafficUnreadReason() {
        if (state.eventPollAnswered || state.trafficIndex?.answer()) return null;
        return {connecting: 'the local evidence broker has not answered yet',
          unresponsive: 'the local evidence broker did not answer within 10 seconds',
          unreachable: 'the local evidence broker is disconnected', malformed: 'the broker returned malformed event data'}[state.connection] ?? null;
      }

      // Until the index first answers, or without a backend, the newest window serves Traffic.
      function trafficIndexActive() {
        const index = state.trafficIndex;
        return Boolean(index) && state.sessionMode !== 'preview' && !(index.error() && !index.answer());
      }

      function renderRequests(selectionOnly = false) {
        const previous = state.trafficRenderedView;
        const index = trafficIndexActive() ? state.trafficIndex : null;
        // Producers replace the retained request array on refresh. Reuse only
        // this exact rendered snapshot and filter/window; all other entry
        // points (polls, search, sort, scrolling and history) take the full path.
        if (selectionOnly === true && previous?.requests === state.requests && previous.retainedCount === state.requests.length &&
            previous.filterKey === trafficRequestFilterKey() && (previous.answer ?? null) === (index?.answer() ?? null) &&
            previous.start === state.trafficWindowStart && previous.anchor === state.trafficWindowAnchor &&
            (!previous.mounted || previous.mounted.has(state.selectedRequestId))) {
          renderTrafficRowSelection(elements.requestRows, state.selectedRequestId);
          renderTrafficWindowStatus(previous.visibleCount, previous.totalCount, previous.outside(state.selectedRequestId), previous.note, previous.totals);
          return;
        }
        state.trafficRenderedView = null;
        if (index && (index.answer() || !state.requests.length)) {
          renderIndexedRequests(index);
          return;
        }
        // Until the index first answers, the newest window's rows serve and the first read starts.
        if (index) wantTrafficIndex(index, {start: 0});
        const unread = state.requests.length === 0 ? trafficUnreadReason() : null;
        renderRequestScopes(undefined, !unread);
        const filter = trafficParseFilter(elements.requestFilter.value);
        const scoped = state.requests.filter(request =>
          requestInScope(request) &&
          (state.requestDomain === 'all' || requestDomain(request) === state.requestDomain) &&
          (state.requestType === 'all' || request.type === state.requestType)
        );
        // Researcher names are searchable too; captured fields stay as recorded.
        const names = globalThis.RebEvidenceNames?.controller?.() ?? null;
        const nameOf = names?.has('captured-request') ? request => names.nameFor('request', request) : () => null;
        const search = trafficSearchRequests(scoped, filter.text, nameOf);
        const filtered = trafficApplyFilter(scoped, search.matches, filter, {flags: state.trafficFlags, range: state.trafficRange, all: state.requests});
        state.trafficSearchMatches = filtered.matches;
        const visible = trafficSortedRequests(scoped.filter(request => filtered.matches.has(request.id)), state.trafficSort, state.trafficSortDirection);
        const totals = {sizes: filtered.sizes, hiddenInternal: filtered.hiddenInternal};
        state.trafficOverview?.render(filtered.timeline, state.trafficRange);
        const filterKey = trafficRequestFilterKey();
        const filterChanged = filterKey !== state.trafficFilterKey;
        if (filterChanged) {
          state.trafficNewIds.clear(); state.trafficWindowStart = 0; state.trafficWindowAnchor = null;
          if (state.trafficFilterKey !== null) elements.requestRows.scrollTop = 0;
        }
        state.trafficFilterKey = filterKey;
        const selectedIsVisible = visible.some(request => request.id === state.selectedRequestId);
        const selectionCleared = state.selectedRequestId !== null && !state.requests.some(request => request.id === state.selectedRequestId);
        if (selectionCleared) resetRequestSelection();
        // Only a live capture can deliver new requests. Stored, demo and idle
        // evidence is a fixed set loaded at once, so none of it is "new".
        const knownIds = state.trafficKnownIds, live = state.sessionMode === 'live';
        const newIds = new Set(live && knownIds ? visible.filter(request => !knownIds.has(request.id)).map(request => request.id) : []);
        state.trafficKnownIds = new Set(state.requests.map(request => request.id));
        if (!live || trafficAtNewest()) state.trafficNewIds.clear();
        else if (!filterChanged) newIds.forEach(id => state.trafficNewIds.add(id));
        for (const id of state.trafficNewIds) if (!state.trafficKnownIds.has(id)) state.trafficNewIds.delete(id);
        // The block follows its first row when rows arrive above it, unless scrolled to the top.
        const start = trafficBlockStart(elements.requestRows, visible.length, state.trafficWindowStart);
        const anchor = start === state.trafficWindowStart && elements.requestRows.scrollTop > 0 ? state.trafficWindowAnchor : null;
        const window = trafficWindow(visible, start, anchor);
        state.trafficWindowStart = window.start;
        state.trafficWindowAnchor = window.rows[0]?.id ?? null;
        const outside = id => id !== null && !state.trafficSearchMatches.has(id);
        const indexError = state.trafficIndex?.error();
        const note = unread ? `nothing read yet${indexError ? ` · request index unavailable (${indexError})` : ''}`
          : indexError ? 'request index unavailable; newest window shown' : 'newest window';
        const counted = unread ? {visible: null, total: null, totals: null} : {visible: visible.length, total: state.requests.length, totals};
        renderTrafficWindowStatus(counted.visible, counted.total, outside(state.selectedRequestId), note, counted.totals);
        const renderedView = {requests: state.requests, retainedCount: state.requests.length, filterKey, start: window.start, anchor: state.trafficWindowAnchor,
          answer: undefined, visibleCount: counted.visible, totalCount: counted.total, outside, note, totals: counted.totals, mounted: null};
        renderTrafficSortButtons();
        elements.requestRows.setAttribute('role', 'listbox');
        if (visible.length === 0) {
          renderTrafficEmpty(unread ? `Nothing has been read yet: ${unread}.` : trafficEmptyText(state.requests.length));
          state.trafficPendingCount = 0;
          elements.requestLatest.hidden = true;
          renderRequestCount(counted.visible, counted.total);
          state.trafficRenderedView = renderedView;
          if (selectionCleared) {
            updateSelectionSummary(null);
            renderInspector();
            renderEvidence();
          }
          return;
        }
        renderTrafficRows(elements.requestRows, window.rows, {
          start: window.start, total: visible.length, selectedId: state.selectedRequestId, newIds,
          onSelect: id => { selectRequest(id); focusRequestRow(id); }, onKey: moveRequestSelection, nameOf,
          scale: trafficScale(filtered.timeline)
        });
        state.trafficPendingCount = state.trafficNewIds.size;
        renderTrafficLatest();
        renderRequestCount(visible.length, state.requests.length);
        state.trafficRenderedView = renderedView;
        finishTrafficFocus();
        if (selectionCleared) {
          updateSelectionSummary(null);
          renderInspector();
          renderEvidence();
        } else if (filterChanged && selectedIsVisible) renderInspector();
      }

      function trafficAtNewest() {
        return elements.requestRows.scrollTop === 0 && state.trafficSort === 'capture' && state.trafficSortDirection < 0;
      }

      function renderTrafficLatest() {
        elements.requestLatest.hidden = state.trafficPendingCount === 0;
        elements.requestLatest.textContent = `${state.trafficPendingCount.toLocaleString('en-US')} new ${state.trafficPendingCount === 1 ? 'request' : 'requests'}`;
      }

      // Researcher names live in the UI, so the index gets the named root events to match.
      function trafficNamedRoots(names, needle, origin) {
        if (!needle || !names) return [];
        return (names.model?.document?.requests ?? []).filter(entry => entry.origin === origin && entry.name.toLowerCase().includes(needle))
          .slice(0, 64).map(entry => `${entry.session}:${entry.process}:${entry.sequence}`);
      }

      function trafficNameOf(names) {
        if (!names?.has('captured-request')) return () => null;
        return request => {
          if (!request.indexRow) return names.nameFor('request', request);
          const identity = request.indexRow.root && RebEvidenceNames.requestIdentity(request, request.indexRow.root);
          return identity ? names.nameOf(identity) : null;
        };
      }

      function trafficIndexNote(answer, error) {
        if (error) return `request index unavailable (${error}); last rows kept`;
        const coverage = answer.index;
        const notes = [];
        if (!coverage.complete) {
          const end = Number(coverage.store_end);
          notes.push(`indexing ${end ? Math.floor(Number(coverage.indexed_end) * 100 / end) : 0}%`);
        }
        if (coverage.unindexed_records !== '0') notes.push(`${coverage.unindexed_records} records past the ${coverage.request_limit.toLocaleString('en-US')}-request limit`);
        if (coverage.malformed_records !== '0') notes.push(`${coverage.malformed_records} unreadable records`);
        return notes.join(' · ');
      }

      function trafficIndexQuery(origin, names = globalThis.RebEvidenceNames?.controller?.() ?? null) {
        const filter = trafficParseFilter(elements.requestFilter.value);
        return trafficIndexParameters({sort: state.trafficSort, direction: state.trafficSortDirection, needle: filter.needle,
          tabId: state.requestTabId, domain: state.requestDomain, type: state.requestType, named: trafficNamedRoots(names, filter.text, origin),
          flags: state.trafficFlags, range: state.trafficRange});
      }

      function wantTrafficIndex(index, {start, origin = state.sessionMode === 'demo' ? 'demo' : 'live', query = trafficIndexQuery(origin)}) {
        return index.want({query, start, origin, locate: [state.selectedRequestId]});
      }

      function renderIndexedRequests(index) {
        const container = elements.requestRows;
        const origin = state.sessionMode === 'demo' ? 'demo' : 'live', live = state.sessionMode === 'live';
        let answer = index.answer();
        if (answer && answer.document.index.epoch !== state.trafficIndexEpoch) {
          // A cleared or replaced store: rows read before it are not this session's.
          if (state.trafficIndexEpoch !== null) { state.trafficLoaded.clear(); rebuildTrafficRequests(); }
          state.trafficIndexEpoch = answer.document.index.epoch;
        }
        // Scopes first: a tab or domain the session no longer has resets its filter.
        if (answer) renderRequestScopes(trafficIndexScopes(answer.document));
        const filterKey = trafficRequestFilterKey();
        const names = globalThis.RebEvidenceNames?.controller?.() ?? null;
        const query = trafficIndexQuery(origin, names);
        const covering = candidate => candidate?.query === query && candidate.origin === origin ? candidate : null;
        // The list moves to the new query only when it answers. Until then the
        // last rows and their scroll position stay, even if the read fails.
        if (covering(answer) && filterKey !== state.trafficFilterKey) {
          state.trafficNewIds.clear(); state.trafficPendingCount = 0; state.trafficSeenThrough = null;
          state.trafficWindowStart = 0; state.trafficWindowAnchor = null;
          if (state.trafficFilterKey !== null) container.scrollTop = 0;
          state.trafficFilterKey = filterKey;
        }
        const known = covering(answer)?.document.matching ?? 0;
        const start = trafficBlockStart(container, known, state.trafficWindowStart);
        state.trafficWindowStart = start;
        answer = wantTrafficIndex(index, {start, origin, query});
        const current = covering(answer);
        renderTrafficSortButtons();
        container.setAttribute('role', 'listbox');
        if (!current) {
          // Another query's rows stay until this one answers; they are never relabeled.
          if (!answer) renderTrafficEmpty('Reading the request index…');
          const failure = index.error();
          const block = container.trafficBlock;
          if (block) {
            const pending = failure ? 'Not loaded: the request index is unavailable' : 'Loading…';
            if (block.options.pending !== pending) renderTrafficRows(container, block.requests, {...block.options, pending, newIds: new Set()});
            renderTrafficRowSelection(container, state.selectedRequestId);
          }
          renderTrafficWindowStatus(null, answer ? answer.document.total : null, false,
            failure ? `${trafficIndexNote(null, failure)}, filter not applied` : 'reading the request index');
          return;
        }
        const page = current.document, matching = page.matching;
        if (current !== state.trafficAppliedAnswer) {
          if (live && state.trafficAppliedAnswer?.query === query && current.added > 0 && !trafficAtNewest()) state.trafficPendingCount += current.added;
          state.trafficAppliedAnswer = current;
        }
        if (!live || trafficAtNewest()) state.trafficPendingCount = 0;
        const length = Math.max(0, Math.min(TRAFFIC_ROW_LIMIT, matching - start));
        const rows = Array.from({length}, (_, offset) => {
          const at = start + offset - current.start;
          return at >= 0 && at < current.rows.length ? current.rows[at] : null;
        });
        const seen = state.trafficSeenThrough;
        const newIds = new Set(live && seen !== null ? rows.filter(row => row && row.indexRow.ordinal >= seen).map(row => row.id) : []);
        state.trafficSeenThrough = page.through;
        const mounted = new Set(rows.filter(Boolean).map(row => row.id));
        const located = page.located ?? {};
        const outside = id => id !== null && !mounted.has(id) && Object.hasOwn(located, id) && located[id] === null;
        const note = trafficIndexNote(page, index.error());
        const totals = {sizes: page.sizes, hiddenInternal: page.hidden_internal,
          unresolved: page.facets.tabs.find(tab => tab.tab_id === '0')?.count ?? 0};
        const timeline = {first: page.timeline.first_time_ns === null ? null : BigInt(page.timeline.first_time_ns),
          last: page.timeline.last_time_ns === null ? null : BigInt(page.timeline.last_time_ns), buckets: page.timeline.buckets};
        state.trafficOverview?.render(timeline, state.trafficRange);
        renderTrafficWindowStatus(matching, page.total, outside(state.selectedRequestId), note, totals);
        renderTrafficLatest();
        renderRequestCount(matching, page.total, 'session');
        if (matching === 0) renderTrafficEmpty(trafficEmptyText(page.total));
        else renderTrafficRows(container, rows, {start, total: matching, selectedId: state.selectedRequestId, newIds,
          onSelect: selectTrafficRow, onKey: moveRequestSelection, nameOf: trafficNameOf(names),
          pending: index.error() ? 'Not loaded: the request index is unavailable' : 'Loading…', scale: trafficScale(timeline)});
        state.trafficWindowAnchor = rows.find(Boolean)?.id ?? null;
        state.trafficRenderedView = {requests: state.requests, retainedCount: state.requests.length, filterKey, start,
          anchor: state.trafficWindowAnchor, answer: current, visibleCount: matching, totalCount: page.total, outside, note, totals, mounted};
        finishTrafficFocus();
        // A loaded selection that gained records is read again, once per count.
        const selected = state.selectedRequestId !== null ? current.rows.find(row => row.id === state.selectedRequestId) : null;
        const loaded = selected && state.trafficLoaded.get(selected.id);
        const attempt = selected && `${selected.id}:${selected.indexRow.records}`;
        if (loaded && trafficRecordCount(loaded) < selected.indexRow.records && state.trafficLoadingId === null && state.trafficReloaded !== attempt) {
          state.trafficReloaded = attempt;
          loadTrafficRequest(selected, false);
        }
      }

      function updateSelectionSummary(request) {
        // A researcher name sits beside the raw URL and never replaces it.
        const names = globalThis.RebEvidenceNames?.controller?.() ?? null;
        const researcherName = names?.nameFor('request', request) ?? null;
        const nameNode = document.querySelector('#selected-name'), rename = document.querySelector('#request-rename');
        if (nameNode) {
          nameNode.textContent = researcherName ?? '';
          nameNode.hidden = !researcherName;
          nameNode.title = researcherName ? `Researcher name: ${researcherName}. The captured URL beside it is unchanged.` : '';
        }
        if (rename) {
          const exact = Boolean(names?.identityFor('request', request));
          rename.disabled = !exact;
          rename.title = exact ? 'Rename this request (F2)' : request ? 'This request has no exact retained identity to name.' : 'Select a request to name it.';
        }
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
        const fullUrl = request.urlTruncated ? requestFullUrl(request) : null;
        elements.selectedUrl.textContent = request.origin === 'sample'
          ? `https://checkout.acme.test${request.path}`
          : request.hostOnly ? `${request.path} (host only metadata)`
            : fullUrl ?? (request.urlTruncated ? `${request.path}… (truncated)` : request.path);
        elements.selectedUrl.title = elements.selectedUrl.textContent;
        // A truncated or scheme-less target is not a URL to copy until its full target is loaded.
        elements.requestCopyUrl.disabled = request.hostOnly || (Boolean(request.urlTruncated) && !fullUrl) || request.targetKind === 'path';
      }

      function selectRequest(id, expectedIdentity = null) {
        if (expectedIdentity) {
          const candidates = state.requests.filter(candidate => candidate.id === id);
          if (candidates.length !== 1 || !investigationSame(expectedIdentity, investigationRequestIdentity(candidates[0]))) {
            investigationNotice('The exact request cannot be selected: its row identifier is missing, changed or ambiguous.', 'ambiguous'); return false;
          }
        }
        // A stale id selects nothing, so it must not cancel the current trace.
        const request = state.requests.find(candidate => candidate.id === id);
        if (!request) return;
        investigationBeforeSelection();
        state.originTraceController?.abort();
        // A store read still running for another row must not select it afterwards.
        if (state.trafficLoadingId !== id) cancelTrafficLoad();
        state.selectedRequestId = id;
        retainTrafficRequest(request);
        state.trafficDetailOpen = true;
        state.trafficSelectionNotice = null;
        clearTrafficUnreadSelection();
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
          elements.prompt.textContent = 'Choose a request value and trace where it came from';
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

      function trafficRecordCount(request) {
        return (request?.events?.length ?? 0) + (request?.details?.length ?? 0);
      }

      function cancelTrafficLoad() {
        state.trafficLoadController?.abort();
        state.trafficLoadController = null;
        state.trafficLoadingId = null;
      }

      // Keeps a selected or store-read row selectable after the newest window moves on.
      function retainTrafficRequest(request) {
        const loaded = state.trafficLoaded;
        if (!loaded) return;
        loaded.delete(request.id);
        loaded.set(request.id, request);
        for (const key of loaded.keys()) {
          if (loaded.size <= 32) break;
          if (key !== state.selectedRequestId && key !== request.id) loaded.delete(key);
        }
      }

      // A row whose records could not be read keeps a notice that names it. The
      // notice goes once that row, or any other, is selected.
      function clearTrafficUnreadSelection() {
        const failed = state.trafficUnreadSelection;
        if (!failed) return;
        state.trafficUnreadSelection = null;
        const notice = document.querySelector('#investigation-notice');
        if (!notice || notice.textContent !== failed.message) return;
        notice.textContent = '';
        const bar = document.querySelector('#investigation-navigation');
        bar.dataset.status = 'ready';
        const details = bar.querySelector('details');
        if (details) details.open = false;
        if (failed.barWasHidden && document.querySelector('#investigation-back')?.disabled && document.querySelector('#investigation-forward')?.disabled) bar.hidden = true;
      }

      function trafficUnreadSelectionText(indexed, reason, previous) {
        const url = String(indexed.path ?? '');
        const name = `${indexed.method} ${url.length > 120 ? `${url.slice(0, 119)}…` : url} (request ${indexed.id})`;
        return `${name} was not opened: its records could not be read (${reason}).${previous ? ' The inspector still shows the request selected before it.' : ''} It opens when its records can be read.`;
      }

      // A row the newest window does not hold whole is read from the store first.
      function selectTrafficRow(id) {
        const indexed = state.trafficIndex?.row(id) ?? null;
        const retained = state.requests.find(request => request.id === id);
        if (retained && (!indexed || trafficRecordCount(retained) >= indexed.indexRow.records)) {
          selectRequest(id);
          focusRequestRow(id);
        } else if (indexed) loadTrafficRequest(indexed, true);
      }

      async function loadTrafficRequest(indexed, select) {
        const id = indexed.id;
        state.trafficLoadController?.abort();
        const controller = new AbortController();
        state.trafficLoadController = controller;
        state.trafficLoadingId = id;
        const row = [...elements.requestRows.querySelectorAll('.request-row')].find(node => node.dataset.requestId === id);
        row?.setAttribute('aria-busy', 'true');
        // WebKit rejects a timed-out fetch with AbortError; the deadline says whether it was reached.
        const deadline = AbortSignal.timeout(10000);
        try {
          const {events, partial} = await state.trafficIndex.events(indexed.indexRow, AbortSignal.any([controller.signal, deadline]));
          if (controller.signal.aborted) return;
          const request = requestsFromEvents(events, indexed.origin).find(candidate => candidate.id === id);
          if (!request) throw new Error('its stored records no longer form this request');
          // Tab sets and links have no request ID, so the store read lacks them; the index row has them.
          Object.assign(request, {tabIds: indexed.tabIds, tabLink: indexed.tabLink, tabLinkLabel: indexed.tabLinkLabel,
            extensionId: indexed.extensionId, recordsPartial: partial});
          retainTrafficRequest(request);
          rebuildTrafficRequests();
          if (select) {
            selectRequest(id);
            // The read can finish after the researcher moved on; never take focus from another control.
            if (trafficListHoldsFocus()) focusRequestRow(id);
            // Selecting opens the inspector, which can cover the row.
            [...elements.requestRows.querySelectorAll('.request-row')].find(node => node.dataset.requestId === id)?.scrollIntoView({block: 'nearest'});
          } else if (state.selectedRequestId === id) {
            renderInspector();
          }
        } catch (error) {
          if (controller.signal.aborted) return;
          if (select) {
            const reason = deadline.aborted ? 'the backend did not answer within 10 seconds' : error.message;
            const message = trafficUnreadSelectionText(indexed, reason, state.selectedRequestId !== null);
            const bar = document.querySelector('#investigation-navigation');
            // A later valid poll reads it again (retryTrafficUnreadSelection).
            state.trafficUnreadSelection = {id, indexed, message,
              barWasHidden: state.trafficUnreadSelection?.barWasHidden ?? Boolean(bar?.hidden)};
            state.trafficSelectionNotice = message;
            if (state.selectedRequestId === null) updateSelectionSummary(null);
            else investigationNotice(message, 'unavailable');
          }
        } finally {
          row?.removeAttribute('aria-busy');
          if (state.trafficLoadController === controller) {
            state.trafficLoadController = null;
            state.trafficLoadingId = null;
          }
          renderRequests();
        }
      }

      function trafficRowAt(position) {
        return [...elements.requestRows.querySelectorAll('.request-row')].find(row => row.dataset.position === String(position)) ?? null;
      }

      // Positions span the whole filtered list; only rows near the view are mounted.
      function moveRequestSelection(event) {
        if (!['ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) return;
        const container = elements.requestRows, view = state.trafficRenderedView;
        const row = event.currentTarget !== container && container.contains(event.currentTarget) ? event.currentTarget : null;
        if (!view || (!row?.dataset.position && event.currentTarget !== container)) return;
        event.preventDefault();
        const selected = container.dataset.selectedPosition;
        const from = row ? Number(row.dataset.position)
          : state.trafficFocusPosition ?? (selected === undefined ? Math.floor(container.scrollTop / trafficRowHeight(container)) : Number(selected));
        const position = event.key === 'Home' ? 0 : event.key === 'End' ? view.visibleCount - 1
          : from + (event.key === 'ArrowDown' ? 1 : -1);
        focusTrafficPosition(Math.max(0, Math.min(view.visibleCount - 1, position)));
      }

      function focusTrafficPosition(position) {
        const container = elements.requestRows;
        const slot = state.trafficRenderedView && trafficRowAt(position);
        delete container.dataset.focusId;
        if (slot?.dataset.requestId) {
          state.trafficFocusPosition = null;
          selectTrafficRow(slot.dataset.requestId);
          if (document.activeElement !== slot) slot.focus({preventScroll: true});
          slot.scrollIntoView({block: 'nearest'});
          return;
        }
        // The list keeps focus while the row's block mounts or loads.
        state.trafficFocusPosition = position;
        container.focus({preventScroll: true});
        if (slot) return;
        const height = trafficRowHeight(container);
        container.scrollTop = Math.max(0, (position + 1) * height - (container.clientHeight || 0) / 2);
        renderRequests();
      }

      function finishTrafficFocus() {
        const position = state.trafficFocusPosition, view = state.trafficRenderedView;
        if (position === null) return;
        if (!view || document.activeElement !== elements.requestRows || position >= view.visibleCount) state.trafficFocusPosition = null;
        else if (trafficRowAt(position)?.dataset.requestId) focusTrafficPosition(position);
      }

      function trafficListHoldsFocus() {
        const active = document.activeElement;
        return !active || active === document.body || elements.requestRows.contains(active);
      }

      function focusRequestRow(id) {
        [...elements.requestRows.querySelectorAll('.request-row')]
          .find(row => row.dataset.requestId === id)?.focus({ preventScroll: true });
      }

      function requestTraceRoot(request) {
        return request?.origin === 'live' ? requestRootEvent(request) : null;
      }

      // The browser start, else the renderer initiation, else any event with a
      // request ID. Backtraces need a live root; researcher names also accept
      // demo rows, whose identity then records that origin.
      function requestRootEvent(request) {
        const candidates = request?.events ?? [];
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

      // Retained request content (protocol/native-network-v2.md) loads only for the
      // selected request and by range: a body 2 MiB at a time, a full target in
      // one read. The backend checks the catalog's size and SHA-256 on every read;
      // this view rechecks the digest once every byte is loaded. Text is only ever
      // assigned to textContent.
      const REQUEST_BODY_PAGE_BYTES = 2 * 1024 * 1024;
      // The backend's largest range read, which is also Chromium's URL limit.
      const REQUEST_TARGET_READ_BYTES = 2 * 1024 * 1024;
      // Loaded bytes kept for recently selected requests, never the session's content.
      const REQUEST_CONTENT_CACHE_BYTES = 32 * 1024 * 1024;
      // A transient read failure (timeout, HTTP status, transport) stays shown
      // and is retried by the next refresh or selection at least this long
      // after it, so a failing backend sees one read per poll, not a loop. A size
      // or SHA-256 mismatch stays cached with its reason.
      const REQUEST_BODY_RETRY_MS = 2000;
      const requestBodyViews = new Map();
      function requestContentArtifact(record, kind) {
        const matches = (state.artifacts ?? []).filter(artifact => artifact.artifact_id === record.artifactId &&
          artifact.kind === kind && artifact.session_id === record.sessionId &&
          artifact.creator_event_id === record.sequenceNumber);
        return matches.length === 1 ? matches[0] : null;
      }
      const trafficArtifacts = createTrafficArtifactLookup({valid: isArtifactResponse, refusalText: decodePayload,
        onChange: () => {
          const selected = state.requests.find(request => request.id === state.selectedRequestId);
          if (['response', 'preview'].includes(state.inspectorTab)) renderInspector();
          else if (selected && requestContentViewKey(selected) !== state.requestBodyViewKey) renderInspector();
        }});
      // The index knows where a request's records start; a refusal is read forward from there.
      function trafficStoreOffset(request) {
        return state.trafficIndex?.row?.(request?.id)?.indexRow?.first_offset ?? '0';
      }
      function requestContentView(record, kind, after = '0') {
        if (location.protocol === 'file:') return {status: 'unavailable'};
        // The receiver's refusal joins the creator record exactly, as its parent.
        const refusal = state.events.find(event => event.type === 'artifact_capture_failed' &&
          event.artifact_id === record.artifactId && event.parent_event_id === record.sequenceNumber &&
          event.session_id === record.sessionId && event.process_id === record.processId);
        if (refusal) return {status: 'refused', reason: decodePayload(refusal)};
        let artifact = requestContentArtifact(record, kind);
        if (!artifact) {
          // Past the catalog's cap, or not in it yet: read it by ID.
          const found = trafficArtifacts.lookup(record, after);
          if (found.status === 'refused') return {status: 'refused', reason: found.reason};
          if (found.status === 'loading') return {status: 'loading'};
          const named = found.status === 'found' && found.artifact.artifact_id === record.artifactId && found.artifact.kind === kind &&
            found.artifact.session_id === record.sessionId && found.artifact.creator_event_id === record.sequenceNumber;
          if (!named) return {status: 'missing', unknown: found.status === 'unknown'};
          artifact = found.artifact;
        }
        const key = `${artifact.session_id}:${artifact.artifact_id}:${artifact.sha256}`;
        // A body kept whole is the bytes its record digested. A cut body's record digests more than was kept.
        if (record.state === 'captured' && record.sha256 && record.sha256 !== artifact.sha256) {
          return {status: 'error', error: "the request record's SHA-256 does not match the retained artifact", retryable: false, url: artifact.url, key};
        }
        const view = requestBodyViews.get(key);
        // A body cut at the capture limit may end inside a character.
        const cut = record.state === 'captured_truncated';
        if (view?.retryable && Date.now() - view.failedAt >= REQUEST_BODY_RETRY_MS) {
          // The failed view stays visible until the retry settles.
          requestBodyViews.set(key, {status: 'loading', previous: view});
          void loadRequestContent(artifact, key, null, cut);
          return {...view, url: artifact.url, key};
        }
        if (view) return {...(view.previous ?? view), loadingMore: view.status === 'loading' && Boolean(view.previous?.bytes), url: artifact.url, key};
        requestBodyViews.set(key, {status: 'loading'});
        void loadRequestContent(artifact, key, null, cut);
        return {status: 'loading', url: artifact.url, key};
      }
      function requestBodyView(request) {
        const body = request?.body;
        if (!body || body.malformed || !['captured', 'captured_truncated'].includes(body.state)) return null;
        return requestContentView(body, 'request_body', trafficStoreOffset(request));
      }
      function requestTargetView(request) {
        const target = request?.fullTarget;
        return target?.retention === 'retained' ? requestContentView(target, 'request_target', trafficStoreOffset(request)) : null;
      }
      // The composed URL once its retained full target is loaded.
      function requestFullUrl(request) {
        const view = requestTargetView(request);
        return view?.status === 'ready' && view.complete ? `${view.url}${view.text}` : null;
      }
      async function loadRequestContent(artifact, key, previous, cut = false) {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 10000);
        const mismatch = message => Object.assign(new Error(message), {integrity: true});
        const loaded = previous?.bytes ?? new Uint8Array(0);
        let view;
        try {
          const page = artifact.kind === 'request_target' ? REQUEST_TARGET_READ_BYTES : REQUEST_BODY_PAGE_BYTES;
          const limit = Math.min(artifact.byte_size - loaded.length, page);
          const response = await fetch(`/api/artifacts/${encodeURIComponent(artifact.artifact_id)}/content?offset=${loaded.length}&limit=${limit}`,
            {cache: 'no-store', signal: controller.signal});
          if (!response.ok) {
            if (response.status === 500 && (await Promise.resolve(response.json?.()).catch(() => null))?.code === 'artifact_integrity') throw mismatch('its bytes do not match the retained SHA-256');
            response.body?.cancel().catch(() => {});
            throw new Error(`the artifact store returned ${response.status}`);
          }
          const chunk = await sourceFactsReadBytes(response, limit, controller.signal);
          if (chunk.length !== limit) throw mismatch('its retained byte size changed');
          const bytes = new Uint8Array(loaded.length + chunk.length);
          bytes.set(loaded);
          bytes.set(chunk, loaded.length);
          const complete = bytes.length === artifact.byte_size;
          let verified = false;
          if (complete && globalThis.crypto?.subtle) {
            const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)),
              byte => byte.toString(16).padStart(2, '0')).join('');
            if (digest !== artifact.sha256) throw mismatch('its bytes do not match the retained SHA-256');
            verified = true;
          }
          // A prefix may end inside a character; streaming leaves that tail out instead of failing it.
          const open = {stream: !complete || cut};
          let lossy = false;
          try {new TextDecoder('utf-8', {fatal: true}).decode(bytes, open);} catch {lossy = true;}
          view = {status: 'ready', artifact, bytes, text: new TextDecoder('utf-8', {fatal: false, ignoreBOM: true}).decode(bytes, open),
            lossy, verified, complete, cut, loaded: bytes.length, total: artifact.byte_size};
        } catch (error) {
          const message = controller.signal.aborted ? 'timed out after 10 seconds' : String(error?.message ?? error).replace(/\.$/, '');
          // A failed next range keeps the bytes already shown; bytes that fail integrity are not shown.
          view = previous && error?.integrity !== true ? {...previous, moreError: message}
            : {status: 'error', error: message, retryable: error?.integrity !== true, failedAt: Date.now()};
        } finally {
          clearTimeout(timeout);
        }
        // Bounded: a few recently selected requests, never the session's content.
        requestBodyViews.delete(key);
        requestBodyViews.set(key, view);
        let retained = [...requestBodyViews.values()].reduce((sum, item) => sum + (item.bytes?.length ?? 0), 0);
        for (const [oldest, item] of requestBodyViews) {
          if (requestBodyViews.size <= 8 && retained <= REQUEST_CONTENT_CACHE_BYTES) break;
          if (oldest === key) continue;
          retained -= item.bytes?.length ?? 0;
          requestBodyViews.delete(oldest);
        }
        const selected = state.requests.find(request => request.id === state.selectedRequestId);
        if (selected && requestContentViewKey(selected) !== state.requestBodyViewKey) renderInspector();
      }
      function startMoreRequestBody(key) {
        const view = requestBodyViews.get(key);
        if (view?.status !== 'ready' || view.complete) return false;
        requestBodyViews.set(key, {status: 'loading', previous: {...view, moreError: null}});
        void loadRequestContent(view.artifact, key, view, view.cut);
        return true;
      }
      function loadMoreRequestBody(key) {
        if (startMoreRequestBody(key)) renderInspector();
      }
      function requestBodyViewKey(view) {
        return view ? `${view.status}|${view.unknown ?? ''}|${view.reason ?? view.error ?? ''}|${view.url ?? ''}|${view.loaded ?? ''}|${view.moreError ?? ''}|${view.loadingMore ?? ''}` : '';
      }
      // General and Headers read the full target; Payload reads the body and its query from the full target.
      function requestContentViewKey(request) {
        return state.inspectorTab === 'payload' ? `${requestBodyViewKey(requestBodyView(request))}#${requestBodyViewKey(requestTargetView(request))}`
          : requestBodyViewKey(requestTargetView(request));
      }
      // Content whose acknowledgment arrives after selection becomes readable on
      // the next catalog refresh without reselecting the request. Unchanged
      // views do not re-render the inspector on every poll.
      function refreshSelectedRequestBody() {
        const selected = state.requests.find(request => request.id === state.selectedRequestId);
        if (selected && ['response', 'preview'].includes(state.inspectorTab)) {
          trafficResponse.render(document.querySelector('#response-inspector'), selected, state.inspectorTab);
          return;
        }
        const target = selected?.fullTarget?.retention === 'retained';
        if (!selected || (state.inspectorTab === 'payload' ? !target && !['captured', 'captured_truncated'].includes(selected.body?.state)
          : !['general', 'headers'].includes(state.inspectorTab) || !target)) return;
        if (requestContentViewKey(selected) !== state.requestBodyViewKey) renderInspector();
      }

      function renderInspectorMessage(message) {
        const empty = document.createElement('div');
        empty.className = 'field-empty';
        empty.textContent = message;
        elements.fieldTree.replaceChildren(empty);
      }

      function renderInspectorDetails(rows) {
        elements.fieldTree.replaceChildren(...inspectorDetailRows(rows));
      }

      function inspectorDetailRows(rows) {
        return rows.map(detail => {
          const row = document.createElement('div');
          row.className = 'field-row'; row.dataset.type = detail.type;
          const key = document.createElement('span'); key.className = 'field-key'; key.textContent = detail.key;
          const value = document.createElement('span'); value.className = 'field-value'; value.textContent = String(detail.value);
          const type = document.createElement('span'); type.className = 'field-type'; type.textContent = detail.type;
          row.append(key, value, type);
          return row;
        });
      }

      // Response and Preview tabs, protocol/native-network-v3.md.
      const trafficResponse = createTrafficResponse({getArtifacts: () => state.artifacts, getEvents: () => state.events,
        contentSession: () => state.requestContentCaptureEnabled, readable: () => location.protocol !== 'file:',
        lookup: (record, request) => trafficArtifacts.lookup(record, trafficStoreOffset(request)), onChange: () => renderInspector()});
      function openResolvedFrame(resolution) {
        if (selectArtifact(resolution.artifact_id, resolution.artifact_line ?? null,
          {column: resolution.artifact_column ?? 0}) !== false) showScreen('sources');
      }
      const requestStackPanel = createRequestStackPanel({
        refresh: () => { if (state.inspectorTab === 'initiator') renderInspector(); },
        open: frame => openResolvedFrame(frame.resolution)
      });

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
        const responseInspector = document.querySelector('#response-inspector');
        responseInspector.hidden = showingGeneral || !['response', 'preview'].includes(state.inspectorTab);
        const headersInspector = document.querySelector('#headers-inspector');
        headersInspector.hidden = showingGeneral || state.inspectorTab !== 'headers';
        const cookiesInspector = document.querySelector('#cookies-inspector');
        cookiesInspector.hidden = showingGeneral || state.inspectorTab !== 'cookies';
        const payloadInspector = document.querySelector('#payload-inspector');
        payloadInspector.hidden = showingGeneral || state.inspectorTab !== 'payload';
        if (!responseInspector.hidden) {
          responseInspector.setAttribute('aria-labelledby', `inspector-tab-${state.inspectorTab}`);
          elements.requestInspector.hidden = true;
          document.querySelector('.detail-pane').classList.add('showing-exchange');
          trafficResponse.render(responseInspector, request, state.inspectorTab);
          return;
        }
        if (!headersInspector.hidden || !cookiesInspector.hidden) {
          elements.requestInspector.hidden = true;
          document.querySelector('.detail-pane').classList.add('showing-exchange');
          if (!headersInspector.hidden) {
            state.requestBodyViewKey = requestContentViewKey(request);
            renderTrafficHeaders(headersInspector, request, renderInspector, requestTargetView(request));
          }
          else renderTrafficCookies(cookiesInspector, request, renderInspector, {requests: state.requests, events: state.events, selectRequest,
            openFrame: openResolvedFrame, storeRevision: state.eventEtag});
          return;
        }
        if (!payloadInspector.hidden) {
          elements.requestInspector.hidden = true;
          document.querySelector('.detail-pane').classList.add('showing-exchange');
          // A parsed view needs every retained byte, so ranges are read on without a click.
          const bodyView = requestBodyView(request);
          if (bodyView?.status === 'ready' && bodyView.complete === false && !bodyView.loadingMore && !bodyView.moreError &&
              trafficPayloadParses(request.body, bodyView)) startMoreRequestBody(bodyView.key);
          state.requestBodyViewKey = requestContentViewKey(request);
          renderTrafficPayload(payloadInspector, request, requestBodyView(request), requestTargetView(request));
          return;
        }
        if (showingGeneral) {
          state.requestBodyViewKey = requestContentViewKey(request);
          renderTrafficDetails(exchangeInspector, request, state.trafficSelectionNotice, requestTargetView(request));
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
            ? 'Choose a request value and trace where it came from'
            : requestTraceable
              ? 'Trace this request backward through observed event relationships'
              : 'No structured request payload was captured';
          elements.fieldTabs.hidden = !traceable;
          elements.traceDock.hidden = !traceable && !requestTraceable;
          renderFields();
          return;
        }
        if (state.inspectorTab === 'signals') {
          elements.prompt.textContent = 'Fingerprint activity before this request';
          elements.fieldTabs.hidden = true;
          elements.traceDock.hidden = !requestTraceRoot(request);
          renderFields(); // Keep the shared dock's target and actions true for this request.
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
            key: 'Coverage',
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
            const details = [{ key: 'Correlation', value: request.id, type: 'id' }];
            if (contextEvent) {
              details.push({ key: 'Browser context', value: browserContextToken(contextEvent), type: 'token' });
            }
            if (correlated || initiated) {
              details.push(
                { key: 'Renderer process', value: correlated?.initiator_process_id ?? initiated.process_id, type: 'pid' },
                { key: 'Renderer request', value: correlated?.initiator_request_id ?? integerText(initiated, 'request_id'), type: 'id' }
              );
            } else {
              details.push(
                { key: 'Browser process', value: contextEvent.process_id, type: 'pid' },
                { key: 'Browser request', value: integerText(contextEvent, 'request_id'), type: 'id' }
              );
            }
            details.push({ key: 'Frame', value: integerText(source, 'frame_id'), type: 'id' });
            requestStackPanel.render(elements.fieldTree, request, inspectorDetailRows(details));
          } else {
            const empty = document.createElement('div');
            empty.className = 'field-empty';
            empty.textContent = request?.origin === 'sample'
              ? 'Sample initiator evidence is available in the request field backtrace.'
              : request?.origin === 'demo'
                ? 'Demo initiator evidence is available in the retained event payload.'
                : 'No renderer initiator was captured for this browser request.';
            requestStackPanel.render(elements.fieldTree, request, [empty]);
          }
          return;
        }
        if (state.inspectorTab === 'timing') {
          elements.prompt.textContent = 'Timing';
          elements.fieldTabs.hidden = true;
          elements.traceDock.hidden = true;
          if (request?.origin === 'live') {
            renderInspectorDetails([
              { key: 'First event', value: request.firstTimestamp, type: 'ns' },
              { key: 'Last event', value: request.lastTimestamp, type: 'ns' },
              { key: 'Duration', value: trafficTimeLabel(request.time), type: 'time' },
              { key: 'Lifecycle', value: request.operation, type: 'state' },
              { key: 'Events', value: request.events.length, type: 'count' },
              { key: 'Phase breakdown', value: 'DNS, connection, TLS, waiting and download phases were not captured.', type: 'unavailable' }
            ]);
          } else if (request) {
            renderInspectorDetails([
              { key: 'Duration', value: trafficTimeLabel(request.time), type: 'time' },
              { key: 'Source', value: request.origin === 'demo' ? 'demo evidence' : 'sample workspace data', type: 'source' }
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

      // Recorded links, shared identifiers and timestamp adjacency are three
      // different classes of evidence. Every row label comes from here so no
      // call site can present the weaker ones as a recorded relationship.
      const traceLinkClasses = {
        observed: {label: 'Recorded link', style: 'exact', detail: 'Recorded event link',
          relation: 'recorded link'},
        correlated: {label: 'Shared identifiers', style: 'correlation', detail: 'Matched by shared identifiers',
          relation: 'shared identifiers only'},
        time_adjacent: {label: 'Time-adjacent only', style: 'adjacency',
          detail: 'Same request identity in another process within a bounded timestamp window. Not a predecessor and not value flow.',
          relation: 'timestamp proximity only'}
      };
      function traceLinkClass(step) {
        return traceLinkClasses[step.confidence] ?? traceLinkClasses.correlated;
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
          ['Link type', traceLinkClass(step).detail],
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
          relation: `Trace step S${step.event.session_id}:P${step.event.process_id}:E${step.event.sequence_number} records this artifact. Trace relationship: ${traceLinkClass(step).relation}. No value flow is implied.`}));
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
          // Arrow keys are keyboard navigation even when the list was entered
          // by pointer, so the moved focus keeps its ring. Focus also scrolls
          // its row into view: a long trace must not move focus off screen.
          rows[next].click();
          rows[next].focus({focusVisible: true});
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
        const labels = {trace_target: 'Selected request', parent_event: 'Previous event', request_initiator: 'Request initiator', request_lifecycle: 'Request lifecycle', artifact_request: 'Related artifact', temporal_adjacency: 'Time-adjacent record · no recorded link',
          issued_during_invocation: 'Started inside JS invocation · identity, not value flow', invocation_settlement: 'Invocation start',
          invocation_value_flow: 'Returned value found in request body · exact bytes'};
        const gapLabels = {
          ambiguous_request: 'Ambiguous request identifier',
          missing_event: 'Missing event · predecessor not retained',
          no_predecessor: 'Missing predecessor · no recorded link',
          cycle: 'Trace stopped · correlation cycle',
          step_limit: 'Trace stopped · step limit reached',
          capture_gap: 'Capture incomplete · native queue drops',
          value_flow_ambiguous: 'Value flow not chosen · several returned values match',
          value_flow_unsearched: 'Value flow not searched · bounded search exceeded'
        };
        (trace?.steps ?? []).forEach((step, index) => {
          models.push({key: `${step.event.process_id}:${step.event.sequence_number}`, index: String(index + 1),
            title: `${step.category} · ${step.operation}`, kind: labels[step.relation] || step.relation,
            confidence: traceLinkClass(step).label, style: traceLinkClass(step).style, step});
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
          // Adjacency is reported beside coverage, never inside it.
          const adjacent = trace.coverage.time_adjacent_links
            ? ` · ${trace.coverage.time_adjacent_links} time-adjacent record, excluded from coverage` : '';
          elements.coverageValue.textContent = `${trace.coverage.percent}% trace coverage · ${links} · ${gapsText}${adjacent}`;
          elements.coverageValue.title = 'Coverage counts recorded predecessor links against named gaps. Time-adjacent records share a request identity in another process within a bounded timestamp window; they are a weaker correlation class and are excluded from coverage. Queue-drop markers describe retained streams and do not identify missing links or prove value flow.';
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

      // The notice is text for the researcher, never operation state; whether a
      // save or load runs is apiCollectionSaving and apiCollectionRefreshing.
      function setCollectionNotice(kind, message) {
        state.apiCollectionStatus = kind;
        state.apiCollectionMessage = message;
        state.apiCollectionNoticeRevision += 1;
        elements.collectionNotice.dataset.kind = kind;
        elements.collectionNotice.textContent = message;
      }

      // A save that met a conflict reloads while it still holds
      // apiCollectionSaving, so no second save can start until it has settled.
      async function refreshApiCollection(force = false, conflictReload = false) {
        if (state.apiCollectionRefreshing || (state.apiCollectionSaving && !conflictReload) || location.protocol === 'file:') return false;
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
            const noticeRevision = state.apiCollectionNoticeRevision;
            const refreshed = await refreshApiCollection(true, true);
            // Keep a notice the reload published itself (a load error or a
            // removed draft); otherwise name the conflict.
            if (refreshed || noticeRevision === state.apiCollectionNoticeRevision) setCollectionNotice('conflict', `${body.error || 'The collection changed in another window.'} Your edits are retained; retry load and review them before saving again.`);
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
            requestRow.append(textElement('span', 'collection-tree-glyph', ''),
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
        elements.collectionDeleteFolder.dataset.confirm = String(state.collectionDeleteFolderId === folder.id);
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
          elements.collectionRequestHeaders.value = request.headers.length
            ? JSON.stringify(Object.fromEntries(request.headers.map(header => [header.name, header.value])), null, 2) : '';
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
        elements.collectionDeleteRequest.dataset.confirm = String(state.collectionDeleteRequestId === request.id);
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

      // Every unsaved draft and unconfirmed save in this document. The native
      // shell asks before it closes the window or replaces this document; a
      // browser asks through beforeunload. A script that stopped before the
      // notebook mounted throws here, which the native shell reports as unknown.
      function hasUnsavedWork() {
        return Boolean(analystHasUnsavedWork() || state.collectionDraftDirty || state.collectionFolderDirty ||
          state.apiCollectionSaving || (typeof investigationNotebook === 'object' && investigationNotebook.hasUnsavedWork()));
      }

      function guardUnsavedWorkUnload(event) {
        if (!hasUnsavedWork()) return;
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
        // Names live in this library; a newer admitted generation refreshes them.
        globalThis.RebEvidenceNames?.observeLibrary(body);
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
          row.title = folder.name; row.dataset.folderId = String(folder.id); row.style.setProperty('--analyst-depth', String(depth));
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
            fileRow.title = file.name; fileRow.dataset.fileId = String(file.id); fileRow.style.setProperty('--analyst-depth', String(depth + 1));
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
        analystElements.deleteFolder.dataset.confirm = String(state.analystDeleteFolderId === folder.id);
      }

      let analystCodeEditor = null;
      function colorAnalystEditor() {
        analystCodeEditor ??= mountCodeEditor(analystElements.content, analystElements.contentColors,
          () => codeViewSyntax(analystElements.kind.value === 'analyst-script' ? 'javascript' : analystElements.language.value));
        analystCodeEditor.refresh();
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
        analystElements.deleteFile.dataset.confirm = String(state.analystDeleteFileId === file.id);
        analystElements.draftStatus.dataset.kind = state.analystDraftDirty ? 'dirty' : 'saved';
        analystElements.draftStatus.textContent = state.analystDraftDirty
          ? 'Unsaved changes cannot run. Save or discard them before choosing another item or closing the app.'
          : `${formatByteSize(file.content_bytes)} saved · file ${file.id} · ${new Date(file.updated_at_ms).toLocaleString()}`;
        colorAnalystEditor();
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
        analystElements.cancel.disabled = !state.analystRunPending ||
          (state.analystCancelRunId !== null && state.analystCancelRunId === state.analystActiveRunId);
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

      // The notice reports the last operation or probe. Engine availability
      // is decoderEngineStatus ('unknown', 'ready' or 'unavailable').
      function setToolsNotice(kind, message) {
        state.decoderStatus = kind;
        state.decoderMessage = message;
        state.decoderNoticeRevision += 1;
      }

      // Probes only an engine not yet known to work. A probe's result never
      // replaces a newer operation notice or claims ready while one runs, and
      // a failed re-check keeps an engine that already worked.
      async function refreshDecoderEngine(force = false) {
        if (state.decoderRefreshing || location.protocol === 'file:' || (!force && state.decoderEngineStatus === 'ready')) return;
        state.decoderRefreshing = true;
        if (state.decoderEngineStatus === 'unknown' && !state.decoderPending && !state.jwtPending) {
          setToolsNotice('loading', 'Checking the native decoder engine…');
        }
        const noticeRevision = state.decoderNoticeRevision;
        let notice = null;
        renderTools();
        try {
          const response = await fetch('/api/decoder', {cache: 'no-store'});
          if (!response.ok) throw new Error(`Decoder service returned ${response.status}`);
          const body = await response.json();
          if (!isDecoderEngine(body)) throw new TypeError('Decoder service returned a malformed capability contract.');
          state.decoderEngine = body;
          state.decoderEngineStatus = body.available ? 'ready' : 'unavailable';
          notice = body.available
            ? ['ready', 'Native C++ decoder ready. Every transform runs only when requested.']
            : ['error', 'The native decoder executable is unavailable. Rebuild the application to restore local tools.'];
        } catch (error) {
          if (state.decoderEngineStatus !== 'ready') {
            state.decoderEngine = emptyDecoderEngine();
            state.decoderEngineStatus = 'unavailable';
            notice = ['error', `Decoder service unavailable: ${error.message}`];
          }
        } finally {
          state.decoderRefreshing = false;
          if (notice && noticeRevision === state.decoderNoticeRevision && !state.decoderPending && !state.jwtPending) {
            setToolsNotice(...notice);
          }
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
          state.analystCancelRunId = null;
          analystElements.confirm.checked = false;
          analystElements.confirmSensitive.checked = false;
          await refreshLocalAnalyst();
          renderLocalAnalyst();
        }
      }

      // A requested cancellation is state, so a render while the run is
      // pending cannot re-enable Cancel for the same run.
      async function cancelLocalAnalystScript() {
        const runId = state.analystActiveRunId;
        if (!runId || state.analystCancelRunId === runId) return;
        state.analystCancelRunId = runId;
        setAnalystNotice('running', `Cancelling analyst run ${runId}…`);
        renderAnalystExecution();
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
          // A run that finished first owns the notice; refusing to cancel a
          // completed run is not news, and there is nothing left to cancel.
          if (state.analystActiveRunId !== runId) return;
          state.analystCancelRunId = null;
          setAnalystNotice('error', `Cancellation failed: ${error.message}`);
          renderAnalystExecution();
        }
      }

      // Source ownership never comes from a URL. Captured documents reuse the
      // Facts identity of their immutable stored artifact.
      function sourceIdentity(source) {
        return source ? sourceFactsIdentity({...source, source_type: 'artifact'}) : null;
      }

      // The one Sources exclusion rule. Canvas images belong to Fingerprinting;
      // request bodies, full targets, header blocks and cookie lists are
      // sensitive network evidence shown with their Traffic row
      // (protocol/native-network-v2.md and v3). None is listed, opened or loaded
      // as a source file.
      function isSourceArtifact(artifact) {
        return Boolean(artifact) && !['canvas_data_url', 'request_body', 'request_target', 'request_headers', 'response_headers', 'cookie_list', 'stack'].includes(artifact.kind);
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

      // Passing the catalog record keeps a whole-catalog release linear.
      function releaseSourcePreview(source, owner = null) {
        const identity = sourceIdentity(source);
        const preview = owner ?? state.artifacts.find(value => sourceIdentity(value) === identity);
        if (preview) {
          preview.controller?.abort();
          for (const field of ['content', 'sourceTextLength', 'contentTruncated', 'contentLongLine', 'loading', 'loadError', 'controller', 'previewUsed', 'contentVerified', 'contentLossy']) delete preview[field];
        }
        for (const cache of [state.deobfuscationRequests, state.deobfuscationCache, state.sourceFormatCache]) {
          for (const [key, value] of cache ?? []) {
            if (!key.startsWith(`${identity}|`)) continue;
            retireDeobfuscationReveal(value.inspectorView);
            value.controller?.abort(); cache.delete(key);
          }
        }
        if (state.sourceEditorView?.identity === identity) state.sourceEditorView = null;
        if (state.sourceOriginalHighlighter?.identity === identity) state.sourceOriginalHighlighter = null;
      }

      function boundSourcePreviews(protectedSource = null) {
        const protectedIdentity = sourceIdentity(selectedSource() ?? protectedSource);
        const entries = (state.artifacts ?? []).filter(isSourceArtifact).map(source => ({source, preview: source}))
          .filter(({preview}) => preview && (preview.loading || preview.content !== undefined));
        entries.sort((a, b) => (a.preview.previewUsed ?? 0) - (b.preview.previewUsed ?? 0));
        let characters = entries.reduce((sum, {preview}) => sum + (preview.content?.length ?? 0), 0);
        let documents = entries.length;
        // Metadata/open tabs remain. Reopening an evicted preview reloads it.
        // Other previews hold at most 32 Mi UTF-16 units across eight owners.
        for (const {source, preview} of entries) {
          if (documents <= 8 && characters <= 32 * 1024 * 1024) break;
          if (sourceIdentity(source) === protectedIdentity) continue;
          characters -= preview.content?.length ?? 0; documents -= 1;
          releaseSourcePreview(source);
        }
      }

      function boundSourceAnalysis(cache, maximum, characterLimit, segmentLimit, keep = null) {
        let characters = 0, segments = 0, wireBytes = 0;
        for (const value of cache.values()) {
          wireBytes += value.sourceDocumentBytes ?? 0;
          characters += (value.original_source?.length ?? value.sourceInput?.length ?? 0) + (value.representation?.text?.length ?? value.text?.length ?? 0);
          segments += value.representation?.segments?.length ?? value.segments?.length ?? 0;
        }
        for (const [key, value] of cache) {
          if (cache.size <= maximum && characters <= characterLimit && segments <= segmentLimit && wireBytes <= 32 * 1024 * 1024) break;
          if (key === keep) continue;
          wireBytes -= value.sourceDocumentBytes ?? 0;
          characters -= (value.original_source?.length ?? value.sourceInput?.length ?? 0) + (value.representation?.text?.length ?? value.text?.length ?? 0);
          segments -= value.representation?.segments?.length ?? value.segments?.length ?? 0;
          retireDeobfuscationReveal(value.inspectorView);
          cache.delete(key);
        }
      }

      function capturedSources(artifactId = null) {
        return state.artifacts
          .filter(artifact => isSourceArtifact(artifact) && (artifactId === null || artifact.artifact_id === artifactId))
          .map(artifact => {
            const key = `artifact:${artifact.artifact_id}`;
            return { ...artifact, source_type: 'artifact', key, deobfuscation: state.deobfuscationCache?.get(deobfuscationKey({...artifact, key})) ?? null };
          });
      }

      // Dynamic code has no file of its own; DevTools names it VM<id> too.
      function sourceDisplayName(source) {
        return source?.capture_origin === 'dynamic_javascript' ? `VM${source.artifact_id}` : sourceName(source);
      }

      // Every artifact kind the evidence contract admits, labeled by what its
      // bytes are. Only javascript artifacts are JavaScript.
      function sourceKindLabel(kind) {
        return {javascript: ['JS', 'JavaScript'], wasm: ['W', 'WebAssembly'], source_map: ['{}', 'source map'],
          response_body: ['R', 'response body'], wasm_guest_adapter: ['AD', 'guest adapter JSON'],
          bytecode_buffer: ['BC', 'guest bytecode']}[kind] ?? null;
      }

      function sourceIcon(source) {
        return sourceKindLabel(source.kind)?.[0] ?? '?';
      }

      function selectedSource() {
        if (state.selectedArtifactId == null) return null;
        const matches = capturedSources(state.selectedArtifactId);
        return matches.length === 1 ? matches[0] : null;
      }

      function renderSourceTree(refresh = true) {
        sourceTreeView.render(refresh);
      }

      let sourceInternalToggleButton = null;
      function sourceInternalToggle(internal) {
        if (!globalThis.RebNetworkScope) return null;
        if (!sourceInternalToggleButton) {
          sourceInternalToggleButton = document.createElement('button');
          sourceInternalToggleButton.type = 'button'; sourceInternalToggleButton.className = 'source-internal-toggle';
          sourceInternalToggleButton.title = 'Hide chrome:, devtools: and other browser-internal sources; nothing is deleted';
          sourceInternalToggleButton.addEventListener('click', () => setHideBrowserInternal(!state.hideBrowserInternal));
        }
        globalThis.RebNetworkScope.renderBrowserInternalToggle(sourceInternalToggleButton, internal, state.hideBrowserInternal);
        return sourceInternalToggleButton;
      }

      // One reversible view filter for Traffic and Sources; evidence is unchanged.
      function setHideBrowserInternal(hide) {
        state.hideBrowserInternal = hide;
        state.trafficFlags = {...state.trafficFlags, hideInternal: hide};
        document.querySelector('.request-flag[data-flag="hideInternal"]')?.setAttribute('aria-pressed', String(hide));
        renderRequests();
        renderSourceTree();
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
        const names = globalThis.RebEvidenceNames?.controller?.() ?? null;
        const rename = document.querySelector('#source-rename');
        if (rename) {
          const selected = sources.find(source => source.artifact_id === state.selectedArtifactId);
          rename.disabled = !names?.identityFor('artifact', selected);
          rename.title = !selected ? 'Open a captured source to name it.' : rename.disabled
            ? 'This source has no exact retained identity to name, or its artifact ID is shared.' : 'Rename this source (F2)';
        }
        if (sources.length === 0) {
          const placeholder = document.createElement('span');
          placeholder.className = 'source-tab-placeholder';
          placeholder.textContent = 'No file open';
          elements.sourceEditorTabs.replaceChildren(placeholder);
          return;
        }
        const shared = new Map();
        for (const source of sources) shared.set(sourceDisplayName(source), (shared.get(sourceDisplayName(source)) ?? 0) + 1);
        const tabs = sources.map((source, index) => {
          const label = sourceDisplayName(source);
          const tab = document.createElement('button');
          tab.type = 'button';
          tab.className = 'source-editor-tab';
          tab.setAttribute('role', 'tab');
          tab.setAttribute('aria-label', `${label}, artifact ${source.artifact_id}. Press Delete to close.`);
          tab.setAttribute('aria-keyshortcuts', 'Delete');
          tab.dataset.sourceIdentity = sourceIdentity(source);
          tab.title = `${source.url || label} · artifact ${source.artifact_id}`;
          const selected = source.artifact_id === state.selectedArtifactId;
          tab.setAttribute('aria-selected', String(selected));
          tab.tabIndex = selected ? 0 : -1;
          const icon = document.createElement('span');
          icon.className = 'source-file-icon';
          icon.dataset.icon = sourceTreeFileIcon(source);
          icon.textContent = sourceIcon(source);
          icon.title = sourceKindLabel(source.kind)?.[1] ?? source.kind;
          const name = document.createElement('span');
          name.textContent = label;
          name.title = tab.title;
          const suffix = document.createElement('span');
          suffix.className = 'source-tab-suffix';
          suffix.textContent = shared.get(label) > 1 ? source.artifact_id : '';
          const close = document.createElement('span');
          close.className = 'source-tab-close';
          close.textContent = '×';
          close.setAttribute('aria-hidden', 'true');
          const researcherName = names?.nameFor('artifact', source) ?? null;
          if (researcherName) {
            const researcher = document.createElement('span');
            researcher.className = 'researcher-name';
            researcher.textContent = researcherName;
            researcher.title = `Researcher name: ${researcherName}`;
            tab.setAttribute('aria-label', `${researcherName} (researcher name), ${label}, artifact ${source.artifact_id}. Press Delete to close.`);
            tab.append(icon, researcher, name, suffix, close);
          } else tab.append(icon, name, suffix, close);
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
        tokens.forEach((token, at) => {
          if (token.type === 'plain') {
            // Leading indentation carries the editor's indent guides.
            const indent = at === 0 ? token.text.match(/^[ \t]+/)?.[0] : null;
            if (indent) fragment.append(textElement('span', 'source-indent', indent));
            fragment.append(document.createTextNode(indent ? token.text.slice(indent.length) : token.text));
          } else {
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

      // Rebuilding a page costs far more than scanning for a match, so a match
      // already mounted moves only the caret. A column cut from its row still needs the render.
      function moveSourceCaretInMountedPage(editor, line, column, length) {
        const excerpt = editor.window.rows[line - editor.window.start];
        if (excerpt?.line !== line || column < excerpt.columnStart || column + length > excerpt.columnEnd) return false;
        editor.window = {...editor.window, line, column};
        state.sourceWindow = {identity: editor.identity, representation: editor.representation, line, column};
        elements.sourceCode.querySelector('.current-line')?.classList.remove('current-line');
        elements.sourceCode.querySelector(`[data-local-line="${line}"]`)?.classList.add('current-line');
        renderSourceWindowControls(editor);
        return true;
      }

      function applySourceSearch(reset = true, direction = 0, {reveal = true} = {}) {
        const query = elements.sourceSearch.value;
        let editor = state.sourceEditorView;
        const source = selectedSource();
        // The coverage sentence is the Find field's tooltip and description.
        const status = message => {
          if (!elements.sourceSearchStatus) return;
          elements.sourceSearchStatus.textContent = message;
          elements.sourceSearch.title = `${message} Enter for next, Shift+Enter for previous.`;
        };
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
        if (editor.view.formatted?.paged) {
          applyPagedSourceSearch(editor, source, query, reset, direction, reveal, status);
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
          status(`${coverage}.${editor.index.complete ? '' : ' Search stopped at the 64 Mi UTF-16-unit bound.'}`);
          return;
        }
        state.sourceSearchIndex = reset ? 0 : (state.sourceSearchIndex + direction + matches.length) % matches.length;
        const match = matches[state.sourceSearchIndex];
        if (reveal && !moveSourceCaretInMountedPage(editor, match.line, match.column, match.length)) {
          // Mount only the matched line/column window. Never enter the full
          // Sources route, which can start explicitly selected analysis.
          renderSourceContent(source, editor.view, {line: match.line, column: match.column, search: false});
          editor = state.sourceEditorView;
        }
        highlightRows();
        const row = elements.sourceCode.querySelector(`[data-local-line="${match.line}"]`);
        const line = match.line;
        const column = match.column;
        elements.sourcePosition.textContent = `${state.sourceSearchIndex + 1} of ${matches.length}${truncated ? '+' : ''} matches · ${editor.view.wasmRows ? `Inspection row ${line + 1}, Column ${column + 1}` : sourcePositionText(editor, line, column)}`;
        status(`${coverage}.${truncated ? ' First 1,000 matches; refine Find for later matches.' : ''}${editor.index.complete ? '' : ' Search stopped at the 64 Mi UTF-16-unit bound.'}`);
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

      // A paged layout holds one page, so Find searches the evidence and maps each match to its page.
      function applyPagedSourceSearch(editor, source, query, reset, direction, reveal, status) {
        const page = editor.view.formatted, original = editor.view.active;
        const coverage = 'Complete retained source text; matches are found in the evidence and shown in the layout';
        const originalIndex = editor.originalIndex ??= sourceDocumentIndex(original);
        if (editor.search?.query !== query) editor.search = {query, ...sourceDocumentMatches(originalIndex, query, 1000)};
        const {matches, truncated, error} = editor.search;
        if (error) {elements.sourcePosition.textContent = error; status(coverage); return;}
        const pageEnd = page.anchors[page.block + 1] ?? original.length;
        const inverse = sourceWhitespaceInverse(page.sourceInput, page.text);
        const shown = match => {
          if (match.offset < page.base || match.offset >= pageEnd) return null;
          const start = inverse(match.offset - page.base), last = inverse(match.offset + match.length - 1 - page.base);
          const at = start === null ? null : sourceDocumentPosition(editor.index, start);
          return at && {...at, length: Math.max(1, (last ?? start) + 1 - start)};
        };
        const placed = matches.map(shown);
        const lines = new Set(placed.filter(Boolean).map(at => at.line));
        elements.sourceCode.querySelectorAll('.source-line[data-line]').forEach(row => row.classList.toggle('search-match', lines.has(Number(row.dataset.localLine))));
        if (!matches.length) {
          state.sourceSearchIndex = 0;
          elements.sourcePosition.textContent = '0 matches in complete retained text.';
          status(coverage);
          return;
        }
        state.sourceSearchIndex = reset ? 0 : (state.sourceSearchIndex + direction + matches.length) % matches.length;
        const match = matches[state.sourceSearchIndex], count = `${state.sourceSearchIndex + 1} of ${matches.length}${truncated ? '+' : ''} matches`;
        status(`${coverage}.${truncated ? ' First 1,000 matches; refine Find for later matches.' : ''}`);
        const at = placed[state.sourceSearchIndex];
        if (!at) {
          if (reveal) {
            state.sourcePagedFind = {identity: editor.identity, query};
            moveSourceWindow(sourceFormatBlock(page.anchors, match.offset) * page.stride);
          }
          elements.sourcePosition.textContent = `${count} · original ${match.line + 1}:${match.column + 1} · reading its part of the layout…`;
          return;
        }
        if (reveal && !moveSourceCaretInMountedPage(editor, at.line, at.column, at.length)) {
          renderSourceContent(source, editor.view, {line: at.line, column: at.column, search: false});
          editor = state.sourceEditorView;
        }
        elements.sourcePosition.textContent = `${count} · ${sourcePositionText(editor, at.line, at.column)}`;
        if (!markSourceMatch(at.line, at.column, at.length) || !reveal) return;
        const row = elements.sourceCode.querySelector(`[data-line="${at.line + 1}"]`);
        revealSourceColumn(row, at.column);
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
        elements.sourceGoto.disabled = !editor;
        elements.sourceWindowPrevious.hidden = !editor || editor.window.start === 0;
        elements.sourceWindowNext.hidden = !editor || editor.window.end === editor.index.lineCount;
        if (!editor) {elements.sourceWindow.hidden = true; return;}
        const {window: window, index} = editor;
        const total = `${index.lineCount}${index.complete ? '' : '+'}`;
        const loading = editor.view.pageLoadingLine ?? null;
        elements.sourceWindowLabel.textContent = loading === null ? `Lines ${window.start + 1}–${window.end} of ${total}`
          : `Lines ${window.start + 1}–${window.end} of ${total} · reading line ${loading + 1}…`;
        elements.sourceWindowPrevious.textContent = window.start ? `↑ Lines ${Math.max(1, window.start - SOURCE_WINDOW_LINES + 1)}–${window.start}` : '';
        elements.sourceWindowNext.textContent = window.end < index.lineCount ? `↓ Lines ${window.end + 1}–${Math.min(index.lineCount, window.end + SOURCE_WINDOW_LINES)} of ${total}` : '';
        if (document.activeElement !== elements.sourceWindowLine) elements.sourceWindowLine.value = String(window.line + 1);
        if (document.activeElement !== elements.sourceWindowColumn) elements.sourceWindowColumn.value = String(Math.max(0, window.column) + 1);
        elements.sourceWindowLine.max = String(index.lineCount);
      }

      function moveSourceWindow(line, column = 0) {
        const editor = state.sourceEditorView, source = selectedSource();
        const bounds = editor && sourceDocumentLine(editor.index, line), paged = Boolean(editor?.view.formatted?.paged);
        if (!editor || editor.identity !== sourceIdentity(source) || !Number.isSafeInteger(line) || line < 0 || line >= editor.index.lineCount ||
            !Number.isSafeInteger(column) || column < 0 || column > (bounds?.length ?? (paged ? Infinity : 0))) return false;
        if (!bounds) {
          // Another page of a large layout; the editor moves once it is read.
          state.sourceWindow = {identity: editor.identity, representation: editor.representation, line, column};
          renderSourceContent(source, sourceDisplayView(source), {line, column, search: false});
          elements.sourcePosition.textContent = `Line ${line + 1} · reading this part of the layout…`;
          return true;
        }
        renderSourceContent(source, editor.view, {line, column, search: false});
        applySourceSearch(false, 0, {reveal: false});
        elements.sourcePosition.textContent = sourcePositionText(state.sourceEditorView, line, column);
        const row = elements.sourceCode.querySelector(`[data-local-line="${line}"]`);
        revealSourceColumn(row, column, true);
        return true;
      }

      // A displayed location, with its original one when the view is a layout or derived text.
      function sourcePositionText(editor, line, column) {
        const start = sourceDocumentOffset(editor.index, line);
        const original = start === null ? null : editor.mappingContext?.position(start + column, start + (sourceDocumentLine(editor.index, line)?.length ?? 0));
        return `Line ${line + 1}, Column ${column + 1}${original ? ` (original ${original.line + 1}:${original.column + 1})` : ''}`;
      }

      // Each page of a large layout starts from the original's lexer state at its first character.
      function sourceOriginalHighlighter(source, text) {
        const identity = sourceIdentity(source), cached = state.sourceOriginalHighlighter;
        if (cached?.identity === identity && cached.text === text) return cached.highlighter;
        const highlighter = createSourceHighlighter(source, sourceDocumentIndex(text));
        state.sourceOriginalHighlighter = {identity, text, highlighter};
        return highlighter;
      }

      function sourceRepresentation(source) {
        return JSON.stringify([sourceIdentity(source), state.sourceWasm, state.sourceDeobfuscated, state.sourceFormatted,
          state.sourceDeobfuscated ? deobfuscationKey(source) : null]);
      }

      function sourceWantedLine(source) {
        const saved = state.sourceWindow;
        return saved?.identity === sourceIdentity(source) && saved.representation === sourceRepresentation(source) ? saved.line : 0;
      }

      function sourceFormattedView(source, value, variant) {
        // The backend Oxc layout for JavaScript evidence, read one 1,000-line page at a time; otherwise the in-page layout, off the UI thread.
        const backend = variant === 'original' ? sourceFormatClient.page(source, value, sourceWantedLine(source)) : null;
        if (backend && !backend.fallback) return backend;
        const key = `${sourceIdentity(source)}|${variant}`, notice = backend?.notice ?? null;
        const prior = state.sourceFormatCache.get(key);
        if (prior?.sourceInput === value && prior.notice === notice) return prior;
        const entry = {pending: true, sourceInput: value, notice};
        state.sourceFormatCache.set(key, entry);
        sourceFormatClient.layout(source, value).then(result => {
          if (state.sourceFormatCache.get(key) !== entry) return;
          Object.assign(entry, result, {pending: false});
          boundSourceAnalysis(state.sourceFormatCache, 8, 64 * 1024 * 1024, Infinity, key);
          if (state.sourceFormatted && sourceIdentity(selectedSource()) === sourceIdentity(source)) renderSources();
        });
        return entry;
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
        // While another page loads, the page shown last stays.
        const shown = formatResult?.pending ? formatResult.previous ?? null : null;
        const formatted = shown ?? (formatResult && !formatResult.error && !formatResult.pending ? formatResult : null);
        return {
          formatPending: Boolean(formatResult?.pending && !shown),
          pageLoadingLine: shown ? sourceWantedLine(source) : null,
          formatNotice: formatResult?.notice ?? null,
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
        const representation = sourceRepresentation(source);
        const page = view.formatted?.paged ? view.formatted : null;
        const mapping = view.wasmRows ? state.wasmCache.get(wasmKey(source)) : view.derived ?? null;
        const formatting = view.formatted ?? null;
        const previous = state.sourceEditorView;
        const sameDocument = previous?.representation === representation && previous.content === content && previous.mapping === mapping && previous.formatting === formatting;
        const index = sameDocument ? previous.index : page ? sourcePageIndex(content, page.lineBase, page.lineCount) : sourceDocumentIndex(content);
        const savedWindow = state.sourceWindow?.identity === identity && state.sourceWindow.representation === representation ? state.sourceWindow : null;
        const requestedLine = target.line ?? savedWindow?.line ?? 0;
        const requestedColumn = target.column ?? savedWindow?.column ?? 0;
        const clampedLine = Math.max(0, Math.min(index.lineCount - 1, Number.isSafeInteger(requestedLine) ? requestedLine : 0));
        const window = sameDocument && previous.window.line === clampedLine && previous.window.column === requestedColumn
          ? previous.window : sourceDocumentWindow(index, clampedLine, requestedColumn);
        state.sourceWindow = view.pageLoadingLine === null || view.pageLoadingLine === undefined
          ? {identity, representation, line: window.line, column: window.column}
          : {identity, representation, line: view.pageLoadingLine, column: target.column ?? savedWindow?.column ?? 0};
        const highlighter = sameDocument && previous.highlighter ? previous.highlighter
          : createSourceHighlighter(view.wasmRows ? {kind: 'plain', mime_type: 'text/plain'} : source, index,
            page ? {highlighter: sourceOriginalHighlighter(source, view.active), offset: page.base} : null);
        if (!highlighter.ready(window.rows)) highlighter.advance(SOURCE_COLOR_SYNC_UNITS);
        const colored = highlighter.ready(window.rows);
        const sameWindow = sameDocument && previous.window.line === window.line && previous.window.column === window.column && previous.colored === colored;
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
        state.sourceEditorView = {identity, representation, content, mapping, formatting, index, window, view, mappingContext, highlighter, colored,
          search: sameDocument ? previous.search : null};
        const lineMap = view.lineMap;
        const colors = colored ? highlighter.rows(window.rows) : null;
        // Checkpoints extend in small steps between tasks; the window recolors once they reach it.
        if (!highlighter.done() && !highlighter.pumping) {
          highlighter.pumping = true;
          const pump = () => {
            const editor = state.sourceEditorView;
            if (editor?.highlighter !== highlighter || editor.identity !== sourceIdentity(selectedSource())) {highlighter.pumping = false; return;}
            highlighter.advance(SOURCE_COLOR_SLICE_UNITS);
            if (!editor.colored && highlighter.ready(editor.window.rows)) {
              renderSourceContent(selectedSource(), editor.view, {line: editor.window.line, column: editor.window.column, search: false});
              if (elements.sourceSearch.value) applySourceSearch(false, 0, {reveal: false});
            }
            if (highlighter.done()) highlighter.pumping = false; else setTimeout(pump, 0);
          };
          setTimeout(pump, 0);
        }

        const nodes = window.rows.map((excerpt, rowIndex) => {
          const {text: line, line: index} = excerpt;
          const mapped = lineMap ? lineMap[index] ?? null : mappedLines?.[rowIndex] ?? null;
          const mappedLine = mapped?.originalLine ?? null;
          const row = document.createElement('span');
          row.className = index === window.line ? 'source-line current-line' : 'source-line';
          row.dataset.line = String(index + 1);
          row.dataset.localLine = String(index);
          row.dataset.columnStart = String(excerpt.columnStart);
          const gutter = document.createElement('button');
          gutter.type = 'button';
          gutter.className = 'source-gutter';
          gutter.textContent = String(index + 1);
          gutter.disabled = mappedLine === null;
          gutter.setAttribute('aria-label', mappedLine === null ? 'Retained source line' : `Show original source at line ${mappedLine + 1}`);
          gutter.title = mappedLine === null ? 'Retained source line' : `Original ${mappedLine + 1}:${(mapped?.originalColumn ?? 0) + 1} · show the original source`;
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
          appendSourceSyntax(text, colors ? colors.rows[rowIndex] : line ? [{type: 'plain', text: line}] : []);
          const displayed = document.createElement('span'); displayed.className = 'source-excerpt';
          if (excerpt.columnStart) displayed.append(textElement('span', 'source-excerpt-notice', `⟪ columns 1–${excerpt.columnStart} omitted ⟫ `));
          displayed.append(text);
          if (excerpt.columnEnd < excerpt.fullLength) displayed.append(textElement('span', 'source-excerpt-notice', ` ⟪ columns ${excerpt.columnEnd + 1}–${excerpt.fullLength} omitted; use Find or Go to column ⟫`));
          row.append(gutter, displayed);
          return row;
        });
        elements.sourceCode.replaceChildren(...nodes);
        elements.sourceCodeWrap.dataset.gutterDigits = String(Math.max(5, String(index.lineCount).length));
        const layout = view.formatPending ? ' · formatting…' : view.formatError ? ` · ${view.formatError}`
          : view.formatted ? ` · ${view.formatted.engine === 'oxc' ? 'Oxc layout' : `whitespace layout${view.formatNotice ? `: ${view.formatNotice}` : ''}`}` : '';
        elements.sourceLanguage.textContent = view.wasmRows ? 'WASM disassembly · byte offsets'
          : `${sourceSyntaxLabel(highlighter.language)}${!colors ? ' · coloring…' : colors.truncated ? ' · color limit reached' : ''}${layout}`;
        elements.sourceLanguage.title = elements.sourceLanguage.textContent;
        elements.sourceCode.hidden = false;
        elements.sourceCodeEmpty.hidden = true;
        renderSourceWindowControls();
        if (sameOwner) {
          elements.sourceCodeWrap.scrollTop = scroll.top;
          elements.sourceCodeWrap.scrollLeft = scroll.left;
          const row = [...elements.sourceCode.children].find(value => value.dataset.line === focused?.line);
          const focusTarget = focused?.gutter ? row?.querySelector('.source-gutter') : row;
          if (focusTarget) {focusTarget.tabIndex = -1; focusTarget.focus({preventScroll: true});}
          const coverageChanged = previous.view.searchCoverage !== view.searchCoverage || previous.view.searchIncomplete !== view.searchIncomplete;
          if (coverageChanged && target.search !== false) applySourceSearch(false, 0, {reveal: false});
        } else {
          elements.sourceCodeWrap.scrollTop = 0;
          elements.sourceCodeWrap.scrollLeft = 0;
          const find = state.sourcePagedFind;
          if (find?.identity === identity && page && view.pageLoadingLine == null) {
            state.sourcePagedFind = null;
            if (elements.sourceSearch.value === find.query) applySourceSearch(false, 0);
          } else if (target.search !== false) applySourceSearch(false, 0, {reveal: false});
        }
      }

      function renderSources() {
        const source = selectedSource();
        sourceFactsPanel.sync(source);
        syncInvestigationRange(source);
        const view = source?.content !== undefined ? sourceDisplayView(source) : null;
        renderSourcePane();
        elements.sourceTree.setAttribute('aria-labelledby', `source-tab-${state.sourceCollection}`);
        renderSourceHealth();
        renderSourceTree();
        renderSourceTabs();
        renderSourceFacts(source);
        elements.sourceLocation.textContent = source?.url || (source ? sourceDisplayName(source) : 'Select a source');
        elements.sourceLocation.title = source ? `${source.url || sourceDisplayName(source)} · artifact ${source.artifact_id}` : '';
        elements.sourceSize.textContent = source ? formatByteSize(source.byte_size) : '0 bytes';
        elements.sourceHash.textContent = source?.sha256 ? `sha256 ${source.sha256}` : '';
        syncSourceDisplayControls(source, view);
        renderSourceContent(source, view);
        if (!investigationPassiveSource && state.sourceDeobfuscated && source?.kind === 'javascript' && !document.querySelector('#screen-sources').hidden) loadDeobfuscation(source);
        renderDeobfuscationReport(source);
        const reveal = state.sourceReveal;
        if (reveal && source?.content !== undefined && reveal.identity === sourceIdentity(source)) {
          state.sourceReveal = null;
          revealOriginalLine(source, reveal.line, reveal.column);
          if (reveal.length && markSourceMatch(reveal.line, reveal.column, reveal.length)) {
            elements.sourcePosition.textContent = `Line ${reveal.line + 1}, Column ${reveal.column + 1} · match from Search all files`;
          }
        }
        resumeInvestigationReturn();
        // After the editor holds this source's text, so Track calls reflects it.
        if (typeof invocationSitesPanel !== 'undefined') invocationSitesPanel.render();
      }

      // The navigator shows the file tree or Search all files; one tab each.
      function renderSourcePane() {
        const search = state.sourcePane === 'search';
        elements.sourceTree.hidden = search;
        document.querySelector('#source-tree-tools').hidden = search;
        document.querySelector('#source-search-all-panel').hidden = !search;
        document.querySelectorAll('.source-side-tab').forEach(tab => {
          const selected = search ? tab.id === 'source-tab-search' : tab.dataset.sourceCollection === state.sourceCollection;
          tab.setAttribute('aria-selected', String(selected));
          tab.tabIndex = selected ? 0 : -1;
        });
      }

      // The viewer's own limit, stated beside the code so it is never mistaken for captured text.
      function sourceLimitText(source, view) {
        if (!source?.contentTruncated || source.content === undefined || view?.wasmRows || view?.derived || sourceFactsPanel.original(source) !== undefined) return '';
        const hex = sourceHexArtifact(source);
        const shown = hex ? `${source.wasmHexBytes.toLocaleString()} bytes` : `${SOURCE_PREVIEW_BYTES / 1048576} MiB`;
        return `${hex ? 'Hex preview' : 'Preview'} limited to the first ${shown} of this ${source.byte_size.toLocaleString()}-byte file. Later bytes are not shown or searched; the original bytes are unchanged.`;
      }

      function syncSourceDisplayControls(source, view) {
        const limit = sourceLimitText(source, view);
        if (elements.sourceLimitNotice) {elements.sourceLimitNotice.textContent = limit; elements.sourceLimitNotice.hidden = !limit;}
        // The status bar names the evidence state; the full provenance is its tooltip.
        const label = sourceViewLabel(source, view);
        elements.sourceViewKind.textContent = (state.sourceWasm && source?.kind === 'wasm') || source?.content === undefined ? label
          : `${state.sourceDeobfuscated && sourceDerivedView(source) ? 'Derived' : 'Original'}${source.contentTruncated ? ' · truncated' : ''}${source.contentLossy ? ' · lossy' : ''}`;
        elements.sourceViewKind.title = label;
        elements.sourceWasm.hidden = source?.kind !== 'wasm' || source?.source_type !== 'artifact';
        elements.sourceWasm.setAttribute('aria-pressed', String(state.sourceWasm));
        elements.sourceWasm.setAttribute('aria-label', state.sourceWasm ? 'Show original WASM hex' : 'Inspect WebAssembly module');
        elements.sourceWasm.textContent = state.sourceWasm ? 'Hex' : 'Inspect';
        elements.sourceCode.classList.toggle('wasm-inspection', Boolean(view?.wasmRows));
        elements.sourcePretty.disabled = !source?.content || !sourcePrettySupported(source);
        elements.sourcePretty.setAttribute('aria-pressed', String(state.sourceFormatted));
        elements.sourcePretty.setAttribute('aria-label', state.sourceFormatted ? 'Show original source' : 'Pretty print source');
        elements.sourcePretty.textContent = !state.sourceFormatted ? '{ }' : view?.formatPending ? '{ } Formatting…'
          : view?.formatError ? '{ } Pretty print unavailable' : '{ } Pretty-printed · Show original';
        elements.sourcePretty.title = !state.sourceFormatted ? `Pretty print ${sourceSyntaxLabel(sourceSyntaxLanguage(source))}`
          : view?.formatError ?? 'A display layout; the evidence is unchanged. Show the source as captured.';
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
        if (view?.formatPending) return `${original} · formatting…`;
        if (view?.formatNotice && !state.sourceDeobfuscated) return `Pretty printed ${original.toLowerCase()} · whitespace layout · ${view.formatNotice}`;
        if (state.sourceDeobfuscated && sourceDerivedView(source)) {
          const status = state.deobfuscationRequests.get(deobfuscationKey(source))?.status;
          return `${state.sourceFormatted ? 'Pretty printed derived' : 'Derived'} · mapped to original source${status === 'error' ? ' · last successful analysis' : status === 'loading' ? ' · reanalyzing' : status === 'cancelled' ? ' · analysis cancelled' : ''}`;
        }
        if (!state.sourceDeobfuscated || !source) {
          return state.sourceFormatted && source ? `Pretty printed ${original.toLowerCase()} · ${view?.formatted?.engine === 'oxc' ? 'Oxc layout · ' : ''}mapped to original source` : original;
        }
        const request = state.deobfuscationRequests.get(deobfuscationKey(source));
        const prefix = state.sourceFormatted ? `Pretty printed ${original.toLowerCase()}` : original;
        return `${prefix} · ${request?.status === 'error' ? 'analysis failed' : request?.status === 'cancelled' ? 'analysis cancelled' : 'analysis pending'}`;
      }

      function sourceDerivedView(source) {
        return source?.deobfuscation?.representation ?? null;
      }

      // Only the original view's coordinates are artifact coordinates; pretty
      // printed, derived and Wasm views would name a different character.
      function invocationSitePositionProblem() {
        const source = selectedSource(), editor = state.sourceEditorView;
        if (source?.source_type !== 'artifact' || source.kind !== 'javascript') return 'Open one captured JavaScript artifact to track a function in it.';
        if (state.sourceWasm || state.sourceDeobfuscated || state.sourceFormatted) return 'Switch to the original source view to track a function at a position.';
        if (!editor || editor.identity !== sourceIdentity(source) || typeof editor.view?.original !== 'string') return 'Open the source text first.';
        return '';
      }

      // The caret or selection start in the source text, else the last line
      // and column Sources moved to with Go, Find or a link.
      function invocationSitePosition() {
        const problem = invocationSitePositionProblem();
        if (problem) return {error: problem};
        const editor = state.sourceEditorView;
        let {line, column} = editor.window;
        const selection = globalThis.getSelection?.();
        const anchor = selection?.rangeCount ? selection.getRangeAt(0) : null;
        const container = anchor?.startContainer?.nodeType === 1 ? anchor.startContainer : anchor?.startContainer?.parentElement;
        const text = container?.closest?.('.source-text');
        if (text && elements.sourceCode.contains(text)) {
          const prefix = document.createRange();
          prefix.setStart(text, 0);
          prefix.setEnd(anchor.startContainer, anchor.startOffset);
          const row = text.closest('.source-line');
          line = Number(row.dataset.localLine);
          column = Number(row.dataset.columnStart ?? 0) + prefix.toString().length;
        }
        const start = sourceDocumentOffset(editor.index, line);
        const original = editor.view.original;
        const byteOffset = start === null ? null : invocationSiteByteOffset(original, start + column, original.length);
        if (byteOffset === null) return {error: 'The current position is not a character of the retained source text.'};
        return {byteOffset, line, column};
      }

      function showInvocationSites() {
        if (document.querySelector('#screen-sources').hidden) showScreen('sources');
        state.sourceSidebarOpen = true;
        renderSourceSidebar();
        const details = document.querySelector('#invocation-sites-details');
        details.open = true;
        details.scrollIntoView?.({block: 'nearest'});
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

      // Marks a match on its displayed original line as the current match, the
      // same highlight Find and Facts ranges use. Columns outside the displayed
      // excerpt are not marked.
      function markSourceMatch(line, column, length) {
        const row = elements.sourceCode.querySelector(`[data-line="${line + 1}"]`);
        const text = row?.querySelector('.source-text');
        const displayColumn = column - Number(row?.dataset.columnStart ?? 0);
        if (!text || displayColumn < 0 || displayColumn >= text.textContent.length) return false;
        const range = sourceOccurrenceRange(text, {column: displayColumn, length: Math.min(length, text.textContent.length - displayColumn)});
        if (!range) return false;
        if (globalThis.Highlight && globalThis.CSS?.highlights) CSS.highlights.set('source-search-match', new Highlight(range));
        return true;
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
        // Request content, header blocks, cookie lists and stacks are read only by their Traffic views.
        if (['request_body', 'request_target', 'request_headers', 'response_headers', 'cookie_list', 'stack'].includes(artifact?.kind)) return;
        if (!sourceIsCurrent(artifact) || artifact.content !== undefined || artifact.loading || (artifact.loadError && !retry)) return;
        const identity = sourceIdentity(artifact);
        const controller = new AbortController();
        // Text previews read the whole artifact, up to its 16 MiB cap, in 2 MiB pages.
        const previewBytes = sourceHexArtifact(artifact) || canvasOwner ? 2097152 : SOURCE_PREVIEW_BYTES;
        const pages = Math.max(1, Math.ceil(Math.min(artifact.byte_size, previewBytes) / 2097152));
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
        }, 5000 + 5000 * pages);
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
          let buffer = await sourceFactsReadBytes(ownedResponse, 2097152, controller.signal);
          if (!current()) return;
          if (buffer.length !== Math.min(artifact.byte_size, 2097152)) throw new Error('The artifact preview byte size changed.');
          const total = response.headers.get('X-Artifact-Total-Bytes');
          if (total !== null && Number(total) !== artifact.byte_size) throw new Error('The artifact total byte size changed.');
          if (pages > 1) {
            const whole = new Uint8Array(Math.min(artifact.byte_size, previewBytes));
            whole.set(buffer);
            for (let offset = buffer.length; offset < whole.length; offset += 2097152) {
              const page = await fetch(`/api/artifacts/${encodeURIComponent(artifact.artifact_id)}/content?offset=${offset}&limit=2097152`, {cache: 'no-store', signal: controller.signal});
              if (!current() || !page.ok) {
                responseCancellation = page.body?.cancel().catch(() => {});
                if (!current()) return;
                throw new Error(`Artifact store returned ${page.status}`);
              }
              const bytes = await sourceFactsReadBytes(page, 2097152, controller.signal);
              if (!current()) return;
              const pageTotal = page.headers.get('X-Artifact-Total-Bytes');
              if (bytes.length !== Math.min(2097152, whole.length - offset) || (pageTotal !== null && Number(pageTotal) !== artifact.byte_size)) {
                throw new Error('The artifact preview byte size changed.');
              }
              whole.set(bytes, offset);
            }
            buffer = whole;
          }
          if (artifact.byte_size <= previewBytes && globalThis.crypto?.subtle) {
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
          artifact.contentLongLine = !sourceHexArtifact(artifact) && !canvasOwner && sourceHasLongLine(content);
          artifact.content = content;
          artifact.wasmHexBytes = sourceHexArtifact(artifact) ? hexBytes : undefined;
          artifact.contentTruncated = artifact.byte_size > buffer.length || (sourceHexArtifact(artifact) && buffer.length > hexBytes);
          if (!canvasOwner) boundSourcePreviews();
          if (!canvasOwner && !state.sourceFormatted && sourceIdentity(selectedSource()) === identity) state.sourceFormatted = sourceFormatWanted(artifact);
        } catch (error) {
          if (current()) {
            if (canvasOwner) for (const field of ['content', 'sourceTextLength', 'contentVerified', 'contentLossy', 'contentTruncated', 'contentLongLine']) delete artifact[field];
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

      // An explicit { } choice for this artifact wins; otherwise a minified file opens pretty-printed.
      function sourceFormatWanted(source) {
        if (!source) return false;
        return state.sourceFormatChoices?.get(sourceIdentity(source)) ?? Boolean(source.contentLongLine && sourcePrettyByDefault(source));
      }

      function selectArtifact(artifactId, line = null, {identity: expectedIdentity = null, passive = false, column = 0, length = 0} = {}) {
        const matches = state.artifacts.filter(candidate => candidate.artifact_id === artifactId);
        if (matches.length !== 1 || (expectedIdentity && !sourceArtifactIdentityMatches(matches[0], expectedIdentity))) {
          state.sourceNoticeKind = 'warning';
          state.sourceNotice = 'This exact artifact is missing, changed or ambiguous across retained sessions. No source was opened.';
          renderSourceHealth();
          return false;
        }
        const artifact = matches[0];
        if (!isSourceArtifact(artifact)) {
          state.sourceNoticeKind = 'warning';
          state.sourceNotice = artifact.kind !== 'canvas_data_url'
            ? `${{request_body: 'Request bodies are', request_target: 'Full request targets are', cookie_list: 'Cookie lists are'}[artifact.kind] ?? 'Header blocks are'} shown with their request in Traffic. No source was opened.`
            : 'Canvas images are shown in Fingerprinting. No source was opened.';
          renderSourceHealth();
          return false;
        }
        investigationPassiveSource = passive;
        state.sourceNotice = null;
        const identity = sourceIdentity(artifact);
        retireSourceAnalysis(identity);
        investigationBeforeSelection();
        sourceFactsPanel.cancel();
        state.selectedArtifactId = artifactId;
        state.sourceDeobfuscated = false;
        state.sourceFormatted = sourceFormatWanted(artifact);
        state.sourceWasm = false;
        if (!state.openArtifactIds.includes(artifactId)) state.openArtifactIds.push(artifactId);
        // A requested location is revealed by renderSources once these bytes
        // display, whether they are already loaded, loading or still to fetch.
        state.sourceReveal = line === null ? null : {identity, line, column, length};
        renderSources();
        loadArtifactContent(artifact);
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
        state.sourceFormatted = sourceFormatWanted(selectedSource());
        state.sourceWasm = false;
        renderSources();
        const selected = selectedSource();

        if (selected?.source_type === 'artifact') loadArtifactContent(state.artifacts.find(value => sourceIdentity(value) === sourceIdentity(selected)));
      }

      function renderQuickOpen() {
        const needle = elements.quickOpenInput.value.trim().toLowerCase();
        const matches = capturedSources().map(sourceReference).filter(source =>
          !needle || `${sourceDisplayName(source)} ${source.url} ${source.artifact_id}`.toLowerCase().includes(needle)
        );
        // The catalog can hold 100,000 sources; the list shows the first 200.
        const rows = matches.slice(0, 200).map(source => {
          const row = document.createElement('button');
          row.type = 'button';
          row.className = 'quick-open-row';
          const name = document.createElement('span'); name.textContent = sourceDisplayName(source);
          const path = document.createElement('small'); path.textContent = `${source.url || '(anonymous)'} · artifact ${source.artifact_id}`;
          row.append(name, path);
          row.addEventListener('click', () => {
            elements.quickOpen.hidden = true;
            selectArtifact(source.artifact_id);
          });
          return row;
        });
        if (matches.length > rows.length) rows.push(textElement('p', 'quick-open-more', `${(matches.length - rows.length).toLocaleString()} more files match. Type more of the name or URL.`));
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
          // The first 50,000 records of every kind are read in manifest order. Past them, only the kinds
          // this catalog alone supplies are read, so request records cannot crowd out scripts; Traffic
          // reads a request's records by ID. Growth continues from the last boundary.
          const catalogLimit = 50000, sourceLimit = 100000;
          const read = async (query, etag = null) => {
            const response = await fetch(`/api/artifacts?${query}`, {cache: 'no-store', headers: etag ? {'If-None-Match': etag} : {}});
            if (response.status === 304) return null;
            if (!response.ok) throw new Error(`Artifact store returned ${response.status}`);
            const body = await response.json();
            if (!isArtifactResponse(body) || (body.query !== undefined && !/^(0|[1-9][0-9]{0,19})$/.test(String(body.query?.next_after)))) {
              throw new TypeError('Malformed artifact response');
            }
            return {body, etag: response.headers.get('ETag')};
          };
          const probe = await read('after=0&limit=1', state.artifactEtag);
          if (!probe) return;
          const {body} = probe;
          let records = body.artifacts, appended = null, cursor = null, complete = true, limit = sourceLimit;
          if (body.query) {
            const first = body.artifacts.length ? JSON.stringify(body.artifacts[0]) : null, previous = state.artifactCursor;
            const grown = first !== null && previous?.first === first && previous.catalog === state.artifacts;
            let after = grown ? previous.after : '0', everyKind = grown ? previous.everyKind : 0, sources = grown ? previous.sources : 0;
            records = []; complete = false;
            // A page is sized so a cursor never lands past a record that was not kept.
            for (let page = 0; page < 256; page++) {
              const unfiltered = everyKind < catalogLimit, full = !unfiltered && sources >= sourceLimit;
              const size = unfiltered ? Math.min(5000, catalogLimit - everyKind) : full ? 1 : Math.min(5000, sourceLimit - sources);
              const next = (await read(`after=${after}&limit=${size}${unfiltered ? '' : `&kind=${catalogOnlyArtifactKinds.join(',')}`}`))?.body;
              if (!next) throw new TypeError('Malformed artifact response');
              // One record past the bound proves more remain, and it is not kept.
              if (full && next.artifacts.length) break;
              records.push(...next.artifacts);
              if (unfiltered) everyKind += next.artifacts.length;
              sources += next.artifacts.filter(isSourceArtifact).length;
              if (!next.query) {complete = true; break;}
              after = next.query.next_after;
              if (!next.query.limited && !next.query.budget_exhausted) {complete = true; break;}
            }
            cursor = {first, after, everyKind, sources};
            if (grown) appended = records;
          } else if (records.length) {
            // A reader that does not page answers the one-record probe with one record, so read what it can give.
            records = (await read('limit=5000'))?.body.artifacts ?? records;
            complete = records.length < 5000;
            limit = 5000;
          }
          const keepCursor = () => {state.artifactCursor = cursor && {...cursor, catalog: state.artifacts};};
          state.artifactCatalogLimit = complete ? 0 : limit;
          state.artifactEtag = probe.etag;
          if (typeof body.artifact_receiver_configured === 'boolean') {
            state.artifactReceiverConfigured = body.artifact_receiver_configured;
          }
          if (typeof body.artifact_receiver_connected === 'boolean') {
            state.artifactReceiverConnected = body.artifact_receiver_connected;
          }
          state.artifactReceiverError = null;
          renderShellStatus();
          const catalogSignature = appended ? null : JSON.stringify(records);
          if (appended ? !appended.length : catalogSignature === state.artifactCatalogSignature) {
            keepCursor();
            if (canvasGalleryVisible()) renderFingerprintActivity();
            renderSourceHealth();
            return;
          }
          state.artifactCatalogSignature = catalogSignature;
          // A newly retained script can be another version of a saved one.
          if (typeof invocationSitesPanel !== 'undefined') invocationSitesPanel.refresh();
          if (records.length === 0 && !appended) {
            if (state.sessionMode === 'live') {
              retireCanvasPreviews('Canvas previews released because the artifact catalog is empty.');
              for (const artifact of state.artifacts) releaseSourcePreview(artifact, artifact);
              state.artifacts = [];
              trafficArtifacts.clear();
              state.openArtifactIds = [];
              state.selectedArtifactId = null;
              renderSources();
            } else {
              renderSourceHealth();
            }
            keepCursor();
            return;
          }
          const origin = state.sessionMode === 'live' ? 'live' : 'demo';
          // Preserve the pending operation's owner, never clone loading state.
          const retain = (artifact, prior = {}) => Object.assign(prior,
            Object.fromEntries(sourceFactsFields.filter(field => Object.hasOwn(artifact, field)).map(field => [field, artifact[field]])), {origin});
          if (appended) state.artifacts = state.artifacts.concat(appended.map(artifact => retain(artifact)));
          else {
            const existing = new Map(state.artifacts.map(artifact => [sourceIdentity(artifact), artifact]));
            const incoming = new Set(records.map(sourceIdentity));
            for (const artifact of state.artifacts) if (!incoming.has(sourceIdentity(artifact))) releaseSourcePreview(artifact, artifact);
            state.artifacts = records.map(artifact => retain(artifact, existing.get(sourceIdentity(artifact))));
          }
          keepCursor();
          if (!canvasGalleryVisible()) retireCanvasPreviews();
          state.openArtifactIds = state.openArtifactIds.filter(id => state.artifacts.some(artifact => artifact.artifact_id === id));
          if (!state.artifacts.some(artifact => artifact.artifact_id === state.selectedArtifactId && isSourceArtifact(artifact))) {
            state.selectedArtifactId = state.artifacts.find(isSourceArtifact)?.artifact_id ?? null;
            state.openArtifactIds = state.selectedArtifactId === null ? [] : [state.selectedArtifactId];
          }
          renderSources();
          const selected = state.artifacts.find(artifact => artifact.artifact_id === state.selectedArtifactId && isSourceArtifact(artifact));
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
          state.artifactCursor = null;
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
          if (trigger?.id === 'nav-vm-workspace' && state.vmAnalysisRequestId !== null) refreshVmAnalysis(null);
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

      // The event poll alone decides the connection state, and it is bounded:
      // a backend that does not answer within 10 seconds is shown as not
      // responding (renderNetworkNotice names the same limit). The reads that
      // follow a poll run afterwards, outside its guard.
      async function refresh() {
        if (state.refreshing) return;
        state.refreshing = true;
        // A capture action that starts or ends while this poll is in flight
        // makes its answer stale: it can describe evidence from before a stop
        // or a clear. Such a poll changes nothing and is read again.
        const captureGeneration = state.captureActionGeneration;
        const stale = () => Boolean(state.captureAction) || captureGeneration !== state.captureActionGeneration;
        const deadline = AbortSignal.timeout(10000);
        let next = null;
        try {
          const headers = state.eventEtag ? { 'If-None-Match': state.eventEtag } : {};
          const response = await fetch('/api/events?limit=5000', { cache: 'no-store', headers, signal: deadline });
          if (stale()) { next = 'repeat'; return; }
          // A failed poll drops the entity tag, so 304 always follows a valid answer.
          if (response.status === 304) {
            state.trafficIndex?.retry();
            next = 'unchanged';
            return;
          }
          if (!response.ok) throw new Error(`Broker returned ${response.status}`);
          const rawBody = await response.text();
          if (stale()) { next = 'repeat'; return; }
          let body;
          try { body = JSON.parse(rawBody); } catch { throw new TypeError('Malformed broker response'); }
          if (!isBrokerResponse(body)) throw new TypeError('Malformed broker response');
          state.eventPollAnswered = true;
          state.eventEtag = response.headers.get('ETag');
          const brokerConnected = body.broker_connected !== false;
          state.captureStopped = body.capture_stopped === true;
          state.captureControlsAvailable = body.capture_controls_available === true;
          const nextSessionMode = ['demo', 'idle'].includes(body.capture_mode)
            ? body.capture_mode : 'live';
          // Rows read for another kind of session are not this session's.
          if (nextSessionMode !== state.sessionMode) state.trafficLoaded.clear();
          state.sessionMode = nextSessionMode;
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
          globalThis.RebRequestTabs?.attachRequestTabs(state.nativeRequests, body.network_events ?? state.events);
          state.captureExclusions = globalThis.RebNetworkScope?.captureExclusionTotals(body.network_events ?? state.events) ?? null;
          rebuildTrafficRequests();
          state.trafficIndex?.invalidate();
          let selectedRequest = state.requests.find(request => request.id === state.selectedRequestId);
          if (!selectedRequest && state.selectedRequestId !== null) resetRequestSelection();
          updateSelectionSummary(selectedRequest);
          setEventConnection(brokerConnected ? 'connected' : 'broker-offline');
          state.lastUpdatedLabel = brokerConnected
            ? state.sessionMode === 'live'
              ? `updated ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}`
              : state.sessionMode === 'demo' ? 'deterministic developer evidence loaded' : 'start a live capture'
            : (state.events.length > 0 ? 'last valid evidence retained' : 'no live evidence');
          renderShellStatus();
          elements.gaps.textContent = eventGapLabel(shownSequenceGaps(), shownQueueDrops(), shownNamedGaps());
          renderNetworkNotice();
          renderRequests();
          renderInspector();
          renderEvidence();
          if (!document.querySelector('#screen-signals').hidden) renderFingerprintActivity();
          next = 'changed';
        } catch (error) {
          if (stale()) { next = 'repeat'; return; }
          state.eventEtag = null;
          const malformed = error instanceof TypeError && error.message === 'Malformed broker response';
          setEventConnection(malformed ? 'malformed' : deadline.aborted ? 'unresponsive' : 'unreachable');
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
          // An action that is still running reads again when it ends.
          if (next === 'repeat') { if (!state.captureAction) await refresh(); }
          else if (next) await refreshPollDependents(next === 'changed');
        }
      }

      // Signal profile, artifact and VM reads follow a valid poll as one chain.
      // A later poll neither waits for a slow chain (a cold VM analysis can run
      // for minutes, bounded by its worker deadline) nor restarts it, so the
      // poll keeps the connection state current meanwhile.
      async function refreshPollDependents(eventsChanged) {
        retryTrafficUnreadSelection();
        if (state.refreshingDependents) {
          if (eventsChanged) renderVmLab();
          return;
        }
        state.refreshingDependents = true;
        try {
          await refreshRequestSignalProfile();
          await refreshArtifacts();
          refreshSelectedRequestBody();
          await refreshVmAnalysis();
          if (eventsChanged) renderVmLab();
        } finally {
          state.refreshingDependents = false;
        }
      }

      // A row whose records could not be read is read again after each valid
      // poll, one read at a time, until it opens or another row is selected.
      function retryTrafficUnreadSelection() {
        const failed = state.trafficUnreadSelection;
        if (!failed || state.trafficLoadingId !== null) return;
        loadTrafficRequest(state.trafficIndex?.row(failed.id) ?? failed.indexed, true);
      }

      // The single transition for the event connection. 'connected' and
      // 'broker-offline' are valid answers (the second has no live broker,
      // for example after Stop). 'unreachable', 'unresponsive' (no answer in
      // time) and 'malformed' are failed polls: the backend's capture state is
      // unknown, so Stop and Clear stay disabled until a valid answer.
      function setEventConnection(connection) {
        state.connection = connection;
        state.broker = connection === 'connecting' || connection === 'connected' || connection === 'preview'
          ? connection : 'unavailable';
        state.eventFailureKind = connection === 'malformed' ? 'malformed'
          : connection === 'unreachable' || connection === 'unresponsive' ? 'disconnected' : null;
        if (state.eventFailureKind) state.captureControlsAvailable = false;
      }

      function useStandalonePreview() {
        state.trafficRenderedView = null;
        setEventConnection('preview');
        state.sessionMode = 'preview';
        state.events = [];
        state.canvasRenderCaptures = [];
        state.eventsLimited = false;
        state.sequenceGaps = 0n;
        state.queueDrops = 0n;
        state.namedGaps = [];
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
        state.decoderEngineStatus = 'unavailable';
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
      // One capture action at a time. The poll re-renders these buttons from
      // state, so the in-flight action is state rather than a disabled button.
      async function performCaptureAction(action) {
        const button = action === 'stop' ? elements.signalStopCapture : elements.signalClearEvents;
        if (state.captureAction || button.disabled) return;
        if (action === 'clear' && !window.confirm(
          'Clear all recorded events, traces, and request signal profiles from this capture session? Canvas artifacts and other saved files will remain on disk. This cannot be undone.'
        )) return;
        state.captureAction = action;
        state.captureActionGeneration += 1;
        state.captureActionError = null;
        renderFingerprintActivity();
        // Stop waits up to 5 seconds for the broker. Past this deadline the
        // outcome is unknown, and the next valid poll shows the capture state.
        const deadline = AbortSignal.timeout(15000);
        try {
          const response = await fetch('/api/capture/actions', {
            method: 'POST', cache: 'no-store', signal: deadline,
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
        } catch (error) {
          state.captureActionError = deadline.aborted
            ? `${action === 'stop' ? 'Stop' : 'Clear'} did not answer within 15 seconds; its outcome is unknown. The next refresh shows the current capture state.`
            : error.message;
        } finally {
          state.captureAction = null;
          state.captureActionGeneration += 1;
        }
        renderFingerprintActivity();
        // A poll that overlapped the action is discarded and repeats itself.
        await refresh();
        renderFingerprintActivity();
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
      // Cmd/Ctrl + 1-8 opens the sidebar workspace at that position, exactly as
      // a click does. Digits follow the visible order, so the hints stay true.
      // Physical digit keys keep the shortcut stable across keyboard layouts;
      // a modal dialog keeps the keyboard.
      document.addEventListener('keydown', event => {
        if (!(event.metaKey || event.ctrlKey) || event.altKey || event.shiftKey || event.repeat) return;
        const digit = /^Digit([1-9])$/.exec(event.code)?.[1];
        if (!digit || document.querySelector('dialog:modal')) return;
        const button = document.querySelectorAll('.primary-nav .nav-button[data-screen]')[Number(digit) - 1];
        if (!button || button.disabled) return;
        event.preventDefault();
        button.click();
        button.focus({ preventScroll: true });
      });
      document.querySelectorAll('.type-filter').forEach(button => button.addEventListener('click', () => {
        state.requestType = button.dataset.filter;
        state.requestDomain = 'all';
        document.querySelectorAll('.type-filter').forEach(candidate => candidate.setAttribute('aria-pressed', String(candidate === button)));
        renderRequests();
      }));
      document.querySelectorAll('.request-flag').forEach(button => button.addEventListener('click', () => {
        if (button.dataset.flag === 'hideInternal') return setHideBrowserInternal(!state.hideBrowserInternal);
        state.trafficFlags = {...state.trafficFlags, [button.dataset.flag]: !state.trafficFlags[button.dataset.flag]};
        button.setAttribute('aria-pressed', String(state.trafficFlags[button.dataset.flag]));
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
        state.trafficSort = 'capture'; state.trafficSortDirection = -1; renderRequests();
      });
      elements.requestLatest.addEventListener('click', () => {
        state.trafficSort = 'capture'; state.trafficSortDirection = -1;
        state.trafficNewIds.clear(); state.trafficPendingCount = 0;
        state.trafficWindowStart = 0; state.trafficWindowAnchor = null;
        elements.requestRows.scrollTop = 0;
        renderRequests();
      });
      document.querySelector('#payload-inspector').addEventListener('click', event => {
        const key = event.target.closest?.('.traffic-body-more')?.dataset.contentKey;
        if (key) loadMoreRequestBody(key);
      });
      // The list holds focus while a keyboard target loads; rows handle their own keys.
      elements.requestRows.addEventListener('keydown', event => {
        if (event.target === elements.requestRows) moveRequestSelection(event);
      });
      elements.requestRows.addEventListener('scroll', () => {
        if (state.trafficScrollFrame) return;
        state.trafficScrollFrame = requestAnimationFrame(() => {
          state.trafficScrollFrame = 0;
          const total = state.trafficRenderedView?.visibleCount ?? 0;
          if (state.trafficPendingCount && trafficAtNewest()) {
            state.trafficPendingCount = 0; state.trafficNewIds.clear(); renderTrafficLatest();
          }
          if (trafficBlockStart(elements.requestRows, total, state.trafficWindowStart) !== state.trafficWindowStart) renderRequests();
          else remountTrafficRows(elements.requestRows);
        });
      }, {passive: true});
      // A list that gains height, or is shown, mounts the rows that come into view.
      if (typeof ResizeObserver === 'function') new ResizeObserver(() => remountTrafficRows(elements.requestRows)).observe(elements.requestRows);
      elements.requestCopyUrl.addEventListener('click', async () => {
        const selected = state.requests.find(request => request.id === state.selectedRequestId);
        const fullUrl = selected?.urlTruncated ? requestFullUrl(selected) : null;
        if (!selected || selected.hostOnly || (selected.urlTruncated && !fullUrl) || selected.targetKind === 'path') return;
        try {
          const url = selected.origin === 'sample' ? `https://checkout.acme.test${selected.path}` : fullUrl ?? selected.path;
          await navigator.clipboard.writeText(url);
          elements.requestCopyUrl.textContent = 'Copied';
        } catch {
          elements.requestCopyUrl.textContent = 'Copy unavailable';
        }
        setTimeout(() => { elements.requestCopyUrl.textContent = 'Copy URL'; }, 1800);
      });
      document.querySelector('#request-unresolved').addEventListener('click', () => {
        state.requestTabId = state.requestTabId === 'unresolved' ? 'all' : 'unresolved';
        state.requestDomain = 'all';
        renderRequests();
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
        if (current?.start) moveSourceWindow(current.start - 1);
      });
      elements.sourceWindowNext.addEventListener('click', () => {
        const current = state.sourceEditorView?.window;
        if (current) moveSourceWindow(current.end);
      });
      function openSourceGoto() {
        if (!state.sourceEditorView) return;
        elements.sourceMore.open = false;
        elements.sourceWindow.hidden = false;
        renderSourceWindowControls();
        elements.sourceWindowLine.focus();
        elements.sourceWindowLine.select();
      }
      function closeSourceGoto(restoreFocus) {
        if (elements.sourceWindow.hidden) return;
        elements.sourceWindow.hidden = true;
        if (restoreFocus) elements.sourceCodeWrap.focus({preventScroll: true});
      }
      elements.sourceGoto.addEventListener('click', openSourceGoto);
      elements.sourceWindow.addEventListener('submit', event => {
        event.preventDefault();
        if (moveSourceWindow(Number(elements.sourceWindowLine.value) - 1, Number(elements.sourceWindowColumn.value) - 1)) closeSourceGoto(false);
        else elements.sourcePosition.textContent = 'Choose a retained line and column within that line.';
      });
      elements.sourceWindow.addEventListener('keydown', event => {
        if (event.key === 'Escape') {event.preventDefault(); closeSourceGoto(true);}
      });
      elements.sourceMore.addEventListener('click', event => {
        const action = event.target.closest?.('.source-more-menu button');
        if (!action) return;
        elements.sourceMore.open = false;
        if (document.activeElement === action || document.activeElement === document.body) elements.sourceMore.querySelector('summary').focus();
      });
      document.addEventListener('pointerdown', event => {
        if (elements.sourceMore.open && !elements.sourceMore.contains(event.target)) elements.sourceMore.open = false;
        if (!elements.sourceWindow.hidden && !elements.sourceWindow.contains(event.target) && !elements.sourceMore.contains(event.target)) closeSourceGoto(false);
      });
      // Cmd/Ctrl+F finds in the open source and Ctrl+G goes to a line, as in VS Code.
      document.addEventListener('keydown', event => {
        if (document.querySelector('#screen-sources').hidden || event.altKey || event.shiftKey || event.repeat || document.querySelector('dialog:modal')) return;
        if (event.key === 'Escape' && elements.sourceMore.open) {
          event.preventDefault();
          const inside = elements.sourceMore.contains(document.activeElement);
          elements.sourceMore.open = false;
          if (inside) elements.sourceMore.querySelector('summary').focus();
        } else if (event.code === 'KeyF' && (event.metaKey || event.ctrlKey)) {
          event.preventDefault();
          elements.sourceSearch.focus();
          elements.sourceSearch.select();
        } else if (event.code === 'KeyG' && event.ctrlKey && !event.metaKey) {
          event.preventDefault();
          openSourceGoto();
        }
      });
      // The raw range of formatted text, or '' when this view has none.
      function sourceRawRangeText(editor, start, end) {
        const view = editor?.view;
        if (!view?.formatted || view.derived) return '';
        const local = sourceWhitespaceRange(view.formatted.map, view.formatted.sourceInput ?? view.active, view.formatted.text, start, end);
        if (!local) return '';
        const base = view.formatted.base ?? 0, range = {start: local.start + base, end: local.end + base};
        const original = editor.originalIndex ??= sourceDocumentIndex(view.active), from = sourceDocumentPosition(original, range.start), to = sourceDocumentPosition(original, range.end);
        return from && to ? ` · raw ${from.line + 1}:${from.column + 1}–${to.line + 1}:${to.column + 1} (offsets ${range.start}–${range.end})` : '';
      }
      // The status bar follows the caret and the selection in the mounted source text.
      function syncSourceSelection() {
        const editor = state.sourceEditorView, selection = globalThis.getSelection?.();
        const point = (node, offset) => {
          const text = (node?.nodeType === 1 ? node : node?.parentElement)?.closest?.('.source-text');
          if (!editor || !text || !elements.sourceCode.contains(text)) return null;
          const prefix = document.createRange();
          prefix.setStart(text, 0);
          prefix.setEnd(node, offset);
          const row = text.closest('.source-line'), line = Number(row.dataset.localLine);
          const column = Number(row.dataset.columnStart ?? 0) + prefix.toString().length, start = sourceDocumentOffset(editor.index, line);
          return start === null ? null : {line, column, offset: start + column};
        };
        const anchor = selection?.rangeCount ? point(selection.anchorNode, selection.anchorOffset) : null;
        const focus = anchor ? point(selection.focusNode, selection.focusOffset) : null;
        const length = focus ? Math.abs(focus.offset - anchor.offset) : 0;
        elements.sourceSelection.hidden = !length;
        elements.sourceSelection.textContent = length ? `${length} selected` : '';
        if (focus) {
          const start = anchor.offset <= focus.offset ? anchor : focus;
          const raw = length ? sourceRawRangeText(editor, start.offset, start.offset + length) : '';
          elements.sourcePosition.textContent = raw ? `Line ${start.line + 1}, Column ${start.column + 1}${raw}` : sourcePositionText(editor, focus.line, focus.column);
        }
      }
      let sourceSelectionFrame = 0;
      document.addEventListener('selectionchange', () => {
        if (sourceSelectionFrame || document.querySelector('#screen-sources').hidden) return;
        sourceSelectionFrame = requestAnimationFrame(() => {sourceSelectionFrame = 0; syncSourceSelection();});
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
        state.sourcePane = 'files';
        state.sourceCollection = button.dataset.sourceCollection;
        const artifact = state.artifacts.find(candidate => candidate.artifact_id === state.selectedArtifactId && isSourceArtifact(candidate)) ??
          state.artifacts.find(isSourceArtifact);
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
        const source = selectedSource();
        state.sourceFormatted = !state.sourceFormatted;
        if (source) state.sourceFormatChoices.set(sourceIdentity(source), state.sourceFormatted);
        if (state.sourceFormatted) sourceFormatClient.forget(source);
        renderSources();
      });
      // A click selects the formatted token, whose characters are its raw range; the status bar then names that range.
      elements.sourceCode.addEventListener('click', event => {
        const editor = state.sourceEditorView, view = editor?.view;
        const token = event.target instanceof Element ? event.target.closest('.source-text > span:not(.source-indent)') : null;
        if (!view?.formatted || view.derived || !token || editor.identity !== sourceIdentity(selectedSource())) return;
        codeViewSelectToken(token);
        // After the caret update that the same click schedules.
        requestAnimationFrame(syncSourceSelection);
      });
      // Search all files. Reads use the artifact content route with a 2 MiB
      // limit and the Sources preview's checks. A loaded preview is reused as is;
      // other text stays in a small search-owned cache, so typing does not
      // refetch every file and neither cache grows the other's bound.
      const SOURCE_SEARCH_CACHE_UNITS = 8 * 1024 * 1024;
      const sourceSearchCache = new Map();
      function sourceSearchFiles() {
        const sources = capturedSources(), retained = new Set(sources.map(sourceIdentity));
        for (const key of sourceSearchCache.keys()) if (!retained.has(key)) sourceSearchCache.delete(key);
        return sources.map(source => ({identity: sourceIdentity(source), artifactId: source.artifact_id, name: `${sourceDisplayName(source)} · artifact ${source.artifact_id}`,
          url: source.url ?? '', icon: sourceIcon(source), byteSize: source.byte_size, binary: sourceHexArtifact(source)}));
      }
      async function readSourceSearchText(entry, signal, limit) {
        const matches = state.artifacts.filter(artifact => artifact.artifact_id === entry.artifactId);
        const artifact = matches.length === 1 && sourceIdentity(matches[0]) === entry.identity ? matches[0] : null;
        if (!artifact) throw new Error('changed or left the retained catalog');
        if (artifact.content !== undefined && !artifact.loading) {
          return {text: artifact.content.slice(0, artifact.sourceTextLength ?? artifact.content.length), bytes: Math.min(artifact.byte_size, limit),
            partial: artifact.byte_size > limit || Boolean(artifact.contentTruncated), lossy: Boolean(artifact.contentLossy)};
        }
        const cached = sourceSearchCache.get(entry.identity);
        if (cached) {sourceSearchCache.delete(entry.identity); sourceSearchCache.set(entry.identity, cached); return cached;}
        const controller = new AbortController(), abort = () => controller.abort();
        signal.addEventListener('abort', abort, {once: true});
        let timedOut = false;
        const timeout = setTimeout(() => {timedOut = true; abort();}, 10000);
        try {
          const response = await fetch(`/api/artifacts/${encodeURIComponent(artifact.artifact_id)}/content?limit=${limit}`, {cache: 'no-store', signal: controller.signal});
          if (!response.ok) {response.body?.cancel().catch(() => {}); throw new Error(`artifact store returned ${response.status}`);}
          const buffer = await sourceFactsReadBytes(response, limit, controller.signal);
          const total = response.headers.get('X-Artifact-Total-Bytes');
          if (buffer.length !== Math.min(artifact.byte_size, limit) || total !== null && Number(total) !== artifact.byte_size) throw new Error('its retained byte size changed');
          if (artifact.byte_size <= limit && globalThis.crypto?.subtle) {
            const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', buffer)), byte => byte.toString(16).padStart(2, '0')).join('');
            if (hash !== artifact.sha256) throw new Error('its bytes do not match the retained SHA-256');
          }
          let lossy = false;
          try {new TextDecoder('utf-8', {fatal: true}).decode(buffer);} catch {lossy = true;}
          const result = {text: new TextDecoder('utf-8', {fatal: false, ignoreBOM: true}).decode(buffer), bytes: buffer.length, partial: artifact.byte_size > buffer.length, lossy};
          if (signal.aborted) return result;
          sourceSearchCache.set(entry.identity, result);
          let units = 0;
          for (const value of sourceSearchCache.values()) units += value.text.length;
          for (const [key, value] of sourceSearchCache) {
            if (units <= SOURCE_SEARCH_CACHE_UNITS) break;
            units -= value.text.length; sourceSearchCache.delete(key);
          }
          return result;
        } catch (error) {
          throw new Error(timedOut ? 'timed out after 10 seconds' : String(error?.message ?? error).replace(/\.$/, ''));
        } finally {
          clearTimeout(timeout);
          signal.removeEventListener('abort', abort);
        }
      }
      // A result opens through the Sources selection with its location, so
      // Back returns to these results with their scroll and focus.
      function openSourceSearchMatch(file, match) {
        const matches = state.artifacts.filter(artifact => artifact.artifact_id === file.artifactId);
        if (matches.length !== 1 || sourceIdentity(matches[0]) !== file.identity) {
          state.sourceNoticeKind = 'warning';
          state.sourceNotice = 'This file changed or left the retained catalog after the search. Search again before opening it.';
          renderSourceHealth();
          return false;
        }
        if (investigationScreen() === 'sources') investigationNavigation?.record();
        if (selectArtifact(file.artifactId, match.line, {passive: true, column: match.column, length: match.length}) === false) return false;
        if (investigationScreen() !== 'sources') showScreen('sources');
        return true;
      }
      const sourceSearchPanel = createSourceSearchPanel({
        input: document.querySelector('#source-search-all-input'), matchCase: document.querySelector('#source-search-all-case'),
        status: document.querySelector('#source-search-all-status'), notes: document.querySelector('#source-search-all-notes'),
        results: document.querySelector('#source-search-all-results'),
        list: sourceSearchFiles, read: readSourceSearchText, open: openSourceSearchMatch
      });
      function openSourceSearch(query) {
        showScreen('sources');
        state.sourcePane = 'search';
        renderSourcePane();
        return sourceSearchPanel.search(query);
      }
      document.querySelector('#source-tab-search').addEventListener('click', () => {
        state.sourcePane = 'search';
        renderSourcePane();
        document.querySelector('#source-search-all-input').focus();
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
      elements.collectionFolderForm.querySelectorAll('input, textarea, select').forEach(field => field.addEventListener('input', () => {
        state.collectionFolderDirty = true;
        state.collectionDeleteFolderId = null;
        renderCollectionFolderForm();
      }));
      elements.collectionDeleteFolder.addEventListener('click', deleteCollectionFolder);
      elements.collectionRequestForm.addEventListener('submit', event => {
        event.preventDefault(); saveCollectionRequest();
      });
      elements.collectionRequestForm.querySelectorAll('input, textarea, select').forEach(field => field.addEventListener('input', () => {
        state.collectionDraftDirty = true;
        state.collectionDeleteRequestId = null;
        renderCollectionRequestForm();
      }));
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
      window.addEventListener('beforeunload', guardUnsavedWorkUnload);
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
      document.querySelector('#console-traffic-back').addEventListener('click', () => setConsoleTrafficView(false));
      document.addEventListener('reb-console-traffic', event => {
        const {session, target, events, dropped} = event.detail;
        if (!/^[1-9][0-9]{0,19}$/.test(session) || !/^[1-9][0-9]{0,19}$/.test(target) || !Array.isArray(events) || events.length > 64) return;
        for (const record of events) {
          if (!/^[1-9][0-9]{0,19}$/.test(record.event_id) || record.document_id !== target || typeof record.origin !== 'string' || record.origin.length > 256 || typeof record.method !== 'string' || record.method.length > 16 || !Number.isInteger(record.status) || !Number.isFinite(record.time)) continue;
          consoleTraffic.set(`${session}:${target}:${record.event_id}`, {...record, session});
        }
        if (investigationScreen() === 'traffic') investigationNavigation?.record();
        while (consoleTraffic.size > 128) consoleTraffic.delete(consoleTraffic.keys().next().value);
        showScreen('traffic'); setConsoleTrafficView(true);
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

      // Sidebar mode. On wide windows the toggle (or Cmd/Ctrl+B) switches between
      // the full sidebar and the icon rail, and the choice is remembered. Narrow
      // windows always use the rail; there the toggle slides the full sidebar over
      // the evidence until a choice, Escape or an outside click closes it.
      const sidebarShell = (() => {
        const app = document.querySelector('.app');
        const sidebar = document.querySelector('#sidebar');
        const toggle = document.querySelector('#sidebar-toggle');
        const narrow = window.matchMedia('(max-width: 1099px)');
        let collapsed = false, peek = false;
        try { collapsed = localStorage.getItem('reb-sidebar') === 'collapsed'; } catch { /* Keep the full sidebar. */ }
        const sync = () => {
          if (!narrow.matches) peek = false;
          const mode = narrow.matches ? (peek ? 'peek' : 'rail') : collapsed ? 'rail' : 'expanded';
          app.dataset.sidebar = mode;
          const label = mode === 'rail' ? 'Expand sidebar' : 'Collapse sidebar';
          toggle.setAttribute('aria-expanded', String(mode !== 'rail'));
          toggle.setAttribute('aria-label', label);
          toggle.title = `${label} (⌘ / Ctrl + B)`;
        };
        const closePeek = (focusToggle = false) => {
          if (!peek) return;
          peek = false;
          sync();
          if (focusToggle) toggle.focus({ preventScroll: true });
        };
        const flip = () => {
          if (narrow.matches) peek = !peek;
          else {
            collapsed = !collapsed;
            try { localStorage.setItem('reb-sidebar', collapsed ? 'collapsed' : 'expanded'); } catch { /* Native private mode may not persist preferences. */ }
          }
          sync();
        };
        toggle.addEventListener('click', flip);
        document.addEventListener('keydown', event => {
          if (event.key === 'Escape' && peek) { event.preventDefault(); closePeek(true); return; }
          if (!(event.metaKey || event.ctrlKey) || event.altKey || event.shiftKey || event.repeat || event.code !== 'KeyB') return;
          // Text fields keep the key: Ctrl+B moves the caret in macOS editors.
          if (event.target?.closest?.('input, textarea, select, [contenteditable="true"]') || document.querySelector('dialog:modal')) return;
          event.preventDefault();
          flip();
        });
        document.addEventListener('pointerdown', event => { if (peek && !sidebar.contains(event.target)) closePeek(); });
        sidebar.addEventListener('click', event => { if (peek && event.target?.closest?.('.nav-button, .sidebar-action, .sidebar-search')) closePeek(); });
        narrow.addEventListener('change', sync);
        sync();
        return { sync, flip };
      })();

      // Command palette (Cmd/Ctrl + K). Every result opens through the function
      // its workspace already uses: sidebar entries and actions click their own
      // controls, and evidence goes through the exact-identity link, so
      // Back/Forward, refusals and focus match any other link. Items keep only
      // identifiers, never captured payloads.
      const commandPalette = (() => {
        const control = selector => () => document.querySelector(selector)?.click();
        const workspaces = {id: 'workspaces', group: 'Workspaces', empty: true, search: () =>
          [...document.querySelectorAll('.primary-nav .nav-button[data-screen]')].map((button, index) => ({
            title: button.getAttribute('aria-label'), detail: `Workspace · ⌘ / Ctrl + ${index + 1}`,
            run() { button.click(); button.focus({preventScroll: true}); }
          }))};
        const actions = {id: 'actions', group: 'Actions', empty: true, search: () => {
          const consoleOpen = document.querySelector('#native-console-toggle').getAttribute('aria-pressed') === 'true';
          const theme = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
          return [
            {title: consoleOpen ? 'Close Console' : 'Open Console', detail: 'Action · ⌘ / Ctrl + J', run: control('#native-console-toggle')},
            {title: 'Open investigation notebook', detail: 'Action · Notebook', run: control('#open-investigation-notebook')},
            {title: `Switch to ${theme} theme`, detail: 'Action · Appearance', run: control('#theme-toggle')},
            {title: document.querySelector('#sidebar-toggle').getAttribute('aria-label'), detail: 'Action · ⌘ / Ctrl + B', run: control('#sidebar-toggle')}
          ];
        }};
        // Request rows without an exact native identity (demo and legacy rows)
        // open the way a row click does, after the same uniqueness check, and
        // leave the same Back stop and row focus as the exact link.
        function openPaletteRequest(id, identity) {
          if (identity) return openInvestigation({kind: 'request', identity});
          if (state.requests.filter(request => request.id === id).length !== 1) {
            investigationNotice('This request is no longer retained, or its row identifier is ambiguous. Nothing was selected.', 'stale'); return false;
          }
          if (investigationScreen() === 'traffic') investigationNavigation?.record();
          showScreen('traffic');
          if (!document.querySelector('#console-experiment-traffic').hidden) document.querySelector('#console-traffic-back').click();
          selectRequest(id);
          const revision = investigationRevision;
          requestAnimationFrame(() => {
            if (revision !== investigationRevision || investigationScreen() !== 'traffic' || state.selectedRequestId !== id) return;
            ([...elements.requestRows.querySelectorAll('.request-row')].find(row => row.dataset.requestId === id) ?? elements.requestFilter).focus({preventScroll: true});
          });
          return true;
        }
        let requestItems = {requests: null, items: []};
        const requests = {id: 'requests', group: 'Requests', search: () => {
          if (requestItems.requests !== state.requests) requestItems = {requests: state.requests, items: state.requests.map(request => {
            const id = request.id, identity = investigationRequestIdentity(request);
            // The host and full captured path, without the scheme.
            return {title: `${request.method} ${String(request.path ?? '').trim().replace(/^[a-z][a-z0-9+.-]*:\/\//i, '')}${request.urlTruncated ? '…' : ''}`,
              detail: [request.status, trafficTypeLabel(request.type), request.hostOnly ? 'host only' : '',
                identity ? `request ${identity.request} · session ${identity.session} · process ${identity.process} · sequence ${identity.sequence}` : 'no exact retained identity'].filter(Boolean).join(' · '),
              run: () => openPaletteRequest(id, identity)};
          })};
          return requestItems.items;
        }};
        const files = {id: 'files', group: 'Files', search: () => capturedSources().map(source => {
          const id = source.artifact_id, identity = investigationArtifactIdentity(source);
          return {title: sourceDisplayName(source),
            detail: [source.url || '(anonymous)', sourceKindLabel(source.kind)?.[1] ?? source.kind, formatByteSize(source.byte_size), `artifact ${id}`].join(' · '),
            run() { if (identity) openInvestigation({kind: 'artifact', identity}); else { showScreen('sources'); selectArtifact(id); } }};
        })};
        function openPaletteFinding(id) {
          const row = () => [...elements.vmList.querySelectorAll('.vm-row')].find(candidate => candidate.dataset.findingId === id);
          showScreen('vm');
          document.querySelector('#vm-show-findings')?.click();
          if (!row()) { investigationNotice('This VM finding is no longer listed. Nothing was selected.', 'stale'); return false; }
          row().click();
          // Linked navigation focuses the workspace's Back control on the next
          // frame; keep focus on the chosen finding instead.
          const revision = investigationRevision;
          requestAnimationFrame(() => { if (revision === investigationRevision && investigationScreen() === 'vm') row()?.focus({preventScroll: true}); });
          return true;
        }
        const findings = {id: 'vm-findings', group: 'VM findings', search: () => state.vmFindings.map(finding => {
          const id = finding.findingId;
          return {title: finding.analysis ? 'VM patterns in source' : finding.label,
            detail: `${finding.analysis ? 'Code analysis' : finding.kind} · finding ${id} · investigation ${finding.investigationId} · ${finding.hostRuntime} · ${finding.confidence}`,
            run: () => openPaletteFinding(id)};
        })};
        // One entry that runs Search all files only when chosen; typing in
        // the palette never reads artifact bytes.
        const sourceText = {id: 'source-text', group: 'Search in sources', search: query => {
          const count = capturedSources().filter(source => !sourceHexArtifact(source)).length;
          return count ? [{title: `Search all sources for “${query}”`, detail: `Literal text in ${count} retained text ${count === 1 ? 'file' : 'files'} · Sources`,
            run: () => openSourceSearch(query)}] : [];
        }};
        return RebCommandPalette.mount({trigger: document.querySelector('#command-palette-open'),
          providers: [workspaces, actions, requests, files, findings, sourceText]});
      })();
      // Researcher names (evidence_names.js). Each kind reuses the exact
      // identity the investigation navigation uses; a name is only ever shown
      // beside the raw evidence and never changes or hides it.
      const vmNameArtifact = workspace => {
        const candidates = state.artifacts.filter(artifact => artifact.artifact_id === workspace?.interpreter_artifact_id);
        return candidates.length === 1 ? candidates[0] : null;
      };
      const evidenceNames = RebEvidenceNames.mount({
        validateLibrary: isLocalAnalystWorkspace,
        kinds: {
          request: {records: () => state.requests, unique: request => request.id,
            identity: request => RebEvidenceNames.requestIdentity(request, requestRootEvent(request))},
          artifact: {records: () => state.artifacts, unique: artifact => artifact.artifact_id,
            identity: artifact => artifact.kind === 'canvas_data_url' ? null : RebEvidenceNames.artifactIdentity(artifact)},
          handler: {records: workspace => vmOpcodeRows(workspace), version: () => [state.artifacts],
            identity: (row, workspace) => RebEvidenceNames.handlerIdentity({workspace, artifact: vmNameArtifact(workspace), row})}
        },
        onChange: renderEvidenceNames,
        catalog: evidenceNameCatalog
      });
      const sameName = (left, right) => Boolean(left && right) && RebEvidenceNames.keyOf(left) === RebEvidenceNames.keyOf(right);
      // Return focus to the control that started the rename while it remains in
      // the document, otherwise to the surface's Rename button.
      const nameRestore = (invoker, fallback) => () => (invoker?.isConnected && invoker !== document.body && !invoker.disabled ? invoker : null) ?? document.querySelector(fallback);

      function renderEvidenceNames() {
        renderRequests();
        updateSelectionSummary(state.requests.find(request => request.id === state.selectedRequestId) ?? null);
        renderSourceTree(false);
        renderSourceTabs();
        refreshVmHandlerNames();
      }

      // Names change without a new VM workspace. Patch the listing, Symbol Tree
      // and Selected handler in place so filters, scroll and focus survive.
      function refreshVmHandlerNames() {
        const selected = state.vmFindings.find(finding => finding.findingId === state.selectedVmFindingId);
        const workspace = selected && vmOpcodeWorkspaceForFinding(state.vmOpcodeWorkspace, selected);
        if (!workspace) return;
        const rows = new Map(vmOpcodeRows(workspace).map(row => [row.key, row]));
        const nameOf = row => row ? evidenceNames.nameFor('handler', row, workspace) : null;
        for (const node of elements.vmDetail.querySelectorAll('.vm-handler-row')) {
          const slot = node.querySelector('.vm-handler-label > .researcher-name'), name = nameOf(rows.get(node.dataset.handlerKey));
          if (slot) {slot.textContent = name ?? ''; slot.hidden = !name;}
        }
        for (const button of document.querySelectorAll('#vm-symbol-list [data-vm-symbol-key]')) {
          const row = rows.get(button.dataset.vmSymbolKey), name = nameOf(row);
          if (!row) continue;
          button.replaceChildren(...(name ? [textElement('span', 'researcher-name', name), document.createTextNode(' ')] : []), textElement('span', 'vm-symbol-raw', row.label));
          button.title = `${name ? `${name} (researcher name) · ` : ''}${row.label} · opcode ${row.opcode} · source ${row.source}`;
        }
        const filter = elements.vmDetail.querySelector('input[aria-label="Filter retained handlers"]');
        if (filter?.value) filter.dispatchEvent(new Event('input'));
        elements.vmDetail.querySelector('.vm-selection-inspector')?.dispatchEvent(new CustomEvent('evidence-names-changed'));
      }

      function renameSelectedRequest() {
        const request = state.requests.find(item => item.id === state.selectedRequestId);
        const identity = evidenceNames.identityFor('request', request);
        if (!identity || !state.trafficDetailOpen) return false;
        return evidenceNames.begin({identity, label: `${request.method} ${request.path}`, host: document.querySelector('#request-name-host'),
          restore: nameRestore(document.activeElement, '#request-rename'),
          isCurrent: () => sameName(identity, evidenceNames.identityFor('request', state.requests.find(item => item.id === state.selectedRequestId)))});
      }
      function renameSelectedSource() {
        const source = selectedSource();
        const identity = evidenceNames.identityFor('artifact', source);
        if (!identity) return false;
        return evidenceNames.begin({identity, label: sourceDisplayName(source), host: document.querySelector('#source-name-host'),
          // Tabs are redrawn after a save; return to the selected tab then.
          restore: nameRestore(document.activeElement, document.activeElement?.closest?.('.source-editor-tab') ? '#source-editor-tabs [aria-selected="true"]' : '#source-rename'),
          isCurrent: () => sameName(identity, evidenceNames.identityFor('artifact', selectedSource()))});
      }
      function renameSelectedVmHandler() {
        const selected = state.vmFindings.find(finding => finding.findingId === state.selectedVmFindingId);
        const workspace = selected && vmOpcodeWorkspaceForFinding(state.vmOpcodeWorkspace, selected);
        const row = workspace && vmOpcodeRows(workspace).find(item => item.key === state.selectedVmHandlerKey);
        const identity = row ? evidenceNames.identityFor('handler', row, workspace) : null;
        const host = elements.vmDetail.querySelector('#vm-handler-name-host');
        if (!identity || !host) return false;
        return evidenceNames.begin({identity, label: `${row.label}, opcode ${row.opcode}, source ${row.source}`, host,
          restore: nameRestore(document.activeElement, '#vm-handler-rename'),
          isCurrent: () => host.isConnected && sameName(identity, evidenceNames.identityFor('handler', row, workspace))});
      }
      document.querySelector('#request-rename').addEventListener('click', renameSelectedRequest);
      document.querySelector('#source-rename').addEventListener('click', renameSelectedSource);
      elements.vmDetail.addEventListener('click', event => {if (event.target?.closest?.('#vm-handler-rename')) renameSelectedVmHandler();});
      // F2 renames the focused or selected evidence item, as in a disassembler.
      // Text fields and modal dialogs keep the key.
      document.addEventListener('keydown', event => {
        if (event.key !== 'F2' || event.altKey || event.ctrlKey || event.metaKey || event.shiftKey || event.repeat || event.defaultPrevented) return;
        if (event.target?.closest?.('input, textarea, select, [contenteditable="true"]') || document.querySelector('dialog:modal')) return;
        const screen = investigationScreen(), target = event.target;
        let started = false;
        if (screen === 'traffic') {
          const row = target?.closest?.('.request-row');
          if (row && (row.dataset.requestId !== state.selectedRequestId || !state.trafficDetailOpen)) row.click();
          started = renameSelectedRequest();
        } else if (screen === 'sources') {
          // A focused folder row has nothing to rename; it never falls back to the open file.
          const item = target?.closest?.('.source-tree-row[data-artifact-id], .source-editor-tab');
          if (!item && target?.closest?.('.source-tree-row')) return;
          if (item && item.getAttribute('aria-selected') !== 'true') item.click();
          started = renameSelectedSource();
        } else if (screen === 'vm') {
          const row = target?.closest?.('.vm-handler-row, [data-vm-symbol-key]');
          const key = row?.dataset.handlerKey ?? row?.dataset.vmSymbolKey;
          if (row && key !== state.selectedVmHandlerKey) row.click();
          started = renameSelectedVmHandler();
        }
        if (started) event.preventDefault();
      });

      // Palette entries open the exact retained item through the same selection
      // paths as the UI. Items whose identity is missing or shared are omitted.
      function evidenceNameCatalog() {
        const items = [], seen = new Set();
        const add = (kind, identity, detail, open) => {
          const key = RebEvidenceNames.keyOf(identity);
          if (key && !seen.has(key) && evidenceNames.nameOf(identity)) {seen.add(key); items.push({kind, identity, detail, open});}
        };
        if (evidenceNames.has('captured-request')) for (const request of state.requests) {
          add('Request', evidenceNames.identityFor('request', request), `${request.method} ${request.path}`, () => openNamedRequest(evidenceNames.identityFor('request', request)));
        }
        if (evidenceNames.has('captured-artifact')) for (const source of capturedSources()) {
          add('Source', evidenceNames.identityFor('artifact', source), `${sourceDisplayName(source)} · artifact ${source.artifact_id}`, () => openNamedSource(evidenceNames.identityFor('artifact', source)));
        }
        if (evidenceNames.has('vm-handler')) for (const finding of state.vmFindings) {
          const workspace = vmOpcodeWorkspaceForFinding(state.vmOpcodeWorkspace, finding);
          if (!workspace) continue;
          for (const row of vmOpcodeRows(workspace)) {
            const identity = evidenceNames.identityFor('handler', row, workspace);
            add('VM handler', identity, `${row.label} · opcode ${row.opcode} · source ${row.source} · artifact ${workspace.interpreter_artifact_id}`,
              () => openNamedVmHandler(finding.findingId, identity));
          }
        }
        return items;
      }
      const namedRelation = 'Opened by its researcher name. The name is your interpretation; the evidence is the exact retained record.';
      function openNamedRequest(identity) {
        const matches = state.requests.filter(request => sameName(identity, evidenceNames.identityFor('request', request)));
        if (matches.length !== 1) {investigationNotice('This named request is no longer retained, or its identity is shared. Nothing was substituted.', 'stale'); return false;}
        const navigation = investigationRequestIdentity(matches[0]);
        if (navigation) return openInvestigation({kind: 'request', identity: navigation, relation: namedRelation});
        // Demo rows have no navigation identity; open them as a row click does.
        showScreen('traffic'); selectRequest(matches[0].id); focusRequestRow(matches[0].id);
        return true;
      }
      function openNamedSource(identity) {
        if (!identity) {investigationNotice('This named source is no longer retained, or its artifact ID is shared. Nothing was substituted.', 'stale'); return false;}
        return openInvestigation({kind: 'artifact', identity: {type: 'captured-artifact', session: identity.session, artifact: identity.artifact,
          sha256: identity.sha256, bytes: identity.bytes}, relation: namedRelation});
      }
      function openNamedVmHandler(findingId, identity) {
        const finding = state.vmFindings.find(item => item.findingId === findingId);
        const workspace = finding && vmOpcodeWorkspaceForFinding(state.vmOpcodeWorkspace, finding);
        const row = workspace && vmOpcodeRows(workspace).find(item => sameName(identity, evidenceNames.identityFor('handler', item, workspace)));
        if (!row) {investigationNotice('This named handler is no longer retained in its exact program. Nothing was substituted.', 'stale'); return false;}
        showScreen('vm');
        if (state.selectedVmFindingId !== findingId) {state.selectedVmFindingId = findingId; renderVmLab();}
        // The Symbol Tree entry is the UI's own path: it clears an excluding
        // filter, selects the row and reveals it. Retiring the screen's pending
        // default focus keeps focus on the handler that was asked for.
        const symbol = [...document.querySelectorAll('#vm-symbol-list [data-vm-symbol-key]')].find(button => button.dataset.vmSymbolKey === row.key);
        if (!symbol) return false;
        investigationBeforeSelection();
        symbol.click();
        return true;
      }

      state.trafficIndex = location.protocol === 'file:' || typeof createTrafficIndex !== 'function' ? null
        : createTrafficIndex({onChange: () => { renderRequests(); renderNetworkNotice(); }});
      if (typeof mountTrafficColumns === 'function') mountTrafficColumns(document.querySelector('#screen-traffic .request-table'));
      state.trafficOverview = typeof mountTrafficOverview === 'function'
        ? mountTrafficOverview(document.querySelector('#request-overview'), {onRange: range => {
          state.trafficRange = range;
          renderRequests();
        }}) : null;
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
        evidenceNames.load();

        setInterval(refresh, 2000);
      }

      initializeInvestigationNavigation();
      const investigationNotebook = RebInvestigationNotebook.mount({
        button: document.querySelector('#open-investigation-notebook'),
        validateLibrary: isLocalAnalystWorkspace,
        // The notebook and Analyst hold separate copies of one library. After
        // a notebook write commits, Analyst reloads its copy, so its next save
        // does not meet a generation conflict that this app caused itself.
        // The notebook reloads on every open, and it is modal, so the reverse
        // direction needs nothing here.
        fetcher: async (path, options) => {
          const response = await fetch(path, options);
          if (path === '/api/local-analyst/actions' && response.ok) queueMicrotask(() => refreshLocalAnalyst());
          return response;
        },
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
