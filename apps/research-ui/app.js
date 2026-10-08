      const evidencePackagePanel = createEvidencePackagePanel({getContext: () => ({
        requestId: evidenceRequestKey(state.requests.find(request => request.id === state.selectedRequestId)),
        requestEvents: state.requests.find(request => request.id === state.selectedRequestId)?.events ?? [],
        requestCorrelated: evidenceDebuggerRequest(state.requests.find(request => request.id === state.selectedRequestId)),
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

      const sourceFactsPanel = createSourceFactsPanel({
        getSource: selectedSource,
        onNavigate: revealSourceFactRange,
        openSidebar() {
          if (state.sourceHooksOpen) closeSourceHooks(false);
          state.sourceSidebarOpen = true;
          renderSourceSidebar();
        }
      });

      async function refreshVmAnalysis(requestId = state.vmAnalysisRequestId) {
        if (location.protocol === 'file:') return;
        const normalizedRequestId = requestId || null;
        const query = normalizedRequestId ? `?request_id=${encodeURIComponent(normalizedRequestId)}` : '';
        const sameSelection = normalizedRequestId === state.vmAnalysisRequestId;
        const headers = sameSelection && state.vmAnalysisEtag ? { 'If-None-Match': state.vmAnalysisEtag } : {};
        state.vmAnalysisStatus = 'loading';
        try {
          const response = await fetch(`/api/analysis/vm${query}`, { cache: 'no-store', headers });
          if (response.status === 304) { state.vmAnalysisStatus = 'ready'; return; }
          if (!response.ok) throw new Error(`Analyzer returned ${response.status}`);
          const document = await response.json();
          if (!isVmAnalysisDocument(document)) throw new TypeError('Malformed VM analysis response');
          state.vmAnalysisEtag = response.headers.get('ETag');
          state.vmAnalysisRequestId = normalizedRequestId;
          state.vmAnalysisStatus = 'ready';
          state.vmAnalysisError = null;
          state.lastValidAnalysisFindings = vmFindingsFromAnalysis(document);
          state.vmFindings = [...state.lastValidAnalysisFindings, ...state.eventVmFindings];
        } catch (error) {
          retainVmAnalysisOnFailure(
            state,
            error instanceof TypeError ? 'malformed' : 'unavailable',
            error.message
          );
        }
        renderVmLab();
      }

      function setNetworkNotice(kind, message) {
        if (elements.networkNotice.dataset.kind !== kind) elements.networkNotice.dataset.kind = kind;
        if (elements.networkNotice.textContent !== message) elements.networkNotice.textContent = message;
        elements.networkNotice.hidden = false;
      }

      function networkContentCaptureEnabled() {
        return state.sessionMode === 'live' && state.debuggerSession?.network?.capture_enabled === true;
      }

      function networkContentCaptureActive() {
        return networkContentCaptureEnabled() && !state.debuggerRefreshFailed &&
          ['running', 'paused'].includes(state.debuggerSession?.state);
      }

      // Both refresh paths project the same status so neither can erase the other's gaps.
      function renderNetworkNotice() {
        const contentCapture = networkContentCaptureEnabled();
        const active = networkContentCaptureActive();
        const gapCount = countSequenceGaps(state.events);
        const reportedDrops = countReportedQueueDrops(state.events);
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
        if (gapCount > 0n) {
          if (kind === 'empty') kind = 'gap';
          messages.push(`${gapCount} captured event ${gapCount === 1n ? 'ID is' : 'IDs are'} missing. Native evidence may be incomplete.`);
        }
        if (reportedDrops > 0n) {
          if (kind === 'empty') kind = 'gap';
          messages.push(`The queue reports ${reportedDrops} dropped ${reportedDrops === 1n ? 'event' : 'events'}${gapCount > 0n ? '; counts may overlap sequence gaps' : '; no sequence jump is visible in this window'}.`);
        }
        if (contentCapture) {
          if (active) {
            if (kind === 'empty') kind = 'active';
            messages.push('Recording live requests and responses · sensitive headers redacted · 128 KiB body limit');
          } else {
            if (kind !== 'malformed') kind = 'disconnected';
            messages.push(state.debuggerRefreshFailed ? 'The live debugger is disconnected.'
              : state.debuggerSession?.state === 'crashed' ? 'The captured browser target crashed.'
                : 'Network capture is waiting for an attached browser target.');
            messages.push(state.requests.length ? 'The last recorded requests remain visible.' : 'No captured network requests are available.');
          }
          const dropped = state.debuggerSession.network.dropped;
          if (dropped) {
            if (kind === 'active') kind = 'gap';
            messages.push(`${dropped} older requests evicted from the 1,000-request window.`);
          }
        } else if (kind === 'malformed' || kind === 'disconnected') {
          messages.push(state.events.length ? 'The last valid evidence remains visible.' : 'No live broker evidence is available.');
        } else if (!messages.length) {
          if (state.sessionMode === 'live' && !state.events.length) messages.push('No live requests yet. Start a capture in the attached browser.');
          else if (state.sessionMode === 'demo') messages.push('Developer evidence loaded. It does not represent a live capture.');
          else if (state.sessionMode === 'idle') messages.push('No evidence is bundled. Start a live capture to populate the workspace.');
        }
        if (messages.length) setNetworkNotice(kind, messages.join(' '));
        else elements.networkNotice.hidden = true;
      }

      function textElement(tag, className, value) {
        const element = document.createElement(tag);
        if (className) element.className = className;
        element.textContent = String(value);
        return element;
      }

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
          delete owner.mounted; delete owner.image;
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

      function renderLiveBrowserTabCount() {
        const count = state.debuggerSession?.live_tab_count;
        const available = state.sessionMode === 'live' && !state.debuggerRefreshFailed &&
          Number.isInteger(count) && count >= 0;
        elements.signalLiveTabs.textContent = available
          ? `${count} open ${count === 1 ? 'tab' : 'tabs'}`
          : state.sessionMode === 'live' ? 'Live tab count unavailable' : 'No live browser';
        elements.signalLiveTabs.dataset.live = String(available);
        elements.signalLiveTabs.title = available
          ? 'Current browser page tabs. Captured tab buttons retain historical evidence.'
          : 'The live browser tab list is unavailable; captured tab buttons show historical evidence.';
      }

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

        const newCount = signalEvents.filter(event => state.signalNewKeys.has(signalEventKey(event))).length;
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

        const gapCount = countSequenceGaps(state.events);
        const reportedDrops = countReportedQueueDrops(state.events);
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
        } else if (state.eventsLimited || displayLimited || gapCount > 0n || reportedDrops > 0n) {
          const limits = [];
          if (state.eventsLimited) limits.push('the event window is capped');
          if (displayLimited) {
            limits.push(`only the newest ${signalEventDisplayLimit} matching events are rendered`);
          }
          if (gapCount > 0n) {
            limits.push(`${gapCount} capture-wide event ${gapCount === 1n ? 'ID is' : 'IDs are'} missing`);
          }
          if (reportedDrops > 0n) {
            limits.push(`${reportedDrops} queue ${reportedDrops === 1n ? 'drop was' : 'drops were'} reported (may overlap missing IDs)`);
          }
          setSignalNotice(
            'partial',
            `Fingerprint activity is visible with partial coverage: ${limits.join('; ')}.`
          );
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
        const cdpRequests = requestsFromDebuggerNetwork(
          state.debuggerSession?.network, state.nativeRequests, state.debuggerNetworkBodyCache
        );
        if (state.sessionMode === 'live') {
          state.requests = state.debuggerSession?.network?.capture_enabled
            ? cdpRequests : state.nativeRequests;
        } else {
          state.requests = state.nativeRequests;
        }
        syncTrafficComparison();
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
        const contentCapture = networkContentCaptureEnabled();
        const networkActive = networkContentCaptureActive();
        const modeLabel = live ? (contentCapture ? 'Live content' : offline ? 'Live offline'
          : artifactOffline ? 'Live degraded' : 'Live session')
          : idle ? 'Ready' : preview ? 'Preview' : 'Demo evidence';
        const captureLabel = networkActive && (offline || connecting) ? 'Network only'
          : connecting ? 'Connecting' : offline ? 'Offline' : artifactOffline ? 'Artifacts offline'
          : live ? 'Capturing' : idle ? 'No session' : preview ? 'Preview' : 'Demo';
        elements.sessionMode.textContent = modeLabel;
        elements.sessionMode.dataset.kind = state.sessionMode;
        elements.sessionMode.title = live
          ? contentCapture
            ? 'CDP request and response content capture is enabled for this session. Sensitive headers are redacted and bodies are bounded.'
            : 'Only live broker evidence is shown; sample rows are hidden.'
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
          ? networkActive && (offline || connecting) ? 'network capture only'
            : offline
            ? state.requests.length ? 'last requests retained' : state.events.length ? 'last live evidence retained' : 'no live evidence'
            : artifactOffline ? 'artifact capture offline'
            : 'sample rows hidden'
          : idle || preview ? 'no bundled evidence' : 'developer evidence';
        if (networkActive && (offline || connecting)) {
          elements.updated.textContent = 'network capture active';
        } else if (contentCapture && offline && state.requests.length) {
          elements.updated.textContent = 'last recorded requests retained';
        } else if (!state.lastUpdatedLabel) {
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

      function renderVmDetail() {
        const selected = state.vmFindings.find(finding => finding.findingId === state.selectedVmFindingId);
        if (!selected) {
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
          const sourceArtifact = state.artifacts.find(artifact => artifact.artifact_id === selected.sourceArtifactId);
          if (sourceArtifact) {
            const openSource = textElement('button', 'secondary-button', 'Open in Sources'); openSource.type = 'button';
            openSource.addEventListener('click', () => { showScreen('sources', openSource); selectArtifact(sourceArtifact.artifact_id); });
            actions.append(openSource);
          }
          head.append(title, actions);
          const fields = document.createElement('div'); fields.className = 'vm-fields';
          fields.append(
            vmField('tier', selected.confidence),
            vmField('source artifact', selected.sourceArtifactId),
            vmField('related requests', result.related_request_ids?.join(', ') || 'none observed'),
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
          card.append(head, fields, evidence);
          elements.vmDetail.replaceChildren(summary, card);
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
        const sourceArtifact = state.artifacts.find(artifact => artifact.artifact_id === selected.sourceArtifactId);
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
        card.append(head, fields);
        if (coverage) {
          const coveragePanel = document.createElement('div'); coveragePanel.className = 'vm-coverage';
          const line = document.createElement('div'); line.className = 'vm-coverage-line';
          line.append(textElement('span', '', coverage.label), textElement('strong', '', `${coverage.observedCount} / ${coverage.totalCount}`));
          const bar = document.createElement('div'); bar.className = 'vm-coverage-bar';
          const fill = document.createElement('span'); fill.style.width = `${coveragePercent}%`; bar.append(fill);
          coveragePanel.append(line, bar); card.append(coveragePanel);
        }
        elements.vmDetail.replaceChildren(summary, card);
      }

      function renderVmLab() {
        const focusedFindingId = document.activeElement?.classList.contains('vm-row')
          ? document.activeElement.dataset.findingId
          : null;
        elements.vmCount.textContent = String(state.vmFindings.length);
        if (!state.vmFindings.some(finding => finding.findingId === state.selectedVmFindingId)) {
          state.selectedVmFindingId = state.vmFindings[0]?.findingId ?? null;
        }
        const gapCount = countSequenceGaps(state.events);
        if (state.broker === 'connecting') {
          setVmNotice('loading', 'Waiting for VM findings from the local evidence broker.');
        } else if (state.vmAnalysisStatus === 'malformed') {
          setVmNotice('malformed', 'Malformed VM analysis was rejected. Valid timeline summaries remain visible.');
        } else if (state.vmAnalysisStatus === 'unavailable') {
          setVmNotice('disconnected', `The cold analyzer is unavailable. ${state.vmFindings.length ? 'Last valid VM evidence remains visible.' : 'No VM evidence is available.'}`);
        } else if (state.broker === 'unavailable') {
          setVmNotice('disconnected', state.vmFindings.length ? 'Broker disconnected. Last valid VM findings remain visible.' : 'Broker disconnected. No VM findings are available.');
        } else if (state.malformedVmFindings > 0) {
          setVmNotice('malformed', `${state.malformedVmFindings} malformed VM ${state.malformedVmFindings === 1 ? 'finding was' : 'findings were'} rejected.`);
        } else if (state.vmFindings.length === 0) {
          setVmNotice('empty', 'No VM findings yet. The lab waits for observed or explicitly inferred evidence.');
        } else if (gapCount > 0n) {
          setVmNotice('gap', `${gapCount} event ${gapCount === 1n ? 'gap may' : 'gaps may'} make VM coverage incomplete.`);
        } else {
          elements.vmNotice.hidden = true;
        }
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
          return {
            id: group.id,
            label: group.id === 'unattributed' ? 'Unattributed' : `Tab ${index + 1}`,
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

      function renderRequests() {
        renderRequestScopes();
        const needle = elements.requestFilter.value.trim().toLowerCase();
        const includeContent = elements.requestSearchScope.value === 'content';
        const scoped = state.requests.filter(request =>
          (state.requestTabId === 'all' ||
            (request.tabId && request.tabId !== '0' ? request.tabId : 'unattributed') === state.requestTabId) &&
          (state.requestDomain === 'all' || requestDomain(request) === state.requestDomain) &&
          (state.requestType === 'all' || request.type === state.requestType)
        );
        const search = trafficSearchRequests(scoped, needle, includeContent);
        state.trafficSearchMatches = search.matches;
        const visible = trafficSortedRequests(scoped.filter(request => search.matches.has(request.id)), state.trafficSort, state.trafficSortDirection);
        const filterKey = JSON.stringify([state.requestTabId, state.requestDomain, state.requestType, needle, includeContent, state.trafficSort, state.trafficSortDirection]);
        const filterChanged = filterKey !== state.trafficFilterKey;
        if (filterChanged) { state.trafficNewIds.clear(); state.trafficWindowStart = 0; state.trafficWindowAnchor = null; }
        state.trafficFilterKey = filterKey;
        elements.requestSearchStatus.hidden = !includeContent;
        elements.requestSearchStatus.dataset.kind = search.omitted ? 'partial' : '';
        const searchMessage = !needle ? 'Search retained headers and text bodies. Content capture is unchanged.'
          : `${visible.length} matching ${visible.length === 1 ? 'request' : 'requests'} · ` +
            (search.omitted ? `Partial content search: ${search.inspected} of ${scoped.length} requests inspected, newest first. Narrow tab, domain, or type to search the rest. ` : '') +
            'Retained text only; truncated prefixes, redacted headers, and uncaptured or binary bodies limit coverage.';
        if (elements.requestSearchStatus.textContent !== searchMessage) elements.requestSearchStatus.textContent = searchMessage;
        const selectedIsVisible = visible.some(request => request.id === state.selectedRequestId);
        const selectionCleared = state.selectedRequestId !== null && !state.requests.some(request => request.id === state.selectedRequestId);
        if (selectionCleared) resetRequestSelection();
        const knownIds = state.trafficKnownIds;
        const newIds = new Set(knownIds ? visible.filter(request => !knownIds.has(request.id)).map(request => request.id) : []);
        state.trafficKnownIds = new Set(state.requests.map(request => request.id));
        if (!filterChanged) newIds.forEach(id => state.trafficNewIds.add(id));
        for (const id of state.trafficNewIds) if (!state.trafficKnownIds.has(id)) state.trafficNewIds.delete(id);
        const window = trafficWindow(visible, state.trafficWindowStart, state.trafficWindowAnchor);
        state.trafficWindowStart = window.start;
        state.trafficWindowAnchor = window.rows[0]?.id ?? null;
        const selectedFiltered = state.selectedRequestId !== null && !selectedIsVisible;
        document.querySelector('#request-window-status').textContent = `${visible.length ? window.start + 1 : 0}–${window.start + window.rows.length} of ${visible.length} matching · ${state.requests.length} retained${selectedFiltered ? ' · Selection outside filter' : ''}`;
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
            : search.omitted ? 'No matches in inspected content. Narrow the filters to search the omitted requests.'
              : 'No requests match the current filters. Clear the filter or choose another type.';
          const hadFocus = elements.requestRows.contains(document.activeElement);
          elements.requestRows.replaceChildren(empty);
          elements.requestRows.tabIndex = 0;
          if (hadFocus) elements.requestRows.focus({preventScroll: true});
          state.trafficPendingCount = 0;
          elements.requestLatest.hidden = true;
          renderRequestCount(0, state.requests.length);
          if (selectionCleared) {
            updateSelectionSummary(null);
            renderInspector();
            renderEvidence();
          }
          return;
        }
        renderTrafficRows(elements.requestRows, window.rows, {
          selectedId: state.selectedRequestId, newIds,
          matches: includeContent && needle ? search.matches : null,
          onSelect: id => { selectRequest(id); focusRequestRow(id); }, onKey: moveRequestSelection
        });
        state.trafficPendingCount = state.trafficNewIds.size;
        elements.requestLatest.hidden = state.trafficPendingCount === 0;
        elements.requestLatest.textContent = `${state.trafficPendingCount} new ${state.trafficPendingCount === 1 ? 'request' : 'requests'}`;
        renderRequestCount(visible.length, state.requests.length);
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
        const match = elements.requestSearchScope.value === 'content' ? state.trafficSearchMatches?.get(id) : null;
        if (match?.side) state.inspectorTab = match.mode === 'headers' ? 'headers' : match.side === 'Request' ? 'payload' : 'response';
        const request = state.requests.find(candidate => candidate.id === id);
        if (!request) return;
        if (state.selectedRequestId !== id) state.repeaterDraftRevision = (state.repeaterDraftRevision ?? 0) + 1;
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
        renderRequests();
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
        if (request?.origin !== 'live' || request.protocolRequestId || String(request.operation).startsWith('cdp_')) return null;
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
            ? request.protocolRequestId ? 'This debugger request has no exact native-event link. Host, method and timing matches are correlation only.' : 'Structured fields were not captured. Request-level origin evidence is still available.'
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
          elements.requestMemoryPivot.disabled = true;
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
        elements.requestMemoryPivot.disabled = !selected;
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
        document.querySelector('#request-package-entry').hidden = state.inspectorTab !== 'evidence';
        document.querySelectorAll('.inspector-tab').forEach(tab => {
          const selected = tab.dataset.inspectorTab === state.inspectorTab;
          tab.setAttribute('aria-selected', String(selected));
          tab.tabIndex = selected ? 0 : -1;
        });
        const exchangeInspector = document.querySelector('#exchange-inspector');
        const showingExchange = ['headers', 'payload', 'preview', 'response'].includes(state.inspectorTab) || state.selectedRequestId === null;
        const request = state.requests.find(candidate => candidate.id === state.selectedRequestId);
        updateSelectionSummary(request);
        document.querySelector('.traffic-grid').dataset.detailOpen = String(state.trafficDetailOpen);
        document.querySelector('.detail-pane').hidden = !state.trafficDetailOpen;
        const showingComparison = state.inspectorTab === 'compare';
        const comparisonPanel = document.querySelector('#traffic-comparison');
        comparisonPanel.hidden = !showingComparison;
        renderTrafficComparison(comparisonPanel, request, showingComparison);
        exchangeInspector.hidden = !showingExchange || showingComparison;
        exchangeInspector.setAttribute('aria-labelledby', `inspector-tab-${state.inspectorTab}`);
        const evidenceToggle = document.querySelector('#request-evidence-toggle');
        evidenceToggle.textContent = state.inspectorTab === 'evidence' ? 'Headers' : 'Evidence';
        evidenceToggle.setAttribute('aria-expanded', String(state.inspectorTab === 'evidence'));
        evidenceToggle.disabled = !request;
        elements.requestCollectionPivot.disabled = !request;
        elements.requestInspector.hidden = showingExchange || showingComparison;
        document.querySelector('.detail-pane').classList.toggle('showing-exchange', showingExchange || showingComparison);
        if (showingComparison) return;
        if (showingExchange) {
          renderTrafficDetails(exchangeInspector, request, state.inspectorTab, (value, selection) => {
            const identity = investigationRequestIdentity(request);
            investigationDecode(value, {route: identity ? {kind: 'request', identity, inspectorTab: state.inspectorTab} : null,
              description: `${selection.side} · ${selection.path} · selected inspector value. UTF-8 string bytes are retained; raw HTTP byte offsets are unavailable.${identity ? '' : ' Exact request identity is unavailable.'}`});
          }, openFieldProvenance, elements.requestSearchScope.value === 'content' && state.trafficSearchMatches?.get(request?.id)?.side
            ? {...state.trafficSearchMatches.get(request.id), query: elements.requestFilter.value.trim()} : null, state.trafficSelectionNotice);
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
          if (isFieldCallSites(request?.initiator) && request.initiator.sites.length) {
            const rows = request.initiator.sites.flatMap((site, index) => [
              {key: `call site ${index + 1}`, value: `${site.function || '(anonymous)'} · ${site.source || '(URL unavailable)'}:${site.line + 1}:${site.column + 1}`, type: 'observed'},
              {key: 'source identity', value: `target ${site.target_id} · script ${site.script_id}${site.source_hash ? ' · hash ' + site.source_hash : ''}`, type: 'id'}
            ]);
            for (const gap of request.initiator.gaps) rows.push({key: 'capture gap', value: gap.replaceAll('_', ' '), type: 'unavailable'});
            renderInspectorDetails(rows);
            return;
          }
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
        document.querySelectorAll('.nav-button[data-screen="experiments"]')
          .forEach(button => {
            button.disabled = false;
            button.title = state.selectedField
              ? 'Open disposable experiments for the selected request field.'
              : 'Experiments use the attached debugger target; selecting a request field is optional.';
          });
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
          ? `${request.method} ${request.path}` : 'Request events and their recorded predecessors';
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

      function requestInterception() {
        return state.debuggerSession?.request_interception ?? null;
      }

      function actionScopeState() {
        return state.debuggerSession?.action_scope ?? null;
      }

      function repeaterState() {
        return state.debuggerSession?.repeater ?? null;
      }

      function objectExperimentState() {
        return state.debuggerSession?.object_experiment ?? null;
      }

      function runtimeHooksState() {
        return state.debuggerSession?.runtime_hooks ?? null;
      }

      function automationRecipesState() {
        return state.debuggerSession?.automation_recipes ?? null;
      }

      function setExperimentMode(mode, focus = false) {
        if (!['interceptor', 'repeater', 'object', 'hooks', 'automation'].includes(mode)) return;
        if (state.sourceHooksOpen) closeSourceHooks(false);
        state.experimentMode = mode;
        elements.interceptionWorkspace.hidden = mode !== 'interceptor';
        elements.repeaterWorkspace.hidden = mode !== 'repeater';
        elements.objectWorkspace.hidden = mode !== 'object';
        elements.hooksWorkspace.hidden = mode !== 'hooks';
        elements.automationWorkspace.hidden = mode !== 'automation';
        elements.experimentModeButtons.forEach(button => {
          const selected = button.dataset.experimentMode === mode;
          button.setAttribute('aria-selected', String(selected));
          button.tabIndex = selected ? 0 : -1;
          if (selected && focus) button.focus();
        });
        renderExperiment();
      }

      function setExperimentNotice(kind, message) {
        elements.experimentNotice.dataset.kind = kind;
        elements.experimentNotice.textContent = message;
      }

      function renderActionScope() {
        const scope = actionScopeState();
        const experiment = requestInterception();
        const sharedMode = ['interceptor', 'automation'].includes(state.experimentMode);
        elements.actionScopePanel.hidden = !sharedMode;
        const busy = state.experimentPending || state.debuggerActionPending ||
          (experiment?.pending_requests ?? 0) > 0 || experiment?.state === 'running' ||
          automationRecipesState()?.auto_armed ||
          ['arming', 'running', 'stopping'].includes(automationRecipesState()?.state);
        const contextExists = Boolean(experiment?.isolated);
        if (scope && state.actionScopeDraftRevision !== scope.revision) {
          state.actionScopeDraftMode = scope.mode;
          state.actionScopeDraftRevision = scope.revision;
        }
        const draftMode = state.actionScopeDraftMode ?? scope?.mode ?? 'global';
        const targets = scope?.targets ?? [];
        const previousTarget = elements.actionScopeTarget.value;
        const selectedTarget = targets.some(target => target.id === previousTarget)
          ? previousTarget
          : scope?.target_id && targets.some(target => target.id === scope.target_id)
            ? scope.target_id : targets[0]?.id ?? '';
        const options = targets.map(target => {
          const option = document.createElement('option'); option.value = target.id;
          option.textContent = `${target.title || 'Untitled page'} · ${target.url || 'about:blank'}`;
          return option;
        });
        if (!options.length) {
          const option = document.createElement('option'); option.value = ''; option.textContent = 'No disposable pages';
          options.push(option);
        }
        elements.actionScopeTarget.replaceChildren(...options);
        elements.actionScopeTarget.value = selectedTarget;
        elements.actionScopeGlobal.setAttribute('aria-pressed', String(draftMode === 'global'));
        elements.actionScopeTargeted.setAttribute('aria-pressed', String(draftMode === 'target'));
        elements.actionScopeGlobal.disabled = !sharedMode || !contextExists || busy;
        elements.actionScopeTargeted.disabled = !sharedMode || !contextExists || busy || targets.length === 0;
        elements.actionScopeTarget.disabled = !sharedMode || !contextExists || busy || draftMode !== 'target' || targets.length === 0;
        const unchanged = scope && draftMode === scope.mode &&
          (draftMode === 'global' || selectedTarget === scope.target_id);
        elements.actionScopeApply.disabled = !sharedMode || !contextExists || busy || !scope || unchanged ||
          (draftMode === 'target' && !selectedTarget);
        elements.actionScopeNewUrl.disabled = !contextExists || busy || targets.length >= (scope?.limits.targets ?? 8);
        elements.actionScopeAdd.disabled = elements.actionScopeNewUrl.disabled;
        if (!sharedMode) {
          elements.actionScopeBadge.dataset.kind = contextExists ? '' : 'offline';
          elements.actionScopeBadge.textContent = 'Target only';
          const labels = {repeater: 'Repeater', object: 'Object Lab', hooks: 'Runtime Hooks'};
          elements.actionScopeMessage.textContent = `${labels[state.experimentMode]} stays on the primary disposable page. Shared scope applies to Interceptor and Automation.`;
        } else {
          elements.actionScopeBadge.dataset.kind = ['error', 'partial'].includes(scope?.state) ? 'error'
            : scope?.state === 'ready' ? '' : 'offline';
          elements.actionScopeBadge.textContent = scope?.state === 'ready'
            ? scope.mode === 'target' ? 'One page' : 'All pages'
            : scope?.state === 'error' ? 'Error' : 'Not set';
          elements.actionScopeMessage.textContent = scope?.message ?? 'Create an isolated context to choose action scope.';
        }
        elements.actionScopeTargets.replaceChildren(...(targets.length ? targets.map(target => {
          const row = document.createElement('div'); row.className = 'action-scope-target';
          row.dataset.matched = String(target.matched);
          const title = textElement('strong', '', target.title || 'Untitled page');
          const meta = textElement('small', '', `${target.connected ? 'connected' : 'disconnected'} · ${target.url || 'about:blank'}`);
          row.append(title, meta);
          if (target.id !== experiment?.target_id) {
            const close = document.createElement('button'); close.type = 'button'; close.textContent = '×';
            close.title = `Close ${target.title || 'disposable page'}`;
            close.setAttribute('aria-label', close.title);
            close.disabled = busy;
            close.addEventListener('click', () => runExperimentAction({action: 'close_experiment_page', target_id: target.id}));
            row.append(close);
          }
          return row;
        }) : [textElement('span', 'experiment-empty', 'No disposable pages.') ]));
      }

      function parseExperimentHeaders(value, label) {
        const source = value.trim();
        if (!source) return {};
        let headers;
        try { headers = JSON.parse(source); }
        catch { throw new TypeError(`${label} must be a JSON object.`); }
        if (!isPlainObject(headers) || Object.values(headers).some(item => typeof item !== 'string')) {
          throw new TypeError(`${label} must map header names to text values.`);
        }
        return headers;
      }

      function setExperimentRuleVisibility() {
        const mode = elements.experimentRuleMode.value;
        elements.experimentRewriteOptions.hidden = mode !== 'rewrite';
        elements.experimentFulfillOptions.hidden = mode !== 'fulfill';
      }

      function prefillExperimentRequest() {
        const request = state.requests.find(candidate => candidate.id === state.selectedRequestId);
        if (!request) return;
        const key = `${request.id}:${request.method}:${request.path}`;
        if (state.experimentPrefillKey === key) return;
        state.experimentPrefillKey = key;
        let requestUrl = request.path;
        if (!/^https?:\/\//i.test(requestUrl)) {
          requestUrl = `https://checkout.acme.test${requestUrl.startsWith('/') ? '' : '/'}${requestUrl}`;
        }
        try {
          const parsed = new URL(requestUrl);
          parsed.search = '';
          parsed.hash = '';
          elements.experimentRequestUrl.value = parsed.toString();
          elements.experimentUrlPattern.value = `${parsed.origin}${parsed.pathname}*`;
        } catch {
          elements.experimentRequestUrl.value = '';
          elements.experimentUrlPattern.value = '*';
        }
        elements.experimentRequestMethod.value = /^[A-Z][A-Z0-9!#$%&'*+.^_`|~-]{0,31}$/.test(request.method)
          ? request.method : 'GET';
        elements.experimentRequestBody.value = '';
      }

      function experimentFact(label, value) {
        const fact = document.createElement('div');
        const name = document.createElement('span'); name.textContent = label;
        const detail = document.createElement('strong'); detail.textContent = value;
        fact.append(name, detail);
        return fact;
      }

      function renderExperimentResult(experiment) {
        const result = experiment?.result;
        if (!result) {
          elements.experimentResult.className = 'experiment-empty';
          elements.experimentResult.textContent = experiment?.state === 'disposed'
            ? 'No response was retained before the disposable context was deleted.'
            : 'Create a context, arm a rule, then run a request.';
          elements.experimentResultMeta.textContent = experiment?.last_request
            ? `${experiment.last_request.method} ${experiment.last_request.url}`
            : 'No experiment request has run.';
          elements.experimentResultBadge.dataset.kind = 'offline';
          elements.experimentResultBadge.textContent = 'No result';
          return;
        }
        elements.experimentResult.className = '';
        const summary = document.createElement('div'); summary.className = 'experiment-result-summary';
        summary.append(
          experimentFact('Status', result.ok ? `${result.status} ${result.status_text}`.trim() : 'Request error'),
          experimentFact('Response URL', result.url || 'Not available'),
          experimentFact('Body', `${utf8ByteLength(result.body)} bytes${result.body_truncated ? ' · truncated' : ''}`)
        );
        const body = document.createElement('pre'); body.className = 'experiment-result-body';
        body.textContent = result.ok ? result.body || '(empty response body)' : result.error;
        elements.experimentResult.replaceChildren(summary, body);
        elements.experimentResultMeta.textContent = experiment.last_request
          ? `${experiment.last_request.method} ${experiment.last_request.url} · ${result.headers.length} response headers${result.headers_truncated ? ' · truncated' : ''}`
          : `${result.headers.length} response headers${result.headers_truncated ? ' · truncated' : ''}`;
        elements.experimentResultBadge.dataset.kind = result.ok ? '' : 'error';
        elements.experimentResultBadge.textContent = result.ok ? 'Complete' : 'Error';
      }

      function renderExperimentAudit(experiment) {
        const audit = experiment?.audit ?? [];
        const countLabel = `${audit.length} ${audit.length === 1 ? 'entry' : 'entries'}`;
        elements.experimentAuditCount.textContent = experiment?.audit_evictions
          ? `${countLabel} · ${experiment.audit_evictions} evicted`
          : countLabel;
        elements.experimentAuditCount.dataset.kind = audit.length ? '' : 'offline';
        if (!audit.length) {
          elements.experimentAudit.replaceChildren(textElement('div', 'experiment-empty', 'No intercepted requests yet.'));
          return;
        }
        elements.experimentAudit.replaceChildren(...[...audit].reverse().map(entry => {
          const row = document.createElement('div'); row.className = 'experiment-audit-row';
          const title = textElement('div', 'experiment-audit-title', `${entry.method || 'REQUEST'} ${entry.url || '(invalid URL)'}`);
          const outcome = textElement('div', 'experiment-audit-outcome', entry.outcome.replaceAll('_', ' '));
          const occurred = new Date(entry.occurred_at_ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
          const target = entry.target_id ? ` · page ${entry.target_id.slice(0, 12)}` : '';
          const meta = textElement('div', 'experiment-audit-meta', `${occurred} · ${entry.resource_type} · ${entry.rule_mode} · ${entry.request_id}${target} · ${entry.detail}`);
          row.append(title, outcome, meta);
          return row;
        }));
      }

      function parseRepeaterVariables(value) {
        const source = value.trim();
        if (!source) return {};
        let variables;
        try { variables = JSON.parse(source); }
        catch { throw new TypeError('Session variables must be a JSON object.'); }
        if (!isPlainObject(variables) || Object.values(variables).some(item => typeof item !== 'string')) {
          throw new TypeError('Session variables must map names to text values.');
        }
        return variables;
      }

      function repeaterHeaderObject(headers) {
        return Object.fromEntries(headers.map(header => [header.name, header.value]));
      }

      function parseRepeaterHeaderRows(value) {
        if (!value.trim()) return [];
        try {
          const headers = JSON.parse(value);
          if (!headers || typeof headers !== 'object' || Array.isArray(headers)) return [];
          return Object.entries(headers)
            .filter(([, headerValue]) => typeof headerValue === 'string')
            .map(([key, headerValue]) => ({key, value: headerValue, enabled: true}));
        } catch { return []; }
      }

      function serializeRepeaterHeaderRows(rows) {
        const headers = Object.fromEntries(rows
          .filter(row => row.enabled && row.key.trim())
          .map(row => [row.key.trim(), row.value]));
        return Object.keys(headers).length ? JSON.stringify(headers, null, 2) : '';
      }

      function decodeRepeaterQueryComponent(value) {
        try { return decodeURIComponent(value.replaceAll('+', ' ')); }
        catch { return value; }
      }

      function encodeRepeaterQueryComponent(value) {
        return encodeURIComponent(value).replaceAll('%7B', '{').replaceAll('%7D', '}');
      }

      function repeaterUrlParts(value) {
        const hashIndex = value.indexOf('#');
        const fragment = hashIndex < 0 ? '' : value.slice(hashIndex);
        const withoutFragment = hashIndex < 0 ? value : value.slice(0, hashIndex);
        const queryIndex = withoutFragment.indexOf('?');
        return {
          base: queryIndex < 0 ? withoutFragment : withoutFragment.slice(0, queryIndex),
          query: queryIndex < 0 ? '' : withoutFragment.slice(queryIndex + 1),
          fragment
        };
      }

      function parseRepeaterQueryRows(value) {
        const {query} = repeaterUrlParts(value);
        if (!query) return [];
        return query.split('&').filter(Boolean).map(parameter => {
          const separator = parameter.indexOf('=');
          return {
            key: decodeRepeaterQueryComponent(separator < 0 ? parameter : parameter.slice(0, separator)),
            value: decodeRepeaterQueryComponent(separator < 0 ? '' : parameter.slice(separator + 1)),
            enabled: true
          };
        });
      }

      function repeaterUrlWithQuery(value, rows) {
        const {base, fragment} = repeaterUrlParts(value);
        const query = rows.filter(row => row.enabled && row.key.trim()).map(row =>
          `${encodeRepeaterQueryComponent(row.key.trim())}=${encodeRepeaterQueryComponent(row.value)}`
        ).join('&');
        return `${base}${query ? `?${query}` : ''}${fragment}`;
      }

      function repeaterEditorRowValues(container) {
        return [...container.querySelectorAll('.repeater-kv-row:not([data-new-row="true"])')].map(row => ({
          key: row.querySelector('[data-repeater-kv-key]').value,
          value: row.querySelector('[data-repeater-kv-value]').value,
          enabled: row.querySelector('[data-repeater-kv-enabled]').checked
        }));
      }

      function markRepeaterDraftChanged() {
        state.repeaterDraftRevision = (state.repeaterDraftRevision ?? 0) + 1;
        state.repeaterDraftDirty = true;
        state.experimentError = null;
        renderRepeaterVariableStatus();
      }

      function syncRepeaterStructuredEditor(kind) {
        const container = kind === 'headers' ? elements.repeaterHeaderRows : elements.repeaterQueryRows;
        const rows = repeaterEditorRowValues(container);
        if (kind === 'headers') {
          elements.repeaterRequestHeaders.value = serializeRepeaterHeaderRows(rows);
          state.repeaterHeadersSource = elements.repeaterRequestHeaders.value;
        } else {
          elements.repeaterRequestUrl.value = repeaterUrlWithQuery(elements.repeaterRequestUrl.value, rows);
          state.repeaterQuerySource = elements.repeaterRequestUrl.value;
        }
        markRepeaterDraftChanged();
      }

      function createRepeaterEditorRow(kind, entry = {key: '', value: '', enabled: true}, newRow = false) {
        const row = document.createElement('div');
        row.className = 'repeater-kv-row';
        row.dataset.newRow = String(newRow);
        row.dataset.enabled = String(entry.enabled);
        row.setAttribute('role', 'row');
        const toggle = document.createElement('label'); toggle.className = 'repeater-kv-toggle';
        const checkbox = document.createElement('input'); checkbox.type = 'checkbox'; checkbox.checked = entry.enabled;
        checkbox.name = `${kind}-enabled`; checkbox.dataset.repeaterKvEnabled = '';
        const key = document.createElement('input'); key.type = 'text'; key.className = 'repeater-kv-input';
        key.value = entry.key; key.placeholder = newRow ? 'New key' : '';
        key.name = `${kind}-key`; key.autocomplete = 'off'; key.spellcheck = false;
        key.maxLength = kind === 'headers' ? 256 : 2048; key.dataset.repeaterKvKey = '';
        key.setAttribute('aria-label', `${kind === 'headers' ? 'Header' : 'Query parameter'} name`);
        const keyCell = document.createElement('span'); keyCell.className = 'repeater-kv-cell';
        keyCell.setAttribute('role', 'cell'); keyCell.append(key);
        const value = document.createElement('input'); value.type = 'text'; value.className = 'repeater-kv-input';
        value.value = entry.value; value.placeholder = newRow ? 'New value' : '';
        value.name = `${kind}-value`; value.autocomplete = 'off'; value.spellcheck = false;
        value.maxLength = kind === 'headers' ? 16384 : 8192; value.dataset.repeaterKvValue = '';
        value.setAttribute('aria-label', `${kind === 'headers' ? 'Header' : 'Query parameter'} value`);
        const valueCell = document.createElement('span'); valueCell.className = 'repeater-kv-cell';
        valueCell.setAttribute('role', 'cell'); valueCell.append(value);
        const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'repeater-kv-remove';
        remove.textContent = '×'; remove.setAttribute('aria-label', `Remove ${kind === 'headers' ? 'header' : 'query parameter'}`);
        const removeCell = document.createElement('span'); removeCell.className = 'repeater-kv-remove-cell';
        removeCell.setAttribute('role', 'cell'); removeCell.append(remove);
        toggle.setAttribute('role', 'cell'); toggle.append(checkbox); row.append(toggle, keyCell, valueCell, removeCell);

        const updateToggleLabel = () => checkbox.setAttribute('aria-label',
          `${checkbox.checked ? 'Disable' : 'Enable'} ${key.value || (kind === 'headers' ? 'header' : 'query parameter')}`);
        const promote = () => {
          if (row.dataset.newRow !== 'true' || (!key.value && !value.value)) return;
          row.dataset.newRow = 'false';
          checkbox.disabled = state.repeaterStructuredEditorsDisabled;
          remove.disabled = state.repeaterStructuredEditorsDisabled;
          row.parentElement.append(createRepeaterEditorRow(kind, undefined, true));
        };
        [key, value].forEach(input => input.addEventListener('input', () => {
          promote(); updateToggleLabel(); syncRepeaterStructuredEditor(kind);
        }));
        checkbox.addEventListener('change', () => {
          row.dataset.enabled = String(checkbox.checked); updateToggleLabel(); syncRepeaterStructuredEditor(kind);
        });
        remove.addEventListener('click', () => { row.remove(); syncRepeaterStructuredEditor(kind); });
        updateToggleLabel();
        [checkbox, key, value, remove].forEach(control => { control.disabled = state.repeaterStructuredEditorsDisabled; });
        return row;
      }

      function renderRepeaterStructuredEditor(kind, rows) {
        const container = kind === 'headers' ? elements.repeaterHeaderRows : elements.repeaterQueryRows;
        container.replaceChildren(...rows.map(row => createRepeaterEditorRow(kind, row)),
          createRepeaterEditorRow(kind, undefined, true));
      }

      function refreshRepeaterStructuredEditors(force = false) {
        if (force || state.repeaterHeadersSource !== elements.repeaterRequestHeaders.value) {
          state.repeaterHeadersSource = elements.repeaterRequestHeaders.value;
          renderRepeaterStructuredEditor('headers', parseRepeaterHeaderRows(elements.repeaterRequestHeaders.value));
        }
        if (force || state.repeaterQuerySource !== elements.repeaterRequestUrl.value) {
          state.repeaterQuerySource = elements.repeaterRequestUrl.value;
          renderRepeaterStructuredEditor('query', parseRepeaterQueryRows(elements.repeaterRequestUrl.value));
        }
      }

      function setRepeaterStructuredEditorsDisabled(disabled) {
        state.repeaterStructuredEditorsDisabled = disabled;
        [elements.repeaterHeaderRows, elements.repeaterQueryRows].forEach(container => {
          container.querySelectorAll('input, button').forEach(control => { control.disabled = disabled; });
        });
      }

      function prefillRepeaterVariables(repeater) {
        const variables = Object.fromEntries((repeater?.variables ?? []).map(item => [item.name, item.value]));
        const key = JSON.stringify(variables);
        if (state.repeaterVariablesKey === key || state.repeaterVariablesDirty) return;
        state.repeaterVariablesKey = key;
        elements.repeaterVariables.value = Object.keys(variables).length
          ? JSON.stringify(variables, null, 2) : '';
      }

      function prefillRepeaterRequest(force = false) {
        const request = state.requests.find(candidate => candidate.id === state.selectedRequestId);
        if (!request || state.repeaterDraftDirty && !force) return;
        const key = `${request.id}:${request.method}:${request.path}`;
        if (!force && state.repeaterPrefillKey === key) return;
        state.repeaterPrefillKey = key;
        let requestUrl = request.path;
        if (!/^https?:\/\//i.test(requestUrl)) {
          requestUrl = `https://checkout.acme.test${requestUrl.startsWith('/') ? '' : '/'}${requestUrl}`;
        }
        try {
          const parsed = new URL(requestUrl);
          parsed.hash = '';
          elements.repeaterRequestUrl.value = parsed.toString();
        } catch { elements.repeaterRequestUrl.value = ''; }
        elements.repeaterRequestMethod.value = /^[A-Z][A-Z0-9!#$%&'*+.^_`|~-]{0,31}$/.test(request.method)
          ? request.method : 'GET';
        elements.repeaterRequestTimeout.value = '15000';
        elements.repeaterRequestHeaders.value = '';
        elements.repeaterRequestBody.value = '';
        state.repeaterDraftDirty = false;
        refreshRepeaterStructuredEditors(true);
        renderRepeaterVariableStatus();
      }

      function loadRepeaterHistoryEntry(entry, focus = false) {
        if (!entry) return;
        state.repeaterDraftRevision = (state.repeaterDraftRevision ?? 0) + 1;
        state.repeaterSelectedHistoryId = entry.id;
        state.repeaterExpectedHistoryId = null;
        elements.repeaterRequestUrl.value = entry.request.url;
        elements.repeaterRequestMethod.value = entry.request.method;
        elements.repeaterRequestTimeout.value = String(entry.request.timeout_ms);
        elements.repeaterRequestHeaders.value = entry.request.headers.length
          ? JSON.stringify(repeaterHeaderObject(entry.request.headers), null, 2) : '';
        elements.repeaterRequestBody.value = entry.request.body;
        state.repeaterDraftDirty = false;
        refreshRepeaterStructuredEditors(true);
        renderRepeaterVariableStatus();
        renderRepeater();
        if (focus) {
          [...elements.repeaterHistory.querySelectorAll('.repeater-history-row')]
            .find(row => Number(row.dataset.historyId) === entry.id)?.focus({preventScroll: true});
        }
      }

      function setRepeaterEditorTab(tab, focus = false) {
        if (!['headers', 'query', 'body', 'settings'].includes(tab)) return;
        refreshRepeaterStructuredEditors();
        state.repeaterEditorTab = tab;
        elements.repeaterEditorTabs.forEach(button => {
          const selected = button.dataset.repeaterEditorTab === tab;
          button.setAttribute('aria-selected', String(selected));
          button.tabIndex = selected ? 0 : -1;
          if (selected && focus) button.focus();
        });
        elements.repeaterEditorPanels.forEach(panel => {
          panel.hidden = panel.dataset.repeaterEditorPanel !== tab;
        });
      }

      function setRepeaterResponseTab(tab, focus = false) {
        if (!['body', 'headers'].includes(tab)) return;
        state.repeaterResponseTab = tab;
        const buttons = [...elements.repeaterResponse.querySelectorAll('[data-repeater-response-tab]')];
        buttons.forEach(button => {
          const selected = button.dataset.repeaterResponseTab === tab;
          button.setAttribute('aria-selected', String(selected));
          button.tabIndex = selected ? 0 : -1;
          if (selected && focus) button.focus();
        });
        elements.repeaterResponse.querySelectorAll('[data-repeater-response-panel]').forEach(panel => {
          panel.hidden = panel.dataset.repeaterResponsePanel !== tab;
        });
      }

      function renderRepeaterVariableStatus() {
        let variables = {};
        let invalidVariables = false;
        try { variables = parseRepeaterVariables(elements.repeaterVariables.value); }
        catch { invalidVariables = true; }
        const source = [
          elements.repeaterRequestUrl.value,
          elements.repeaterRequestMethod.value,
          elements.repeaterRequestHeaders.value,
          elements.repeaterRequestBody.value
        ].join('\n');
        const names = new Set();
        for (const match of source.matchAll(/\{\{(=)?([^{}]+)\}\}/g)) {
          if (!match[1]) names.add(match[2]);
        }
        const chips = [];
        if (invalidVariables) {
          const chip = textElement('span', 'repeater-variable-chip', 'Invalid variable JSON');
          chip.dataset.kind = 'missing'; chips.push(chip);
        }
        [...names].sort().forEach(name => {
          const resolved = Object.hasOwn(variables, name);
          const chip = textElement('span', 'repeater-variable-chip', `${resolved ? 'Resolved' : 'Missing'} · {{${name}}}`);
          if (!resolved) chip.dataset.kind = 'missing';
          chips.push(chip);
        });
        elements.repeaterVariableStatus.hidden = chips.length === 0;
        elements.repeaterVariableStatus.replaceChildren(...chips);
      }

      function selectedRepeaterEntry(repeater = repeaterState()) {
        return repeater?.history.find(entry => entry.id === state.repeaterSelectedHistoryId) ?? null;
      }

      function renderRepeaterHistory(repeater) {
        const history = repeater?.history ?? [];
        if (state.repeaterExpectedHistoryId !== null && history.some(entry => entry.id === state.repeaterExpectedHistoryId)) {
          state.repeaterSelectedHistoryId = state.repeaterExpectedHistoryId;
          state.repeaterExpectedHistoryId = null;
        }
        if (!history.some(entry => entry.id === state.repeaterSelectedHistoryId)) {
          state.repeaterSelectedHistoryId = history.at(-1)?.id ?? null;
        }
        elements.repeaterHistoryBadge.textContent = `${history.length} ${history.length === 1 ? 'run' : 'runs'}${repeater?.history_evictions ? ` · ${repeater.history_evictions} evicted` : ''}`;
        elements.repeaterHistoryBadge.dataset.kind = history.length ? '' : 'offline';
        elements.repeaterHistoryBytes.textContent = `${Math.ceil((repeater?.history_bytes ?? 0) / 1024)} / 512 KiB`;
        elements.repeaterHistoryUsage.textContent = `${history.length} / ${repeater?.limits?.history_entries ?? 24}`;
        if (!history.length) {
          elements.repeaterHistory.replaceChildren(emptyListboxOption('experiment-empty', 'No Repeater requests yet.'));
          elements.repeaterHistoryPrev.disabled = true;
          elements.repeaterHistoryNext.disabled = true;
          return;
        }
        const selectedIndex = history.findIndex(entry => entry.id === state.repeaterSelectedHistoryId);
        elements.repeaterHistoryPrev.disabled = selectedIndex <= 0;
        elements.repeaterHistoryNext.disabled = selectedIndex < 0 || selectedIndex >= history.length - 1;
        elements.repeaterHistory.replaceChildren(...[...history].reverse().map(entry => {
          const row = document.createElement('button'); row.type = 'button'; row.className = 'repeater-history-row';
          row.dataset.historyId = String(entry.id); row.setAttribute('role', 'option');
          row.setAttribute('aria-selected', String(entry.id === state.repeaterSelectedHistoryId));
          row.tabIndex = entry.id === state.repeaterSelectedHistoryId ? 0 : -1;
          const title = textElement('span', 'repeater-history-title', `${entry.resolved_request.method} ${entry.resolved_request.url}`);
          const status = textElement('span', 'repeater-history-state', entry.response.ok ? String(entry.response.status) : entry.state.replaceAll('_', ' '));
          if (!entry.response.ok) status.dataset.kind = 'error';
          const occurred = new Date(entry.completed_at_ms).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit', second: '2-digit'});
          const meta = textElement('span', 'repeater-history-meta', `run ${entry.id} · ${entry.response.duration_ms} ms · ${occurred}`);
          row.append(title, status, meta);
          row.addEventListener('click', () => loadRepeaterHistoryEntry(entry, true));
          row.addEventListener('keydown', event => {
            if (!['ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) return;
            event.preventDefault();
            const rows = [...elements.repeaterHistory.querySelectorAll('.repeater-history-row')];
            const index = rows.indexOf(row);
            const next = event.key === 'Home' ? 0 : event.key === 'End' ? rows.length - 1
              : Math.max(0, Math.min(rows.length - 1, index + (event.key === 'ArrowDown' ? 1 : -1)));
            rows[next].click();
          });
          return row;
        }));
      }

      function renderRepeaterResponse(repeater) {
        const entry = selectedRepeaterEntry(repeater);
        elements.repeaterCopyResolved.disabled = !entry || ['running', 'cancelling'].includes(repeater?.state) || state.experimentPending;
        elements.repeaterCopyResolved.hidden = !entry;
        elements.repeaterResponseBadge.hidden = !entry;
        if (!entry) {
          elements.repeaterResponse.className = 'repeater-response experiment-empty';
          elements.repeaterResponse.textContent = 'Send a request or choose one from history.';
          elements.repeaterResponseMeta.textContent = 'Select a completed run to inspect its bounded response.';
          elements.repeaterResponseBadge.dataset.kind = 'offline';
          elements.repeaterResponseBadge.textContent = 'No response';
          return;
        }
        const response = entry.response;
        elements.repeaterResponse.className = 'repeater-response';
        const summary = document.createElement('div'); summary.className = 'experiment-result-summary';
        summary.append(
          experimentFact('Status', response.ok ? `${response.status} ${response.status_text}`.trim() : entry.state.replaceAll('_', ' ')),
          experimentFact('Duration', `${response.duration_ms} ms`),
          experimentFact('Body', `${utf8ByteLength(response.body)} bytes${response.body_truncated ? ' · truncated' : ''}`)
        );
        const headers = document.createElement('div');
        headers.id = 'repeater-response-headers-panel';
        headers.className = 'repeater-response-headers repeater-response-panel';
        headers.dataset.repeaterResponsePanel = 'headers';
        headers.setAttribute('role', 'tabpanel');
        if (response.headers.length) {
          headers.append(...response.headers.map(header => {
            const row = document.createElement('div'); row.className = 'repeater-response-header';
            row.append(textElement('span', '', header.name), textElement('span', '', header.value));
            return row;
          }));
        } else headers.append(textElement('div', 'experiment-empty', 'No response headers.'));
        const bodyPanel = document.createElement('div');
        bodyPanel.id = 'repeater-response-body-panel';
        bodyPanel.className = 'repeater-response-panel';
        bodyPanel.dataset.repeaterResponsePanel = 'body';
        bodyPanel.setAttribute('role', 'tabpanel');
        const body = document.createElement('pre'); body.className = 'experiment-result-body';
        body.textContent = response.ok ? response.body || '(empty response body)' : response.error;
        bodyPanel.append(body);
        const tabs = document.createElement('div');
        tabs.className = 'repeater-response-tabs';
        tabs.setAttribute('role', 'tablist');
        tabs.setAttribute('aria-label', 'Response inspector');
        [['body', 'Body'], ['headers', `Headers (${response.headers.length})`]].forEach(([tab, label]) => {
          const button = textElement('button', 'repeater-response-tab', label);
          button.type = 'button';
          button.dataset.repeaterResponseTab = tab;
          button.setAttribute('role', 'tab');
          button.setAttribute('aria-controls', `repeater-response-${tab}-panel`);
          button.addEventListener('click', () => setRepeaterResponseTab(tab));
          button.addEventListener('keydown', event => {
            if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
            event.preventDefault();
            const responseTabs = [...tabs.querySelectorAll('[data-repeater-response-tab]')];
            const current = responseTabs.indexOf(button);
            const next = event.key === 'Home' ? 0 : event.key === 'End' ? responseTabs.length - 1
              : (current + (event.key === 'ArrowRight' ? 1 : -1) + responseTabs.length) % responseTabs.length;
            responseTabs[next].click();
            responseTabs[next].focus();
          });
          tabs.append(button);
        });
        const view = document.createElement('div'); view.className = 'repeater-response-view';
        view.append(bodyPanel, headers);
        elements.repeaterResponse.replaceChildren(summary, tabs, view);
        setRepeaterResponseTab(state.repeaterResponseTab);
        elements.repeaterResponseMeta.textContent = `run ${entry.id} · ${entry.resolved_request.method} ${entry.resolved_request.url} · ${response.headers.length} headers${response.headers_truncated ? ' · truncated' : ''}`;
        elements.repeaterResponseBadge.dataset.kind = response.ok ? '' : 'error';
        elements.repeaterResponseBadge.textContent = response.ok ? 'Complete' : entry.state.replaceAll('_', ' ');
      }

      function renderRepeaterBodyDiff(comparison) {
        const panel = elements.repeaterBodyDiff;
        const diff = comparison?.body_diff;
        panel.hidden = !diff;
        const key = JSON.stringify([comparison?.baseline_id, comparison?.current_id, diff]);
        // Polling must preserve keyboard focus and the researcher's scroll position.
        if (panel.dataset.renderKey === key) return;
        panel.dataset.renderKey = key;
        panel.replaceChildren();
        if (!diff) return;
        const heading = document.createElement('h3'); heading.textContent = 'Body line changes';
        const summary = document.createElement('p');
        summary.textContent = `+${diff.added} added · −${diff.removed} removed${diff.partial ? ' · Partial' : ''}`;
        const coverage = document.createElement('p'); coverage.className = 'repeater-diff-coverage';
        const reasons = {
          capture_truncated: 'A captured response was truncated.',
          line_limit: 'Only the first 1,000 lines of each response were aligned.',
          output_limit: 'The excerpt is limited to 200 rows and 32 KiB of text.',
          line_text_limit: 'Long lines are clipped to 4 KiB.'
        };
        coverage.textContent = diff.limits_reached.map(limit => reasons[limit]).join(' ') ||
          'Baseline and current line numbers. Two nearby rows of context; unmarked endings are LF.';
        panel.append(heading, summary, coverage);
        if (!diff.lines.length) {
          const empty = document.createElement('p');
          empty.textContent = comparison.body_changed ? 'No changed lines in the inspected prefixes.' : 'Captured response bodies are identical.';
          panel.append(empty); return;
        }
        const rows = document.createElement('ol'); rows.className = 'repeater-diff-lines';
        rows.tabIndex = 0; rows.setAttribute('aria-label', 'Body diff. Baseline line, current line, change, and text');
        let baseline = 0, current = 0;
        for (const line of diff.lines) {
          if ((line.baseline_line !== null && line.baseline_line > baseline + 1) ||
              (line.current_line !== null && line.current_line > current + 1)) {
            const gap = document.createElement('li'); gap.className = 'repeater-diff-gap';
            gap.textContent = '⋯ unchanged context omitted'; rows.append(gap);
          }
          const row = document.createElement('li'); row.dataset.kind = line.kind;
          const oldNumber = document.createElement('span'); oldNumber.textContent = line.baseline_line ?? '';
          const newNumber = document.createElement('span'); newNumber.textContent = line.current_line ?? '';
          const marker = document.createElement('span');
          marker.textContent = line.kind === 'added' ? '+' : line.kind === 'removed' ? '−' : ' ';
          marker.setAttribute('aria-label', line.kind);
          const text = document.createElement('code'); text.textContent = line.text;
          const notes = [line.ending === 'crlf' ? 'CRLF' : line.ending === 'none' ? 'no final newline' : '',
            line.text_truncated ? 'text clipped' : ''].filter(Boolean);
          if (notes.length) {
            const note = document.createElement('em'); note.textContent = ` [${notes.join(' · ')}]`; text.append(note);
          }
          row.append(oldNumber, newNumber, marker, text); rows.append(row);
          baseline = line.baseline_line ?? baseline; current = line.current_line ?? current;
        }
        panel.append(rows);
      }

      function renderRepeaterComparison(repeater) {
        const successful = (repeater?.history ?? []).filter(entry => entry.response.ok);
        const retained = new Set(successful.map(entry => entry.id));
        const comparison = repeater?.comparison ?? null;
        renderRepeaterBodyDiff(comparison);
        const comparisonKey = comparison ? `${comparison.baseline_id}:${comparison.current_id}` : null;
        if (comparison && comparisonKey !== state.repeaterComparisonKey) {
          state.repeaterCompareBaselineId = comparison.baseline_id;
          state.repeaterCompareCurrentId = comparison.current_id;
        }
        state.repeaterComparisonKey = comparisonKey;
        if (!retained.has(state.repeaterCompareBaselineId)) state.repeaterCompareBaselineId = successful.at(-2)?.id ?? null;
        if (!retained.has(state.repeaterCompareCurrentId)) state.repeaterCompareCurrentId = successful.at(-1)?.id ?? null;
        const options = successful.map(entry => {
          const option = document.createElement('option'); option.value = String(entry.id);
          option.textContent = `Run ${entry.id} · ${entry.response.status} · ${entry.response.duration_ms} ms`;
          return option;
        });
        const optionKey = options.map(option => `${option.value}:${option.textContent}`).join('|');
        if (elements.repeaterCompareBaseline.dataset.optionKey !== optionKey) {
          elements.repeaterCompareBaseline.dataset.optionKey = optionKey;
          elements.repeaterCompareBaseline.replaceChildren(...options.map(option => option.cloneNode(true)));
          elements.repeaterCompareCurrent.replaceChildren(...options);
        }
        elements.repeaterCompareBaseline.value = state.repeaterCompareBaselineId === null ? '' : String(state.repeaterCompareBaselineId);
        elements.repeaterCompareCurrent.value = state.repeaterCompareCurrentId === null ? '' : String(state.repeaterCompareCurrentId);
        elements.repeaterCompare.disabled = successful.length < 2 ||
          state.repeaterCompareBaselineId === state.repeaterCompareCurrentId ||
          ['running', 'cancelling'].includes(repeater?.state) || state.experimentPending;
        if (!comparison) {
          elements.repeaterComparison.className = 'experiment-empty';
          elements.repeaterComparison.textContent = 'Complete two requests to compare their responses.';
          elements.repeaterComparisonBadge.dataset.kind = 'offline';
          elements.repeaterComparisonBadge.textContent = 'No comparison';
          return;
        }
        elements.repeaterComparison.className = 'repeater-comparison';
        const signed = value => `${value > 0 ? '+' : ''}${value}`;
        const headerDetail = [
          comparison.headers_added.length ? `added ${comparison.headers_added.join(', ')}` : '',
          comparison.headers_removed.length ? `removed ${comparison.headers_removed.join(', ')}` : '',
          comparison.headers_changed.length ? `changed ${comparison.headers_changed.join(', ')}` : ''
        ].filter(Boolean).join(' · ') || 'No response-header changes';
        elements.repeaterComparison.replaceChildren(
          experimentFact('Status', comparison.status_changed
            ? `${comparison.baseline_status} → ${comparison.current_status}` : `${comparison.current_status} unchanged`),
          experimentFact('Latency', `${signed(comparison.duration_delta_ms)} ms`),
          experimentFact('Body', comparison.body_changed ? 'Digest changed' : 'Exact digest match'),
          experimentFact('Body size', `${signed(comparison.body_bytes_delta)} bytes`),
          experimentFact('Header names', headerDetail),
          experimentFact('Coverage', comparison.partial
            ? comparison.body_diff?.partial ? 'Partial; inspect limits below' : 'Partial due to response truncation'
            : 'Complete within limits')
        );
        elements.repeaterComparison.lastElementChild.classList.add('repeater-comparison-detail');
        elements.repeaterComparisonBadge.dataset.kind = comparison.partial ? 'error' : '';
        elements.repeaterComparisonBadge.textContent = `Run ${comparison.baseline_id} vs ${comparison.current_id}`;
      }

      function renderRepeater() {
        prefillRepeaterRequest();
        refreshRepeaterStructuredEditors();
        const experiment = requestInterception();
        const repeater = repeaterState();
        const attached = ['running', 'paused'].includes(state.debuggerSession?.state);
        const active = ['running', 'cancelling'].includes(repeater?.state);
        const hookBusy = ['arming', 'armed', 'handling', 'stopping'].includes(runtimeHooksState()?.state);
        const automationBusy = automationRecipesState()?.auto_armed ||
          ['arming', 'running', 'stopping'].includes(automationRecipesState()?.state);
        const working = state.experimentPending || ['creating', 'disposing'].includes(experiment?.state) || hookBusy || automationBusy;
        const contextReady = attached && experiment?.isolated &&
          experiment.target_id === state.debuggerSession?.target?.id && ['ready', 'error'].includes(experiment.state) &&
          ['ready', 'error'].includes(repeater?.state);
        const canDispose = experiment?.isolated && ['ready', 'error'].includes(experiment.state) &&
          experiment.pending_requests === 0 && !active && !hookBusy && !automationBusy;
        const request = state.requests.find(candidate => candidate.id === state.selectedRequestId);
        elements.experimentTitle.textContent = 'Repeater';
        elements.experimentSubtitle.textContent = request
          ? `request-${request.id} · editable credential-free replay · isolated session`
          : 'Editable credential-free replay · isolated session';
        if (state.experimentError) setExperimentNotice('error', state.experimentError);
        else if (!repeater || !experiment) setExperimentNotice('error', 'The debugger session is unavailable or malformed.');
        else if (active || working) setExperimentNotice('working', repeater.message);
        else if (repeater.state === 'error') setExperimentNotice('error', repeater.message);
        else if (contextReady || repeater.state === 'disposed') setExperimentNotice('ready', repeater.message);
        else if (!attached) setExperimentNotice('idle', 'Connect a browser target to send requests.');
        else setExperimentNotice('idle', repeater.message);

        elements.repeaterContextBadge.dataset.kind = repeater?.state === 'error' ? 'error' : experiment?.isolated ? '' : 'offline';
        elements.repeaterContextBadge.textContent = experiment?.state === 'creating' ? 'Creating'
          : experiment?.state === 'disposing' ? 'Disposing'
            : experiment?.isolated ? 'Isolated'
              : repeater?.state === 'disposed' ? 'Disposed' : 'Not created';
        elements.repeaterContextMessage.textContent = repeater?.state === 'error' ? repeater.message
          : contextReady ? 'Disposable page attached. Repeater has no baseline cookies or storage.'
            : repeater?.message ?? 'No disposable request-lab context exists.';
        elements.repeaterSessionBar.hidden = !attached && !experiment?.isolated;
        elements.repeaterStorageState.textContent = experiment?.isolated ? 'Ephemeral and isolated'
          : repeater?.state === 'disposed' ? 'Deleted and erased' : 'Not allocated';
        elements.repeaterCreate.disabled = !attached || Boolean(experiment?.isolated) || working || state.debuggerActionPending;
        elements.repeaterDispose.disabled = !canDispose || working || state.debuggerActionPending;
        elements.repeaterCreate.hidden = Boolean(experiment?.isolated);
        elements.repeaterDispose.hidden = !experiment?.isolated;
        elements.repeaterClearHistory.disabled = !repeater?.history.length || active || working || state.debuggerActionPending;

        prefillRepeaterVariables(repeater);
        const variableCount = repeater?.variables.length ?? 0;
        elements.repeaterVariableBadge.textContent = `${variableCount} ${variableCount === 1 ? 'variable' : 'variables'}`;
        elements.repeaterVariableBadge.dataset.kind = contextReady ? '' : 'offline';
        elements.repeaterApplyVariables.disabled = !contextReady || active || working || state.debuggerActionPending;
        elements.repeaterVariables.disabled = !contextReady || active || working;
        const requestDisabled = !contextReady || active || working;
        [elements.repeaterRequestUrl, elements.repeaterRequestMethod, elements.repeaterRequestTimeout,
          elements.repeaterRequestHeaders, elements.repeaterRequestBody]
          .forEach(field => { field.disabled = requestDisabled; });
        setRepeaterStructuredEditorsDisabled(requestDisabled);
        elements.repeaterSend.disabled = !contextReady || active || working || state.debuggerActionPending;
        elements.repeaterCancel.disabled = !active || repeater?.state === 'cancelling';
        elements.repeaterSend.hidden = active;
        elements.repeaterCancel.hidden = !active;
        elements.repeaterRequestBadge.dataset.kind = active ? '' : contextReady ? '' : 'offline';
        elements.repeaterRequestBadge.textContent = repeater?.state === 'cancelling' ? 'Cancelling'
          : repeater?.state === 'running' ? 'Running' : 'Draft';
        elements.repeaterRequestBadge.hidden = !active;
        elements.repeaterActiveRequest.textContent = repeater?.active_execution
          ? `run ${repeater.active_execution.execution_id} · ${repeater.active_execution.resolved_method} ${repeater.active_execution.resolved_url}`
          : 'No active request';
        elements.repeaterActiveRequest.hidden = !repeater?.active_execution;
        setRepeaterEditorTab(state.repeaterEditorTab);
        renderRepeaterVariableStatus();
        elements.repeaterRequestFooter.hidden = elements.repeaterVariableStatus.hidden && elements.repeaterActiveRequest.hidden;
        renderRepeaterHistory(repeater);
        renderRepeaterResponse(repeater);
        renderRepeaterComparison(repeater);
      }

      function selectedObjectExperimentResult(experiment = objectExperimentState()) {
        return experiment?.results.find(result => result.id === state.objectSelectedResultId) ?? null;
      }

      function selectObjectExperimentResult(resultId, focus = false) {
        const experiment = objectExperimentState();
        if (!experiment?.results.some(result => result.id === resultId)) return;
        state.objectSelectedResultId = resultId;
        state.objectSelectionSearchId = experiment.search_id;
        elements.objectConfirm.checked = false;
        renderObjectExperiment();
        if (focus) elements.objectResults.querySelector(`[data-object-result-id="${CSS.escape(resultId)}"]`)?.focus();
      }

      function renderObjectResults(experiment) {
        if (state.objectSelectionSearchId !== (experiment?.search_id ?? 0) ||
            !experiment?.results.some(result => result.id === state.objectSelectedResultId)) {
          state.objectSelectionSearchId = experiment?.search_id ?? 0;
          state.objectSelectedResultId = experiment?.results[0]?.id ?? null;
          elements.objectConfirm.checked = false;
        }
        const results = experiment?.results ?? [];
        elements.objectResultCount.textContent = `${results.length} ${results.length === 1 ? 'match' : 'matches'}`;
        elements.objectResultCount.dataset.kind = results.length > 0 ? '' : 'offline';
        if (results.length === 0) {
          elements.objectResults.replaceChildren(emptyListboxOption('experiment-empty',
            experiment?.search ? 'No objects matched within the visible limits.' : 'No retained object references.'));
        } else {
          elements.objectResults.replaceChildren(...results.map(result => {
            const row = document.createElement('button'); row.type = 'button'; row.className = 'object-result-row';
            row.dataset.objectResultId = result.id;
            row.setAttribute('role', 'option');
            row.setAttribute('aria-selected', String(result.id === state.objectSelectedResultId));
            const title = textElement('span', 'object-result-title', `${result.class_name} · object ${result.id}`);
            const count = textElement('span', 'object-result-count', `${result.property_count} props`);
            const preview = textElement('span', 'object-result-preview', result.preview.length > 0
              ? result.preview.slice(0, 3).map(property => `${property.name}: ${property.value}`).join(' · ')
              : 'No retained own-property preview');
            row.append(title, count, preview);
            row.addEventListener('click', () => selectObjectExperimentResult(result.id));
            return row;
          }));
        }
        const search = experiment?.search;
        if (!search) elements.objectSearchMeta.textContent = 'Open a page and run one bounded search.';
        else {
          const limits = [];
          if (search.timed_out) limits.push('time limit reached');
          if (search.result_limit_reached) limits.push('result limit reached');
          if (search.scan_limit_reached) limits.push('candidate limit reached');
          if (search.property_limit_reached) limits.push('property limit reached');
          elements.objectSearchMeta.textContent = `${results.length} shown from ${search.analyzed.toLocaleString()} inspected objects in ${search.duration_ms} ms${limits.length ? ` · ${limits.join(' · ')}` : ''}`;
        }
      }

      function renderObjectSelection(experiment) {
        const selected = selectedObjectExperimentResult(experiment);
        elements.objectSelectionMeta.textContent = selected
          ? `${selected.class_name} · retained result ${selected.id} · search ${experiment.search_id}`
          : 'Select one retained object result.';
        elements.objectMutationBadge.dataset.kind = selected ? '' : 'offline';
        elements.objectMutationBadge.textContent = selected ? `Object ${selected.id}` : 'Locked';
        if (!selected) {
          elements.objectPreview.replaceChildren(textElement('div', 'experiment-empty', 'No object selected.'));
          return;
        }
        const rows = selected.preview.map(property => {
          const row = document.createElement('div'); row.className = 'object-property-row';
          row.append(textElement('span', '', property.name), textElement('span', '', property.type),
            textElement('span', '', property.value));
          return row;
        });
        if (rows.length === 0) rows.push(textElement('div', 'experiment-empty', 'No own properties in the bounded preview.'));
        elements.objectPreview.replaceChildren(...rows);
      }

      function renderObjectMutation(experiment) {
        const mutation = experiment?.last_mutation;
        if (!mutation) {
          elements.objectMutationResult.dataset.kind = '';
          elements.objectMutationResult.textContent = 'No mutation attempted.';
          return;
        }
        elements.objectMutationResult.dataset.kind = mutation.ok ? 'ready' : 'error';
        const before = mutation.before.preview ?? mutation.before.type;
        const after = mutation.after.preview ?? mutation.after.type;
        elements.objectMutationResult.textContent = mutation.ok
          ? `Audit ${mutation.audit_id} · ${mutation.operation} ${mutation.property} · ${before} → ${after} · ${mutation.value_bytes} value bytes`
          : `Audit ${mutation.audit_id} · ${mutation.outcome} · ${mutation.error}`;
      }

      function renderObjectAudit(experiment) {
        const audit = experiment?.audit ?? [];
        elements.objectAuditCount.textContent = `${audit.length} ${audit.length === 1 ? 'entry' : 'entries'}`;
        elements.objectAuditCount.dataset.kind = audit.length > 0 ? '' : 'offline';
        if (audit.length === 0) {
          elements.objectAudit.replaceChildren(textElement('div', 'experiment-empty', 'No object mutations attempted.'));
          return;
        }
        elements.objectAudit.replaceChildren(...audit.slice().reverse().map(entry => {
          const row = document.createElement('div'); row.className = 'experiment-audit-row';
          const title = textElement('span', 'experiment-audit-title',
            `${entry.operation.toUpperCase()} ${entry.target_class}.${entry.property}`);
          const outcome = textElement('span', 'experiment-audit-outcome', entry.outcome.replaceAll('_', ' '));
          if (!entry.success) outcome.style.color = 'var(--red)';
          const digest = entry.value_digest ? `${entry.value_digest.slice(0, 12)}…` : 'none';
          const meta = textElement('span', 'experiment-audit-meta',
            `audit ${entry.id} · nav ${entry.navigation_id} · search ${entry.search_id} · object ${entry.result_id} · ${entry.before_type} → ${entry.after_type} · ${entry.value_bytes} bytes · sha256 ${digest} · ${entry.url}`);
          row.append(title, outcome, meta);
          return row;
        }));
      }

      function renderObjectExperiment() {
        const experiment = requestInterception();
        const objectExperiment = objectExperimentState();
        const repeater = repeaterState();
        const attached = ['running', 'paused'].includes(state.debuggerSession?.state);
        const objectBusy = ['navigating', 'searching', 'mutating'].includes(objectExperiment?.state);
        const hookBusy = ['arming', 'armed', 'handling', 'stopping'].includes(runtimeHooksState()?.state);
        const automationBusy = automationRecipesState()?.auto_armed ||
          ['arming', 'running', 'stopping'].includes(automationRecipesState()?.state);
        const contextBusy = state.experimentPending || ['creating', 'running', 'disposing'].includes(experiment?.state) ||
          ['running', 'cancelling'].includes(repeater?.state) || objectBusy || hookBusy || automationBusy;
        const contextReady = attached && experiment?.isolated && objectExperiment?.isolated &&
          experiment.target_id === state.debuggerSession?.target?.id &&
          objectExperiment.target_id === state.debuggerSession?.target?.id &&
          !['attaching', 'disposing', 'disposed'].includes(objectExperiment.state);
        const pageReady = contextReady && objectExperiment.navigation_id > 0 && objectExperiment.url;
        if (state.objectSelectionSearchId !== (objectExperiment?.search_id ?? 0) ||
            !objectExperiment?.results.some(result => result.id === state.objectSelectedResultId)) {
          state.objectSelectionSearchId = objectExperiment?.search_id ?? 0;
          state.objectSelectedResultId = objectExperiment?.results[0]?.id ?? null;
          elements.objectConfirm.checked = false;
        }
        const selected = selectedObjectExperimentResult(objectExperiment);
        const canDispose = experiment?.isolated && experiment.pending_requests === 0 &&
          !['running', 'cancelling'].includes(repeater?.state) && !objectBusy && !hookBusy && !automationBusy;
        elements.experimentTitle.textContent = 'Objects';
        elements.experimentSubtitle.textContent = 'Find an object, inspect its properties, and test a change on a disposable page.';

        if (state.experimentError) setExperimentNotice('error', state.experimentError);
        else if (!experiment || !objectExperiment) setExperimentNotice('error', 'The debugger session is unavailable or malformed.');
        else if (contextBusy) setExperimentNotice('working', objectExperiment.message);
        else if (objectExperiment.state === 'error' || objectExperiment.last_mutation?.ok === false) setExperimentNotice('error', objectExperiment.message);
        else if (pageReady || objectExperiment.state === 'disposed') setExperimentNotice('ready', objectExperiment.message);
        else if (!attached) setExperimentNotice('idle', 'Connect a browser target to inspect live objects.');
        else setExperimentNotice('idle', objectExperiment.message);

        elements.objectContextBadge.dataset.kind = objectExperiment?.state === 'error' ? 'error' : objectExperiment?.isolated ? '' : 'offline';
        elements.objectContextBadge.textContent = experiment?.state === 'creating' ? 'Creating'
          : experiment?.state === 'disposing' ? 'Disposing'
            : objectExperiment?.isolated ? 'Isolated'
              : objectExperiment?.state === 'disposed' ? 'Disposed' : 'Not created';
        elements.objectContextMessage.textContent = objectExperiment?.message ?? 'No disposable Experiment context exists.';
        elements.objectStorageState.textContent = objectExperiment?.isolated ? 'Ephemeral and isolated'
          : objectExperiment?.state === 'disposed' ? 'Deleted and erased' : 'Not allocated';
        elements.objectPageState.textContent = objectExperiment?.url || 'Not opened';
        elements.objectPageBadge.dataset.kind = pageReady ? '' : objectExperiment?.state === 'error' ? 'error' : 'offline';
        elements.objectPageBadge.textContent = objectExperiment?.state === 'navigating' ? 'Opening'
          : pageReady ? 'Loaded' : 'No page';
        const search = objectExperiment?.search;
        const partial = search && (search.timed_out || search.result_limit_reached || search.scan_limit_reached || search.property_limit_reached);
        elements.objectSearchBadge.dataset.kind = partial ? 'error' : search ? '' : 'offline';
        elements.objectSearchBadge.textContent = objectExperiment?.state === 'searching' ? 'Searching'
          : search ? partial ? 'Partial' : 'Complete' : 'No search';

        elements.objectCreate.disabled = !attached || Boolean(experiment?.isolated) || contextBusy || state.debuggerActionPending;
        elements.objectDispose.disabled = !canDispose || contextBusy || state.debuggerActionPending;
        elements.objectNavigationForm.querySelectorAll('input').forEach(field => { field.disabled = !contextReady || contextBusy; });
        elements.objectNavigate.disabled = !contextReady || contextBusy || state.debuggerActionPending;
        elements.objectSearchForm.querySelectorAll('input, textarea').forEach(field => { field.disabled = !pageReady || contextBusy; });
        elements.objectSearch.disabled = !pageReady || contextBusy || state.debuggerActionPending;
        elements.objectValueField.hidden = elements.objectOperation.value === 'delete';
        elements.objectMutationForm.querySelectorAll('input, select, textarea').forEach(field => {
          field.disabled = !selected || contextBusy;
        });
        elements.objectMutationValue.disabled = !selected || contextBusy || elements.objectOperation.value === 'delete';
        elements.objectMutate.disabled = !selected || contextBusy || !elements.objectConfirm.checked ||
          !elements.objectMutationProperty.value || state.debuggerActionPending ||
          (objectExperiment?.mutation_attempts ?? 0) >= (objectExperiment?.limits?.mutation_attempts ?? 256);
        renderObjectResults(objectExperiment);
        renderObjectSelection(objectExperiment);
        renderObjectMutation(objectExperiment);
        renderObjectAudit(objectExperiment);
      }

      function renderRuntimeHookDefinitions(hooks, active) {
        const definitions = hooks?.definitions ?? [];
        elements.hooksDefinitionCount.textContent = `${definitions.length} / ${hooks?.limits?.definitions ?? 8}`;
        elements.hooksDefinitionCount.dataset.kind = definitions.length ? '' : 'offline';
        elements.hooksDefinitionBadge.textContent = definitions.length
          ? `${definitions.length} ${definitions.length === 1 ? 'hook' : 'hooks'}` : 'Empty';
        elements.hooksDefinitionBadge.dataset.kind = definitions.length ? '' : 'offline';
        if (!definitions.length) {
          elements.hooksDefinitions.replaceChildren(textElement('div', 'experiment-empty', 'No hooks yet.'));
          return;
        }
        elements.hooksDefinitions.replaceChildren(...definitions.map(definition => {
          const row = document.createElement('div'); row.className = 'hook-definition-row';
          const title = textElement('span', 'hook-definition-title', definition.label);
          const phases = [definition.entry_enabled ? 'entry' : '', definition.return_enabled ? 'return' : ''].filter(Boolean).join(' + ');
          const phase = textElement('span', 'hook-definition-phase', phases);
          const resolved = definition.resolved
            ? ` · ${definition.resolved.entry_points} entry / ${definition.resolved.return_points} return points`
            : '';
          const behavior = [definition.condition ? 'condition' : '', definition.entry_logic || definition.return_logic ? 'logic' : '',
            definition.return_mode !== 'none' ? `${definition.return_mode} override` : ''].filter(Boolean).join(' · ') || 'observe only';
          const functionKind = definition.function_kind.replaceAll('_', ' ');
          const location = definition.entry_mode === 'function'
            ? `live function ${definition.function_expression}`
            : `${functionKind} at ${definition.function_start.line + 1}:${definition.function_start.column + 1} · V8 entry search ${definition.target_line + 1}:${definition.target_column + 1}`;
          const meta = textElement('span', 'hook-definition-meta',
            `${definition.target_type} ${definition.target_id.slice(0, 12)} · ${sourceName({url: definition.url, source_type: 'script', script_id: definition.script_id})}:${definition.line + 1}:${definition.column + 1} · ${location}${resolved} · ${behavior}`);
          const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'hook-remove';
          remove.textContent = 'Remove'; remove.disabled = active || state.experimentPending || state.debuggerActionPending;
          remove.setAttribute('aria-label', `Remove ${definition.label}`);
          remove.addEventListener('click', () => runExperimentAction({action: 'remove_runtime_hook', hook_id: definition.id}));
          row.append(title, remove, phase, meta);
          return row;
        }));
      }

      function renderRuntimeHookHits(hooks) {
        const hits = hooks?.hits ?? [];
        const requests = hooks?.requests ?? [];
        const total = hooks?.total_hits ?? 0;
        elements.hooksHitCount.textContent = `${total} / ${hooks?.limits?.total_hits ?? 512}`;
        elements.hooksHitCount.dataset.kind = hooks?.last_failure ? 'error' : hits.length ? '' : 'offline';
        const hitDetails = [];
        if (hooks?.hit_evictions || hits.length !== total) hitDetails.push(`${hits.length} retained`);
        if (hooks?.hit_evictions) hitDetails.push(`${hooks.hit_evictions} evicted`);
        if (requests.length) hitDetails.push(`${requests.length} ${requests.length === 1 ? 'request' : 'requests'}`);
        elements.hooksHitMeta.textContent = hitDetails.join(' · ');
        elements.hooksHitMeta.hidden = !hitDetails.length;
        const key = JSON.stringify([hits, requests, total, hooks?.hit_evictions, hooks?.last_failure]);
        if (key === state.runtimeHookHitsKey) return;
        state.runtimeHookHitsKey = key;
        if (!hits.length && !requests.length) {
          elements.hooksHits.replaceChildren(textElement('div', 'experiment-empty', 'Arm a hook, then exercise the isolated page.'));
          return;
        }
        const events = [
          ...hits.map(hit => ({kind: 'hit', occurred_at_ms: hit.occurred_at_ms, id: hit.id, value: hit})),
          ...requests.map(request => ({kind: 'request', occurred_at_ms: request.occurred_at_ms, id: request.id, value: request}))
        ].sort((left, right) => left.occurred_at_ms - right.occurred_at_ms ||
          (left.kind === right.kind ? left.id - right.id : left.kind === 'hit' ? -1 : 1));
        const rows = events.map(event => {
          if (event.kind === 'request') {
            const request = event.value;
            const row = document.createElement('button'); row.type = 'button'; row.className = 'hook-hit-row hook-hit-link';
            row.setAttribute('aria-label', `Show ${request.method} ${request.target_type || 'worker'} request in Traffic`);
            row.addEventListener('click', () => revealRuntimeHookRequest(request));
            row.append(
              textElement('span', 'hook-hit-title', `${request.method} ${request.url}`),
              textElement('span', 'hook-hit-operation', request.status === null ? 'pending' : String(request.status)),
              textElement('span', 'hook-hit-meta', `${new Date(request.occurred_at_ms).toLocaleTimeString()} · observed ${request.target_type || 'worker'} request ${request.target_id.slice(0, 12)} · ${request.resource_type || 'resource'}`),
              textElement('span', 'hook-hit-bindings', request.related_hit_ids.length
                ? `Related hits ${request.related_hit_ids.join(', ')} · ${request.relation}; not proof of a causal call chain`
                : 'No hook hit linked to this request')
            );
            return row;
          }
          const hit = event.value;
          const row = document.createElement('button'); row.type = 'button'; row.className = 'hook-hit-row hook-hit-link';
          row.setAttribute('aria-label', `Show ${hit.label} ${hit.category} hit in Sources`);
          row.addEventListener('click', () => revealRuntimeHookHit(hit));
          const title = textElement('span', 'hook-hit-title', `${hit.label} · ${hit.function}`);
          const operation = textElement('span', 'hook-hit-operation', hit.operation.replaceAll('_', ' '));
          const source = sourceName({url: hit.source, source_type: 'script', script_id: ''});
          const meta = textElement('span', 'hook-hit-meta',
            `${new Date(hit.occurred_at_ms).toLocaleTimeString()} · ${hit.target_type} ${hit.target_id.slice(0, 12)} · ${hit.category} · ${source}:${hit.line + 1}:${hit.column + 1} · session ${hit.session_id} / hook ${hit.hook_id} / hit ${hit.id}`);
          const values = hit.bindings.map(binding => `${binding.name}=${debuggerValueText(binding.value)}`);
          const returnText = hit.category === 'return'
            ? `return ${debuggerValueText(hit.original_return)}${hit.replacement_return ? ` → ${debuggerValueText(hit.replacement_return)}` : ''}` : '';
          const bindingText = [...values, returnText].filter(Boolean).join(' · ') || 'No local data properties captured';
          const bindings = textElement('span', 'hook-hit-bindings', `${bindingText}${hit.bindings_truncated ? ' · binding limit reached' : ''}`);
          row.append(title, operation, meta, bindings);
          if (hit.error) row.append(textElement('span', 'hook-hit-error', hit.error));
          return row;
        });
        elements.hooksHits.replaceChildren(...rows);
      }

      function revealRuntimeHookRequest(request) {
        if (investigationScreen() === 'traffic') investigationNavigation?.record();
        state.selectedRuntimeHookRequest = {sessionId: runtimeHooksState()?.session_id, id: request.id};
        state.runtimeHookTrafficKey = null;
        showScreen('traffic');
        renderRuntimeHookTraffic();
        requestAnimationFrame(() => elements.runtimeHookTraffic.focus({preventScroll: true}));
      }

      function renderRuntimeHookTraffic() {
        const selected = state.selectedRuntimeHookRequest;
        elements.runtimeHookTraffic.hidden = !selected;
        if (!selected) return;
        const hooks = runtimeHooksState();
        const request = hooks?.session_id === selected.sessionId
          ? hooks.requests.find(candidate => candidate.id === selected.id) : null;
        const related = request?.related_hit_ids.map(id => hooks.hits.find(hit => hit.id === id)).filter(Boolean) ?? [];
        const key = JSON.stringify([selected, request, related]);
        if (key === state.runtimeHookTrafficKey) return;
        state.runtimeHookTrafficKey = key;
        const close = document.createElement('button'); close.type = 'button'; close.className = 'source-tool';
        close.textContent = 'Close'; close.setAttribute('aria-label', 'Close request trail');
        close.addEventListener('click', () => {
          state.selectedRuntimeHookRequest = null;
          state.runtimeHookTrafficKey = null;
          elements.runtimeHookTraffic.hidden = true;
          elements.requestFilter.focus({preventScroll: true});
        });
        if (!request) {
          elements.runtimeHookTraffic.replaceChildren(
            textElement('span', 'runtime-hook-traffic-status', 'This ephemeral request is no longer available.'), close);
          return;
        }
        const title = textElement('strong', 'runtime-hook-traffic-title', `${request.method} ${request.url}`);
        const status = textElement('span', 'runtime-hook-traffic-status',
          `${request.status ?? 'Pending'} · ${request.resource_type || 'resource'} · isolated ${request.target_type || 'worker'} ${request.target_id.slice(0, 12)}`);
        const relation = textElement('span', 'runtime-hook-traffic-relation',
          related.length ? `${request.relation}; not proof of a causal call chain`
            : 'No retained hook hit is linked to this request.');
        const heading = textElement('span', 'runtime-hook-traffic-heading', 'Isolated request trail · ephemeral, separate from captured requests');
        const links = related.map(hit => {
          const button = document.createElement('button'); button.type = 'button'; button.className = 'source-tool';
          button.textContent = `Hit ${hit.id} · ${hit.category} in Sources`;
          button.addEventListener('click', () => revealRuntimeHookHit(hit));
          return button;
        });
        const testField = document.createElement('button'); testField.type = 'button'; testField.className = 'source-tool';
        testField.textContent = ['arming', 'armed', 'handling', 'stopping'].includes(hooks?.state)
          ? 'Disarm to test a value' : 'Test a request value';
        testField.addEventListener('click', async () => {
          if (['arming', 'armed', 'handling', 'stopping'].includes(runtimeHooksState()?.state)) {
            const response = currentExperimentReceipt(await runExperimentAction({action: 'disarm_runtime_hooks'}));
            if (!response) return;
          }
          elements.hooksFieldUrl.value = request.url;
          elements.hooksFieldMethod.value = request.method;
          elements.hooksFieldConfirm.checked = false;
          showScreen('sources');
          if (!state.sourceHooksOpen) openSourceHooks(false, false);
          renderRuntimeHooks();
          focusRuntimeFieldTest();
        });
        elements.runtimeHookTraffic.replaceChildren(heading, title, status, relation, ...links, testField, close);
      }

      function revealRuntimeHookHit(hit) {
        const sources = liveSources().filter(candidate => candidate.target_id === hit.target_id &&
          hit.script_id && hit.source_hash && candidate.script_id === hit.script_id && candidate.hash === hit.source_hash);
        const source = sources.length === 1 ? sources[0] : null;
        if (!source) {
          state.experimentError = 'This hit has no unambiguous attached target, script and hash identity. A URL match cannot establish its original source location.';
          showScreen('sources');
          if (!state.sourceHooksOpen) openSourceHooks(false, false);
          else renderRuntimeHooks();
          return;
        }
        showScreen('sources');
        if (!state.sourceHooksOpen) openSourceHooks(false, false);
        if (selectScript(source.script_id, hit.line) === false) return;
        if (!setSourceCursor(source, hit.line, hit.column)) return;
        elements.sourcePosition.textContent = `Line ${hit.line + 1}, Column ${hit.column + 1}`;
        const identity = sourceIdentity(source);
        requestAnimationFrame(() => {
          if (sourceIdentity(selectedSource()) === identity && !document.querySelector('#screen-sources').hidden) elements.sourceCodeWrap.focus({preventScroll: true});
        });
      }

      function renderRuntimeHooks() {
        const experiment = requestInterception();
        const objectExperiment = objectExperimentState();
        const hooks = runtimeHooksState();
        const attached = ['running', 'paused'].includes(state.debuggerSession?.state);
        const activeStates = ['arming', 'armed', 'handling', 'stopping'];
        const active = activeStates.includes(hooks?.state);
        const objectBusy = ['navigating', 'searching', 'mutating'].includes(objectExperiment?.state);
        const requestBusy = ['running', 'cancelling'].includes(repeaterState()?.state);
        const automationBusy = automationRecipesState()?.auto_armed ||
          ['arming', 'running', 'stopping'].includes(automationRecipesState()?.state);
        const contextWorking = state.experimentPending || ['creating', 'disposing'].includes(experiment?.state) ||
          objectBusy || requestBusy || automationBusy;
        const contextReady = attached && experiment?.isolated && hooks?.isolated &&
          experiment.target_id === state.debuggerSession?.target?.id && hooks.target_id === state.debuggerSession?.target?.id &&
          ['ready', 'error'].includes(experiment.state) && !['attaching', 'disposing', 'disposed'].includes(hooks.state);
        const pageReady = contextReady && objectExperiment?.navigation_id > 0 && objectExperiment.url;
        const canDispose = experiment?.isolated && experiment.pending_requests === 0 && !active && !contextWorking;
        const editable = contextReady && !active && !contextWorking;
        const hookableScripts = (state.debuggerSession?.scripts ?? []).filter(script => {
          if (script.language !== 'JavaScript') return false;
          const url = script.url ?? '';
          return !url.startsWith('file:') && !url.startsWith('evaluate;') && !url.startsWith('pptr:');
        });
        const workerScripts = hookableScripts.filter(script => script.target_type === 'worker').slice(-128);
        const scripts = [
          ...workerScripts,
          ...hookableScripts.filter(script => script.target_type !== 'worker').slice(-(256 - workerScripts.length))
        ];
        elements.hooksWorkspace.dataset.sourceReady = String(Boolean(pageReady && scripts.length));
        const selectedScript = elements.hooksScript.value;
        const options = scripts.map(script => {
          const option = document.createElement('option'); option.value = script.script_id;
          option.textContent = `${script.target_type === 'worker' ? `Worker ${script.target_id.slice(0, 12)}` : 'Page'} · ${sourceName({...script, source_type: 'script'})} · lines ${script.start_line + 1}-${script.end_line + 1}`;
          return option;
        });
        if (!options.length) {
          const option = document.createElement('option'); option.value = ''; option.textContent = 'No live JavaScript sources';
          options.push(option);
        }
        elements.hooksScript.replaceChildren(...options);
        if (scripts.some(script => script.script_id === selectedScript)) elements.hooksScript.value = selectedScript;

        elements.experimentTitle.textContent = 'Runtime Hooks';
        elements.experimentSubtitle.textContent = 'Observe function calls or test return values on a disposable page or its worker.';
        if (state.experimentError) setExperimentNotice('error', state.experimentError);
        else if (!experiment || !hooks || !objectExperiment) setExperimentNotice('error', 'The debugger session is unavailable or malformed.');
        else if (contextWorking || ['arming', 'handling', 'stopping'].includes(hooks.state)) setExperimentNotice('working', hooks.message);
        else if (hooks.last_failure) setExperimentNotice('error', hooks.last_failure);
        else if (hooks.state === 'armed' || contextReady || hooks.state === 'disposed') setExperimentNotice('ready', hooks.message);
        else if (!attached) setExperimentNotice('idle', 'Connect a browser target to configure hooks.');
        else setExperimentNotice('idle', hooks.message);

        elements.hooksContextBadge.dataset.kind = hooks?.state === 'error' ? 'error' : hooks?.isolated ? '' : 'offline';
        elements.hooksContextBadge.textContent = experiment?.state === 'creating' ? 'Creating'
          : experiment?.state === 'disposing' ? 'Disposing' : hooks?.isolated ? 'Isolated'
            : hooks?.state === 'disposed' ? 'Disposed' : 'Not created';
        const workerCount = hooks?.workers?.length ?? 0;
        const workerOverflow = hooks?.worker_overflow ?? 0;
        elements.hooksContextMessage.textContent = workerCount || workerOverflow
          ? `${workerCount} ${workerCount === 1 ? 'worker' : 'workers'} discovered${workerOverflow ? ` · ${workerOverflow} beyond the attachment limit` : ''}`
          : '';
        elements.hooksContextMessage.hidden = !(workerCount || workerOverflow);
        elements.hooksStorageState.textContent = hooks?.isolated ? 'Ephemeral and isolated'
          : hooks?.state === 'disposed' ? 'Deleted and erased' : 'Not allocated';
        elements.hooksPointUsage.textContent = `${hooks?.active_points ?? 0} / ${hooks?.limits?.active_points ?? 64}`;
        elements.hooksPageBadge.dataset.kind = pageReady ? '' : objectExperiment?.state === 'error' ? 'error' : 'offline';
        elements.hooksPageBadge.textContent = objectExperiment?.state === 'navigating' ? 'Opening' : pageReady ? 'Loaded' : 'No page';
        const stateLabels = {arming: 'Arming', armed: 'Armed', handling: 'Handling', stopping: 'Stopping',
          disarmed: 'Disarmed', ready: 'Disarmed', error: 'Error'};
        elements.hooksStateBadge.textContent = stateLabels[hooks?.state] ?? 'Disarmed';
        elements.hooksStateBadge.dataset.kind = hooks?.last_failure ? 'error' : hooks?.state === 'armed' ? '' : 'offline';

        elements.hooksCreate.disabled = !attached || Boolean(experiment?.isolated) || contextWorking || state.debuggerActionPending;
        elements.hooksDispose.disabled = !canDispose || state.debuggerActionPending;
        elements.hooksClear.disabled = !(hooks?.hits.length || hooks?.requests.length) || active || contextWorking || state.debuggerActionPending;
        elements.hooksPageUrl.disabled = !editable;
        elements.hooksNavigate.disabled = !editable || state.debuggerActionPending;
        elements.hooksDefinitionForm.querySelectorAll('input, select, textarea').forEach(field => { field.disabled = !editable; });
        const functionMode = elements.hooksEntryMode.value === 'function';
        elements.hooksSourceLocationFields.hidden = functionMode;
        elements.hooksFunctionExpressionField.hidden = !functionMode;
        elements.hooksReturnEnabled.disabled = !editable || functionMode;
        elements.hooksReturnLogic.disabled = !editable || functionMode;
        elements.hooksReturnMode.disabled = !editable || functionMode;
        elements.hooksReturnValueField.hidden = functionMode || elements.hooksReturnMode.value === 'none';
        elements.hooksReturnValueField.firstChild.textContent = elements.hooksReturnMode.value === 'json'
          ? 'Replacement JSON' : 'Replacement frame expression';
        elements.hooksAdd.disabled = !editable || !scripts.length || !elements.hooksLabel.value.trim() ||
          (!elements.hooksEntryEnabled.checked && !elements.hooksReturnEnabled.checked) ||
          (functionMode && !elements.hooksFunctionExpression.value.trim()) || state.debuggerActionPending;
        elements.hooksConfirm.disabled = !contextReady || active || !hooks?.definitions.length || contextWorking;
        elements.hooksArm.disabled = !editable || !hooks?.definitions.length || !elements.hooksConfirm.checked || state.debuggerActionPending;
        elements.hooksDisarm.disabled = !active || state.debuggerActionPending;
        renderRuntimeHookDefinitions(hooks, active);
        renderRuntimeHookHits(hooks);
        renderRuntimeFieldTest(hooks, editable, contextReady && !contextWorking &&
          !['arming', 'handling', 'stopping'].includes(hooks?.state));
        elements.sourceHooksNotice.dataset.kind = elements.experimentNotice.dataset.kind;
        elements.sourceHooksNotice.textContent = hooks?.state === 'armed' && !state.experimentError && !hooks.last_failure
          ? `Armed · ${hooks.total_hits} ${hooks.total_hits === 1 ? 'hit' : 'hits'}`
          : elements.experimentNotice.textContent;
        elements.sourceHooksNotice.hidden = !state.sourceHooksOpen ||
          (contextReady && !active && !contextWorking && !state.experimentError && !hooks?.last_failure);
      }

      function parseAutomationVariables() {
        const source = elements.automationVariables.value.trim();
        if (!source) return {};
        let variables;
        try { variables = JSON.parse(source); }
        catch { throw new TypeError('Automation variables must be valid JSON.'); }
        if (!isPlainObject(variables) || Object.values(variables).some(value => typeof value !== 'string')) {
          throw new TypeError('Automation variables must map names to text values.');
        }
        if (Object.keys(variables).length > 32 || Object.entries(variables).some(([name, value]) =>
          !/^[A-Za-z_][A-Za-z0-9_.-]*$/.test(name) || utf8ByteLength(name) > 128 || utf8ByteLength(value) > 4 * 1024)) {
          throw new TypeError('Automation variables exceed the visible name, count, or 4 KiB value limits.');
        }
        const total = Object.entries(variables).reduce((bytes, [name, value]) =>
          bytes + utf8ByteLength(name) + utf8ByteLength(value), 0);
        if (total > 16 * 1024) throw new TypeError('Automation variables exceed the 16 KiB session limit.');
        return variables;
      }

      function resetAutomationEditor() {
        state.automationEditingRecipeId = null;
        elements.automationLabel.value = '';
        elements.automationTrigger.value = 'manual';
        elements.automationEnabled.checked = true;
        elements.automationSource.value = '';
      }

      function editAutomationRecipe(recipeId) {
        const recipe = automationRecipesState()?.recipes.find(candidate => candidate.id === recipeId);
        if (!recipe) return;
        state.automationEditingRecipeId = recipe.id;
        elements.automationLabel.value = recipe.label;
        elements.automationTrigger.value = recipe.trigger;
        elements.automationEnabled.checked = recipe.enabled;
        elements.automationSource.value = recipe.source;
        renderAutomationRecipes();
        elements.automationLabel.focus();
      }

      function renderAutomationRecipeLibrary(automation, libraryEditable, canRun) {
        const recipes = automation?.recipes ?? [];
        elements.automationRecipeCount.textContent = `${recipes.length} / ${automation?.limits?.recipes ?? 16}`;
        elements.automationRecipeCount.dataset.kind = recipes.length ? '' : 'offline';
        elements.automationSourceUsage.textContent = `${Math.ceil((automation?.source_bytes ?? 0) / 1024)} / 64 KiB`;
        elements.automationSourceUsage.dataset.kind = recipes.length ? '' : 'offline';
        if (!recipes.length) {
          elements.automationRecipes.replaceChildren(textElement('div', 'experiment-empty', 'No page-context recipes configured.'));
          return;
        }
        elements.automationRecipes.replaceChildren(...recipes.map(recipe => {
          const row = document.createElement('div'); row.className = 'automation-recipe-row';
          const title = textElement('span', 'automation-recipe-title', recipe.label);
          const trigger = textElement('span', 'automation-trigger', recipe.enabled ? recipe.trigger : 'disabled');
          const meta = textElement('span', 'automation-recipe-meta',
            `recipe ${recipe.id} · ${recipe.source_bytes.toLocaleString()} source bytes · ${recipe.trigger === 'manual' ? 'manual execution' : 'automatic and manual execution'}`);
          const actions = document.createElement('div'); actions.className = 'automation-recipe-actions';
          const run = document.createElement('button'); run.type = 'button'; run.textContent = 'Run now';
          run.disabled = !canRun || !elements.automationConfirm.checked;
          run.setAttribute('aria-label', `Run ${recipe.label} now`);
          run.addEventListener('click', () => runAutomationRecipe(recipe.id));
          const edit = document.createElement('button'); edit.type = 'button'; edit.textContent = 'Edit';
          edit.disabled = !libraryEditable;
          edit.addEventListener('click', () => editAutomationRecipe(recipe.id));
          const remove = document.createElement('button'); remove.type = 'button'; remove.textContent = 'Remove';
          remove.disabled = !libraryEditable;
          remove.addEventListener('click', async () => {
            const response = currentExperimentReceipt(await runExperimentAction({action: 'remove_automation_recipe', recipe_id: recipe.id}));
            if (response && state.automationEditingRecipeId === recipe.id) resetAutomationEditor();
          });
          actions.append(run, edit, remove);
          row.append(title, trigger, meta, actions);
          return row;
        }));
      }

      function selectAutomationRun(runId, focus = false) {
        if (!automationRecipesState()?.runs.some(run => run.id === runId)) return;
        state.automationSelectedRunId = runId;
        renderAutomationRecipes();
        if (focus) elements.automationRuns.querySelector(`[data-automation-run-id="${runId}"]`)?.focus();
      }

      function renderAutomationTimeline(automation) {
        const runs = automation?.runs ?? [];
        if (!runs.some(run => run.id === state.automationSelectedRunId)) {
          state.automationSelectedRunId = runs.at(-1)?.id ?? null;
        }
        elements.automationRunCount.textContent = `${runs.length} / ${automation?.limits?.retained_runs ?? 64}`;
        elements.automationRunCount.dataset.kind = automation?.last_failure ? 'error' : runs.length ? '' : 'offline';
        elements.automationRunMeta.textContent = runs.length
          ? `${automation.total_runs} total · ${automation.automatic_runs} automatic · ${automation.run_evictions} evicted · ${automation.dropped_triggers} trigger batches dropped`
          : 'Time, source, trigger, outcome, and correlation IDs for every retained run.';
        if (!runs.length) {
          elements.automationRuns.replaceChildren(emptyListboxOption('experiment-empty', 'Run a recipe to see its bounded result and logs.'));
        } else {
          elements.automationRuns.replaceChildren(...[...runs].reverse().map(run => {
            const row = document.createElement('button'); row.type = 'button'; row.className = 'automation-run-row';
            row.dataset.automationRunId = String(run.id);
            row.setAttribute('role', 'option');
            row.setAttribute('aria-selected', String(run.id === state.automationSelectedRunId));
            const title = textElement('span', 'automation-run-title', run.label);
            const outcome = textElement('span', 'automation-outcome', run.operation.replaceAll('_', ' '));
            if (['failed', 'timed_out'].includes(run.operation)) outcome.style.color = 'var(--red)';
            const source = sourceName({url: run.source, source_type: 'script', script_id: ''});
            const meta = textElement('span', 'automation-run-meta',
              `${new Date(run.occurred_at_ms).toLocaleTimeString()} · ${source} · ${run.category} · ${run.duration_ms} ms · session ${run.session_id} / recipe ${run.recipe_id} / run ${run.id}`);
            row.append(title, outcome, meta);
            row.addEventListener('click', () => selectAutomationRun(run.id));
            return row;
          }));
        }
        const selected = runs.find(run => run.id === state.automationSelectedRunId) ?? null;
        elements.automationResultBadge.dataset.kind = selected
          ? ['failed', 'timed_out'].includes(selected.operation) ? 'error' : '' : 'offline';
        elements.automationResultBadge.textContent = selected ? selected.operation.replaceAll('_', ' ') : 'No result';
        elements.automationResultMeta.textContent = selected
          ? `${selected.result_type} · ${selected.duration_ms} ms · ${selected.logs.length} logs${selected.logs_truncated ? ' · log limit reached' : ''}`
          : 'Select a completed run.';
        if (!selected) {
          elements.automationResult.replaceChildren(textElement('div', 'experiment-empty', 'No run selected.'));
          return;
        }
        const output = document.createElement('pre');
        output.textContent = selected.error || selected.result_text || '[undefined]';
        const logs = document.createElement('div'); logs.className = 'automation-log-list';
        if (!selected.logs.length) logs.append(textElement('div', 'experiment-empty', 'No console output captured.'));
        else selected.logs.forEach(log => {
          const row = textElement('div', 'automation-log-row', `${log.level.toUpperCase()}  ${log.text}`);
          row.dataset.level = log.level;
          logs.append(row);
        });
        elements.automationResult.replaceChildren(output, logs);
      }

      function renderAutomationRecipes() {
        const experiment = requestInterception();
        const objectExperiment = objectExperimentState();
        const automation = automationRecipesState();
        const attached = ['running', 'paused'].includes(state.debuggerSession?.state);
        const autoBusy = ['arming', 'running', 'stopping'].includes(automation?.state) || automation?.active_run !== null;
        const otherBusy = ['navigating', 'searching', 'mutating'].includes(objectExperiment?.state) ||
          ['arming', 'armed', 'handling', 'stopping'].includes(runtimeHooksState()?.state) ||
          ['running', 'cancelling'].includes(repeaterState()?.state) || experiment?.state === 'running';
        const working = state.experimentPending || ['creating', 'disposing'].includes(experiment?.state) || autoBusy || otherBusy;
        const contextReady = attached && experiment?.isolated && automation?.isolated &&
          experiment.target_id === state.debuggerSession?.target?.id && automation.target_id === state.debuggerSession?.target?.id &&
          ['ready', 'error'].includes(experiment.state) && !['attaching', 'disposing', 'disposed'].includes(automation.state);
        const pageReady = contextReady && objectExperiment?.navigation_id > 0 && objectExperiment.url;
        const libraryEditable = !state.experimentPending && !automation?.auto_armed && !autoBusy && !otherBusy;
        const canRun = contextReady && !working && !automation?.auto_armed;
        const canDispose = experiment?.isolated && experiment.pending_requests === 0 && !autoBusy && !otherBusy;
        const automaticRecipes = automation?.recipes.filter(recipe => recipe.enabled && recipe.trigger !== 'manual').length ?? 0;

        elements.experimentTitle.textContent = 'Automation';
        elements.experimentSubtitle.textContent = 'Run a page script once or on a chosen trigger. Review each run and its logs.';
        if (state.experimentError) setExperimentNotice('error', state.experimentError);
        else if (!experiment || !automation || !objectExperiment) setExperimentNotice('error', 'The debugger session is unavailable or malformed.');
        else if (working) setExperimentNotice('working', automation.message);
        else if (automation.last_failure) setExperimentNotice('error', automation.last_failure);
        else if (automation.auto_armed || contextReady || automation.state === 'disposed') setExperimentNotice('ready', automation.message);
        else if (!attached) setExperimentNotice('idle', 'Connect a browser target to run automations.');
        else setExperimentNotice('idle', automation.message);

        elements.automationContextBadge.dataset.kind = automation?.state === 'error' ? 'error' : automation?.isolated ? '' : 'offline';
        elements.automationContextBadge.textContent = experiment?.state === 'creating' ? 'Creating'
          : experiment?.state === 'disposing' ? 'Disposing' : automation?.isolated ? 'Isolated'
            : automation?.state === 'disposed' ? 'Disposed' : 'Not created';
        elements.automationContextMessage.textContent = automation?.message ?? 'Recipe definitions stay local; execution requires a disposable context.';
        elements.automationStorageState.textContent = automation?.isolated ? 'Ephemeral execution'
          : automation?.state === 'disposed' ? 'Runs erased · recipes retained' : 'Definitions in memory';
        elements.automationRunUsage.textContent = `${automation?.total_runs ?? 0} / ${automation?.limits?.total_runs ?? 256}`;
        elements.automationPageBadge.dataset.kind = pageReady ? '' : objectExperiment?.state === 'error' ? 'error' : 'offline';
        elements.automationPageBadge.textContent = objectExperiment?.state === 'navigating' ? 'Opening' : pageReady ? 'Loaded' : 'No page';
        const stateLabels = {arming: 'Arming', armed: 'Armed', running: 'Running', stopping: 'Stopping', ready: 'Disarmed', error: 'Error'};
        elements.automationStateBadge.textContent = stateLabels[automation?.state] ?? 'Disarmed';
        elements.automationStateBadge.dataset.kind = automation?.last_failure ? 'error' : automation?.auto_armed ? '' : 'offline';

        elements.automationCreate.disabled = !attached || Boolean(experiment?.isolated) || working || state.debuggerActionPending;
        elements.automationDispose.disabled = !canDispose || state.debuggerActionPending;
        elements.automationClear.disabled = !automation?.runs.length || automation.auto_armed || autoBusy || state.debuggerActionPending;
        elements.automationPageUrl.disabled = !contextReady || autoBusy || otherBusy;
        elements.automationNavigate.disabled = !contextReady || autoBusy || otherBusy || state.debuggerActionPending;
        elements.automationVariables.disabled = !contextReady || automation?.auto_armed || autoBusy || otherBusy;
        elements.automationConfirm.disabled = !contextReady || autoBusy || otherBusy;
        elements.automationArm.disabled = !contextReady || autoBusy || otherBusy || automation?.auto_armed ||
          automaticRecipes === 0 || !elements.automationConfirm.checked || state.debuggerActionPending;
        elements.automationDisarm.disabled = !(automation?.auto_armed || automation?.active_run) || state.debuggerActionPending;
        elements.automationCancel.disabled = !automation?.active_run;
        elements.automationRecipeForm.querySelectorAll('input, select, textarea').forEach(field => { field.disabled = !libraryEditable; });
        elements.automationSave.disabled = !libraryEditable || !elements.automationLabel.value.trim() ||
          !elements.automationSource.value.trim() || state.debuggerActionPending;
        elements.automationSave.textContent = state.automationEditingRecipeId === null ? 'Add recipe' : 'Save recipe';
        elements.automationCancelEdit.hidden = state.automationEditingRecipeId === null;
        elements.automationCancelEdit.disabled = !libraryEditable;
        renderAutomationRecipeLibrary(automation, libraryEditable, canRun);
        renderAutomationTimeline(automation);
      }

      function renderExperiment() {
        elements.experimentModeButtons.forEach(button => {
          const selected = button.dataset.experimentMode === state.experimentMode;
          button.setAttribute('aria-selected', String(selected));
          button.tabIndex = selected ? 0 : -1;
        });
        elements.interceptionWorkspace.hidden = state.experimentMode !== 'interceptor';
        elements.repeaterWorkspace.hidden = state.experimentMode !== 'repeater';
        elements.objectWorkspace.hidden = state.experimentMode !== 'object';
        elements.hooksWorkspace.hidden = !state.sourceHooksOpen && state.experimentMode !== 'hooks';
        elements.automationWorkspace.hidden = state.experimentMode !== 'automation';
        renderActionScope();
        if (state.experimentMode === 'repeater') {
          renderRepeater();
          return;
        }
        if (state.experimentMode === 'object') {
          renderObjectExperiment();
          return;
        }
        if (state.experimentMode === 'hooks') {
          renderRuntimeHooks();
          return;
        }
        if (state.experimentMode === 'automation') {
          renderAutomationRecipes();
          return;
        }
        elements.experimentTitle.textContent = 'Interceptor';
        prefillExperimentRequest();
        setExperimentRuleVisibility();
        const experiment = requestInterception();
        const request = state.requests.find(candidate => candidate.id === state.selectedRequestId);
        const attached = ['running', 'paused'].includes(state.debuggerSession?.state);
        const hookBusy = ['arming', 'armed', 'handling', 'stopping'].includes(runtimeHooksState()?.state);
        const automationBusy = automationRecipesState()?.auto_armed || ['arming', 'running', 'stopping'].includes(automationRecipesState()?.state);
        const working = state.experimentPending || ['creating', 'running', 'disposing'].includes(experiment?.state) || hookBusy || automationBusy;
        const hasPendingRequests = (experiment?.pending_requests ?? 0) > 0;
        const contextReady = attached && experiment?.isolated &&
          experiment.target_id === state.debuggerSession?.target?.id && ['ready', 'error'].includes(experiment.state);
        const canDispose = experiment?.isolated && ['ready', 'error'].includes(experiment.state) && experiment.pending_requests === 0 && !hookBusy && !automationBusy;
        elements.experimentSubtitle.textContent = request && state.selectedField
          ? `request-${request.id} · ${state.selectedField.label} ${state.selectedField.path} · isolated replay only`
          : attached
            ? 'Debugger target running · request field optional · disposable context only'
            : 'Disposable context requires an attached debugger target';

        if (state.experimentError) setExperimentNotice('error', state.experimentError);
        else if (!experiment) setExperimentNotice('error', 'The debugger session is unavailable or malformed.');
        else if (working) setExperimentNotice('working', experiment.message);
        else if (experiment.state === 'error' || experiment.result?.ok === false) setExperimentNotice('error', experiment.message);
        else if (contextReady) setExperimentNotice('ready', experiment.message);
        else if (experiment.state === 'disposed') setExperimentNotice('ready', experiment.message);
        else if (!attached) setExperimentNotice('idle', 'Connect a browser target to intercept requests.');
        else if (!request || !state.selectedField) {
          setExperimentNotice('idle', 'Debugger target is running. Experiments are available without a selected request field; create a disposable context to begin.');
        }
        else setExperimentNotice('idle', experiment.message);

        const contextKind = experiment?.state === 'error' ? 'error' : experiment?.isolated ? '' : 'offline';
        elements.experimentContextBadge.dataset.kind = contextKind;
        elements.experimentContextBadge.textContent = experiment?.state === 'creating' ? 'Creating'
          : experiment?.state === 'disposing' ? 'Disposing'
            : experiment?.isolated ? 'Isolated'
              : experiment?.state === 'disposed' ? 'Disposed' : 'Not created';
        elements.experimentContextMessage.textContent = experiment?.state === 'error'
          ? experiment.message
          : experiment?.isolated
            ? contextReady ? 'Disposable page attached. Its cookies and storage are isolated from the baseline target.'
              : 'Disposable context exists. Waiting for its page debugger to attach.'
            : experiment?.message ?? 'No isolated browser context exists.';
        elements.experimentStorageState.textContent = experiment?.isolated ? 'Ephemeral and isolated'
          : experiment?.state === 'disposed' ? 'Deleted' : 'Not allocated';
        elements.experimentPendingCount.textContent = `${experiment?.pending_requests ?? 0} / ${experiment?.limits?.pending_requests ?? 16}`;

        elements.experimentCreate.disabled = !attached || Boolean(experiment?.isolated) || working || state.debuggerActionPending;
        elements.experimentDispose.disabled = !canDispose || working || state.debuggerActionPending;
        elements.experimentClear.disabled = !experiment || !['disposed', 'error'].includes(experiment.state) || experiment.isolated || working || state.debuggerActionPending;
        elements.experimentArmRule.disabled = !contextReady || hasPendingRequests || working || state.debuggerActionPending;
        elements.experimentRun.disabled = !contextReady || hasPendingRequests || working || state.debuggerActionPending;
        const fields = elements.experimentRuleForm.querySelectorAll('input, select, textarea');
        fields.forEach(field => { field.disabled = !contextReady || working; });
        elements.experimentRequestForm.querySelectorAll('input, textarea').forEach(field => { field.disabled = !contextReady || working; });

        const modeLabels = { continue: 'Continue', block: 'Block', drop: 'Drop', rewrite: 'Rewrite', fulfill: 'Fulfill' };
        elements.experimentRuleBadge.dataset.kind = contextReady ? '' : 'offline';
        elements.experimentRuleBadge.textContent = experiment && experiment.experiment_id > 0
          ? modeLabels[experiment.rule.mode] : 'Unarmed';
        renderExperimentResult(experiment);
        renderExperimentAudit(experiment);
      }

      function experimentLifetimeKey(session) {
        const experiment = session?.request_interception;
        return JSON.stringify([experiment?.experiment_id ?? 0, experiment?.created_at_ms ?? 0,
          experiment?.isolated ?? false, experiment?.target_id ?? null,
          ...['repeater', 'object_experiment', 'runtime_hooks', 'automation_recipes'].flatMap(group =>
            [session?.[group]?.session_id ?? 0, session?.[group]?.target_id ?? null])]);
      }

      function experimentContextKey() {
        return JSON.stringify([state.experimentContextEpoch ?? 0, experimentLifetimeKey(state.debuggerSession),
          state.debuggerSession?.target?.id ?? null]);
      }

      function currentExperimentReceipt(response) {
        const owner = response && state.experimentReceiptOwners?.get(response);
        if (!owner || owner.context !== experimentContextKey()) return null;
        const generation = Math.max(state.debuggerSession?.generation ?? 0, state.experimentReceipt?.generation ?? 0);
        if (response.generation < generation && owner.groups.some(group =>
            !experimentRecordMatches(state.debuggerSession[group === 'experiment' ? 'request_interception' : group], response[group]))) return null;
        return response;
      }

      function experimentEditorKey(names, selection = null) {
        return JSON.stringify([selection, ...names.map(name => [elements[name]?.value, elements[name]?.checked])]);
      }

      function repeaterSubmissionKey() {
        return JSON.stringify([experimentContextKey(), state.repeaterDraftRevision ?? 0, state.selectedRequestId,
          ...['repeaterRequestUrl', 'repeaterRequestMethod', 'repeaterRequestTimeout', 'repeaterRequestHeaders',
            'repeaterRequestBody', 'repeaterVariables'].map(name => elements[name].value)]);
      }

      function experimentActionGroups(action) {
        const families = [
          [['experiment', 'action_scope', 'object_experiment', 'runtime_hooks', 'automation_recipes', 'repeater'],
            ['create_request_interception_experiment', 'dispose_request_interception_experiment']],
          [['action_scope'], ['set_action_scope', 'close_experiment_page', 'create_experiment_page']],
          [['experiment'], ['configure_request_interception', 'run_request_interception', 'clear_request_interception_result']],
          [['object_experiment'], ['navigate_object_experiment', 'search_object_experiment', 'mutate_object_experiment']],
          [['runtime_hooks'], ['add_runtime_hook', 'remove_runtime_hook', 'arm_runtime_hooks', 'disarm_runtime_hooks',
            'clear_runtime_hook_hits', 'configure_runtime_field_test', 'compare_runtime_field_test']],
          [['automation_recipes'], ['add_automation_recipe', 'update_automation_recipe', 'remove_automation_recipe',
            'arm_automation_recipes', 'disarm_automation_recipes', 'cancel_automation_recipe', 'clear_automation_runs', 'run_automation_recipe']],
          [['repeater'], ['configure_repeater_variables', 'run_repeater_request', 'cancel_repeater_request',
            'compare_repeater_history', 'clear_repeater_history']]
        ];
        return families.find(([, actions]) => actions.includes(action))?.[0] ?? null;
      }

      function experimentReceiptBounded(value) {
        // Validators allow additive fields. Bound those fields as well before
        // retaining or comparing a receipt; never recurse over untrusted JSON.
        const pending = [[value, 0]];
        let nodes = 0, characters = 0;
        while (pending.length) {
          const [item, depth] = pending.pop();
          if (++nodes > 65536 || depth > 64) return false;
          if (typeof item === 'string') characters += item.length;
          if (characters > 4 * 1024 * 1024) return false;
          if (item && typeof item === 'object') {
            const keys = Object.keys(item);
            if (nodes + pending.length + keys.length > 65536) return false;
            for (const key of keys) {
              characters += key.length;
              if (characters > 4 * 1024 * 1024) return false;
              pending.push([item[key], depth + 1]);
            }
          }
        }
        return true;
      }

      function experimentRecordMatches(record, candidate) {
        if (!experimentReceiptBounded(record) || !experimentReceiptBounded(candidate)) return false;
        const pending = [[record, candidate]];
        while (pending.length) {
          const [left, right] = pending.pop();
          if (left === null || typeof left !== 'object') {
            if (left !== right) return false;
          } else {
            if (right === null || typeof right !== 'object' || Array.isArray(left) !== Array.isArray(right) ||
                (Array.isArray(left) && left.length !== right.length)) return false;
            // Additional alias fields are harmless; every authoritative field
            // must still be present and equal to the validated group record.
            for (const key of Object.keys(left)) {
              if (!Object.hasOwn(right, key)) return false;
              pending.push([left[key], right[key]]);
            }
          }
        }
        return true;
      }

      function isExperimentReceipt(response, request, submittedGeneration) {
        const groups = experimentActionGroups(request.action);
        if (!groups || !isPlainObject(response) || response.ok !== true ||
            !isSafeIntegerInRange(response.generation, submittedGeneration, Number.MAX_SAFE_INTEGER) ||
            !experimentReceiptBounded(response)) return false;
        const validators = {experiment: isRequestInterception, action_scope: isActionScope,
          object_experiment: isObjectExperiment, runtime_hooks: isRuntimeHooks,
          automation_recipes: isAutomationRecipes, repeater: isRepeater};
        if (groups.some(group => !validators[group](response[group]))) return false;
        if (['create_request_interception_experiment', 'dispose_request_interception_experiment'].includes(request.action)) {
          const experiment = response.experiment;
          const isolated = request.action === 'create_request_interception_experiment';
          if (experiment.isolated !== isolated || (isolated ? experiment.state !== 'ready' : experiment.state !== 'disposed') ||
              ['repeater', 'object_experiment', 'runtime_hooks', 'automation_recipes'].some(group =>
                response[group].session_id !== experiment.experiment_id || (group !== 'repeater' &&
                  (response[group].isolated !== isolated || response[group].target_id !== experiment.target_id)))) return false;
        }
        if (request.action === 'create_experiment_page' &&
            (!isBoundedText(response.target_id, 4096) || !response.target_id ||
             !response.action_scope.targets.some(target => target.id === response.target_id))) return false;
        if (['add_automation_recipe', 'update_automation_recipe'].includes(request.action)) {
          const recipe = response.automation_recipes.recipes.find(item => item.id === response.recipe?.id);
          if (!recipe || !experimentRecordMatches(recipe, response.recipe) ||
              (request.action === 'update_automation_recipe' && recipe.id !== request.recipe_id)) return false;
        }
        if (request.action === 'run_automation_recipe') {
          if (!Array.isArray(response.runs) || response.runs.length > 8 ||
              response.runs.some((run, index) => !run || run.recipe_id !== request.recipe_id ||
                response.runs.findIndex(other => other?.id === run.id) !== index ||
                !response.automation_recipes.runs.some(record => experimentRecordMatches(record, run))) ||
              !(response.runs.length ? experimentRecordMatches(response.runs.at(-1), response.run) : response.run === null)) return false;
        }
        return true;
      }

      function clearExperimentLifetime() {
        for (const name of ['objectConfirm', 'hooksConfirm', 'hooksFieldConfirm', 'automationConfirm']) {
          if (elements[name]) elements[name].checked = false;
        }
        for (const name of ['actionScopeNewUrl', 'actionScopeTarget', 'repeaterRequestUrl', 'repeaterRequestHeaders',
          'repeaterRequestBody', 'repeaterVariables', 'experimentRequestUrl', 'experimentRequestHeaders',
          'experimentRequestBody', 'experimentMethodFilter', 'experimentRewriteUrl', 'experimentRewriteMethod',
          'experimentRewriteHeaders', 'experimentRewriteBody', 'experimentResponseHeaders', 'experimentResponseBody',
          'objectPageUrl', 'objectPropertyQuery', 'objectValueQuery', 'objectClassQuery', 'objectShapeQuery',
          'objectMutationProperty', 'objectMutationValue', 'hooksPageUrl', 'hooksLabel', 'hooksScript',
          'hooksCondition', 'hooksEntryLogic', 'hooksReturnLogic', 'hooksReturnValue', 'hooksFunctionExpression',
          'hooksFieldUrl', 'hooksFieldPointer', 'automationPageUrl', 'automationVariables', 'automationLabel', 'automationSource']) {
          if (elements[name]) elements[name].value = '';
        }
        const defaults = {repeaterRequestMethod: 'GET', repeaterRequestTimeout: '15000', experimentRequestMethod: 'GET',
          experimentUrlPattern: '*', experimentRuleMode: 'continue', experimentResponseCode: '200', objectOperation: 'set',
          objectSimilarityThreshold: '0.75', hooksEntryMode: 'source', hooksLine: '1', hooksColumn: '1',
          hooksReturnMode: 'none', hooksFieldMethod: 'POST', hooksFieldKind: 'json', automationTrigger: 'manual'};
        for (const [name, value] of Object.entries(defaults)) if (elements[name]) elements[name].value = value;
        for (const [name, checked] of Object.entries({objectRegex: false, objectCaseSensitive: false, objectShapeValues: false,
          hooksEntryEnabled: true, hooksReturnEnabled: false, automationEnabled: true})) {
          if (elements[name]) elements[name].checked = checked;
        }
        // Hidden workspaces also own disposable previews and text. Erase them
        // immediately; polling only renders the currently visible workspace.
        for (const name of ['repeaterHeaderRows', 'repeaterQueryRows', 'repeaterHistory', 'repeaterResponse', 'repeaterResponseMeta',
          'repeaterComparison', 'repeaterBodyDiff', 'repeaterCompareBaseline', 'repeaterCompareCurrent', 'repeaterVariableStatus',
          'repeaterActiveRequest', 'experimentResult', 'experimentResultMeta', 'experimentAudit', 'experimentArmedRule',
          'objectResults', 'objectPreview', 'objectMutationResult', 'objectAudit', 'objectSearchMeta', 'objectSelectionMeta',
          'hooksDefinitions', 'hooksHits', 'hooksHitMeta', 'hooksFieldObservations', 'hooksFieldBaseline', 'hooksFieldVariant',
          'hooksFieldResult', 'hooksFieldStatus', 'sourceHooksNotice', 'runtimeHookTraffic', 'automationRuns', 'automationRunMeta',
          'automationResult', 'automationResultMeta', 'actionScopeTargets']) {
          const node = elements[name];
          if (!node) continue;
          node.textContent = ''; node.title = '';
          if (node.dataset) { delete node.dataset.renderKey; delete node.dataset.optionKey; }
        }
        if (elements.runtimeHookTraffic) elements.runtimeHookTraffic.hidden = true;
        // Collection definitions/drafts are durable, but these claims identify
        // executions in the disposable lifetime and may not survive reused IDs.
        state.collectionRunOwners?.clear();
        Object.assign(state, {collectionSubmittedOwners: [], collectionPendingRunSelection: null,
          collectionPendingSubmission: null, collectionRunPending: false, collectionSelectedHistoryId: null});
        Object.assign(state, {experimentError: null, repeaterDraftDirty: false, repeaterVariablesDirty: false, repeaterVariablesKey: null,
          repeaterSelectedHistoryId: null, repeaterExpectedHistoryId: null, experimentPrefillKey: null, repeaterPrefillKey: null,
          repeaterHeadersSource: null, repeaterQuerySource: null, repeaterCompareBaselineId: null, repeaterCompareCurrentId: null,
          repeaterComparisonKey: null, objectSelectedResultId: null, objectSelectionSearchId: 0, automationEditingRecipeId: null,
          automationSelectedRunId: null, actionScopeDraftMode: null, actionScopeDraftRevision: -1,
          selectedRuntimeHookRequest: null, runtimeHookTrafficKey: null, runtimeHookHitsKey: null, runtimeFieldTestKey: null});
      }

      function syncExperimentSession(previous, current, receiptAtPollStart = null, acknowledgement = false) {
        const receipt = state.experimentReceipt;
        state.experimentNeedsRefresh = false;
        if (!acknowledgement && receipt && current.generation < receipt.generation && receiptAtPollStart !== receipt) {
          // This GET was already in flight when the action was acknowledged.
          // Keep its unrelated state, but do not roll back the applied groups.
          state.experimentNeedsRefresh = true;
          current = {...current};
          for (const group of receipt.groups) current[group] = previous[group];
          return current;
        }
        const restarted = current.generation < previous?.generation || (!acknowledgement && receipt && current.generation < receipt.generation);
        const changed = experimentLifetimeKey(previous) !== experimentLifetimeKey(current);
        const targetChanged = (previous?.target?.id ?? null) !== (current.target?.id ?? null);
        if (restarted || changed || targetChanged) {
          state.experimentContextEpoch = (state.experimentContextEpoch ?? 0) + 1;
          state.repeaterSubmissionOwner = null;
          const before = previous?.request_interception, after = current.request_interception;
          let expired = false;
          for (const owner of state.experimentActionOwners ?? []) {
            let expected = false;
            if (!restarted && owner.action === 'create_request_interception_experiment' && !owner.initialIsolated) {
              const creation = JSON.stringify([after.experiment_id, after.created_at_ms]);
              if (after.experiment_id > 0 && after.created_at_ms > 0 && ['creating', 'ready', 'error'].includes(after.state)) {
                owner.creation ??= creation;
                expected = owner.creation === creation;
              }
            }
            if (!restarted && owner.action === 'dispose_request_interception_experiment') {
              expected = before?.experiment_id === after.experiment_id && before?.created_at_ms === after.created_at_ms &&
                (!owner.disposed || !after.isolated);
              owner.disposed ||= !after.isolated;
            }
            if (!expected) {
              expired = true;
              owner.expired = true;
              owner.transport?.retire?.('The disposable session ended. Native completion is unknown; no cancellation or retry was requested.');
              if (state.debuggerActionOwner === owner.transport) {
                state.debuggerActionOwner = null;
                state.debuggerActionPending = false;
              }
              if (state.experimentPrimaryOwner === owner) {
                state.experimentPrimaryOwner = null;
                state.experimentPending = false;
              }
            }
          }
          if ((restarted || changed) && previous?.request_interception?.experiment_id > 0) clearExperimentLifetime();
          if (expired) state.experimentError = 'The disposable session changed. Its pending action acknowledgement is unavailable; native completion is unknown. No cancellation or retry was sent.';
        }
        state.experimentReceipt = null;
        return current;
      }

      async function runExperimentAction(request) {
        const parallelControl = ['cancel_repeater_request', 'cancel_automation_recipe'].includes(request.action);
        if (state.experimentPending && !parallelControl) return null;
        const session = state.debuggerSession;
        if (!session || !experimentActionGroups(request.action)) return null;
        const owner = {action: request.action, initialIsolated: session.request_interception.isolated, expired: false,
          initialCreation: JSON.stringify([session.request_interception.experiment_id, session.request_interception.created_at_ms])};
        if (state.experimentNeedsRefresh) {
          state.experimentError = 'Waiting for a current debugger snapshot before another experiment action. No request was sent.';
          renderExperiment();
          return null;
        }
        state.experimentActionOwners ??= new Set();
        state.experimentActionOwners.add(owner);
        const generation = Math.max(session.generation, state.experimentReceipt?.generation ?? 0);
        if (!parallelControl) {
          state.experimentPending = true;
          state.experimentPrimaryOwner = owner;
        }
        state.experimentError = null;
        renderExperiment();
        let result = null;
        try {
          const response = await debuggerAction(request, null, owner);
          if (owner.expired) throw new Error('The disposable session changed while awaiting this action. Its acknowledgement is unavailable.');
          if (!response) throw new Error(state.debuggerError || 'The experiment action acknowledgement is unavailable.');
          if (response.ok === false) throw new Error(isBoundedText(response.error, 512) && response.error || 'The experiment action was rejected.');
          if (!isExperimentReceipt(response, request, generation)) throw new Error('The experiment action returned an invalid acknowledgement.');
          const current = state.debuggerSession;
          const next = {...current};
          const groups = experimentActionGroups(request.action).map(group => group === 'experiment' ? 'request_interception' : group);
          for (const group of experimentActionGroups(request.action)) next[group === 'experiment' ? 'request_interception' : group] = response[group];
          const lifecycle = ['create_request_interception_experiment', 'dispose_request_interception_experiment'].includes(request.action);
          const receiptCreation = JSON.stringify([response.experiment?.experiment_id, response.experiment?.created_at_ms]);
          if ((request.action === 'create_request_interception_experiment' && owner.creation && owner.creation !== receiptCreation) ||
              (request.action === 'dispose_request_interception_experiment' && owner.initialCreation !== receiptCreation) ||
              (!lifecycle && experimentLifetimeKey(next) !== experimentLifetimeKey(current))) {
            throw new Error('The experiment acknowledgement belongs to another disposable session.');
          }
          const latestGeneration = Math.max(current.generation, state.experimentReceipt?.generation ?? 0);
          if (response.generation < latestGeneration && experimentActionGroups(request.action).some(group =>
              !experimentRecordMatches(current[group === 'experiment' ? 'request_interception' : group], response[group]))) {
            throw new Error('Newer experiment state arrived before this acknowledgement. The current result and draft are retained.');
          }
          if (response.generation >= latestGeneration) {
            const retainedGroups = state.experimentReceipt?.groups ?? [];
            state.debuggerSession = syncExperimentSession(current, next, null, true);
            state.experimentReceipt = {generation: response.generation, groups: [...new Set([...retainedGroups, ...groups])]};
          }
          result = response;
        } catch (error) {
          if (!owner.expired) state.experimentError = `${error.message} No automatic retry was sent.`;
        } finally {
          state.experimentActionOwners.delete(owner);
          if (state.experimentPrimaryOwner === owner) {
            state.experimentPrimaryOwner = null;
            state.experimentPending = false;
          }
          if (!owner.expired) renderExperiment();
        }
        if (result && !owner.expired) {
          state.experimentReceiptOwners ??= new WeakMap();
          state.experimentReceiptOwners.set(result, {context: experimentContextKey(), groups: experimentActionGroups(request.action)});
        }
        return owner.expired ? null : result;
      }

      async function configureExperimentRule() {
        try {
          const mode = elements.experimentRuleMode.value;
          const request = {
            action: 'configure_request_interception',
            url_pattern: elements.experimentUrlPattern.value.trim(),
            method_filter: elements.experimentMethodFilter.value.trim(),
            mode
          };
          if (mode === 'rewrite') Object.assign(request, {
            rewrite_url: elements.experimentRewriteUrl.value.trim(),
            rewrite_method: elements.experimentRewriteMethod.value.trim(),
            rewrite_headers: parseExperimentHeaders(elements.experimentRewriteHeaders.value, 'Rewrite headers'),
            rewrite_body: elements.experimentRewriteBody.value
          });
          if (mode === 'fulfill') Object.assign(request, {
            response_code: Number(elements.experimentResponseCode.value),
            response_headers: parseExperimentHeaders(elements.experimentResponseHeaders.value, 'Response headers'),
            response_body: elements.experimentResponseBody.value
          });
          await runExperimentAction(request);
        } catch (error) {
          state.experimentError = error.message;
          renderExperiment();
        }
      }

      async function runExperimentRequest() {
        try {
          const method = elements.experimentRequestMethod.value.trim().toUpperCase();
          const body = elements.experimentRequestBody.value;
          if (['GET', 'HEAD'].includes(method) && body) throw new TypeError(`${method} requests cannot include a body.`);
          await runExperimentAction({
            action: 'run_request_interception',
            url: elements.experimentRequestUrl.value.trim(),
            method,
            headers: parseExperimentHeaders(elements.experimentRequestHeaders.value, 'Request headers'),
            body
          });
        } catch (error) {
          state.experimentError = error.message;
          renderExperiment();
        }
      }

      async function navigateObjectExperiment() {
        const url = elements.objectPageUrl.value.trim();
        if (!url) {
          state.experimentError = 'Enter one HTTP or HTTPS URL for the disposable page.';
          renderExperiment();
          elements.objectPageUrl.focus();
          return;
        }
        const response = currentExperimentReceipt(await runExperimentAction({action: 'navigate_object_experiment', url}));
        if (response) {
          state.objectSelectedResultId = null;
          state.objectSelectionSearchId = 0;
          elements.objectConfirm.checked = false;
          elements.objectMutationValue.value = '';
        }
      }

      async function searchObjectExperiment() {
        const threshold = Number(elements.objectSimilarityThreshold.value);
        if (!Number.isFinite(threshold) || threshold < 0 || threshold > 1) {
          state.experimentError = 'Similarity must be between 0 and 1.';
          renderExperiment();
          elements.objectSimilarityThreshold.focus();
          return;
        }
        const request = {
          action: 'search_object_experiment',
          property_query: elements.objectPropertyQuery.value,
          value_query: elements.objectValueQuery.value,
          class_query: elements.objectClassQuery.value,
          shape: elements.objectShapeQuery.value,
          similarity_threshold: threshold,
          regex: elements.objectRegex.checked,
          case_sensitive: elements.objectCaseSensitive.checked,
          include_shape_values: elements.objectShapeValues.checked
        };
        if (![request.property_query, request.value_query, request.class_query, request.shape].some(value => value.trim())) {
          state.experimentError = 'Enter at least one bounded live-object search criterion.';
          renderExperiment();
          elements.objectPropertyQuery.focus();
          return;
        }
        const response = currentExperimentReceipt(await runExperimentAction(request));
        if (response?.object_experiment) {
          state.objectSelectionSearchId = response.object_experiment.search_id;
          state.objectSelectedResultId = response.object_experiment.results[0]?.id ?? null;
          elements.objectConfirm.checked = false;
          elements.objectMutationValue.value = '';
          renderObjectExperiment();
        }
      }

      async function mutateObjectExperiment() {
        const experiment = objectExperimentState();
        const selected = selectedObjectExperimentResult(experiment);
        if (!selected || !experiment) return;
        const operation = elements.objectOperation.value;
        const property = elements.objectMutationProperty.value;
        if (!property) {
          state.experimentError = 'Enter one explicit own-property name.';
          renderExperiment();
          elements.objectMutationProperty.focus();
          return;
        }
        if (!elements.objectConfirm.checked) {
          state.experimentError = 'Confirm the disposable-page mutation before applying it.';
          renderExperiment();
          elements.objectConfirm.focus();
          return;
        }
        const request = {
          action: 'mutate_object_experiment',
          search_id: experiment.search_id,
          result_id: selected.id,
          operation,
          property,
          confirmed: true
        };
        if (operation === 'set') {
          try { request.value = JSON.parse(elements.objectMutationValue.value); }
          catch {
            state.experimentError = 'Set value must be valid JSON.';
            renderExperiment();
            elements.objectMutationValue.focus();
            return;
          }
        }
        const response = currentExperimentReceipt(await runExperimentAction(request));
        if (response) {
          elements.objectConfirm.checked = false;
          elements.objectMutationValue.value = '';
          renderObjectExperiment();
        }
      }

      async function navigateRuntimeHooks() {
        const url = elements.hooksPageUrl.value.trim();
        if (!url) {
          state.experimentError = 'Enter one HTTP or HTTPS URL for the disposable page.';
          renderExperiment();
          elements.hooksPageUrl.focus();
          return;
        }
        const response = currentExperimentReceipt(await runExperimentAction({action: 'navigate_object_experiment', url}));
        if (response) {
          elements.hooksConfirm.checked = false;
          renderRuntimeHooks();
        }
      }

      async function navigateAutomationRecipes() {
        const url = elements.automationPageUrl.value.trim();
        if (!url) {
          state.experimentError = 'Enter one HTTP or HTTPS URL for the disposable page.';
          renderExperiment();
          elements.automationPageUrl.focus();
          return;
        }
        await runExperimentAction({action: 'navigate_object_experiment', url});
      }

      async function saveAutomationRecipe() {
        const draft = () => experimentEditorKey(['automationLabel', 'automationTrigger', 'automationEnabled', 'automationSource'], state.automationEditingRecipeId);
        const submittedDraft = draft();
        const request = {
          action: state.automationEditingRecipeId === null ? 'add_automation_recipe' : 'update_automation_recipe',
          label: elements.automationLabel.value.trim(),
          trigger: elements.automationTrigger.value,
          enabled: elements.automationEnabled.checked,
          source: elements.automationSource.value
        };
        if (state.automationEditingRecipeId !== null) request.recipe_id = state.automationEditingRecipeId;
        if (!request.label || !request.source.trim()) {
          state.experimentError = 'Enter a recipe label and page-context JavaScript.';
          renderExperiment();
          (!request.label ? elements.automationLabel : elements.automationSource).focus();
          return;
        }
        const response = currentExperimentReceipt(await runExperimentAction(request));
        if (response && draft() === submittedDraft) resetAutomationEditor();
      }

      async function runAutomationRecipe(recipeId) {
        if (!elements.automationConfirm.checked) {
          state.experimentError = 'Confirm disposable-page code execution before running a recipe.';
          renderExperiment();
          elements.automationConfirm.focus();
          return;
        }
        try {
          const response = currentExperimentReceipt(await runExperimentAction({
            action: 'run_automation_recipe', recipe_id: recipeId, confirmed: true,
            variables: parseAutomationVariables()
          }));
          if (response?.run) state.automationSelectedRunId = response.run.id;
          if (response) elements.automationConfirm.checked = false;
        } catch (error) {
          state.experimentError = error.message;
          renderExperiment();
        }
      }

      async function addRuntimeHook() {
        const draft = () => experimentEditorKey(['hooksLabel', 'hooksScript', 'hooksLine', 'hooksColumn', 'hooksEntryMode',
          'hooksFunctionExpression', 'hooksEntryEnabled', 'hooksReturnEnabled', 'hooksCondition', 'hooksEntryLogic',
          'hooksReturnLogic', 'hooksReturnMode', 'hooksReturnValue'], state.selectedScriptId);
        const submittedDraft = draft();
        try {
          const line = Number(elements.hooksLine.value);
          const column = Number(elements.hooksColumn.value);
          if (!Number.isSafeInteger(line) || line < 1 || !Number.isSafeInteger(column) || column < 1) {
            throw new TypeError('Hook line and column must be positive integers.');
          }
          const returnMode = elements.hooksReturnMode.value;
          const request = {
            action: 'add_runtime_hook',
            label: elements.hooksLabel.value.trim(),
            script_id: elements.hooksScript.value,
            entry_mode: elements.hooksEntryMode.value,
            function_expression: elements.hooksFunctionExpression.value.trim(),
            line: line - 1,
            column: column - 1,
            entry_enabled: elements.hooksEntryEnabled.checked,
            return_enabled: elements.hooksReturnEnabled.checked,
            condition: elements.hooksCondition.value,
            entry_logic: elements.hooksEntryLogic.value,
            return_logic: elements.hooksReturnLogic.value,
            return_mode: returnMode
          };
          if (!request.label) throw new TypeError('Enter a short hook label.');
          if (!request.script_id) throw new TypeError('Choose one live JavaScript source.');
          if (!request.entry_enabled && !request.return_enabled) throw new TypeError('Enable entry, synchronous return, or both.');
          if (request.entry_mode === 'function' && (!request.function_expression || !request.entry_enabled || request.return_enabled)) {
            throw new TypeError('Live function targeting needs an expression and entry-only capture.');
          }
          if (returnMode === 'json') {
            try { request.return_value = JSON.parse(elements.hooksReturnValue.value); }
            catch { throw new TypeError('Return replacement must be valid JSON.'); }
          }
          if (returnMode === 'expression') {
            request.return_expression = elements.hooksReturnValue.value.trim();
            if (!request.return_expression) throw new TypeError('Enter one return-frame expression.');
          }
          const response = currentExperimentReceipt(await runExperimentAction(request));
          if (response && draft() === submittedDraft) {
            elements.hooksConfirm.checked = false;
            elements.hooksLabel.value = '';
            elements.hooksFunctionExpression.value = '';
            elements.hooksCondition.value = '';
            elements.hooksEntryLogic.value = '';
            elements.hooksReturnLogic.value = '';
            elements.hooksReturnMode.value = 'none';
            elements.hooksReturnValue.value = '';
            renderRuntimeHooks();
          }
        } catch (error) {
          state.experimentError = error.message;
          renderExperiment();
        }
      }

      function prefillHookFromSource(source) {
        const hooks = runtimeHooksState();
        if (source?.source_type !== 'script' || state.sourceDeobfuscated || state.sourceFormatted || !hooks?.isolated ||
            hooks.target_id !== state.debuggerSession?.target?.id) return false;
        const cursor = sourceCursorFor(source);
        const line = cursor?.line ?? source.start_line;
        elements.hooksScript.value = source.script_id;
        elements.hooksEntryMode.value = 'source';
        elements.hooksLine.value = String(line + 1);
        elements.hooksColumn.value = String((cursor?.column ?? sourceRuntimeColumn(source, 0)) + 1);
        if (!elements.hooksLabel.value) elements.hooksLabel.value = `${sourceName(source)}:${line + 1}`;
        return true;
      }

      function openSourceHooks(prefill = true, focus = true) {
        state.sourceHooksOpen = true;
        state.experimentMode = 'hooks';
        document.querySelector('#screen-sources').dataset.hooksOpen = 'true';
        document.querySelector('#screen-sources').append(elements.hooksWorkspace);
        elements.sourceHooksHits.append(elements.hooksHitsColumn);
        elements.hooksWorkspace.hidden = false;
        elements.sourceHooksHits.hidden = false;
        elements.sourceHooksNotice.hidden = false;
        elements.sourceHookPivot.setAttribute('aria-expanded', 'true');
        renderSourceSidebar();
        renderRuntimeHooks();
        if (prefill) {
          prefillHookFromSource(selectedSource());
          renderRuntimeHooks();
        }
        if (focus) requestAnimationFrame(() => {
          const field = [elements.hooksLabel, elements.hooksCreate, elements.hooksDisarm, elements.sourceHooksClose]
            .find(candidate => !candidate.disabled);
          field?.focus({preventScroll: true});
        });
      }

      function closeSourceHooks(restoreFocus = true) {
        state.sourceHooksOpen = false;
        document.querySelector('#screen-sources').dataset.hooksOpen = 'false';
        elements.hooksHome.after(elements.hooksWorkspace);
        elements.hooksHitsHome.after(elements.hooksHitsColumn);
        elements.sourceHooksHits.hidden = true;
        elements.sourceHooksNotice.hidden = true;
        elements.sourceHookPivot.setAttribute('aria-expanded', 'false');
        elements.hooksWorkspace.hidden = state.experimentMode !== 'hooks' || document.querySelector('#screen-experiments').hidden;
        renderSourceSidebar();
        if (restoreFocus) elements.sourceHookPivot.focus({preventScroll: true});
      }

      function pivotSourceToRuntimeHooks() {
        if (state.sourceHooksOpen) {
          closeSourceHooks();
          return;
        }
        if (!['running', 'paused'].includes(state.debuggerSession?.state)) return;
        openSourceHooks(Boolean(selectedSource()));
      }

      async function applyRepeaterVariables() {
        try {
          const draft = elements.repeaterVariables.value;
          const variables = parseRepeaterVariables(draft);
          const response = currentExperimentReceipt(await runExperimentAction({action: 'configure_repeater_variables', variables}));
          if (!response || elements.repeaterVariables.value !== draft) return null;
          state.repeaterVariablesDirty = false;
          state.repeaterVariablesKey = JSON.stringify(variables);
          renderRepeaterVariableStatus();
          return response;
        } catch (error) {
          state.experimentError = error.message;
          renderExperiment();
          return null;
        }
      }

      async function runRepeaterRequest() {
        if (state.repeaterSubmissionOwner) return;
        const owner = {key: repeaterSubmissionKey()};
        state.repeaterSubmissionOwner = owner;
        const current = () => state.repeaterSubmissionOwner === owner && owner.key === repeaterSubmissionKey();
        try {
          const previousHistoryId = repeaterState()?.history.at(-1)?.id ?? 0;
          const method = elements.repeaterRequestMethod.value.trim();
          const body = elements.repeaterRequestBody.value;
          const resolvedMethod = method.toUpperCase();
          if (['GET', 'HEAD'].includes(resolvedMethod) && body && !method.includes('{{')) {
            throw new TypeError(`${resolvedMethod} requests cannot include a body.`);
          }
          const timeout = Number(elements.repeaterRequestTimeout.value);
          if (!Number.isInteger(timeout) || timeout < 100 || timeout > 30000) {
            throw new TypeError('Repeater timeout must be between 100 and 30000 ms.');
          }
          const payload = {action: 'run_repeater_request', url: elements.repeaterRequestUrl.value.trim(), method,
            headers: parseExperimentHeaders(elements.repeaterRequestHeaders.value, 'Request headers'), body, timeout_ms: timeout};
          const applied = currentExperimentReceipt(await applyRepeaterVariables());
          if (!applied || !current() || state.repeaterVariablesDirty) return;
          const response = currentExperimentReceipt(await runExperimentAction(payload));
          if (!response || !current()) return;
          const executionId = response.repeater.active_execution?.execution_id ?? response.repeater.history.at(-1)?.id;
          if (Number.isSafeInteger(executionId) && executionId > previousHistoryId) {
            state.repeaterExpectedHistoryId = executionId;
            renderExperiment();
          }
          state.repeaterDraftDirty = false;
        } catch (error) {
          if (current()) {
            state.experimentError = error.message;
            renderExperiment();
          }
        } finally {
          if (state.repeaterSubmissionOwner === owner) state.repeaterSubmissionOwner = null;
        }
      }

      async function compareRepeaterResponses() {
        const baselineId = Number(elements.repeaterCompareBaseline.value);
        const currentId = Number(elements.repeaterCompareCurrent.value);
        if (!Number.isSafeInteger(baselineId) || !Number.isSafeInteger(currentId) || baselineId === currentId) return;
        state.repeaterCompareBaselineId = baselineId;
        state.repeaterCompareCurrentId = currentId;
        await runExperimentAction({
          action: 'compare_repeater_history', baseline_id: baselineId, current_id: currentId
        });
      }

      async function copyResolvedRepeaterRequest() {
        const entry = selectedRepeaterEntry();
        if (!entry) return;
        const request = {
          url: entry.resolved_request.url,
          method: entry.resolved_request.method,
          headers: repeaterHeaderObject(entry.resolved_request.headers),
          body: entry.resolved_request.body,
          timeout_ms: entry.resolved_request.timeout_ms
        };
        try {
          await navigator.clipboard.writeText(JSON.stringify(request, null, 2));
          setExperimentNotice('ready', `Resolved request from run ${entry.id} copied to the clipboard.`);
        } catch {
          state.experimentError = 'The resolved request could not be copied to the clipboard.';
          renderExperiment();
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

      function collectionNextRequestId() {
        // Do not recycle a deleted recipe ID while its ephemeral runs still exist.
        const repeater = repeaterState();
        return Math.max(collectionNextId(state.apiCollection.requests),
          (state.collectionPendingSubmission?.requestId ?? 0) + 1,
          ...(state.collectionSubmittedOwners ?? []).filter(owner => owner.targetId === requestInterception()?.target_id &&
            owner.experimentId === requestInterception()?.experiment_id).map(owner => owner.requestId + 1),
          ...[...(repeater?.history ?? []), repeater?.active_execution].map(entry =>
            Number.isSafeInteger(entry?.collection_request_id) ? entry.collection_request_id + 1 : 1));
      }

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
        const headers = parseExperimentHeaders(value, 'Request headers');
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
          elements.collectionResponse.setAttribute('aria-labelledby', `collection-response-tab-${tab}`);
          elements.collectionResponse.dataset.renderKey = '';
          renderCollectionExecution();
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
          elements.collectionRequestHeaders.value = request.headers.length
            ? JSON.stringify(repeaterHeaderObject(request.headers), null, 2) : '';
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

      function collectionRunKey(executionId) {
        return JSON.stringify([requestInterception()?.target_id, requestInterception()?.experiment_id, executionId]);
      }

      function rememberCollectionRunOwner(key, owner) {
        const owners = state.collectionRunOwners ??= new Map();
        owners.set(key, {requestId: owner.requestId, createdAt: owner.createdAt});
        while (owners.size > 25) owners.delete(owners.keys().next().value);
        return owners.get(key);
      }

      function collectionObservedRunOwner(entry, active = false) {
        const executionId = active ? entry?.execution_id : entry?.id;
        if (!entry || !Number.isSafeInteger(executionId)) return null;
        const key = collectionRunKey(executionId);
        const known = state.collectionRunOwners?.get(key);
        if (known) return known;
        // Polling can observe a run before its POST acknowledgement, or after
        // that acknowledgement is lost. Dispatch ownership must already exist.
        const candidates = (state.collectionSubmittedOwners ?? []).filter(owner =>
          owner.targetId === requestInterception()?.target_id && owner.experimentId === requestInterception()?.experiment_id &&
          owner.requestId === entry.collection_request_id && owner.executionId === undefined && executionId > owner.afterExecutionId);
        if (!candidates.length) return null;
        const owner = candidates[0];
        if (candidates.some(candidate => candidate.createdAt !== owner.createdAt)) return {ambiguous: true};
        owner.executionId = executionId;
        return rememberCollectionRunOwner(key, owner);
      }

      function collectionRunBelongsToRequest(entry, active = false) {
        const owner = collectionObservedRunOwner(entry, active);
        const request = collectionRequest();
        if (!request || !entry || entry.collection_request_id !== request.id || !Number.isSafeInteger(entry.started_at_ms) || entry.started_at_ms < request.created_at_ms) return false;
        return !owner || !owner.ambiguous && owner.requestId === request.id && owner.createdAt === request.created_at_ms;
      }

      function collectionHistoryEntries() {
        return (repeaterState()?.history ?? []).filter(entry => collectionRunBelongsToRequest(entry));
      }

      function collectionPendingRunForSelection() {
        const pending = state.collectionPendingRunSelection;
        if (!pending) return null;
        const request = collectionRequest();
        if (pending.selection !== state.collectionSelectionVersion || pending.historySelection !== state.collectionHistorySelectionVersion ||
            pending.requestId !== request?.id || pending.createdAt !== request?.created_at_ms ||
            pending.key !== collectionRunKey(pending.executionId) || !requestInterception()?.isolated) {
          state.collectionPendingRunSelection = null;
          return null;
        }
        return pending;
      }

      function renderCollectionResponse(entry) {
        const repeater = repeaterState();
        const running = ['running', 'cancelling'].includes(repeater?.state) &&
          collectionRunBelongsToRequest(repeater?.active_execution, true);
        const pending = collectionPendingRunForSelection();
        const pendingLabel = running ? ' · another run in progress' : pending ? ` · waiting for run ${pending.executionId}` : '';
        const key = JSON.stringify([requestInterception()?.experiment_id, state.collectionSelectedRequestId,
          entry?.id, state.collectionResponseTab, entry ? 'complete' : pending?.executionId ?? (running ? repeater.state : 'idle')]);
        if (entry) elements.collectionResponseMeta.textContent = `Run ${entry.id} · ${entry.resolved_request.method} ${entry.resolved_request.url}${pendingLabel}`;
        if (elements.collectionResponse.dataset.renderKey === key) return;
        elements.collectionResponse.dataset.renderKey = key;
        if (!entry) {
          elements.collectionResponse.className = 'repeater-response experiment-empty';
          elements.collectionResponse.textContent = pending ? `Waiting for acknowledged run ${pending.executionId} to appear in history…` : running ? 'Waiting for this request’s response…'
            : collectionRequest() ? 'Run this saved request to inspect its bounded response.' : 'Select a saved request to inspect its runs.';
          elements.collectionResponseMeta.textContent = pending ? `Run ${pending.executionId} acknowledged; response pending.` : running ? 'An explicit run is in progress.' : 'No completed run for this request.';
          elements.collectionResponseBadge.dataset.kind = 'offline';
          elements.collectionResponseBadge.textContent = pending ? running && repeater.state === 'cancelling' ? 'Cancelling' : 'Awaiting response' : running ? repeater.state === 'cancelling' ? 'Cancelling' : 'Running' : 'No response';
          return;
        }
        const response = entry.response;
        const summary = document.createElement('div'); summary.className = 'experiment-result-summary';
        summary.append(experimentFact('Status', response.ok ? `${response.status} ${response.status_text}`.trim() : entry.state.replaceAll('_', ' ')),
          experimentFact('Duration', `${response.duration_ms} ms`),
          experimentFact('Body', `${utf8ByteLength(response.body)} bytes${response.body_truncated ? ' · truncated' : ''}`));
        let content;
        if (state.collectionResponseTab === 'headers') {
          content = document.createElement('div'); content.className = 'repeater-response-headers';
          if (response.headers.length) content.append(...response.headers.map(header => {
            const row = document.createElement('div'); row.className = 'repeater-response-header';
            row.append(textElement('span', '', header.name), textElement('span', '', header.value)); return row;
          }));
          else content.append(textElement('div', 'experiment-empty', 'No response headers were retained.'));
          if (response.headers_truncated) content.append(textElement('p', 'collection-help', 'Response headers were truncated; only the retained subset is shown.'));
        } else {
          content = document.createElement('pre'); content.className = 'experiment-result-body';
          content.textContent = response.ok ? response.body || '(empty response body)' : response.error;
        }
        elements.collectionResponse.className = 'repeater-response';
        elements.collectionResponse.replaceChildren(summary, content);
        elements.collectionResponse.scrollTop = 0;
        elements.collectionResponseMeta.textContent = `Run ${entry.id} · ${entry.resolved_request.method} ${entry.resolved_request.url}${pendingLabel}`;
        elements.collectionResponseBadge.dataset.kind = response.ok ? '' : 'error';
        elements.collectionResponseBadge.textContent = response.ok ? 'Complete' : entry.state.replaceAll('_', ' ');
      }

      function renderCollectionExecution() {
        const experiment = requestInterception();
        const repeater = repeaterState();
        const history = collectionHistoryEntries();
        const pendingSelection = collectionPendingRunForSelection();
        if (pendingSelection && history.some(entry => entry.id === pendingSelection.executionId)) {
          state.collectionSelectedHistoryId = pendingSelection.executionId;
          state.collectionPendingRunSelection = null;
        }
        const attached = ['running', 'paused'].includes(state.debuggerSession?.state);
        const active = ['running', 'cancelling'].includes(repeater?.state);
        const contextReady = attached && experiment?.isolated && experiment.target_id === state.debuggerSession?.target?.id &&
          ['ready', 'error'].includes(experiment.state) && ['ready', 'error'].includes(repeater?.state);
        elements.collectionContextBadge.dataset.kind = repeater?.state === 'error' ? 'error' : contextReady ? '' : 'offline';
        elements.collectionContextBadge.textContent = active ? repeater.state === 'cancelling' ? 'Cancelling' : 'Running'
          : contextReady ? 'Isolated' : experiment?.state === 'creating' ? 'Creating' : 'Not created';
        elements.collectionContextMessage.textContent = active
          ? `Request #${repeater.active_execution?.collection_request_id ?? 'external'} is ${repeater.state}. Cancellation does not undo an already sent request.`
          : contextReady ? 'Disposable page attached. Baseline cookies and storage are excluded.'
            : attached ? repeater?.message ?? 'Create the shared isolated Request Lab context.'
              : 'Attach an authorized browser target before creating a context.';
        elements.collectionCreateContext.disabled = !attached || Boolean(experiment?.isolated) ||
          state.experimentPending || state.debuggerActionPending;
        elements.collectionRun.disabled = !collectionRequest() || !contextReady || active || state.experimentPending ||
          state.apiCollectionSaving || state.apiCollectionNeedsReload || state.collectionRunPending || Boolean(collectionPendingRunForSelection()) || state.debuggerActionPending || state.collectionFolderDirty;
        elements.collectionRun.textContent = state.collectionRunPending ? 'Submitting…' : state.collectionDraftDirty ? 'Save & Run' : 'Run saved request';
        elements.collectionRunHelp.textContent = collectionPendingRunForSelection() ? 'The acknowledged run is awaiting its response. Selecting another run only changes the displayed result.'
          : state.collectionFolderDirty ? 'Save or discard folder variables before running.'
          : !attached ? 'A browser target and isolated context are required to run.'
            : !contextReady ? active ? 'Wait for the active run, or cancel it in Isolated context.' : 'Create an isolated context to run this request.'
              : state.collectionDraftDirty ? 'Save & Run saves these edits locally, then sends that saved request once.'
                : 'Run sends the saved method, URL, headers and body once. Selecting a request never sends it.';
        elements.collectionCancel.disabled = !active || state.debuggerActionPending || repeater?.state === 'cancelling';
        if (!history.some(entry => entry.id === state.collectionSelectedHistoryId)) {
          state.collectionSelectedHistoryId = history.at(-1)?.id ?? null;
        }
        elements.collectionHistoryBadge.textContent = `${history.length} ${history.length === 1 ? 'run' : 'runs'}`;
        elements.collectionHistoryBadge.dataset.kind = history.length ? '' : 'offline';
        const historyKey = JSON.stringify([experiment?.experiment_id, state.collectionSelectedRequestId,
          state.collectionSelectedHistoryId, history.map(entry => entry.id)]);
        if (elements.collectionHistory.dataset.renderKey !== historyKey) {
          const focusedId = elements.collectionHistory.contains(document.activeElement) ? document.activeElement?.dataset.runId : null;
          const scrollTop = elements.collectionHistory.scrollTop;
          elements.collectionHistory.dataset.renderKey = historyKey;
          if (!history.length) elements.collectionHistory.replaceChildren(
            emptyListboxOption('experiment-empty', collectionRequest() ? 'No executions for this request.' : 'Select a saved request.')
          );
          else elements.collectionHistory.replaceChildren(...[...history].reverse().map(entry => {
            const row = document.createElement('button'); row.type = 'button'; row.className = 'collection-history-row';
            row.dataset.runId = String(entry.id);
            row.setAttribute('role', 'option'); row.setAttribute('aria-selected', String(entry.id === state.collectionSelectedHistoryId));
            row.tabIndex = entry.id === state.collectionSelectedHistoryId ? 0 : -1;
            row.append(textElement('span', '', `${entry.resolved_request.method} ${entry.resolved_request.url}`),
              textElement('strong', '', entry.response.ok ? String(entry.response.status) : entry.state.replaceAll('_', ' ')),
              textElement('small', '', `Run ${entry.id} · ${entry.response.duration_ms} ms · ${new Date(entry.completed_at_ms).toLocaleTimeString()}`));
            row.addEventListener('click', () => {
              state.collectionHistorySelectionVersion += 1;
              state.collectionPendingRunSelection = null;
              state.collectionSelectedHistoryId = entry.id; renderCollectionExecution();
              elements.collectionHistory.querySelector(`[data-run-id="${entry.id}"]`)?.focus({preventScroll: true});
            });
            row.addEventListener('keydown', event => {
              if (!['ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) return;
              event.preventDefault();
              const rows = [...elements.collectionHistory.querySelectorAll('.collection-history-row')];
              const index = rows.indexOf(row);
              const next = event.key === 'Home' ? 0 : event.key === 'End' ? rows.length - 1
                : Math.max(0, Math.min(rows.length - 1, index + (event.key === 'ArrowDown' ? 1 : -1)));
              rows[next].click();
            });
            return row;
          }));
          elements.collectionHistory.scrollTop = scrollTop;
          if (focusedId) elements.collectionHistory.querySelector(`[data-run-id="${focusedId}"]`)?.focus({preventScroll: true});
        }
        renderCollectionResponse(history.find(entry => entry.id === state.collectionSelectedHistoryId) ?? null);
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
        elements.collectionGeneration.textContent = `Generation ${state.apiCollection.generation}`;
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
        renderCollectionExecution();
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

      async function runCollectionRequest() {
        const request = collectionRequest();
        if (!request || state.collectionRunPending || collectionPendingRunForSelection() || state.apiCollectionSaving || state.apiCollectionNeedsReload || state.experimentPending || state.debuggerActionPending) return;
        if (state.collectionFolderDirty) {
          setCollectionNotice('conflict', 'Save or discard folder variables before running a request.'); return;
        }
        const selection = state.collectionSelectionVersion;
        const historySelection = state.collectionHistorySelectionVersion;
        const targetId = state.debuggerSession?.target?.id;
        const experimentId = requestInterception()?.experiment_id;
        const context = experimentContextKey();
        const ready = () => context === experimentContextKey() && ['running', 'paused'].includes(state.debuggerSession?.state) && targetId === state.debuggerSession?.target?.id &&
          experimentId === requestInterception()?.experiment_id && requestInterception()?.target_id === targetId && requestInterception()?.isolated &&
          ['ready', 'error'].includes(requestInterception()?.state) && ['ready', 'error'].includes(repeaterState()?.state);
        if (!ready()) { setCollectionNotice('error', 'Create an isolated context before running.'); return; }
        state.collectionRunPending = true;
        const pendingOwner = {requestId: request.id, createdAt: request.created_at_ms, targetId, experimentId};
        state.collectionPendingSubmission = pendingOwner;
        renderCollectionExecution();
        let savedEdits = false;
        try {
          const expected = state.collectionDraftDirty ? collectionRequestDraft() : request;
          const draftRevision = state.collectionDraftRevision ?? 0;
          if (state.collectionDraftDirty) {
            // The button explicitly says Save & Run. Selection and plain saves never send.
            if (!(await saveCollectionRequest())) return;
            savedEdits = true;
          }
          const saved = collectionRequest(request.id);
          if (!ready()) throw new Error('The isolated context changed before the request could run.');
          if (!saved || Object.keys(expected).some(key => !['created_at_ms', 'updated_at_ms'].includes(key) &&
              JSON.stringify(expected[key]) !== JSON.stringify(saved[key])) || (state.collectionDraftRevision ?? 0) !== draftRevision) {
            throw new Error('The submitted request draft changed before sending. No request was sent.');
          }
          const savedKey = JSON.stringify([saved, collectionFolderLineage(saved.folder_id)]);
          const variables = {};
          collectionFolderLineage(saved.folder_id).forEach(folder => folder.variables.forEach(variable => {
            variables[variable.name] = variable.value;
          }));
          saved.variables.forEach(variable => { variables[variable.name] = variable.value; });
          const payload = {action: 'run_repeater_request', url: saved.url, method: saved.method,
            headers: repeaterHeaderObject(saved.headers), body: saved.body, timeout_ms: saved.timeout_ms,
            collection_request_id: saved.id};
          if (!ready()) throw new Error('The isolated context changed before the request could run.');
          const configured = currentExperimentReceipt(await runExperimentAction({action: 'configure_repeater_variables', variables}));
          if (!configured) {
            throw new Error(state.experimentError || 'Request variables could not be configured.');
          }
          if (!ready()) throw new Error('The isolated context changed before the request could run.');
          if (state.apiCollectionNeedsReload || collectionRequest(saved.id)?.created_at_ms !== saved.created_at_ms) {
            throw new Error('The saved request was removed or replaced before sending. No request was sent.');
          }
          if (savedKey !== JSON.stringify([collectionRequest(saved.id), collectionFolderLineage(saved.folder_id)]) ||
              ((state.collectionDraftRevision ?? 0) !== draftRevision) ||
              (state.collectionSelectedRequestId === saved.id && state.collectionDraftDirty)) {
            throw new Error('The submitted request or its variables changed before sending. No request was sent.');
          }
          const previousId = repeaterState()?.history.at(-1)?.id ?? 0;
          const submittedOwners = state.collectionSubmittedOwners ??= [];
          const submission = {...state.collectionPendingSubmission, afterExecutionId: previousId};
          submittedOwners.push(submission);
          if (submittedOwners.length > 25) submittedOwners.shift();
          const response = currentExperimentReceipt(await runExperimentAction(payload));
          if (!response) throw new Error(state.experimentError || 'The run could not be confirmed. It was not automatically retried.');
          const acknowledgement = response.repeater?.active_execution?.collection_request_id === saved.id
            ? response.repeater.active_execution : response.repeater?.history.findLast(entry => entry.collection_request_id === saved.id && entry.id > previousId);
          const executionId = acknowledgement?.execution_id ?? acknowledgement?.id;
          if (!Number.isSafeInteger(executionId) || executionId <= previousId) {
            throw new Error('The run acknowledgement did not identify this request. Its outcome is unknown and it was not retried.');
          }
          const key = JSON.stringify([targetId, experimentId, executionId]);
          submission.executionId = executionId;
          rememberCollectionRunOwner(key, {requestId: saved.id, createdAt: saved.created_at_ms});
          if (selection === state.collectionSelectionVersion && historySelection === state.collectionHistorySelectionVersion &&
              state.collectionSelectedRequestId === saved.id && collectionRequest()?.created_at_ms === saved.created_at_ms) {
            state.collectionPendingRunSelection = {key, executionId, requestId: saved.id, createdAt: saved.created_at_ms, selection, historySelection};
          }
          setCollectionNotice('ready', `${savedEdits ? 'Edits saved. ' : ''}Run submitted for “${saved.name}”. Responses remain tied to that submitted request.`);
        } catch (error) {
          if (state.collectionPendingSubmission === pendingOwner) setCollectionNotice('error', `${savedEdits ? 'Edits saved. ' : ''}${error.message}`);
        } finally {
          if (state.collectionPendingSubmission === pendingOwner) {
            state.collectionPendingSubmission = null;
            state.collectionRunPending = false;
            renderApiCollection();
          }
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
                setAnalystNotice(count ? 'ready' : 'empty', count
                  ? `${count} saved ${count === 1 ? 'file' : 'files'} loaded from the permission-restricted local workspace.`
                  : 'Start by saving a script or note.');
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
        'json-minify'
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
        renderDecoderFieldOrigin();
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
        clearDecoderFieldOrigin();
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
          state.jwtResult = null;
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

      function liveScriptIdentity(script) {
        return JSON.stringify([script.target_id ?? state.debuggerSession?.target?.id ?? '', script.script_id, script.hash,
          script.execution_context_id ?? null, script.start_line ?? 0, script.start_column ?? 0, script.length ?? null]);
      }


      // Source ownership never comes from a URL. Captured documents reuse the
      // Facts identity; live documents include the actual page/worker target.
      function sourceIdentity(source) {
        if (!source) return null;
        if (source.source_type === 'script' || (source.artifact_id === undefined && source.script_id !== undefined)) {
          return JSON.stringify(['script', source.script_id, liveScriptIdentity(source),
            source.execution_context_id ?? null, source.start_line ?? 0, source.start_column ?? 0]);
        }
        return sourceFactsIdentity({...source, source_type: 'artifact'});
      }

      function sourceIsCurrent(source) {
        const candidates = source.source_type === 'script' || (source.artifact_id === undefined && source.script_id !== undefined)
          ? (state.debuggerSession?.scripts ?? []).filter(value => value.script_id === source.script_id && !state.staleScriptIds?.has(value.script_id))
          : state.artifacts.filter(value => value.artifact_id === source.artifact_id);
        return candidates.length === 1 && sourceIdentity(candidates[0]) === sourceIdentity(source);
      }

      function sourceReference(source) {
        // Navigator/tab/Quick Open handlers must not keep an evicted document
        // alive through a hidden DOM closure. Keep descriptors, never payloads.
        return Object.fromEntries(Object.entries(source).filter(([key]) => !['content', 'deobfuscation', 'controller'].includes(key)));
      }

      function setSourceCursor(source, line, column) {
        if (source?.source_type !== 'script' || !sourceIsCurrent(source) ||
            sourceIdentity(selectedSource()) !== sourceIdentity(source) ||
            state.sourceDeobfuscated || state.sourceFormatted || state.sourceWasm ||
            !Number.isSafeInteger(line) || line < 0 || !Number.isSafeInteger(column) || column < 0) return false;
        state.sourceCursor = {identity: sourceIdentity(source), representation: 'original', scriptId: source.script_id, line, column};
        return true;
      }

      function sourceCursorFor(source) {
        return !state.sourceDeobfuscated && !state.sourceFormatted && !state.sourceWasm &&
          state.sourceCursor?.identity === sourceIdentity(source) && state.sourceCursor?.representation === 'original'
          ? state.sourceCursor : null;
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
        const preview = source.source_type === 'script'
          ? state.liveScriptContent.get(source.script_id)
          : state.artifacts.find(value => sourceIdentity(value) === identity);
        if (source.source_type === 'script') {
          if (preview?.identity === liveScriptIdentity(source)) {
            preview.controller?.abort();
            state.liveScriptContent.delete(source.script_id);
          }
        } else if (preview) {
          preview.controller?.abort();
          for (const field of ['content', 'contentTruncated', 'loading', 'loadError', 'controller', 'previewUsed', 'contentVerified', 'contentLossy']) delete preview[field];
        }
        for (const cache of [state.deobfuscationRequests, state.deobfuscationCache, state.sourceFormatCache]) {
          for (const [key, value] of cache ?? []) {
            if (!key.startsWith(`${identity}|`)) continue;
            retireDeobfuscationReveal(value.inspectorView);
            value.controller?.abort(); cache.delete(key);
          }
        }
        if (state.sourceEditorView?.identity === identity) state.sourceEditorView = null;
        if (state.sourceCursor?.identity === identity) state.sourceCursor = null;
      }

      function boundSourcePreviews(protectedSource = null) {
        const protectedIdentity = sourceIdentity(selectedSource() ?? protectedSource);
        const entries = [
          ...(state.artifacts ?? []).filter(source => source.kind !== 'canvas_data_url').map(source => ({source, preview: source})),
          ...(state.debuggerSession?.scripts ?? []).map(source => ({source: {...source, source_type: 'script'}, preview: state.liveScriptContent.get(source.script_id)}))
        ].filter(({preview}) => preview && (preview.loading || preview.content !== undefined));
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

      function pruneLiveScriptContent() {
        const identities = new Map((state.debuggerSession?.scripts ?? [])
          .map(script => [script.script_id, liveScriptIdentity(script)]));
        for (const [scriptId, cached] of state.liveScriptContent) {
          if (identities.get(scriptId) !== cached.identity || state.staleScriptIds.has(scriptId)) {
            cached.controller?.abort();
            state.liveScriptContent.delete(scriptId);
          }
        }
      }

      function liveSources() {
        const staleScriptIds = state.staleScriptIds ?? new Set();
        return (state.debuggerSession?.scripts ?? []).filter(script => !staleScriptIds.has(script.script_id)).map(script => {
          const entry = state.liveScriptContent.get(script.script_id);
          const cached = entry?.identity === liveScriptIdentity(script) ? entry : {};
          const analysis = state.deobfuscationCache?.get(deobfuscationKey({...script, source_type: 'script', target_id: script.target_id ?? state.debuggerSession?.target?.id, sha256: script.hash}));
          return {
            ...script,
            ...cached,
            source_type: 'script',
            key: `script:${script.script_id}`,
            target_id: script.target_id ?? state.debuggerSession?.target?.id ?? '',
            target_title: script.target_type === 'worker'
              ? (runtimeHooksState()?.workers ?? []).find(worker => worker.id === script.target_id)?.title ?? 'Worker'
              : state.debuggerSession?.target?.title ?? '',
            kind: script.language === 'WebAssembly' ? 'wasm' : 'javascript',
            mime_type: script.language === 'WebAssembly' ? 'application/wasm' : 'text/javascript',
            byte_size: script.length,
            sha256: script.hash,
            sensitive: false,
            deobfuscation: analysis && sourceOwnedLiveText({...script, source_type: 'script'}) === analysis.original_source ? analysis : null
          };
        });
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
        const identity = source.source_type === 'script'
          ? `script ${source.script_id}` : `artifact ${source.artifact_id}`;
        if (source.source_type === 'script' && !source.url) return `anonymous · ${identity}`;
        return `${sourceName(source)} · ${identity}`;
      }

      function sourceDisplayMeta(source) {
        if (source.source_type === 'script') {
          const language = source.language === 'WebAssembly' ? 'WASM' : 'JS';
          const context = source.execution_context_id > 0 ? `ctx ${source.execution_context_id}` : 'ctx unknown';
          return `${language} · ${source.target_type === 'worker' ? 'worker' : 'page'} · live · ${context}`;
        }
        return `${source.origin === 'sample' ? 'sample' : source.origin === 'demo' ? 'demo' : 'evidence'} · ${source.kind}`;
      }

      function sourcePathParts(source) {
        try { return source.url ? new URL(source.url).pathname.split('/').filter(Boolean) : [sourceName(source)]; } catch { return [sourceName(source)]; }
      }

      function sourceIcon(source) {
        if (source.kind === 'wasm') return 'W';
        if (source.kind === 'source_map') return '{}';
        if (source.kind === 'response_body') return 'R';
        return 'JS';
      }

      function markLiveSourceStale(scriptId, reason = 'The live source detached before its bytes could be loaded.') {
        if (!scriptId) return;
        state.staleScriptIds ??= new Set();
        state.staleScriptIds.add(scriptId);
        state.liveScriptContent.get(scriptId)?.controller?.abort();
        state.liveScriptContent.delete(scriptId);
        state.openScriptIds = state.openScriptIds.filter(id => id !== scriptId);
        if (state.selectedScriptId === scriptId) {
          state.selectedScriptId = null;
          state.pendingSourceLine = null;
          state.sourceDeobfuscated = false;
          state.sourceFormatted = false;
          state.selectedArtifactId = state.openArtifactIds.at(-1) ?? null;
          state.sourceCollection = 'captured';
        }
        state.sourceNoticeKind = 'error';
        state.sourceNotice = `${reason} The stale live source was removed from Page and open tabs.`;
      }

      function selectedSource() {
        const matches = state.selectedScriptId !== null
          ? liveSources().filter(source => source.script_id === state.selectedScriptId)
          : capturedSources().filter(source => source.artifact_id === state.selectedArtifactId);
        return matches.length === 1 ? matches[0] : null;
      }

      function sourceTreeRow(label, glyph, depth, source = null, meta = '') {
        if (source) source = sourceReference(source);
        const row = document.createElement('button');
        row.type = 'button';
        row.className = 'source-tree-row';
        row.style.setProperty('--source-depth', String(depth));
        row.setAttribute('role', 'treeitem');
        row.setAttribute('aria-level', String(depth + 1));
        const icon = document.createElement('span');
        icon.className = source ? `source-file-icon ${source.kind}` : 'tree-glyph';
        icon.textContent = glyph;
        const name = document.createElement('span');
        name.className = 'source-tree-name';
        name.textContent = label;
        name.title = source?.url ?? label;
        const detail = document.createElement('span');
        detail.className = 'source-tree-meta';
        detail.textContent = meta;
        row.append(icon, name, detail);
        if (source) {
          if (source.source_type === 'artifact') row.dataset.artifactId = source.artifact_id;
          if (source.source_type === 'script') row.dataset.scriptId = source.script_id;
          const selected = source.source_type === 'artifact'
            ? source.artifact_id === state.selectedArtifactId && state.selectedScriptId === null
            : source.script_id === state.selectedScriptId;
          row.setAttribute('aria-selected', String(selected));
          row.addEventListener('click', () => source.source_type === 'script'
            ? selectScript(source.script_id)
            : selectArtifact(source.artifact_id));
        } else {
          row.setAttribute('aria-expanded', 'true');
        }
        return row;
      }

      function renderSourceTree() {
        const sources = state.sourceCollection === 'page' ? liveSources() : capturedSources();
        if (sources.length === 0) {
          const empty = document.createElement('div');
          empty.className = 'source-tree-empty';
          empty.textContent = state.sourceCollection === 'page'
            ? state.debuggerSession?.state === 'waiting' || state.debuggerSession?.state === 'connecting'
              ? 'Waiting for an authorized browser target. Open a page in the live Brave session.'
              : 'Live scripts appear here when Origin Trace is started with make live.'
            : 'No artifacts captured. JavaScript, WASM, source maps, and approved response bodies will appear here.';
          elements.sourceTree.replaceChildren(empty);
          return;
        }
        const rows = [sourceTreeRow('top', '⌄', 0, null, `${sources.length}`)];
        const byOrigin = new Map();
        sources.forEach(source => {
          const origin = sourceOrigin(source);
          if (!byOrigin.has(origin)) byOrigin.set(origin, []);
          byOrigin.get(origin).push(source);
        });
        [...byOrigin.entries()].sort(([left], [right]) => left.localeCompare(right)).forEach(([origin, originSources]) => {
          rows.push(sourceTreeRow(origin.replace(/^https?:\/\//, ''), '⌄', 1, null, `${originSources.length}`));
          const renderedDirectories = new Set();
          originSources.sort((left, right) => left.url.localeCompare(right.url)).forEach(source => {
            const parts = sourcePathParts(source);
            parts.slice(0, -1).forEach((directory, index) => {
              const key = parts.slice(0, index + 1).join('/');
              if (renderedDirectories.has(key)) return;
              renderedDirectories.add(key);
              rows.push(sourceTreeRow(directory, '⌄', index + 2));
            });
            rows.push(sourceTreeRow(
              sourceDisplayName(source),
              sourceIcon(source),
              Math.max(2, parts.length + 1),
              source,
              sourceDisplayMeta(source)
            ));
          });
        });
        elements.sourceTree.replaceChildren(...rows);
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
        const live = index(liveSources(), 'script_id'), captured = index(capturedSources(), 'artifact_id');
        const sources = [...state.openScriptIds.map(id => live.get(id)), ...state.openArtifactIds.map(id => captured.get(id))].filter(Boolean);
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
          const selected = source.source_type === 'script'
            ? source.script_id === state.selectedScriptId
            : source.artifact_id === state.selectedArtifactId && state.selectedScriptId === null;
          tab.setAttribute('aria-selected', String(selected));
          tab.tabIndex = selected ? 0 : -1;
          const icon = document.createElement('span');
          icon.className = `source-file-icon ${source.kind}`;
          icon.textContent = sourceIcon(source);
          const name = document.createElement('span');
          name.textContent = sourceDisplayName(source);
          name.title = source.url || sourceDisplayName(source);
          const close = document.createElement('span');
          close.className = 'source-tab-close';
          close.textContent = '×';
          close.setAttribute('aria-hidden', 'true');
          const kind = document.createElement('span'); kind.className = 'source-tab-kind'; kind.textContent = source.source_type === 'script' ? 'live' : 'captured';
          tab.append(icon, name, kind, close);
          tab.addEventListener('click', event => {
            if (event.target === close) {
              closeSource(source);
              return;
            }
            if (source.source_type === 'script') selectScript(source.script_id);
            else selectArtifact(source.artifact_id);
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
            const target = sources[next];
            if (target.source_type === 'script') selectScript(target.script_id);
            else selectArtifact(target.artifact_id);
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
        const facts = source.source_type === 'script'
          ? [
              ['Runtime', 'live target'], ['Target', source.target_title || source.target_id || 'attached browser'],
              ['Script', source.script_id],
              ['Context', source.execution_context_id], ['Language', source.language],
              ['Module', source.is_module ? 'yes' : 'no'], ['Source map', source.source_map_url || 'none'],
              ['Hash', source.hash || 'unreported'], ['Length', formatByteSize(source.length)]
            ]
          : [
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

      function applySourceSearch(reset = true, direction = 0) {
        const query = elements.sourceSearch.value;
        const rows = [...elements.sourceCode.querySelectorAll('.source-line[data-line]')];
        const {matches, truncated} = findSourceOccurrences(rows.map(row => row.querySelector('.source-text').textContent), query);
        const source = selectedSource();
        const cursor = sourceCursorFor(source);
        const matchingLines = new Set(matches.map(match => match.line));
        rows.forEach((row, index) => row.classList.toggle('search-match', matchingLines.has(index)));
        globalThis.CSS?.highlights?.delete('source-search-match');
        if (!query || !matches.length) {
          state.sourceSearchIndex = 0;
          elements.sourcePosition.textContent = query ? '0 matches' : `Line ${(cursor?.line ?? source?.start_line ?? 0) + 1}, Column ${(cursor?.column ?? sourceRuntimeColumn(source, 0)) + 1}`;
          return;
        }
        state.sourceSearchIndex = reset ? 0 : (state.sourceSearchIndex + direction + matches.length) % matches.length;
        const match = matches[state.sourceSearchIndex];
        const row = rows[match.line];
        const line = Number(row.dataset.line) - 1;
        const transformed = state.sourceDeobfuscated || state.sourceFormatted;
        const column = match.column + (transformed ? 0 : sourceRuntimeColumn(source, match.line));
        if (source?.source_type === 'script' && !transformed) {
          setSourceCursor(source, line, column);
          rows.forEach(candidate => candidate.classList.toggle('cursor', candidate === row));
        }
        elements.sourcePosition.textContent = `${state.sourceSearchIndex + 1} of ${matches.length}${truncated ? '+' : ''} matches · Line ${line + 1}, Column ${column + 1}`;
        const range = sourceOccurrenceRange(row.querySelector('.source-text'), match);
        if (!range) return;
        if (globalThis.Highlight && globalThis.CSS?.highlights) CSS.highlights.set('source-search-match', new Highlight(range));
        const rect = range.getBoundingClientRect();
        const viewport = elements.sourceCodeWrap.getBoundingClientRect();
        elements.sourceCodeWrap.scrollLeft += rect.left - viewport.left - Math.min(120, viewport.width / 4);
        elements.sourceCodeWrap.scrollTop += rect.top - viewport.top - viewport.height / 2;
      }

      function sourceRuntimeLine(source, sourceLine) {
        return source?.source_type === 'script' ? source.start_line + sourceLine : sourceLine;
      }

      function sourceRuntimeColumn(source, sourceLine) {
        return source?.source_type === 'script' && sourceLine === 0 ? source.start_column : 0;
      }

      function sourceClickColumn(line, event) {
        const text = line.querySelector('.source-text');
        if (!text) return 0;
        // DOM Range offsets and CDP columns both count UTF-16 code units.
        // Measure across syntax spans, excluding the line-number gutter.
        const caret = document.caretPositionFromPoint?.(event.clientX, event.clientY);
        const range = caret ? null : document.caretRangeFromPoint?.(event.clientX, event.clientY);
        const node = caret?.offsetNode ?? range?.startContainer;
        const offset = caret?.offset ?? range?.startOffset;
        if (!node || !text.contains(node)) return 0;
        const prefix = document.createRange();
        prefix.selectNodeContents(text);
        prefix.setEnd(node, offset);
        return prefix.toString().length;
      }

      function breakpointLinesForSource(source) {
        const byLine = new Map();
        if (source?.source_type !== 'script') return byLine;
        (state.debuggerSession?.breakpoints ?? []).forEach(breakpoint => {
          const resolved = breakpoint.locations?.filter(location => location.script_id === source.script_id) ?? [];
          if (resolved.length > 0) {
            resolved.forEach(location => { if (!byLine.has(location.line)) byLine.set(location.line, breakpoint); });
            return;
          }
          if ((source.url && breakpoint.url === source.url) || breakpoint.script_id === source.script_id) {
            if (!byLine.has(breakpoint.line)) byLine.set(breakpoint.line, breakpoint);
          }
        });
        return byLine;
      }

      function breakpointAt(source, line) {
        return breakpointLinesForSource(source).get(line) ?? null;
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
            return {content: rows.map(row => row.byte_offset === null ? `;; ${row.text}` : `${row.kind === 'instruction' ? `func ${row.function_index}`.padEnd(11) : row.kind.padEnd(11)} ${row.text}`).join('\n'), lineMap: null, wasmRows: rows};
          }
        }
        const original = sourceFactsPanel.original(source) ?? source.content ?? '';
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
          lineMap: sourceRepresentationLineMap(derived ? source.deobfuscation.original_source : original, active, derived, formatted)
        };
      }

      function retrySourcePreview(source) {
        const identity = sourceIdentity(source);
        if (sourceIdentity(selectedSource()) !== identity || !sourceIsCurrent(source)) return;
        if (source.source_type === 'script') loadScriptContent(source);
        else loadArtifactContent(state.artifacts.find(value => sourceIdentity(value) === identity), {retry: true});
      }

      function renderSourceContent(source, view = null) {
        const identity = sourceIdentity(source);
        const resetEditor = () => {state.sourceEditorView = null; elements.sourceCode.replaceChildren();};
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
          elements.sourceCodeEmpty.textContent = source.source_type === 'script' ? 'Loading live script source…' : 'Loading immutable artifact bytes…';
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
          return;
        }
        view ??= sourceDisplayView(source);
        const content = view.content;
        const representation = JSON.stringify([identity, state.sourceWasm, state.sourceDeobfuscated, state.sourceFormatted,
          state.sourceDeobfuscated ? deobfuscationKey(source) : null, state.pendingSourceLine?.identity, state.pendingSourceLine?.line]);
        const mapping = view.wasmRows ? state.wasmCache.get(wasmKey(source)) : view.derived ?? null;
        const formatting = view.formatted ?? null;
        const previous = state.sourceEditorView;
        if (previous?.representation === representation && previous.content === content && previous.mapping === mapping && previous.formatting === formatting) {
          updateSourceDecorations();
          return;
        }
        elements.sourceCodeEmpty.replaceChildren();
        const sameOwner = previous?.identity === identity && previous.representation === representation && previous.mapping === mapping && previous.formatting === formatting;
        const scroll = {top: elements.sourceCodeWrap.scrollTop, left: elements.sourceCodeWrap.scrollLeft};
        const focused = elements.sourceCode.contains(document.activeElement)
          ? {line: document.activeElement.closest('.source-line')?.dataset.line, gutter: document.activeElement.classList.contains('source-gutter')} : null;
        state.sourceEditorView = {identity, representation, content, mapping, formatting};
        const lineMap = view.lineMap;
        const lines = content.split('\n');
        const renderedLines = lines.slice(0, 20000);
        const breakpointsByLine = breakpointLinesForSource(source);
        const tokenizer = createSourceTokenizer(view.wasmRows ? {kind: 'plain', mime_type: 'text/plain'} : source);
        const cursor = sourceCursorFor(source);
        const nodes = renderedLines.map((line, index) => {
          const runtimeLine = sourceRuntimeLine(source, index);
          const mapped = lineMap ? lineMap[index] ?? null : null;
          const mappedLine = mapped?.originalLine ?? null;
          const row = document.createElement('span');
          row.className = 'source-line';
          row.dataset.line = String(runtimeLine + 1);
          const breakpoint = breakpointsByLine.get(runtimeLine) ?? null;
          if (breakpoint) row.classList.add('breakpoint');
          if (source.source_type === 'script' && !state.sourceDeobfuscated && !state.sourceFormatted && state.pendingSourceLine?.identity === identity && state.pendingSourceLine.line === runtimeLine) {
            row.classList.add('current');
          }
          if (source.source_type === 'script' && cursor?.line === runtimeLine) {
            row.classList.add('cursor');
          }
          const gutter = document.createElement('button');
          gutter.type = 'button';
          gutter.className = 'source-gutter';
          gutter.textContent = String((mappedLine ?? runtimeLine) + 1);
          const transformed = state.sourceDeobfuscated || state.sourceFormatted;
          gutter.disabled = mappedLine === null && (source.source_type !== 'script' || source.target_type === 'worker' || transformed || !['running', 'paused'].includes(state.debuggerSession?.state) || memoryOriginTraceActive());
          gutter.title = mappedLine === null
            ? transformed ? 'Show original source to edit breakpoints' : ''
            : `Show original source at line ${mappedLine + 1}`;
          gutter.setAttribute('aria-label', mappedLine === null
            ? `${breakpoint ? 'Remove' : 'Add'} breakpoint on line ${runtimeLine + 1}`
            : `Show original source at line ${mappedLine + 1}`);
          gutter.addEventListener('click', event => {
            event.stopPropagation();
            if (view.wasmRows) return;
            if (mappedLine !== null) { revealOriginalLine(source, mappedLine, mapped?.originalColumn ?? 0); return; }
            toggleLineBreakpoint(source, runtimeLine, sourceRuntimeColumn(source, index), breakpointAt(source, runtimeLine));
          });
          if (view.wasmRows) {
            const offset = view.wasmRows[index]?.byte_offset;
            gutter.textContent = offset == null ? '' : offset.toString(16).padStart(6, '0');
            gutter.disabled = offset == null || offset >= 20000 * 16;
            gutter.setAttribute('aria-label', offset == null ? 'Inspection notice' : `Show original bytes at offset ${offset}`);
            gutter.title = offset == null ? '' : offset >= 20000 * 16 ? `Byte offset ${offset} is beyond the first 20,000 hex rows shown in Sources` : `Original byte offset ${offset} (0x${offset.toString(16)})`;
            gutter.addEventListener('click', () => {
              if (offset == null) return;
              state.sourceWasm = false;
              renderSources();
              const hexRow = elements.sourceCode.children[Math.floor(offset / 16)];
              if (hexRow) { hexRow.tabIndex = -1; hexRow.focus({preventScroll: true}); hexRow.scrollIntoView({block: 'center'}); }
            });
          }
          const text = document.createElement('span');
          text.className = 'source-text';
          appendSourceSyntax(text, sourceSyntaxTokens(line, tokenizer));
          row.append(gutter, text);
          return row;
        });
        if (lines.length > renderedLines.length) {
          const notice = document.createElement('span');
          notice.className = 'source-line';
          const gutter = document.createElement('button'); gutter.type = 'button'; gutter.className = 'source-gutter'; gutter.disabled = true; gutter.textContent = '…';
          const text = document.createElement('span'); text.className = 'source-text';
          text.textContent = `Viewer limit reached. ${lines.length - renderedLines.length} more lines remain in the source.`;
          notice.append(gutter, text);
          nodes.push(notice);
        }
        elements.sourceCode.replaceChildren(...nodes);
        elements.sourceLanguage.textContent = view.wasmRows ? 'WASM disassembly · byte offsets' : `${sourceSyntaxLabel(tokenizer.language)}${tokenizer.truncated ? ' · color limit reached' : ''}`;
        elements.sourceCode.hidden = false;
        elements.sourceCodeEmpty.hidden = true;
        if (sameOwner) {
          elements.sourceCodeWrap.scrollTop = scroll.top;
          elements.sourceCodeWrap.scrollLeft = scroll.left;
          const row = [...elements.sourceCode.children].find(value => value.dataset.line === focused?.line);
          const target = focused?.gutter ? row?.querySelector('.source-gutter') : row;
          if (target) {target.tabIndex = -1; target.focus({preventScroll: true});}
        } else {
          elements.sourceCodeWrap.scrollTop = 0;
          elements.sourceCodeWrap.scrollLeft = 0;
          applySourceSearch();
          elements.sourceCode.querySelector('.source-line.current')?.scrollIntoView({block: 'center'});
        }
      }

      function updateSourceDecorations() {
        const source = selectedSource();
        if (source?.source_type !== 'script' || elements.sourceCode.hidden || state.sourceDeobfuscated || state.sourceFormatted || state.sourceWasm) return;
        const breakpointsByLine = breakpointLinesForSource(source);
        const identity = sourceIdentity(source);
        const enabled = source.target_type !== 'worker' && !state.sourceDeobfuscated && !state.sourceFormatted && ['running', 'paused'].includes(state.debuggerSession?.state) && !memoryOriginTraceActive();
        elements.sourceCode.querySelectorAll('.source-line[data-line]').forEach(row => {
          const runtimeLine = Number(row.dataset.line) - 1;
          const breakpoint = breakpointsByLine.get(runtimeLine) ?? null;
          const current = !state.sourceDeobfuscated && !state.sourceFormatted && state.pendingSourceLine?.identity === identity && state.pendingSourceLine.line === runtimeLine;
          row.classList.toggle('breakpoint', Boolean(breakpoint));
          row.classList.toggle('current', current);
          const gutter = row.querySelector('.source-gutter');
          if (!gutter) return;
          gutter.disabled = !enabled;
          gutter.setAttribute('aria-label', `${breakpoint ? 'Remove' : 'Add'} breakpoint on line ${runtimeLine + 1}`);
        });
        elements.sourceCode.querySelector('.source-line.current')?.scrollIntoView({ block: 'center' });
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
        elements.sourceHash.textContent = source?.sha256 ? `${source.source_type === 'script' ? 'hash' : 'sha256'} ${source.sha256}` : '';
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
        elements.sourceDeob.setAttribute('aria-label', state.sourceDeobfuscated ? 'Show original evidence' : 'Show deobfuscated representation');
        elements.sourceDeob.title = state.sourceDeobfuscated ? 'Show original evidence' : 'Show deobfuscated representation';
        elements.sourceHookPivot.disabled = !['running', 'paused'].includes(state.debuggerSession?.state);
        elements.sourceHookPivot.setAttribute('aria-expanded', String(state.sourceHooksOpen));
        renderSourceContent(source, view);
        if (!investigationPassiveSource && state.sourceDeobfuscated && source?.kind === 'javascript' && !document.querySelector('#screen-sources').hidden) loadDeobfuscation(source);
        renderDeobfuscationReport(source);
        resumeInvestigationReturn();
      }

      function sourceViewLabel(source, view = null) {
        if (state.sourceWasm && source?.kind === 'wasm' && source.source_type === 'artifact') {
          const report = state.wasmCache.get(wasmKey(source));
          const request = state.wasmRequests.get(wasmKey(source));
          return report ? `${report.status === 'partial' ? 'Partial' : 'Static'} inspection · original byte offsets` : request?.status === 'error' ? 'Inspection failed · original bytes preserved' : request?.status === 'loading' ? 'Inspection pending' : 'Inspection preview released';
        }
        view ??= source?.content !== undefined ? sourceDisplayView(source) : null;
        const original = source?.source_type === 'script' ? 'Live runtime source'
          : sourceFactsPanel.original(source) !== undefined ? 'Verified original evidence'
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
        if (source.source_type === 'script') {
          setSourceCursor(source, sourceRuntimeLine(source, line), (column ?? 0) + sourceRuntimeColumn(source, line));
        }
        renderSources();
        const runtimeLine = sourceRuntimeLine(source, line);
        const row = [...elements.sourceCode.querySelectorAll('.source-line')].find(candidate => Number(candidate.dataset.line) === runtimeLine + 1);
        if (row) {
          row.tabIndex = -1;
          row.focus({preventScroll: true});
          row.scrollIntoView({block: 'center'});
        } else {
          elements.sourcePosition.textContent = `Original line ${runtimeLine + 1} is outside the displayed preview. Facts can read verified original-byte ranges.`;
        }
      }

      function revealSourceFactRange(source, range, position) {
        if (sourceFactsIdentity(selectedSource()) !== sourceFactsIdentity(source)) return;
        if (position.line >= 20000) throw new Error('This range starts beyond the first 20,000 displayed lines. Its original byte offsets remain available in Facts.');
        // This uses separately hash-verified, strict UTF-8 original bytes, never
        // a lossy preview, derived text, or a live debugger script.
        if (getComputedStyle(elements.sourceSidebar).position === 'absolute') {
          state.sourceSidebarOpen = false;
          renderSourceSidebar();
        }
        revealOriginalLine(source, position.line, position.column);
        const row = elements.sourceCode.querySelector(`[data-line="${position.line + 1}"]`);
        if (!row) throw new Error('This original range is outside the current source view.');
        const text = row.querySelector('.source-text');
        const highlight = sourceOccurrenceRange(text, {column: position.column,
          length: Math.min(position.length, text.textContent.length - position.column)});
        if (highlight && globalThis.Highlight && globalThis.CSS?.highlights) CSS.highlights.set('source-search-match', new Highlight(highlight));
        rememberInvestigationRange(source, range);
        elements.sourcePosition.textContent = `Original UTF-8 bytes [${range.start}, ${range.end}) · Line ${position.line + 1}, Column ${position.column + 1}${position.multiline ? ' · range continues on following lines' : ''}`;
        if (highlight) {
          const bounds = highlight.getBoundingClientRect();
          const viewport = elements.sourceCodeWrap.getBoundingClientRect();
          elements.sourceCodeWrap.scrollLeft += bounds.left - viewport.left - Math.min(120, viewport.width / 4);
        }
      }

      function deobfuscationKey(source) {
        return `${sourceIdentity(source)}|intrinsics:${Boolean(state.deobfuscationAssumeIntrinsics)}`;
      }

      function sourceOwnedLiveText(source) {
        if (source?.source_type !== 'script' || !sourceIsCurrent(source)) return null;
        const entry = state.liveScriptContent.get(source.script_id);
        return entry?.identity === liveScriptIdentity(source) && !entry.loading && !entry.loadError &&
          entry.contentTruncated === false && typeof entry.content === 'string' && entry.sourceTextLength === entry.content.length
          ? entry.content : null;
      }

      async function validateSourceAnalysis(payload, source, assumeIntrinsics, liveOriginal = null) {
        const original = payload?.original_source;
        const representation = payload?.representation;
        const expectedAssumptions = assumeIntrinsics ? ['standard-intrinsics'] : [];
        if (payload?.schema !== 'deobfuscation-analysis-v1' || !['rust-oxc', 'python-lexical'].includes(payload.engine) || payload.mode !== 'derived' || payload.source_truncated !== false ||
            payload.artifact_id !== (source.source_type === 'artifact' ? source.artifact_id : null) ||
            payload.script_id !== (source.source_type === 'script' ? source.script_id : null) ||
            typeof original !== 'string' || original.length > 4 * 1024 * 1024 ||
            !/^[0-9a-f]{64}$/.test(payload.analysis?.source?.sha256) ||
            (source.source_type === 'artifact' && (!/^[0-9a-f]{64}$/.test(source.sha256) || payload.analysis.source.sha256 !== source.sha256)) ||
            (source.source_type === 'script' && (liveOriginal === null || original !== liveOriginal)) ||
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
        return {changes, synthetic, originalBytes: bytes.length, derivedBytes: derivedBytes.length,
          byteRanges: payload.engine === 'rust-oxc' && representation.offset_unit === 'utf-8-byte'};
      }

      async function loadDeobfuscation(source, {retry = false} = {}) {
        const sourceId = source?.source_type === 'artifact' ? source.artifact_id : source?.script_id;
        const sourceParam = source?.source_type === 'artifact' ? 'artifact_id' : 'script_id';
        if (!sourceId || !sourceIsCurrent(source)) return;
        const key = deobfuscationKey(source);
        const identity = sourceIdentity(source);
        const liveOwner = source.source_type === 'script' ? state.liveScriptContent.get(source.script_id) : null;
        const liveOriginal = source.source_type === 'script' ? sourceOwnedLiveText(source) : null;
        if (source.source_type === 'script' && state.deobfuscationCache.get(key)?.original_source !== liveOriginal) state.deobfuscationCache.delete(key);
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
          !controller.signal.aborted && sourceIsCurrent(source) && deobfuscationKey(source) === key &&
          (source.source_type !== 'script' || state.liveScriptContent.get(source.script_id) === liveOwner);
        const timeout = setTimeout(() => {
          if (state.deobfuscationRequests.get(key) !== request || request.status !== 'loading') return;
          request.status = 'error'; request.error = 'Analysis timed out. Retry explicitly; original bytes are preserved.';
          controller.abort();
          if (sourceIdentity(selectedSource()) === identity) renderSources();
        }, 10000);
        try {
          if (source.source_type === 'script' && liveOriginal === null) throw new Error('Load the complete owned live source before analyzing it; truncated previews cannot establish exact text.');
          const response = await fetch(`/api/deobfuscation?${sourceParam}=${encodeURIComponent(sourceId)}&mode=derived&assume_intrinsics=${assumeIntrinsics ? 1 : 0}`, {cache: 'no-store', signal: controller.signal});
          const bytes = await sourceFactsReadBytes(response, 33 * 1024 * 1024, controller.signal);
          if (!current()) return;
          if (bytes.length > 32 * 1024 * 1024) throw new Error('The analyzer response exceeds the retained-document budget.');
          const payload = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes));
          if (!response.ok) throw new Error(payload.error || `Deobfuscation analysis returned ${response.status}`);
          const inspection = await validateSourceAnalysis(payload, source, assumeIntrinsics, liveOriginal);
          if (!current()) return;
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
        if (owner.source.source_type === 'script') {
          if (sourceOwnedLiveText(owner.source) !== owner.payload.original_source) return;
          const position = sourceLocationForOffset(sourceLineStarts(owner.payload.original_source), change.original_start);
          if (position.line >= 20000) {
            view.notice = 'This range starts beyond the first 20,000 displayed lines. Its original byte offsets remain available above.';
            renderDeobfuscationReport(owner.source); return;
          }
          if (getComputedStyle(elements.sourceSidebar).position === 'absolute') {
            state.sourceSidebarOpen = false;
            renderSourceSidebar();
          }
          revealOriginalLine(owner.source, position.line, position.column);
          elements.sourcePosition.textContent = `Original live-source UTF-8 bytes [${wire.original_start}, ${wire.original_end}) · Line ${sourceRuntimeLine(owner.source, position.line) + 1}, Column ${position.column + sourceRuntimeColumn(owner.source, position.line) + 1}`;
          return;
        }
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
        const stamp = JSON.stringify([key, request?.status, request?.error, view?.change, view?.pages, view?.notice, view?.revealing]);
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
          nodes.push(textElement('strong', 'deobfuscation-title', `Static analysis · ${changes.length ? `${changes.length} changed spans` : 'No safe rewrites found'}`));
          nodes.push(deobfuscationRow('Bytes', `${formatByteSize(inspection.originalBytes)} → ${formatByteSize(inspection.derivedBytes)}`));
          nodes.push(deobfuscationRow('Source', `${target.source_type === 'script' ? 'Live script' : 'Captured artifact'} ${target.script_id ?? target.artifact_id}`));
          nodes.push(deobfuscationRow('SHA-256', analysis.source.sha256));
          nodes.push(textElement('p', 'deobfuscation-note', 'Original bytes are unchanged. Static reconstruction does not execute this source or prove equivalent runtime behavior. Pretty printing is a separate display layer.'));
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
        container.deobfuscationRender.stamp = JSON.stringify([key, request?.status, request?.error, view?.change, view?.pages, view?.notice, view?.revealing]);
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
          if (artifact.kind !== 'wasm') {
            try {new TextDecoder('utf-8', {fatal: true}).decode(buffer); artifact.contentLossy = false;}
            catch {artifact.contentLossy = true;}
          }
          // Hex is only a view: do not expand 2 MiB to 131,072 rows while the
          // editor can display only 20,000. The immutable blob is untouched.
          const content = artifact.kind === 'wasm'
            ? formatWasmHex(buffer.subarray(0, 20000 * 16))
            : new TextDecoder('utf-8', {fatal: false, ignoreBOM: true}).decode(buffer);
          if (canvasOwner && (artifact.contentLossy || !canvasDataUrlPattern.test(content))) {
            throw new Error('The retained bytes do not pass the bounded image data URL validator.');
          }
          if (canvasOwner) {
            const inspection = inspectCanvasPng(content);
            if (inspection.reason) canvasOwner.imageError = inspection.reason;
            else canvasOwner.imageInfo = inspection;
          }
          artifact.content = content;
          artifact.contentTruncated = artifact.byte_size > buffer.length || (artifact.kind === 'wasm' && buffer.length > 20000 * 16);
          if (artifact.contentTruncated) artifact.content += artifact.kind === 'wasm'
            ? '\n\n[Hex preview limited to the first 20,000 rows; original bytes are unchanged]'
            : '\n\n[Viewer preview limited to the first 2 MiB; original bytes are unchanged]';
          if (!canvasOwner) boundSourcePreviews();
        } catch (error) {
          if (current()) {
            if (canvasOwner) for (const field of ['content', 'contentVerified', 'contentLossy', 'contentTruncated']) delete artifact[field];
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
        state.sourceCollection = 'captured';
        state.selectedScriptId = null;
        state.selectedArtifactId = artifactId;
        state.pendingSourceLine = null;
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

      function selectScript(scriptId, line = null) {
        const candidates = liveSources().filter(candidate => candidate.script_id === scriptId);
        if (candidates.length !== 1) {
          state.sourceNoticeKind = 'warning';
          state.sourceNotice = 'This live script ID is missing or ambiguous. Refresh the Page catalog before opening it.';
          renderSourceHealth();
          return false;
        }
        const source = candidates[0];
        investigationPassiveSource = false;
        state.sourceNotice = null;
        retireSourceAnalysis(sourceIdentity(source));
        investigationBeforeSelection();
        sourceFactsPanel.cancel();
        state.sourceCollection = 'page';
        state.selectedScriptId = scriptId;
        state.selectedArtifactId = null;
        state.pendingSourceLine = line === null ? null : { identity: sourceIdentity(source), scriptId, line };
        state.sourceDeobfuscated = false;
        state.sourceFormatted = false;
        state.sourceWasm = false;
        if (!state.openScriptIds.includes(scriptId)) state.openScriptIds.push(scriptId);
        renderSources();
        if (state.sourceHooksOpen && line === null && prefillHookFromSource(source)) renderRuntimeHooks();
        loadScriptContent(source);
      }

      function closeSource(source) {
        if (!sourceIsCurrent(source)) return;
        releaseSourcePreview(source);
        if (source.source_type === 'script') {
          const closedIndex = state.openScriptIds.indexOf(source.script_id);
          state.openScriptIds = state.openScriptIds.filter(id => id !== source.script_id);
          if (state.selectedScriptId === source.script_id) {
            state.selectedScriptId = state.openScriptIds[Math.max(0, closedIndex - 1)] ?? null;
            if (state.selectedScriptId === null) {
              state.selectedArtifactId = state.openArtifactIds.at(-1) ?? null;
              state.sourceCollection = 'captured';
            }
          }
        } else {
          const closedIndex = state.openArtifactIds.indexOf(source.artifact_id);
          state.openArtifactIds = state.openArtifactIds.filter(id => id !== source.artifact_id);
          if (state.selectedArtifactId === source.artifact_id && state.selectedScriptId === null) {
            state.selectedArtifactId = state.openArtifactIds[Math.max(0, closedIndex - 1)] ?? null;
          }
        }
        state.pendingSourceLine = null;
        state.sourceDeobfuscated = false;
        state.sourceFormatted = false;
        state.sourceWasm = false;
        renderSources();
        const selected = selectedSource();
        if (selected?.source_type === 'script') loadScriptContent(selected);
        else if (selected) loadArtifactContent(state.artifacts.find(value => sourceIdentity(value) === sourceIdentity(selected)));
      }

      async function loadScriptContent(source) {
        const identity = liveScriptIdentity(source);
        const attached = () => sourceIsCurrent({...source, source_type: 'script'});
        if (!attached()) return;
        const existing = state.liveScriptContent.get(source.script_id);
        if (existing?.identity === identity && (existing.content !== undefined || existing.loading)) return;
        existing?.controller?.abort();
        const controller = new AbortController();
        const previewUsed = state.sourcePreviewSequence = (state.sourcePreviewSequence ?? 0) + 1;
        const pending = { identity, loading: true, loadError: null, controller, previewUsed };
        state.liveScriptContent.set(source.script_id, pending);
        boundSourcePreviews(source);
        // Longer than the backend's CDP deadline, but bound stalled HTTP/body reads too.
        const timeout = setTimeout(() => {
          if (state.liveScriptContent.get(source.script_id) !== pending) return;
          state.liveScriptContent.set(source.script_id, {identity, loading: false,
            loadError: 'Live source is unavailable: Loading timed out after 15 seconds. Retry source explicitly.'});
          controller.abort();
          if (sourceIdentity(selectedSource()) === sourceIdentity(source)) renderSources();
        }, 15000);
        const stillCurrent = () => state.liveScriptContent.get(source.script_id) === pending && attached();
        try {
          renderSources();
          const response = await fetch(`/api/debugger/source?script_id=${encodeURIComponent(source.script_id)}`, {
            cache: 'no-store', signal: controller.signal
          });
          const bytes = await sourceFactsReadBytes(response, 13 * 1024 * 1024, controller.signal);
          const body = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes));
          if (!stillCurrent()) return;
          const responseError = body?.error || `Debugger returned ${response.status}`;
          if (!response.ok) {
            if (/^No script for id:/i.test(responseError)) {
              markLiveSourceStale(source.script_id, responseError);
              renderSources();
              return;
            }
            throw new Error(responseError);
          }
          if (!isPlainObject(body) || body.protocol_version !== 1 || body.script_id !== source.script_id ||
              typeof body.source !== 'string' || body.source.length > 2097152 || typeof body.truncated !== 'boolean') throw new TypeError('Malformed debugger source response');
          const sourceBytes = new TextEncoder().encode(body.source);
          if (sourceBytes.length > 2097152) throw new TypeError('The live source exceeded its byte limit');
          // CDP's hash is an opaque owner/version token, not a UTF-8 digest.
          // Deob validates against this exact complete text and its own SHA-256.
          const content = source.kind === 'wasm'
            ? body.source
            : body.source + (body.truncated ? '\n\n[Live source preview limited to the first 2 MB]' : '');
          state.liveScriptContent.set(source.script_id, { identity, loading: false, loadError: null, content, previewUsed,
            sourceTextLength: body.source.length, contentTruncated: body.truncated });
          boundSourcePreviews();
        } catch (error) {
          if (!stillCurrent()) return;
          const message = controller.signal.aborted || error.name === 'AbortError'
            ? 'Loading timed out after 15 seconds. Select the source to retry.' : error.message;
          state.liveScriptContent.set(source.script_id, { identity, loading: false, loadError: `Live source is unavailable: ${String(message).slice(0, 1024)}` });
          state.sourceNoticeKind = 'warning';
          state.sourceNotice = `Live source ${sourceDisplayName(source)} could not be loaded. The last debugger catalog remains visible.`;
        } finally {
          clearTimeout(timeout);
          // A detached or superseded response must not leave a loading entry behind.
          if (state.liveScriptContent.get(source.script_id) === pending) state.liveScriptContent.delete(source.script_id);
        }
        renderSources();
      }

      async function toggleLineBreakpoint(source, line, column, breakpoint) {
        if (state.debuggerActionPending) return;
        if (breakpoint) await debuggerAction({ action: 'remove_breakpoint', breakpoint_id: breakpoint.id });
        else await debuggerAction({ action: 'set_breakpoint', url: source.url, script_id: source.script_id, line, column, condition: '' });
      }

      function renderQuickOpen() {
        const needle = elements.quickOpenInput.value.trim().toLowerCase();
        const matches = [...liveSources(), ...capturedSources()].map(sourceReference).filter(source =>
          !needle || `${sourceDisplayName(source)} ${source.url}`.toLowerCase().includes(needle)
        );
        const rows = matches.map(source => {
          const row = document.createElement('button');
          row.type = 'button';
          row.className = 'quick-open-row';
          const name = document.createElement('span'); name.textContent = sourceDisplayName(source);
          const path = document.createElement('small'); path.textContent = `${source.source_type === 'script' ? 'Live' : 'Captured'} · ${source.url || '(anonymous)'}`;
          row.append(name, path);
          row.addEventListener('click', () => {
            elements.quickOpen.hidden = true;
            if (source.source_type === 'script') selectScript(source.script_id);
            else selectArtifact(source.artifact_id);
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

      function memoryAttached() {
        return ['running', 'paused'].includes(state.debuggerSession?.state);
      }

      // One in-flight action and one bounded result. UI ownership is not native cancellation.
      function memoryOwnerCurrent(owner) {
        return Boolean(owner && !owner.expired && memoryAttached() && owner.targetId === state.debuggerSession?.target?.id &&
          owner.scopeVersion === (state.memoryScopeVersion ?? 0));
      }

      function memoryBaselineKey(baseline) {
        return baseline ? JSON.stringify([baseline.target_id, baseline.captured_at_ms, baseline.file_bytes]) : '';
      }

      function syncMemorySession(previous, current) {
        state.memoryPollSequence = (state.memoryPollSequence ?? 0) + 1;
        if (current.generation < previous?.generation) state.memoryNativeEpoch = (state.memoryNativeEpoch ?? 0) + 1;
        const contexts = new Set((current?.scripts ?? []).filter(script => !script.target_type)
          .map(script => script.execution_context_id));
        const scriptIdentities = new Map((current?.scripts ?? []).filter(script => !script.target_type).map(script => [script.script_id, script.hash]));
        const expired = current?.generation < previous?.generation ||
          (previous?.scripts ?? []).some(script => !script.target_type && scriptIdentities.has(script.script_id) && scriptIdentities.get(script.script_id) !== script.hash) ||
          (previous?.target?.id ?? null) !== (current?.target?.id ?? null) ||
          (['running', 'paused'].includes(previous?.state) && !['running', 'paused'].includes(current?.state)) ||
          (previous?.scripts ?? []).some(script => !script.target_type && !contexts.has(script.execution_context_id));
        if (expired) state.memoryScopeVersion = (state.memoryScopeVersion ?? 0) + 1;
        // Native baseline metadata is target-scoped, not a document identity.
        if (current?.generation < previous?.generation || (previous?.target?.id ?? null) !== (current?.target?.id ?? null) ||
            current.generation >= (state.memoryBaselineGeneration ?? 0)) {
          state.memoryDiffBaseline = current?.heap_diff_baseline?.target_id === current?.target?.id
            ? current.heap_diff_baseline : null;
          state.memoryBaselineGeneration = current.generation;
        }
        if (expired && state.memoryMode === 'origin' && !state.memoryOperation) {
          state.memorySearchPending = false;
          state.memorySearchStatus = 'unavailable';
          state.memorySearchMessage = 'Trace context expired. The retained sample is historical; native completion is unconfirmed until refreshed for its target.';
        }
        retireObsoleteMemoryRequest(current);
      }

      function memoryActionDeadline(action) {
        // Native live search has 3+5+3 second commands and two 3 second releases.
        // Heap capture is 3+60 seconds; search/diff workers add 20/60 seconds.
        // These bound waiting for HTTP headers AND body, not native execution.
        const deadlines = {search_live_objects: 30000, search_heap_snapshot: 120000,
          capture_heap_diff_baseline: 90000, compare_heap_diff: 150000,
          clear_heap_diff_baseline: 15000, start_memory_origin_trace: 15000,
          stop_memory_origin_trace: 15000, clear_memory_origin_trace: 15000};
        return Object.hasOwn(deadlines, action) ? deadlines[action] : 0;
      }

      function retireObsoleteMemoryRequest(current) {
        const transport = state.debuggerActionOwner;
        const operation = transport?.memoryOwner;
        if (!operation || !transport.retire) return;
        if (!memoryOwnerCurrent(operation) || operation.mode !== state.memoryMode ||
            (operation.action === 'compare_heap_diff' && memoryBaselineKey(operation.baseline) !== memoryBaselineKey(state.memoryDiffBaseline))) {
          transport.retire('Memory request ownership expired. Its native completion is unknown; no cancellation or retry was requested.');
          return;
        }
        const trace = current.memory_origin_trace;
        if (current.generation <= operation.submittedGeneration || !isMemoryOriginTrace(trace) ||
            new Set(trace.steps.map(step => step.id)).size !== trace.steps.length) return;
        const terminal = ['found', 'not_found', 'aborted', 'error'].includes(trace.state) && trace.target_id === operation.targetId;
        const previousIdentity = trace.trace_id === operation.traceId && trace.started_at_ms === operation.traceStartedAt;
        const request = transport.request;
        const startedTrace = operation.action === 'start_memory_origin_trace' && terminal && !previousIdentity &&
          trace.query === request.query && trace.scope === request.scope && trace.before_steps === request.before_steps && trace.after_steps === request.after_steps;
        const stoppedTrace = operation.action === 'stop_memory_origin_trace' && terminal && previousIdentity;
        const clearedTrace = operation.action === 'clear_memory_origin_trace' && trace.state === 'idle';
        if (startedTrace || stoppedTrace || clearedTrace) {
          transport.retire('A newer native trace lifecycle was observed. The action acknowledgement remains unavailable; ending this wait does not cancel or retry native work.');
        }
      }

      function beginMemoryOperation(action, criteria = '') {
        if (!memoryAttached() || state.memorySearchPending || state.debuggerActionPending) return null;
        const operation = {
          id: (state.memoryOperationSequence ?? 0) + 1, action, mode: state.memoryMode,
          targetId: state.debuggerSession.target.id,
          scopeVersion: state.memoryScopeVersion ?? 0, nativeEpoch: state.memoryNativeEpoch ?? 0,
          pollSequence: state.memoryPollSequence ?? 0,
          submittedAt: Date.now(), submittedGeneration: state.debuggerSession.generation, criteria,
          traceId: state.debuggerSession.memory_origin_trace?.trace_id ?? 0,
          traceStartedAt: state.debuggerSession.memory_origin_trace?.started_at_ms ?? 0,
          baseline: state.memoryDiffBaseline ? { ...state.memoryDiffBaseline } : null
        };
        state.memoryOperationSequence = operation.id;
        state.memoryOperation = operation;
        state.memoryLastOperation = operation;
        state.memorySearchPending = true;
        return operation;
      }

      function finishMemoryOperation(operation, body) {
        if (state.memoryOperation !== operation) return false;
        state.memoryOperation = null;
        state.memorySearchPending = false;
        if (!memoryOwnerCurrent(operation) || operation.mode !== state.memoryMode ||
            (body && Number.isSafeInteger(body.generation) && body.generation < operation.submittedGeneration) ||
            (operation.action === 'compare_heap_diff' &&
              memoryBaselineKey(operation.baseline) !== memoryBaselineKey(state.memoryDiffBaseline))) {
          if (operation.mode === 'origin' && (state.memoryPollSequence ?? 0) > operation.pollSequence) {
            // The old operation may belong to a prior epoch. Display the current
            // validated poll without comparing its generation to that old reply.
            applyMemoryOriginTrace(state.debuggerSession?.memory_origin_trace);
          }
          state.memorySearchStatus = 'unavailable';
          state.memorySearchMessage = `The ${operation.action.replaceAll('_', ' ')} reply submitted to ${operation.targetId} at ${new Date(operation.submittedAt).toLocaleTimeString()} was discarded because target, context, mode, or baseline changed. Native completion is not cancelled or confirmed by discarding this reply.`;
          renderMemory();
          return false;
        }
        return true;
      }

      function isMemoryAcknowledgement(body, trace = false) {
        return isPlainObject(body) && Object.keys(body).length === (trace ? 3 : 2) && body.ok === true &&
          (!trace || Object.hasOwn(body, 'trace')) &&
          isSafeIntegerInRange(body.generation, 0, Number.MAX_SAFE_INTEGER);
      }

      function memoryTracePollAfter(operation, generation = null) {
        // Keep one authoritative session snapshot, not another trace payload queue.
        // A completed poll can arrive while POST is pending; its ETag may make all
        // following GETs 304, so reconcile it before accepting the action reply.
        if (!memoryOwnerCurrent(operation) || operation.nativeEpoch !== (state.memoryNativeEpoch ?? 0) ||
            (state.memoryPollSequence ?? 0) <= operation.pollSequence) return null;
        const session = state.debuggerSession;
        const trace = session?.memory_origin_trace;
        if ((generation !== null && session.generation < generation) || !isMemoryOriginTrace(trace) ||
            (trace.state !== 'idle' && trace.target_id !== operation.targetId) ||
            new Set(trace.steps.map(step => step.id)).size !== trace.steps.length) return null;
        return trace;
      }

      function reconcileMemoryOrigin(operation, body = null) {
        const valid = isMemoryAcknowledgement(body, true);
        const trace = memoryTracePollAfter(operation, valid ? body.generation : null) ?? (valid ? body.trace : null);
        return trace ? applyMemoryOriginTrace(trace) : false;
      }

      function keepNewerMemoryBaseline(operation, body) {
        if (body.generation >= (state.memoryBaselineGeneration ?? 0)) return false;
        // The operation did complete, but its acknowledgement is not the current
        // baseline. Do not lower the generation or delete a later client's data.
        operation.acknowledgedGeneration = body.generation;
        state.memorySearchStatus = 'ready';
        state.memorySearchMessage = `${operation.action === 'clear_heap_diff_baseline' ? 'Reset' : 'Capture'} acknowledged for target ${operation.targetId} at generation ${body.generation}. Newer native baseline information at generation ${state.memoryBaselineGeneration} is retained.`;
        renderMemory();
        return true;
      }

      function memoryOperationFailed(message) {
        state.memorySearchStatus = 'unavailable';
        const attempt = state.memoryLastOperation;
        const submitted = attempt ? `Submitted to ${attempt.targetId} at ${new Date(attempt.submittedAt).toLocaleTimeString()}. ` : '';
        state.memorySearchMessage = `${submitted}${message} Completion is unconfirmed; no automatic retry. Any retained preview is from the last successful action. Refresh debugger state before choosing another action.`;
      }

      function commitMemoryOwner(operation) {
        state.memoryResultOwner = operation;
        state.memoryTargetId = operation.targetId;
      }

      function memoryResultSignature() {
        // Live/snapshot/diff arrays are immutable until an explicit action. Origin
        // refresh can replace at most 25 rows, so only that small window is hashed.
        const rows = state.memoryMode === 'origin' ? JSON.stringify(state.memoryResults) : state.memoryResults;
        return { rows, mode: state.memoryMode, selected: state.selectedMemoryResultId,
          meta: state.memorySearchMeta, stale: !memoryOwnerCurrent(state.memoryResultOwner) };
      }

      function selectMemoryResult(id, focus = false) {
        const result = state.memoryResults.find(candidate => candidate.id === id);
        if (!result) return;
        state.selectedMemoryResultId = id;
        renderMemory();
        if (focus) {
          [...elements.memoryResults.querySelectorAll('.memory-result-row')]
            .find(row => row.dataset.resultId === id)?.focus({ preventScroll: true });
        }
      }

      function moveMemorySelection(event) {
        if (!['ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) return;
        const rows = [...elements.memoryResults.querySelectorAll('.memory-result-row')];
        const current = rows.indexOf(event.currentTarget);
        if (current < 0 || rows.length === 0) return;
        event.preventDefault();
        const next = event.key === 'Home'
          ? 0
          : event.key === 'End'
            ? rows.length - 1
            : Math.max(0, Math.min(rows.length - 1, current + (event.key === 'ArrowDown' ? 1 : -1)));
        selectMemoryResult(rows[next].dataset.resultId, true);
      }

      function formatSignedByteSize(value) {
        if (value === 0) return '0 bytes';
        return `${value > 0 ? '+' : '-'}${formatByteSize(Math.abs(value))}`;
      }

      function formatSignedCount(value) {
        return `${value > 0 ? '+' : ''}${value.toLocaleString()}`;
      }

      function memoryFactRow(name, type, value) {
        const row = document.createElement('div'); row.className = 'memory-property';
        row.append(
          textElement('span', 'memory-property-name', name),
          textElement('span', 'memory-property-type', type),
          textElement('span', 'memory-property-value', value)
        );
        return row;
      }

      function renderHeapDiffDetail(result) {
        const diff = state.memorySearchMeta;
        if (!diff) {
          elements.memoryDetail.replaceChildren(textElement('div', 'memory-empty',
            state.memoryDiffBaseline
              ? 'Run the page activity you want to measure, then capture the current heap.'
              : 'Capture a baseline before the page activity you want to measure.'));
          return;
        }
        const cards = [];
        const summaryCard = document.createElement('article'); summaryCard.className = 'memory-detail-card';
        const summaryHead = document.createElement('header'); summaryHead.className = 'memory-detail-head';
        const summaryTitle = document.createElement('div');
        summaryTitle.append(
          textElement('h2', '', result ? result.name || `(${result.type})` : 'Heap comparison'),
          textElement('p', '', result
            ? `${result.type} · ${formatSignedByteSize(result.self_size_delta)} self memory`
            : `${formatSignedByteSize(diff.self_size_delta)} total self memory · ${diff.duration_ms} ms native analysis`)
        );
        summaryHead.append(summaryTitle, textElement('span', 'memory-readonly', Object.entries(diff).some(([key, value]) => (key.endsWith('_reached') || key === 'retained_size_saturated') && value) ? 'Bounded partial diff' : 'Indexed heap diff'));
        const facts = document.createElement('div'); facts.className = 'memory-properties';
        if (result) {
          facts.append(
            memoryFactRow('object count', 'baseline → current', `${result.baseline_count.toLocaleString()} → ${result.current_count.toLocaleString()} (${formatSignedCount(result.count_delta)})`),
            memoryFactRow('self memory', 'baseline → current', `${formatByteSize(result.baseline_self_size)} → ${formatByteSize(result.current_self_size)} (${formatSignedByteSize(result.self_size_delta)})`),
            memoryFactRow('signature', result.type, result.name || '(anonymous)')
          );
        } else {
          facts.append(
            memoryFactRow('heap nodes', 'baseline → current', `${diff.baseline_nodes.toLocaleString()} → ${diff.current_nodes.toLocaleString()}`),
            memoryFactRow('reachable nodes', 'baseline → current', `${diff.baseline_reachable_nodes.toLocaleString()} → ${diff.current_reachable_nodes.toLocaleString()}`),
            memoryFactRow('self memory', 'baseline → current', `${formatByteSize(diff.baseline_self_size)} → ${formatByteSize(diff.current_self_size)} (${formatSignedByteSize(diff.self_size_delta)})`)
          );
        }
        summaryCard.append(summaryHead, facts);
        cards.push(summaryCard);

        const ownersCard = document.createElement('article'); ownersCard.className = 'memory-detail-card';
        const ownersHead = document.createElement('header'); ownersHead.className = 'memory-detail-head';
        const ownersTitle = document.createElement('div');
        ownersTitle.append(
          textElement('h2', '', 'Top retained-memory changes'),
          textElement('p', '', 'Dominators over indexed reachable non-weak V8 heap edges; reported limits qualify this comparison')
        );
        ownersHead.append(ownersTitle, textElement('span', 'memory-readonly', 'Native C++'));
        const owners = document.createElement('div'); owners.className = 'memory-properties';
        if (diff.dominators.length === 0) {
          owners.append(textElement('div', 'memory-empty', 'No individual retained-size changes were detected.'));
        } else {
          diff.dominators.forEach(change => {
            owners.append(memoryFactRow(
              change.name || `(${change.type})`,
              `${change.type} · node ${change.id}`,
              `${formatSignedByteSize(change.retained_size_delta)} · ${formatByteSize(change.baseline_retained_size)} → ${formatByteSize(change.current_retained_size)}`
            ));
          });
        }
        ownersCard.append(ownersHead, owners);
        cards.push(ownersCard);
        elements.memoryDetail.replaceChildren(...cards);
      }

      function renderMemoryOriginDetail(result) {
        const trace = state.memorySearchMeta;
        if (!result) {
          const message = trace && ['armed', 'capturing', 'stepping', 'stopping'].includes(trace.state)
            ? trace.message
            : 'Arm a trace, then click the page action that creates the value.';
          elements.memoryDetail.replaceChildren(textElement('div', 'memory-empty', message));
          return;
        }
        const card = document.createElement('article'); card.className = 'memory-detail-card';
        const head = document.createElement('header'); head.className = 'memory-detail-head';
        const title = document.createElement('div');
        title.append(
          textElement('h2', '', result.location.function_name || '(anonymous)'),
          textElement('p', '', `${result.location.url || '(recorded anonymous script)'}:${result.location.line + 1}:${result.location.column + 1}`)
        );
        head.append(title, textElement('span', 'memory-readonly', result.is_first_match ? 'First appearance' : result.matched ? 'Observed' : result.coverage_partial ? 'Not found · partial' : 'Not found in sample'));
        head.append(textElement('span', 'memory-source-unavailable',
          'Source link unavailable: this trace records a script ID and location, without execution-context or source-hash identity.'));
        const facts = document.createElement('div'); facts.className = 'memory-properties';
        facts.append(
          memoryFactRow('trace step', result.is_first_match ? 'origin' : 'context', `${result.step} of ${trace?.step_count ?? result.step}`),
          memoryFactRow('heap match', result.matched ? 'found' : 'absent', result.match ? `${result.match.type} · node ${result.match.id}` : result.coverage_partial ? 'No match in the inspected subset; absence is unproven' : 'No matching node in this sampled snapshot'),
          memoryFactRow('native probe', result.coverage_partial ? 'partial' : 'bounded', `${result.analyzed_nodes.toLocaleString()} of ${result.total_nodes.toLocaleString()} nodes · ${result.duration_ms} ms`),
          memoryFactRow('heap capture', 'temporary', `${formatByteSize(result.capture_bytes)} · deleted after probe`),
          memoryFactRow('source filter', result.location.framework_filtered ? 'applied' : 'direct', result.location.url || '(anonymous script)')
        );
        card.append(head, facts);
        const context = document.createElement('article'); context.className = 'memory-detail-card';
        const contextHead = document.createElement('header'); contextHead.className = 'memory-detail-head';
        const contextTitle = document.createElement('div');
        contextTitle.append(
          textElement('h2', '', result.match ? result.match.name || `(${result.match.type})` : 'Temporal context'),
          textElement('p', '', result.match
            ? `${result.match.type} · ${result.match.self_size.toLocaleString()} self bytes`
            : 'No value was found in the inspected nodes at this function boundary')
        );
        contextHead.append(contextTitle, textElement('span', 'memory-readonly', result.matched ? 'Native match' : 'Before window'));
        const explanation = textElement('div', 'memory-empty', result.is_first_match
          ? 'This is the first sampled function boundary whose bounded V8 heap contains the requested value.'
          : result.matched
            ? 'The value remains present after its first sampled appearance.'
            : 'This retained step provides execution context immediately before the first sampled appearance.');
        context.append(contextHead, explanation);
        elements.memoryDetail.replaceChildren(card, context);
      }

      function renderMemoryDetail() {
        const result = state.memoryResults.find(candidate => candidate.id === state.selectedMemoryResultId);
        if (state.memoryMode === 'diff') {
          renderHeapDiffDetail(result);
          return;
        }
        if (state.memoryMode === 'origin') {
          renderMemoryOriginDetail(result);
          return;
        }
        if (!result) {
          const empty = textElement('div', 'memory-empty', memoryAttached()
            ? 'Enter at least one criterion, then start a bounded search.'
            : 'Run make live to attach an authorized browser target.');
          elements.memoryDetail.replaceChildren(empty);
          return;
        }
        const card = document.createElement('article'); card.className = 'memory-detail-card';
        const head = document.createElement('header'); head.className = 'memory-detail-head';
        const title = document.createElement('div');
        if (state.memoryMode === 'snapshot') {
          title.append(
            textElement('h2', '', result.name || `(${result.type})`),
            textElement('p', '', `${result.type} · node ${result.id} · ${result.self_size.toLocaleString()} self bytes · ${result.reachable ? 'root-reachable' : 'unreachable'}`)
          );
          head.append(title, textElement('span', 'memory-readonly', result.reachable ? 'Root reachable' : 'Unreachable'));
          const facts = document.createElement('div'); facts.className = 'memory-properties';
          [
            ['node id', 'uint64', result.id],
            ['type', 'V8 node', result.type],
            ['self size', 'bytes', result.self_size.toLocaleString()],
            ['incoming refs', result.incoming_reference_limit_reached ? 'capped' : 'full', result.incoming_reference_count.toLocaleString()]
          ].forEach(([name, type, value]) => {
            const row = document.createElement('div'); row.className = 'memory-property';
            row.append(
              textElement('span', 'memory-property-name', name),
              textElement('span', 'memory-property-type', type),
              textElement('span', 'memory-property-value', value)
            );
            facts.append(row);
          });
          const path = document.createElement('div'); path.className = 'memory-retaining-path';
          path.append(textElement('div', 'memory-results-head', !result.reachable
            ? 'No strong retaining path from a V8 root'
            : result.retaining_path_complete ? 'Shortest retaining path from a V8 root' : 'Partial retaining path'));
          if (result.retaining_path.length === 0) {
            path.append(textElement('div', 'memory-empty', result.reachable
              ? 'No retaining path was available inside the bounded native index.'
              : 'This node is not reachable from the V8 root through indexed non-weak edges. Inspect its incoming references below.'));
          } else {
            result.retaining_path.forEach(step => {
              const row = document.createElement('div'); row.className = 'memory-path-step';
              row.append(
                textElement('span', 'memory-path-edge', `${step.edge_type} · ${step.edge}`),
                textElement('span', 'memory-path-type', step.type),
                textElement('span', 'memory-path-name', step.name || '(anonymous)')
              );
              path.append(row);
            });
          }
          card.append(head, facts, path);
          const referencesCard = document.createElement('details'); referencesCard.className = 'memory-detail-card memory-detail-disclosure'; referencesCard.open = true;
          const summary = textElement('summary', '', '3 · Incoming references'); referencesCard.append(summary);
          const referencesHead = document.createElement('header'); referencesHead.className = 'memory-detail-head';
          const referencesTitle = document.createElement('div');
          referencesTitle.append(
            textElement('h2', '', 'Referring nodes'),
            textElement('p', '', result.incoming_reference_limit_reached
              ? `Showing ${result.incoming_references.length} prioritized references of ${result.incoming_reference_count.toLocaleString()}`
              : `${result.incoming_reference_count.toLocaleString()} indexed references`)
          );
          referencesHead.append(referencesTitle, textElement('span', 'memory-readonly', 'Internal first'));
          const references = document.createElement('div'); references.className = 'memory-reference-list';
          if (result.incoming_references.length === 0) {
            references.append(textElement('div', 'memory-empty', 'No incoming references were present in the bounded snapshot index.'));
          } else {
            result.incoming_references.forEach(reference => {
              const row = document.createElement('div'); row.className = 'memory-reference-row';
              const kind = textElement('span', 'memory-reference-kind', reference.edge_type);
              kind.dataset.kind = reference.edge_type;
              const source = document.createElement('span'); source.className = 'memory-reference-source';
              source.append(
                textElement('span', '', `${reference.source_type} · ${reference.source_name || '(anonymous)'}`),
                textElement('small', '', `source node ${reference.source_id}`)
              );
              row.append(kind, textElement('span', 'memory-reference-edge', reference.edge), source);
              references.append(row);
            });
          }
          referencesCard.append(referencesHead, references);
          elements.memoryDetail.replaceChildren(card, referencesCard);
          return;
        }
        const similarity = result.similarity === null ? 'shape filter not used' : `${Math.round(result.similarity * 100)}% structural similarity`;
        title.append(
          textElement('h2', '', result.class_name || 'Object'),
          textElement('p', '', `${result.property_count} own properties · ${similarity}`)
        );
        head.append(title, textElement('span', 'memory-readonly', memoryOwnerCurrent(state.memoryResultOwner) ? 'Ephemeral preview' : 'Expired preview'));
        const properties = document.createElement('div'); properties.className = 'memory-properties';
        if (result.preview.length === 0) {
          properties.append(textElement('div', 'memory-empty', 'The matched object has no previewable own properties.'));
        } else {
          result.preview.forEach(property => {
            const row = document.createElement('div'); row.className = 'memory-property';
            row.append(
              textElement('span', 'memory-property-name', property.name),
              textElement('span', 'memory-property-type', property.type),
              textElement('span', 'memory-property-value', property.value)
            );
            properties.append(row);
          });
          if (result.properties_truncated) {
            const row = document.createElement('div'); row.className = 'memory-property';
            row.append(
              textElement('span', 'memory-property-name', 'preview'),
              textElement('span', 'memory-property-type', 'bounded'),
              textElement('span', 'memory-property-value', `Showing ${result.preview.length} of ${result.property_count} properties`)
            );
            properties.append(row);
          }
        }
        card.append(head, properties);
        elements.memoryDetail.replaceChildren(card);
      }

      function renderMemory() {
        const attached = memoryAttached();
        const targetId = state.debuggerSession?.target?.id ?? null;
        const stale = state.memoryResultOwner && !memoryOwnerCurrent(state.memoryResultOwner);
        if (!attached && !state.memorySearchPending && !state.memoryResultOwner && state.memorySearchStatus === 'idle') state.memorySearchStatus = 'offline';
        if (attached && state.memorySearchStatus === 'offline') state.memorySearchStatus = 'idle';
        elements.memoryTarget.textContent = attached ? `Selected target · ${targetId}` : 'Target unavailable';
        elements.memoryTarget.title = targetId ?? 'No selected target';
        const owner = state.memoryResultOwner;
        const pending = state.memoryOperation;
        elements.memorySubmission.textContent = pending
          ? `Submitted to ${pending.targetId} · ${new Date(pending.submittedAt).toLocaleTimeString()} · ${pending.action.replaceAll('_', ' ')}. Waiting does not stop native work.`
          : owner
            ? `${stale ? 'Expired context · historical preview' : 'Last successful result'} · target ${owner.targetId} · ${new Date(owner.submittedAt).toLocaleTimeString()} · ${owner.action.replaceAll('_', ' ')}${owner.baseline && owner.action === 'compare_heap_diff' ? ` · submitted baseline ${owner.baseline.target_id} at ${new Date(owner.baseline.captured_at_ms).toLocaleTimeString()}` : ''}`
            : state.memoryLastOperation
              ? `Last submitted action · target ${state.memoryLastOperation.targetId} · ${new Date(state.memoryLastOperation.submittedAt).toLocaleTimeString()} · no accepted result`
              : 'No submitted result. Editing criteria does not run a search.';
        elements.memorySubmission.dataset.stale = String(Boolean(stale));
        const attempt = state.memoryLastOperation;
        elements.memorySubmittedCriteria.textContent = pending
          ? `Pending attempt · target ${pending.targetId}\n${pending.criteria}`
          : owner
            ? `Retained result · target ${owner.targetId}\n${owner.criteria}${attempt && attempt !== owner ? `\n\nLatest attempt · target ${attempt.targetId} · ${new Date(attempt.submittedAt).toLocaleTimeString()}\n${attempt.criteria}` : ''}`
            : attempt ? `Latest attempt · target ${attempt.targetId}\n${attempt.criteria}` : 'No submitted criteria';
        const instructions = {live: 'Find an object by property, value, class, or shape. Inspect inert own-property previews.', snapshot: 'Capture once to find heap nodes, then follow retaining paths and incoming references.', diff: 'Capture a baseline, perform the page activity, then compare the current heap.', origin: 'Arm a bounded trace, trigger a page click, then inspect the first sampled appearance.'};
        elements.memoryWorkflow.textContent = instructions[state.memoryMode];
        const snapshotMode = state.memoryMode === 'snapshot';
        const diffMode = state.memoryMode === 'diff';
        const originMode = state.memoryMode === 'origin';
        const liveMode = state.memoryMode === 'live';
        const originTrace = state.debuggerSession?.memory_origin_trace ?? null;
        const originActive = originTrace?.target_id === targetId && ['armed', 'capturing', 'stepping', 'stopping'].includes(originTrace.state);
        elements.memorySearchForm.dataset.mode = state.memoryMode;
        elements.memoryModeButtons.forEach(button => {
          button.setAttribute('aria-pressed', String(button.dataset.memoryMode === state.memoryMode));
          button.disabled = state.memorySearchPending || state.debuggerActionPending;
        });
        elements.memorySearchForm.querySelectorAll('.memory-live-only').forEach(element => {
          element.hidden = !liveMode;
        });
        elements.memorySearchForm.querySelectorAll('.memory-search-only').forEach(element => {
          element.hidden = diffMode;
        });
        elements.memorySearchForm.querySelectorAll('.memory-reference-only').forEach(element => {
          element.hidden = !(snapshotMode || originMode);
        });
        elements.memorySearchForm.querySelectorAll('.memory-snapshot-only').forEach(element => {
          element.hidden = !snapshotMode;
        });
        elements.memorySearchForm.querySelectorAll('.memory-diff-only').forEach(element => {
          element.hidden = !diffMode;
        });
        elements.memorySearchForm.querySelectorAll('.memory-origin-only').forEach(element => {
          element.hidden = !originMode;
        });
        elements.memoryValueCaption.textContent = originMode ? 'Value or node name to trace' : snapshotMode ? 'Snapshot value or node name' : 'Value';
        elements.memoryValueQuery.placeholder = snapshotMode || originMode ? 'value from a request, closure, or unreachable object' : 'exact text or pattern';
        elements.memorySearchHelp.textContent = diffMode
          ? 'The baseline stays in local temporary storage until reset, target change, or shutdown. Current captures are deleted after native comparison.'
          : originMode
            ? 'The trace arms on the next page click, samples bounded heap snapshots at function-return boundaries, keeps only the requested context window, and deletes every temporary snapshot immediately.'
          : snapshotMode
            ? 'Capturing briefly pauses the target. Native C++ classifies root reachability and prioritizes hidden, internal, and weak incoming references. The temporary file is deleted immediately.'
            : 'Accessors are reported without invoking getters. Results are ephemeral and are never added to the evidence store.';
        const controls = elements.memorySearchForm.querySelectorAll('input, textarea, select');
        controls.forEach(control => { control.disabled = !attached || state.memorySearchPending || state.debuggerActionPending; });
        elements.memorySearchButton.disabled = !attached || state.memorySearchPending || state.debuggerActionPending;
        elements.memorySearchButton.setAttribute('aria-busy', String(state.memorySearchPending));
        elements.memorySearchButton.textContent = state.memorySearchPending
          ? originMode ? originTrace?.state === 'armed' ? 'Armed for page click...' : 'Tracing function boundaries...' : snapshotMode ? 'Capturing and indexing...' : 'Searching...'
          : originMode ? 'Arm origin trace' : snapshotMode ? 'Capture and search snapshot' : 'Search live objects';
        elements.memoryOriginStop.disabled = !originActive || state.debuggerActionPending;
        elements.memoryOriginReset.disabled = Boolean(originActive) || !originTrace || originTrace.state === 'idle' || state.debuggerActionPending;
        const baseline = state.memoryDiffBaseline;
        elements.memoryBaselineTitle.textContent = baseline ? 'Baseline ready' : 'Not captured';
        elements.memoryBaselineMeta.textContent = baseline
          ? `Target ${baseline.target_id} · ${formatByteSize(baseline.file_bytes)} · captured ${new Date(baseline.captured_at_ms).toLocaleString()}. Native target-scoped baseline; document identity is not supplied.`
          : 'Capture the target before the activity you want to measure.';
        elements.memoryCaptureBaseline.disabled = !attached || state.memorySearchPending || state.debuggerActionPending;
        elements.memoryClearBaseline.disabled = !attached || !baseline || baseline.target_id !== targetId || state.memorySearchPending || state.debuggerActionPending;
        elements.memoryCompareSnapshot.disabled = !attached || !baseline || baseline.target_id !== targetId || state.memorySearchPending || state.debuggerActionPending;
        elements.memoryCaptureBaseline.textContent = state.memoryOperation?.action === 'capture_heap_diff_baseline'
          ? 'Capturing baseline...' : baseline ? 'Replace baseline' : 'Capture baseline';
        elements.memoryCompareSnapshot.textContent = state.memoryOperation?.action === 'compare_heap_diff'
          ? 'Capturing and comparing...' : 'Capture current and compare';

        const messages = diffMode ? {
          offline: 'Run a live session to attach an authorized browser target.',
          idle: state.memorySearchMessage || (baseline
            ? 'Baseline ready. Run the activity you want to measure, then compare.'
            : 'Capture a baseline before the page activity you want to measure.'),
          searching: state.memorySearchMessage || 'Capturing a bounded heap snapshot for native comparison.',
          empty: state.memorySearchMessage || 'The compared heaps have no reported memory changes.',
          ready: state.memorySearchMessage || 'Native retained-memory comparison completed.',
          partial: state.memorySearchMessage || 'Heap comparison completed with explicit bounded coverage.',
          error: state.memorySearchMessage || 'Native heap comparison failed.'
        } : originMode ? {
          offline: 'Run a live session to attach an authorized browser target.',
          idle: state.memorySearchMessage || 'Enter a value, arm the trace, then click the page action that creates it.',
          searching: state.memorySearchMessage || originTrace?.message || 'Sampling bounded heap snapshots at debugger function boundaries.',
          empty: state.memorySearchMessage || originTrace?.message || 'The value did not appear in the bounded temporal trace.',
          ready: state.memorySearchMessage || originTrace?.message || 'The first sampled appearance is highlighted with its source function.',
          partial: state.memorySearchMessage || originTrace?.message || 'The origin was found with explicit partial context or snapshot coverage.',
          error: state.memorySearchMessage || originTrace?.message || 'Memory Origin Trace failed.'
        } : snapshotMode ? {
          offline: 'Run a live session to attach an authorized browser target.',
          idle: state.memorySearchMessage || 'Enter a value to capture and search the full V8 heap, including unreachable nodes.',
          searching: 'Capturing the target heap, then building a bounded native C++ reachability and reference index.',
          empty: state.memorySearchMessage || 'No snapshot nodes matched the current value.',
          ready: state.memorySearchMessage || 'Native heap snapshot search completed.',
          partial: state.memorySearchMessage || 'Native heap snapshot search returned explicit partial coverage.',
          error: state.memorySearchMessage || 'Native heap snapshot search failed.'
        } : {
          offline: 'Run a live session to attach an authorized browser target.',
          idle: state.memorySearchMessage || 'Enter a property, primitive value, class, or JSON shape to search live objects.',
          searching: 'Scanning the attached page with explicit time, candidate, and result limits.',
          empty: state.memorySearchMessage || 'No live objects matched the current criteria.',
          ready: state.memorySearchMessage || 'Live object search completed.',
          partial: state.memorySearchMessage || 'Live object search returned partial bounded results.',
          error: state.memorySearchMessage || 'Live object search failed.'
        };
        elements.memoryNotice.dataset.kind = state.memorySearchStatus;
        elements.memoryNotice.textContent = state.memorySearchStatus === 'unavailable' ? state.memorySearchMessage : messages[state.memorySearchStatus] ?? messages.idle;
        elements.memoryResultLabel.textContent = diffMode ? '2 · Changed groups' : originMode ? '2 · Sampled steps' : '2 · Matches';
        elements.memoryResultCount.textContent = String(state.memoryResults.length);
        elements.memoryResults.setAttribute('aria-label', diffMode ? 'Heap growth groups' : originMode ? 'Memory origin trace steps' : snapshotMode ? 'Heap snapshot matches' : 'Live object matches');

        const memoryResultsPane = elements.memoryDetail.parentElement;
        const signature = memoryResultSignature();
        const previous = state.memoryRenderSignature;
        const sameRows = previous?.rows === signature.rows && previous?.mode === signature.mode;
        const sameDetail = sameRows && previous?.selected === signature.selected && previous?.stale === signature.stale &&
          (state.memoryResults.length > 0 || previous?.status === state.memorySearchStatus) &&
          (originMode || previous?.meta === signature.meta);
        if (sameDetail) return;
        const focusedId = elements.memoryResults.contains(document.activeElement) ? document.activeElement?.dataset.resultId : null;
        const resultsTop = elements.memoryResults.parentElement.scrollTop;
        const detailTop = elements.memoryDetail.scrollTop;
        state.memoryRenderSignature = {...signature, status: state.memorySearchStatus};
        if (state.memoryResults.length === 0) {
          const empty = textElement('div', 'memory-empty', state.memorySearchStatus === 'partial'
            ? 'No matches in the inspected subset. Coverage limits prevent a claim of complete absence.'
            : state.memorySearchStatus === 'empty'
            ? originMode
              ? 'The bounded trace contains no retained steps for this result.'
              : snapshotMode
              ? 'No heap nodes matched this value and reference scope. Adjust the value or scope.'
              : diffMode ? 'The compared heaps have no reported memory changes.'
                : 'No objects matched. Broaden one criterion or lower the similarity threshold.'
            : ['error', 'unavailable'].includes(state.memorySearchStatus)
              ? 'Results unavailable. No accepted results were returned; this is not an empty search.'
                : diffMode ? state.memorySearchMeta ? 'No changed signature groups. Retained-owner changes are shown in the comparison detail.' : 'Capture a baseline, use the page, then compare a second snapshot to see what grew.' : originMode ? 'Enter the value to trace, arm the trace, then perform the page action that creates it.' : snapshotMode ? 'Enter a value, then capture a snapshot to find matching objects and references.' : 'Enter a property name or value, then run a bounded live-object search.');
          elements.memoryResults.removeAttribute('role');
          elements.memoryResults.replaceChildren(empty);
          memoryResultsPane?.setAttribute('data-empty', 'true');
          elements.memoryDetail.hidden = !(diffMode && state.memorySearchMeta);
          if (diffMode && state.memorySearchMeta) { memoryResultsPane?.setAttribute('data-empty', 'false'); renderHeapDiffDetail(null); }
          else elements.memoryDetail.replaceChildren();
          return;
        }
        memoryResultsPane?.setAttribute('data-empty', 'false');
        elements.memoryDetail.hidden = false;
        elements.memoryResults.setAttribute('role', 'listbox');
        if (!state.memoryResults.some(result => result.id === state.selectedMemoryResultId)) {
          state.selectedMemoryResultId = state.memoryResults[0].id;
        }
        if (!sameRows) elements.memoryResults.replaceChildren(...state.memoryResults.map(result => {
          const row = document.createElement('button');
          row.type = 'button'; row.className = 'memory-result-row'; row.dataset.resultId = result.id;
          row.setAttribute('role', 'option');
          row.setAttribute('aria-selected', String(result.id === state.selectedMemoryResultId));
          row.tabIndex = result.id === state.selectedMemoryResultId ? 0 : -1;
          if (originMode) row.dataset.firstMatch = String(result.is_first_match);
          const score = diffMode
            ? formatSignedByteSize(result.self_size_delta)
            : originMode
            ? result.is_first_match ? 'origin' : result.matched ? 'present' : 'absent'
            : snapshotMode
            ? result.reachable ? 'root' : 'unreachable'
            : result.similarity === null ? 'match' : `${Math.round(result.similarity * 100)}%`;
          const title = diffMode ? result.name || `(${result.type})` : originMode ? result.location.function_name || '(anonymous)' : snapshotMode ? result.name || `(${result.type})` : result.class_name || 'Object';
          const metadata = diffMode
            ? `${result.type} · ${result.baseline_count.toLocaleString()} → ${result.current_count.toLocaleString()} objects (${formatSignedCount(result.count_delta)})`
            : originMode
            ? `step ${result.step} · ${`${result.location.url || '(recorded anonymous script)'}:${result.location.line + 1}:${result.location.column + 1}`} · ${result.analyzed_nodes.toLocaleString()} nodes in ${result.duration_ms} ms`
            : snapshotMode
            ? `${result.type} · ${result.self_size.toLocaleString()} self bytes · ${result.incoming_reference_count.toLocaleString()} incoming references`
            : `${result.property_count} properties · ${result.preview.slice(0, 5).map(property => property.name).join(', ') || 'no own properties'}`;
          row.append(
            textElement('span', 'memory-result-class', title),
            textElement('span', 'memory-result-score', score),
            textElement('span', 'memory-result-meta', metadata)
          );
          row.addEventListener('click', () => selectMemoryResult(result.id));
          row.addEventListener('keydown', moveMemorySelection);
          return row;
        }));
        for (const row of elements.memoryResults.querySelectorAll('.memory-result-row')) {
          const selected = row.dataset.resultId === state.selectedMemoryResultId;
          row.setAttribute('aria-selected', String(selected)); row.tabIndex = selected ? 0 : -1;
        }
        const disclosure = elements.memoryDetail.querySelector('.memory-detail-disclosure');
        const disclosureOpen = previous?.selected === signature.selected ? disclosure?.open : undefined;
        const disclosureFocused = disclosure?.querySelector('summary') === document.activeElement;
        renderMemoryDetail();
        const nextDisclosure = elements.memoryDetail.querySelector('.memory-detail-disclosure');
        if (nextDisclosure && disclosureOpen !== undefined) nextDisclosure.open = disclosureOpen;
        if (disclosureFocused) nextDisclosure?.querySelector('summary')?.focus({preventScroll: true});
        elements.memoryResults.parentElement.scrollTop = resultsTop;
        if (previous?.selected === signature.selected) elements.memoryDetail.scrollTop = detailTop;
        if (focusedId) [...elements.memoryResults.querySelectorAll('.memory-result-row')]
          .find(row => row.dataset.resultId === focusedId)?.focus({ preventScroll: true });
      }

      function applyMemoryOriginTrace(trace) {
        if (!isMemoryOriginTrace(trace) || new Set(trace.steps.map(step => step.id)).size !== trace.steps.length) return false;
        const targetId = state.debuggerSession?.target?.id ?? null;
        if (trace.state !== 'idle' && trace.target_id !== targetId) return false;
        if (state.memoryOperation) return false;
        const sameEpoch = state.memoryResultOwner?.nativeEpoch === (state.memoryNativeEpoch ?? 0) &&
          state.memoryResultOwner?.targetId === targetId;
        const previousTrace = state.memoryMode === 'origin' && sameEpoch ? state.memorySearchMeta : null;
        if (previousTrace?.trace_id > trace.trace_id && trace.state !== 'idle') return false;
        if (previousTrace?.trace_id === trace.trace_id && (previousTrace.step_count > trace.step_count ||
            (!['armed', 'capturing', 'stepping', 'stopping'].includes(previousTrace.state) && ['armed', 'capturing', 'stepping', 'stopping'].includes(trace.state)))) return false;
        if (sameEpoch && state.memorySearchMeta?.trace_id === trace.trace_id && !memoryOwnerCurrent(state.memoryResultOwner)) return false;
        const active = ['armed', 'capturing', 'stepping', 'stopping'].includes(trace.state);
        if (active && state.memoryMode !== 'origin') state.memoryMode = 'origin';
        if (state.memoryMode !== 'origin') return true;
        if (trace.state === 'idle' && state.memoryResultOwner) {
          state.memoryResultOwner.expired = true;
          state.memorySearchPending = false;
          state.memorySearchStatus = 'unavailable';
          state.memorySearchMessage = 'The native trace is no longer available. Retained samples are historical; no active trace or complete absence is implied.';
          return true;
        }
        const previousFirstMatch = state.memorySearchMeta?.first_match_step ?? null;
        if (trace.trace_id > 0 && (!sameEpoch || state.memorySearchMeta?.trace_id !== trace.trace_id)) {
          state.memoryResultOwner = {targetId: trace.target_id, scopeVersion: state.memoryScopeVersion ?? 0, nativeEpoch: state.memoryNativeEpoch ?? 0,
            submittedAt: trace.started_at_ms, action: 'start_memory_origin_trace', mode: 'origin',
            criteria: `${trace.query} · ${trace.scope} · trace ${trace.trace_id}`, baseline: null};
          state.memoryLastOperation = state.memoryResultOwner;
        }
        state.memorySearchMeta = trace;
        state.memoryResults = trace.steps;
        state.memoryTargetId = trace.target_id;
        state.memorySearchPending = active;
        const firstMatch = trace.steps.find(step => step.is_first_match);
        if (firstMatch && previousFirstMatch !== trace.first_match_step) {
          state.selectedMemoryResultId = firstMatch.id;
        } else if (!trace.steps.some(step => step.id === state.selectedMemoryResultId)) {
          state.selectedMemoryResultId = firstMatch?.id ?? trace.steps.at(-1)?.id ?? null;
        }
        const coverage = trace.limit_reason ? ` · ${trace.limit_reason.replaceAll('_', ' ')}` : '';
        state.memorySearchMessage = trace.state === 'idle'
          ? null
          : `${trace.message} · ${trace.step_count}/${trace.step_limit} sampled steps${coverage}`;
        if (active) state.memorySearchStatus = 'searching';
        else if (trace.state === 'found') state.memorySearchStatus = trace.partial ? 'partial' : 'ready';
        else if (trace.state === 'not_found') state.memorySearchStatus = trace.partial ? 'partial' : 'empty';
        else if (trace.state === 'error') state.memorySearchStatus = 'error';
        else if (trace.state === 'aborted') state.memorySearchStatus = trace.steps.length > 0 ? 'partial' : 'idle';
        else state.memorySearchStatus = memoryAttached() ? 'idle' : 'offline';
        return true;
      }

      async function runMemoryOriginTrace() {
        if (!memoryAttached() || state.memorySearchPending) return;
        const query = elements.memoryValueQuery.value.trim();
        if (!query) {
          state.memorySearchStatus = 'error';
          state.memorySearchMessage = 'Enter one value or node name to trace.';
          renderMemory();
          elements.memoryValueQuery.focus();
          return;
        }
        const beforeSteps = Number(elements.memoryOriginBefore.value);
        const afterSteps = Number(elements.memoryOriginAfter.value);
        if (!Number.isInteger(beforeSteps) || beforeSteps < 0 || beforeSteps > 8 ||
            !Number.isInteger(afterSteps) || afterSteps < 0 || afterSteps > 16) {
          state.memorySearchStatus = 'error';
          state.memorySearchMessage = 'Choose 0 to 8 steps before and 0 to 16 steps after the first match.';
          renderMemory();
          return;
        }
        const operation = beginMemoryOperation('start_memory_origin_trace', `${query} · ${elements.memoryReferenceScope.value} · ${beforeSteps} before / ${afterSteps} after`);
        if (!operation) return;
        state.memorySearchStatus = 'searching';
        state.memorySearchMessage = 'Arming a bounded click-driven temporal trace.';
        renderMemory();
        const body = await debuggerAction({
          action: 'start_memory_origin_trace', query,
          scope: elements.memoryReferenceScope.value,
          case_sensitive: false,
          before_steps: beforeSteps,
          after_steps: afterSteps
        }, operation);
        if (!finishMemoryOperation(operation, body)) return;
        if (!isMemoryAcknowledgement(body, true) || !isMemoryOriginTrace(body.trace) || body.trace.target_id !== operation.targetId ||
            body.trace.query !== query || body.trace.scope !== elements.memoryReferenceScope.value ||
            body.trace.before_steps !== beforeSteps || body.trace.after_steps !== afterSteps) {
          reconcileMemoryOrigin(operation);
          state.memoryLastOperation = operation;
          memoryOperationFailed(state.debuggerError || 'The debugger returned malformed Memory Origin Trace state.');
          renderMemory();
          return;
        }
        if (!reconcileMemoryOrigin(operation, body)) memoryOperationFailed('The returned trace could not be adopted with its recorded identity.');
        renderMemory();
      }

      async function stopMemoryOriginTrace() {
        const trace = state.debuggerSession?.memory_origin_trace;
        if (!memoryOriginTraceActive() || trace?.target_id !== state.debuggerSession?.target?.id || state.debuggerActionPending) return;
        const owner = {targetId: trace.target_id, scopeVersion: state.memoryScopeVersion ?? 0, nativeEpoch: state.memoryNativeEpoch ?? 0,
          pollSequence: state.memoryPollSequence ?? 0, submittedGeneration: state.debuggerSession.generation,
          action: 'stop_memory_origin_trace', mode: 'origin', submittedAt: Date.now(), criteria: `Stop trace ${trace.trace_id}`, baseline: null,
          traceId: trace.trace_id, traceStartedAt: trace.started_at_ms};
        state.memoryLastOperation = owner;
        const body = await debuggerAction({ action: 'stop_memory_origin_trace' }, owner);
        if (!memoryOwnerCurrent(owner) || state.debuggerSession?.memory_origin_trace?.trace_id !== trace.trace_id) return;
        if (!isMemoryAcknowledgement(body, true) || body.generation < owner.submittedGeneration || !isMemoryOriginTrace(body.trace) || body.trace.trace_id !== trace.trace_id || body.trace.target_id !== owner.targetId) {
          reconcileMemoryOrigin(owner);
          memoryOperationFailed(state.debuggerError || 'The native stop outcome is unknown.');
        } else reconcileMemoryOrigin(owner, body);
        renderMemory();
      }

      async function clearMemoryOriginTrace() {
        if (state.memorySearchPending) return;
        const operation = beginMemoryOperation('clear_memory_origin_trace', 'Clear trace result');
        if (!operation) return;
        renderMemory();
        const body = await debuggerAction({ action: 'clear_memory_origin_trace' }, operation);
        if (!finishMemoryOperation(operation, body)) return;
        if (!isMemoryAcknowledgement(body)) {
          reconcileMemoryOrigin(operation);
          state.memoryLastOperation = operation;
          memoryOperationFailed(state.debuggerError || 'The native clear outcome is unknown.');
          renderMemory(); return;
        }
        const newerTrace = memoryTracePollAfter(operation, body.generation);
        if (newerTrace && newerTrace.state !== 'idle') {
          applyMemoryOriginTrace(newerTrace);
          state.memorySearchMessage = 'Clear acknowledged. A newer validated native trace is retained.';
          renderMemory(); return;
        }
        state.memoryResults = [];
        state.selectedMemoryResultId = null;
        state.memorySearchMeta = null;
        state.memoryResultOwner = null;
        state.memoryTargetId = null;
        state.memorySearchStatus = memoryAttached() ? 'idle' : 'offline';
        state.memorySearchMessage = 'Temporal trace result cleared.';
        renderMemory();
      }

      async function runLiveObjectSearch() {
        if (!memoryAttached() || state.memorySearchPending) return;
        if (state.memoryMode === 'diff') {
          await runHeapSnapshotDiff();
          return;
        }
        if (state.memoryMode === 'snapshot') {
          await runHeapSnapshotSearch();
          return;
        }
        if (state.memoryMode === 'origin') {
          await runMemoryOriginTrace();
          return;
        }
        const request = {
          action: 'search_live_objects',
          property_query: elements.memoryPropertyQuery.value.trim(),
          value_query: elements.memoryValueQuery.value.trim(),
          class_query: elements.memoryClassQuery.value.trim(),
          shape: elements.memoryShapeQuery.value.trim(),
          similarity_threshold: Number(elements.memorySimilarityThreshold.value),
          regex: elements.memoryRegex.checked,
          case_sensitive: elements.memoryCaseSensitive.checked,
          include_shape_values: elements.memoryShapeValues.checked
        };
        if (!request.property_query && !request.value_query && !request.class_query && !request.shape) {
          state.memorySearchStatus = 'error';
          state.memorySearchMessage = 'Enter at least one property, value, class, or structural shape criterion.';
          renderMemory();
          elements.memoryPropertyQuery.focus();
          return;
        }
        const operation = beginMemoryOperation('search_live_objects', JSON.stringify(request));
        if (!operation) return;
        state.memorySearchStatus = 'searching';
        state.memorySearchMessage = null;
        renderMemory();
        const body = await debuggerAction(request, operation);
        if (!finishMemoryOperation(operation, body)) return;
        if (!isLiveObjectSearchResponse(body) || new Set(body.search.results.map(result => result.id)).size !== body.search.results.length) {
          memoryOperationFailed(state.debuggerError || 'The debugger returned malformed live object results.');
          renderMemory();
          return;
        }
        const search = body.search;
        state.memoryResults = search.results;
        state.selectedMemoryResultId = search.results[0]?.id ?? null;
        state.memorySearchMeta = search;
        commitMemoryOwner(operation);
        const limits = [];
        if (search.timed_out) limits.push('time limit reached');
        if (search.result_limit_reached) limits.push(`${search.result_limit} result limit reached`);
        if (search.scan_limit_reached) limits.push('candidate limit reached');
        if (search.property_limit_reached) limits.push('property limit reached');
        const summary = `${search.results.length} ${search.results.length === 1 ? 'match' : 'matches'} from ${search.analyzed} inspected objects in ${search.duration_ms} ms`;
        state.memorySearchMessage = limits.length > 0 ? `${summary} · ${limits.join(' · ')}` : summary;
        state.memorySearchStatus = limits.length > 0 ? 'partial' : search.results.length > 0 ? 'ready' : 'empty';
        renderMemory();
      }

      async function runHeapSnapshotSearch() {
        if (!memoryAttached() || state.memorySearchPending || state.debuggerActionPending) return;
        const query = elements.memoryValueQuery.value.trim();
        if (!query) {
          state.memorySearchStatus = 'error';
          state.memorySearchMessage = 'Enter one snapshot value or node name.';
          renderMemory();
          elements.memoryValueQuery.focus();
          return;
        }
        const operation = beginMemoryOperation('search_heap_snapshot', `${query} · ${elements.memoryReferenceScope.value}`);
        if (!operation) return;
        state.memorySearchStatus = 'searching';
        state.memorySearchMessage = null;
        renderMemory();
        const body = await debuggerAction({
          action: 'search_heap_snapshot', query, case_sensitive: false,
          scope: elements.memoryReferenceScope.value
        }, operation);
        if (!finishMemoryOperation(operation, body)) return;
        if (!isHeapSnapshotSearchResponse(body) || new Set(body.snapshot.results.map(result => result.id)).size !== body.snapshot.results.length || body.snapshot.scope !== elements.memoryReferenceScope.value) {
          memoryOperationFailed(state.debuggerError || 'The native snapshot index returned malformed results.');
          renderMemory();
          return;
        }
        const snapshot = body.snapshot;
        state.memoryResults = snapshot.results;
        state.selectedMemoryResultId = snapshot.results[0]?.id ?? null;
        state.memorySearchMeta = snapshot;
        commitMemoryOwner(operation);
        const limits = [];
        if (snapshot.result_limit_reached) limits.push(`${snapshot.result_limit} result limit reached`);
        if (snapshot.node_limit_reached) limits.push('node limit reached');
        if (snapshot.edge_limit_reached) limits.push('edge limit reached');
        if (snapshot.string_limit_reached) limits.push('string budget reached');
        if (snapshot.retaining_paths_partial) limits.push('some retaining paths are partial');
        if (snapshot.results.some(result => result.incoming_reference_limit_reached)) {
          limits.push(`${snapshot.reference_limit} incoming reference display limit reached`);
        }
        const scopeLabel = snapshot.scope === 'unreachable' ? 'unreachable' : snapshot.scope === 'reachable' ? 'root-reachable' : 'total';
        const summary = `${snapshot.results.length} shown of ${snapshot.matched_nodes.toLocaleString()} ${scopeLabel} ${snapshot.matched_nodes === 1 ? 'match' : 'matches'} across ${snapshot.analyzed_nodes.toLocaleString()} nodes in ${snapshot.duration_ms} ms`;
        state.memorySearchMessage = limits.length > 0 ? `${summary} · ${limits.join(' · ')}` : summary;
        state.memorySearchStatus = limits.length > 0 ? 'partial' : snapshot.results.length > 0 ? 'ready' : 'empty';
        renderMemory();
      }

      async function captureHeapDiffBaseline() {
        if (!memoryAttached() || state.memorySearchPending) return;
        const operation = beginMemoryOperation('capture_heap_diff_baseline', 'Capture baseline');
        if (!operation) return;
        state.memorySearchStatus = 'searching';
        state.memorySearchMessage = 'Capturing the comparison baseline. The target may pause briefly.';
        renderMemory();
        const body = await debuggerAction({ action: 'capture_heap_diff_baseline' }, operation);
        if (!finishMemoryOperation(operation, body)) return;
        if (!isHeapDiffBaselineResponse(body) || body.baseline.target_id !== operation.targetId) {
          memoryOperationFailed(state.debuggerError || 'The debugger returned malformed baseline metadata.');
          renderMemory();
          return;
        }
        if (keepNewerMemoryBaseline(operation, body)) return;
        state.memoryBaselineGeneration = body.generation;
        state.memoryDiffBaseline = body.baseline;
        state.memoryResults = [];
        state.selectedMemoryResultId = null;
        state.memorySearchMeta = null;
        commitMemoryOwner(operation);
        state.memorySearchStatus = 'ready';
        state.memorySearchMessage = `${formatByteSize(body.baseline.file_bytes)} baseline captured. Run the activity you want to measure, then compare.`;
        renderMemory();
      }

      async function clearHeapDiffBaseline() {
        if (state.memorySearchPending || !state.memoryDiffBaseline) return;
        const operation = beginMemoryOperation('clear_heap_diff_baseline', 'Reset baseline');
        if (!operation) return;
        renderMemory();
        const body = await debuggerAction({ action: 'clear_heap_diff_baseline' }, operation);
        if (!finishMemoryOperation(operation, body)) return;
        if (!isMemoryAcknowledgement(body)) {
          memoryOperationFailed(state.debuggerError || 'The heap comparison baseline could not be reset.');
          renderMemory();
          return;
        }
        if (keepNewerMemoryBaseline(operation, body)) return;
        state.memoryBaselineGeneration = body.generation;
        state.memoryResultOwner = null;
        state.memoryDiffBaseline = null;
        state.memoryResults = [];
        state.selectedMemoryResultId = null;
        state.memorySearchMeta = null;
        state.memorySearchStatus = memoryAttached() ? 'idle' : 'offline';
        state.memorySearchMessage = 'Baseline reset and its local temporary file was deleted.';
        renderMemory();
      }

      async function runHeapSnapshotDiff() {
        if (!memoryAttached() || state.memorySearchPending) return;
        if (!state.memoryDiffBaseline || state.memoryDiffBaseline.target_id !== state.debuggerSession?.target?.id) {
          state.memorySearchStatus = 'error';
          state.memorySearchMessage = 'Capture a baseline before comparing the heap.';
          renderMemory();
          elements.memoryCaptureBaseline.focus();
          return;
        }
        const operation = beginMemoryOperation('compare_heap_diff', 'Capture current and compare');
        if (!operation) return;
        state.memorySearchStatus = 'searching';
        state.memorySearchMessage = 'Capturing the current heap, then computing dominators and retained-size changes within the native index.';
        renderMemory();
        const body = await debuggerAction({ action: 'compare_heap_diff' }, operation);
        if (!finishMemoryOperation(operation, body)) return;
        if (!isHeapSnapshotDiffResponse(body)) {
          memoryOperationFailed(state.debuggerError || 'The native heap comparison returned malformed results.');
          renderMemory();
          return;
        }
        const diff = body.diff;
        state.memoryResults = diff.groups.map((group, index) => ({ ...group, id: `heap-diff-${index}` }));
        state.selectedMemoryResultId = state.memoryResults[0]?.id ?? null;
        state.memorySearchMeta = diff;
        commitMemoryOwner(operation);
        const limits = [];
        if (diff.group_result_limit_reached) limits.push(`${diff.result_limit} group limit reached`);
        if (diff.dominator_result_limit_reached) limits.push(`${diff.result_limit} dominator limit reached`);
        if (diff.aggregation_limit_reached) limits.push('signature budget reached');
        if (diff.baseline_node_limit_reached || diff.current_node_limit_reached) limits.push('node limit reached');
        if (diff.baseline_edge_limit_reached || diff.current_edge_limit_reached) limits.push('edge limit reached');
        if (diff.baseline_string_limit_reached || diff.current_string_limit_reached) limits.push('string budget reached');
        if (diff.retained_size_saturated) limits.push('size counter saturated');
        const summary = `${diff.groups.length} changed ${diff.groups.length === 1 ? 'group' : 'groups'}, ${diff.dominators.length} retained owners, ${formatSignedByteSize(diff.self_size_delta)} total self memory in ${diff.duration_ms} ms`;
        state.memorySearchMessage = limits.length > 0 ? `${summary} · ${limits.join(' · ')}` : summary;
        state.memorySearchStatus = limits.length > 0
          ? 'partial'
          : diff.groups.length > 0 || diff.dominators.length > 0 ? 'ready' : 'empty';
        renderMemory();
      }

      function setMemoryMode(mode) {
        if (!['live', 'snapshot', 'diff', 'origin'].includes(mode) || state.memorySearchPending || state.debuggerActionPending || mode === state.memoryMode) return;
        state.memoryMode = mode;
        state.memoryTargetId = null;
        state.memoryLastOperation = null;
        state.memoryResultOwner = null;
        state.memoryResults = [];
        state.selectedMemoryResultId = null;
        state.memorySearchMeta = null;
        state.memorySearchMessage = null;
        state.memorySearchStatus = memoryAttached() ? 'idle' : 'offline';
        if (mode === 'origin') applyMemoryOriginTrace(state.debuggerSession?.memory_origin_trace);
        renderMemory();
      }

      function debuggerValueText(value) {
        if (!value) return 'unavailable';
        if (value.unserializable_value) return value.unserializable_value;
        const suffix = value.value_truncated ? '…' : '';
        if (value.type === 'string') return `${JSON.stringify(value.value ?? '')}${suffix}`;
        if (value.value !== null && value.value !== undefined) return `${String(value.value)}${suffix}`;
        return value.description || value.class_name || value.subtype || value.type;
      }

      function debuggerScriptName(scriptId, fallbackUrl = '') {
        const script = state.debuggerSession?.scripts.find(candidate => candidate.script_id === scriptId);
        if (script) return sourceName({ ...script, source_type: 'script' });
        if (fallbackUrl) return sourceName({ url: fallbackUrl, source_type: 'script', script_id: scriptId });
        return `(script ${scriptId})`;
      }

      function debuggerLocationText(location, fallbackUrl = '') {
        return `${debuggerScriptName(location.script_id, fallbackUrl)}:${location.line + 1}:${location.column + 1}`;
      }

      function selectedCallFrame() {
        const frames = state.debuggerSession?.paused?.call_frames ?? [];
        return frames.find(frame => frame.id === state.selectedCallFrameId) ?? frames[0] ?? null;
      }

      function memoryOriginTraceActive() {
        return ['armed', 'capturing', 'stepping', 'stopping'].includes(
          state.debuggerSession?.memory_origin_trace?.state
        );
      }

      function renderSourceSidebar() {
        const attached = ['running', 'paused'].includes(state.debuggerSession?.state);
        const open = state.sourceSidebarOpen ?? (attached || state.debuggerSession?.state === 'crashed');
        elements.sourceSidebar.dataset.attached = String(attached);
        elements.sourceSidebar.hidden = !open;
        document.querySelector('#screen-sources').dataset.sidebarOpen = String(open);
        elements.sourceSidebarToggle.setAttribute('aria-expanded', String(open));
        elements.sourceSidebarToggle.textContent = attached ? 'Debugger' : 'Details';
        elements.sourceSidebarToggle.title = attached ? 'Toggle debugger sidebar' : 'Source details and debugger connection status';
      }

      function renderDebuggerState() {
        renderSourceSidebar();
        const session = state.debuggerSession;
        const originTraceActive = memoryOriginTraceActive();
        const stateLabels = {
          unavailable: 'Offline', waiting: 'Waiting', connecting: 'Attaching', running: 'Running', paused: 'Paused', crashed: 'Crashed'
        };
        const line = document.createElement('div'); line.className = 'debug-state-line';
        const label = document.createElement('strong'); label.textContent = stateLabels[session?.state] ?? 'Offline';
        const target = document.createElement('span'); target.className = 'debug-target';
        target.textContent = session?.target?.title || (session?.state === 'unavailable'
          ? 'Run make live to attach the browser debugger'
          : 'Waiting for an authorized browser target');
        line.append(label, target);
        const nodes = [line];
        if ((session?.targets.length ?? 0) > 1) {
          const select = document.createElement('select'); select.id = 'debugger-target-select'; select.name = 'debugger_target';
          select.className = 'debug-select'; select.setAttribute('aria-label', 'Debugger target');
          session.targets.filter(candidate => ['page', 'webview'].includes(candidate.type)).forEach(candidate => {
            const option = document.createElement('option'); option.value = candidate.id; option.textContent = candidate.title || candidate.url || candidate.id;
            option.selected = candidate.id === session.target?.id; select.append(option);
          });
          select.disabled = originTraceActive;
          select.addEventListener('change', () => debuggerAction({ action: 'select_target', target_id: select.value }));
          nodes.push(select);
        }
        if (state.debuggerError || session?.error) {
          const error = document.createElement('div'); error.className = 'debug-state-error'; error.textContent = state.debuggerError || session.error; nodes.push(error);
        }
        elements.debugState.replaceChildren(...nodes);
      }

      function renderCallStack() {
        const originTraceActive = memoryOriginTraceActive();
        const paused = state.debuggerSession?.paused;
        if (!paused || paused.call_frames.length === 0) {
          elements.callStack.textContent = state.debuggerSession?.state === 'paused' ? 'No JavaScript frames were reported.' : 'Not paused';
          return;
        }
        const nodes = [];
        const appendFrame = (frame, async = false) => {
          const row = document.createElement('button'); row.type = 'button'; row.className = 'call-frame';
          row.setAttribute('aria-selected', String(!async && frame.id === state.selectedCallFrameId));
          const name = document.createElement('span'); name.className = 'call-frame-name'; name.textContent = frame.function_name || '(anonymous)';
          const location = document.createElement('span'); location.className = 'call-frame-location'; location.textContent = debuggerLocationText(frame.location, frame.url);
          row.append(name, location);
          row.addEventListener('click', () => {
            if (async) {
              revealDebuggerLocation(frame.location);
              return;
            }
            selectCallFrame(frame);
          });
          nodes.push(row);
        };
        paused.call_frames.forEach(frame => appendFrame(frame));
        paused.async_stack.forEach(stack => {
          const label = document.createElement('div'); label.className = 'async-stack-label'; label.textContent = stack.description || 'Async'; nodes.push(label);
          (stack.call_frames ?? []).forEach(frame => appendFrame(frame, true));
        });
        const tools = document.createElement('div'); tools.className = 'debug-form';
        const restart = document.createElement('button'); restart.type = 'button'; restart.textContent = 'Restart frame';
        restart.disabled = originTraceActive;
        restart.addEventListener('click', () => {
          const frame = selectedCallFrame();
          if (frame) debuggerAction({ action: 'restart_frame', call_frame_id: frame.id });
        });
        const copy = document.createElement('button'); copy.type = 'button'; copy.textContent = 'Copy stack';
        copy.addEventListener('click', () => copyStackTrace(paused));
        tools.append(restart, copy); nodes.push(tools);
        elements.callStack.replaceChildren(...nodes);
      }

      async function copyStackTrace(paused) {
        const lines = paused.call_frames.map(frame => `${frame.function_name} (${debuggerLocationText(frame.location, frame.url)})`);
        paused.async_stack.forEach(stack => {
          lines.push(`--- ${stack.description || 'Async'} ---`);
          (stack.call_frames ?? []).forEach(frame => lines.push(`${frame.function_name} (${debuggerLocationText(frame.location, frame.url)})`));
        });
        try { await navigator.clipboard.writeText(lines.join('\n')); }
        catch { state.debuggerError = 'The call stack could not be copied to the clipboard.'; renderDebuggerState(); }
      }

      function selectCallFrame(frame) {
        state.selectedCallFrameId = frame.id;
        revealDebuggerLocation(frame.location);
        if (!memoryOriginTraceActive()) {
          debuggerAction({ action: 'evaluate_watches', call_frame_id: frame.id });
        }
        renderDebugger();
      }

      function revealDebuggerLocation(location) {
        const source = liveSources().find(candidate => candidate.script_id === location.script_id);
        if (!source) return false;
        selectScript(source.script_id, location.line);
        return true;
      }

      function renderScope() {
        const frame = selectedCallFrame();
        if (!frame) {
          elements.scopeList.textContent = 'Not paused';
          return;
        }
        const nodes = [];
        frame.scopes.forEach((scope, index) => {
          const group = document.createElement('details'); group.className = 'scope-group'; group.open = index < 2;
          const summary = document.createElement('summary'); summary.textContent = scope.name || `${scope.type[0].toUpperCase()}${scope.type.slice(1)}`;
          const properties = scope.properties.map(property => {
            const row = document.createElement('div'); row.className = 'scope-property';
            const name = document.createElement('span'); name.className = 'scope-property-name'; name.textContent = property.name;
            const value = document.createElement('span'); value.className = 'scope-property-value'; value.textContent = debuggerValueText(property.value ?? property.get);
            row.append(name, value); return row;
          });
          if (properties.length === 0) properties.push(textElement('div', 'debug-pane-empty', 'No retained properties'));
          group.append(summary, ...properties); nodes.push(group);
        });
        if (frame.this) {
          const row = document.createElement('div'); row.className = 'scope-property';
          const name = document.createElement('span'); name.className = 'scope-property-name'; name.textContent = 'this';
          const value = document.createElement('span'); value.className = 'scope-property-value'; value.textContent = debuggerValueText(frame.this);
          row.append(name, value); nodes.unshift(row);
        }
        const coverage = state.debuggerSession.paused.scope_coverage;
        const note = document.createElement('div'); note.className = 'debug-row-meta';
        note.textContent = `${coverage.status} · ${coverage.properties}/${coverage.limit} bounded properties`;
        nodes.push(note);
        elements.scopeList.replaceChildren(...nodes);
      }

      function renderWatches() {
        const originTraceActive = memoryOriginTraceActive();
        const watches = state.debuggerSession?.watches ?? [];
        const nodes = watches.map(watch => {
          const row = document.createElement('div'); row.className = 'debug-row';
          const main = document.createElement('div'); main.className = 'debug-row-main';
          const expression = document.createElement('div'); expression.textContent = watch.expression;
          const value = document.createElement('div'); value.className = watch.error ? 'debug-state-error' : 'debug-row-value';
          value.textContent = watch.error || debuggerValueText(watch.result);
          main.append(expression, value);
          const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'debug-row-action'; remove.textContent = '×'; remove.setAttribute('aria-label', `Remove watch ${watch.expression}`);
          remove.disabled = originTraceActive;
          remove.addEventListener('click', () => debuggerAction({ action: 'remove_watch', watch_id: watch.id }));
          row.append(main, remove); return row;
        });
        if (nodes.length === 0) nodes.push(textElement('div', 'debug-pane-empty', 'No watch expressions'));
        elements.watchList.replaceChildren(...nodes);
      }

      function renderBreakpoints() {
        const originTraceActive = memoryOriginTraceActive();
        const breakpoints = state.debuggerSession?.breakpoints ?? [];
        const nodes = breakpoints.map(breakpoint => {
          const row = document.createElement('div'); row.className = 'debug-row';
          const reveal = document.createElement('button'); reveal.type = 'button'; reveal.className = 'call-frame';
          const name = document.createElement('span'); name.className = 'call-frame-name';
          name.textContent = breakpoint.kind === 'logpoint'
            ? `Logpoint: ${breakpoint.expression}`
            : breakpoint.kind === 'conditional' ? `Conditional: ${breakpoint.expression}` : 'Line breakpoint';
          const location = document.createElement('span'); location.className = 'call-frame-location';
          const resolved = breakpoint.locations?.[0] ?? { script_id: '', line: breakpoint.line, column: breakpoint.column };
          const script = liveSources().find(candidate => candidate.url === breakpoint.url || candidate.script_id === resolved.script_id || candidate.script_id === breakpoint.script_id);
          location.textContent = `${script ? sourceName(script) : sourceName({ url: breakpoint.url, source_type: 'script', script_id: breakpoint.script_id })}:${resolved.line + 1}${breakpoint.locations_truncated ? ' · more locations' : ''}`;
          reveal.append(name, location);
          reveal.addEventListener('click', () => {
            const script = liveSources().find(candidate => candidate.url === breakpoint.url || candidate.script_id === resolved.script_id);
            if (script) selectScript(script.script_id, resolved.line);
          });
          const actions = document.createElement('div'); actions.className = 'debug-row-actions';
          const edit = document.createElement('button'); edit.type = 'button'; edit.className = 'debug-row-action'; edit.textContent = '✎'; edit.setAttribute('aria-label', `Edit breakpoint on line ${breakpoint.line + 1}`);
          edit.disabled = originTraceActive;
          edit.addEventListener('click', () => { state.editingBreakpointId = state.editingBreakpointId === breakpoint.id ? null : breakpoint.id; renderBreakpoints(); });
          const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'debug-row-action'; remove.textContent = '×'; remove.setAttribute('aria-label', `Remove breakpoint on line ${breakpoint.line + 1}`);
          remove.disabled = originTraceActive;
          remove.addEventListener('click', () => debuggerAction({ action: 'remove_breakpoint', breakpoint_id: breakpoint.id }));
          actions.append(edit, remove);
          row.append(reveal, actions);
          if (state.editingBreakpointId === breakpoint.id) {
            const editor = document.createElement('form'); editor.className = 'debug-row-editor';
            const kind = document.createElement('select'); kind.setAttribute('aria-label', 'Breakpoint type');
            [['line', 'Line'], ['conditional', 'Conditional'], ['logpoint', 'Logpoint']].forEach(([value, label]) => {
              const option = document.createElement('option'); option.value = value; option.textContent = label; option.selected = value === breakpoint.kind; kind.append(option);
            });
            const expression = document.createElement('input'); expression.type = 'text'; expression.value = breakpoint.expression ?? ''; expression.placeholder = 'Expression'; expression.setAttribute('aria-label', 'Breakpoint expression');
            const save = document.createElement('button'); save.type = 'submit'; save.className = 'debug-row-action'; save.textContent = 'Save';
            kind.disabled = originTraceActive;
            expression.disabled = originTraceActive;
            save.disabled = originTraceActive;
            const updateVisibility = () => { expression.hidden = kind.value === 'line'; };
            kind.addEventListener('change', updateVisibility); updateVisibility();
            editor.addEventListener('submit', event => {
              event.preventDefault();
              if (kind.value !== 'line' && !expression.value.trim()) return;
              state.editingBreakpointId = null;
              debuggerAction({ action: 'update_breakpoint', breakpoint_id: breakpoint.id, kind: kind.value, expression: expression.value.trim() });
            });
            editor.append(kind, expression, save); row.append(editor);
          }
          return row;
        });
        if (nodes.length === 0) nodes.push(textElement('div', 'debug-pane-empty', 'No breakpoints'));
        elements.breakpointList.replaceChildren(...nodes);
      }

      function renderSpecialBreakpoints() {
        const settings = state.debuggerSession?.settings;
        const originTraceActive = memoryOriginTraceActive();
        const attached = ['running', 'paused'].includes(state.debuggerSession?.state);
        elements.pauseOnExceptions.value = settings?.pause_on_exceptions ?? 'none';
        const xhrRows = (settings?.xhr_breakpoints ?? []).map(pattern => {
          const row = document.createElement('div'); row.className = 'debug-row';
          const value = document.createElement('span'); value.className = 'debug-row-value'; value.textContent = pattern || 'Any XHR or fetch';
          const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'debug-row-action'; remove.textContent = '×';
          remove.disabled = originTraceActive;
          remove.addEventListener('click', () => debuggerAction({ action: 'remove_xhr_breakpoint', pattern }));
          row.append(value, remove); return row;
        });
        if (xhrRows.length === 0) xhrRows.push(textElement('div', 'debug-pane-empty', 'No XHR/fetch breakpoints'));
        elements.xhrBreakpointList.replaceChildren(...xhrRows);
        const events = [
          ['listener:click', 'Mouse · click'], ['listener:keydown', 'Keyboard · keydown'],
          ['listener:submit', 'Control · submit'], ['listener:DOMContentLoaded', 'Load · DOMContentLoaded'],
          ['instrumentation:setTimeout.callback', 'Timer · setTimeout']
        ];
        const eventRows = events.map(([eventName, label]) => {
          const row = document.createElement('label'); row.className = 'debug-checkbox';
          const input = document.createElement('input'); input.type = 'checkbox'; input.name = 'event_breakpoint';
          input.id = `event-breakpoint-${eventName.replace(/[^a-zA-Z0-9_-]/g, '-')}`;
          input.checked = settings?.event_breakpoints.includes(eventName) ?? false;
          input.disabled = !attached || originTraceActive;
          input.addEventListener('change', () => debuggerAction({ action: input.checked ? 'set_event_breakpoint' : 'remove_event_breakpoint', event_name: eventName }));
          const text = document.createElement('span'); text.textContent = label; row.append(input, text); return row;
        });
        elements.eventBreakpointList.replaceChildren(...eventRows);
      }

      function consoleEntryNode(entry) {
        const row = document.createElement('div'); row.className = `console-entry ${entry.type}`; row.dataset.consoleId = entry.id;
        const type = document.createElement('span'); type.textContent = entry.type;
        const message = document.createElement('span'); message.textContent = (entry.arguments ?? []).map(debuggerValueText).join(' ') || '(no value)';
        const source = document.createElement('span'); source.className = 'console-entry-source';
        const frame = entry.stack?.[0]; source.textContent = frame ? `${sourceName({ url: frame.url, source_type: 'script', script_id: '' })}:${frame.line + 1}` : '';
        row.append(type, message, source);
        return row;
      }

      function renderConsole() {
        const entries = state.debuggerSession?.console ?? [];
        elements.consoleCount.textContent = `${entries.length} ${entries.length === 1 ? 'message' : 'messages'}`;
        const signature = entries.length === 0 ? 'empty' : `${entries.length}:${entries[0].id}:${entries.at(-1).id}`;
        if (state.renderedConsoleSignature === signature) return;
        state.renderedConsoleSignature = signature;
        if (entries.length === 0) {
          elements.consoleEntries.replaceChildren(textElement('div', 'debug-pane-empty', 'No console messages from the attached target.'));
          return;
        }
        const existing = new Map(
          [...elements.consoleEntries.querySelectorAll('.console-entry[data-console-id]')]
            .map(row => [row.dataset.consoleId, row])
        );
        elements.consoleEntries.replaceChildren(...entries.map(entry => existing.get(entry.id) ?? consoleEntryNode(entry)));
      }

      function renderDebuggerPart(name, signature, render) {
        if (state.debuggerRenderKeys[name] === signature) return;
        state.debuggerRenderKeys[name] = signature;
        render();
      }

      function renderDebugger() {
        const session = state.debuggerSession;
        const paused = session?.state === 'paused';
        const running = session?.state === 'running';
        const attached = paused || running;
        elements.sourceHookPivot.disabled = !attached;
        const originTraceActive = memoryOriginTraceActive();
        elements.debugResume.disabled = !paused || state.debuggerActionPending || originTraceActive;
        elements.debugPause.disabled = !running || state.debuggerActionPending || originTraceActive;
        [elements.debugStepOver, elements.debugStepInto, elements.debugStepOut].forEach(button => { button.disabled = !paused || state.debuggerActionPending || originTraceActive; });
        elements.debugBreakpointsActive.disabled = !attached || state.debuggerActionPending || originTraceActive;
        elements.debugBreakpointsActive.setAttribute('aria-pressed', String(session?.settings.breakpoints_active ?? true));
        elements.debugBreakpointsActive.title = session?.settings.breakpoints_active ? 'Deactivate breakpoints' : 'Activate breakpoints';
        elements.watchExpression.disabled = !attached || originTraceActive;
        elements.watchForm.querySelector('button').disabled = !attached || originTraceActive;
        elements.pauseOnExceptions.disabled = !attached || originTraceActive;
        elements.xhrBreakpointPattern.disabled = !attached || originTraceActive;
        elements.xhrBreakpointForm.querySelector('button').disabled = !attached || originTraceActive;
        elements.consoleClear.disabled = !attached || originTraceActive;
        const pausedSignature = JSON.stringify(session?.paused ?? null);
        const selectedPauseSignature = `${state.selectedCallFrameId ?? ''}:${pausedSignature}`;
        renderDebuggerPart('state', JSON.stringify([session?.state, session?.error, session?.target, session?.targets, state.debuggerError, originTraceActive]), renderDebuggerState);
        renderDebuggerPart('callStack', `${originTraceActive}:${selectedPauseSignature}`, renderCallStack);
        renderDebuggerPart('scope', selectedPauseSignature, renderScope);
        renderDebuggerPart('watches', JSON.stringify([session?.watches ?? [], originTraceActive]), renderWatches);
        renderDebuggerPart('breakpoints', JSON.stringify([session?.breakpoints ?? [], originTraceActive]), renderBreakpoints);
        renderDebuggerPart('specialBreakpoints', JSON.stringify([session?.settings ?? null, attached, originTraceActive]), renderSpecialBreakpoints);
        renderConsole();
      }

      async function debuggerAction(request, memoryOwner = null, experimentOwner = null) {
        const parallelControl = ['cancel_repeater_request', 'cancel_automation_recipe'].includes(request.action);
        if ((state.debuggerActionPending && !parallelControl) || (memoryOriginTraceActive() && request.action !== 'stop_memory_origin_trace')) return null;
        const deadline = memoryOwner ? memoryActionDeadline(request.action) : 0;
        if (memoryOwner && (!deadline || memoryOwner.action !== request.action)) return null;
        const owner = {memoryOwner, experimentOwner, request, retire: null};
        if (experimentOwner) experimentOwner.transport = owner;
        if (!parallelControl) {
          state.debuggerActionOwner = owner;
          state.debuggerActionPending = true;
        }
        const current = () => (parallelControl || state.debuggerActionOwner === owner) && !experimentOwner?.expired;
        state.debuggerError = null;
        renderDebugger();
        let result = null, timer = null, controller = null, retired = false;
        try {
          let retirement;
          if (memoryOwner || experimentOwner) {
            controller = new AbortController();
            retirement = new Promise((_, reject) => {
              owner.retire = message => {
                if (retired) return;
                retired = true;
                // Reject the UI wait even if a fetch/body implementation ignores
                // abort. Abort only releases this HTTP read, never native work.
                reject(new Error(message));
                controller.abort();
              };
              if (memoryOwner) timer = setTimeout(() => owner.retire?.(`Memory action acknowledgement exceeded ${deadline / 1000} seconds. Native completion is unknown; no cancellation or retry was requested.`), deadline);
            });
          }
          const transport = (async () => {
            const response = await fetch('/api/debugger/actions', {
              method: 'POST', cache: 'no-store', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(request),
              ...(controller ? {signal: controller.signal} : {})
            });
            if ((memoryOwner || experimentOwner) && (retired || !current())) return null;
            const body = await response.json();
            if ((memoryOwner || experimentOwner) && (retired || !current())) return null;
            if (!response.ok) throw new Error(body.error || `Debugger returned ${response.status}`);
            return body;
          })();
          const body = await (retirement ? Promise.race([transport, retirement]) : transport);
          if (current() && !retired) result = body;
        } catch (error) {
          if (current()) state.debuggerError = error.message;
        } finally {
          if (timer !== null) clearTimeout(timer);
          owner.retire = null;
          if (current()) {
            if (!parallelControl) {
              state.debuggerActionOwner = null;
              state.debuggerActionPending = false;
            }
            renderDebugger();
            // Refresh current controls even when the Memory caller exits on an
            // expired owner. Generic callers and replaced tokens do not redraw.
            if (memoryOwner) renderMemory();
            if (!state.debuggerRefreshing) scheduleDebuggerRefresh(0);
          }
        }
        return result;
      }

      function debuggerScriptCatalogSignature(session) {
        const scripts = session?.scripts ?? [];
        if (scripts.length === 0) return `${session?.target?.id ?? ''}:empty`;
        const first = scripts[0];
        const last = scripts.at(-1);
        return `${session?.target?.id ?? ''}:${scripts.length}:${first.script_id}:${first.hash}:${last.script_id}:${last.hash}`;
      }

      function scheduleDebuggerRefresh(delay = 0) {
        if (location.protocol === 'file:') return;
        if (state.debuggerRefreshTimer !== null) clearTimeout(state.debuggerRefreshTimer);
        state.debuggerRefreshTimer = setTimeout(() => {
          state.debuggerRefreshTimer = null;
          refreshDebugger();
        }, delay);
      }

      async function refreshDebugger(force = false) {
        if (state.debuggerRefreshing || location.protocol === 'file:') return;
        state.debuggerRefreshing = true;
        const experimentReceiptAtStart = state.experimentReceipt;
        try {
          const headers = !force && state.debuggerEtag ? { 'If-None-Match': state.debuggerEtag } : {};
          const wait = !force && state.debuggerEtag && state.debuggerSession?.state !== 'unavailable' ? 25000 : 0;
          const response = await fetch(`/api/debugger?wait_ms=${wait}`, { cache: 'no-store', headers });
          if (response.status === 304) return;
          if (!response.ok) throw new Error(`Debugger returned ${response.status}`);
          let body = await response.json();
          if (!isDebuggerResponse(body)) throw new TypeError('Malformed debugger response');
          const previousSession = state.debuggerSession;
          const previousSelectedScript = previousSession?.scripts.find(script => script.script_id === state.selectedScriptId);
          const previousSelectedIdentity = previousSelectedScript ? liveScriptIdentity(previousSelectedScript) : null;
          const previousState = state.debuggerSession?.state;
          const previousFrame = state.debuggerSession?.paused?.call_frames?.[0]?.id;
          const previousCatalog = debuggerScriptCatalogSignature(previousSession);
          const previousBreakpoints = JSON.stringify(previousSession?.breakpoints ?? []);
          const previousOpenScripts = state.openScriptIds.join('\u0000');
          const previousPendingLine = state.pendingSourceLine ? `${state.pendingSourceLine.scriptId}:${state.pendingSourceLine.line}` : '';
          body = syncExperimentSession(previousSession, body, experimentReceiptAtStart);
          state.debuggerSession = body;
          rebuildTrafficRequests();
          syncMemorySession(previousSession, body);
          applyMemoryOriginTrace(body.memory_origin_trace);
          state.debuggerEtag = state.experimentNeedsRefresh ? null : response.headers.get('ETag');
          state.debuggerError = null;
          state.debuggerRefreshFailed = false;
          renderLiveBrowserTabCount();
          state.staleScriptIds ??= new Set();
          if ((previousSession?.target?.id ?? '') !== (body.target?.id ?? '')) {
            state.staleScriptIds.clear();
          } else {
            const currentScripts = new Map(body.scripts.map(script => [script.script_id, script]));
            const previousScripts = new Map((previousSession?.scripts ?? []).map(script => [script.script_id, script]));
            state.staleScriptIds.forEach(scriptId => {
              const current = currentScripts.get(scriptId);
              const previous = previousScripts.get(scriptId);
              if (!current || (previous && current.hash !== previous.hash)) state.staleScriptIds.delete(scriptId);
            });
          }
          pruneLiveScriptContent();
          state.openScriptIds = state.openScriptIds.filter(id =>
            body.scripts.some(script => script.script_id === id) && !state.staleScriptIds.has(id));
          if (state.editingBreakpointId !== null && !body.breakpoints.some(breakpoint => breakpoint.id === state.editingBreakpointId)) {
            state.editingBreakpointId = null;
          }
          if (state.selectedScriptId !== null &&
              (!body.scripts.some(script => script.script_id === state.selectedScriptId) ||
               state.staleScriptIds.has(state.selectedScriptId))) {
            state.sourceNoticeKind = 'warning';
            state.sourceNotice = 'The selected live source is no longer attached to the current debugger target. The current Page catalog is shown after refresh.';
            state.selectedScriptId = null;
            state.pendingSourceLine = null;
            state.selectedArtifactId = state.openArtifactIds.at(-1) ?? null;
            state.sourceCollection = 'captured';
          }
          const firstFrame = body.paused?.call_frames?.[0] ?? null;
          let sourceRendered = false;
          if (firstFrame && (previousState !== 'paused' || previousFrame !== firstFrame.id)) {
            state.selectedCallFrameId = firstFrame.id;
            sourceRendered = revealDebuggerLocation(firstFrame.location);
          } else if (!firstFrame) {
            state.selectedCallFrameId = null;
            state.pendingSourceLine = null;
          }
          renderDebugger();
          const selectedTrafficRequest = state.requests.find(request => request.id === state.selectedRequestId) ?? null;
          if (!selectedTrafficRequest && state.selectedRequestId !== null) resetRequestSelection();
          renderShellStatus();
          renderNetworkNotice();
          if (!document.querySelector('#screen-traffic').hidden) {
            renderRequests();
            updateSelectionSummary(selectedTrafficRequest);
            renderInspector();
          }
          renderMemory();
          if (!document.querySelector('#screen-experiments').hidden) renderExperiment();
          if (state.sourceHooksOpen) renderRuntimeHooks();
          if (state.selectedRuntimeHookRequest) renderRuntimeHookTraffic();
          renderFieldProvenance();
          if (!document.querySelector('#screen-api-collection').hidden) renderApiCollection();
          const sourcesVisible = !document.querySelector('#screen-sources').hidden;
          if (sourcesVisible && !sourceRendered) {
            const currentSelectedScript = body.scripts.find(script => script.script_id === state.selectedScriptId);
            const selectedIdentityChanged = previousSelectedIdentity !== null && currentSelectedScript &&
              previousSelectedIdentity !== liveScriptIdentity(currentSelectedScript);
            const catalogChanged = previousCatalog !== debuggerScriptCatalogSignature(body);
            const openScriptsChanged = previousOpenScripts !== state.openScriptIds.join('\u0000');
            const pendingLine = state.pendingSourceLine ? `${state.pendingSourceLine.scriptId}:${state.pendingSourceLine.line}` : '';
            if (selectedIdentityChanged) {
              renderSources();
              loadScriptContent(selectedSource());
            } else if (openScriptsChanged || (state.selectedScriptId === null && previousSession?.scripts?.length > 0 && body.scripts.length === 0)) {
              renderSources();
            } else {
              if (catalogChanged && state.sourceCollection === 'page') renderSourceTree();
              if (catalogChanged && state.openScriptIds.length > 0) renderSourceTabs();
              if (previousBreakpoints !== JSON.stringify(body.breakpoints) || previousPendingLine !== pendingLine || previousState !== body.state) {
                updateSourceDecorations();
              }
            }
          }
        } catch (error) {
          state.debuggerError = error instanceof TypeError ? 'The debugger returned malformed state. The last valid pause is retained.' : error.message;
          // Rejected actions and clipboard errors do not describe capture health.
          state.debuggerRefreshFailed = true;
          // A 304 cannot clear a failed refresh; recovery needs a validated body.
          state.debuggerEtag = null;
          renderShellStatus();
          renderNetworkNotice();
          renderLiveBrowserTabCount();
          renderDebugger();
          renderMemory();
          if (!document.querySelector('#screen-experiments').hidden) renderExperiment();
          if (state.sourceHooksOpen) renderRuntimeHooks();
          if (state.selectedRuntimeHookRequest) renderRuntimeHookTraffic();
          renderFieldProvenance();
          if (!document.querySelector('#screen-api-collection').hidden) renderApiCollection();
        } finally {
          state.debuggerRefreshing = false;
          const quiet = document.hidden || state.debuggerSession?.state === 'unavailable' || state.debuggerError;
          scheduleDebuggerRefresh(quiet ? 1000 : 50);
        }
      }

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
        if (screenName !== 'sources' && state.sourceHooksOpen) closeSourceHooks(false);
        document.querySelectorAll('.screen').forEach(screen => { screen.hidden = screen.id !== `screen-${screenName}`; });
        document.querySelectorAll('.nav-button').forEach(button => {
          const active = button.dataset.screen === screenName || (button.dataset.screen === 'backtrace' && screenName === 'evidence') || (button.dataset.screen === 'traffic' && ['vm', 'field-provenance'].includes(screenName));
          if (active) button.setAttribute('aria-current', 'page');
          else button.removeAttribute('aria-current');
        });
        // Advanced is a floating chooser at every width. Finish the choice
        // without leaving focus on a menu item that is about to be hidden.
        const navigation = document.querySelector('#advanced-navigation');
        if (navigation.contains(document.activeElement)) navigation.querySelector('summary').focus({ preventScroll: true });
        navigation.open = false;
        if (screenName === 'signals') renderFingerprintActivity();
        if (screenName === 'traffic') renderRuntimeHookTraffic();
        if (screenName === 'backtrace') renderBacktrace();
        if (screenName === 'experiments') renderExperiment();
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
          renderDebugger();
          renderSources();
          const source = selectedSource();
          if (source?.source_type === 'script') loadScriptContent(source);
          else if (source) loadArtifactContent(state.artifacts.find(candidate => candidate.artifact_id === source.artifact_id));
        }
        if (screenName === 'memory') renderMemory();
        if (screenName === 'vm') {
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
          state.eventsLimited = body.count >= 5000;
          const vmModel = vmFindingsFromEvents(state.events);
          state.eventVmFindings = vmModel.findings;
          state.vmFindings = [...state.lastValidAnalysisFindings, ...state.eventVmFindings];
          state.malformedVmFindings = vmModel.malformedCount;
          const eventOrigin = state.sessionMode === 'demo' ? 'demo' : 'live';
          state.nativeRequests = requestsFromEvents(state.events, eventOrigin);
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
          const gapCount = countSequenceGaps(state.events);
          const reportedDrops = countReportedQueueDrops(state.events);
          elements.gaps.textContent = `${gapCount} missing event ${gapCount === 1n ? 'ID' : 'IDs'}` +
            (reportedDrops > 0n ? ` · ${reportedDrops} reported queue ${reportedDrops === 1n ? 'drop' : 'drops'} (may overlap)` : '');
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
        state.broker = 'preview';
        state.eventFailureKind = null;
        state.sessionMode = 'preview';
        state.events = [];
        state.canvasRenderCaptures = [];
        state.eventsLimited = false;
        state.requests = [];
        state.artifacts = [];
        state.openArtifactIds = [];
        state.selectedArtifactId = null;
        state.artifactReceiverConfigured = false;
        state.artifactReceiverConnected = false;
        state.artifactReceiverError = null;
        state.staleScriptIds?.clear();
        state.sourceNotice = null;
        state.selectedRequestId = null;
        state.selectedField = null;
        state.lastUpdatedLabel = 'start a live capture';
        renderShellStatus();
        elements.gaps.textContent = '0 missing event IDs';
        setNetworkNotice('empty', 'No evidence is bundled. Start a live capture to populate the workspace.');
        renderRequests();
        renderEvidence();
        renderDebugger();
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
        state.inspectorTab = state.inspectorTab === 'evidence' ? 'headers' : 'evidence';
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
      elements.requestSearchScope.addEventListener('change', renderRequests);
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
      elements.requestRepeaterPivot.addEventListener('click', () => {
        state.experimentMode = 'repeater';
        state.repeaterDraftDirty = false;
        state.repeaterPrefillKey = null;
        prefillRepeaterRequest(true);
        showScreen('experiments', elements.requestRepeaterPivot);
        requestAnimationFrame(() => elements.repeaterRequestUrl.focus({preventScroll: true}));
      });
      elements.requestCollectionPivot.addEventListener('click', copyInvestigationRequestToCollection);
      elements.requestDecoderPivot.addEventListener('click', useSelectedFieldInDecoder);
      elements.requestMemoryPivot.addEventListener('click', () => {
        if (state.memorySearchPending || state.debuggerActionPending) {
          showScreen('memory', elements.requestMemoryPivot);
          return;
        }
        const selected = state.selectedField;
        if (!selected) return;
        let value = String(selected.value ?? '').trim();
        if (selected.type === 'str' && value.startsWith('"') && value.endsWith('"')) {
          value = value.slice(1, -1);
        }
        value = value.replace(/(?:…|\.{3})+$/u, '').slice(0, 512);
        if (!value) return;
        state.memoryResultOwner = null;
        state.memoryLastOperation = null;
        state.memoryMode = 'live';
        state.memoryResults = [];
        state.selectedMemoryResultId = null;
        state.memorySearchMeta = null;
        state.memoryTargetId = null;
        state.memorySearchStatus = memoryAttached() ? 'idle' : 'offline';
        state.memorySearchMessage = `Pivoted from request-${state.selectedRequestId} · ${selected.label} · ${selected.path}`;
        elements.memoryPropertyQuery.value = '';
        elements.memoryValueQuery.value = value;
        elements.memoryClassQuery.value = '';
        elements.memoryShapeQuery.value = '';
        elements.memoryRegex.checked = false;
        elements.memoryCaseSensitive.checked = false;
        elements.memoryShapeValues.checked = false;
        showScreen('memory', elements.requestMemoryPivot);
        requestAnimationFrame(() => elements.memoryValueQuery.focus({ preventScroll: true }));
      });
      elements.requestVmCandidates.addEventListener('click', async () => {
        const request = state.requests.find(candidate => candidate.id === state.selectedRequestId);
        const requestId = request?.event ? String(request.event.request_id) : /^\d+$/.test(request?.id ?? '') ? request.id : null;
        if (requestId) await refreshVmAnalysis(requestId);
        showScreen('vm', elements.requestVmCandidates);
      });
      elements.sourceSearch.addEventListener('input', () => applySourceSearch());
      elements.sourceSearch.addEventListener('keydown', event => {
        if (event.key !== 'Enter') return;
        event.preventDefault();
        applySourceSearch(false, event.shiftKey ? -1 : 1);
      });
      document.querySelectorAll('[data-source-collection]').forEach(button => button.addEventListener('click', () => {
        state.sourceCollection = button.dataset.sourceCollection;
        if (state.sourceCollection === 'page') {
          const script = liveSources().find(source => source.script_id === state.selectedScriptId) ?? liveSources()[0];
          if (script) selectScript(script.script_id);
          else renderSources();
        } else {
          state.selectedScriptId = null;
          state.pendingSourceLine = null;
          const artifact = state.artifacts.find(candidate => candidate.artifact_id === state.selectedArtifactId) ?? state.artifacts[0];
          if (artifact) selectArtifact(artifact.artifact_id);
          else renderSources();
        }
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
      elements.sourceCode.addEventListener('click', event => {
        const line = event.target.closest('.source-line');
        if (!line?.dataset.line) return;
        const source = selectedSource();
        const runtimeLine = Number(line.dataset.line) - 1;
        const localLine = runtimeLine - (source?.source_type === 'script' ? source.start_line : 0);
        const transformed = state.sourceDeobfuscated || state.sourceFormatted;
        const column = sourceClickColumn(line, event) + (transformed ? 0 : sourceRuntimeColumn(source, localLine));
        if (source?.source_type === 'script' && !transformed) {
          setSourceCursor(source, runtimeLine, column);
          elements.sourceCode.querySelectorAll('.source-line').forEach(row => row.classList.toggle('cursor', row === line));
          if (state.sourceHooksOpen && prefillHookFromSource(source)) renderRuntimeHooks();
        }
        elements.sourcePosition.textContent = `Line ${line.dataset.line}, Column ${column + 1}`;
      });
      elements.sourceHookPivot.addEventListener('click', pivotSourceToRuntimeHooks);
      elements.sourceHooksClose.addEventListener('click', () => closeSourceHooks());
      elements.sourceHooksExperiments.addEventListener('click', () => showScreen('experiments'));
      const setConsoleOpen = open => {
        state.consoleOpen = open;
        elements.consoleDrawer.hidden = !open;
        elements.sourcesEditor.classList.toggle('console-open', open);
        elements.consoleToggle.setAttribute('aria-pressed', String(open));
      };
      elements.sourceSidebarToggle.addEventListener('click', () => {
        state.sourceSidebarOpen = elements.sourceSidebar.hidden;
        renderSourceSidebar();
      });
      elements.consoleToggle.addEventListener('click', () => setConsoleOpen(!state.consoleOpen));
      elements.consoleClear.addEventListener('click', () => debuggerAction({ action: 'clear_console' }));
      elements.debugResume.addEventListener('click', () => debuggerAction({ action: 'resume' }));
      elements.debugPause.addEventListener('click', () => debuggerAction({ action: 'pause' }));
      elements.debugStepOver.addEventListener('click', () => debuggerAction({ action: 'step_over' }));
      elements.debugStepInto.addEventListener('click', () => debuggerAction({ action: 'step_into' }));
      elements.debugStepOut.addEventListener('click', () => debuggerAction({ action: 'step_out' }));
      elements.debugBreakpointsActive.addEventListener('click', () => debuggerAction({
        action: 'set_breakpoints_active', active: !(state.debuggerSession?.settings.breakpoints_active ?? true)
      }));
      elements.watchForm.addEventListener('submit', event => {
        event.preventDefault();
        const expression = elements.watchExpression.value.trim();
        if (!expression) return;
        elements.watchExpression.value = '';
        debuggerAction({ action: 'add_watch', expression });
      });
      elements.pauseOnExceptions.addEventListener('change', () => debuggerAction({
        action: 'set_pause_on_exceptions', mode: elements.pauseOnExceptions.value
      }));
      elements.xhrBreakpointForm.addEventListener('submit', event => {
        event.preventDefault();
        const pattern = elements.xhrBreakpointPattern.value.trim();
        elements.xhrBreakpointPattern.value = '';
        debuggerAction({ action: 'set_xhr_breakpoint', pattern });
      });
      elements.actionScopeGlobal.addEventListener('click', () => {
        state.actionScopeDraftMode = 'global';
        renderExperiment();
      });
      elements.actionScopeTargeted.addEventListener('click', () => {
        state.actionScopeDraftMode = 'target';
        renderExperiment();
      });
      elements.actionScopeTarget.addEventListener('change', renderExperiment);
      elements.actionScopeApply.addEventListener('click', () => {
        const mode = state.actionScopeDraftMode ?? actionScopeState()?.mode ?? 'global';
        const request = {action: 'set_action_scope', mode};
        if (mode === 'target') request.target_id = elements.actionScopeTarget.value;
        runExperimentAction(request);
      });
      elements.actionScopeAddForm.addEventListener('submit', async event => {
        event.preventDefault();
        const value = elements.actionScopeNewUrl.value.trim();
        let url = 'about:blank';
        if (value) {
          try {
            const parsed = new URL(value);
            if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.hash) throw new Error();
            url = value;
          } catch {
            state.experimentError = 'Disposable page URL must be credential-free HTTP or HTTPS with no fragment.';
            renderExperiment();
            return;
          }
        }
        const response = currentExperimentReceipt(await runExperimentAction({action: 'create_experiment_page', url}));
        if (response) elements.actionScopeNewUrl.value = '';
      });
      elements.experimentCreate.addEventListener('click', () => runExperimentAction({
        action: 'create_request_interception_experiment'
      }));
      elements.experimentDispose.addEventListener('click', () => runExperimentAction({
        action: 'dispose_request_interception_experiment'
      }));
      elements.experimentClear.addEventListener('click', async () => {
        const response = currentExperimentReceipt(await runExperimentAction({ action: 'clear_request_interception_result' }));
        if (response) {
          state.experimentPrefillKey = null;
          prefillExperimentRequest();
        }
      });
      elements.experimentRuleMode.addEventListener('change', () => {
        state.experimentError = null;
        setExperimentRuleVisibility();
      });
      elements.experimentRuleForm.addEventListener('submit', event => {
        event.preventDefault();
        configureExperimentRule();
      });
      elements.experimentRequestForm.addEventListener('submit', event => {
        event.preventDefault();
        runExperimentRequest();
      });
      elements.experimentModeButtons.forEach(button => button.addEventListener('click', () => {
        setExperimentMode(button.dataset.experimentMode);
      }));
      enableTabKeyboardNavigation('.experiment-mode-tab');
      elements.repeaterEditorTabs.forEach(button => button.addEventListener('click', () => {
        setRepeaterEditorTab(button.dataset.repeaterEditorTab);
      }));
      enableTabKeyboardNavigation('.repeater-editor-tab');
      elements.objectCreate.addEventListener('click', () => runExperimentAction({
        action: 'create_request_interception_experiment'
      }));
      elements.objectDispose.addEventListener('click', async () => {
        const response = currentExperimentReceipt(await runExperimentAction({action: 'dispose_request_interception_experiment'}));
        if (response) {
          state.objectSelectedResultId = null;
          state.objectSelectionSearchId = 0;
          elements.objectConfirm.checked = false;
          elements.objectMutationValue.value = '';
          elements.objectMutationProperty.value = '';
        }
      });
      elements.objectNavigationForm.addEventListener('submit', event => {
        event.preventDefault();
        navigateObjectExperiment();
      });
      elements.objectSearchForm.addEventListener('submit', event => {
        event.preventDefault();
        searchObjectExperiment();
      });
      elements.objectMutationForm.addEventListener('submit', event => {
        event.preventDefault();
        mutateObjectExperiment();
      });
      elements.objectOperation.addEventListener('change', () => {
        elements.objectConfirm.checked = false;
        renderObjectExperiment();
      });
      elements.objectConfirm.addEventListener('change', renderObjectExperiment);
      elements.objectMutationProperty.addEventListener('input', () => {
        state.experimentError = null;
        renderObjectExperiment();
      });
      elements.objectMutationValue.addEventListener('input', () => { state.experimentError = null; });
      elements.objectResults.addEventListener('keydown', event => {
        if (!['ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) return;
        const results = objectExperimentState()?.results ?? [];
        if (results.length === 0) return;
        event.preventDefault();
        const current = Math.max(0, results.findIndex(result => result.id === state.objectSelectedResultId));
        const index = event.key === 'Home' ? 0 : event.key === 'End' ? results.length - 1
          : event.key === 'ArrowUp' ? Math.max(0, current - 1) : Math.min(results.length - 1, current + 1);
        selectObjectExperimentResult(results[index].id, true);
      });
      elements.hooksCreate.addEventListener('click', () => runExperimentAction({
        action: 'create_request_interception_experiment'
      }));
      elements.hooksDispose.addEventListener('click', async () => {
        const response = currentExperimentReceipt(await runExperimentAction({action: 'dispose_request_interception_experiment'}));
        if (response) {
          elements.hooksConfirm.checked = false;
          elements.hooksDefinitionForm.reset();
          elements.hooksEntryEnabled.checked = true;
          elements.hooksReturnEnabled.checked = true;
          elements.hooksReturnMode.value = 'none';
          renderRuntimeHooks();
        }
      });
      elements.hooksClear.addEventListener('click', () => runExperimentAction({action: 'clear_runtime_hook_hits'}));
      elements.hooksNavigationForm.addEventListener('submit', event => {
        event.preventDefault();
        navigateRuntimeHooks();
      });
      elements.hooksDefinitionForm.addEventListener('submit', event => {
        event.preventDefault();
        addRuntimeHook();
      });
      elements.hooksScript.addEventListener('change', () => {
        const script = (state.debuggerSession?.scripts ?? []).find(candidate => candidate.script_id === elements.hooksScript.value);
        if (script) {
          elements.hooksLine.value = String(script.start_line + 1);
          elements.hooksColumn.value = String(script.start_column + 1);
        }
      });
      elements.hooksReturnMode.addEventListener('change', () => {
        state.experimentError = null;
        renderRuntimeHooks();
      });
      elements.hooksEntryMode.addEventListener('change', () => {
        if (elements.hooksEntryMode.value === 'function') {
          elements.hooksEntryEnabled.checked = true;
          elements.hooksReturnEnabled.checked = false;
          elements.hooksReturnMode.value = 'none';
          elements.hooksReturnLogic.value = '';
          elements.hooksReturnValue.value = '';
        }
        state.experimentError = null;
        renderRuntimeHooks();
      });
      elements.hooksDefinitionForm.addEventListener('input', () => {
        state.experimentError = null;
        renderRuntimeHooks();
      });
      elements.hooksConfirm.addEventListener('change', renderRuntimeHooks);
      elements.hooksArm.addEventListener('click', async () => {
        const response = currentExperimentReceipt(await runExperimentAction({action: 'arm_runtime_hooks', confirmed: elements.hooksConfirm.checked}));
        if (response) elements.hooksConfirm.checked = false;
      });
      elements.hooksDisarm.addEventListener('click', async () => {
        const response = currentExperimentReceipt(await runExperimentAction({action: 'disarm_runtime_hooks'}));
        if (response) elements.hooksConfirm.checked = false;
      });
      bindRuntimeFieldTest();
      elements.automationCreate.addEventListener('click', () => runExperimentAction({
        action: 'create_request_interception_experiment'
      }));
      elements.automationDispose.addEventListener('click', async () => {
        const response = currentExperimentReceipt(await runExperimentAction({action: 'dispose_request_interception_experiment'}));
        if (response) {
          state.automationSelectedRunId = null;
          elements.automationConfirm.checked = false;
          elements.automationVariables.value = '';
          resetAutomationEditor();
        }
      });
      elements.automationClear.addEventListener('click', async () => {
        const response = currentExperimentReceipt(await runExperimentAction({action: 'clear_automation_runs'}));
        if (response) state.automationSelectedRunId = null;
      });
      elements.automationNavigationForm.addEventListener('submit', event => {
        event.preventDefault();
        navigateAutomationRecipes();
      });
      elements.automationRecipeForm.addEventListener('submit', event => {
        event.preventDefault();
        saveAutomationRecipe();
      });
      elements.automationRecipeForm.addEventListener('input', () => {
        state.experimentError = null;
        renderAutomationRecipes();
      });
      elements.automationCancelEdit.addEventListener('click', () => {
        resetAutomationEditor();
        renderAutomationRecipes();
      });
      elements.automationConfirm.addEventListener('change', renderAutomationRecipes);
      elements.automationArm.addEventListener('click', async () => {
        try {
          const response = currentExperimentReceipt(await runExperimentAction({
            action: 'arm_automation_recipes', confirmed: elements.automationConfirm.checked,
            variables: parseAutomationVariables()
          }));
          if (response) elements.automationConfirm.checked = false;
        } catch (error) {
          state.experimentError = error.message;
          renderExperiment();
        }
      });
      elements.automationDisarm.addEventListener('click', async () => {
        const response = currentExperimentReceipt(await runExperimentAction({action: 'disarm_automation_recipes'}));
        if (response) elements.automationConfirm.checked = false;
      });
      elements.automationCancel.addEventListener('click', () => runExperimentAction({
        action: 'cancel_automation_recipe'
      }));
      elements.automationRuns.addEventListener('keydown', event => {
        if (!['ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) return;
        const runs = automationRecipesState()?.runs ?? [];
        if (!runs.length) return;
        event.preventDefault();
        const current = Math.max(0, runs.findIndex(run => run.id === state.automationSelectedRunId));
        const index = event.key === 'Home' ? 0 : event.key === 'End' ? runs.length - 1
          : event.key === 'ArrowUp' ? Math.max(0, current - 1) : Math.min(runs.length - 1, current + 1);
        selectAutomationRun(runs[index].id, true);
      });
      elements.repeaterCreate.addEventListener('click', () => runExperimentAction({
        action: 'create_request_interception_experiment'
      }));
      elements.repeaterDispose.addEventListener('click', async () => {
        const response = currentExperimentReceipt(await runExperimentAction({action: 'dispose_request_interception_experiment'}));
        if (response) {
          state.repeaterSelectedHistoryId = null;
          state.repeaterExpectedHistoryId = null;
          state.repeaterVariablesKey = null;
          state.repeaterVariablesDirty = false;
          state.repeaterComparisonKey = null;
        }
      });
      elements.repeaterClearHistory.addEventListener('click', async () => {
        const response = currentExperimentReceipt(await runExperimentAction({action: 'clear_repeater_history'}));
        if (response) {
          state.repeaterSelectedHistoryId = null;
          state.repeaterExpectedHistoryId = null;
          state.repeaterComparisonKey = null;
        }
      });
      elements.repeaterVariableForm.addEventListener('submit', event => {
        event.preventDefault();
        applyRepeaterVariables();
      });
      elements.repeaterVariables.addEventListener('input', () => {
        state.repeaterDraftRevision = (state.repeaterDraftRevision ?? 0) + 1;
        state.repeaterVariablesDirty = true;
        state.experimentError = null;
        renderRepeaterVariableStatus();
      });
      [elements.repeaterRequestUrl, elements.repeaterRequestMethod, elements.repeaterRequestTimeout,
        elements.repeaterRequestHeaders, elements.repeaterRequestBody].forEach(field => field.addEventListener('input', () => {
        if (field === elements.repeaterRequestUrl) state.repeaterQuerySource = null;
        markRepeaterDraftChanged();
      }));
      elements.repeaterRequestUrl.addEventListener('change', () => {
        if (state.repeaterEditorTab === 'query') refreshRepeaterStructuredEditors();
      });
      elements.repeaterRequestForm.addEventListener('submit', event => {
        event.preventDefault();
        runRepeaterRequest();
      });
      elements.repeaterCancel.addEventListener('click', () => runExperimentAction({action: 'cancel_repeater_request'}));
      elements.repeaterCopyResolved.addEventListener('click', copyResolvedRepeaterRequest);
      elements.repeaterCompareBaseline.addEventListener('change', () => {
        state.repeaterCompareBaselineId = Number(elements.repeaterCompareBaseline.value);
        renderRepeaterComparison(repeaterState());
      });
      elements.repeaterCompareCurrent.addEventListener('change', () => {
        state.repeaterCompareCurrentId = Number(elements.repeaterCompareCurrent.value);
        renderRepeaterComparison(repeaterState());
      });
      elements.repeaterCompare.addEventListener('click', compareRepeaterResponses);
      elements.repeaterHistoryPrev.addEventListener('click', () => {
        const history = repeaterState()?.history ?? [];
        const index = history.findIndex(entry => entry.id === state.repeaterSelectedHistoryId);
        if (index > 0) loadRepeaterHistoryEntry(history[index - 1]);
      });
      elements.repeaterHistoryNext.addEventListener('click', () => {
        const history = repeaterState()?.history ?? [];
        const index = history.findIndex(entry => entry.id === state.repeaterSelectedHistoryId);
        if (index >= 0 && index < history.length - 1) loadRepeaterHistoryEntry(history[index + 1]);
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
        elements.collectionFolderDraftStatus.textContent = '· Unsaved';
        elements.collectionDiscardFolder.disabled = false;
        renderCollectionExecution();
      }));
      elements.collectionDeleteFolder.addEventListener('click', deleteCollectionFolder);
      elements.collectionRequestForm.addEventListener('submit', event => {
        event.preventDefault(); saveCollectionRequest();
      });
      elements.collectionRequestForm.querySelectorAll('input, textarea, select').forEach(field => field.addEventListener('input', () => {
        state.collectionDraftRevision = (state.collectionDraftRevision ?? 0) + 1;
        state.collectionDraftDirty = true;
        state.collectionDeleteRequestId = null;
        elements.collectionDraftStatus.textContent = 'Unsaved edits · Save or discard before switching.';
        elements.collectionDiscardRequest.disabled = false;
        renderCollectionVariableStatus();
        renderCollectionExecution();
      }));
      elements.collectionDuplicateRequest.addEventListener('click', duplicateCollectionRequest);
      elements.collectionDeleteRequest.addEventListener('click', deleteCollectionRequest);
      elements.collectionCreateContext.addEventListener('click', async () => {
        if (state.experimentPending || elements.collectionCreateContext.disabled) return;
        elements.collectionCreateContext.disabled = true;
        const result = currentExperimentReceipt(await runExperimentAction({action: 'create_request_interception_experiment'}));
        if (!result) setCollectionNotice('error', state.experimentError || 'Isolated context could not be created.');
        renderApiCollection();
      });
      elements.collectionRun.addEventListener('click', runCollectionRequest);
      elements.collectionCancel.addEventListener('click', async () => {
        if (elements.collectionCancel.disabled) return;
        elements.collectionCancel.disabled = true;
        const result = currentExperimentReceipt(await runExperimentAction({action: 'cancel_repeater_request'}));
        if (!result) setCollectionNotice('error', state.experimentError || 'Cancellation could not be confirmed.');
        renderApiCollection();
      });
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
      toolsElements.findSources.addEventListener('click', searchDecodedFieldSources);
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
      elements.memorySearchForm.addEventListener('submit', event => {
        event.preventDefault();
        runLiveObjectSearch();
      });
      elements.memoryValueQuery.addEventListener('keydown', event => {
        if (event.key !== 'Enter' || !['snapshot', 'origin'].includes(state.memoryMode)) return;
        event.preventDefault();
        if (state.memoryMode === 'origin') runMemoryOriginTrace();
        else runHeapSnapshotSearch();
      });
      elements.memoryModeButtons.forEach(button => button.addEventListener('click', () => {
        setMemoryMode(button.dataset.memoryMode);
      }));
      elements.memoryReferenceScope.addEventListener('change', () => {
        if (!['snapshot', 'origin'].includes(state.memoryMode) || state.memorySearchPending) return;
        state.memorySearchMessage = 'Reference scope changed. It applies only to the next explicit action; the submitted result keeps its original scope.';
        renderMemory();
      });
      elements.memoryOriginStop.addEventListener('click', stopMemoryOriginTrace);
      elements.memoryOriginReset.addEventListener('click', clearMemoryOriginTrace);
      elements.memoryCaptureBaseline.addEventListener('click', captureHeapDiffBaseline);
      elements.memoryClearBaseline.addEventListener('click', clearHeapDiffBaseline);
      elements.memoryCompareSnapshot.addEventListener('click', runHeapSnapshotDiff);
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
      document.addEventListener('keydown', event => {
        if (event.defaultPrevented || event.target.closest?.('#native-console-panel')) return;
        const sourcesVisible = !document.querySelector('#screen-sources').hidden;
        if (sourcesVisible && event.key === 'Escape' && elements.quickOpen.hidden) {
          event.preventDefault();
          setConsoleOpen(!state.consoleOpen);
          return;
        }
        if (sourcesVisible && ['F8', 'F10', 'F11'].includes(event.key)) {
          const debugState = state.debuggerSession?.state;
          if (['armed', 'capturing', 'stepping', 'stopping'].includes(state.debuggerSession?.memory_origin_trace?.state)) return;
          if (!['running', 'paused'].includes(debugState)) return;
          if (event.key !== 'F8' && debugState !== 'paused') return;
          event.preventDefault();
          if (event.key === 'F8') debuggerAction({ action: debugState === 'paused' ? 'resume' : 'pause' });
          if (event.key === 'F10') debuggerAction({ action: 'step_over' });
          if (event.key === 'F11') debuggerAction({ action: event.shiftKey ? 'step_out' : 'step_into' });
          return;
        }
        const commandKey = navigator.platform.includes('Mac') ? event.metaKey : event.ctrlKey;
        if (!commandKey || event.altKey) return;
        if (event.key.toLowerCase() === 'p') {
          event.preventDefault();
          showScreen('sources');
          openQuickOpen();
        }
        if (event.key.toLowerCase() === 'f' && !document.querySelector('#screen-sources').hidden) {
          event.preventDefault();
          elements.sourceSearch.focus();
          elements.sourceSearch.select();
        }
      });
      document.querySelector('#theme-toggle').addEventListener('click', () => {
        const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
        document.documentElement.dataset.theme = next;
        try { localStorage.setItem('reb-theme', next); } catch { /* Native private mode may not persist preferences. */ }
      });
      let savedTheme = null;
      try { savedTheme = localStorage.getItem('reb-theme'); } catch { /* Keep the system theme. */ }
      if (savedTheme === 'light' || savedTheme === 'dark') document.documentElement.dataset.theme = savedTheme;

      document.addEventListener('visibilitychange', () => {
        if (document.hidden || location.protocol === 'file:') return;
        state.debuggerRenderKeys = {};
        state.renderedConsoleSignature = null;
        renderDebugger();
        if (!document.querySelector('#screen-experiments').hidden) renderExperiment();
        if (!document.querySelector('#screen-api-collection').hidden) {
          renderApiCollection();
          refreshApiCollection();
        }
        if (!document.querySelector('#screen-analyst').hidden) {
          renderLocalAnalyst();
          refreshLocalAnalyst();
        }
        if (!document.querySelector('#screen-tools').hidden) {
          renderTools();
          refreshDecoderEngine(true);
        }
        if (!document.querySelector('#screen-sources').hidden) renderSources();
        scheduleDebuggerRefresh(0);
      });

      renderRequests();
      renderInspector();
      renderEvidence();
      renderDebugger();
      renderMemory();
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
        scheduleDebuggerRefresh();
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
