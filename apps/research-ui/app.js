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
        elements.networkNotice.dataset.kind = kind;
        elements.networkNotice.textContent = message;
        elements.networkNotice.hidden = false;
      }

      function textElement(tag, className, value) {
        const element = document.createElement(tag);
        if (className) element.className = className;
        element.textContent = String(value);
        return element;
      }

      function setVmNotice(kind, message) {
        elements.vmNotice.dataset.kind = kind;
        elements.vmNotice.textContent = message;
        elements.vmNotice.hidden = false;
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

      function renderRequests() {
        const needle = elements.requestFilter.value.trim().toLowerCase();
        const visible = state.requests.filter(request =>
          (state.requestType === 'all' || request.type === state.requestType) &&
          (!needle || `${request.method} ${request.path} ${request.status}`.toLowerCase().includes(needle))
        );
        if (visible.length === 0) {
          const empty = document.createElement('div');
          empty.className = 'request-empty';
          empty.setAttribute('role', 'status');
          empty.textContent = 'No requests match the current filters.';
          elements.requestRows.removeAttribute('role');
          elements.requestRows.replaceChildren(empty);
          elements.requestCount.textContent = String(state.requests.length);
          return;
        }
        elements.requestRows.setAttribute('role', 'listbox');
        const selectedIsVisible = visible.some(request => request.id === state.selectedRequestId);
        elements.requestRows.replaceChildren(...visible.map((request, index) => {
          const row = document.createElement('button');
          row.type = 'button';
          row.className = 'request-row';
          row.setAttribute('role', 'option');
          row.dataset.requestId = request.id;
          row.setAttribute('aria-selected', String(request.id === state.selectedRequestId));
          row.setAttribute('aria-label', `${request.method} ${request.path}, ${request.status}, ${request.time}, ${request.origin}, ${request.id}`);
          row.tabIndex = request.id === state.selectedRequestId || !selectedIsVisible && index === 0 ? 0 : -1;

          const name = document.createElement('span'); name.className = 'request-name'; name.textContent = request.path;
          name.title = `${request.method} ${request.path} · network · ${request.operation ?? 'sample'} · ${request.id}`;
          const source = document.createElement('span'); source.className = request.origin === 'live' ? 'live-chip' : 'sample-chip'; source.textContent = request.origin;
          name.append(source);
          const method = document.createElement('span'); method.className = 'request-method'; method.textContent = request.method;
          const status = document.createElement('span');
          const numericStatus = Number(request.status);
          status.className = request.failed || (Number.isFinite(numericStatus) && numericStatus >= 400)
            ? 'status-error'
            : Number.isFinite(numericStatus) && numericStatus >= 200
              ? 'status-ok'
              : 'status-neutral';
          status.textContent = request.status;
          const time = document.createElement('span'); time.textContent = typeof request.time === 'number' ? `${request.time} ms` : request.time;
          const waterfallCell = document.createElement('span');
          const waterfall = document.createElement('i'); waterfall.className = 'waterfall'; waterfall.setAttribute('aria-hidden', 'true'); waterfall.style.setProperty('--water-start', `${request.start}%`); waterfall.style.setProperty('--water-mid', `${request.mid}%`); waterfall.style.setProperty('--water-end', `${request.end}%`); waterfallCell.append(waterfall);
          row.append(name, method, status, time, waterfallCell);
          row.addEventListener('click', () => {
            selectRequest(request.id);
            focusRequestRow(request.id);
          });
          row.addEventListener('keydown', moveRequestSelection);
          return row;
        }));
        elements.requestCount.textContent = String(state.requests.length);
      }

      function updateSelectionSummary(request) {
        elements.selectedMethod.textContent = request.method;
        elements.selectedStatus.textContent = request.status;
        const numericStatus = Number(request.status);
        const failed = Boolean(request.failed) || Number.isFinite(numericStatus) && numericStatus >= 400;
        elements.selectedStatus.classList.toggle('status-error', failed);
        elements.selectedStatus.classList.toggle('status-neutral', !failed && !Number.isFinite(numericStatus));
        elements.selectedUrl.textContent = request.origin === 'sample'
          ? `https://checkout.acme.test${request.path}`
          : request.path;
      }

      function selectRequest(id) {
        const request = state.requests.find(candidate => candidate.id === id);
        if (!request) return;
        state.selectedRequestId = id;
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
        const request = state.requests.find(candidate => candidate.id === state.selectedRequestId);
        const root = requestTraceRoot(request);
        if (!request || !root) return null;
        return {
          request,
          root,
          requestID: integerText(root, 'request_id'),
          sessionID: integerText(root, 'session_id'),
          key: `${request.id}:${integerText(root, 'session_id')}:${root.process_id}:${integerText(root, 'sequence_number')}`
        };
      }

      async function refreshRequestSignalProfile() {
        const generation = ++state.signalProfileGeneration;
        const selection = requestSignalProfileSelection();
        if (!selection || location.protocol === 'file:') {
          state.signalProfile = null;
          state.signalProfileStatus = 'empty';
          state.signalProfileError = null;
          if (state.inspectorTab === 'signals') renderInspector();
          return;
        }
        state.signalProfileStatus = 'loading';
        state.signalProfileError = null;
        if (state.inspectorTab === 'signals') renderInspector();
        try {
          const headers = state.signalProfileKey === selection.key && state.signalProfileEtag
            ? { 'If-None-Match': state.signalProfileEtag }
            : {};
          const parameters = new URLSearchParams({
            session_id: selection.sessionID,
            request_id: selection.requestID,
            root_process_id: String(selection.root.process_id),
            root_sequence_number: integerText(selection.root, 'sequence_number')
          });
          const response = await fetch(`/api/request-signal-profile?${parameters}`, { cache: 'no-store', headers });
          if (generation !== state.signalProfileGeneration) return;
          if (response.status === 304) {
            state.signalProfileStatus = state.signalProfile ? 'ready' : 'empty';
          } else if (response.status === 404) {
            state.signalProfile = null;
            state.signalProfileStatus = 'empty';
            state.signalProfileKey = selection.key;
            state.signalProfileEtag = response.headers.get('ETag');
          } else {
            if (!response.ok) throw new Error(`Request signal profile store returned ${response.status}`);
            const body = await response.json();
            if (!isRequestSignalProfile(body)) throw new TypeError('Malformed request signal profile');
            state.signalProfile = body;
            state.signalProfileStatus = 'ready';
            state.signalProfileKey = selection.key;
            state.signalProfileEtag = response.headers.get('ETag');
          }
        } catch (error) {
          if (generation !== state.signalProfileGeneration) return;
          state.signalProfileStatus = 'error';
          state.signalProfileError = error.message;
        }
        if (state.inspectorTab === 'signals') renderInspector();
      }

      function traceIsAvailable() {
        const request = state.requests.find(candidate => candidate.id === state.selectedRequestId);
        return Boolean(requestTraceRoot(request) || state.selectedField);
      }

      function renderFields() {
        document.querySelectorAll('.field-tab').forEach(tab => {
          const selected = tab.dataset.fieldTab === state.fieldTab;
          tab.setAttribute('aria-selected', String(selected));
          tab.tabIndex = selected ? 0 : -1;
        });
        const request = state.requests.find(candidate => candidate.id === state.selectedRequestId);
        if (state.inspectorTab === 'payload' && request?.traceable) {
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
            : 'Select a live request to build a broker-backed origin trace.';
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
        document.querySelectorAll('.inspector-tab').forEach(tab => {
          const selected = tab.dataset.inspectorTab === state.inspectorTab;
          tab.setAttribute('aria-selected', String(selected));
          tab.tabIndex = selected ? 0 : -1;
        });
        elements.requestInspector.setAttribute('aria-labelledby', `inspector-tab-${state.inspectorTab}`);
        if (state.inspectorTab !== 'payload') {
          elements.fieldTree.removeAttribute('role');
          elements.fieldTree.removeAttribute('aria-labelledby');
          elements.fieldTree.tabIndex = -1;
        }
        const request = state.requests.find(candidate => candidate.id === state.selectedRequestId);
        if (state.inspectorTab === 'payload') {
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
        if (state.inspectorTab === 'headers') {
          const traceable = Boolean(request?.traceable);
          state.fieldTab = 'headers';
          state.selectedField = traceable ? fieldSets.headers.find(field => field.traceable) : null;
          elements.prompt.textContent = 'Request headers';
          elements.fieldTabs.hidden = true;
          elements.traceDock.hidden = !traceable;
          if (traceable) {
            renderFields();
          } else {
            renderInspectorMessage('Request header capture is disabled for this session.');
          }
          return;
        }
        if (state.inspectorTab === 'signals') {
          elements.prompt.textContent = 'Request signal profile';
          elements.fieldTabs.hidden = true;
          elements.traceDock.hidden = !requestTraceRoot(request);
          if (request?.origin !== 'live') {
            renderInspectorMessage('Signal profiles are built from live broker evidence.');
            return;
          }
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
          const labels = {
            canvas: 'Canvas', webgl: 'WebGL', web_audio: 'Web Audio', navigator: 'Navigator',
            permissions: 'Permissions', storage: 'Storage', webrtc: 'WebRTC'
          };
          const details = state.signalProfile.signals.map(signal => ({
            key: labels[signal.category],
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
          const correlated = lifecycleEvents.find(event => event.protocol_version === 2 && event.initiator_process_id > 0);
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
              { key: 'duration', value: request.time, type: 'time' },
              { key: 'lifecycle', value: request.operation, type: 'state' },
              { key: 'events', value: request.events.length, type: 'count' }
            ]);
          } else if (request) {
            renderInspectorDetails([
              { key: 'duration', value: `${request.time} ms`, type: 'time' },
              { key: 'source', value: 'sample workspace data', type: 'source' }
            ]);
          } else {
            renderInspectorMessage('No request timing is available.');
          }
          return;
        }

        const messages = {
          preview: 'No safe preview is available for this response.',
          response: 'Response body capture is disabled for this session.'
        };
        elements.prompt.textContent = state.inspectorTab[0].toUpperCase() + state.inspectorTab.slice(1);
        elements.fieldTabs.hidden = true;
        elements.traceDock.hidden = true;
        renderInspectorMessage(messages[state.inspectorTab] || 'No captured data is available.');
      }

      function renderEvidence() {
        document.querySelectorAll('.nav-button[data-screen="experiments"]')
          .forEach(button => { button.disabled = !state.selectedField; });
        const documentSteps = state.originTrace?.steps ?? [];
        const firstTime = documentSteps.length ? BigInt(documentSteps[documentSteps.length - 1].monotonic_time_ns) : 0n;
        const tracedEvidence = documentSteps.map(step => ({
          relative: formatMilliseconds(BigInt(step.monotonic_time_ns) - firstTime, '+'),
          source: step.confidence,
          category: step.category,
          type: step.operation,
          correlation: `session ${step.event.session_id} · process ${step.event.process_id} · seq ${step.event.sequence_number} · frame ${step.frame_id} · request ${step.request_id} · artifact ${step.artifact_id}`,
          value: step.value || step.relation
        }));
        const gapEvidence = (state.originTrace?.gaps ?? []).map(gap => ({
          relative: 'gap', source: 'unknown', category: 'trace', type: gap.reason,
          correlation: `after step ${gap.after_step + 1}`, value: gap.detail
        }));
        const selectedSampleEvidence = !state.originTrace && state.selectedField ? sampleEvidence : [];
        const evidence = [...tracedEvidence, ...gapEvidence, ...selectedSampleEvidence];
        elements.evidenceRows.replaceChildren(...evidence.map(event => {
          const row = document.createElement('div'); row.className = 'evidence-row'; row.setAttribute('role', 'row');
          const values = [event.relative, event.source, event.category, event.type, event.correlation, event.value];
          values.forEach((value, index) => {
            const cell = document.createElement('span'); cell.textContent = String(value ?? ''); cell.title = cell.textContent;
            cell.setAttribute('role', 'cell');
            if (index === 1) cell.className = event.source === 'observed' ? 'source-live' : 'source-sample';
            if (index === 2) cell.className = 'category-cell';
            if (index === 4) cell.className = 'correlation-cell';
            row.append(cell);
          });
          return row;
        }));
        elements.evidenceCount.textContent = `${evidence.length} trace records`;
        elements.evidenceLinkCount.textContent = String(evidence.length);
        if (!document.querySelector('#screen-backtrace').hidden) renderBacktrace();
      }

      function originTraceSelection() {
        const request = state.requests.find(candidate => candidate.id === state.selectedRequestId);
        const root = requestTraceRoot(request);
        if (!request || !root) return null;
        const requestID = integerText(root, 'request_id');
        return {
          request,
          root,
          requestID,
          key: `${request.id}:${root.process_id}:${integerText(root, 'sequence_number')}`
        };
      }

      async function refreshOriginTrace() {
        const generation = ++state.originTraceGeneration;
        const selection = originTraceSelection();
        if (!selection || location.protocol === 'file:') {
          state.originTraceStatus = 'empty';
          state.originTraceError = 'A live broker request is required for origin tracing.';
          renderBacktrace();
          return;
        }
        state.originTraceStatus = 'loading';
        state.originTraceError = null;
        renderBacktrace();
        try {
          const headers = state.originTraceKey === selection.key && state.originTraceEtag
            ? { 'If-None-Match': state.originTraceEtag }
            : {};
          const parameters = new URLSearchParams({
            request_id: selection.requestID,
            root_process_id: String(selection.root.process_id),
            root_sequence_number: integerText(selection.root, 'sequence_number')
          });
          const response = await fetch(`/api/origin-trace?${parameters}`, { cache: 'no-store', headers });
          if (generation !== state.originTraceGeneration) return;
          if (response.status === 304 && state.originTrace) {
            state.originTraceStatus = 'ready';
            renderBacktrace();
            return;
          }
          if (!response.ok) throw new Error(`Origin trace store returned ${response.status}`);
          const body = await response.json();
          if (generation !== state.originTraceGeneration) return;
          if (!isOriginTraceResponse(body)) throw new TypeError('Malformed origin trace response');
          state.originTrace = body;
          state.originTraceStatus = 'ready';
          state.originTraceKey = selection.key;
          state.originTraceEtag = response.headers.get('ETag');
        } catch (error) {
          if (generation !== state.originTraceGeneration) return;
          state.originTraceStatus = 'error';
          state.originTraceError = error.message;
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
        [
          ['Relationship', step.relation.replaceAll('_', ' ')],
          ['Link type', step.confidence === 'observed' ? 'Recorded event link' : 'Matched by shared identifiers'],
          ['Time (monotonic ns)', step.monotonic_time_ns],
          ['Session', step.event.session_id], ['Process', step.event.process_id],
          ['Event', step.event.sequence_number], ['Frame', step.frame_id],
          ['Request', step.request_id], ['Artifact', step.artifact_id]
        ].forEach(([label, value]) => facts.append(textElement('dt', '', label), textElement('dd', '', String(value))));
        panel.append(facts);
        if (step.value) panel.append(textElement('h4', '', 'Captured value'), textElement('pre', 'trace-value', step.value));
        const artifact = state.artifacts.find(candidate => candidate.artifact_id === step.artifact_id);
        if (artifact) {
          const open = textElement('button', 'secondary-button', 'Open source'); open.type = 'button';
          open.addEventListener('click', () => { showScreen('sources', open); selectArtifact(artifact.artifact_id); });
          panel.append(open);
        }
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
          option.textContent = `${candidate.method} ${candidate.path}${requestTraceRoot(candidate) ? '' : candidate.origin === 'sample' ? ' (sample, no trace)' : ' (no request identifier)'}`;
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
        const trace = selection ? state.originTrace : null;
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
          : !selection ? (request?.origin === 'sample' ? 'This sample request has no trace' : request ? 'This event has no request identifier' : 'No captured requests yet') : trace ? 'No earlier events were retained' : 'Ready to load';
        elements.traceEmptyMessage.textContent = loading ? 'Reading the recorded events for this request.'
          : failed ? (state.originTraceError || 'Try loading the trace again.')
          : !selection ? (captured.length ? 'Choose a captured request above, or open the first one below.' : 'Capture a request in a live session, then return here to inspect its events.')
          : trace ? (trace.gaps[0]?.detail || 'The capture does not contain a predecessor for this request.') : 'Choose Load trace to inspect this request.';
        const models = [];
        const labels = {trace_target: 'Selected request', parent_event: 'Previous event', request_initiator: 'Request initiator', request_lifecycle: 'Request lifecycle', artifact_request: 'Related artifact'};
        (trace?.steps ?? []).forEach((step, index) => {
          models.push({key: `${step.event.process_id}:${step.event.sequence_number}`, index: String(index + 1),
            title: `${step.category} · ${step.operation}`, kind: labels[step.relation] || step.relation,
            confidence: step.confidence === 'observed' ? 'Recorded link' : 'Shared identifiers',
            style: step.confidence === 'observed' ? 'exact' : 'correlation', step});
          trace.gaps.filter(gap => gap.after_step === index).forEach((gap, gapIndex) => models.push({
            key: `gap:${index}:${gapIndex}`, index: '!', title: gap.reason.replaceAll('_', ' '),
            kind: 'Missing event', confidence: 'Gap', style: 'unknown', meta: gap.detail, gap: true
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
        elements.coverageValue.textContent = hasSteps ? `${trace.coverage.percent}% coverage` : '';
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
            ? `${scope.matched_target_count} ${scope.matched_target_count === 1 ? 'page' : 'pages'}`
            : scope?.state ?? 'No scope';
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
          parsed.search = '';
          parsed.hash = '';
          elements.repeaterRequestUrl.value = parsed.toString();
        } catch { elements.repeaterRequestUrl.value = ''; }
        elements.repeaterRequestMethod.value = /^[A-Z][A-Z0-9!#$%&'*+.^_`|~-]{0,31}$/.test(request.method)
          ? request.method : 'GET';
        elements.repeaterRequestTimeout.value = '15000';
        elements.repeaterRequestHeaders.value = '';
        elements.repeaterRequestBody.value = '';
        state.repeaterDraftDirty = false;
        renderRepeaterVariableStatus();
      }

      function loadRepeaterHistoryEntry(entry, focus = false) {
        if (!entry) return;
        state.repeaterSelectedHistoryId = entry.id;
        state.repeaterExpectedHistoryId = null;
        elements.repeaterRequestUrl.value = entry.request.url;
        elements.repeaterRequestMethod.value = entry.request.method;
        elements.repeaterRequestTimeout.value = String(entry.request.timeout_ms);
        elements.repeaterRequestHeaders.value = entry.request.headers.length
          ? JSON.stringify(repeaterHeaderObject(entry.request.headers), null, 2) : '';
        elements.repeaterRequestBody.value = entry.request.body;
        state.repeaterDraftDirty = false;
        renderRepeaterVariableStatus();
        renderRepeater();
        if (focus) {
          [...elements.repeaterHistory.querySelectorAll('.repeater-history-row')]
            .find(row => Number(row.dataset.historyId) === entry.id)?.focus({preventScroll: true});
        }
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
        if (!chips.length) chips.push(textElement('span', 'repeater-variable-chip', 'No variables used'));
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
          elements.repeaterHistory.replaceChildren(textElement('div', 'experiment-empty', 'No Repeater requests yet.'));
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
        const headers = document.createElement('div'); headers.className = 'repeater-response-headers';
        if (response.headers.length) {
          headers.append(...response.headers.map(header => {
            const row = document.createElement('div'); row.className = 'repeater-response-header';
            row.append(textElement('span', '', header.name), textElement('span', '', header.value));
            return row;
          }));
        } else headers.append(textElement('div', 'experiment-empty', 'No response headers.'));
        const body = document.createElement('pre'); body.className = 'experiment-result-body';
        body.textContent = response.ok ? response.body || '(empty response body)' : response.error;
        elements.repeaterResponse.replaceChildren(summary, headers, body);
        elements.repeaterResponseMeta.textContent = `run ${entry.id} · ${entry.resolved_request.method} ${entry.resolved_request.url} · ${response.headers.length} headers${response.headers_truncated ? ' · truncated' : ''}`;
        elements.repeaterResponseBadge.dataset.kind = response.ok ? '' : 'error';
        elements.repeaterResponseBadge.textContent = response.ok ? 'Complete' : entry.state.replaceAll('_', ' ');
      }

      function renderRepeaterComparison(repeater) {
        const successful = (repeater?.history ?? []).filter(entry => entry.response.ok);
        const retained = new Set(successful.map(entry => entry.id));
        const comparison = repeater?.comparison ?? null;
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
        elements.repeaterCompareBaseline.replaceChildren(...options.map(option => option.cloneNode(true)));
        elements.repeaterCompareCurrent.replaceChildren(...options);
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
          experimentFact('Coverage', comparison.partial ? 'Partial due to truncation' : 'Complete within limits')
        );
        elements.repeaterComparison.lastElementChild.classList.add('repeater-comparison-detail');
        elements.repeaterComparisonBadge.dataset.kind = comparison.partial ? 'error' : '';
        elements.repeaterComparisonBadge.textContent = `Run ${comparison.baseline_id} vs ${comparison.current_id}`;
      }

      function renderRepeater() {
        prefillRepeaterRequest();
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
        else if (!attached) setExperimentNotice('idle', 'Attach an authorized browser target before creating a Repeater session.');
        else setExperimentNotice('idle', repeater.message);

        elements.repeaterContextBadge.dataset.kind = repeater?.state === 'error' ? 'error' : experiment?.isolated ? '' : 'offline';
        elements.repeaterContextBadge.textContent = experiment?.state === 'creating' ? 'Creating'
          : experiment?.state === 'disposing' ? 'Disposing'
            : experiment?.isolated ? 'Isolated'
              : repeater?.state === 'disposed' ? 'Disposed' : 'Not created';
        elements.repeaterContextMessage.textContent = repeater?.state === 'error' ? repeater.message
          : contextReady ? 'Disposable page attached. Repeater has no baseline cookies or storage.'
            : repeater?.message ?? 'No disposable request-lab context exists.';
        elements.repeaterStorageState.textContent = experiment?.isolated ? 'Ephemeral and isolated'
          : repeater?.state === 'disposed' ? 'Deleted and erased' : 'Not allocated';
        elements.repeaterCreate.disabled = !attached || Boolean(experiment?.isolated) || working || state.debuggerActionPending;
        elements.repeaterDispose.disabled = !canDispose || working || state.debuggerActionPending;
        elements.repeaterClearHistory.disabled = !repeater?.history.length || active || working || state.debuggerActionPending;

        prefillRepeaterVariables(repeater);
        const variableCount = repeater?.variables.length ?? 0;
        elements.repeaterVariableBadge.textContent = `${variableCount} ${variableCount === 1 ? 'variable' : 'variables'}`;
        elements.repeaterVariableBadge.dataset.kind = contextReady ? '' : 'offline';
        elements.repeaterApplyVariables.disabled = !contextReady || active || working || state.debuggerActionPending;
        elements.repeaterVariables.disabled = !contextReady || active || working;
        elements.repeaterRequestForm.querySelectorAll('input, textarea').forEach(field => { field.disabled = !contextReady || active || working; });
        elements.repeaterSend.disabled = !contextReady || active || working || state.debuggerActionPending;
        elements.repeaterCancel.disabled = !active || repeater?.state === 'cancelling';
        elements.repeaterRequestBadge.dataset.kind = active ? '' : contextReady ? '' : 'offline';
        elements.repeaterRequestBadge.textContent = repeater?.state === 'cancelling' ? 'Cancelling'
          : repeater?.state === 'running' ? 'Running' : 'Draft';
        elements.repeaterActiveRequest.textContent = repeater?.active_execution
          ? `run ${repeater.active_execution.execution_id} · ${repeater.active_execution.resolved_method} ${repeater.active_execution.resolved_url}`
          : 'None';
        renderRepeaterVariableStatus();
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
          elements.objectResults.replaceChildren(textElement('div', 'experiment-empty',
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
        elements.experimentTitle.textContent = 'Live Object Lab';
        elements.experimentSubtitle.textContent = 'Find an object, inspect its properties, and test a change on a disposable page.';

        if (state.experimentError) setExperimentNotice('error', state.experimentError);
        else if (!experiment || !objectExperiment) setExperimentNotice('error', 'The debugger session is unavailable or malformed.');
        else if (contextBusy) setExperimentNotice('working', objectExperiment.message);
        else if (objectExperiment.state === 'error' || objectExperiment.last_mutation?.ok === false) setExperimentNotice('error', objectExperiment.message);
        else if (pageReady || objectExperiment.state === 'disposed') setExperimentNotice('ready', objectExperiment.message);
        else if (!attached) setExperimentNotice('idle', 'Attach an authorized browser target before creating Object Lab.');
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
          elements.hooksDefinitions.replaceChildren(textElement('div', 'experiment-empty', 'No function hooks configured.'));
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
          const meta = textElement('span', 'hook-definition-meta',
            `${sourceName({url: definition.url, source_type: 'script', script_id: definition.script_id})}:${definition.line + 1}:${definition.column + 1}${resolved} · ${behavior}`);
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
        const total = hooks?.total_hits ?? 0;
        elements.hooksHitCount.textContent = `${total} / ${hooks?.limits?.total_hits ?? 512}`;
        elements.hooksHitCount.dataset.kind = hooks?.last_failure ? 'error' : hits.length ? '' : 'offline';
        elements.hooksHitMeta.textContent = hits.length
          ? `${hits.length} retained · ${hooks.hit_evictions} evicted · metadata never enters evidence storage`
          : 'Entry bindings and return outcomes stay in ephemeral session memory.';
        if (!hits.length) {
          elements.hooksHits.replaceChildren(textElement('div', 'experiment-empty', 'Arm a hook, then exercise the isolated page.'));
          return;
        }
        elements.hooksHits.replaceChildren(...[...hits].reverse().map(hit => {
          const row = document.createElement('div'); row.className = 'hook-hit-row';
          const title = textElement('span', 'hook-hit-title', `${hit.label} · ${hit.function}`);
          const operation = textElement('span', 'hook-hit-operation', hit.operation.replaceAll('_', ' '));
          const source = sourceName({url: hit.source, source_type: 'script', script_id: ''});
          const meta = textElement('span', 'hook-hit-meta',
            `${new Date(hit.occurred_at_ms).toLocaleTimeString()} · ${hit.category} · ${source}:${hit.line + 1}:${hit.column + 1} · session ${hit.session_id} / hook ${hit.hook_id} / hit ${hit.id}`);
          const values = hit.bindings.map(binding => `${binding.name}=${debuggerValueText(binding.value)}`);
          const returnText = hit.category === 'return'
            ? `return ${debuggerValueText(hit.original_return)}${hit.replacement_return ? ` → ${debuggerValueText(hit.replacement_return)}` : ''}` : '';
          const bindingText = [...values, returnText].filter(Boolean).join(' · ') || 'No local data properties captured';
          const bindings = textElement('span', 'hook-hit-bindings', `${bindingText}${hit.bindings_truncated ? ' · binding limit reached' : ''}`);
          row.append(title, operation, meta, bindings);
          if (hit.error) row.append(textElement('span', 'hook-hit-error', hit.error));
          return row;
        }));
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
        const scripts = (state.debuggerSession?.scripts ?? []).filter(script => {
          if (script.language !== 'JavaScript') return false;
          const url = script.url ?? '';
          return !url.startsWith('file:') && !url.startsWith('evaluate;') && !url.startsWith('pptr:');
        }).slice(-256);
        const selectedScript = elements.hooksScript.value;
        const options = scripts.map(script => {
          const option = document.createElement('option'); option.value = script.script_id;
          option.textContent = `${sourceName({...script, source_type: 'script'})} · lines ${script.start_line + 1}-${script.end_line + 1}`;
          return option;
        });
        if (!options.length) {
          const option = document.createElement('option'); option.value = ''; option.textContent = 'No live JavaScript sources';
          options.push(option);
        }
        elements.hooksScript.replaceChildren(...options);
        if (scripts.some(script => script.script_id === selectedScript)) elements.hooksScript.value = selectedScript;

        elements.experimentTitle.textContent = 'Runtime Hook Studio';
        elements.experimentSubtitle.textContent = 'Observe function calls or test return values on a disposable page.';
        if (state.experimentError) setExperimentNotice('error', state.experimentError);
        else if (!experiment || !hooks || !objectExperiment) setExperimentNotice('error', 'The debugger session is unavailable or malformed.');
        else if (contextWorking || ['arming', 'handling', 'stopping'].includes(hooks.state)) setExperimentNotice('working', hooks.message);
        else if (hooks.last_failure) setExperimentNotice('error', hooks.last_failure);
        else if (hooks.state === 'armed' || contextReady || hooks.state === 'disposed') setExperimentNotice('ready', hooks.message);
        else if (!attached) setExperimentNotice('idle', 'Attach an authorized browser target before creating Hook Studio.');
        else setExperimentNotice('idle', hooks.message);

        elements.hooksContextBadge.dataset.kind = hooks?.state === 'error' ? 'error' : hooks?.isolated ? '' : 'offline';
        elements.hooksContextBadge.textContent = experiment?.state === 'creating' ? 'Creating'
          : experiment?.state === 'disposing' ? 'Disposing' : hooks?.isolated ? 'Isolated'
            : hooks?.state === 'disposed' ? 'Disposed' : 'Not created';
        elements.hooksContextMessage.textContent = hooks?.message ?? 'No disposable Experiment context exists.';
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
        elements.hooksClear.disabled = !(hooks?.hits.length) || active || contextWorking || state.debuggerActionPending;
        elements.hooksPageUrl.disabled = !editable;
        elements.hooksNavigate.disabled = !editable || state.debuggerActionPending;
        elements.hooksDefinitionForm.querySelectorAll('input, select, textarea').forEach(field => { field.disabled = !editable; });
        elements.hooksReturnValueField.hidden = elements.hooksReturnMode.value === 'none';
        elements.hooksReturnValueField.firstChild.textContent = elements.hooksReturnMode.value === 'json'
          ? 'Replacement JSON' : 'Replacement frame expression';
        elements.hooksAdd.disabled = !editable || !scripts.length || !elements.hooksLabel.value.trim() ||
          (!elements.hooksEntryEnabled.checked && !elements.hooksReturnEnabled.checked) || state.debuggerActionPending;
        elements.hooksConfirm.disabled = !contextReady || active || !hooks?.definitions.length || contextWorking;
        elements.hooksArm.disabled = !editable || !hooks?.definitions.length || !elements.hooksConfirm.checked || state.debuggerActionPending;
        elements.hooksDisarm.disabled = !active || state.debuggerActionPending;
        renderRuntimeHookDefinitions(hooks, active);
        renderRuntimeHookHits(hooks);
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
            const response = await runExperimentAction({action: 'remove_automation_recipe', recipe_id: recipe.id});
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
          elements.automationRuns.replaceChildren(textElement('div', 'experiment-empty', 'Run a recipe to see its bounded result and logs.'));
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

        elements.experimentTitle.textContent = 'Automation Recipe Studio';
        elements.experimentSubtitle.textContent = 'Run a page script once or on a chosen trigger. Review each run and its logs.';
        if (state.experimentError) setExperimentNotice('error', state.experimentError);
        else if (!experiment || !automation || !objectExperiment) setExperimentNotice('error', 'The debugger session is unavailable or malformed.');
        else if (working) setExperimentNotice('working', automation.message);
        else if (automation.last_failure) setExperimentNotice('error', automation.last_failure);
        else if (automation.auto_armed || contextReady || automation.state === 'disposed') setExperimentNotice('ready', automation.message);
        else if (!attached) setExperimentNotice('idle', 'Attach an authorized browser target before creating Automation Studio.');
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
        elements.hooksWorkspace.hidden = state.experimentMode !== 'hooks';
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
        elements.experimentTitle.textContent = 'Request Interception Lab';
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
          : 'Disposable context · no baseline cookies, storage, or credentials';

        if (state.experimentError) setExperimentNotice('error', state.experimentError);
        else if (!experiment) setExperimentNotice('error', 'The debugger session is unavailable or malformed.');
        else if (working) setExperimentNotice('working', experiment.message);
        else if (experiment.state === 'error' || experiment.result?.ok === false) setExperimentNotice('error', experiment.message);
        else if (contextReady) setExperimentNotice('ready', experiment.message);
        else if (experiment.state === 'disposed') setExperimentNotice('ready', experiment.message);
        else if (!attached) setExperimentNotice('idle', 'Attach an authorized browser target before creating an experiment.');
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

      async function runExperimentAction(request) {
        const parallelControl = ['cancel_repeater_request', 'cancel_automation_recipe'].includes(request.action);
        if (state.experimentPending && !parallelControl) return null;
        if (!parallelControl) state.experimentPending = true;
        state.experimentError = null;
        renderExperiment();
        const response = await debuggerAction(request);
        if (response?.experiment && isRequestInterception(response.experiment) && state.debuggerSession) {
          state.debuggerSession.request_interception = response.experiment;
        }
        if (response?.action_scope && isActionScope(response.action_scope) && state.debuggerSession) {
          state.debuggerSession.action_scope = response.action_scope;
        }
        if (response?.object_experiment && isObjectExperiment(response.object_experiment) && state.debuggerSession) {
          state.debuggerSession.object_experiment = response.object_experiment;
        }
        if (response?.runtime_hooks && isRuntimeHooks(response.runtime_hooks) && state.debuggerSession) {
          state.debuggerSession.runtime_hooks = response.runtime_hooks;
        }
        if (response?.automation_recipes && isAutomationRecipes(response.automation_recipes) && state.debuggerSession) {
          state.debuggerSession.automation_recipes = response.automation_recipes;
        }
        if (response?.repeater && isRepeater(response.repeater) && state.debuggerSession) {
          state.debuggerSession.repeater = response.repeater;
        }
        if (!response) state.experimentError = state.debuggerError || 'The experiment action did not complete.';
        if (!parallelControl) state.experimentPending = false;
        renderExperiment();
        return response;
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
        const response = await runExperimentAction({action: 'navigate_object_experiment', url});
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
        const response = await runExperimentAction(request);
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
        const response = await runExperimentAction(request);
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
        const response = await runExperimentAction({action: 'navigate_object_experiment', url});
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
        const response = await runExperimentAction(request);
        if (response) resetAutomationEditor();
      }

      async function runAutomationRecipe(recipeId) {
        if (!elements.automationConfirm.checked) {
          state.experimentError = 'Confirm disposable-page code execution before running a recipe.';
          renderExperiment();
          elements.automationConfirm.focus();
          return;
        }
        try {
          const response = await runExperimentAction({
            action: 'run_automation_recipe', recipe_id: recipeId, confirmed: true,
            variables: parseAutomationVariables()
          });
          if (response?.run) state.automationSelectedRunId = response.run.id;
          if (response) elements.automationConfirm.checked = false;
        } catch (error) {
          state.experimentError = error.message;
          renderExperiment();
        }
      }

      async function addRuntimeHook() {
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
          if (returnMode === 'json') {
            try { request.return_value = JSON.parse(elements.hooksReturnValue.value); }
            catch { throw new TypeError('Return replacement must be valid JSON.'); }
          }
          if (returnMode === 'expression') {
            request.return_expression = elements.hooksReturnValue.value.trim();
            if (!request.return_expression) throw new TypeError('Enter one return-frame expression.');
          }
          const response = await runExperimentAction(request);
          if (response) {
            elements.hooksConfirm.checked = false;
            elements.hooksLabel.value = '';
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

      function pivotSourceToRuntimeHooks() {
        const source = selectedSource();
        const hooks = runtimeHooksState();
        if (source?.source_type !== 'script' || !hooks?.isolated ||
            hooks.target_id !== state.debuggerSession?.target?.id) return;
        const line = state.sourceCursor?.scriptId === source.script_id
          ? state.sourceCursor.line : source.start_line;
        state.experimentMode = 'hooks';
        showScreen('experiments');
        elements.hooksScript.value = source.script_id;
        elements.hooksLine.value = String(line + 1);
        elements.hooksColumn.value = String((state.sourceCursor?.column ?? sourceRuntimeColumn(source, 0)) + 1);
        if (!elements.hooksLabel.value) elements.hooksLabel.value = `${sourceName(source)}:${line + 1}`;
        renderRuntimeHooks();
        requestAnimationFrame(() => elements.hooksLabel.focus());
      }

      async function applyRepeaterVariables() {
        try {
          const variables = parseRepeaterVariables(elements.repeaterVariables.value);
          const response = await runExperimentAction({action: 'configure_repeater_variables', variables});
          if (response) {
            state.repeaterVariablesDirty = false;
            state.repeaterVariablesKey = JSON.stringify(variables);
            renderRepeaterVariableStatus();
          }
          return response;
        } catch (error) {
          state.experimentError = error.message;
          renderExperiment();
          return null;
        }
      }

      async function runRepeaterRequest() {
        try {
          const applied = await applyRepeaterVariables();
          if (!applied) return;
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
          const response = await runExperimentAction({
            action: 'run_repeater_request',
            url: elements.repeaterRequestUrl.value.trim(),
            method,
            headers: parseExperimentHeaders(elements.repeaterRequestHeaders.value, 'Request headers'),
            body,
            timeout_ms: timeout
          });
          const executionId = response?.repeater?.active_execution?.execution_id ??
            response?.repeater?.history.at(-1)?.id;
          if (Number.isSafeInteger(executionId) && executionId > previousHistoryId) {
            state.repeaterExpectedHistoryId = executionId;
            renderExperiment();
          }
          state.repeaterDraftDirty = false;
        } catch (error) {
          state.experimentError = error.message;
          renderExperiment();
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
        if (state.apiCollectionRefreshing || location.protocol === 'file:') return false;
        state.apiCollectionRefreshing = true;
        if (!state.apiCollectionLoaded) setCollectionNotice('loading', 'Loading the local API Collection…');
        try {
          const headers = !force && state.apiCollectionEtag ? {'If-None-Match': state.apiCollectionEtag} : {};
          const response = await fetch('/api/api-collection', {cache: 'no-store', headers});
          if (response.status === 304) return true;
          if (!response.ok) throw new Error(`API Collection store returned ${response.status}`);
          const body = await response.json();
          if (!isApiCollection(body)) throw new TypeError('Malformed API Collection response');
          state.apiCollection = body;
          state.apiCollectionLoaded = true;
          state.apiCollectionEtag = response.headers.get('ETag');
          if (!collectionFolder(state.collectionSelectedFolderId)) state.collectionSelectedFolderId = 1;
          if (!collectionRequest()) state.collectionSelectedRequestId = null;
          setCollectionNotice(body.requests.length ? 'ready' : 'empty', body.requests.length
            ? `${body.requests.length} saved ${body.requests.length === 1 ? 'request' : 'requests'} loaded from the permission-restricted local store.`
            : 'The local collection is empty. Create a request or import only method and URL from Traffic.');
          renderApiCollection();
          return true;
        } catch (error) {
          setCollectionNotice('error', `API Collection unavailable: ${error.message}. The last valid collection remains visible.`);
          renderApiCollection();
          return false;
        } finally {
          state.apiCollectionRefreshing = false;
        }
      }

      async function replaceApiCollection(folders, requests, successMessage) {
        if (state.apiCollectionSaving) return false;
        state.apiCollectionSaving = true;
        setCollectionNotice('saving', 'Saving one atomic API Collection generation…');
        renderApiCollection();
        try {
          const response = await fetch('/api/api-collection/actions', {
            method: 'POST', cache: 'no-store', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(collectionReplacement(folders, requests))
          });
          const body = await response.json();
          if (response.status === 409) {
            state.apiCollectionEtag = null;
            await refreshApiCollection(true);
            setCollectionNotice('conflict', body.error || 'The collection changed in another window. The current generation was reloaded.');
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
          setCollectionNotice('error', `API Collection was not changed: ${error.message}`);
          return false;
        } finally {
          state.apiCollectionSaving = false;
          renderApiCollection();
        }
      }

      function collectionFolderOptions(selectedId, excludedIds = new Set()) {
        return state.apiCollection.folders
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
      }

      function selectCollectionFolder(folderId, focus = false) {
        if (!collectionFolder(folderId)) return;
        state.collectionSelectedFolderId = folderId;
        state.collectionSelectedRequestId = null;
        state.collectionFolderDraftId = null;
        state.collectionFolderDirty = false;
        state.collectionDeleteFolderId = null;
        renderApiCollection();
        if (focus) elements.collectionTree.querySelector(`[data-folder-id="${folderId}"]`)?.focus({preventScroll: true});
      }

      function selectCollectionRequest(requestId, focus = false) {
        const request = collectionRequest(requestId);
        if (!request) return;
        state.collectionSelectedRequestId = requestId;
        state.collectionSelectedFolderId = request.folder_id;
        state.collectionExpandedFolderIds.add(request.folder_id);
        state.collectionRequestDraftId = null;
        state.collectionDraftDirty = false;
        state.collectionDeleteRequestId = null;
        state.collectionSelectedHistoryId = null;
        renderApiCollection();
        if (focus) elements.collectionTree.querySelector(`[data-request-id="${requestId}"]`)?.focus({preventScroll: true});
      }

      function moveCollectionTreeSelection(event) {
        if (!['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
        const row = event.currentTarget;
        const rows = [...elements.collectionTree.querySelectorAll('.collection-tree-row')];
        const index = rows.indexOf(row);
        if (index < 0) return;
        event.preventDefault();
        if (row.dataset.folderId && ['ArrowLeft', 'ArrowRight'].includes(event.key)) {
          const folderId = Number(row.dataset.folderId);
          const expanded = state.collectionExpandedFolderIds.has(folderId);
          if (event.key === 'ArrowRight' && !expanded) state.collectionExpandedFolderIds.add(folderId);
          else if (event.key === 'ArrowLeft' && expanded && folderId !== 1) state.collectionExpandedFolderIds.delete(folderId);
          else if (event.key === 'ArrowLeft') {
            const parentId = collectionFolder(folderId)?.parent_id;
            if (parentId !== null && parentId !== undefined) selectCollectionFolder(parentId, true);
            return;
          } else return;
          renderApiCollection();
          elements.collectionTree.querySelector(`[data-folder-id="${folderId}"]`)?.focus();
          return;
        }
        const next = event.key === 'Home' ? 0 : event.key === 'End' ? rows.length - 1
          : Math.max(0, Math.min(rows.length - 1, index + (event.key === 'ArrowDown' ? 1 : -1)));
        rows[next].click(); rows[next].focus();
      }

      function renderCollectionTree() {
        const rows = [];
        const appendFolder = (folder, level) => {
          const children = state.apiCollection.folders.filter(candidate => candidate.parent_id === folder.id)
            .sort((left, right) => left.name.localeCompare(right.name));
          const requests = state.apiCollection.requests.filter(request => request.folder_id === folder.id)
            .sort((left, right) => left.name.localeCompare(right.name));
          const hasChildren = children.length > 0 || requests.length > 0;
          const expanded = folder.id === 1 || state.collectionExpandedFolderIds.has(folder.id);
          const row = document.createElement('button'); row.type = 'button'; row.className = 'collection-tree-row';
          row.dataset.folderId = String(folder.id); row.style.setProperty('--collection-depth', String(level - 1));
          row.setAttribute('role', 'treeitem'); row.setAttribute('aria-level', String(level));
          row.setAttribute('aria-selected', String(!state.collectionSelectedRequestId && state.collectionSelectedFolderId === folder.id));
          if (hasChildren) row.setAttribute('aria-expanded', String(expanded));
          row.tabIndex = !state.collectionSelectedRequestId && state.collectionSelectedFolderId === folder.id ? 0 : -1;
          row.append(textElement('span', 'collection-tree-glyph', hasChildren ? expanded ? '▾' : '▸' : '·'),
            textElement('span', 'collection-tree-name', folder.name),
            textElement('span', 'collection-tree-meta', `${requests.length}`));
          row.addEventListener('click', () => selectCollectionFolder(folder.id));
          row.addEventListener('dblclick', () => { if (hasChildren && folder.id !== 1) {
            if (expanded) state.collectionExpandedFolderIds.delete(folder.id); else state.collectionExpandedFolderIds.add(folder.id);
            renderApiCollection();
          }});
          row.addEventListener('keydown', moveCollectionTreeSelection);
          rows.push(row);
          if (!expanded) return;
          children.forEach(child => appendFolder(child, level + 1));
          requests.forEach(request => {
            const requestRow = document.createElement('button'); requestRow.type = 'button'; requestRow.className = 'collection-tree-row';
            requestRow.dataset.requestId = String(request.id); requestRow.style.setProperty('--collection-depth', String(level));
            requestRow.setAttribute('role', 'treeitem'); requestRow.setAttribute('aria-level', String(level + 1));
            requestRow.setAttribute('aria-selected', String(state.collectionSelectedRequestId === request.id));
            requestRow.tabIndex = state.collectionSelectedRequestId === request.id ? 0 : -1;
            requestRow.append(textElement('span', 'collection-tree-glyph', '↗'),
              textElement('span', 'collection-tree-name', request.name),
              textElement('span', 'collection-tree-meta', request.method));
            requestRow.addEventListener('click', () => selectCollectionRequest(request.id));
            requestRow.addEventListener('keydown', moveCollectionTreeSelection);
            rows.push(requestRow);
          });
        };
        appendFolder(collectionFolder(1), 1);
        elements.collectionTree.replaceChildren(...rows);
      }

      function renderCollectionFolderForm() {
        const folder = collectionFolder(state.collectionSelectedFolderId) ?? collectionFolder(1);
        if (state.collectionFolderDraftId !== folder.id || !state.collectionFolderDirty) {
          state.collectionFolderDraftId = folder.id;
          elements.collectionFolderName.value = folder.name;
          elements.collectionFolderVariables.value = collectionVariablesText(folder.variables);
        }
        const excluded = collectionDescendantIds(folder.id); excluded.add(folder.id);
        elements.collectionFolderParent.replaceChildren(...collectionFolderOptions(folder.parent_id ?? 1, excluded));
        elements.collectionFolderParent.value = String(folder.parent_id ?? 1);
        const root = folder.id === 1;
        elements.collectionFolderName.disabled = root || state.apiCollectionSaving;
        elements.collectionFolderParent.disabled = root || state.apiCollectionSaving;
        elements.collectionFolderVariables.disabled = state.apiCollectionSaving;
        elements.collectionSaveFolder.disabled = state.apiCollectionSaving;
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
        elements.collectionRequestBadge.textContent = request ? request.method : 'No request';
        if (!request) return;
        if (state.collectionRequestDraftId !== request.id || !state.collectionDraftDirty) {
          state.collectionRequestDraftId = request.id;
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
        elements.collectionRequestFolder.replaceChildren(...collectionFolderOptions(request.folder_id));
        elements.collectionRequestFolder.value = String(request.folder_id);
        elements.collectionRequestForm.querySelectorAll('input, textarea, select').forEach(field => {
          field.disabled = state.apiCollectionSaving;
        });
        elements.collectionSaveRequest.disabled = state.apiCollectionSaving;
        elements.collectionDuplicateRequest.disabled = state.apiCollectionSaving || state.apiCollection.requests.length >= 128;
        elements.collectionDeleteRequest.disabled = state.apiCollectionSaving;
        elements.collectionDeleteRequest.textContent = state.collectionDeleteRequestId === request.id ? 'Confirm delete' : 'Delete';
        renderCollectionVariableStatus();
      }

      function collectionHistoryEntries() {
        const requestId = state.collectionSelectedRequestId;
        return (repeaterState()?.history ?? []).filter(entry => entry.collection_request_id === requestId);
      }

      function renderCollectionResponse(entry) {
        if (!entry) {
          elements.collectionResponse.className = 'repeater-response experiment-empty';
          elements.collectionResponse.textContent = 'Run the selected request to inspect its bounded response.';
          elements.collectionResponseMeta.textContent = 'Select a completed execution.';
          elements.collectionResponseBadge.dataset.kind = 'offline';
          elements.collectionResponseBadge.textContent = 'No response';
          return;
        }
        const response = entry.response;
        const summary = document.createElement('div'); summary.className = 'experiment-result-summary';
        summary.append(experimentFact('Status', response.ok ? `${response.status} ${response.status_text}`.trim() : entry.state.replaceAll('_', ' ')),
          experimentFact('Duration', `${response.duration_ms} ms`),
          experimentFact('Body', `${utf8ByteLength(response.body)} bytes${response.body_truncated ? ' · truncated' : ''}`));
        const headers = document.createElement('div'); headers.className = 'repeater-response-headers';
        if (response.headers.length) headers.append(...response.headers.map(header => {
          const row = document.createElement('div'); row.className = 'repeater-response-header';
          row.append(textElement('span', '', header.name), textElement('span', '', header.value)); return row;
        }));
        else headers.append(textElement('div', 'experiment-empty', 'No response headers.'));
        const body = document.createElement('pre'); body.className = 'experiment-result-body';
        body.textContent = response.ok ? response.body || '(empty response body)' : response.error;
        elements.collectionResponse.className = 'repeater-response';
        elements.collectionResponse.replaceChildren(summary, headers, body);
        elements.collectionResponseMeta.textContent = `run ${entry.id} · ${entry.resolved_request.method} ${entry.resolved_request.url}`;
        elements.collectionResponseBadge.dataset.kind = response.ok ? '' : 'error';
        elements.collectionResponseBadge.textContent = response.ok ? 'Complete' : entry.state.replaceAll('_', ' ');
      }

      function renderCollectionExecution() {
        const experiment = requestInterception();
        const repeater = repeaterState();
        const attached = ['running', 'paused'].includes(state.debuggerSession?.state);
        const active = ['running', 'cancelling'].includes(repeater?.state);
        const contextReady = attached && experiment?.isolated && experiment.target_id === state.debuggerSession?.target?.id &&
          ['ready', 'error'].includes(experiment.state) && ['ready', 'error'].includes(repeater?.state);
        elements.collectionContextBadge.dataset.kind = repeater?.state === 'error' ? 'error' : contextReady ? '' : 'offline';
        elements.collectionContextBadge.textContent = active ? repeater.state === 'cancelling' ? 'Cancelling' : 'Running'
          : contextReady ? 'Isolated' : experiment?.state === 'creating' ? 'Creating' : 'Not created';
        elements.collectionContextMessage.textContent = contextReady
          ? 'Disposable page attached with no baseline cookies or storage.'
          : attached ? repeater?.message ?? 'Create the shared isolated Request Lab context.'
            : 'Attach an authorized browser target before creating a context.';
        elements.collectionCreateContext.disabled = !attached || Boolean(experiment?.isolated) ||
          state.experimentPending || state.debuggerActionPending;
        elements.collectionRun.disabled = !collectionRequest() || !contextReady || active || state.experimentPending || state.apiCollectionSaving;
        elements.collectionCancel.disabled = !active || state.debuggerActionPending || repeater?.state === 'cancelling';
        const history = collectionHistoryEntries();
        if (!history.some(entry => entry.id === state.collectionSelectedHistoryId)) {
          state.collectionSelectedHistoryId = history.at(-1)?.id ?? null;
        }
        elements.collectionHistoryBadge.textContent = `${history.length} ${history.length === 1 ? 'run' : 'runs'}`;
        elements.collectionHistoryBadge.dataset.kind = history.length ? '' : 'offline';
        if (!history.length) elements.collectionHistory.replaceChildren(
          textElement('div', 'experiment-empty', collectionRequest() ? 'No executions for this request.' : 'Select a saved request.')
        );
        else elements.collectionHistory.replaceChildren(...[...history].reverse().map(entry => {
          const row = document.createElement('button'); row.type = 'button'; row.className = 'collection-history-row';
          row.setAttribute('role', 'option'); row.setAttribute('aria-selected', String(entry.id === state.collectionSelectedHistoryId));
          row.tabIndex = entry.id === state.collectionSelectedHistoryId ? 0 : -1;
          row.append(textElement('span', '', `${entry.resolved_request.method} ${entry.resolved_request.url}`),
            textElement('strong', '', entry.response.ok ? String(entry.response.status) : entry.state.replaceAll('_', ' ')),
            textElement('small', '', `run ${entry.id} · ${entry.response.duration_ms} ms · ${new Date(entry.completed_at_ms).toLocaleTimeString()}`));
          row.addEventListener('click', () => { state.collectionSelectedHistoryId = entry.id; renderCollectionExecution(); });
          row.addEventListener('keydown', event => {
            if (!['ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) return;
            event.preventDefault();
            const rows = [...elements.collectionHistory.querySelectorAll('.collection-history-row')];
            const index = rows.indexOf(row);
            const next = event.key === 'Home' ? 0 : event.key === 'End' ? rows.length - 1
              : Math.max(0, Math.min(rows.length - 1, index + (event.key === 'ArrowDown' ? 1 : -1)));
            rows[next].click(); rows[next].focus();
          });
          return row;
        }));
        renderCollectionResponse(history.find(entry => entry.id === state.collectionSelectedHistoryId) ?? null);
      }

      function renderApiCollection() {
        if (!elements.collectionTree) return;
        if (state.apiCollectionLoaded && state.apiCollectionStatus === 'loading') {
          state.apiCollectionStatus = state.apiCollection.requests.length ? 'ready' : 'empty';
          state.apiCollectionMessage = state.apiCollection.requests.length
            ? `${state.apiCollection.requests.length} saved ${state.apiCollection.requests.length === 1 ? 'request' : 'requests'} loaded from the permission-restricted local store.`
            : 'The local collection is empty. Create a request or import only method and URL from Traffic.';
        }
        elements.collectionGeneration.textContent = `Generation ${state.apiCollection.generation}`;
        elements.collectionCount.textContent = `${state.apiCollection.requests.length} / 128`;
        elements.collectionNewFolder.disabled = state.apiCollectionSaving || state.apiCollection.folders.length >= 32 ||
          collectionFolderDepth(state.collectionSelectedFolderId) >= 4;
        elements.collectionNewRequest.disabled = state.apiCollectionSaving || state.apiCollection.requests.length >= 128;
        elements.collectionNotice.dataset.kind = state.apiCollectionStatus;
        elements.collectionNotice.textContent = state.apiCollectionMessage;
        renderCollectionTree();
        renderCollectionFolderForm();
        renderCollectionRequestForm();
        renderCollectionExecution();
      }

      async function createCollectionFolder() {
        const name = elements.collectionNewFolderName.value.trim();
        if (!name) { setCollectionNotice('error', 'Enter a folder name.'); return; }
        const parentId = state.collectionSelectedFolderId;
        const folder = {id: collectionNextId(state.apiCollection.folders), name, parent_id: parentId, variables: []};
        if (await replaceApiCollection([...state.apiCollection.folders, folder], state.apiCollection.requests, `Folder “${name}” created.`)) {
          state.collectionSelectedFolderId = folder.id;
          state.collectionExpandedFolderIds.add(parentId);
          elements.collectionNewFolderForm.hidden = true;
          elements.collectionNewFolderName.value = '';
          renderApiCollection();
        }
      }

      async function saveCollectionFolder() {
        const folder = collectionFolder(state.collectionSelectedFolderId);
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

      async function createCollectionRequest(template = null) {
        const folderId = state.collectionSelectedFolderId;
        const base = template?.name || 'New request';
        const siblingNames = new Set(state.apiCollection.requests.filter(request => request.folder_id === folderId)
          .map(request => request.name.toLocaleLowerCase()));
        let name = base;
        for (let suffix = 2; siblingNames.has(name.toLocaleLowerCase()); suffix += 1) name = `${base} ${suffix}`;
        const request = {
          id: collectionNextId(state.apiCollection.requests), folder_id: folderId, name,
          url: template?.url || 'https://example.test/', method: template?.method || 'GET', headers: [], body: '',
          timeout_ms: 15000, variables: []
        };
        if (await replaceApiCollection(state.apiCollection.folders, [...state.apiCollection.requests, request], `Request “${name}” created.`)) {
          state.collectionSelectedRequestId = request.id;
          state.collectionExpandedFolderIds.add(folderId);
          state.collectionRequestDraftId = null;
          state.collectionDraftDirty = false;
          renderApiCollection();
          requestAnimationFrame(() => elements.collectionRequestName.focus({preventScroll: true}));
        }
      }

      async function duplicateCollectionRequest() {
        const source = collectionRequest();
        if (!source) return;
        const id = collectionNextId(state.apiCollection.requests);
        const siblingNames = new Set(state.apiCollection.requests.filter(request => request.folder_id === source.folder_id)
          .map(request => request.name.toLocaleLowerCase()));
        let name = `${source.name} copy`;
        for (let suffix = 2; siblingNames.has(name.toLocaleLowerCase()); suffix += 1) name = `${source.name} copy ${suffix}`;
        const duplicate = {...source, id, name};
        delete duplicate.created_at_ms; delete duplicate.updated_at_ms;
        if (await replaceApiCollection(state.apiCollection.folders, [...state.apiCollection.requests, duplicate], `Request “${name}” duplicated.`)) {
          state.collectionSelectedRequestId = id; state.collectionRequestDraftId = null; state.collectionDraftDirty = false;
          renderApiCollection();
        }
      }

      async function deleteCollectionRequest() {
        const request = collectionRequest();
        if (!request) return;
        if (state.collectionDeleteRequestId !== request.id) {
          state.collectionDeleteRequestId = request.id; setCollectionNotice('ready', 'Select Delete again to remove this saved request.');
          renderApiCollection(); return;
        }
        if (await replaceApiCollection(state.apiCollection.folders,
          state.apiCollection.requests.filter(candidate => candidate.id !== request.id), `Request “${request.name}” deleted.`)) {
          state.collectionSelectedRequestId = null; state.collectionDeleteRequestId = null;
          state.collectionRequestDraftId = null; state.collectionDraftDirty = false;
          renderApiCollection();
        }
      }

      async function deleteCollectionFolder() {
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
        if (!request) return;
        if (state.collectionDraftDirty && !(await saveCollectionRequest())) return;
        try {
          const saved = collectionRequest(request.id);
          const variables = {};
          collectionFolderLineage(saved.folder_id).forEach(folder => folder.variables.forEach(variable => {
            variables[variable.name] = variable.value;
          }));
          saved.variables.forEach(variable => { variables[variable.name] = variable.value; });
          if (!await runExperimentAction({action: 'configure_repeater_variables', variables})) return;
          const previousId = repeaterState()?.history.at(-1)?.id ?? 0;
          const response = await runExperimentAction({
            action: 'run_repeater_request', url: saved.url, method: saved.method,
            headers: repeaterHeaderObject(saved.headers), body: saved.body, timeout_ms: saved.timeout_ms,
            collection_request_id: saved.id
          });
          const executionId = response?.repeater?.active_execution?.execution_id ?? response?.repeater?.history.at(-1)?.id;
          if (Number.isSafeInteger(executionId) && executionId > previousId) state.collectionSelectedHistoryId = executionId;
          renderApiCollection();
        } catch (error) { setCollectionNotice('error', error.message); renderApiCollection(); }
      }

      const analystExactKeys = (value, keys) => isPlainObject(value) &&
        Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));

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
        if (!analystExactKeys(result, ['protocol_version', 'run_id', 'script_id', 'library_generation', 'ok',
          'outcome', 'result_type', 'result_text', 'result_truncated', 'logs', 'logs_truncated',
          'duration_ms', 'error']) || result.protocol_version !== 1 || result.run_id !== run.run_id ||
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

      async function refreshLocalAnalyst(force = false) {
        if (state.localAnalystRefreshing || location.protocol === 'file:') return false;
        state.localAnalystRefreshing = true;
        if (!state.localAnalystLoaded) setAnalystNotice('loading', 'Loading the local analyst workspace…');
        let loaded = false;
        try {
          const headers = !force && state.localAnalystEtag ? {'If-None-Match': state.localAnalystEtag} : {};
          const response = await fetch('/api/local-analyst', {cache: 'no-store', headers});
          if (response.status !== 304) {
            if (!response.ok) throw new Error(`Analyst workspace store returned ${response.status}`);
            const body = await response.json();
            if (!isLocalAnalystWorkspace(body)) throw new TypeError('Malformed analyst workspace response');
            state.localAnalyst = body;
            state.localAnalystLoaded = true;
            state.localAnalystEtag = response.headers.get('ETag');
          }
          if (!analystFolder()) state.analystSelectedFolderId = 1;
          if (!analystFile()) state.analystSelectedFileId = null;
          const count = state.localAnalyst.files.length;
          setAnalystNotice(count ? 'ready' : 'empty', count
            ? `${count} saved ${count === 1 ? 'file' : 'files'} loaded from the permission-restricted local workspace.`
            : 'The workspace is empty. Create an analyst script or a non-executable scratchpad.');
          loaded = true;
        } catch (error) {
          setAnalystNotice('error', `Analyst workspace unavailable: ${error.message}. The last valid generation remains visible.`);
        }
        try {
          const response = await fetch('/api/local-analyst/runner', {cache: 'no-store'});
          if (!response.ok) throw new Error(`runner returned ${response.status}`);
          const runner = await response.json();
          if (!isLocalAnalystRunner(runner)) throw new TypeError('malformed runner state');
          state.localAnalystRunner = runner;
        } catch (error) {
          state.localAnalystRunner = {protocol_version: 1, available: false, active_run_id: null,
            limits: emptyLocalAnalystWorkspace().limits, error: error.message};
        } finally {
          state.localAnalystRefreshing = false;
          renderLocalAnalyst();
        }
        return loaded;
      }

      async function replaceLocalAnalyst(folders, files, successMessage) {
        if (state.localAnalystSaving) return false;
        state.localAnalystSaving = true;
        setAnalystNotice('saving', 'Saving one atomic analyst workspace generation…');
        renderLocalAnalyst();
        try {
          const response = await fetch('/api/local-analyst/actions', {
            method: 'POST', cache: 'no-store', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(analystReplacement(folders, files))
          });
          const body = await response.json();
          if (response.status === 409) {
            state.localAnalystEtag = null;
            await refreshLocalAnalyst(true);
            setAnalystNotice('conflict', body.error || 'The workspace changed in another window. The latest generation was reloaded.');
            return false;
          }
          if (!response.ok) throw new Error(body.error || `Analyst workspace store returned ${response.status}`);
          if (!isLocalAnalystWorkspace(body)) throw new TypeError('Malformed analyst workspace response');
          state.localAnalyst = body;
          state.localAnalystLoaded = true;
          state.localAnalystEtag = `"local-analyst-${body.generation}"`;
          setAnalystNotice('ready', successMessage);
          return true;
        } catch (error) {
          setAnalystNotice('error', `Analyst workspace was not changed: ${error.message}`);
          return false;
        } finally {
          state.localAnalystSaving = false;
          renderLocalAnalyst();
        }
      }

      function selectAnalystFolder(folderId, focus = false) {
        if (!analystFolder(folderId)) return;
        state.analystSelectedFolderId = folderId;
        state.analystSelectedFileId = null;
        state.analystFolderDraftId = null;
        state.analystFolderDirty = false;
        state.analystDeleteFolderId = null;
        renderLocalAnalyst();
        if (focus) analystElements.tree.querySelector(`[data-folder-id="${folderId}"]`)?.focus({preventScroll: true});
      }

      function selectAnalystFile(fileId, focus = false) {
        const file = analystFile(fileId);
        if (!file) return;
        state.analystSelectedFileId = fileId;
        state.analystSelectedFolderId = file.folder_id;
        state.analystExpandedFolderIds.add(file.folder_id);
        state.analystDraftDirty = false;
        state.analystDeleteFileId = null;
        renderLocalAnalyst();
        if (focus) analystElements.tree.querySelector(`[data-file-id="${fileId}"]`)?.focus({preventScroll: true});
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
        rows[next].click(); rows[next].focus({preventScroll: true});
      }

      function renderAnalystTree() {
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
            selectAnalystFolder(folder.id);
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
            fileRow.addEventListener('click', () => selectAnalystFile(file.id));
            fileRow.addEventListener('keydown', moveAnalystTreeSelection);
            nodes.push(fileRow);
          });
        };
        const root = analystFolder(1);
        if (root) appendFolder(root, 0);
        analystElements.tree.replaceChildren(...nodes);
      }

      function analystFolderOptions(selectedId, excludedIds = new Set()) {
        return state.localAnalyst.folders.filter(folder => !excludedIds.has(folder.id))
          .sort((left, right) => analystFolderLineage(left.id).map(item => item.name).join('/').localeCompare(
            analystFolderLineage(right.id).map(item => item.name).join('/')))
          .map(folder => {
            const option = document.createElement('option'); option.value = String(folder.id);
            option.textContent = analystFolderLineage(folder.id).map(item => item.name).join(' / ');
            option.selected = folder.id === selectedId;
            return option;
          });
      }

      function renderAnalystFolderForm() {
        const folder = analystFolder();
        if (!folder) return;
        const draftParentId = state.analystFolderDirty ? Number(analystElements.folderParent.value) : folder.parent_id ?? 1;
        if (state.analystFolderDraftId !== folder.id || !state.analystFolderDirty) {
          state.analystFolderDraftId = folder.id;
          analystElements.folderName.value = folder.name;
        }
        const excluded = folder.id === 1 ? new Set(state.localAnalyst.folders.map(item => item.id))
          : new Set([folder.id, ...analystDescendantIds(folder.id)]);
        analystElements.folderParent.replaceChildren(...analystFolderOptions(draftParentId, excluded));
        if (folder.id !== 1) analystElements.folderParent.value = String(draftParentId);
        analystElements.folderName.disabled = folder.id === 1 || state.localAnalystSaving;
        analystElements.folderParent.disabled = folder.id === 1 || state.localAnalystSaving;
        analystElements.saveFolder.disabled = folder.id === 1 || state.localAnalystSaving || !state.analystFolderDirty;
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
        analystElements.save.disabled = state.localAnalystSaving || !state.analystDraftDirty;
        analystElements.revert.disabled = state.localAnalystSaving || !state.analystDraftDirty;
        analystElements.deleteFile.disabled = state.localAnalystSaving;
        analystElements.deleteFile.textContent = state.analystDeleteFileId === file.id ? 'Confirm delete' : 'Delete';
        analystElements.draftStatus.dataset.kind = state.analystDraftDirty ? 'dirty' : 'saved';
        analystElements.draftStatus.textContent = state.analystDraftDirty
          ? 'Unsaved changes cannot run. Save or revert this draft.'
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
        const runnable = file?.kind === 'analyst-script' && !state.analystDraftDirty && runnerAvailable && !runnerBusy &&
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
          textElement('div', 'analyst-empty', state.analystHistoryEvictions
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
        return decoderHasExactKeys(value, ['protocol_version', 'ok', 'algorithm', 'signature_status', 'header_json',
          'payload_json', 'token_bytes', 'signature_bytes', 'error', 'duration_us']) && value.protocol_version === 1 &&
          typeof value.ok === 'boolean' && typeof value.algorithm === 'string' && value.algorithm.length <= 128 &&
          ['not_checked', 'verified', 'invalid', 'unsigned', 'unsupported'].includes(value.signature_status) &&
          typeof value.header_json === 'string' && utf8ByteLength(value.header_json) <= 65536 &&
          typeof value.payload_json === 'string' && utf8ByteLength(value.payload_json) <= 65536 &&
          isSafeIntegerInRange(value.token_bytes, 0, 65536) && isSafeIntegerInRange(value.signature_bytes, 0, 65536) &&
          (value.error === null || (typeof value.error === 'string' && utf8ByteLength(value.error) <= 4096)) &&
          isSafeIntegerInRange(value.duration_us, 1, Number.MAX_SAFE_INTEGER);
      }

      function isJwtCreation(value) {
        return decoderHasExactKeys(value, ['protocol_version', 'ok', 'token', 'error', 'duration_us']) &&
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
        renderDecoder();
        renderJwt();
      }

      function setToolsTab(tab) {
        const next = tab === 'jwt' ? 'jwt' : 'decoder';
        if (next !== state.toolsTab && !state.decoderPending && !state.jwtPending && state.decoderEngine.available) {
          setToolsNotice('ready', next === 'jwt'
            ? 'Paste a JWT to inspect its claims. Verify its signature separately before trusting them.'
            : 'Enter a value, choose a transformation, then inspect the result or add another step.');
        }
        state.toolsTab = next;
        renderTools();
      }

      function resetDecoderChain(message = 'Decoder chain cleared. Input was preserved.') {
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
        resetDecoderChain('Selected request value copied into a fresh decoder chain.');
        toolsElements.inputEncoding.value = 'text';
        toolsElements.input.value = value;
        showScreen('tools', elements.requestDecoderPivot);
        setToolsTab('decoder');
        requestAnimationFrame(() => toolsElements.input.focus({preventScroll: true}));
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
        const folder = analystFolder();
        if (!folder || folder.id === 1) return;
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
        const file = analystFile();
        if (!file) return false;
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
          if (state.analystDraftDirty) throw new TypeError('Save or revert the script before running it.');
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

      function liveSources() {
        return (state.debuggerSession?.scripts ?? []).map(script => {
          const cached = state.liveScriptContent.get(script.script_id) ?? {};
          return {
            ...script,
            ...cached,
            source_type: 'script',
            key: `script:${script.script_id}`,
            kind: script.language === 'WebAssembly' ? 'wasm' : 'javascript',
            mime_type: script.language === 'WebAssembly' ? 'application/wasm' : 'text/javascript',
            byte_size: script.length,
            sha256: script.hash,
            sensitive: false
          };
        });
      }

      function capturedSources() {
        return state.artifacts.map(artifact => ({ ...artifact, source_type: 'artifact', key: `artifact:${artifact.artifact_id}` }));
      }

      function sourceOrigin(source) {
        try { return source.url ? new URL(source.url).origin : '(anonymous)'; } catch { return '(generated)'; }
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

      function selectedSource() {
        if (state.selectedScriptId !== null) {
          return liveSources().find(source => source.script_id === state.selectedScriptId) ?? null;
        }
        return capturedSources().find(source => source.artifact_id === state.selectedArtifactId) ?? null;
      }

      function sourceTreeRow(label, glyph, depth, source = null, meta = '') {
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
              sourceName(source),
              sourceIcon(source),
              Math.max(2, parts.length + 1),
              source,
              source.source_type === 'script' ? 'live' : source.origin === 'sample' ? 'sample' : 'evidence'
            ));
          });
        });
        elements.sourceTree.replaceChildren(...rows);
      }

      function renderSourceTabs() {
        const sources = [
          ...state.openScriptIds.map(id => liveSources().find(source => source.script_id === id)),
          ...state.openArtifactIds.map(id => capturedSources().find(source => source.artifact_id === id))
        ].filter(Boolean);
        if (sources.length === 0) {
          const placeholder = document.createElement('span');
          placeholder.className = 'source-tab-placeholder';
          placeholder.textContent = 'No file open';
          elements.sourceEditorTabs.replaceChildren(placeholder);
          return;
        }
        const tabs = sources.map(source => {
          const tab = document.createElement('button');
          tab.type = 'button';
          tab.className = 'source-editor-tab';
          tab.setAttribute('role', 'tab');
          const selected = source.source_type === 'script'
            ? source.script_id === state.selectedScriptId
            : source.artifact_id === state.selectedArtifactId && state.selectedScriptId === null;
          tab.setAttribute('aria-selected', String(selected));
          tab.tabIndex = selected ? 0 : -1;
          const icon = document.createElement('span');
          icon.className = `source-file-icon ${source.kind}`;
          icon.textContent = sourceIcon(source);
          const name = document.createElement('span');
          name.textContent = sourceName(source);
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
          return tab;
        });
        elements.sourceEditorTabs.replaceChildren(...tabs);
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
              ['Runtime', 'live target'], ['Script', source.script_id],
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

      function applySourceSearch() {
        const needle = elements.sourceSearch.value.toLowerCase();
        let matches = 0;
        let first = null;
        elements.sourceCode.querySelectorAll('.source-line').forEach(line => {
          const matched = Boolean(needle) && line.querySelector('.source-text')?.textContent.toLowerCase().includes(needle);
          line.classList.toggle('search-match', matched);
          if (matched) { matches += 1; first ??= line; }
        });
        if (needle) {
          elements.sourcePosition.textContent = `${matches} ${matches === 1 ? 'match' : 'matches'}`;
          first?.scrollIntoView({ block: 'center' });
        } else {
          elements.sourcePosition.textContent = 'Line 1, Column 1';
        }
      }

      function sourceRuntimeLine(source, sourceLine) {
        return source?.source_type === 'script' ? source.start_line + sourceLine : sourceLine;
      }

      function sourceRuntimeColumn(source, sourceLine) {
        return source?.source_type === 'script' && sourceLine === 0 ? source.start_column : 0;
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

      function renderSourceContent(source) {
        if (!source) {
          elements.sourceLanguage.textContent = 'Plain text';
          elements.sourceCode.hidden = true;
          elements.sourceCodeEmpty.hidden = false;
          elements.sourceCodeEmpty.textContent = 'Select a JavaScript file, WASM module, source map, or approved response body.';
          return;
        }
        if (source.loading) {
          elements.sourceLanguage.textContent = 'Detecting syntax';
          elements.sourceCode.hidden = true;
          elements.sourceCodeEmpty.hidden = false;
          elements.sourceCodeEmpty.textContent = source.source_type === 'script' ? 'Loading live script source…' : 'Loading immutable artifact bytes…';
          return;
        }
        if (source.loadError) {
          elements.sourceLanguage.textContent = 'Unavailable';
          elements.sourceCode.hidden = true;
          elements.sourceCodeEmpty.hidden = false;
          elements.sourceCodeEmpty.textContent = source.loadError;
          return;
        }
        const original = source.content ?? '';
        const content = state.sourcePretty && source.kind === 'javascript'
          ? formatJavaScript(original)
          : original;
        const lines = content.split('\n');
        const renderedLines = lines.slice(0, 20000);
        const breakpointsByLine = breakpointLinesForSource(source);
        const tokenizer = createSourceTokenizer(source);
        const nodes = renderedLines.map((line, index) => {
          const runtimeLine = sourceRuntimeLine(source, index);
          const row = document.createElement('span');
          row.className = 'source-line';
          row.dataset.line = String(runtimeLine + 1);
          const breakpoint = breakpointsByLine.get(runtimeLine) ?? null;
          if (breakpoint) row.classList.add('breakpoint');
          if (source.source_type === 'script' && state.pendingSourceLine?.scriptId === source.script_id && state.pendingSourceLine.line === runtimeLine) {
            row.classList.add('current');
          }
          if (source.source_type === 'script' && state.sourceCursor?.scriptId === source.script_id && state.sourceCursor.line === runtimeLine) {
            row.classList.add('cursor');
          }
          const gutter = document.createElement('button');
          gutter.type = 'button';
          gutter.className = 'source-gutter';
          gutter.textContent = String(runtimeLine + 1);
          gutter.disabled = source.source_type !== 'script' || state.sourcePretty || !['running', 'paused'].includes(state.debuggerSession?.state) || memoryOriginTraceActive();
          gutter.title = state.sourcePretty ? 'Show original source to edit breakpoints' : '';
          gutter.setAttribute('aria-label', `${breakpoint ? 'Remove' : 'Add'} breakpoint on line ${runtimeLine + 1}`);
          gutter.addEventListener('click', event => {
            event.stopPropagation();
            toggleLineBreakpoint(source, runtimeLine, sourceRuntimeColumn(source, index), breakpointAt(source, runtimeLine));
          });
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
        elements.sourceLanguage.textContent = `${sourceSyntaxLabel(tokenizer.language)}${tokenizer.truncated ? ' · color limit reached' : ''}`;
        elements.sourceCode.hidden = false;
        elements.sourceCodeEmpty.hidden = true;
        elements.sourceCodeWrap.scrollTop = 0;
        applySourceSearch();
        elements.sourceCode.querySelector('.source-line.current')?.scrollIntoView({ block: 'center' });
      }

      function updateSourceDecorations() {
        const source = selectedSource();
        if (source?.source_type !== 'script' || elements.sourceCode.hidden) return;
        const breakpointsByLine = breakpointLinesForSource(source);
        const enabled = !state.sourcePretty && ['running', 'paused'].includes(state.debuggerSession?.state) && !memoryOriginTraceActive();
        elements.sourceCode.querySelectorAll('.source-line[data-line]').forEach(row => {
          const runtimeLine = Number(row.dataset.line) - 1;
          const breakpoint = breakpointsByLine.get(runtimeLine) ?? null;
          const current = state.pendingSourceLine?.scriptId === source.script_id && state.pendingSourceLine.line === runtimeLine;
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
        document.querySelectorAll('[data-source-collection]').forEach(tab => {
          const selected = tab.dataset.sourceCollection === state.sourceCollection;
          tab.setAttribute('aria-selected', String(selected));
          tab.tabIndex = selected ? 0 : -1;
        });
        elements.sourceTree.setAttribute('aria-labelledby', `source-tab-${state.sourceCollection}`);
        renderSourceTree();
        renderSourceTabs();
        renderSourceFacts(source);
        elements.sourceLocation.textContent = source?.url || (source ? sourceName(source) : 'Select a source');
        elements.sourceSize.textContent = source ? formatByteSize(source.byte_size) : '0 bytes';
        elements.sourceHash.textContent = source?.sha256 ? `${source.source_type === 'script' ? 'hash' : 'sha256'} ${source.sha256}` : '';
        elements.sourceViewKind.textContent = state.sourcePretty
          ? 'Readable derived view'
          : source?.source_type === 'script' ? 'Live runtime source' : 'Original evidence';
        elements.sourcePretty.disabled = source?.kind !== 'javascript' || !source.content;
        elements.sourcePretty.setAttribute('aria-pressed', String(state.sourcePretty));
        elements.sourcePretty.title = state.sourcePretty ? 'Show original evidence' : 'Show readable representation';
        const hooks = runtimeHooksState();
        elements.sourceHookPivot.disabled = source?.source_type !== 'script' || state.sourcePretty ||
          !hooks?.isolated || hooks.target_id !== state.debuggerSession?.target?.id ||
          ['arming', 'armed', 'handling', 'stopping'].includes(hooks?.state);
        renderSourceContent(source);
      }

      async function loadArtifactContent(artifact) {
        if (artifact.content !== undefined || artifact.loading) return;
        artifact.loading = true;
        artifact.loadError = null;
        renderSources();
        try {
          const response = await fetch(`/api/artifacts/${encodeURIComponent(artifact.artifact_id)}/content?limit=2097152`, { cache: 'no-store' });
          if (!response.ok) throw new Error(`Artifact store returned ${response.status}`);
          const buffer = await response.arrayBuffer();
          artifact.content = artifact.kind === 'wasm'
            ? formatWasmHex(buffer)
            : new TextDecoder('utf-8', { fatal: false }).decode(buffer);
          artifact.contentTruncated = response.headers.get('X-Artifact-Truncated') === '1';
          if (artifact.contentTruncated) artifact.content += '\n\n[Viewer preview limited to the first 2 MB]';
        } catch (error) {
          artifact.loadError = `Artifact bytes are unavailable: ${error.message}`;
        } finally {
          artifact.loading = false;
          renderSources();
        }
      }

      function selectArtifact(artifactId) {
        const artifact = state.artifacts.find(candidate => candidate.artifact_id === artifactId);
        if (!artifact) return;
        state.sourceCollection = 'captured';
        state.selectedScriptId = null;
        state.selectedArtifactId = artifactId;
        state.pendingSourceLine = null;
        state.sourcePretty = false;
        if (!state.openArtifactIds.includes(artifactId)) state.openArtifactIds.push(artifactId);
        renderSources();
        loadArtifactContent(artifact);
      }

      function selectScript(scriptId, line = null) {
        const source = liveSources().find(candidate => candidate.script_id === scriptId);
        if (!source) return;
        state.sourceCollection = 'page';
        state.selectedScriptId = scriptId;
        state.selectedArtifactId = null;
        state.pendingSourceLine = line === null ? null : { scriptId, line };
        state.sourcePretty = false;
        if (!state.openScriptIds.includes(scriptId)) state.openScriptIds.push(scriptId);
        renderSources();
        loadScriptContent(source);
      }

      function closeSource(source) {
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
        state.sourcePretty = false;
        renderSources();
      }

      async function loadScriptContent(source) {
        const existing = state.liveScriptContent.get(source.script_id);
        if (existing?.content !== undefined || existing?.loading) return;
        state.liveScriptContent.set(source.script_id, { loading: true, loadError: null });
        renderSources();
        try {
          const response = await fetch(`/api/debugger/source?script_id=${encodeURIComponent(source.script_id)}`, { cache: 'no-store' });
          const body = await response.json();
          if (!response.ok) throw new Error(body.error || `Debugger returned ${response.status}`);
          if (!isPlainObject(body) || body.protocol_version !== 1 || body.script_id !== source.script_id ||
              typeof body.source !== 'string' || typeof body.truncated !== 'boolean') throw new TypeError('Malformed debugger source response');
          const content = source.kind === 'wasm'
            ? body.source
            : body.source + (body.truncated ? '\n\n[Live source preview limited to the first 2 MB]' : '');
          state.liveScriptContent.set(source.script_id, { loading: false, loadError: null, content, contentTruncated: body.truncated });
        } catch (error) {
          state.liveScriptContent.set(source.script_id, { loading: false, loadError: `Live source is unavailable: ${error.message}` });
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
        const matches = [...liveSources(), ...capturedSources()].filter(source =>
          !needle || `${sourceName(source)} ${source.url}`.toLowerCase().includes(needle)
        );
        const rows = matches.map(source => {
          const row = document.createElement('button');
          row.type = 'button';
          row.className = 'quick-open-row';
          const name = document.createElement('span'); name.textContent = sourceName(source);
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
        summaryHead.append(summaryTitle, textElement('span', 'memory-readonly', 'Exact diff'));
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
          textElement('p', '', 'Exact dominators over reachable non-weak V8 heap edges')
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
          textElement('p', '', debuggerLocationText(result.location, result.location.url))
        );
        head.append(title, textElement('span', 'memory-readonly', result.is_first_match ? 'First appearance' : result.matched ? 'Present' : 'Not present'));
        if (result.location.script_id && state.debuggerSession?.scripts.some(script => script.script_id === result.location.script_id)) {
          const source = document.createElement('button'); source.type = 'button'; source.className = 'secondary-button'; source.textContent = 'Open source';
          source.addEventListener('click', () => {
            showScreen('sources');
            revealDebuggerLocation(result.location);
          });
          head.append(source);
        }
        const facts = document.createElement('div'); facts.className = 'memory-properties';
        facts.append(
          memoryFactRow('trace step', result.is_first_match ? 'origin' : 'context', `${result.step} of ${trace?.step_count ?? result.step}`),
          memoryFactRow('heap match', result.matched ? 'found' : 'absent', result.match ? `${result.match.type} · node ${result.match.id}` : 'No matching node in this snapshot'),
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
            : 'The value had not appeared at this function boundary')
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
          const referencesCard = document.createElement('article'); referencesCard.className = 'memory-detail-card';
          const referencesHead = document.createElement('header'); referencesHead.className = 'memory-detail-head';
          const referencesTitle = document.createElement('div');
          referencesTitle.append(
            textElement('h2', '', 'Incoming references'),
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
        head.append(title, textElement('span', 'memory-readonly', 'Read-only preview'));
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
        const preserveDisconnectedOrigin = state.memoryMode === 'origin' && targetId === null &&
          state.memorySearchMeta?.protocol_version === 1 && state.memorySearchMeta?.trace_id > 0;
        if (state.memoryTargetId !== null && state.memoryTargetId !== targetId && !preserveDisconnectedOrigin) {
          state.memoryResults = [];
          state.selectedMemoryResultId = null;
          state.memorySearchMeta = null;
          state.memorySearchMessage = null;
          state.memoryDiffBaseline = null;
          state.memoryTargetId = null;
          state.memorySearchStatus = attached ? 'idle' : 'offline';
        } else if (!attached && state.memorySearchStatus !== 'searching' && !preserveDisconnectedOrigin) {
          state.memorySearchStatus = 'offline';
        } else if (attached && state.memorySearchStatus === 'offline') {
          state.memorySearchStatus = 'idle';
        }
        const snapshotMode = state.memoryMode === 'snapshot';
        const diffMode = state.memoryMode === 'diff';
        const originMode = state.memoryMode === 'origin';
        const liveMode = state.memoryMode === 'live';
        const originTrace = state.debuggerSession?.memory_origin_trace ?? null;
        const originActive = originTrace && ['armed', 'capturing', 'stepping', 'stopping'].includes(originTrace.state);
        elements.memorySearchForm.dataset.mode = state.memoryMode;
        elements.memoryModeButtons.forEach(button => {
          button.setAttribute('aria-pressed', String(button.dataset.memoryMode === state.memoryMode));
          button.disabled = state.memorySearchPending;
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
        controls.forEach(control => { control.disabled = !attached || state.memorySearchPending; });
        elements.memorySearchButton.disabled = !attached || state.memorySearchPending;
        elements.memorySearchButton.setAttribute('aria-busy', String(state.memorySearchPending));
        elements.memorySearchButton.textContent = state.memorySearchPending
          ? originMode ? originTrace?.state === 'armed' ? 'Armed for page click...' : 'Tracing function boundaries...' : snapshotMode ? 'Capturing and indexing...' : 'Searching...'
          : originMode ? 'Arm origin trace' : snapshotMode ? 'Capture and search snapshot' : 'Search live objects';
        elements.memoryOriginStop.disabled = !originActive || state.debuggerActionPending;
        elements.memoryOriginReset.disabled = Boolean(originActive) || !originTrace || originTrace.state === 'idle' || state.debuggerActionPending;
        const baseline = state.memoryDiffBaseline;
        elements.memoryBaselineTitle.textContent = baseline ? 'Baseline ready' : 'Not captured';
        elements.memoryBaselineMeta.textContent = baseline
          ? `${formatByteSize(baseline.file_bytes)} · captured ${new Date(baseline.captured_at_ms).toLocaleTimeString()}`
          : 'Capture the target before the activity you want to measure.';
        elements.memoryCaptureBaseline.disabled = !attached || state.memorySearchPending;
        elements.memoryClearBaseline.disabled = !baseline || state.memorySearchPending;
        elements.memoryCompareSnapshot.disabled = !attached || !baseline || state.memorySearchPending;
        elements.memoryCaptureBaseline.textContent = state.memorySearchPending && diffMode && !baseline
          ? 'Capturing baseline...' : baseline ? 'Replace baseline' : 'Capture baseline';
        elements.memoryCompareSnapshot.textContent = state.memorySearchPending && diffMode && baseline
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
        elements.memoryNotice.textContent = messages[state.memorySearchStatus] ?? messages.idle;
        elements.memoryResultLabel.textContent = diffMode ? 'Changed groups' : originMode ? 'Trace steps' : 'Matches';
        elements.memoryResultCount.textContent = String(state.memoryResults.length);
        elements.memoryResults.setAttribute('aria-label', diffMode ? 'Heap growth groups' : originMode ? 'Memory origin trace steps' : snapshotMode ? 'Heap snapshot matches' : 'Live object matches');

        if (state.memoryResults.length === 0) {
          const empty = textElement('div', 'memory-empty', state.memorySearchStatus === 'empty'
            ? originMode
              ? 'The bounded trace contains no retained steps for this result.'
              : snapshotMode
              ? 'No heap nodes matched this value and reference scope. Adjust the value or scope.'
              : diffMode ? 'The compared heaps have no reported memory changes.'
                : 'No objects matched. Broaden one criterion or lower the similarity threshold.'
            : state.memorySearchStatus === 'error'
              ? 'The last search did not replace any retained results.'
              : diffMode ? 'Capture a baseline, use the page, then compare a second snapshot to see what grew.' : originMode ? 'Enter the value to trace, arm the trace, then perform the page action that creates it.' : snapshotMode ? 'Enter a value, then capture a snapshot to find matching objects and references.' : 'Start with a property name or value, then choose Search live objects.');
          elements.memoryResults.removeAttribute('role');
          elements.memoryResults.replaceChildren(empty);
          renderMemoryDetail();
          return;
        }
        elements.memoryResults.setAttribute('role', 'listbox');
        if (!state.memoryResults.some(result => result.id === state.selectedMemoryResultId)) {
          state.selectedMemoryResultId = state.memoryResults[0].id;
        }
        elements.memoryResults.replaceChildren(...state.memoryResults.map(result => {
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
            ? `step ${result.step} · ${debuggerLocationText(result.location, result.location.url)} · ${result.analyzed_nodes.toLocaleString()} nodes in ${result.duration_ms} ms`
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
        renderMemoryDetail();
      }

      function applyMemoryOriginTrace(trace) {
        if (!isMemoryOriginTrace(trace)) return false;
        const active = ['armed', 'capturing', 'stepping', 'stopping'].includes(trace.state);
        if (active && state.memoryMode !== 'origin') state.memoryMode = 'origin';
        if (state.memoryMode !== 'origin') return true;
        const previousFirstMatch = state.memorySearchMeta?.first_match_step ?? null;
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
        state.memorySearchPending = true;
        state.memorySearchStatus = 'searching';
        state.memorySearchMessage = 'Arming a bounded click-driven temporal trace.';
        state.memoryResults = [];
        state.selectedMemoryResultId = null;
        renderMemory();
        const body = await debuggerAction({
          action: 'start_memory_origin_trace', query,
          scope: elements.memoryReferenceScope.value,
          case_sensitive: false,
          before_steps: beforeSteps,
          after_steps: afterSteps
        });
        if (!isPlainObject(body) || body.ok !== true || !isMemoryOriginTrace(body.trace)) {
          state.memorySearchPending = false;
          state.memorySearchStatus = 'error';
          state.memorySearchMessage = state.debuggerError || 'The debugger returned malformed Memory Origin Trace state.';
          renderMemory();
          return;
        }
        applyMemoryOriginTrace(body.trace);
        renderMemory();
      }

      async function stopMemoryOriginTrace() {
        if (!state.memorySearchPending) return;
        const body = await debuggerAction({ action: 'stop_memory_origin_trace' });
        if (!isPlainObject(body) || body.ok !== true) {
          state.memorySearchStatus = 'error';
          state.memorySearchMessage = state.debuggerError || 'Memory Origin Trace could not be stopped.';
          renderMemory();
        }
      }

      async function clearMemoryOriginTrace() {
        if (state.memorySearchPending) return;
        const body = await debuggerAction({ action: 'clear_memory_origin_trace' });
        if (!isPlainObject(body) || body.ok !== true) {
          state.memorySearchStatus = 'error';
          state.memorySearchMessage = state.debuggerError || 'Memory Origin Trace could not be cleared.';
          renderMemory();
          return;
        }
        state.memoryResults = [];
        state.selectedMemoryResultId = null;
        state.memorySearchMeta = null;
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
        state.memorySearchPending = true;
        state.memorySearchStatus = 'searching';
        state.memorySearchMessage = null;
        renderMemory();
        const body = await debuggerAction(request);
        state.memorySearchPending = false;
        if (!isLiveObjectSearchResponse(body)) {
          state.memorySearchStatus = 'error';
          state.memorySearchMessage = state.debuggerError || 'The debugger returned malformed live object results.';
          renderMemory();
          return;
        }
        const search = body.search;
        state.memoryResults = search.results;
        state.selectedMemoryResultId = search.results[0]?.id ?? null;
        state.memorySearchMeta = search;
        state.memoryTargetId = state.debuggerSession?.target?.id ?? null;
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
        const query = elements.memoryValueQuery.value.trim();
        if (!query) {
          state.memorySearchStatus = 'error';
          state.memorySearchMessage = 'Enter one snapshot value or node name.';
          renderMemory();
          elements.memoryValueQuery.focus();
          return;
        }
        state.memorySearchPending = true;
        state.memorySearchStatus = 'searching';
        state.memorySearchMessage = null;
        renderMemory();
        const body = await debuggerAction({
          action: 'search_heap_snapshot', query, case_sensitive: false,
          scope: elements.memoryReferenceScope.value
        });
        state.memorySearchPending = false;
        if (!isHeapSnapshotSearchResponse(body)) {
          state.memorySearchStatus = 'error';
          state.memorySearchMessage = state.debuggerError || 'The native snapshot index returned malformed results.';
          renderMemory();
          return;
        }
        const snapshot = body.snapshot;
        state.memoryResults = snapshot.results;
        state.selectedMemoryResultId = snapshot.results[0]?.id ?? null;
        state.memorySearchMeta = snapshot;
        state.memoryTargetId = state.debuggerSession?.target?.id ?? null;
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
        state.memorySearchPending = true;
        state.memorySearchStatus = 'searching';
        state.memorySearchMessage = 'Capturing the comparison baseline. The target may pause briefly.';
        renderMemory();
        const body = await debuggerAction({ action: 'capture_heap_diff_baseline' });
        state.memorySearchPending = false;
        if (!isHeapDiffBaselineResponse(body)) {
          state.memorySearchStatus = 'error';
          state.memorySearchMessage = state.debuggerError || 'The debugger returned malformed baseline metadata.';
          renderMemory();
          return;
        }
        state.memoryDiffBaseline = body.baseline;
        state.memoryResults = [];
        state.selectedMemoryResultId = null;
        state.memorySearchMeta = null;
        state.memoryTargetId = state.debuggerSession?.target?.id ?? null;
        state.memorySearchStatus = 'ready';
        state.memorySearchMessage = `${formatByteSize(body.baseline.file_bytes)} baseline captured. Run the activity you want to measure, then compare.`;
        renderMemory();
      }

      async function clearHeapDiffBaseline() {
        if (state.memorySearchPending || !state.memoryDiffBaseline) return;
        state.memorySearchPending = true;
        renderMemory();
        const body = await debuggerAction({ action: 'clear_heap_diff_baseline' });
        state.memorySearchPending = false;
        if (!isPlainObject(body) || body.ok !== true) {
          state.memorySearchStatus = 'error';
          state.memorySearchMessage = state.debuggerError || 'The heap comparison baseline could not be reset.';
          renderMemory();
          return;
        }
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
        if (!state.memoryDiffBaseline) {
          state.memorySearchStatus = 'error';
          state.memorySearchMessage = 'Capture a baseline before comparing the heap.';
          renderMemory();
          elements.memoryCaptureBaseline.focus();
          return;
        }
        state.memorySearchPending = true;
        state.memorySearchStatus = 'searching';
        state.memorySearchMessage = 'Capturing the current heap, then computing exact dominators and retained-size changes.';
        renderMemory();
        const body = await debuggerAction({ action: 'compare_heap_diff' });
        state.memorySearchPending = false;
        if (!isHeapSnapshotDiffResponse(body)) {
          state.memorySearchStatus = 'error';
          state.memorySearchMessage = state.debuggerError || 'The native heap comparison returned malformed results.';
          renderMemory();
          return;
        }
        const diff = body.diff;
        state.memoryResults = diff.groups.map((group, index) => ({ ...group, id: `heap-diff-${index}` }));
        state.selectedMemoryResultId = state.memoryResults[0]?.id ?? null;
        state.memorySearchMeta = diff;
        state.memoryTargetId = state.debuggerSession?.target?.id ?? null;
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
        if (!['live', 'snapshot', 'diff', 'origin'].includes(mode) || state.memorySearchPending || mode === state.memoryMode) return;
        state.memoryMode = mode;
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
        const open = state.sourceSidebarOpen ?? attached;
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
          unavailable: 'Offline', waiting: 'Waiting', connecting: 'Attaching', running: 'Running', paused: 'Paused'
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

      async function debuggerAction(request) {
        const parallelControl = ['cancel_repeater_request', 'cancel_automation_recipe'].includes(request.action);
        if ((state.debuggerActionPending && !parallelControl) || (memoryOriginTraceActive() && request.action !== 'stop_memory_origin_trace')) return null;
        if (!parallelControl) state.debuggerActionPending = true;
        state.debuggerError = null;
        renderDebugger();
        let result = null;
        try {
          const response = await fetch('/api/debugger/actions', {
            method: 'POST', cache: 'no-store', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(request)
          });
          const body = await response.json();
          if (!response.ok) throw new Error(body.error || `Debugger returned ${response.status}`);
          result = body;
        } catch (error) {
          state.debuggerError = error.message;
        } finally {
          if (!parallelControl) state.debuggerActionPending = false;
          renderDebugger();
          if (!state.debuggerRefreshing) scheduleDebuggerRefresh(0);
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
        try {
          const headers = !force && state.debuggerEtag ? { 'If-None-Match': state.debuggerEtag } : {};
          const wait = !force && state.debuggerEtag && state.debuggerSession?.state !== 'unavailable' ? 25000 : 0;
          const response = await fetch(`/api/debugger?wait_ms=${wait}`, { cache: 'no-store', headers });
          if (response.status === 304) return;
          if (!response.ok) throw new Error(`Debugger returned ${response.status}`);
          const body = await response.json();
          if (!isDebuggerResponse(body)) throw new TypeError('Malformed debugger response');
          const previousSession = state.debuggerSession;
          const previousState = state.debuggerSession?.state;
          const previousFrame = state.debuggerSession?.paused?.call_frames?.[0]?.id;
          const previousCatalog = debuggerScriptCatalogSignature(previousSession);
          const previousBreakpoints = JSON.stringify(previousSession?.breakpoints ?? []);
          const previousOpenScripts = state.openScriptIds.join('\u0000');
          const previousPendingLine = state.pendingSourceLine ? `${state.pendingSourceLine.scriptId}:${state.pendingSourceLine.line}` : '';
          state.debuggerSession = body;
          state.memoryDiffBaseline = body.heap_diff_baseline;
          applyMemoryOriginTrace(body.memory_origin_trace);
          state.debuggerEtag = response.headers.get('ETag');
          state.debuggerError = null;
          state.openScriptIds = state.openScriptIds.filter(id => body.scripts.some(script => script.script_id === id));
          if (state.editingBreakpointId !== null && !body.breakpoints.some(breakpoint => breakpoint.id === state.editingBreakpointId)) {
            state.editingBreakpointId = null;
          }
          if (state.selectedScriptId !== null && !body.scripts.some(script => script.script_id === state.selectedScriptId)) {
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
          renderMemory();
          if (!document.querySelector('#screen-experiments').hidden) renderExperiment();
          if (!document.querySelector('#screen-api-collection').hidden) renderApiCollection();
          const sourcesVisible = !document.querySelector('#screen-sources').hidden;
          if (sourcesVisible && !sourceRendered) {
            const catalogChanged = previousCatalog !== debuggerScriptCatalogSignature(body);
            const openScriptsChanged = previousOpenScripts !== state.openScriptIds.join('\u0000');
            const pendingLine = state.pendingSourceLine ? `${state.pendingSourceLine.scriptId}:${state.pendingSourceLine.line}` : '';
            if (openScriptsChanged || (state.selectedScriptId === null && previousSession?.scripts?.length > 0 && body.scripts.length === 0)) {
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
          renderDebugger();
          renderMemory();
          if (!document.querySelector('#screen-experiments').hidden) renderExperiment();
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
          if (body.artifacts.length === 0) return;
          const existing = new Map(state.artifacts.map(artifact => [artifact.artifact_id, artifact]));
          state.artifacts = body.artifacts.map(artifact => {
            const cached = existing.get(artifact.artifact_id);
            return {
              ...artifact,
              origin: 'live',
              content: cached?.content,
              loading: cached?.loading,
              loadError: cached?.loadError,
              contentTruncated: cached?.contentTruncated
            };
          });
          state.openArtifactIds = state.openArtifactIds.filter(id => state.artifacts.some(artifact => artifact.artifact_id === id));
          if (!state.artifacts.some(artifact => artifact.artifact_id === state.selectedArtifactId)) {
            state.selectedArtifactId = state.artifacts[0].artifact_id;
            state.openArtifactIds = [state.selectedArtifactId];
          }
          renderSources();
          const selected = state.artifacts.find(artifact => artifact.artifact_id === state.selectedArtifactId);
          if (selected) loadArtifactContent(selected);
        } catch (error) {
          if (state.artifacts.every(artifact => artifact.origin === 'sample')) return;
          elements.sourceCodeEmpty.textContent = `Artifact catalog unavailable: ${error.message}`;
        } finally {
          state.artifactRefreshing = false;
        }
      }

      function showScreen(name, trigger = null) {
        const screenName = name === 'backtraces' ? 'backtrace' : name;
        document.querySelectorAll('.screen').forEach(screen => { screen.hidden = screen.id !== `screen-${screenName}`; });
        document.querySelectorAll('.nav-button').forEach(button => {
          const active = button.dataset.screen === screenName || (button.dataset.screen === 'backtrace' && screenName === 'evidence');
          if (active) button.setAttribute('aria-current', 'page'); else button.removeAttribute('aria-current');
        });
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
          requestAnimationFrame(() => {
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
          const response = await fetch('/api/events?limit=500', { cache: 'no-store', headers });
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
          state.events = body.events;
          const vmModel = vmFindingsFromEvents(state.events);
          state.eventVmFindings = vmModel.findings;
          state.vmFindings = [...state.lastValidAnalysisFindings, ...state.eventVmFindings];
          state.malformedVmFindings = vmModel.malformedCount;
          state.requests = [...sampleRequests, ...requestsFromEvents(state.events)];
          let selectedRequest = state.requests.find(request => request.id === state.selectedRequestId);
          if (!selectedRequest) {
            state.selectedRequestId = '81';
            state.fieldTab = 'body';
            state.selectedField = fieldSets.body.find(field => field.traceable);
            selectedRequest = sampleRequests.find(request => request.id === state.selectedRequestId);
          }
          updateSelectionSummary(selectedRequest);
          const brokerConnected = body.broker_connected !== false;
          state.broker = brokerConnected ? 'connected' : 'unavailable';
          elements.capture.classList.toggle('offline', !brokerConnected);
          elements.capture.querySelector('span:last-child').textContent = brokerConnected ? 'Capturing' : 'Offline';
          elements.broker.classList.toggle('offline', !brokerConnected);
          elements.broker.textContent = brokerConnected ? 'broker connected' : 'broker unavailable';
          elements.updated.textContent = brokerConnected
            ? `updated ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}`
            : (state.events.length > 0 ? 'last valid evidence retained' : 'sample data remains available');
          const gapCount = countSequenceGaps(state.events);
          elements.gaps.textContent = `${gapCount} sequence ${gapCount === 1n ? 'gap' : 'gaps'}`;
          if (!brokerConnected) {
            setNetworkNotice('disconnected', `The local evidence broker is disconnected. ${state.events.length > 0 ? 'The last valid evidence remains visible.' : 'Sample requests remain available.'}`);
          } else if (gapCount > 0n) {
            setNetworkNotice('gap', `${gapCount} captured ${gapCount === 1n ? 'event is' : 'events are'} missing. Request rows may be incomplete.`);
          } else if (state.events.length === 0) {
            setNetworkNotice('empty', 'No live requests yet. Sample requests remain available for exploring the workspace.');
          } else {
            elements.networkNotice.hidden = true;
          }
          renderRequests();
          renderInspector();
          renderEvidence();
          await refreshRequestSignalProfile();
          await refreshArtifacts();
          await refreshVmAnalysis();
          renderVmLab();
        } catch (error) {
          state.broker = 'unavailable';
          elements.capture.classList.add('offline');
          elements.capture.querySelector('span:last-child').textContent = 'Offline';
          elements.broker.classList.add('offline');
          elements.broker.textContent = 'broker unavailable';
          const malformed = error instanceof TypeError && error.message === 'Malformed broker response';
          const retainedEvidence = state.events.length > 0;
          elements.updated.textContent = retainedEvidence ? 'last valid evidence retained' : 'sample data remains available';
          setNetworkNotice(
            malformed ? 'malformed' : 'disconnected',
            malformed
              ? `The broker returned malformed event data. ${retainedEvidence ? 'The last valid evidence remains visible.' : 'Sample requests remain available.'}`
              : `The local evidence broker is disconnected. ${retainedEvidence ? 'The last valid evidence remains visible.' : 'Sample requests remain available.'}`
          );
          renderRequests();
          renderEvidence();
          renderVmLab();
        } finally {
          state.refreshing = false;
        }
      }

      function useStandalonePreview() {
        state.broker = 'preview';
        elements.capture.classList.remove('offline');
        elements.capture.querySelector('span:last-child').textContent = 'Sample';
        elements.broker.classList.remove('offline');
        elements.broker.textContent = 'standalone preview';
        elements.updated.textContent = 'open the app for live evidence';
        elements.gaps.textContent = '0 sequence gaps';
        setNetworkNotice('empty', 'Standalone preview. Open the local app to capture live requests.');
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
        showScreen(button.dataset.screen, button);
        if (button.dataset.screen === 'backtrace' && originTraceSelection()) await refreshOriginTrace();
      }));
      document.querySelectorAll('.type-filter').forEach(button => button.addEventListener('click', () => {
        state.requestType = button.dataset.filter;
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
        if (state.inspectorTab === 'payload' && state.fieldTab === 'headers') {
          state.fieldTab = 'body';
          const request = state.requests.find(candidate => candidate.id === state.selectedRequestId);
          state.selectedField = request?.traceable ? fieldSets.body.find(field => field.traceable) : null;
        }
        renderInspector();
        renderEvidence();
        if (state.inspectorTab === 'signals') refreshRequestSignalProfile();
      }));
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
      elements.traceButton.addEventListener('click', async () => {
        showScreen('backtrace', elements.traceButton);
        await refreshOriginTrace();
      });
      elements.requestRepeaterPivot.addEventListener('click', () => {
        state.experimentMode = 'repeater';
        state.repeaterDraftDirty = false;
        state.repeaterPrefillKey = null;
        prefillRepeaterRequest(true);
        showScreen('experiments', elements.requestRepeaterPivot);
        requestAnimationFrame(() => elements.repeaterRequestUrl.focus({preventScroll: true}));
      });
      elements.requestCollectionPivot.addEventListener('click', async () => {
        await refreshApiCollection();
        const selected = state.requests.find(request => request.id === state.selectedRequestId);
        if (!selected) return;
        let requestUrl = selected.path;
        if (!/^https?:\/\//iu.test(requestUrl)) {
          requestUrl = `https://checkout.acme.test${requestUrl.startsWith('/') ? '' : '/'}${requestUrl}`;
        }
        try {
          const parsed = new URL(requestUrl);
          parsed.search = '';
          parsed.hash = '';
          const pathName = parsed.pathname.split('/').filter(Boolean).at(-1) || parsed.hostname;
          await createCollectionRequest({
            name: `${selected.method} ${pathName}`,
            url: parsed.toString(),
            method: /^[A-Z][A-Z0-9!#$%&'*+.^_`|~-]{0,31}$/u.test(selected.method) ? selected.method : 'GET'
          });
          showScreen('api-collection', elements.requestCollectionPivot);
        } catch {
          setCollectionNotice('error', 'The selected request URL cannot be imported safely.');
          showScreen('api-collection', elements.requestCollectionPivot);
        }
      });
      elements.requestDecoderPivot.addEventListener('click', useSelectedFieldInDecoder);
      elements.requestMemoryPivot.addEventListener('click', () => {
        const selected = state.selectedField;
        if (!selected) return;
        let value = String(selected.value ?? '').trim();
        if (selected.type === 'str' && value.startsWith('"') && value.endsWith('"')) {
          value = value.slice(1, -1);
        }
        value = value.replace(/(?:…|\.{3})+$/u, '').slice(0, 512);
        if (!value) return;
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
      elements.sourceSearch.addEventListener('input', applySourceSearch);
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
      elements.sourcePretty.addEventListener('click', () => {
        state.sourcePretty = !state.sourcePretty;
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
        if (!line) return;
        const source = selectedSource();
        if (source?.source_type === 'script') {
          state.sourceCursor = {scriptId: source.script_id, line: Number(line.dataset.line ?? 1) - 1, column: 0};
          elements.sourceCode.querySelectorAll('.source-line').forEach(row => row.classList.toggle('cursor', row === line));
        }
        elements.sourcePosition.textContent = `Line ${line.dataset.line ?? 1}, Column 1`;
      });
      elements.sourceHookPivot.addEventListener('click', pivotSourceToRuntimeHooks);
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
        const response = await runExperimentAction({action: 'create_experiment_page', url});
        if (response) elements.actionScopeNewUrl.value = '';
      });
      elements.experimentCreate.addEventListener('click', () => runExperimentAction({
        action: 'create_request_interception_experiment'
      }));
      elements.experimentDispose.addEventListener('click', () => runExperimentAction({
        action: 'dispose_request_interception_experiment'
      }));
      elements.experimentClear.addEventListener('click', async () => {
        const response = await runExperimentAction({ action: 'clear_request_interception_result' });
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
      elements.objectCreate.addEventListener('click', () => runExperimentAction({
        action: 'create_request_interception_experiment'
      }));
      elements.objectDispose.addEventListener('click', async () => {
        const response = await runExperimentAction({action: 'dispose_request_interception_experiment'});
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
        const response = await runExperimentAction({action: 'dispose_request_interception_experiment'});
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
      elements.hooksDefinitionForm.addEventListener('input', () => {
        state.experimentError = null;
        renderRuntimeHooks();
      });
      elements.hooksConfirm.addEventListener('change', renderRuntimeHooks);
      elements.hooksArm.addEventListener('click', async () => {
        const response = await runExperimentAction({action: 'arm_runtime_hooks', confirmed: elements.hooksConfirm.checked});
        if (response) elements.hooksConfirm.checked = false;
      });
      elements.hooksDisarm.addEventListener('click', async () => {
        const response = await runExperimentAction({action: 'disarm_runtime_hooks'});
        if (response) elements.hooksConfirm.checked = false;
      });
      elements.automationCreate.addEventListener('click', () => runExperimentAction({
        action: 'create_request_interception_experiment'
      }));
      elements.automationDispose.addEventListener('click', async () => {
        const response = await runExperimentAction({action: 'dispose_request_interception_experiment'});
        if (response) {
          state.automationSelectedRunId = null;
          elements.automationConfirm.checked = false;
          elements.automationVariables.value = '';
          resetAutomationEditor();
        }
      });
      elements.automationClear.addEventListener('click', async () => {
        const response = await runExperimentAction({action: 'clear_automation_runs'});
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
          const response = await runExperimentAction({
            action: 'arm_automation_recipes', confirmed: elements.automationConfirm.checked,
            variables: parseAutomationVariables()
          });
          if (response) elements.automationConfirm.checked = false;
        } catch (error) {
          state.experimentError = error.message;
          renderExperiment();
        }
      });
      elements.automationDisarm.addEventListener('click', async () => {
        const response = await runExperimentAction({action: 'disarm_automation_recipes'});
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
        const response = await runExperimentAction({action: 'dispose_request_interception_experiment'});
        if (response) {
          state.repeaterSelectedHistoryId = null;
          state.repeaterExpectedHistoryId = null;
          state.repeaterVariablesKey = null;
          state.repeaterVariablesDirty = false;
          state.repeaterComparisonKey = null;
        }
      });
      elements.repeaterClearHistory.addEventListener('click', async () => {
        const response = await runExperimentAction({action: 'clear_repeater_history'});
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
        state.repeaterVariablesDirty = true;
        state.experimentError = null;
        renderRepeaterVariableStatus();
      });
      elements.repeaterRequestForm.querySelectorAll('input, textarea').forEach(field => field.addEventListener('input', () => {
        state.repeaterDraftDirty = true;
        state.experimentError = null;
        renderRepeaterVariableStatus();
      }));
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
      elements.collectionNewFolder.addEventListener('click', () => {
        elements.collectionNewFolderForm.hidden = false;
        elements.collectionNewFolderName.value = '';
        requestAnimationFrame(() => elements.collectionNewFolderName.focus());
      });
      elements.collectionCancelFolder.addEventListener('click', () => {
        elements.collectionNewFolderForm.hidden = true;
        elements.collectionNewFolderName.value = '';
      });
      elements.collectionConfirmFolder.addEventListener('click', createCollectionFolder);
      elements.collectionNewFolderName.addEventListener('keydown', event => {
        if (event.key === 'Enter') { event.preventDefault(); createCollectionFolder(); }
        if (event.key === 'Escape') elements.collectionCancelFolder.click();
      });
      elements.collectionNewRequest.addEventListener('click', () => createCollectionRequest());
      elements.collectionFolderForm.addEventListener('submit', event => {
        event.preventDefault(); saveCollectionFolder();
      });
      elements.collectionFolderForm.querySelectorAll('input, textarea, select').forEach(field => field.addEventListener('input', () => {
        state.collectionFolderDirty = true;
        state.collectionDeleteFolderId = null;
      }));
      elements.collectionDeleteFolder.addEventListener('click', deleteCollectionFolder);
      elements.collectionRequestForm.addEventListener('submit', event => {
        event.preventDefault(); saveCollectionRequest();
      });
      elements.collectionRequestForm.querySelectorAll('input, textarea, select').forEach(field => field.addEventListener('input', () => {
        state.collectionDraftDirty = true;
        state.collectionDeleteRequestId = null;
        renderCollectionVariableStatus();
      }));
      elements.collectionDuplicateRequest.addEventListener('click', duplicateCollectionRequest);
      elements.collectionDeleteRequest.addEventListener('click', deleteCollectionRequest);
      elements.collectionCreateContext.addEventListener('click', async () => {
        await runExperimentAction({action: 'create_request_interception_experiment'});
        renderApiCollection();
      });
      elements.collectionRun.addEventListener('click', runCollectionRequest);
      elements.collectionCancel.addEventListener('click', async () => {
        await runExperimentAction({action: 'cancel_repeater_request'});
        renderApiCollection();
      });
      analystElements.newFolder.addEventListener('click', createAnalystFolder);
      analystElements.newScript.addEventListener('click', () => createAnalystFile('analyst-script'));
      analystElements.newNote.addEventListener('click', () => createAnalystFile('scratchpad'));
      analystElements.folderForm.addEventListener('submit', event => {
        event.preventDefault();
        saveAnalystFolder();
      });
      analystElements.folderForm.querySelectorAll('input, select').forEach(field => field.addEventListener('input', () => {
        state.analystFolderDirty = true;
        state.analystDeleteFolderId = null;
        analystElements.saveFolder.disabled = false;
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
      analystElements.revert.addEventListener('click', () => {
        state.analystDraftDirty = false;
        state.analystDeleteFileId = null;
        renderLocalAnalyst();
      });
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
        if (state.memoryMode === 'origin') {
          state.memorySearchMessage = 'Reference scope changed. It will apply to the next trace.';
          renderMemory();
          return;
        }
        state.memoryResults = [];
        state.selectedMemoryResultId = null;
        state.memorySearchMeta = null;
        state.memorySearchStatus = memoryAttached() ? 'idle' : 'offline';
        state.memorySearchMessage = 'Reference scope changed. Capture a new snapshot to apply it.';
        renderMemory();
      });
      elements.memoryOriginStop.addEventListener('click', stopMemoryOriginTrace);
      elements.memoryOriginReset.addEventListener('click', clearMemoryOriginTrace);
      elements.memoryCaptureBaseline.addEventListener('click', captureHeapDiffBaseline);
      elements.memoryClearBaseline.addEventListener('click', clearHeapDiffBaseline);
      elements.memoryCompareSnapshot.addEventListener('click', runHeapSnapshotDiff);
      document.addEventListener('keydown', event => {
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
