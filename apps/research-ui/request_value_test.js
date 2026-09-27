// Ephemeral request-value controls shared by Sources and Experiments.
// Capture lifecycle and evidence semantics remain owned by the debugger bridge.

      function renderRuntimeFieldTest(hooks, editable, comparable) {
        const test = hooks?.field_test;
        elements.hooksFieldBadge.textContent = test?.enabled ? `${test.observations.length} observed` : 'Off';
        elements.hooksFieldBadge.dataset.kind = test?.enabled ? '' : 'offline';
        elements.hooksFieldStatus.textContent = test?.enabled
          ? `Capturing ${test.method} ${test.url} · ${test.kind} ${test.pointer || '(whole body)'}. ${editable ? 'Starting a new capture erases these observations.' : 'Disarm hooks to change capture or stop and erase.'}${test.observation_evictions ? ` ${test.observation_evictions} older observations evicted.` : ''}`
          : '1. Choose one request value. No hook is needed to observe it.';
        elements.hooksFieldConfigure.textContent = test?.enabled ? 'Restart capture and erase' : 'Start value capture';
        elements.hooksFieldForm.querySelectorAll('input, select').forEach(field => { field.disabled = !editable; });
        const kind = elements.hooksFieldKind.value;
        elements.hooksFieldPointerLabel.firstChild.textContent = kind === 'json' ? 'JSON pointer' :
          kind === 'body' ? 'No field name needed' : kind === 'header' ? 'Header name' : 'Field name';
        elements.hooksFieldPointer.placeholder = kind === 'json' ? '/payload' : kind === 'header' ? 'X-Request-ID' :
          kind === 'body' ? '' : 'payload';
        elements.hooksFieldPointer.disabled = !editable || kind === 'body';
        elements.hooksFieldConfigure.disabled = !editable || !elements.hooksFieldConfirm.checked ||
          !elements.hooksFieldUrl.value.trim() || (kind !== 'body' && !elements.hooksFieldPointer.value) || state.debuggerActionPending;
        elements.hooksFieldErase.disabled = !editable || !test?.enabled || state.debuggerActionPending;
        const observations = test?.observations ?? [];
        const key = JSON.stringify([observations, test?.comparison, test?.enabled]);
        if (key !== state.runtimeFieldTestKey) {
          state.runtimeFieldTestKey = key;
          if (observations.length) {
            elements.hooksFieldObservations.replaceChildren(...observations.map(observation => {
              const row = document.createElement('div'); row.className = 'hook-hit-row';
              row.append(textElement('span', 'hook-hit-title', `#${observation.id} · ${observation.method} ${observation.url}`),
                textElement('span', 'hook-hit-operation', observation.status.replaceAll('_', ' ')),
                textElement('span', 'hook-hit-meta', `${new Date(observation.occurred_at_ms).toLocaleTimeString()} · ${observation.target_type || 'worker'} ${observation.target_id.slice(0, 12)} · request ${observation.request_id}`),
                textElement('span', 'hook-hit-bindings', observation.status === 'available'
                  ? `${observation.preview || '(empty)'}${observation.bytes > new TextEncoder().encode(observation.preview).length ? '…' : ''} · SHA-256 ${observation.sha256}`
                  : 'No complete selected value retained.'));
              return row;
            }));
          } else elements.hooksFieldObservations.replaceChildren(textElement('div', 'experiment-empty',
            test?.enabled ? 'Repeat the page or worker request. A return hook is optional for observation.' :
              'Configure a value, then run the isolated page. Add a return hook to test an intervention.'));
          const selection = runtimeFieldSelection(observations, elements.hooksFieldBaseline.value, elements.hooksFieldVariant.value);
          const options = available => available.map(observation => {
            const option = document.createElement('option'); option.value = String(observation.id);
            option.textContent = `#${observation.id} · ${observation.target_type} ${observation.target_id.slice(0, 8)} · ${new Date(observation.occurred_at_ms).toLocaleTimeString()}`;
            return option;
          });
          const available = observations.filter(observation => observation.status === 'available');
          elements.hooksFieldBaseline.replaceChildren(...options(available));
          elements.hooksFieldVariant.replaceChildren(...options(available));
          elements.hooksFieldBaseline.value = selection.baseline;
          elements.hooksFieldVariant.value = selection.variant;
          const comparison = test?.comparison;
          elements.hooksFieldResult.replaceChildren();
          if (comparison) {
            elements.hooksFieldResult.append(document.createTextNode(
              `#${comparison.baseline_id} → #${comparison.variant_id}: ${comparison.changed ? 'value changed' : 'value unchanged'} · ${comparison.interpretation.replaceAll('-', ' ')}${comparison.same_query_context ? '' : ' · other query input changed'}. This does not prove the full value-flow chain.`));
            const hit = hooks.hits.find(candidate => candidate.id === comparison.intervention_hit_id);
            if (hit) {
              const sourceLink = document.createElement('button');
              sourceLink.type = 'button';
              sourceLink.className = 'source-tool';
              sourceLink.textContent = `Override hit ${hit.id} in Sources`;
              sourceLink.addEventListener('click', () => revealRuntimeHookHit(hit));
              elements.hooksFieldResult.append(sourceLink);
            }
          }
        }
        elements.hooksFieldCompare.disabled = !comparable || !test?.enabled || state.debuggerActionPending ||
          !elements.hooksFieldBaseline.value || !elements.hooksFieldVariant.value ||
          elements.hooksFieldBaseline.value === elements.hooksFieldVariant.value;
      }

      function bindRuntimeFieldTest() {
        elements.hooksFieldForm.addEventListener('submit', async event => {
          event.preventDefault();
          const response = await runExperimentAction({action: 'configure_runtime_field_test', enabled: true,
            url: elements.hooksFieldUrl.value.trim(), method: elements.hooksFieldMethod.value.trim().toUpperCase(),
            kind: elements.hooksFieldKind.value, pointer: elements.hooksFieldKind.value === 'body' ? '' : elements.hooksFieldPointer.value,
            confirmed: elements.hooksFieldConfirm.checked});
          if (response) {
            elements.hooksFieldConfirm.checked = false;
            renderRuntimeHooks();
          }
        });
        elements.hooksFieldForm.addEventListener('input', event => {
          if (event.target !== elements.hooksFieldConfirm) elements.hooksFieldConfirm.checked = false;
          renderRuntimeHooks();
        });
        elements.hooksFieldJump.addEventListener('click', focusRuntimeFieldTest);
        elements.hooksFieldKind.addEventListener('change', () => {
          elements.hooksFieldPointer.value = '';
          renderRuntimeHooks();
        });
        elements.hooksFieldErase.addEventListener('click', () => runExperimentAction({action: 'configure_runtime_field_test', enabled: false}));
        elements.hooksFieldCompare.addEventListener('click', () => runExperimentAction({action: 'compare_runtime_field_test',
          baseline_id: Number(elements.hooksFieldBaseline.value), variant_id: Number(elements.hooksFieldVariant.value)}));
        elements.hooksFieldBaseline.addEventListener('change', renderRuntimeHooks);
        elements.hooksFieldVariant.addEventListener('change', renderRuntimeHooks);
      }

      function focusRuntimeFieldTest() {
        requestAnimationFrame(() => {
          elements.hooksFieldCard.scrollIntoView({block: 'start'});
          const field = elements.hooksFieldPointer.disabled ? elements.hooksFieldCard : elements.hooksFieldPointer;
          field.focus({preventScroll: true});
        });
      }

      // Keep a researcher's valid pair across refreshes. With only one prior
      // observation both selects point at it; select a distinct new variant as
      // soon as one exists, without silently switching to another target.
      function runtimeFieldSelection(observations, baselineId, variantId) {
        const available = observations.filter(item => item.status === 'available');
        const baseline = available.find(item => String(item.id) === baselineId) ?? available[0];
        const candidates = available.filter(item => item.id !== baseline?.id &&
          item.target_id === baseline?.target_id && item.url === baseline?.url && item.method === baseline?.method);
        const variant = candidates.find(item => String(item.id) === variantId) ?? candidates[candidates.length - 1];
        return {baseline: baseline ? String(baseline.id) : '', variant: variant ? String(variant.id) : ''};
      }
