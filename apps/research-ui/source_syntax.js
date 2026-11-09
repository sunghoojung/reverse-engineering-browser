// Source display formatting and bounded tokenization. No DOM, network, or application state.

      function findSourceOccurrences(lines, query, limit = 1000) {
        const matches = [];
        if (!query) return {matches, truncated: false};
        const escaped = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        // RegExp indexes preserve source UTF-16 offsets even when case folding
        // would change the length of an earlier character (for example U+0130).
        const pattern = new RegExp(escaped, 'giu');
        for (let line = 0; line < lines.length; line += 1) {
          pattern.lastIndex = 0;
          let match;
          while ((match = pattern.exec(lines[line])) !== null) {
            if (matches.length === limit) return {matches, truncated: true};
            matches.push({line, column: match.index, length: match[0].length});
          }
        }
        return {matches, truncated: false};
      }

      // One selected document owns this sparse index. No array is allocated per
      // newline, and excerpts never normalize CRLF, BOMs or UTF-16 positions.
      // 64 Mi units hold a 16 MiB artifact laid out at up to four times its size.
      const SOURCE_DOCUMENT_LIMIT = 64 * 1024 * 1024;
      // The artifact receiver's default per-artifact cap; larger text shows a limit notice.
      const SOURCE_PREVIEW_BYTES = 16 * 1024 * 1024;
      const SOURCE_WINDOW_LINES = 1000;
      const SOURCE_WINDOW_COLUMN_LIMIT = 16384;
      const SOURCE_WINDOW_OTHER_COLUMNS = 512;
      function sourceDocumentIndex(text) {
        const length = Math.min(text.length, SOURCE_DOCUMENT_LIMIT);
        const anchors = [0];
        let lineCount = 1;
        for (let offset = text.indexOf('\n'); offset >= 0 && offset < length; offset = text.indexOf('\n', offset + 1)) {
          if (lineCount % 128 === 0) anchors.push(offset + 1);
          lineCount++;
        }
        return {text, length, anchors, lineCount, complete: length === text.length};
      }
      // One page of a longer document: absolute lines from lineBase, offsets within the page text.
      function sourcePageIndex(text, lineBase, lineCount) {
        const index = sourceDocumentIndex(text);
        return Object.assign(index, {lineBase, pageLines: index.lineCount, lineCount});
      }
      function sourceDocumentOffset(index, line) {
        line -= index.lineBase ?? 0;
        if (!Number.isSafeInteger(line) || line < 0 || line >= (index.pageLines ?? index.lineCount)) return null;
        let current = Math.floor(line / 128) * 128;
        let offset = index.anchors[Math.floor(line / 128)];
        while (current++ < line) offset = index.text.indexOf('\n', offset) + 1;
        return offset;
      }
      // Ascending lookups continue from the previous line instead of rescanning
      // from its anchor, which matters inside one very long line.
      function sourceDocumentPosition(index, offset) {
        if (!Number.isSafeInteger(offset) || offset < 0 || offset > index.length) return null;
        let cursor = index.cursor;
        if (!cursor || offset < cursor.start) {
          let low = 0, high = index.anchors.length - 1;
          while (low < high) {
            const middle = Math.ceil((low + high) / 2);
            if (index.anchors[middle] <= offset) low = middle; else high = middle - 1;
          }
          const start = index.anchors[low];
          cursor = index.cursor = {start, line: low * 128, newline: index.text.indexOf('\n', start)};
        }
        while (cursor.newline >= 0 && cursor.newline < offset) {
          cursor.start = cursor.newline + 1; cursor.line++;
          cursor.newline = index.text.indexOf('\n', cursor.start);
        }
        return {line: (index.lineBase ?? 0) + cursor.line, column: offset - cursor.start};
      }
      function sourceDocumentLine(index, line) {
        const start = sourceDocumentOffset(index, line);
        if (start === null) return null;
        const newline = index.text.indexOf('\n', start);
        const end = newline < 0 ? index.length : Math.min(newline, index.length);
        return {start, end, length: end - start};
      }
      function sourceDocumentMatches(index, query, limit = 1000, acceptLine = null, matchCase = false) {
        const matches = [];
        if (!query) return {matches, truncated: false, error: ''};
        if (query.length > 512) return {matches, truncated: false, error: 'Find accepts at most 512 UTF-16 code units.'};
        if (/[\r\n\u2028\u2029]/u.test(query)) return {matches, truncated: false, error: 'Find uses a single-line literal; line separators are not supported.'};
        const escaped = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        // Every syntax character is escaped, so the pattern is a literal with no
        // quantifier to backtrack; Unicode case folding is applied unless the
        // caller asks to match case.
        const pattern = new RegExp(escaped, matchCase ? 'gu' : 'giu');
        // Accepted representation bounds normally make this a shared string;
        // an oversized defensive input is explicitly a searched prefix.
        const text = index.complete ? index.text : index.text.slice(0, index.length);
        let match, line = index.lineBase ?? 0, lineStart = 0, newline = text.indexOf('\n');
        while ((match = pattern.exec(text)) !== null) {
          while (newline >= 0 && newline < match.index) {line++; lineStart = newline + 1; newline = text.indexOf('\n', lineStart);}
          if (acceptLine && !acceptLine(line)) continue;
          if (matches.length === limit) return {matches, truncated: true, error: ''};
          matches.push({line, column: match.index - lineStart, offset: match.index, length: match[0].length});
        }
        return {matches, truncated: false, error: ''};
      }
      function sourceDocumentExcerpt(index, line, column = 0, maximum = SOURCE_WINDOW_OTHER_COLUMNS) {
        const bounds = sourceDocumentLine(index, line);
        if (!bounds) return null;
        const requested = Math.max(0, Math.min(bounds.length, Number.isSafeInteger(column) ? column : 0));
        let start = Math.max(0, Math.min(bounds.length - maximum, requested - Math.floor(maximum / 4)));
        let end = Math.min(bounds.length, start + maximum);
        // Never split a scalar at a visual-window boundary. Absolute positions
        // stay in UTF-16; exact evidence byte ranges remain separately verified.
        const low = at => {const code = index.text.charCodeAt(bounds.start + at); return code >= 0xdc00 && code <= 0xdfff;};
        if (start && low(start)) start--;
        if (end < bounds.length && low(end)) end--;
        return {line, offset: bounds.start, columnStart: start, columnEnd: end, fullLength: bounds.length,
          text: index.text.slice(bounds.start + start, bounds.start + end)};
      }
      function sourceDocumentWindow(index, line = 0, column = 0) {
        const base = index.lineBase ?? 0, last = base + (index.pageLines ?? index.lineCount) - 1;
        const target = Math.max(base, Math.min(last, Number.isSafeInteger(line) ? line : 0));
        column = Math.max(0, Math.min(sourceDocumentLine(index, target).length, Number.isSafeInteger(column) ? column : 0));
        const start = base + Math.floor((target - base) / SOURCE_WINDOW_LINES) * SOURCE_WINDOW_LINES;
        const end = Math.min(last + 1, start + SOURCE_WINDOW_LINES);
        const rows = [];
        for (let at = start; at < end; at++) rows.push(sourceDocumentExcerpt(index, at, at === target ? column : 0,
          at === target ? SOURCE_WINDOW_COLUMN_LIMIT : SOURCE_WINDOW_OTHER_COLUMNS));
        return {start, end, line: target, column, rows};
      }

      // Map only mounted lines. Normalized segment arrays and sparse source
      // indices belong to the one editor owner, not every refresh or Find step.
      // A pretty-printed row maps through its first non-whitespace character.
      function sourceWindowMapping(original, active, derived, formatted) {
        if (!derived && !formatted) return null;
        const originalIndex = sourceDocumentIndex(original);
        const activeIndex = sourceDocumentIndex(active);
        const derivedSegments = derived ? sourceSegmentsUTF16(original, active, derived.segments ?? [], derived.offset_unit) : null;
        // A page of a layout maps against its slice of the original, from `base`.
        const walk = formatted?.map ? sourceWhitespaceWalker(formatted.map, formatted.sourceInput ?? active, formatted.text) : null;
        const layout = walk && (target => {const at = walk(target); return at === null ? null : at + (formatted.base ?? 0);});
        const firstMapped = (segments, start, end) => {
          let low = 0, high = segments.length;
          while (low < high) {const middle = (low + high) >> 1; if (segments[middle].derived_end <= start) low = middle + 1; else high = middle;}
          for (let at = low; at < segments.length && segments[at].derived_start <= end; at++) {
            const value = derivedOriginalOffset(segments, Math.max(start, segments[at].derived_start));
            if (value !== null) return value;
          }
          return null;
        };
        const position = offset => {
          if (offset !== null && layout && derivedSegments) offset = derivedOriginalOffset(derivedSegments, offset);
          return offset === null ? null : sourceDocumentPosition(derived ? originalIndex : activeIndex, offset);
        };
        const mapping = rows => rows.map(row => {
          const visible = layout ? sourceFirstNonSpace(formatted.text, row.offset, row.offset + row.fullLength) : null;
          const at = position(layout ? (visible === null ? null : layout(visible))
            : formatted ? null : firstMapped(derivedSegments, row.offset, row.offset + row.fullLength));
          return {originalLine: at?.line ?? null, originalColumn: at?.column ?? null};
        });
        // The original location of one displayed offset, or of the next visible character on its line.
        mapping.position = (offset, lineEnd = offset + 1) => {
          if (!layout) return derivedSegments && !formatted ? position(derivedOriginalOffset(derivedSegments, offset)) : null;
          const visible = sourceFirstNonSpace(formatted.text, offset, lineEnd);
          return visible === null ? null : position(layout(visible));
        };
        return mapping;
      }

      function sourceFirstNonSpace(text, start, end) {
        for (let at = start; at < end && at < text.length; at++) if (!sourceFormatSpace(text.charCodeAt(at))) return at;
        return null;
      }

      // ECMAScript WhiteSpace and LineTerminator, the separators a layout may change.
      function sourceFormatSpace(code) {
        return code === 32 || (code >= 9 && code <= 13) || code === 0xa0 || code === 0x1680 ||
          (code >= 0x2000 && code <= 0x200a) || code === 0x2028 || code === 0x2029 ||
          code === 0x202f || code === 0x205f || code === 0x3000 || code === 0xfeff;
      }

      // A layout that changes only whitespace maps by walking both texts in step.
      // Instead of a segment per change, it keeps one sync point per 4 Ki
      // formatted units; null means a non-whitespace character differs.
      const SOURCE_LAYOUT_ANCHOR_UNITS = 4096;
      function sourceWhitespaceMap(original, formatted) {
        const anchors = [0, 0];
        const originalLength = original.length, formattedLength = formatted.length;
        let from = 0, to = 0, next = SOURCE_LAYOUT_ANCHOR_UNITS;
        for (;;) {
          while (from < originalLength && to < formattedLength && original.charCodeAt(from) === formatted.charCodeAt(to)) {
            from++; to++;
            if (to === next) {anchors.push(to, from); next += SOURCE_LAYOUT_ANCHOR_UNITS;}
          }
          if (from === originalLength && to === formattedLength) break;
          const skippedFrom = from, skippedTo = to;
          while (from < originalLength && sourceFormatSpace(original.charCodeAt(from))) from++;
          while (to < formattedLength && sourceFormatSpace(formatted.charCodeAt(to))) to++;
          if (from === skippedFrom && to === skippedTo) return null;
          if (to >= next) {anchors.push(to, from); next = (Math.floor(to / SOURCE_LAYOUT_ANCHOR_UNITS) + 1) * SOURCE_LAYOUT_ANCHOR_UNITS;}
        }
        return {anchors: Uint32Array.from(anchors), originalLength, formattedLength};
      }

      // Original offset of a non-whitespace formatted offset. Ascending lookups continue the walk.
      function sourceWhitespaceWalker(map, original, formatted) {
        const anchors = map.anchors;
        let from = 0, to = 0;
        return target => {
          if (!Number.isSafeInteger(target) || target < 0 || target >= formatted.length || sourceFormatSpace(formatted.charCodeAt(target))) return null;
          let low = 0, high = anchors.length / 2 - 1;
          while (low < high) {const middle = (low + high + 1) >> 1; if (anchors[middle * 2] <= target) low = middle; else high = middle - 1;}
          if (target < to || anchors[low * 2] > to) {to = anchors[low * 2]; from = anchors[low * 2 + 1];}
          for (;;) {
            while (to < target && from < original.length && original.charCodeAt(from) === formatted.charCodeAt(to)) {from++; to++;}
            if (to === target) break;
            const skippedFrom = from, skippedTo = to;
            while (from < original.length && sourceFormatSpace(original.charCodeAt(from))) from++;
            while (to < target && sourceFormatSpace(formatted.charCodeAt(to))) to++;
            if (from === skippedFrom && to === skippedTo) {from = 0; to = 0; return null;}
          }
          while (from < original.length && original.charCodeAt(from) !== formatted.charCodeAt(to) && sourceFormatSpace(original.charCodeAt(from))) from++;
          if (original.charCodeAt(from) === formatted.charCodeAt(to)) return from;
          from = 0; to = 0;
          return null;
        };
      }

      // Formatted offset of an original offset, or of the next character past changed whitespace.
      function sourceWhitespaceInverse(original, formatted) {
        let from = 0, to = 0;
        return target => {
          if (!Number.isSafeInteger(target) || target < 0 || target > original.length) return null;
          if (target < from) {from = 0; to = 0;}
          while (from < target) {
            if (to < formatted.length && original.charCodeAt(from) === formatted.charCodeAt(to)) {from++; to++; continue;}
            const skippedFrom = from, skippedTo = to;
            while (from < original.length && sourceFormatSpace(original.charCodeAt(from))) from++;
            while (to < formatted.length && sourceFormatSpace(formatted.charCodeAt(to))) to++;
            if (from === skippedFrom && to === skippedTo) {from = 0; to = 0; return null;}
          }
          let at = to;
          while (at < formatted.length && sourceFormatSpace(formatted.charCodeAt(at)) && formatted.charCodeAt(at) !== original.charCodeAt(from)) at++;
          return at;
        };
      }

      // The page holding an original offset, from each page's first original offset.
      function sourceFormatBlock(anchors, offset) {
        let low = 0, high = anchors.length - 1;
        while (low < high) {const middle = (low + high + 1) >> 1; if (anchors[middle] <= offset) low = middle; else high = middle - 1;}
        return low;
      }

      // Original offsets of a formatted token. A token's edge whitespace (the space opening a comment
      // body) counts only where the evidence holds those same characters; a range of only whitespace has none.
      function sourceWhitespaceRange(map, original, formatted, start, end) {
        if (!(end > start)) return null;
        const firstVisible = sourceFirstNonSpace(formatted, start, end);
        if (firstVisible === null) return null;
        let lastVisible = end - 1;
        while (sourceFormatSpace(formatted.charCodeAt(lastVisible))) lastVisible -= 1;
        const walk = sourceWhitespaceWalker(map, original, formatted);
        const first = walk(firstVisible), last = walk(lastVisible);
        if (first === null || last === null) return null;
        const leading = firstVisible - start, trailing = end - 1 - lastVisible;
        return {
          start: original.slice(first - leading, first) === formatted.slice(start, firstVisible) ? first - leading : first,
          end: original.slice(last + 1, last + 1 + trailing) === formatted.slice(lastVisible + 1, end) ? last + 1 + trailing : last + 1
        };
      }

      function sourceName(source) {
        // Kept inside sourceName: the navigator check extracts this function
        // through the following formatByteSize declaration.
        const fileName = () => {
          if (!source?.url) return '';
          try {
            return new URL(source.url).pathname.split('/').filter(Boolean).at(-1) || '';
          } catch {
            return String(source.url).split('/').filter(Boolean).at(-1) || '';
          }
        };
        const wasm = source?.kind === 'wasm' || String(source?.mime_type ?? '').split(';', 1)[0].toLowerCase() === 'application/wasm' || source?.language === 'WebAssembly';
        const file = fileName();
        if (wasm) {
          if (file.toLowerCase().endsWith('.wasm')) return file;
          const origin = String(source?.capture_origin || 'module').replaceAll('_', ' ');
          return `wasm ${origin}`;
        }
        if (!source?.url) return `artifact-${source?.artifact_id}`;
        return file || source.url;
      }

      // One hex row is 78 UTF-16 units, including its newline. The hex view of
      // a 2 MiB binary preview stays within 8 Mi units.
      const WASM_HEX_ROW_UNITS = 78;
      function wasmHexByteLimit() {
        const rows = Math.floor((8 * 1024 * 1024 - 160) / WASM_HEX_ROW_UNITS);
        return rows * 16;
      }

      function formatByteSize(bytes) {
        if (bytes < 1024) return `${bytes} bytes`;
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
        return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
      }

      // Binary artifacts render as an inert hex view of their retained bytes,
      // never as decoded text. Guest bytecode has no text representation.
      function sourceHexArtifact(source) {
        return source?.kind === 'wasm' || source?.kind === 'bytecode_buffer';
      }

      function formatWasmHex(buffer) {
        const bytes = new Uint8Array(buffer);
        const rows = [];
        for (let offset = 0; offset < bytes.length; offset += 16) {
          const chunk = bytes.slice(offset, offset + 16);
          const address = offset.toString(16).padStart(8, '0');
          const hex = [...chunk].map(byte => byte.toString(16).padStart(2, '0')).join(' ').padEnd(47, ' ');
          const printable = [...chunk].map(byte => byte >= 32 && byte < 127 ? String.fromCharCode(byte) : '.').join('');
          rows.push(`${address}  ${hex}  |${printable}|`);
        }
        return rows.join('\n');
      }

      // The in-page layout streams its tokens and keeps no per-token mapping,
      // so it accepts the 16 MiB artifact cap; output stays within 3x input.
      const SOURCE_PRETTY_INPUT_LIMIT = 16 * 1024 * 1024;
      const SOURCE_PRETTY_OUTPUT_LIMIT = 48 * 1024 * 1024;
      const SOURCE_PRETTY_TOKEN_LIMIT = 250000;
      const SOURCE_PRETTY_LANGUAGES = new Set(['javascript', 'json', 'css', 'markup']);
      const SOURCE_PRETTY_CONTROL_WORDS = new Set(['catch', 'for', 'if', 'switch', 'while', 'with']);
      const SOURCE_PRETTY_REGEX_PREFIXES = new Set([
        'await', 'case', 'delete', 'do', 'else', 'in', 'instanceof', 'new', 'of',
        'return', 'throw', 'typeof', 'void', 'yield'
      ]);
      const SOURCE_PRETTY_NUMBER_PATTERN = /(?:0[xX][\da-fA-F](?:_?[\da-fA-F])*n?|0[bB][01](?:_?[01])*n?|0[oO][0-7](?:_?[0-7])*n?|(?:\d(?:_?\d)*(?:\.(?:\d(?:_?\d)*)?)?|\.\d(?:_?\d)*)(?:[eE][+-]?\d(?:_?\d)*)?n?)/y;
      const SOURCE_PRETTY_OPERATORS = [
        '>>>=', '**=', '===', '!==', '>>>', '<<=', '>>=', '&&=', '||=', '??=',
        '...', '=>', '==', '!=', '<=', '>=', '++', '--', '&&', '||', '??', '?.', '**',
        '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '<<', '>>',
        '{', '}', '(', ')', '[', ']', ';', ',', ':', '.', '?', '+', '-', '*',
        '/', '%', '=', '<', '>', '!', '~', '&', '|', '^'
      ];
      const SOURCE_PRETTY_OPERATOR_PATTERN = new RegExp(SOURCE_PRETTY_OPERATORS.map(value => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'), 'y');

      function sourcePrettySupported(source) {
        return SOURCE_PRETTY_LANGUAGES.has(sourceSyntaxLanguage(source));
      }

      // Minified JavaScript, CSS and JSON open pretty-printed (#433).
      const SOURCE_LONG_LINE_UNITS = 16 * 1024;
      function sourcePrettyByDefault(source) {
        return ['javascript', 'css', 'json'].includes(sourceSyntaxLanguage(source));
      }

      function sourceHasLongLine(text, limit = SOURCE_LONG_LINE_UNITS) {
        for (let start = 0; start < text.length;) {
          const end = text.indexOf('\n', start);
          if ((end < 0 ? text.length : end) - start > limit) return true;
          if (end < 0) break;
          start = end + 1;
        }
        return false;
      }

      function sourcePrettyQuotedEnd(value, start, quote) {
        let escaped = false;
        for (let index = start + 1; index < value.length; index += 1) {
          const character = value[index];
          if (escaped) escaped = false;
          else if (character === '\\') escaped = true;
          else if (character === quote) return index + 1;
        }
        return value.length;
      }

      function sourcePrettyRegexEnd(value, start) {
        let escaped = false;
        let characterClass = false;
        for (let index = start + 1; index < value.length; index += 1) {
          const character = value[index];
          if (escaped) { escaped = false; continue; }
          if (character === '\\') { escaped = true; continue; }
          if (character === '[') { characterClass = true; continue; }
          if (character === ']') { characterClass = false; continue; }
          if (character === '/' && !characterClass) {
            let end = index + 1;
            while (/[a-z]/i.test(value[end] ?? '')) end += 1;
            return end;
          }
          if (character === '\n' || character === '\r') return start + 1;
        }
        return start + 1;
      }

      function sourcePrettyMayStartRegex(previous) {
        if (!previous) return true;
        if (previous.kind === 'word') return SOURCE_PRETTY_REGEX_PREFIXES.has(previous.text);
        return previous.kind === 'operator' && ![')', ']', '}', '++', '--'].includes(previous.text);
      }

      // Returns the next token, whitespace included, or null; nothing is retained.
      function createSourcePrettyLexer(value, language) {
        let index = 0;
        let previous = null;
        const token = (kind, start, end) => {
          const result = {kind, start, end, text: value.slice(start, end)};
          if (kind !== 'whitespace' && kind !== 'comment') previous = result;
          return result;
        };
        return () => {
          if (index >= value.length) return null;
          const start = index;
          const character = value[index];
          const next = value[index + 1] ?? '';
          if (/\s/.test(character)) {
            while (index < value.length && /\s/.test(value[index])) index += 1;
            return token('whitespace', start, index);
          }
          if ((language === 'javascript' || language === 'css') && character === '/' && next === '*') {
            const close = value.indexOf('*/', index + 2);
            index = close === -1 ? value.length : close + 2;
            return token('comment', start, index);
          }
          if (language === 'javascript' && character === '/' && next === '/') {
            const close = value.indexOf('\n', index + 2);
            index = close === -1 ? value.length : close;
            return token('line-comment', start, index);
          }
          if (character === '"' || character === "'" || (language === 'javascript' && character === '`')) {
            index = sourcePrettyQuotedEnd(value, index, character);
            return token('literal', start, index);
          }
          if (language === 'javascript' && character === '/' && next !== '/' && next !== '*' && sourcePrettyMayStartRegex(previous)) {
            const end = sourcePrettyRegexEnd(value, index);
            if (end > index + 1) {
              index = end;
              return token('literal', start, index);
            }
          }
          if (/[A-Za-z_$]/.test(character)) {
            index += 1;
            while (/[\w$]/.test(value[index] ?? '')) index += 1;
            return token('word', start, index);
          }
          if (/\d/.test(character) || (character === '.' && /\d/.test(next))) {
            SOURCE_PRETTY_NUMBER_PATTERN.lastIndex = index;
            index = SOURCE_PRETTY_NUMBER_PATTERN.exec(value)?.index === start
              ? SOURCE_PRETTY_NUMBER_PATTERN.lastIndex
              : index + 1;
            return token('number', start, index);
          }
          SOURCE_PRETTY_OPERATOR_PATTERN.lastIndex = index;
          index += SOURCE_PRETTY_OPERATOR_PATTERN.exec(value)?.[0].length ?? 1;
          return token('operator', start, index);
        };
      }

      function sourcePrettyTokens(value, language) {
        const next = createSourcePrettyLexer(value, language);
        const tokens = [];
        for (let token = next(); token; token = next()) {
          if (tokens.length >= SOURCE_PRETTY_TOKEN_LIMIT) throw new RangeError('Pretty print token limit reached');
          tokens.push(token);
        }
        return tokens;
      }

      function sourcePrettySignificant(next) {
        return () => {
          for (let token = next(); token; token = next()) if (token.kind !== 'whitespace') return token;
          return null;
        };
      }

      // The output is the input's tokens in order with synthetic whitespace
      // between them, so sourceWhitespaceMap can map it back exactly.
      function createSourcePrettyWriter() {
        const blocks = [];
        let parts = [];
        let length = 0;
        let last = 0;
        let syntheticTail = 0;
        let indent = 0;
        let lineStart = true;
        const append = (chunk, synthetic) => {
          if (!chunk) return;
          if (length + chunk.length > SOURCE_PRETTY_OUTPUT_LIMIT) throw new RangeError('Pretty-print output exceeds three times the input limit');
          parts.push(chunk);
          if (parts.length === 8192) { blocks.push(parts.join('')); parts = []; }
          length += chunk.length;
          last = chunk.charCodeAt(chunk.length - 1);
          syntheticTail = synthetic ? syntheticTail + chunk.length : 0;
          lineStart = last === 10;
        };
        return {
          original: token => {
            if (lineStart) append('  '.repeat(Math.min(indent, 32)), true);
            append(token.text, false);
          },
          space: () => { if (!lineStart && length && !sourceFormatSpace(last)) append(' ', true); },
          newline: () => { if (length && last !== 10) append('\n', true); },
          indent: () => { indent += 1; },
          outdent: () => { indent = Math.max(0, indent - 1); },
          isLineStart: () => lineStart,
          finish: () => {
            blocks.push(parts.join(''));
            const text = blocks.join('');
            return syntheticTail ? text.slice(0, text.length - syntheticTail) : text;
          }
        };
      }

      function prettyPrintStructuredSource(value, language) {
        const read = sourcePrettySignificant(createSourcePrettyLexer(value, language));
        const writer = createSourcePrettyWriter();
        let parens = 0;
        let brackets = 0;
        let braces = 0;
        const multilineBrackets = [];
        let forDepth = null;
        let previous = null;
        let pendingFor = false;
        for (let token = read(), next = token && read(); token; token = next, next = token && read()) {
          if (token.kind === 'line-comment') {
            writer.space(); writer.original(token); writer.newline(); previous = token; continue;
          }
          if (token.kind === 'comment') {
            writer.space(); writer.original(token);
            if (token.text.includes('\n') || next) writer.newline();
            previous = token; continue;
          }
          if (token.kind === 'word') {
            if (token.text === 'for') pendingFor = true;
            if (previous && ['word', 'number', 'literal'].includes(previous.kind)) writer.space();
            if (previous?.text === ')' || previous?.text === ']') writer.space();
            writer.original(token);
            previous = token;
            continue;
          }
          if (token.kind === 'number' || token.kind === 'literal') {
            if (previous && ['word', 'number', 'literal'].includes(previous.kind)) writer.space();
            writer.original(token);
            previous = token;
            continue;
          }
          const operator = token.text;
          if (operator === '{') {
            writer.space(); writer.original(token); braces += 1;
            if (next?.text !== '}') { writer.indent(); writer.newline(); }
          } else if (operator === '}') {
            if (previous?.text !== '{') writer.outdent();
            if (!writer.isLineStart() && previous?.text !== '{') writer.newline();
            writer.original(token); braces = Math.max(0, braces - 1);
            if (next && ![';', ',', ')', ']', '.', '?.'].includes(next.text) && !['else', 'catch', 'finally', 'while'].includes(next.text)) writer.newline();
            else if (next && ['else', 'catch', 'finally'].includes(next.text)) writer.space();
          } else if (operator === '(') {
            if (previous?.kind === 'word' && SOURCE_PRETTY_CONTROL_WORDS.has(previous.text)) writer.space();
            writer.original(token); parens += 1;
            if (pendingFor) { forDepth = parens; pendingFor = false; }
          } else if (operator === ')') {
            writer.original(token);
            if (forDepth === parens) forDepth = null;
            parens = Math.max(0, parens - 1);
          } else if (operator === '[') {
            writer.original(token); brackets += 1;
            const multiline = language === 'json' || !previous ||
              (previous.kind === 'operator' && ![')', ']'].includes(previous.text));
            multilineBrackets.push(multiline);
            if (multiline && next?.text !== ']') { writer.indent(); writer.newline(); }
          } else if (operator === ']') {
            const multiline = multilineBrackets.pop() ?? false;
            if (multiline && previous?.text !== '[') { writer.outdent(); writer.newline(); }
            writer.original(token); brackets = Math.max(0, brackets - 1);
          } else if (operator === ';') {
            writer.original(token);
            if (forDepth === null) writer.newline(); else writer.space();
          } else if (operator === ',') {
            writer.original(token);
            if (language === 'json' || (language === 'javascript' && parens === 0 && (braces > 0 || brackets > 0))) writer.newline();
            else writer.space();
          } else if (operator === ':') {
            writer.original(token); writer.space();
          } else if (operator === '.' || operator === '?.' || ['++', '--', '!', '~'].includes(operator)) {
            writer.original(token);
          } else if (operator === '?') {
            writer.space(); writer.original(token); writer.space();
          } else if ((operator === '-' || operator === '+') && (!previous || (previous.kind === 'operator' && ![')', ']', '}'].includes(previous.text)) ||
              (previous.kind === 'word' && SOURCE_PRETTY_REGEX_PREFIXES.has(previous.text)))) {
            // Unary sign: `-2.5`, `x = -y`, `return +n`.
            if (previous && previous.text !== '(' && previous.text !== '[') writer.space();
            writer.original(token);
          } else {
            writer.space(); writer.original(token); writer.space();
          }
          previous = token;
        }
        return writer.finish();
      }

      // One statement is laid out at a time. A statement past this many tokens is written as it came.
      const SOURCE_PRETTY_CSS_STATEMENT_TOKENS = 65536;
      // The layout only adds line breaks and the space after a declaration's colon or before `{`.
      // Between two other tokens it writes a space exactly where the input had whitespace, so
      // `600px`, `a:hover`, `#main::before`, `!important` and `100% - var(--gap)` keep their spacing.
      function prettyPrintCssSource(value) {
        const read = createSourcePrettyLexer(value, 'css');
        const writer = createSourcePrettyWriter();
        let statement = [], open = false, spaced = false, parens = 0;
        // A block's first line break waits so that `a {}` stays on one line.
        const enter = () => { if (open) { writer.indent(); writer.newline(); open = false; } };
        const write = entry => { if (entry.spaced) writer.space(); writer.original(entry.token); };
        // Declarations and preludes differ only in where they may break or gain a space.
        const flush = kind => {
          if (statement.length) enter();
          const atRule = statement[0]?.token.text === '@';
          const colon = kind === 'declaration' && !atRule ? statement.findIndex(entry => entry.colon) : -1;
          statement.forEach((entry, at) => {
            if (at === colon) { writer.original(entry.token); writer.space(); return; }
            if (at === colon + 1 && colon >= 0) { writer.original(entry.token); return; }
            write(entry);
            if (kind === 'prelude' && !atRule && entry.depth === 0 && entry.token.text === ',') writer.newline();
          });
          statement = [];
        };
        for (let token = read(); token; token = read()) {
          if (token.kind === 'whitespace') { spaced = true; continue; }
          if (token.kind === 'comment' && !statement.length) {
            enter(); writer.original(token); writer.newline(); spaced = false; continue;
          }
          if (token.text === '{' && parens === 0 && token.kind === 'operator') {
            flush('prelude');
            enter();
            writer.space(); writer.original(token); open = true;
          } else if (token.text === '}' && token.kind === 'operator') {
            flush('declaration');
            parens = 0;
            if (open) open = false;
            else { writer.newline(); writer.outdent(); }
            writer.original(token); writer.newline();
          } else if (token.text === ';' && parens === 0 && token.kind === 'operator') {
            flush('declaration');
            enter(); writer.original(token); writer.newline();
          } else {
            if (token.kind === 'operator' && '([{'.includes(token.text)) parens += 1;
            statement.push({token, spaced, colon: token.kind === 'operator' && token.text === ':' && parens === 0, depth: parens});
            if (token.kind === 'operator' && ')]}'.includes(token.text)) parens = Math.max(0, parens - 1);
            if (statement.length === SOURCE_PRETTY_CSS_STATEMENT_TOKENS) flush('');
          }
          spaced = false;
        }
        flush('declaration');
        return writer.finish();
      }

      function createSourcePrettyMarkupLexer(value) {
        let index = 0;
        const queue = [];
        const trimmed = (kind, start, end) => {
          while (start < end && /\s/.test(value[start])) start += 1;
          while (end > start && /\s/.test(value[end - 1])) end -= 1;
          if (start < end) queue.push({kind, start, end, text: value.slice(start, end)});
        };
        return () => {
          while (!queue.length && index < value.length) {
            if (value[index] !== '<') {
              const end = value.indexOf('<', index);
              const boundary = end === -1 ? value.length : end;
              trimmed('text', index, boundary);
              index = boundary;
              continue;
            }
            const start = index;
            if (value.startsWith('<!--', index)) {
              const close = value.indexOf('-->', index + 4);
              index = close === -1 ? value.length : close + 3;
            } else {
              let quote = '';
              index += 1;
              for (; index < value.length; index += 1) {
                const character = value[index];
                if (quote) {
                  if (character === '\\') index += 1;
                  else if (character === quote) quote = '';
                } else if (character === '"' || character === "'") quote = character;
                else if (character === '>') { index += 1; break; }
              }
            }
            const text = value.slice(start, index);
            queue.push({kind: 'tag', start, end: index, text});
            const rawTag = text.match(/^<\s*(script|style)\b/i)?.[1]?.toLowerCase();
            if (rawTag && !/\/\s*>$/.test(text)) {
              const closing = new RegExp(`</${rawTag}`, 'gi');
              closing.lastIndex = index;
              const close = closing.exec(value)?.index;
              if (close !== undefined) {
                trimmed('raw', index, close);
                index = close;
              }
            }
          }
          return queue.shift() ?? null;
        };
      }

      function prettyPrintMarkupSource(value) {
        const read = createSourcePrettyMarkupLexer(value);
        const writer = createSourcePrettyWriter();
        const voidTag = /^<\s*(?:area|base|br|col|embed|hr|img|input|link|meta|param|source|track|wbr)\b/i;
        for (let token = read(); token; token = read()) {
          if (token.kind !== 'tag') {
            writer.original(token); writer.newline(); continue;
          }
          const closing = /^<\s*\//.test(token.text);
          const declaration = /^<\s*[!?]/.test(token.text);
          const selfClosing = /\/\s*>$/.test(token.text) || voidTag.test(token.text) || declaration;
          if (closing) writer.outdent();
          writer.original(token);
          writer.newline();
          if (!closing && !selfClosing) writer.indent();
        }
        return writer.finish();
      }

      // {text, map} where map is the whitespace-only mapping back to `value`.
      function prettyPrintSource(source, value) {
        const language = sourceSyntaxLanguage(source);
        if (!SOURCE_PRETTY_LANGUAGES.has(language)) return {error: `Pretty print does not support ${sourceSyntaxLabel(language)}.`};
        if (value.length > SOURCE_PRETTY_INPUT_LIMIT) return {error: 'Pretty print is limited to the 16 MiB artifact cap.'};
        try {
          const text = language === 'markup' ? prettyPrintMarkupSource(value)
            : language === 'css' ? prettyPrintCssSource(value)
              : prettyPrintStructuredSource(value, language);
          const map = sourceWhitespaceMap(value, text);
          if (!map) return {error: 'Pretty print changed more than whitespace.'};
          return {text, map, offset_unit: 'utf-16-code-unit', language, changed: text !== value, engine: 'in-page'};
        } catch (error) {
          return {error: error instanceof Error ? error.message : 'Pretty print failed.'};
        }
      }

      const SOURCE_HIGHLIGHT_TOKEN_LIMIT = 50000;
      // Token kinds are VS Code TextMate scopes, as the Rosé Pine theme colors them (app.css).
      const SOURCE_KEYWORDS = new Set([
        'async', 'await', 'break', 'case', 'catch', 'class', 'const', 'continue', 'debugger',
        'default', 'delete', 'do', 'else', 'enum', 'export', 'extends', 'finally', 'for',
        'function', 'if', 'implements', 'import', 'in', 'instanceof', 'interface', 'let', 'new',
        'of', 'package', 'private', 'protected', 'public', 'return', 'static', 'switch', 'this',
        'throw', 'try', 'typeof', 'var', 'void', 'while', 'with', 'yield'
      ]);
      const SOURCE_REGEX_KEYWORDS = new Set([
        'await', 'case', 'delete', 'do', 'else', 'in', 'instanceof', 'new', 'of', 'return',
        'throw', 'typeof', 'void', 'yield'
      ]);
      const SOURCE_LITERALS = new Set(['false', 'Infinity', 'NaN', 'null', 'true', 'undefined']);
      // The grammar scopes only these names; window, JSON, Math and the like render as ordinary variables.
      const SOURCE_SUPPORT_NAMES = new Set(['Promise', 'exports', 'module']);
      const SOURCE_BINDINGS = new Set(['const', 'let', 'var']);
      const SOURCE_BUILTIN_PROPERTIES = new Set(['__proto__', 'constructor', 'length', 'prototype']);
      const SOURCE_NUMBER_PATTERN = /(?:0[xX][\da-fA-F](?:_?[\da-fA-F])*n?|0[bB][01](?:_?[01])*n?|0[oO][0-7](?:_?[0-7])*n?|(?:\d(?:_?\d)*(?:\.(?:\d(?:_?\d)*)?)?|\.\d(?:_?\d)*)(?:[eE][+-]?\d(?:_?\d)*)?n?)/y;
      const SOURCE_IDENTIFIER_PATTERN = /[\p{ID_Start}$_][\p{ID_Continue}$‌‍]*/uy;
      const SOURCE_SPACE_PATTERN = /[\s﻿]+/y;
      const SOURCE_OPERATOR_PATTERN = /(?:>>>=|\.\.\.|===|!==|\*\*=|<<=|>>=|>>>|&&=|\|\|=|\?\?=|=>|==|!=|<=|>=|\+\+|--|&&|\|\||\?\?|\?\.(?!\d)|\*\*|\+=|-=|\*=|\/=|%=|&=|\|=|\^=|<<|>>|[=+\-*/%<>!~&|^?.])/y;
      const SOURCE_ESCAPE_PATTERN = /\\(?:x[\da-fA-F]{2}|u\{[\da-fA-F]+\}|u[\da-fA-F]{4}|[0-7]{1,3}|[\s\S])/g;
      const SOURCE_FOLLOWED_CALL = /\s*(?:\?\.\s*)?[(`]/y;
      const SOURCE_FOLLOWED_ARROW = /\s*=>/y;
      const SOURCE_FOLLOWED_KEY = /\s*:(?!:)/y;
      const SOURCE_FUNCTION_VALUE = /\s*(?::|=(?![=>]))\s*(?:async\s*)?(?:function\b|\([^()]*\)\s*=>|[\p{ID_Start}$_][\p{ID_Continue}$]*\s*=>)/uy;
      const SOURCE_ACCESSOR_NAME = /\s+[#\p{ID_Start}$_][\p{ID_Continue}$]*\s*\(/uy;
      const SOURCE_FROM_STRING = /\s*['"]/y;
      const SOURCE_ASYNC_TARGET = /\s*(?:function\b|[(*#[]|[\p{ID_Start}$_])/uy;
      const SOURCE_AS_TARGET = /\s+[\p{ID_Start}$_]/uy;
      const SOURCE_FOLLOWED_PROTOTYPE = /\s*\.\s*prototype\b/y;
      const SOURCE_FOLLOWED_DOT = /\s*\??\./y;
      const SOURCE_DOTTED_CALL = /(?:\s*\.\s*[\p{ID_Start}$_][\p{ID_Continue}$]*)+\s*\(/uy;
      const SOURCE_REGEXP_ESCAPE = /\\(?:x[\da-fA-F]{2}|u\{[\da-fA-F]+\}|u[\da-fA-F]{4}|c[A-Za-z]|[1-9]\d*|[\s\S])/y;
      const SOURCE_REGEXP_QUANTIFIER = /\{(?:\d+(?:,\d*)?|,\d+)\}/y;
      const SOURCE_REGEXP_GROUP = /\(\?(?:[:=!]|<[=!])/y;
      const SOURCE_REGEXP_NAME = /\(\?<([\p{ID_Start}$_][\p{ID_Continue}$]*)>/uy;
      const SOURCE_REGEXP_BACKREFERENCE = /\\k<([\p{ID_Start}$_][\p{ID_Continue}$]*)>/uy;
      const SOURCE_CSS_NESTED = /[^;{}]*\{/y;
      const SOURCE_CSS_ATTRIBUTE_OPERATOR = /[~|^$*]?=/y;
      const SOURCE_CSS_NTH_ARGUMENT = /\s*[+-]?\d*n?(?:\s*[+-]\s*\d+)?\s*(?=\))/y;
      const SOURCE_CSS_COLOR_PATTERN = /#[\da-fA-F]{3,8}\b/y;
      const SOURCE_CSS_NUMBER_PATTERN = /[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?/y;
      const SOURCE_CSS_UNIT_PATTERN = /%|[a-zA-Z]+/y;
      const SOURCE_CSS_IDENTIFIER_PATTERN = /-{0,2}[A-Za-z_ -￿][\w -￿-]*/y;
      const SOURCE_MARKUP_IDENTIFIER_PATTERN = /[A-Za-z_:][\w:.-]*/y;
      const SOURCE_WASM_VALUE_PATTERN = /(?:[\da-fA-F]{8}|[\da-fA-F]{2})(?=\s|$)/y;
      const SOURCE_WASM_IDENTIFIER_PATTERN = /\$?[A-Za-z_][\w.$-]*/y;

      function sourceMatchAt(pattern, value, index) {
        pattern.lastIndex = index;
        return pattern.exec(value)?.[0] ?? null;
      }

      function sourceFollowedBy(pattern, value, index) {
        pattern.lastIndex = index;
        return pattern.test(value);
      }

      function sourceNextSignificant(value, index) {
        while (/\s/.test(value[index] ?? '')) index += 1;
        return value[index] ?? '';
      }

      function sourceSyntaxLanguage(source) {
        if (!source) return 'text';
        const mime = String(source.mime_type ?? '').toLowerCase().split(';', 1)[0];
        const name = sourceName(source).toLowerCase();
        if (source.kind === 'bytecode_buffer') return 'bytes';
        if (source.kind === 'wasm' || mime === 'application/wasm') return 'wasm';
        if (source.kind === 'javascript' || /(?:java|ecma)script/.test(mime) || /\.[cm]?jsx?$/.test(name)) return 'javascript';
        if (source.kind === 'source_map' || /json/.test(mime) || /\.(?:json|map)$/.test(name)) return 'json';
        if (/css/.test(mime) || /\.css$/.test(name)) return 'css';
        if (/(?:html|xml|svg)/.test(mime) || /\.(?:html?|xml|svg)$/.test(name)) return 'markup';
        return 'text';
      }

      function sourceSyntaxLabel(language) {
        return {javascript: 'JavaScript', json: 'JSON', css: 'CSS', markup: 'HTML', wasm: 'WebAssembly hex', bytes: 'Guest bytecode hex', text: 'Plain text'}[language];
      }

      function createSourceTokenizer(source) {
        return {
          language: sourceSyntaxLanguage(source),
          state: 'code',
          depth: 0,
          templates: [],
          ternaries: [],
          previous: '',
          previousKind: '',
          member: '',
          declaration: '',
          // The depth a `class` head started at and the depths of open class bodies.
          classHead: -1,
          classBodies: [],
          // The current const/let/var statement, its depth, and a destructuring pattern's depth.
          varKind: '',
          varDepth: 0,
          binding: 0,
          // An `instanceof` operand continues as a type across its dots.
          typeChain: false,
          pendingParams: false,
          params: null,
          cssValue: false,
          cssBlocks: [],
          cssAtRule: '',
          cssParens: 0,
          // 'name' or 'value' inside an [attribute] selector.
          cssAttribute: '',
          coloredTokens: 0,
          truncated: false,
          // Line position of the next token; only tokens inside the clip are emitted.
          cursor: 0,
          clipStart: 0,
          clipEnd: Infinity
        };
      }

      // Lexer stacks stay bounded so checkpoints copy a fixed amount of state.
      function pushSourceState(stack, value) {
        if (stack.length === 64) stack.shift();
        stack.push(value);
      }

      function sourceTokenizerSnapshot(tokenizer) {
        return {...tokenizer, templates: tokenizer.templates.slice(), ternaries: tokenizer.ternaries.slice(),
          classBodies: tokenizer.classBodies.slice(), cssBlocks: tokenizer.cssBlocks.slice(), params: tokenizer.params && {...tokenizer.params}};
      }

      function pushSourceToken(tokens, tokenizer, type, text) {
        if (!text) return;
        const start = tokenizer.cursor;
        tokenizer.cursor += text.length;
        if (!tokens) return;
        const from = Math.max(start, tokenizer.clipStart), to = Math.min(tokenizer.cursor, tokenizer.clipEnd);
        if (to <= from) return;
        if (from > start || to < tokenizer.cursor) text = text.slice(from - start, to - start);
        let boundedType = type;
        // Plain and text cost nothing to paint; text only makes visible characters clickable.
        if (type !== 'plain' && type !== 'text') {
          if (tokenizer.coloredTokens >= SOURCE_HIGHLIGHT_TOKEN_LIMIT) {
            boundedType = 'plain';
            tokenizer.truncated = true;
          } else {
            tokenizer.coloredTokens += 1;
          }
        }
        const previous = tokens.at(-1);
        if (previous?.type === boundedType) previous.text += text;
        else tokens.push({type: boundedType, text});
      }

      function quotedSourceEnd(line, start, quote) {
        let escaped = false;
        for (let index = start + 1; index < line.length; index += 1) {
          const character = line[index];
          if (escaped) escaped = false;
          else if (character === '\\') escaped = true;
          else if (character === quote) return index + 1;
        }
        return line.length;
      }

      function regexpSourceEnd(line, start) {
        let escaped = false;
        let characterClass = false;
        for (let index = start + 1; index < line.length; index += 1) {
          const character = line[index];
          if (escaped) { escaped = false; continue; }
          if (character === '\\') { escaped = true; continue; }
          if (character === '[') { characterClass = true; continue; }
          if (character === ']') { characterClass = false; continue; }
          if (character === '/' && !characterClass) {
            let end = index + 1;
            while (/[a-z]/i.test(line[end] ?? '')) end += 1;
            return end;
          }
        }
        return start + 1;
      }

      function pushSourceString(tokens, tokenizer, text, type = 'string') {
        if (!tokens) { tokenizer.cursor += text.length; return; }
        let last = 0;
        SOURCE_ESCAPE_PATTERN.lastIndex = 0;
        for (let match; (match = SOURCE_ESCAPE_PATTERN.exec(text));) {
          pushSourceToken(tokens, tokenizer, type, text.slice(last, match.index));
          pushSourceToken(tokens, tokenizer, 'escape', match[0]);
          last = match.index + match[0].length;
        }
        pushSourceToken(tokens, tokenizer, type, text.slice(last));
      }

      function pushSourceBracket(tokens, tokenizer, text, opening) {
        if (!opening) tokenizer.depth = Math.max(0, tokenizer.depth - 1);
        pushSourceToken(tokens, tokenizer, `bracket-${tokenizer.depth % 6}`, text);
        if (opening) tokenizer.depth += 1;
      }

      // The grammar's same-line lookahead: `(...) =>`, or a method's `(...) {`.
      function sourceParameterList(line, open, tokenizer) {
        const before = tokenizer.previous;
        if (tokenizer.pendingParams) return true;
        if (['if', 'for', 'while', 'switch', 'with', 'catch', 'extends'].includes(before)) return false;
        let depth = 0;
        const limit = Math.min(line.length, open + 512);
        for (let index = open; index < limit; index += 1) {
          const character = line[index];
          if (character === '"' || character === "'" || character === '`') { index = quotedSourceEnd(line, index, character) - 1; continue; }
          if (character === '(') depth += 1;
          else if (character === ')' && --depth === 0) {
            const rest = line.slice(index + 1, index + 8).trimStart();
            return rest.startsWith('=>') || (tokenizer.previousKind === 'word' && rest.startsWith('{'));
          }
        }
        return false;
      }

      // One regular expression, in the grammar's parts: bytes stay strings, syntax takes the keyword color.
      function pushSourceRegexp(tokens, tokenizer, text) {
        if (!tokens) { tokenizer.cursor += text.length; return; }
        const push = (type, value) => pushSourceToken(tokens, tokenizer, type, value);
        const close = text.lastIndexOf('/');
        let index = 1, plainFrom = 1;
        const flush = () => { push('regexp', text.slice(plainFrom, index)); };
        const take = (type, length) => { flush(); push(type, text.slice(index, index + length)); index += length; plainFrom = index; };
        push('regexp', '/');
        while (index < close) {
          const character = text[index];
          if (character === '\\') {
            const reference = sourceMatchAt(SOURCE_REGEXP_BACKREFERENCE, text, index);
            if (reference) {
              take('keyword', 3);
              take('variable-other', reference.length - 4);
              take('keyword', 1);
            } else {
              take('keyword', sourceMatchAt(SOURCE_REGEXP_ESCAPE, text, index)?.length ?? 2);
            }
          } else if ('|^$.'.includes(character)) {
            take('keyword', 1);
          } else if ('*+?'.includes(character)) {
            take('keyword', 1);
          } else if (character === '{') {
            const quantifier = sourceMatchAt(SOURCE_REGEXP_QUANTIFIER, text, index);
            if (quantifier) take('keyword', quantifier.length); else index += 1;
          } else if (character === '(') {
            const named = sourceMatchAt(SOURCE_REGEXP_NAME, text, index);
            if (named) {
              take('punctuation', 3);
              take('variable-other', named.length - 4);
              take('punctuation', 1);
            } else {
              take('punctuation', sourceMatchAt(SOURCE_REGEXP_GROUP, text, index)?.length ?? 1);
            }
          } else if (character === ')') {
            take('punctuation', 1);
          } else if (character === '[') {
            take('punctuation', 1);
            while (index < close && text[index] !== ']') {
              if (text[index] === '\\') take('keyword', sourceMatchAt(SOURCE_REGEXP_ESCAPE, text, index)?.length ?? 2);
              else {
                const start = index;
                while (index < close && text[index] !== ']' && text[index] !== '\\') index += 1;
                push('keyword', text.slice(start, index));
                plainFrom = index;
              }
            }
            if (index < close) take('punctuation', 1);
          } else {
            index += 1;
          }
        }
        flush();
        push('regexp', '/');
        push('keyword', text.slice(close + 1));
      }

      // A class member begins after these, or first on its own line when a field omits the semicolon.
      function sourceClassMemberStart(line, start, tokenizer) {
        return ['{', ';', '}', 'static', 'async', 'get', 'set', '*'].includes(tokenizer.previous) || !line.slice(0, start).trim();
      }

      // Kinds follow what the grammar and the theme render, not what a name means: `JSON` is a
      // variable and `JSON.stringify(` an ordinary function call, as in VS Code.
      function sourceIdentifierType(line, end, name, tokenizer, start) {
        const {previous} = tokenizer;
        const afterDot = previous === '.' || previous === '?.';
        const key = (previous === '{' || previous === ',') && sourceFollowedBy(SOURCE_FOLLOWED_KEY, line, end);
        const member = !afterDot && tokenizer.classBodies.at(-1) === tokenizer.depth && sourceClassMemberStart(line, start, tokenizer);
        const call = sourceFollowedBy(SOURCE_FOLLOWED_CALL, line, end);
        if (!afterDot && !key) {
          if (SOURCE_LITERALS.has(name)) return 'number';
          if (name === 'this') return 'this';
          if (name === 'super') return 'variable-other';
          if (name === 'constructor' && member && call) return 'keyword';
          if (name === 'async') return sourceFollowedBy(SOURCE_ASYNC_TARGET, line, end) ? 'keyword' : 'variable-other';
          if (name === 'static') return member ? 'keyword' : 'variable-other';
          if ((name === 'get' || name === 'set') && sourceFollowedBy(SOURCE_ACCESSOR_NAME, line, end)) return 'keyword';
          if (name === 'from' && sourceFollowedBy(SOURCE_FROM_STRING, line, end)) return 'keyword';
          if (name === 'as' && (tokenizer.previousKind === 'word' || previous === '*') && sourceFollowedBy(SOURCE_AS_TARGET, line, end)) return 'keyword';
          if (SOURCE_KEYWORDS.has(name)) return 'keyword';
        }
        if (tokenizer.declaration === 'class') return 'type';
        if (tokenizer.declaration === 'extends') {
          if (sourceFollowedBy(SOURCE_DOTTED_CALL, line, end)) { tokenizer.declaration = ''; return 'variable-other'; }
          return sourceFollowedBy(SOURCE_FOLLOWED_DOT, line, end) ? 'type' : 'inherited';
        }
        if (tokenizer.declaration === 'function') return 'function';
        if (tokenizer.params && !tokenizer.params.defaults) return key ? 'variable' : 'parameter';
        const functionValue = sourceFollowedBy(SOURCE_FUNCTION_VALUE, line, end);
        if (afterDot) {
          if (tokenizer.typeChain) return 'type';
          if (call) return 'function';
          if (SOURCE_BUILTIN_PROPERTIES.has(name)) return 'builtin';
          if ((tokenizer.member === 'module' && name === 'exports') || (tokenizer.member === 'import' && name === 'meta') || (tokenizer.member === 'new' && name === 'target')) return 'builtin';
          return functionValue ? 'function' : 'variable-other';
        }
        if (previous === 'instanceof') return 'type';
        // entity.name.label: `break x`, and a name opening its statement before a colon.
        if (previous === 'break' || previous === 'continue' || (['', ';', '}'].includes(previous) && !tokenizer.ternaries.length && sourceFollowedBy(SOURCE_FOLLOWED_KEY, line, end))) return 'function';
        if (sourceFollowedBy(SOURCE_FOLLOWED_ARROW, line, end)) return 'parameter';
        if (SOURCE_SUPPORT_NAMES.has(name) || sourceFollowedBy(SOURCE_FOLLOWED_PROTOTYPE, line, end)) return 'builtin';
        if (call) return 'function';
        if (key) return functionValue ? 'function' : tokenizer.binding ? 'variable' : 'property';
        if (member) return functionValue ? 'function' : 'variable';
        if (functionValue) return tokenizer.varKind === 'const' && tokenizer.varDepth === tokenizer.depth && (previous === 'const' || previous === ',') ? 'variable' : 'function';
        return 'variable-other';
      }

      function sourceRegexAllowed(tokenizer) {
        const {previous, previousKind} = tokenizer;
        if (!previousKind) return true;
        if (previousKind === 'word') return SOURCE_REGEX_KEYWORDS.has(previous);
        if (previousKind === 'close' || previousKind === 'value') return false;
        return !['++', '--'].includes(previous);
      }

      function tokenizeTemplateText(line, from, tokens, tokenizer, scan = from) {
        const index = from;
        let cursor = scan;
        while (cursor < line.length) {
          const character = line[cursor];
          if (character === '\\') { cursor += 2; continue; }
          if (character === '`') {
            pushSourceString(tokens, tokenizer, line.slice(index, cursor + 1));
            tokenizer.state = 'code';
            tokenizer.previous = '`';
            tokenizer.previousKind = 'value';
            return cursor + 1;
          }
          if (character === '$' && line[cursor + 1] === '{') {
            pushSourceString(tokens, tokenizer, line.slice(index, cursor));
            pushSourceBracket(tokens, tokenizer, '${', true);
            pushSourceState(tokenizer.templates, tokenizer.depth);
            tokenizer.state = 'code';
            tokenizer.previous = '${';
            tokenizer.previousKind = 'open';
            return cursor + 2;
          }
          cursor += 1;
        }
        pushSourceString(tokens, tokenizer, line.slice(index, Math.min(cursor, line.length)));
        return line.length;
      }

      // Tokenizes from `from` until a token ends at or after `stop`; tokenizer.cursor is where it stopped.
      function tokenizeCodeSourceLine(line, tokenizer, from = 0, stop = line.length, tokens = []) {
        const json = tokenizer.language === 'json';
        const push = (type, text) => pushSourceToken(tokens, tokenizer, type, text);
        const significant = (text, kind) => { tokenizer.previous = text; tokenizer.previousKind = kind; };
        let index = from;
        tokenizer.cursor = from;
        // Without a trailing comma, a new line ends a statement that omitted its semicolon.
        if (from === 0 && tokenizer.previous !== ',') tokenizer.varKind = '';
        while (index < stop) {
          if (tokenizer.coloredTokens >= SOURCE_HIGHLIGHT_TOKEN_LIMIT) {
            tokenizer.truncated = true;
            push('plain', line.slice(index));
            break;
          }
          if (tokenizer.state === 'block-comment') {
            const end = line.indexOf('*/', index);
            if (end === -1) { push('comment', line.slice(index)); break; }
            push('comment', line.slice(index, end)); push('comment-mark', '*/');
            tokenizer.state = 'code'; index = end + 2; continue;
          }
          if (tokenizer.state === 'template') { index = tokenizeTemplateText(line, index, tokens, tokenizer); continue; }
          const space = sourceMatchAt(SOURCE_SPACE_PATTERN, line, index);
          if (space) { push('plain', space); index += space.length; continue; }
          const character = line[index];
          const next = line[index + 1] ?? '';
          if (character === '/' && next === '/') {
            push('comment-mark', '//'); push('comment', line.slice(index + 2)); break;
          }
          if (character === '/' && next === '*') {
            push('comment-mark', '/*');
            const end = line.indexOf('*/', index + 2);
            if (end === -1) { push('comment', line.slice(index + 2)); tokenizer.state = 'block-comment'; break; }
            push('comment', line.slice(index + 2, end)); push('comment-mark', '*/');
            index = end + 2; continue;
          }
          if (character === '"' || character === "'") {
            const end = quotedSourceEnd(line, index, character);
            const text = line.slice(index, end);
            if (json && sourceNextSignificant(line, end) === ':') {
              const closed = text.length > 1 && text.endsWith(character);
              push('punctuation', character);
              pushSourceString(tokens, tokenizer, text.slice(1, closed ? -1 : undefined), 'key');
              if (closed) push('punctuation', character);
            } else {
              pushSourceString(tokens, tokenizer, text);
            }
            significant(text, 'value'); index = end; continue;
          }
          if (!json && character === '`') {
            tokenizer.state = 'template';
            index = tokenizeTemplateText(line, index, tokens, tokenizer, index + 1);
            continue;
          }
          const sign = json && character === '-' && /\d/.test(next) ? 1 : 0;
          const number = sourceMatchAt(SOURCE_NUMBER_PATTERN, line, index + sign);
          if (number && (sign || /\d/.test(character) || (character === '.' && /\d/.test(next)))) {
            const text = line.slice(index, index + sign + number.length);
            const bigint = !json && text.endsWith('n');
            push('number', bigint ? text.slice(0, -1) : text);
            if (bigint) push('keyword', 'n');
            significant(text, 'value'); index += text.length; continue;
          }
          if (!json && character === '#') {
            const name = sourceMatchAt(SOURCE_IDENTIFIER_PATTERN, line, index + 1);
            if (name) {
              const end = index + 1 + name.length, afterDot = tokenizer.previous === '.' || tokenizer.previous === '?.';
              const call = sourceFollowedBy(SOURCE_FOLLOWED_CALL, line, end);
              const member = !afterDot && tokenizer.classBodies.at(-1) === tokenizer.depth && sourceClassMemberStart(line, index, tokenizer);
              if (afterDot) push(call ? 'function' : 'variable-other', `#${name}`);
              else if (member && !call) push('variable', `#${name}`);
              else { push('text', '#'); push(call ? 'function' : 'variable-other', name); }
              significant(name, 'word'); index = end; continue;
            }
          }
          const identifier = sourceMatchAt(SOURCE_IDENTIFIER_PATTERN, line, index);
          if (identifier) {
            const end = index + identifier.length;
            const type = json ? (SOURCE_LITERALS.has(identifier) ? 'number' : 'text') : sourceIdentifierType(line, end, identifier, tokenizer, index);
            push(type, identifier);
            tokenizer.typeChain = type === 'type' && sourceFollowedBy(SOURCE_FOLLOWED_DOT, line, end);
            if (type === 'keyword') {
              if (identifier === 'function') { tokenizer.declaration = 'function'; tokenizer.pendingParams = true; }
              else if (identifier === 'class') { tokenizer.declaration = 'class'; tokenizer.classHead = tokenizer.depth; }
              else if (identifier === 'extends') tokenizer.declaration = 'extends';
              else if (SOURCE_BINDINGS.has(identifier)) { tokenizer.varKind = identifier; tokenizer.varDepth = tokenizer.depth; }
            } else if (tokenizer.declaration === 'function' || tokenizer.declaration === 'class') {
              tokenizer.declaration = '';
            }
            significant(identifier, type === 'number' || type === 'string' ? 'value' : 'word');
            index = end; continue;
          }
          if (!json && character === '/' && sourceRegexAllowed(tokenizer)) {
            const end = regexpSourceEnd(line, index);
            if (end > index + 1) {
              pushSourceRegexp(tokens, tokenizer, line.slice(index, end)); significant('/', 'value'); index = end; continue;
            }
          }
          if ('([{'.includes(character)) {
            const params = character === '(' && !json && sourceParameterList(line, index, tokenizer);
            if (tokenizer.declaration === 'extends' || (character === '{' && tokenizer.declaration === 'class')) tokenizer.declaration = '';
            const classBody = character === '{' && tokenizer.classHead === tokenizer.depth;
            const binding = character === '{' && SOURCE_BINDINGS.has(tokenizer.previous);
            pushSourceBracket(tokens, tokenizer, character, true);
            if (classBody) { pushSourceState(tokenizer.classBodies, tokenizer.depth); tokenizer.classHead = -1; }
            if (binding) tokenizer.binding = tokenizer.depth;
            if (params) tokenizer.params = {depth: tokenizer.depth, defaults: false};
            tokenizer.pendingParams = false;
            if (tokenizer.declaration === 'function') tokenizer.declaration = '';
            significant(character, 'open'); index += 1; continue;
          }
          if (')]}'.includes(character)) {
            if (character === '}' && tokenizer.templates.at(-1) === tokenizer.depth) {
              tokenizer.templates.pop();
              pushSourceBracket(tokens, tokenizer, '}', false);
              tokenizer.state = 'template';
              index += 1; continue;
            }
            if (tokenizer.params?.depth === tokenizer.depth && character === ')') tokenizer.params = null;
            if (character === '}' && tokenizer.classBodies.at(-1) === tokenizer.depth) tokenizer.classBodies.pop();
            pushSourceBracket(tokens, tokenizer, character, false);
            if (tokenizer.binding > tokenizer.depth) tokenizer.binding = 0;
            while (tokenizer.ternaries.length && tokenizer.ternaries.at(-1) > tokenizer.depth) tokenizer.ternaries.pop();
            significant(character, 'close'); index += 1; continue;
          }
          if (character === ',' || character === ';') {
            if (tokenizer.params?.depth === tokenizer.depth) tokenizer.params.defaults = false;
            if (tokenizer.declaration !== 'extends') tokenizer.declaration = '';
            tokenizer.pendingParams = false;
            if (character === ';') {
              tokenizer.classHead = -1;
              if (tokenizer.varDepth === tokenizer.depth) tokenizer.varKind = '';
            }
            push('punctuation', character); significant(character, 'punctuation'); index += 1; continue;
          }
          if (character === ':') {
            const ternary = !json && tokenizer.ternaries.at(-1) === tokenizer.depth;
            if (ternary) tokenizer.ternaries.pop();
            tokenizer.declaration = '';
            tokenizer.pendingParams = false;
            push(ternary ? 'operator' : 'punctuation', ':'); significant(':', 'punctuation'); index += 1; continue;
          }
          const operator = json ? null : sourceMatchAt(SOURCE_OPERATOR_PATTERN, line, index);
          if (operator) {
            if (operator === '?') pushSourceState(tokenizer.ternaries, tokenizer.depth);
            if (operator === '=' && tokenizer.params?.depth === tokenizer.depth) tokenizer.params.defaults = true;
            if (operator === '.' || operator === '?.') tokenizer.member = tokenizer.previousKind === 'word' ? tokenizer.previous : '';
            else if (operator !== '=>' && tokenizer.declaration === 'extends') tokenizer.declaration = '';
            // The namespace star of an import or export is the grammar's constant.language.
            push(operator === '*' && (tokenizer.previous === 'import' || tokenizer.previous === 'export') ? 'number' : 'operator', operator);
            significant(operator, 'operator'); index += operator.length; continue;
          }
          push('text', character); index += 1;
        }
        return tokens;
      }

      // In a declaration block, a `{` before the next `;` or `}` makes this a nested selector, not `name: value`.
      function sourceCssNestedSelector(line, index) {
        SOURCE_CSS_NESTED.lastIndex = index;
        return SOURCE_CSS_NESTED.test(line);
      }

      function tokenizeCssSourceLine(line, tokenizer, from = 0, stop = line.length, tokens = []) {
        const push = (type, text) => pushSourceToken(tokens, tokenizer, type, text);
        let index = from;
        tokenizer.cursor = from;
        while (index < stop) {
          if (tokenizer.coloredTokens >= SOURCE_HIGHLIGHT_TOKEN_LIMIT) {
            tokenizer.truncated = true;
            push('plain', line.slice(index));
            break;
          }
          if (tokenizer.state === 'block-comment') {
            const end = line.indexOf('*/', index);
            if (end === -1) { push('comment', line.slice(index)); break; }
            push('comment', line.slice(index, end)); push('comment-mark', '*/');
            tokenizer.state = 'code'; index = end + 2; continue;
          }
          const space = sourceMatchAt(SOURCE_SPACE_PATTERN, line, index);
          if (space) { push('plain', space); index += space.length; continue; }
          if (line.startsWith('/*', index)) {
            push('comment-mark', '/*');
            const end = line.indexOf('*/', index + 2);
            if (end === -1) { push('comment', line.slice(index + 2)); tokenizer.state = 'block-comment'; break; }
            push('comment', line.slice(index + 2, end)); push('comment-mark', '*/');
            index = end + 2; continue;
          }
          const character = line[index];
          const value = tokenizer.cssValue;
          if (character === '"' || character === "'") {
            const end = quotedSourceEnd(line, index, character);
            pushSourceString(tokens, tokenizer, line.slice(index, end)); index = end; continue;
          }
          // @media-like blocks hold rules; style blocks and preludes hold declarations.
          const declarations = tokenizer.cssBlocks.at(-1) === 'declarations' || Boolean(tokenizer.cssAtRule);
          if ('{[('.includes(character)) {
            if (character === '{') {
              pushSourceState(tokenizer.cssBlocks, /^(?:-\w+-)?keyframes$/.test(tokenizer.cssAtRule) ? 'keyframes'
                : /^(?:media|supports|document|layer|container|scope|starting-style)$/.test(tokenizer.cssAtRule) ? 'rules' : 'declarations');
              tokenizer.cssAtRule = ''; tokenizer.cssValue = false; tokenizer.cssParens = 0;
            } else if (character === '(') {
              tokenizer.cssParens += 1;
            } else if (!value) {
              tokenizer.cssAttribute = 'name';
            }
            pushSourceBracket(tokens, tokenizer, character, true); index += 1; continue;
          }
          if ('}])'.includes(character)) {
            if (character === '}') { tokenizer.cssBlocks.pop(); tokenizer.cssValue = false; tokenizer.cssParens = 0; }
            if (character === ')') {
              tokenizer.cssParens = Math.max(0, tokenizer.cssParens - 1);
              if (tokenizer.cssAtRule) tokenizer.cssValue = false;
            }
            if (character === ']') tokenizer.cssAttribute = '';
            pushSourceBracket(tokens, tokenizer, character, false); index += 1; continue;
          }
          if (character === ';' || character === ',') {
            if (character === ';') { tokenizer.cssValue = false; tokenizer.cssAtRule = ''; tokenizer.cssParens = 0; }
            push('punctuation', character); index += 1; continue;
          }
          if (tokenizer.cssBlocks.at(-1) === 'keyframes') {
            const offset = line.slice(index).match(/^[^\s{},;/]+/)?.[0];
            if (offset) { push('text', offset); index += offset.length; continue; }
          }
          if (tokenizer.cssAttribute) {
            const comparison = sourceMatchAt(SOURCE_CSS_ATTRIBUTE_OPERATOR, line, index);
            if (comparison) { tokenizer.cssAttribute = 'value'; push('keyword', comparison); index += comparison.length; continue; }
            const word = sourceMatchAt(SOURCE_CSS_IDENTIFIER_PATTERN, line, index);
            if (word) {
              push(tokenizer.cssAttribute === 'name' ? 'attribute' : /^[is]$/i.test(word) ? 'keyword' : 'string', word);
              index += word.length; continue;
            }
          }
          if (character === ':' && declarations && !value && (tokenizer.cssAtRule || !sourceCssNestedSelector(line, index))) {
            tokenizer.cssValue = true; push('punctuation', ':'); index += 1; continue;
          }
          if (value) {
            if (line.startsWith('--', index)) {
              const custom = sourceMatchAt(SOURCE_CSS_IDENTIFIER_PATTERN, line, index);
              if (custom) { push('variable-other', custom); index += custom.length; continue; }
            }
            const color = sourceMatchAt(SOURCE_CSS_COLOR_PATTERN, line, index);
            if (color) { push('punctuation', '#'); push('keyword', color.slice(1)); index += color.length; continue; }
            const number = /[\d.+-]/.test(character) ? sourceMatchAt(SOURCE_CSS_NUMBER_PATTERN, line, index) : null;
            if (number && /\d/.test(number)) {
              push('number', number); index += number.length;
              const unit = sourceMatchAt(SOURCE_CSS_UNIT_PATTERN, line, index);
              if (unit) { push('unit', unit); index += unit.length; }
              continue;
            }
            if (line.startsWith('!important', index)) { push('keyword', '!important'); index += 10; continue; }
            // A slash is arithmetic only inside a function; `font: 12px/1.5` keeps the value color.
            if ('+-*/'.includes(character)) { push(character === '/' && !tokenizer.cssParens ? 'constant' : 'operator', character); index += 1; continue; }
            if (character === '!') { push('constant', character); index += 1; continue; }
          }
          if (character === '@') {
            const name = sourceMatchAt(SOURCE_CSS_IDENTIFIER_PATTERN, line, index + 1) ?? '';
            tokenizer.cssAtRule = name.toLowerCase();
            push('punctuation', '@'); push('keyword', name); index += name.length + 1; continue;
          }
          const identifier = sourceMatchAt(SOURCE_CSS_IDENTIFIER_PATTERN, line, index);
          if (identifier) {
            const following = line[index + identifier.length] ?? '';
            const custom = identifier.startsWith('--');
            const atRule = !value && tokenizer.cssAtRule;
            const type = following === '(' ? 'builtin-function'
              : atRule && /keyframes$/.test(atRule) ? 'parameter'
                : atRule && /^(?:and|not|only|or)$/i.test(identifier) ? 'keyword'
                  : value ? 'constant'
                    : declarations && sourceNextSignificant(line, index + identifier.length) === ':' && (atRule || !sourceCssNestedSelector(line, index)) ? (custom ? 'variable' : 'key')
                      : atRule ? 'constant' : 'tag';
            push(type, identifier); index += identifier.length;
            if (following === '(' && /^url$/i.test(identifier)) {
              // An unquoted url is one token up to its closing parenthesis.
              pushSourceBracket(tokens, tokenizer, '(', true); tokenizer.cssParens += 1; index += 1;
              const argument = line.slice(index).match(/^[^)"']+/)?.[0];
              if (argument) { push('parameter', argument); index += argument.length; }
            }
            continue;
          }
          if ((character === '.' || character === '#' || character === ':') && !value) {
            const colons = line.startsWith('::', index) ? '::' : character;
            const name = sourceMatchAt(SOURCE_CSS_IDENTIFIER_PATTERN, line, index + colons.length);
            if (name) {
              push('attribute-mark', colons); push('attribute', name); index += colons.length + name.length;
              if (/^nth-/i.test(name) && line[index] === '(') {
                const argument = sourceMatchAt(SOURCE_CSS_NTH_ARGUMENT, line, index + 1);
                pushSourceBracket(tokens, tokenizer, '(', true); tokenizer.cssParens += 1; index += 1;
                if (argument) { push('number', argument); index += argument.length; }
              }
              continue;
            }
          }
          if (character === '&' && !value) { push('tag', '&'); index += 1; continue; }
          if (character === '*' && !value) { push('tag', '*'); index += 1; continue; }
          if ('>+~'.includes(character) && !value) { push('operator', character); index += 1; continue; }
          push('text', character); index += 1;
        }
        return tokens;
      }

      function tokenizeMarkupTag(text, tokenizer, tokens) {
        const push = (type, value) => pushSourceToken(tokens, tokenizer, type, value);
        const opener = text.match(/^<[/!?]?/)?.[0] ?? '';
        push('tag-mark', opener);
        let index = opener.length;
        let tagSeen = false;
        while (index < text.length) {
          if (tokenizer.coloredTokens >= SOURCE_HIGHLIGHT_TOKEN_LIMIT) {
            tokenizer.truncated = true;
            push('plain', text.slice(index));
            break;
          }
          const character = text[index];
          if (character === '"' || character === "'") {
            const end = quotedSourceEnd(text, index, character);
            tokenizeMarkupEntities(text.slice(index, end), tokens, tokenizer, 'string'); index = end; continue;
          }
          if (character === '>' || (character === '/' && text[index + 1] === '>')) {
            const mark = character === '>' ? '>' : '/>';
            push('tag-mark', mark); index += mark.length; continue;
          }
          if (character === '=') {
            push('punctuation', '=');
            const unquoted = text.slice(index + 1).match(/^[^\s"'=<>`/]+/)?.[0];
            if (unquoted) push('string', unquoted);
            index += 1 + (unquoted?.length ?? 0); continue;
          }
          const identifier = sourceMatchAt(SOURCE_MARKUP_IDENTIFIER_PATTERN, text, index);
          if (identifier) {
            push(tagSeen ? 'attribute' : 'tag', identifier);
            tagSeen = true; index += identifier.length; continue;
          }
          push(/\s/.test(character) ? 'plain' : 'text', character); index += 1;
        }
      }

      function tokenizeMarkupSourceLine(line, tokenizer, from = 0, stop = line.length, tokens = []) {
        const push = (type, text) => pushSourceToken(tokens, tokenizer, type, text);
        let index = from;
        tokenizer.cursor = from;
        while (index < stop) {
          if (tokenizer.coloredTokens >= SOURCE_HIGHLIGHT_TOKEN_LIMIT) {
            tokenizer.truncated = true;
            push('plain', line.slice(index));
            break;
          }
          if (tokenizer.state === 'markup-comment') {
            const end = line.indexOf('-->', index);
            if (end === -1) { push('comment', line.slice(index)); break; }
            push('comment', line.slice(index, end)); push('comment-mark', '-->');
            tokenizer.state = 'code'; index = end + 3; continue;
          }
          const tag = line.indexOf('<', index);
          if (tag === -1) {
            tokenizeMarkupText(line.slice(index), tokens, tokenizer); break;
          }
          tokenizeMarkupText(line.slice(index, tag), tokens, tokenizer);
          if (line.startsWith('<!--', tag)) {
            push('comment-mark', '<!--');
            const end = line.indexOf('-->', tag + 4);
            if (end === -1) { push('comment', line.slice(tag + 4)); tokenizer.state = 'markup-comment'; break; }
            push('comment', line.slice(tag + 4, end)); push('comment-mark', '-->');
            index = end + 3; continue;
          }
          const end = line.indexOf('>', tag + 1);
          if (end === -1) {
            tokenizeMarkupTag(line.slice(tag), tokenizer, tokens); break;
          }
          tokenizeMarkupTag(line.slice(tag, end + 1), tokenizer, tokens);
          index = end + 1;
        }
        return tokens;
      }

      function tokenizeMarkupText(text, tokens, tokenizer) {
        tokenizeMarkupEntities(text, tokens, tokenizer, 'text');
      }

      // `&` and the closing `;` of a named reference are punctuation; a numeric reference keeps its `#` and `;` in the keyword color.
      function tokenizeMarkupEntities(text, tokens, tokenizer, type) {
        const run = value => {
          if (type !== 'text') { pushSourceToken(tokens, tokenizer, type, value); return; }
          const lead = value.match(/^\s*/)[0].length, trail = value.slice(lead).match(/\s*$/)[0].length;
          pushSourceToken(tokens, tokenizer, 'plain', value.slice(0, lead));
          pushSourceToken(tokens, tokenizer, 'text', value.slice(lead, value.length - trail));
          pushSourceToken(tokens, tokenizer, 'plain', value.slice(value.length - trail));
        };
        let last = 0;
        for (const match of text.matchAll(/&(#\d+;|#x[\da-fA-F]+;|[A-Za-z][\w]*(;))/g)) {
          run(text.slice(last, match.index));
          pushSourceToken(tokens, tokenizer, 'punctuation', '&');
          if (match[2]) {
            pushSourceToken(tokens, tokenizer, 'escape', match[1].slice(0, -1));
            pushSourceToken(tokens, tokenizer, 'punctuation', ';');
          } else {
            pushSourceToken(tokens, tokenizer, 'escape', match[1]);
          }
          last = match.index + match[0].length;
        }
        run(text.slice(last));
      }

      function tokenizeWasmSourceLine(line, tokenizer, from = 0, stop = line.length, tokens = []) {
        let index = from;
        tokenizer.cursor = from;
        while (index < stop) {
          if (tokenizer.coloredTokens >= SOURCE_HIGHLIGHT_TOKEN_LIMIT) {
            tokenizer.truncated = true;
            pushSourceToken(tokens, tokenizer, 'plain', line.slice(index));
            break;
          }
          if (line.startsWith(';;', index)) {
            pushSourceToken(tokens, tokenizer, 'comment', line.slice(index)); break;
          }
          if (line[index] === '|') {
            pushSourceToken(tokens, tokenizer, 'string', line.slice(index)); break;
          }
          const value = sourceMatchAt(SOURCE_WASM_VALUE_PATTERN, line, index);
          const identifier = sourceMatchAt(SOURCE_WASM_IDENTIFIER_PATTERN, line, index);
          if (value) {
            pushSourceToken(tokens, tokenizer, 'number', value); index += value.length; continue;
          }
          if (identifier) {
            pushSourceToken(tokens, tokenizer, /^(?:i32|i64|f32|f64|v128|funcref|externref)$/.test(identifier) ? 'type' : 'keyword', identifier);
            index += identifier.length; continue;
          }
          pushSourceToken(tokens, tokenizer, 'plain', line[index]); index += 1;
        }
        return tokens;
      }

      function sourceSyntaxTokens(line, tokenizer) {
        if (!line) return [{type: 'plain', text: ' '}];
        if (tokenizer.truncated) return [{type: 'plain', text: line}];
        if (tokenizer.language === 'javascript' || tokenizer.language === 'json') return tokenizeCodeSourceLine(line, tokenizer);
        if (tokenizer.language === 'css') return tokenizeCssSourceLine(line, tokenizer);
        if (tokenizer.language === 'markup') return tokenizeMarkupSourceLine(line, tokenizer);
        if (tokenizer.language === 'wasm' || tokenizer.language === 'bytes') return tokenizeWasmSourceLine(line, tokenizer);
        return [{type: 'plain', text: line}];
      }

      function sourceLineTokenizer(language) {
        if (language === 'javascript' || language === 'json') return tokenizeCodeSourceLine;
        if (language === 'css') return tokenizeCssSourceLine;
        if (language === 'markup') return tokenizeMarkupSourceLine;
        if (language === 'wasm' || language === 'bytes') return tokenizeWasmSourceLine;
        return null;
      }

      // Lexer state saved every 4 Ki units of one document lets a window start
      // tokenizing near its first row, so later and column-clipped windows keep
      // their colors. advance() extends the checkpoints in bounded steps.
      const SOURCE_CHECKPOINT_UNITS = 4096;
      // About 10 ms of lexing per background step; a render lexes at most 256 Ki ahead.
      const SOURCE_COLOR_SLICE_UNITS = 64 * 1024;
      const SOURCE_COLOR_SYNC_UNITS = 256 * 1024;
      // `prefix` ({highlighter, offset}) seeds a layout page with the original's lexer state where it begins.
      function createSourceHighlighter(source, index, prefix = null) {
        const language = sourceSyntaxLanguage(source);
        const tokenize = sourceLineTokenizer(language);
        const {text, length} = index;
        const checkpoints = [{offset: 0, lineStart: 0, state: createSourceTokenizer(source)}];
        let builder = createSourceTokenizer(source), seeded = !tokenize || !prefix;
        let lineStart = 0, lineText = null, column = 0, frontier = 0, done = !tokenize || length === 0;
        const lineEnd = start => {const end = text.indexOf('\n', start); return end < 0 || end > length ? length : end;};
        const checkpointAt = offset => {
          let low = 0, high = checkpoints.length - 1;
          while (low < high) {const middle = (low + high + 1) >> 1; if (checkpoints[middle].offset <= offset) low = middle; else high = middle - 1;}
          return checkpoints[low];
        };
        const ready = rows => {
          const first = rows.find(row => row.fullLength);
          return seeded && (done || !first || first.offset + first.columnStart <= frontier);
        };
        return {
          language,
          done: () => seeded && done,
          ready,
          // null while the checkpoints are behind `offset`.
          stateAt(offset) {
            if (!tokenize) return createSourceTokenizer(source);
            if (!seeded || (!done && frontier < offset)) return null;
            const checkpoint = checkpointAt(offset);
            const current = sourceTokenizerSnapshot(checkpoint.state);
            let at = checkpoint.lineStart, position = checkpoint.offset;
            while (position < offset) {
              const end = lineEnd(at), stop = Math.min(end, offset);
              if (position < stop) tokenize(text.slice(at, end), current, position - at, stop - at, null);
              if (stop < end || end >= length) break;
              at = end + 1; position = at;
            }
            return Object.assign(current, {cursor: 0, clipStart: 0, clipEnd: Infinity, coloredTokens: 0});
          },
          // Tokenizes about `units` more of the document; true once it reached the end.
          advance(units) {
            if (!seeded) {
              const state = prefix.highlighter.stateAt(prefix.offset);
              if (!state) {prefix.highlighter.advance(units); return false;}
              checkpoints[0].state = state;
              builder = sourceTokenizerSnapshot(state);
              seeded = true;
            }
            let spent = 0;
            while (!done && spent < units) {
              lineText ??= text.slice(lineStart, lineEnd(lineStart));
              const boundary = (Math.floor(frontier / SOURCE_CHECKPOINT_UNITS) + 1) * SOURCE_CHECKPOINT_UNITS;
              if (column < lineText.length) {
                tokenize(lineText, builder, column, Math.min(lineText.length, boundary - lineStart), null);
                spent += builder.cursor - column;
                column = builder.cursor;
                frontier = lineStart + column;
              }
              if (column >= lineText.length) {
                if (lineStart + lineText.length >= length) {done = true; frontier = length; break;}
                lineStart += lineText.length + 1; lineText = null; column = 0; frontier = lineStart; spent += 1;
              }
              if (frontier >= boundary) checkpoints.push({offset: frontier, lineStart, state: sourceTokenizerSnapshot(builder)});
            }
            return done;
          },
          // Tokens for each mounted excerpt, or null while the checkpoints are behind the window.
          rows(windowRows) {
            if (!tokenize) return {rows: windowRows.map(row => row.text ? [{type: 'plain', text: row.text}] : []), truncated: false};
            if (!ready(windowRows)) return null;
            let current = null, position = 0, lineAt = 0, colored = 0, truncated = false;
            const rows = windowRows.map(row => {
              if (!row.text) return [];
              if (truncated) return [{type: 'plain', text: row.text}];
              const start = row.offset + row.columnStart;
              const checkpoint = checkpointAt(start);
              if (!current || position > start || checkpoint.offset > position) {
                current = sourceTokenizerSnapshot(checkpoint.state); position = checkpoint.offset; lineAt = checkpoint.lineStart;
              }
              while (lineAt < row.offset) {
                const end = lineEnd(lineAt);
                if (position < end) tokenize(text.slice(lineAt, end), current, position - lineAt, end - lineAt, null);
                lineAt = end + 1; position = lineAt;
              }
              Object.assign(current, {clipStart: row.columnStart, clipEnd: row.columnEnd, coloredTokens: colored});
              const tokens = tokenize(text.slice(row.offset, row.offset + row.fullLength), current, position - row.offset, row.columnEnd, []);
              colored = current.coloredTokens; truncated = current.truncated;
              position = row.offset + current.cursor;
              Object.assign(current, {clipStart: 0, clipEnd: Infinity});
              return tokens;
            });
            return {rows, truncated};
          }
        };
      }

      function derivedSegmentAt(segments, derivedOffset) {
        let low = 0;
        let high = segments.length - 1;
        while (low <= high) {
          const middle = (low + high) >> 1;
          const segment = segments[middle];
          if (derivedOffset < segment.derived_start) high = middle - 1;
          else if (derivedOffset >= segment.derived_end) low = middle + 1;
          else return segment;
        }
        return null;
      }

      function derivedOriginalOffset(segments, derivedOffset) {
        const segment = derivedSegmentAt(segments, derivedOffset);
        if (!segment || segment.original_start === null || segment.original_start === undefined) return null;
        if (segment.kind === 'synthetic' || segment.kind === 'replacement') return segment.original_start;
        return segment.original_start + (derivedOffset - segment.derived_start);
      }

      // Wire offsets name their encoding. JavaScript and CDP use UTF-16 units.
      // Build maps only for segment boundaries, in one scan of each source.
      function sourceOffsetBoundaries(text, offsets, unit) {
        const wanted = new Set(offsets);
        const result = new Map();
        let wire = 0;
        let utf16 = 0;
        for (const character of text) {
          if (wanted.has(wire)) result.set(wire, utf16);
          const point = character.codePointAt(0);
          wire += unit === 'unicode-code-point' ? 1 : point <= 0x7f ? 1 : point <= 0x7ff ? 2 : point <= 0xffff ? 3 : 4;
          utf16 += character.length;
        }
        if (wanted.has(wire)) result.set(wire, utf16);
        return result;
      }

      function sourceSegmentsUTF16(original, derived, segments, unit) {
        if (unit === 'utf-16-code-unit') return segments;
        // Legacy Python documents used code-point offsets without a unit tag.
        unit = unit ?? 'unicode-code-point';
        if (!['unicode-code-point', 'utf-8-byte'].includes(unit)) return [];
        const originals = sourceOffsetBoundaries(original, segments.flatMap(s => [s.original_start, s.original_end]), unit);
        const deriveds = sourceOffsetBoundaries(derived, segments.flatMap(s => [s.derived_start, s.derived_end]), unit);
        return segments.map(segment => ({...segment,
          original_start: originals.get(segment.original_start), original_end: originals.get(segment.original_end),
          derived_start: deriveds.get(segment.derived_start), derived_end: deriveds.get(segment.derived_end)
        }));
      }
