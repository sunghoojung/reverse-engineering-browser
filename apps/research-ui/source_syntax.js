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

      function sourceName(source) {
        if (!source.url) return source.source_type === 'script' ? `(anonymous ${source.script_id})` : `artifact-${source.artifact_id}`;
        try {
          const path = new URL(source.url).pathname;
          return path.split('/').filter(Boolean).at(-1) || source.url;
        } catch {
          return source.url.split('/').filter(Boolean).at(-1) || source.url;
        }
      }

      function formatByteSize(bytes) {
        if (bytes < 1024) return `${bytes} bytes`;
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
        return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
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

      const SOURCE_PRETTY_INPUT_LIMIT = 2 * 1024 * 1024;
      const SOURCE_PRETTY_OUTPUT_LIMIT = 4 * 1024 * 1024;
      const SOURCE_PRETTY_TOKEN_LIMIT = 250000;
      const SOURCE_PRETTY_SEGMENT_LIMIT = 500000;
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

      function sourcePrettySupported(source) {
        return SOURCE_PRETTY_LANGUAGES.has(sourceSyntaxLanguage(source));
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

      function sourcePrettyTokens(value, language) {
        const tokens = [];
        let index = 0;
        let previous = null;
        const push = (kind, start, end) => {
          if (tokens.length >= SOURCE_PRETTY_TOKEN_LIMIT) throw new RangeError('Pretty print token limit reached');
          const token = {kind, start, end, text: value.slice(start, end)};
          tokens.push(token);
          if (kind !== 'whitespace' && kind !== 'comment') previous = token;
        };
        while (index < value.length) {
          const start = index;
          const character = value[index];
          const next = value[index + 1] ?? '';
          if (/\s/.test(character)) {
            while (index < value.length && /\s/.test(value[index])) index += 1;
            push('whitespace', start, index);
            continue;
          }
          if ((language === 'javascript' || language === 'css') && character === '/' && next === '*') {
            const close = value.indexOf('*/', index + 2);
            index = close === -1 ? value.length : close + 2;
            push('comment', start, index);
            continue;
          }
          if (language === 'javascript' && character === '/' && next === '/') {
            const close = value.indexOf('\n', index + 2);
            index = close === -1 ? value.length : close;
            push('line-comment', start, index);
            continue;
          }
          if (character === '"' || character === "'" || (language === 'javascript' && character === '`')) {
            index = sourcePrettyQuotedEnd(value, index, character);
            push('literal', start, index);
            continue;
          }
          if (language === 'javascript' && character === '/' && next !== '/' && next !== '*' && sourcePrettyMayStartRegex(previous)) {
            const end = sourcePrettyRegexEnd(value, index);
            if (end > index + 1) {
              index = end;
              push('literal', start, index);
              continue;
            }
          }
          if (/[A-Za-z_$]/.test(character)) {
            index += 1;
            while (/[\w$]/.test(value[index] ?? '')) index += 1;
            push('word', start, index);
            continue;
          }
          if (/\d/.test(character) || (character === '.' && /\d/.test(next))) {
            SOURCE_PRETTY_NUMBER_PATTERN.lastIndex = index;
            index = SOURCE_PRETTY_NUMBER_PATTERN.exec(value)?.index === start
              ? SOURCE_PRETTY_NUMBER_PATTERN.lastIndex
              : index + 1;
            push('number', start, index);
            continue;
          }
          const operator = SOURCE_PRETTY_OPERATORS.find(candidate => value.startsWith(candidate, index));
          index += operator?.length ?? 1;
          push('operator', start, index);
        }
        return tokens;
      }

      function createSourcePrettyWriter(value) {
        let text = '';
        const segments = [];
        let indent = 0;
        let lineStart = true;
        const append = (kind, chunk, originalStart, originalEnd) => {
          if (!chunk) return;
          if (text.length + chunk.length > SOURCE_PRETTY_OUTPUT_LIMIT) throw new RangeError('Pretty-print output exceeds 4 MB');
          const derivedStart = text.length;
          text += chunk;
          const segment = {kind, original_start: originalStart, original_end: originalEnd, derived_start: derivedStart, derived_end: text.length};
          const previous = segments.at(-1);
          const contiguous = previous && previous.kind === kind && previous.derived_end === segment.derived_start &&
            (kind === 'synthetic' || previous.original_end === segment.original_start);
          if (contiguous) {
            previous.original_end = segment.original_end;
            previous.derived_end = segment.derived_end;
          } else {
            if (segments.length >= SOURCE_PRETTY_SEGMENT_LIMIT) throw new RangeError('Pretty print mapping limit reached');
            segments.push(segment);
          }
          lineStart = chunk.endsWith('\n');
        };
        const synthetic = (chunk, anchor) => append('synthetic', chunk, anchor, anchor);
        const original = token => {
          if (lineStart) synthetic('  '.repeat(Math.min(indent, 32)), token.start);
          append('verbatim', token.text, token.start, token.end);
        };
        const space = anchor => {
          if (!lineStart && text && !/\s$/.test(text)) synthetic(' ', anchor);
        };
        const newline = anchor => {
          if (!text || text.endsWith('\n')) return;
          synthetic('\n', anchor);
          lineStart = true;
        };
        return {
          original, space, newline,
          indent: () => { indent += 1; },
          outdent: () => { indent = Math.max(0, indent - 1); },
          isLineStart: () => lineStart,
          finish: () => {
            while (segments.at(-1)?.kind === 'synthetic') {
              const segment = segments.at(-1);
              const chunk = text.slice(segment.derived_start, segment.derived_end);
              const trimmed = chunk.replace(/\s+$/, '');
              if (trimmed === chunk) break;
              text = text.slice(0, segment.derived_start) + trimmed;
              segment.derived_end = text.length;
              if (segment.derived_start === segment.derived_end) segments.pop();
            }
            return {text, segments};
          }
        };
      }

      function prettyPrintStructuredSource(value, language) {
        const tokens = sourcePrettyTokens(value, language);
        const writer = createSourcePrettyWriter(value);
        let parens = 0;
        let brackets = 0;
        let braces = 0;
        const multilineBrackets = [];
        let forDepth = null;
        let previous = null;
        let pendingFor = false;
        const significant = tokens.filter(token => token.kind !== 'whitespace');
        for (let index = 0; index < significant.length; index += 1) {
          const token = significant[index];
          const next = significant[index + 1] ?? null;
          if (token.kind === 'line-comment') {
            writer.space(token.start); writer.original(token); writer.newline(token.end); previous = token; continue;
          }
          if (token.kind === 'comment') {
            writer.space(token.start); writer.original(token);
            if (token.text.includes('\n') || next) writer.newline(token.end);
            previous = token; continue;
          }
          if (token.kind === 'word') {
            if (token.text === 'for') pendingFor = true;
            if (previous && ['word', 'number', 'literal'].includes(previous.kind)) writer.space(token.start);
            if (previous?.text === ')' || previous?.text === ']') writer.space(token.start);
            writer.original(token);
            previous = token;
            continue;
          }
          if (token.kind === 'number' || token.kind === 'literal') {
            if (previous && ['word', 'number', 'literal'].includes(previous.kind)) writer.space(token.start);
            writer.original(token);
            previous = token;
            continue;
          }
          const operator = token.text;
          if (operator === '{') {
            writer.space(token.start); writer.original(token); braces += 1;
            if (next?.text !== '}') { writer.indent(); writer.newline(token.end); }
          } else if (operator === '}') {
            if (previous?.text !== '{') writer.outdent();
            if (!writer.isLineStart() && previous?.text !== '{') writer.newline(token.start);
            writer.original(token); braces = Math.max(0, braces - 1);
            if (next && ![';', ',', ')', ']', '.', '?.'].includes(next.text) && !['else', 'catch', 'finally', 'while'].includes(next.text)) writer.newline(token.end);
            else if (next && ['else', 'catch', 'finally'].includes(next.text)) writer.space(token.end);
          } else if (operator === '(') {
            if (previous?.kind === 'word' && SOURCE_PRETTY_CONTROL_WORDS.has(previous.text)) writer.space(token.start);
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
            if (multiline && next?.text !== ']') { writer.indent(); writer.newline(token.end); }
          } else if (operator === ']') {
            const multiline = multilineBrackets.pop() ?? false;
            if (multiline && previous?.text !== '[') { writer.outdent(); writer.newline(token.start); }
            writer.original(token); brackets = Math.max(0, brackets - 1);
          } else if (operator === ';') {
            writer.original(token);
            if (forDepth === null) writer.newline(token.end); else writer.space(token.end);
          } else if (operator === ',') {
            writer.original(token);
            if (language === 'json' || (language === 'javascript' && parens === 0 && (braces > 0 || brackets > 0))) writer.newline(token.end);
            else writer.space(token.end);
          } else if (operator === ':') {
            writer.original(token); writer.space(token.end);
          } else if (operator === '.') {
            writer.original(token);
          } else if (operator === '?.') {
            writer.original(token);
          } else if (['++', '--', '!', '~'].includes(operator)) {
            writer.original(token);
          } else if (operator === '?') {
            writer.space(token.start); writer.original(token); writer.space(token.end);
          } else {
            writer.space(token.start); writer.original(token); writer.space(token.end);
          }
          previous = token;
        }
        return writer.finish();
      }

      function prettyPrintCssSource(value) {
        const tokens = sourcePrettyTokens(value, 'css').filter(token => token.kind !== 'whitespace');
        const writer = createSourcePrettyWriter(value);
        let depth = 0;
        for (let index = 0; index < tokens.length; index += 1) {
          const token = tokens[index];
          const next = tokens[index + 1] ?? null;
          if (token.kind === 'comment') {
            writer.original(token); writer.newline(token.end); continue;
          }
          if (token.kind !== 'operator') {
            if (index && ![':', '(', '[', '.', '#', '-', '@'].includes(tokens[index - 1]?.text)) writer.space(token.start);
            writer.original(token); continue;
          }
          if (token.text === '{') {
            writer.space(token.start); writer.original(token); depth += 1;
            if (next?.text !== '}') { writer.indent(); writer.newline(token.end); }
          } else if (token.text === '}') {
            if (tokens[index - 1]?.text !== '{') writer.outdent();
            writer.newline(token.start); writer.original(token); depth = Math.max(0, depth - 1);
            if (next) writer.newline(token.end);
          } else if (token.text === ';') {
            writer.original(token); writer.newline(token.end);
          } else if (token.text === ':') {
            writer.original(token); writer.space(token.end);
          } else if (token.text === ',' && depth === 0) {
            writer.original(token); writer.newline(token.end);
          } else {
            writer.original(token);
          }
        }
        return writer.finish();
      }

      function sourcePrettyMarkupTokens(value) {
        const tokens = [];
        const push = token => {
          if (tokens.length >= SOURCE_PRETTY_TOKEN_LIMIT) throw new RangeError('Pretty print token limit reached');
          tokens.push(token);
        };
        let index = 0;
        while (index < value.length) {
          if (value[index] !== '<') {
            const end = value.indexOf('<', index);
            const boundary = end === -1 ? value.length : end;
            const leading = value.slice(index, boundary).search(/\S/);
            if (leading !== -1) {
              const start = index + leading;
              const trailing = value.slice(start, boundary).match(/\s*$/)?.[0].length ?? 0;
              push({kind: 'text', start, end: boundary - trailing, text: value.slice(start, boundary - trailing)});
            }
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
          push({kind: 'tag', start, end: index, text});
          const rawTag = text.match(/^<\s*(script|style)\b/i)?.[1]?.toLowerCase();
          if (rawTag && !/\/\s*>$/.test(text)) {
            const close = value.toLowerCase().indexOf(`</${rawTag}`, index);
            if (close !== -1) {
              const leading = value.slice(index, close).search(/\S/);
              if (leading !== -1) {
                const rawStart = index + leading;
                const trailing = value.slice(rawStart, close).match(/\s*$/)?.[0].length ?? 0;
                push({kind: 'raw', start: rawStart, end: close - trailing, text: value.slice(rawStart, close - trailing)});
              }
              index = close;
            }
          }
        }
        return tokens;
      }

      function prettyPrintMarkupSource(value) {
        const tokens = sourcePrettyMarkupTokens(value);
        const writer = createSourcePrettyWriter(value);
        const voidTag = /^<\s*(?:area|base|br|col|embed|hr|img|input|link|meta|param|source|track|wbr)\b/i;
        for (const token of tokens) {
          if (token.kind !== 'tag') {
            writer.original(token); writer.newline(token.end); continue;
          }
          const closing = /^<\s*\//.test(token.text);
          const declaration = /^<\s*[!?]/.test(token.text);
          const selfClosing = /\/\s*>$/.test(token.text) || voidTag.test(token.text) || declaration;
          if (closing) writer.outdent();
          writer.original(token);
          writer.newline(token.end);
          if (!closing && !selfClosing) writer.indent();
        }
        return writer.finish();
      }

      function prettyPrintSource(source, value) {
        const language = sourceSyntaxLanguage(source);
        if (!SOURCE_PRETTY_LANGUAGES.has(language)) return {error: `Pretty print does not support ${sourceSyntaxLabel(language)}.`};
        if (value.length > SOURCE_PRETTY_INPUT_LIMIT) return {error: 'Pretty print is limited to the first 2 MB.'};
        try {
          const formatted = language === 'markup' ? prettyPrintMarkupSource(value)
            : language === 'css' ? prettyPrintCssSource(value)
              : prettyPrintStructuredSource(value, language);
          return {...formatted, offset_unit: 'utf-16-code-unit', language, changed: formatted.text !== value};
        } catch (error) {
          return {error: error instanceof Error ? error.message : 'Pretty print failed.'};
        }
      }

      const SOURCE_HIGHLIGHT_TOKEN_LIMIT = 50000;
      const SOURCE_CONTROL_WORDS = new Set([
        'break', 'case', 'catch', 'continue', 'debugger', 'default', 'do', 'else',
        'finally', 'for', 'if', 'return', 'switch', 'throw', 'try', 'while', 'with',
        'yield', 'await'
      ]);
      const SOURCE_KEYWORDS = new Set([
        'as', 'async', 'class', 'const', 'delete', 'enum', 'export', 'extends',
        'from', 'function', 'get', 'implements', 'import', 'in', 'instanceof',
        'interface', 'let', 'new', 'of', 'package', 'private', 'protected', 'public',
        'set', 'static', 'super', 'this', 'typeof', 'var', 'void'
      ]);
      const SOURCE_LITERALS = new Set([
        'false', 'Infinity', 'NaN', 'null', 'true', 'undefined'
      ]);
      const SOURCE_NUMBER_PATTERN = /(?:0[xX][\da-fA-F]+|0[bB][01]+|0[oO][0-7]+|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?n?)/y;
      const SOURCE_IDENTIFIER_PATTERN = /[A-Za-z_$][\w$]*/y;
      const SOURCE_CSS_COLOR_PATTERN = /#[\da-fA-F]{3,8}\b/y;
      const SOURCE_CSS_NUMBER_PATTERN = /(?:\d+\.?\d*|\.\d+)(?:[a-z%]+)?/iy;
      const SOURCE_CSS_IDENTIFIER_PATTERN = /@?-{0,2}[A-Za-z_][\w-]*/y;
      const SOURCE_MARKUP_IDENTIFIER_PATTERN = /[A-Za-z_:][\w:.-]*/y;
      const SOURCE_WASM_VALUE_PATTERN = /(?:[\da-fA-F]{8}|[\da-fA-F]{2})(?=\s|$)/y;
      const SOURCE_WASM_IDENTIFIER_PATTERN = /\$?[A-Za-z_][\w.$-]*/y;

      function sourceMatchAt(pattern, value, index) {
        pattern.lastIndex = index;
        return pattern.exec(value)?.[0] ?? null;
      }

      function sourceNextSignificant(value, index) {
        while (/\s/.test(value[index] ?? '')) index += 1;
        return value[index] ?? '';
      }

      function sourcePreviousSignificant(value, index) {
        for (let previous = index - 1; previous >= 0; previous -= 1) {
          if (!/\s/.test(value[previous])) return value[previous];
        }
        return '';
      }

      function sourceIdentifierStart(character) {
        const code = character.charCodeAt(0);
        return character === '$' || character === '_' ||
          (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
      }

      function sourceDigit(character) {
        const code = character.charCodeAt(0);
        return code >= 48 && code <= 57;
      }

      function sourceCodeTokenStart(value, index, json) {
        const character = value[index] ?? '';
        const next = value[index + 1] ?? '';
        return sourceIdentifierStart(character) || sourceDigit(character) ||
          (character === '.' && sourceDigit(next)) || character === '/' ||
          character === '"' || character === "'" || (!json && character === '`');
      }

      function sourceCssTokenStart(value, index) {
        const character = value[index] ?? '';
        const next = value[index + 1] ?? '';
        return sourceIdentifierStart(character) || sourceDigit(character) ||
          (character === '.' && sourceDigit(next)) ||
          ['#', '/', '"', "'", '@', '-'].includes(character);
      }

      function sourceSyntaxLanguage(source) {
        if (!source) return 'text';
        const mime = String(source.mime_type ?? '').toLowerCase().split(';', 1)[0];
        const name = sourceName(source).toLowerCase();
        if (source.kind === 'wasm' || mime === 'application/wasm') return 'wasm';
        if (source.kind === 'javascript' || /(?:java|ecma)script/.test(mime) || /\.[cm]?jsx?$/.test(name)) return 'javascript';
        if (source.kind === 'source_map' || /json/.test(mime) || /\.(?:json|map)$/.test(name)) return 'json';
        if (/css/.test(mime) || /\.css$/.test(name)) return 'css';
        if (/(?:html|xml|svg)/.test(mime) || /\.(?:html?|xml|svg)$/.test(name)) return 'markup';
        return 'text';
      }

      function sourceSyntaxLabel(language) {
        return {javascript: 'JavaScript', json: 'JSON', css: 'CSS', markup: 'HTML', wasm: 'WebAssembly hex', text: 'Plain text'}[language];
      }

      function createSourceTokenizer(source) {
        return {
          language: sourceSyntaxLanguage(source),
          state: 'code',
          coloredTokens: 0,
          truncated: false
        };
      }

      function pushSourceToken(tokens, tokenizer, type, text) {
        if (!text) return;
        let boundedType = type;
        if (type !== 'plain') {
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

      function tokenizeCodeSourceLine(line, tokenizer) {
        const tokens = [];
        const json = tokenizer.language === 'json';
        let index = 0;
        while (index < line.length) {
          if (tokenizer.coloredTokens >= SOURCE_HIGHLIGHT_TOKEN_LIMIT) {
            tokenizer.truncated = true;
            pushSourceToken(tokens, tokenizer, 'plain', line.slice(index));
            break;
          }
          if (tokenizer.state === 'block-comment') {
            const end = line.indexOf('*/', index);
            if (end === -1) { pushSourceToken(tokens, tokenizer, 'comment', line.slice(index)); break; }
            pushSourceToken(tokens, tokenizer, 'comment', line.slice(index, end + 2));
            tokenizer.state = 'code'; index = end + 2; continue;
          }
          if (tokenizer.state === 'template') {
            const end = quotedSourceEnd(line, index - 1, '`');
            pushSourceToken(tokens, tokenizer, 'string', line.slice(index, end));
            if (end < line.length || line[end - 1] === '`') tokenizer.state = 'code';
            index = end; continue;
          }
          const character = line[index];
          const next = line[index + 1] ?? '';
          if (character === '/' && next === '/') {
            pushSourceToken(tokens, tokenizer, 'comment', line.slice(index)); break;
          }
          if (character === '/' && next === '*') {
            const end = line.indexOf('*/', index + 2);
            if (end === -1) {
              pushSourceToken(tokens, tokenizer, 'comment', line.slice(index));
              tokenizer.state = 'block-comment'; break;
            }
            pushSourceToken(tokens, tokenizer, 'comment', line.slice(index, end + 2));
            index = end + 2; continue;
          }
          if (character === '"' || character === "'" || (!json && character === '`')) {
            const end = quotedSourceEnd(line, index, character);
            const nextSignificant = sourceNextSignificant(line, end);
            const type = json && nextSignificant === ':' ? 'property' : 'string';
            pushSourceToken(tokens, tokenizer, type, line.slice(index, end));
            if (character === '`' && line[end - 1] !== '`') tokenizer.state = 'template';
            index = end; continue;
          }
          if (!sourceCodeTokenStart(line, index, json)) {
            const start = index;
            do { index += 1; } while (index < line.length && !sourceCodeTokenStart(line, index, json));
            pushSourceToken(tokens, tokenizer, 'plain', line.slice(start, index));
            continue;
          }
          const number = sourceMatchAt(SOURCE_NUMBER_PATTERN, line, index);
          if (number) {
            pushSourceToken(tokens, tokenizer, 'number', number); index += number.length; continue;
          }
          const identifier = sourceMatchAt(SOURCE_IDENTIFIER_PATTERN, line, index);
          if (identifier) {
            const following = sourceNextSignificant(line, index + identifier.length);
            const type = SOURCE_CONTROL_WORDS.has(identifier) ? 'control'
              : SOURCE_KEYWORDS.has(identifier) ? 'keyword'
                : SOURCE_LITERALS.has(identifier) ? 'number'
                    : following === '(' ? 'function'
                      : /^[A-Z]/.test(identifier) ? 'type'
                        : 'property';
            pushSourceToken(tokens, tokenizer, type, identifier);
            index += identifier.length; continue;
          }
          const previous = sourcePreviousSignificant(line, index);
          if (!json && character === '/' && next && !/[/\s]/.test(next) &&
              (!previous || /[([{=,:;!&|?+\-*%^~<>]/.test(previous))) {
            const end = regexpSourceEnd(line, index);
            if (end > index + 1) {
              pushSourceToken(tokens, tokenizer, 'regexp', line.slice(index, end));
              index = end; continue;
            }
          }
          pushSourceToken(tokens, tokenizer, 'plain', character);
          index += 1;
        }
        return tokens;
      }

      function tokenizeCssSourceLine(line, tokenizer) {
        const tokens = [];
        let index = 0;
        while (index < line.length) {
          if (tokenizer.coloredTokens >= SOURCE_HIGHLIGHT_TOKEN_LIMIT) {
            tokenizer.truncated = true;
            pushSourceToken(tokens, tokenizer, 'plain', line.slice(index));
            break;
          }
          if (tokenizer.state === 'block-comment') {
            const end = line.indexOf('*/', index);
            if (end === -1) { pushSourceToken(tokens, tokenizer, 'comment', line.slice(index)); break; }
            pushSourceToken(tokens, tokenizer, 'comment', line.slice(index, end + 2));
            tokenizer.state = 'code'; index = end + 2; continue;
          }
          if (line.startsWith('/*', index)) {
            const end = line.indexOf('*/', index + 2);
            if (end === -1) {
              pushSourceToken(tokens, tokenizer, 'comment', line.slice(index));
              tokenizer.state = 'block-comment'; break;
            }
            pushSourceToken(tokens, tokenizer, 'comment', line.slice(index, end + 2));
            index = end + 2; continue;
          }
          const character = line[index];
          if (character === '"' || character === "'") {
            const end = quotedSourceEnd(line, index, character);
            pushSourceToken(tokens, tokenizer, 'string', line.slice(index, end));
            index = end; continue;
          }
          if (!sourceCssTokenStart(line, index)) {
            const start = index;
            do { index += 1; } while (index < line.length && !sourceCssTokenStart(line, index));
            pushSourceToken(tokens, tokenizer, 'plain', line.slice(start, index));
            continue;
          }
          const color = sourceMatchAt(SOURCE_CSS_COLOR_PATTERN, line, index);
          const number = sourceMatchAt(SOURCE_CSS_NUMBER_PATTERN, line, index);
          if (color || number) {
            const value = color || number;
            pushSourceToken(tokens, tokenizer, 'number', value); index += value.length; continue;
          }
          const identifier = sourceMatchAt(SOURCE_CSS_IDENTIFIER_PATTERN, line, index);
          if (identifier) {
            const following = sourceNextSignificant(line, index + identifier.length);
            pushSourceToken(tokens, tokenizer, identifier.startsWith('@') ? 'keyword' : following === ':' ? 'property' : 'type', identifier);
            index += identifier.length; continue;
          }
          pushSourceToken(tokens, tokenizer, 'plain', character); index += 1;
        }
        return tokens;
      }

      function tokenizeMarkupTag(text, tokenizer, tokens) {
        let index = 0;
        let tagSeen = false;
        while (index < text.length) {
          if (tokenizer.coloredTokens >= SOURCE_HIGHLIGHT_TOKEN_LIMIT) {
            tokenizer.truncated = true;
            pushSourceToken(tokens, tokenizer, 'plain', text.slice(index));
            break;
          }
          const character = text[index];
          if (character === '"' || character === "'") {
            const end = quotedSourceEnd(text, index, character);
            pushSourceToken(tokens, tokenizer, 'string', text.slice(index, end));
            index = end; continue;
          }
          const identifier = sourceMatchAt(SOURCE_MARKUP_IDENTIFIER_PATTERN, text, index);
          if (identifier) {
            pushSourceToken(tokens, tokenizer, tagSeen ? 'attribute' : 'tag', identifier);
            tagSeen = true; index += identifier.length; continue;
          }
          pushSourceToken(tokens, tokenizer, 'plain', character); index += 1;
        }
      }

      function tokenizeMarkupSourceLine(line, tokenizer) {
        const tokens = [];
        let index = 0;
        while (index < line.length) {
          if (tokenizer.coloredTokens >= SOURCE_HIGHLIGHT_TOKEN_LIMIT) {
            tokenizer.truncated = true;
            pushSourceToken(tokens, tokenizer, 'plain', line.slice(index));
            break;
          }
          if (tokenizer.state === 'markup-comment') {
            const end = line.indexOf('-->', index);
            if (end === -1) { pushSourceToken(tokens, tokenizer, 'comment', line.slice(index)); break; }
            pushSourceToken(tokens, tokenizer, 'comment', line.slice(index, end + 3));
            tokenizer.state = 'code'; index = end + 3; continue;
          }
          const tag = line.indexOf('<', index);
          if (tag === -1) {
            pushSourceToken(tokens, tokenizer, 'plain', line.slice(index)); break;
          }
          pushSourceToken(tokens, tokenizer, 'plain', line.slice(index, tag));
          if (line.startsWith('<!--', tag)) {
            const end = line.indexOf('-->', tag + 4);
            if (end === -1) {
              pushSourceToken(tokens, tokenizer, 'comment', line.slice(tag));
              tokenizer.state = 'markup-comment'; break;
            }
            pushSourceToken(tokens, tokenizer, 'comment', line.slice(tag, end + 3));
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

      function tokenizeWasmSourceLine(line, tokenizer) {
        const tokens = [];
        let index = 0;
        while (index < line.length) {
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
        if (tokenizer.language === 'wasm') return tokenizeWasmSourceLine(line, tokenizer);
        return [{type: 'plain', text: line}];
      }

      function sourceLineStarts(text) {
        const starts = [0];
        for (let index = 0; index < text.length; index += 1) {
          if (text[index] === '\n') starts.push(index + 1);
        }
        return starts;
      }

      function sourceLocationForOffset(starts, offset) {
        let low = 0;
        let high = starts.length - 1;
        while (low < high) {
          const middle = Math.ceil((low + high) / 2);
          if (starts[middle] <= offset) low = middle;
          else high = middle - 1;
        }
        return {line: low, column: Math.max(0, offset - starts[low])};
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

      function derivedLineMap(originalText, derivedText, segments, offsetUnit) {
        segments = sourceSegmentsUTF16(originalText, derivedText, segments, offsetUnit);
        const starts = sourceLineStarts(originalText);
        const lines = derivedText.split('\n');
        const mapped = [];
        let offset = 0;
        let segmentIndex = 0;
        for (let line = 0; line < lines.length; line += 1) {
          const lineEnd = offset + lines[line].length;
          while (segmentIndex < segments.length && segments[segmentIndex].derived_end <= offset) segmentIndex += 1;
          let mappedOffset = null;
          let segment = null;
          for (let candidateIndex = segmentIndex; candidateIndex < segments.length; candidateIndex += 1) {
            const candidate = segments[candidateIndex];
            if (candidate.derived_start > lineEnd) break;
            const candidateOffset = Math.max(offset, candidate.derived_start);
            const original = derivedOriginalOffset(segments, candidateOffset);
            if (original !== null) {
              mappedOffset = original;
              segment = candidate;
              break;
            }
          }
          const originalOffset = mappedOffset;
          const location = originalOffset === null ? null : sourceLocationForOffset(starts, originalOffset);
          mapped.push({
            line,
            synthetic: !segment || segment.kind === 'synthetic',
            originalOffset,
            originalLine: location ? location.line : null,
            originalColumn: location ? location.column : null
          });
          offset += lines[line].length + 1;
        }
        return mapped;
      }

      function sourceRepresentationLineMap(originalText, activeText, derived, formatted) {
        if (!formatted && !derived) return null;
        const activeMap = formatted
          ? derivedLineMap(activeText, formatted.text, formatted.segments ?? [], formatted.offset_unit)
          : null;
        if (!derived) return activeMap;
        if (!formatted) {
          return derivedLineMap(originalText, activeText, derived.segments ?? [], derived.offset_unit);
        }
        const derivedSegments = sourceSegmentsUTF16(
          originalText,
          activeText,
          derived.segments ?? [],
          derived.offset_unit
        );
        const originalStarts = sourceLineStarts(originalText);
        return activeMap.map(entry => {
          const originalOffset = entry.originalOffset === null
            ? null
            : derivedOriginalOffset(derivedSegments, entry.originalOffset);
          const location = originalOffset === null ? null : sourceLocationForOffset(originalStarts, originalOffset);
          return {
            ...entry,
            originalOffset,
            originalLine: location ? location.line : null,
            originalColumn: location ? location.column : null
          };
        });
      }
