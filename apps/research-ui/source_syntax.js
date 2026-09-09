// Source display formatting and bounded tokenization. No DOM, network, or application state.

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

      function formatJavaScript(source) {
        if (source.split('\n').length > 5) return source;
        let output = '';
        let indent = 0;
        let quote = '';
        let escaped = false;
        let lineComment = false;
        let blockComment = false;
        const newline = () => { output = `${output.trimEnd()}\n${'  '.repeat(indent)}`; };
        for (let index = 0; index < source.length; index += 1) {
          const character = source[index];
          const next = source[index + 1] ?? '';
          if (lineComment) {
            output += character;
            if (character === '\n') { lineComment = false; output += '  '.repeat(indent); }
            continue;
          }
          if (blockComment) {
            output += character;
            if (character === '*' && next === '/') { output += next; index += 1; blockComment = false; }
            continue;
          }
          if (quote) {
            output += character;
            if (escaped) escaped = false;
            else if (character === '\\') escaped = true;
            else if (character === quote) quote = '';
            continue;
          }
          if (character === '/' && next === '/') { output += '//'; index += 1; lineComment = true; continue; }
          if (character === '/' && next === '*') { output += '/*'; index += 1; blockComment = true; continue; }
          if (character === '"' || character === "'" || character === '`') { quote = character; output += character; continue; }
          if (character === '{') { output += ' {'; indent += 1; newline(); continue; }
          if (character === '}') { indent = Math.max(0, indent - 1); newline(); output += '}'; if (next && next !== ';' && next !== ',' && next !== ')') newline(); continue; }
          if (character === ';') { output += ';'; newline(); continue; }
          if (character === ',') { output += ', '; continue; }
          if (/\s/.test(character)) {
            if (output && !/\s$/.test(output)) output += ' ';
            continue;
          }
          output += character;
        }
        return output.trim();
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
