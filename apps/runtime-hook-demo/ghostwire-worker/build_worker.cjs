const fs = require('node:fs');
const JavaScriptObfuscator = require('javascript-obfuscator');

const source = `
(() => {
  const names = ['replace', 'normalize', 'trim', 'fromCharCode', 'join'];
  names.unshift(names.pop());
  const secret = [91, 17, 203, 44, 6, 155, 72, 230, 39, 113, 8, 194, 61];
  function word(index) { return names[index]; }
  function checksum(bytes) {
    let a = 0x13579bdf;
    for (let i = 0; i < bytes.length; i++) {
      a = Math.imul(a ^ bytes[i], 0x45d9f3b) >>> 0;
      a = (a << 7 | a >>> 25) >>> 0;
    }
    return a;
  }
  function sign(message, nonce) {
    const clean = message[word(1)]('NFKC')[word(2)]()[word(3)](/\\s+/g, ' ').toLowerCase();
    const bytes = Array.from(new TextEncoder().encode(clean));
    const header = [nonce & 255, nonce >>> 8 & 255, bytes.length & 255, checksum(bytes) & 255];
    let state = (nonce ^ 0xa5) & 255;
    const mixed = header.concat(bytes).map((byte, index) => {
      const key = secret[index % secret.length] ^ ((index * 31 + nonce) & 255);
      state = ((byte ^ key ^ state) * 13 + 17) & 255;
      return state;
    });
    return 'ws1.' + btoa(mixed.map(x => String[word(4)](x))[word(0)](''))
      [word(3)](/\\+/g, '-')[word(3)](/\\//g, '_')[word(3)](/=+$/g, '');
  }
  // javascript-obfuscator:disable
  self.onmessage = event => {
    const message = event.data.message;
    const nonce = Number(event.data.nonce);
    const payload = sign(message, nonce);
    fetch('/api/submit', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({payload})})
      .then(response => response.json())
      .then(result => postMessage({ok:true, receipt:result.receipt}));
  };
  // javascript-obfuscator:enable
})();`;

const result = JavaScriptObfuscator.obfuscate(source, {
  compact: true,
  controlFlowFlattening: false,
  deadCodeInjection: false,
  identifierNamesGenerator: 'hexadecimal',
  numbersToExpressions: true,
  renameGlobals: true,
  selfDefending: false,
  simplify: true,
  splitStrings: true,
  splitStringsChunkLength: 4,
  stringArray: true,
  stringArrayCallsTransform: true,
  stringArrayCallsTransformThreshold: 1,
  stringArrayEncoding: ['rc4'],
  stringArrayIndexShift: true,
  stringArrayRotate: true,
  stringArrayShuffle: true,
  stringArrayThreshold: 1,
  stringArrayWrappersChainedCalls: true,
  stringArrayWrappersCount: 3,
  stringArrayWrappersParametersMaxCount: 5,
  stringArrayWrappersType: 'function',
  target: 'browser',
  transformObjectKeys: true,
  seed: 7331,
});
fs.writeFileSync(__dirname + '/signer-worker.js', '(()=>{' + result.getObfuscatedCode() + '})();\n');
