# hCaptcha HSW Proof-of-Work Path

Static analysis of the JWT/PoW flow through hsw.wasm. Not a solver.

## Entry: hsw(jwt, extra, cb)

```
hsw(jwt, extra, cb)
  |
  +-- parseCompactJwt(jwt)          // split "header.payload.signature"
  |     header  = JSON.parse(atob(parts[0]))
  |     payload = JSON.parse(atob(parts[1]))
  |     sig     = base64url-decode(parts[2])
  |
  +-- aeB(JSON.stringify(payload), Math.round(Date.now()/1000), extra, cb)
        |
        export Uc (func 491)
```

## Export Uc / func 491

**Signature:** `(i32 payloadPtr, i32 payloadLen, i64 unixSec, i32 extraHandle, i32 progressHandle) -> i32`

**Frame:** 1312 bytes (scrambled stores of args into 320-byte pages)

**Flow:**
1. Store args via scrambled i32/i64 writes (funcs 305, 286)
2. Call host import `a.Qa` to create a Promise with wasm executor
3. Pass control to func 659

The Promise executor is `a_P` which calls wasm export `Dc` with:
```
vu.Dc(closure_a, closure_b, addHeapObject(resolve), addHeapObject(reject))
```

## Func 659 (Promise body / JWT work dispatcher)

**Called by:** func 491 after Promise creation

**Role:** Unpacks the JWT payload and args, calls the fingerprint/PoW chain

**Outputs to host:**
- Fingerprint data (via funcs 218, 323)
- PoW result (via func 606)

## Call Chain: Giants

```
func 491 (Uc)
  |
  +-- func 659 (Promise work body)
        |
        +-- func 1033 (529-arm CFF, 20,196 B)
              |
              +-- func 606 (732-arm CFF, 29,424 B) <-- a.Yb PoW HERE
                    |
                    +-- func 218 (749-arm CFF, 30,476 B) <-- fingerprint cluster
                          |
                          +-- func 323 (611-arm CFF, 27,003 B)
```

## Host Import a.Yb: SHA-1 Leading-Zero Proof

**Import index:** 158 (in type section order)  
**Signature:** `(i32 prefixPtr, i32 prefixLen, i32 difficultyBits) -> i32`  
**Returns:** JS handle to Promise<nonce>

### Input Format

```
prefix = aSJ(prefixPtr, prefixLen)   // UTF-8 decode from wasm memory
difficulty = difficultyBits >>> 0    // unsigned 32-bit: number of leading zero BITS
```

The prefix string comes from wasm and encodes challenge context (likely includes
site key, timestamp, JWT fields). The exact composition is assembled by func 606.

### Hash Construction

```
message = prefix + ":" + nonce.toString(16)
digest  = SHA-1(message)              // 20 bytes
```

### Leading Zero Check

```javascript
const ROTATION = 173;                 // byte offset into digest

function checkLeadingZeros(digest, bits) {
  const fullBytes = Math.floor(bits / 8);
  const partialBits = bits % 8;
  
  for (let i = 0; i < fullBytes; i++) {
    if (digest[(ROTATION + i) % 20] !== 0) return false;
  }
  
  if (partialBits > 0) {
    const mask = 1 << (8 - partialBits);
    if (digest[(ROTATION + fullBytes) % 20] >= mask) return false;
  }
  
  return true;
}
```

The rotation by 173 bytes (mod 20) is an obfuscation; effectively checks a
rotated view of the 20-byte SHA-1 output.

### PoW Loop

Primary path uses `crypto.subtle.digest("SHA-1")` with 16 parallel promises:

```javascript
const BATCH_SIZE = 16;

async function powLoop(prefix, bits) {
  const encoder = new TextEncoder();
  const prefixBytes = encoder.encode(prefix + ":");
  
  for (let base = 0; ; base += BATCH_SIZE) {
    const promises = [];
    for (let i = 0; i < BATCH_SIZE; i++) {
      const nonceHex = (base + i).toString(16);
      const input = new Uint8Array(prefixBytes.length + nonceHex.length);
      input.set(prefixBytes);
      for (let j = 0; j < nonceHex.length; j++) {
        input[prefixBytes.length + j] = nonceHex.charCodeAt(j);
      }
      promises.push(crypto.subtle.digest("SHA-1", input));
    }
    
    const digests = await Promise.all(promises);
    for (let i = 0; i < BATCH_SIZE; i++) {
      if (checkLeadingZeros(new Uint8Array(digests[i]), bits)) {
        return base + i;  // winning nonce
      }
    }
  }
}
```

Fallback uses a pure-JS SHA-1 implementation when `crypto.subtle` is unavailable.

## PoW Difficulty

Typical observed difficulties:
- Easy: 10-14 bits (~1K-16K iterations avg)
- Medium: 16-18 bits (~64K-256K iterations avg)  
- Hard: 20+ bits (~1M+ iterations avg)

The difficulty is extracted from the JWT payload or computed by the wasm based
on session/risk signals.

## What Gets Posted Back

After PoW completes, func 606 stores the nonce result, then the chain unwinds
through 1033 back to 659, which:

1. Assembles the response object (fingerprint + PoW nonce + timestamps)
2. Calls host imports to JSON.stringify the result
3. Resolves the Promise created in func 491

The final response structure (assembled by JS glue after wasm returns):

```javascript
{
  "st": startTime,           // Unix seconds when work began
  "t": elapsedMs,            // Milliseconds to complete
  "n": nonceHex,             // Winning nonce as hex string
  // Plus fingerprint fields from func 218/323
}
```

## Host Imports Used by PoW Path

| Import | Name | Role in PoW |
|--------|------|-------------|
| `Qa` | new Promise(executor) | Wraps func 491 work in Promise |
| `Yb` | SHA-1 PoW | The actual proof-of-work |
| `Hb` | box wasm string | Convert prefix ptr+len to JS string |
| `zb` | drop handle | Release JS handles after use |
| `Sb` | Promise.resolve | Box resolved value |
| `h` | JSON.stringify | Encode final response |
| `nb` | Date.now | Timestamps |
| `ta` | performance.now | Elapsed time measurement |

## Remaining Unknowns

1. **Prefix composition:** The exact fields concatenated into the PoW prefix
   string are assembled by func 606 from scrambled memory. Likely includes:
   - Site key / challenge ID
   - Timestamp
   - Session token fragments
   - JWT payload fields

2. **Difficulty source:** Whether difficulty comes from JWT payload field or
   is computed by wasm based on fingerprint signals.

3. **Nonce encoding in response:** Whether returned as decimal or hex string,
   and field name in final JSON.

4. **Fingerprint fields:** What func 218/323 contribute to the response
   alongside the PoW result.
