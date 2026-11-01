# LIVE_E449 glue (hsw-live-e449-glue.js)

Captured artifact 4 from session 11521922066149179537
(`44bb181c…`, ~1.56 MB). Reconstructive only.

## window.hsw modes → Yc magics (ascii-proven)

| mode | glue | Yc magic | notes |
|-----:|------|---------:|-------|
| 0 decrypt | **aHz** | **1668574287** | `bbB[…](1668574287,0,0,0,Zy(Vb),Wz,0)` then Result unpack |
| 1 encrypt | **aJp** | **1908833735** | `bbB[…](1908833735,Wz,Zy(Vb),0,0,0,0)` |
| 2 update_token | **GC** (via hsw) | **-20745895** | stack frame + token args |

`bbB[aQK(8)]` is the Yc export call site in this binder.

Wasm path already in `guest_ops.js` LIVE_E449: Yc 1164 → 1138→880 / 1068→874 / 727.
