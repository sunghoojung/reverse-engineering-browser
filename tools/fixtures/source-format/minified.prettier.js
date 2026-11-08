var a = function (e, t) {
    if (!e) return null;
    for (var n = 0, r = e.length; n < r; n++) {
      t(e[n], n)
    }
    return {
      ok: !0,
      list: [1, 2, 3],
      fn: async () => {
        await fetch("/x?y=" + n, {
          method: "POST",
          body: JSON.stringify({ a: 1 })
        })
      }
    }
  },
  b = a?.c ?? (d, e => e * 2);
