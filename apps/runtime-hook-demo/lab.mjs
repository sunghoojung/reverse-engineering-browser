import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { parseArgs } from "node:util";

const { values } = parseArgs({
  options: {
    page: { type: "string", default: "worker" },
    port: { type: "string" },
  },
});
if (!["callback", "worker"].includes(values.page)) {
  throw new Error("--page must be callback or worker");
}
const port = Number(values.port ?? (values.page === "callback" ? 7320 : 8766));
if (!Number.isInteger(port) || port < 0 || port > 65535) {
  throw new Error("--port must be an integer from 0 through 65535");
}
const routes =
  values.page === "callback"
    ? {
        "/": ["index.html", "text/html; charset=utf-8"],
        "/demo.js": ["demo.js", "text/javascript"],
      }
    : {
        "/": ["ghostwire-worker/parcel.html", "text/html; charset=utf-8"],
        "/signer-worker.js": [
          "ghostwire-worker/signer-worker.js",
          "text/javascript",
        ],
      };
const assets = new Map(
  await Promise.all(
    Object.entries(routes).map(async ([route, [file, mime]]) => [
      route,
      { body: await readFile(new URL(file, import.meta.url)), mime },
    ]),
  ),
);
function reply(response, status, body, mime = "application/json") {
  const bytes = Buffer.from(
    typeof body === "string" ? body : JSON.stringify(body),
  );
  response.writeHead(status, {
    "Content-Type": mime,
    "Content-Length": bytes.length,
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  response.end(bytes);
}
const server = createServer(async (request, response) => {
  const path = request.url.split("?", 1)[0];
  const asset = assets.get(path);
  if (request.method === "GET" && asset) {
    response.writeHead(200, {
      "Content-Type": asset.mime,
      "Content-Length": asset.body.length,
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    });
    response.end(asset.body);
    return;
  }
  if (
    values.page !== "worker" ||
    request.method !== "POST" ||
    path !== "/api/submit"
  ) {
    reply(response, 404, "Not found", "text/plain");
    request.resume();
    return;
  }
  try {
    const chunks = [];
    let size = 0;
    for await (const chunk of request) {
      size += chunk.length;
      if (size > 16384) {
        reply(response, 400, { error: "invalid body" });
        request.resume();
        return;
      }
      chunks.push(chunk);
    }
    if (size === 0) throw new Error("invalid body");
    const payload = JSON.parse(Buffer.concat(chunks).toString("utf8")).payload;
    if (typeof payload !== "string") throw new Error("invalid payload");
    reply(response, 200, {
      accepted: true,
      receipt: createHash("sha256").update(payload).digest("hex").slice(0, 12),
    });
  } catch {
    if (!response.writableEnded)
      reply(response, 400, { error: "invalid payload" });
  }
});
server.requestTimeout = 10000;
server.headersTimeout = 10000;
server.timeout = 10000;
server.maxHeadersCount = 32;
server.listen(port, "127.0.0.1", () =>
  console.log(`http://127.0.0.1:${server.address().port}/`),
);
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    server.closeAllConnections();
    server.close();
  });
}
