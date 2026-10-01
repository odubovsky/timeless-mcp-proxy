import { createHash } from "node:crypto";
import https from "node:https";

const UPSTREAM = process.env.TIMELESS_MCP_URL || "https://api.timeless.day/mcp/";

const REQUEST_HEADERS = ["accept", "content-type", "mcp-session-id", "mcp-protocol-version", "last-event-id"];
const RESPONSE_HEADERS = [
  "content-type",
  "cache-control",
  "mcp-session-id",
  "mcp-protocol-version",
  "www-authenticate",
  "retry-after",
  "x-accel-buffering",
];

export function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

export function forwardMcp({ method, headers, body, timelessKey, authAssert = false }) {
  const target = new URL(UPSTREAM);
  const upstreamAuthorization = `Bearer ${timelessKey}`;
  const inboundAuthorization = headers.authorization || headers.Authorization || "";
  const reqHeaders = { host: target.host, authorization: upstreamAuthorization };
  for (const name of REQUEST_HEADERS) {
    const value = headers[name];
    if (value) reqHeaders[name] = Array.isArray(value) ? value.join(", ") : value;
  }
  if (!reqHeaders.accept) reqHeaders.accept = "application/json, text/event-stream";
  if (body?.length) reqHeaders["content-length"] = String(body.length);

  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        protocol: target.protocol,
        hostname: target.hostname,
        port: 443,
        path: `${target.pathname}${target.search}`,
        method,
        headers: reqHeaders,
      },
      (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => {
          const responseHeaders = {};
          for (const name of RESPONSE_HEADERS) {
            if (res.headers[name] != null) responseHeaders[name] = res.headers[name];
          }
          if (authAssert) {
            const replaced = inboundAuthorization !== upstreamAuthorization ? "1" : "0";
            const upstreamTimeless = reqHeaders.authorization === upstreamAuthorization ? "1" : "0";
            const inboundSha = createHash("sha256").update(inboundAuthorization).digest("hex").slice(0, 16);
            responseHeaders["x-proxy-auth-assert"] = `inbound-replaced=${replaced}; upstream-timeless=${upstreamTimeless}; inbound-sha=${inboundSha}`;
          }
          resolve({
            status: res.statusCode || 502,
            headers: responseHeaders,
            body: Buffer.concat(chunks),
          });
        });
      },
    );
    req.on("error", reject);
    if (body?.length) req.write(body);
    req.end();
  });
}
