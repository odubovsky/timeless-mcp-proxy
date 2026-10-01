import http from "node:http";
import https from "node:https";

export const TIMELESS_MCP_URL = "https://api.timeless.day/mcp/";

export function parseMcpBody(raw) {
  const messages = [];
  if (!raw) return messages;
  const trimmed = raw.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    messages.push(JSON.parse(trimmed));
    return messages;
  }
  for (const line of raw.split(/\r?\n/)) {
    if (line.startsWith("data:")) {
      const payload = line.slice(5).trim();
      if (payload) messages.push(JSON.parse(payload));
    }
  }
  return messages;
}

export function mcpRequest({
  url,
  token,
  method = "POST",
  body,
  headers = {},
}) {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    const lib = target.protocol === "https:" ? https : http;
    const payload =
      body == null
        ? null
        : Buffer.from(typeof body === "string" ? body : JSON.stringify(body));
    const reqHeaders = {
      accept: "application/json, text/event-stream",
      ...headers,
    };
    if (payload) {
      reqHeaders["content-type"] = reqHeaders["content-type"] || "application/json";
      reqHeaders["content-length"] = String(payload.length);
    }
    if (token) reqHeaders.authorization = `Bearer ${token}`;

    const req = lib.request(
      {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port || (target.protocol === "https:" ? 443 : 80),
        path: `${target.pathname}${target.search}`,
        method,
        headers: reqHeaders,
      },
      (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => {
          const raw = Buffer.concat(chunks).toString("utf8");
          let messages = [];
          let parseError = null;
          try {
            messages = parseMcpBody(raw);
          } catch (error) {
            parseError = error.message;
          }
          resolve({
            status: res.statusCode,
            headers: res.headers,
            raw,
            messages,
            parseError,
          });
        });
      },
    );
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

export function rpcBody(method, params, id = 1) {
  const body = { jsonrpc: "2.0", method };
  if (id != null) body.id = id;
  if (params !== undefined) body.params = params;
  return body;
}
