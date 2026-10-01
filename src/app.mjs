import { createHash } from "node:crypto";
import { forwardMcp, readBody } from "./forward.mjs";
import {
  authorizationServerMetadata,
  authorizeGet,
  authorizePost,
  challengeHeader,
  protectedResourceMetadata,
  registerClient,
  tokenExchange,
  verifyAccessToken,
} from "./oauth.mjs";

function send(res, status, headers, body) {
  const payload = Buffer.isBuffer(body) ? body : Buffer.from(body ?? "");
  res.writeHead(status, { ...headers, "content-length": String(payload.length) });
  res.end(payload);
}

function sendJson(res, status, body, extraHeaders = {}) {
  send(res, status, { "content-type": "application/json", "cache-control": "no-store", ...extraHeaders }, JSON.stringify(body));
}

export function requestBase(req) {
  if (process.env.PUBLIC_BASE_URL) return process.env.PUBLIC_BASE_URL.replace(/\/$/, "");
  const proto = String(req.headers["x-forwarded-proto"] || "http").split(",")[0].trim();
  const host = String(req.headers["x-forwarded-host"] || req.headers.host || "127.0.0.1").split(",")[0].trim();
  return `${proto}://${host}`;
}

export function requestUrl(req) {
  const rawHeader = req.headers["x-forwarded-uri"] || req.headers["x-original-url"];
  const raw = rawHeader || req.url || "/";
  if (raw.startsWith("http://") || raw.startsWith("https://")) return new URL(raw);
  return new URL(raw, `${requestBase(req)}/`);
}

function formPairs(raw) {
  return Object.fromEntries(new URLSearchParams(raw.toString("utf8")));
}

function oauthEnabled() {
  return process.env.OAUTH_ENABLED === "1";
}

export async function handle(req, res) {
  const url = requestUrl(req);
  const base = requestBase(req);
  const path = url.pathname;

  if (path === "/.well-known/oauth-protected-resource" || path === "/.well-known/oauth-protected-resource/mcp") {
    sendJson(res, 200, protectedResourceMetadata(base));
    return;
  }
  if (path === "/.well-known/oauth-authorization-server" || path === "/.well-known/openid-configuration") {
    sendJson(res, 200, authorizationServerMetadata(base));
    return;
  }
  if (path === "/register" && req.method === "POST") {
    const body = JSON.parse((await readBody(req)).toString("utf8") || "{}");
    const result = registerClient(body);
    if (result.error) {
      sendJson(res, result.status, { error: result.error });
      return;
    }
    sendJson(res, result.status, result.body);
    return;
  }
  if (path === "/authorize" && req.method === "GET") {
    const params = Object.fromEntries(url.searchParams);
    const result = await authorizeGet(params, base);
    send(res, result.status, result.headers, result.body);
    return;
  }
  if (path === "/authorize" && req.method === "POST") {
    const params = formPairs(await readBody(req));
    const result = await authorizePost(params, base);
    send(res, result.status, result.headers, result.body);
    return;
  }
  if (path === "/token" && req.method === "POST") {
    const params = formPairs(await readBody(req));
    const result = await tokenExchange(params, base);
    sendJson(res, result.status, result.body);
    return;
  }

  const isMcp =
    path === "/mcp" ||
    path === "/mcp/" ||
    path === "/" ||
    path === "";
  if (!isMcp) {
    sendJson(res, 404, { error: "not_found" });
    return;
  }

  if (oauthEnabled()) {
    let verdict;
    try {
      verdict = verifyAccessToken(req.headers.authorization, base);
    } catch {
      verdict = { ok: false, error: "invalid_token" };
    }
    if (!verdict.ok) {
      const description = verdict.error === "insufficient_scope" ? "insufficient_scope" : "invalid_token";
      sendJson(
        res,
        401,
        { error: description },
        { "www-authenticate": challengeHeader(base) },
      );
      return;
    }
  }

  const timelessKey = process.env.TIMELESS_API_KEY;
  if (!timelessKey) {
    sendJson(res, 503, { error: "timeless_credential_missing" });
    return;
  }

  const body = await readBody(req);
  try {
    const upstream = await forwardMcp({
      method: req.method || "POST",
      headers: req.headers,
      body,
      timelessKey,
      authAssert: process.env.AUTH_ASSERT === "1",
    });
    console.error(`${req.method} /mcp ${upstream.status}`);
    send(res, upstream.status, upstream.headers, upstream.body);
  } catch {
    console.error(`${req.method} /mcp upstream_unreachable`);
    sendJson(res, 502, { error: "upstream_unreachable" });
  }
}

export function authMaterialHash(authorization) {
  return createHash("sha256").update(authorization || "").digest("hex").slice(0, 16);
}
