import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const SCOPE = "mcp:read";

function b64url(input) {
  return Buffer.from(input).toString("base64url");
}

function fromB64url(input) {
  return Buffer.from(input, "base64url");
}

function signPart(part, secret) {
  return createHmac("sha256", secret).update(part).digest("base64url");
}

function sameText(left, right) {
  const leftHash = createHash("sha256").update(String(left)).digest();
  const rightHash = createHash("sha256").update(String(right)).digest();
  return timingSafeEqual(leftHash, rightHash);
}

function secret() {
  const value = process.env.OAUTH_JWT_SECRET;
  if (!value) throw new Error("oauth_secret_missing");
  return value;
}

export function resourceUrl(base) {
  return `${base.replace(/\/$/, "")}/mcp`;
}

export function protectedResourceMetadata(base) {
  return {
    resource: resourceUrl(base),
    authorization_servers: [base.replace(/\/$/, "")],
    scopes_supported: [SCOPE],
    bearer_methods_supported: ["header"],
  };
}

export function authorizationServerMetadata(base) {
  const issuer = base.replace(/\/$/, "");
  return {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    registration_endpoint: `${issuer}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    client_id_metadata_document_supported: true,
    authorization_response_iss_parameter_supported: true,
    scopes_supported: [SCOPE],
  };
}

function pack(payload) {
  const body = b64url(JSON.stringify(payload));
  return `${body}.${signPart(body, secret())}`;
}

function unpack(token) {
  if (!token || !token.includes(".")) return null;
  const [body, sig, extra] = token.split(".");
  if (!body || !sig || extra) return null;
  const expected = signPart(body, secret());
  const sigBuf = Buffer.from(sig);
  const expectedBuf = Buffer.from(expected);
  if (sigBuf.length !== expectedBuf.length || !timingSafeEqual(sigBuf, expectedBuf)) return null;
  try {
    return JSON.parse(fromB64url(body).toString("utf8"));
  } catch {
    return null;
  }
}

export function signJwt(claims) {
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = b64url(JSON.stringify(claims));
  const signingInput = `${header}.${payload}`;
  return `${signingInput}.${signPart(signingInput, secret())}`;
}

export function verifyJwt(token) {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [header, payload, sig] = parts;
  let headerJson;
  try {
    headerJson = JSON.parse(fromB64url(header).toString("utf8"));
  } catch {
    return null;
  }
  if (headerJson.alg !== "HS256") return null;
  const expected = signPart(`${header}.${payload}`, secret());
  const sigBuf = Buffer.from(sig);
  const expectedBuf = Buffer.from(expected);
  if (sigBuf.length !== expectedBuf.length || !timingSafeEqual(sigBuf, expectedBuf)) return null;
  try {
    return JSON.parse(fromB64url(payload).toString("utf8"));
  } catch {
    return null;
  }
}

function loopback(uri) {
  try {
    const url = new URL(uri);
    return url.protocol === "http:" && (url.hostname === "127.0.0.1" || url.hostname === "localhost");
  } catch {
    return false;
  }
}

function httpsUrl(uri) {
  try {
    const url = new URL(uri);
    return url.protocol === "https:" && !url.username && !url.password;
  } catch {
    return false;
  }
}

function allowedRedirect(uri) {
  return httpsUrl(uri) || loopback(uri);
}

export function registerClient(body) {
  const redirectUris = Array.isArray(body.redirect_uris) ? body.redirect_uris : [];
  if (!redirectUris.length || redirectUris.some((uri) => !allowedRedirect(uri))) {
    return { error: "invalid_redirect_uri", status: 400 };
  }
  const clientId = `dcr.${pack({
    redirect_uris: redirectUris,
    client_name: typeof body.client_name === "string" ? body.client_name.slice(0, 80) : "mcp-client",
  })}`;
  return {
    status: 201,
    body: {
      client_id: clientId,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      redirect_uris: redirectUris,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    },
  };
}

const cimdCache = new Map();

async function resolveClient(clientId) {
  if (clientId.startsWith("dcr.")) {
    const packed = unpack(clientId.slice(4));
    if (!packed?.redirect_uris) return null;
    return { client_id: clientId, redirect_uris: packed.redirect_uris };
  }
  if (!httpsUrl(clientId)) return null;
  const cached = cimdCache.get(clientId);
  if (cached && cached.expires > Date.now()) return cached.doc;
  const response = await fetch(clientId, { redirect: "error" });
  if (!response.ok) return null;
  const doc = await response.json();
  if (doc.client_id !== clientId || !Array.isArray(doc.redirect_uris)) return null;
  cimdCache.set(clientId, { expires: Date.now() + 5 * 60 * 1000, doc });
  return doc;
}

function redirectError(redirectUri, state, issuer, error, description) {
  const url = new URL(redirectUri);
  url.searchParams.set("error", error);
  url.searchParams.set("error_description", description);
  url.searchParams.set("iss", issuer);
  if (state) url.searchParams.set("state", state);
  return { status: 302, headers: { location: url.toString() }, body: "" };
}

export function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

export async function authorizeGet(params, base) {
  const issuer = base.replace(/\/$/, "");
  const client = await resolveClient(params.client_id || "");
  if (!client || !client.redirect_uris.includes(params.redirect_uri)) {
    return { status: 400, headers: { "content-type": "text/plain; charset=utf-8" }, body: "invalid client or redirect_uri" };
  }
  if (params.response_type !== "code") {
    return redirectError(params.redirect_uri, params.state, issuer, "unsupported_response_type", "response_type must be code");
  }
  if (params.resource && params.resource !== resourceUrl(base)) {
    return redirectError(params.redirect_uri, params.state, issuer, "invalid_target", "resource does not match this MCP server");
  }
  if (params.code_challenge_method !== "S256" || !params.code_challenge) {
    return redirectError(params.redirect_uri, params.state, issuer, "invalid_request", "PKCE S256 code_challenge is required");
  }
  const fields = [
    "response_type",
    "client_id",
    "redirect_uri",
    "state",
    "code_challenge",
    "code_challenge_method",
    "resource",
    "scope",
  ];
  const formParams = { response_type: "code", ...params };
  const hidden = fields
    .filter((name) => formParams[name])
    .map((name) => `<input type="hidden" name="${name}" value="${escapeHtml(formParams[name])}">`)
    .join("");
  const body = `<!doctype html><html><head><meta charset="utf-8"><title>Authorize Timeless proxy</title></head><body><h1>Authorize MCP access</h1><p>This grants ${escapeHtml(params.scope || SCOPE)} for the Timeless proxy.</p><form method="post" action="/authorize">${hidden}<label>User <input name="username" autocomplete="username"></label><label>Password <input name="password" type="password" autocomplete="current-password"></label><button type="submit">Continue</button></form></body></html>`;
  return { status: 200, headers: { "content-type": "text/html; charset=utf-8" }, body };
}

export async function authorizePost(params, base) {
  const issuer = base.replace(/\/$/, "");
  const user = process.env.OAUTH_LOGIN_USER || "owner";
  const password = process.env.OAUTH_LOGIN_PASSWORD || "";
  if (!password || !sameText(params.username || "", user) || !sameText(params.password || "", password)) {
    const form = await authorizeGet(params, base);
    if (form.status !== 200) return form;
    return { ...form, body: form.body.replace("<form", "<p>Login failed.</p><form") };
  }
  const precheck = await authorizeGet(params, base);
  if (precheck.status !== 200) return precheck;
  const code = pack({
    typ: "code",
    client_id: params.client_id,
    redirect_uri: params.redirect_uri,
    challenge: params.code_challenge,
    scope: SCOPE,
    resource: resourceUrl(base),
    sub: user,
    exp: Math.floor(Date.now() / 1000) + 120,
  });
  const url = new URL(params.redirect_uri);
  url.searchParams.set("code", code);
  url.searchParams.set("iss", issuer);
  if (params.state) url.searchParams.set("state", params.state);
  return { status: 302, headers: { location: url.toString() }, body: "" };
}

function issueTokens(subject, base) {
  const now = Math.floor(Date.now() / 1000);
  const accessToken = signJwt({
    iss: base.replace(/\/$/, ""),
    aud: resourceUrl(base),
    sub: subject,
    scope: SCOPE,
    iat: now,
    exp: now + 3600,
  });
  const refreshToken = pack({
    typ: "refresh",
    sub: subject,
    exp: now + 30 * 24 * 3600,
  });
  return {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600,
    refresh_token: refreshToken,
    scope: SCOPE,
  };
}

function pkceOk(verifier, challenge) {
  if (!verifier) return false;
  const actual = createHash("sha256").update(verifier).digest("base64url");
  return sameText(actual, challenge);
}

export async function tokenExchange(params, base) {
  if (params.grant_type === "refresh_token") {
    const refresh = unpack(params.refresh_token || "");
    if (!refresh || refresh.typ !== "refresh" || refresh.exp < Math.floor(Date.now() / 1000)) {
      return { status: 400, body: { error: "invalid_grant" } };
    }
    return { status: 200, body: issueTokens(refresh.sub, base) };
  }
  if (params.grant_type !== "authorization_code") {
    return { status: 400, body: { error: "unsupported_grant_type" } };
  }
  const code = unpack(params.code || "");
  const now = Math.floor(Date.now() / 1000);
  if (!code || code.typ !== "code" || code.exp < now) {
    return { status: 400, body: { error: "invalid_grant" } };
  }
  if (code.client_id !== params.client_id || code.redirect_uri !== params.redirect_uri) {
    return { status: 400, body: { error: "invalid_grant" } };
  }
  if (params.resource && params.resource !== code.resource) {
    return { status: 400, body: { error: "invalid_target" } };
  }
  if (!pkceOk(params.code_verifier, code.challenge)) {
    return { status: 400, body: { error: "invalid_grant", error_description: "PKCE verification failed" } };
  }
  return { status: 200, body: issueTokens(code.sub, base) };
}

export function verifyAccessToken(authorization, base) {
  const header = authorization || "";
  const match = header.match(/^Bearer\s+(\S+)$/i);
  if (!match) return { ok: false, error: "invalid_token" };
  let claims;
  try {
    claims = verifyJwt(match[1]);
  } catch {
    return { ok: false, error: "invalid_token" };
  }
  if (!claims) return { ok: false, error: "invalid_token" };
  const now = Math.floor(Date.now() / 1000);
  if (claims.iss !== base.replace(/\/$/, "")) return { ok: false, error: "invalid_token" };
  const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audience.includes(resourceUrl(base))) return { ok: false, error: "invalid_token" };
  if (typeof claims.exp !== "number" || claims.exp <= now) return { ok: false, error: "invalid_token" };
  const scopes = String(claims.scope || "").split(/\s+/);
  if (!scopes.includes(SCOPE)) return { ok: false, error: "insufficient_scope" };
  return { ok: true, claims };
}

export function challengeHeader(base) {
  const metadata = `${base.replace(/\/$/, "")}/.well-known/oauth-protected-resource`;
  return `Bearer resource_metadata="${metadata}", scope="${SCOPE}"`;
}

export function pkcePair() {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}
