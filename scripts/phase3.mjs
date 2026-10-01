import { createHash, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { mcpRequest, rpcBody, TIMELESS_MCP_URL } from "./mcp-client.mjs";
import { pkcePair, signJwt } from "../src/oauth.mjs";

const evidenceDir = path.resolve("evidence/phase3");
const base = (process.env.BASE_URL || "").replace(/\/$/, "");
const key = process.env.TIMELESS_API_KEY;
const allowInsecure = process.env.ALLOW_INSECURE === "1";
if (!base || !key || !process.env.OAUTH_JWT_SECRET || !process.env.OAUTH_LOGIN_PASSWORD) {
  console.error("BASE_URL, TIMELESS_API_KEY, OAUTH_JWT_SECRET, and OAUTH_LOGIN_PASSWORD are required.");
  process.exit(1);
}

const cases = [];
const captured = [];
let server = null;
let serverLog = "";

function record(id, result, evidence, note = "") {
  cases.push({ id, result, evidence, note });
  console.log(`${id} ${result}${note ? ` — ${note}` : ""}`);
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((name) => [name, stable(value[name])]));
  }
  return value;
}

function normalizeTools(tools) {
  return stable([...tools].map((tool) => ({
    name: tool.name,
    description: tool.description ?? null,
    inputSchema: tool.inputSchema ?? null,
    annotations: tool.annotations ?? null,
  })).sort((left, right) => left.name.localeCompare(right.name)));
}

async function httpCall(pathname, { method = "GET", headers = {}, body, token } = {}) {
  const response = await fetch(`${base}${pathname}`, {
    method,
    headers: {
      ...(body ? { "content-type": "application/json" } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body,
    redirect: "manual",
  });
  const raw = await response.text();
  captured.push(raw);
  return {
    status: response.status,
    headers: Object.fromEntries(response.headers.entries()),
    raw,
  };
}

function mcpHeaders(token) {
  return {
    accept: "application/json, text/event-stream",
    "content-type": "application/json",
    ...(token ? { authorization: `Bearer ${token}` } : {}),
  };
}

async function proxyMcp(body, token) {
  const response = await httpCall("/mcp", {
    method: "POST",
    headers: mcpHeaders(token),
    body: JSON.stringify(body),
  });
  let messages = [];
  try {
    const parsed = await import("./mcp-client.mjs");
    messages = parsed.parseMcpBody(response.raw);
  } catch {
    messages = [];
  }
  return { ...response, messages };
}

function toolText(message) {
  return message?.result?.content?.find((item) => item.type === "text")?.text ?? "";
}

async function directTool(name, args, id) {
  return mcpRequest({
    url: TIMELESS_MCP_URL,
    token: key,
    body: rpcBody("tools/call", { name, arguments: args }, id),
  });
}

async function startLocal() {
  if (process.env.START_LOCAL !== "1") return;
  serverLog = "";
  server = spawn(process.execPath, ["src/server.mjs"], {
    env: {
      ...process.env,
      PORT: "3010",
      HOST: "127.0.0.1",
      OAUTH_ENABLED: "1",
      AUTH_ASSERT: "1",
      PUBLIC_BASE_URL: base,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("local proxy did not start")), 5000);
    const onChunk = (chunk) => {
      serverLog += chunk.toString("utf8");
      if (serverLog.includes("listening")) {
        clearTimeout(timer);
        resolve();
      }
    };
    server.stdout.on("data", onChunk);
    server.stderr.on("data", onChunk);
  });
}

async function stopLocal() {
  if (!server) return;
  server.kill("SIGTERM");
  await new Promise((resolve) => server.once("exit", resolve));
  server = null;
}

function hashBearer(token) {
  return createHash("sha256").update(`Bearer ${token}`).digest("hex").slice(0, 16);
}

await mkdir(evidenceDir, { recursive: true });

try {
  await startLocal();
  const httpsOk = base.startsWith("https://") || (allowInsecure && base.startsWith("http://"));
  let reach = { status: 0 };
  try {
    reach = await httpCall("/.well-known/oauth-protected-resource");
  } catch (error) {
    reach = { status: 0, raw: error.message };
  }
  const tc301 = httpsOk && reach.status === 200;
  await writeFile(path.join(evidenceDir, "connectivity.json"), JSON.stringify({
    baseProtocol: new URL(base).protocol,
    status: reach.status,
    https: base.startsWith("https://"),
  }, null, 2));
  record("TC-301", tc301 ? "PASS" : "FAIL", "evidence/phase3/connectivity.json", tc301 ? "endpoint reachable" : "endpoint unreachable");
  if (!tc301) await finish(1);

  const unauth = await httpCall("/mcp", {
    method: "POST",
    headers: mcpHeaders(),
    body: JSON.stringify(rpcBody("initialize", {
      protocolVersion: "2025-03-26",
      capabilities: {},
      clientInfo: { name: "phase3", version: "0.1.0" },
    })),
  });
  const wwwAuthenticate = unauth.headers["www-authenticate"] || "";
  const tc302 = unauth.status === 401
    && wwwAuthenticate.includes("resource_metadata=")
    && !unauth.raw.includes("jsonrpc")
    && !unauth.raw.includes(key);
  await writeFile(path.join(evidenceDir, "unauthenticated.json"), JSON.stringify({
    status: unauth.status,
    wwwAuthenticate,
    body: unauth.raw,
  }, null, 2));
  record("TC-302", tc302 ? "PASS" : "FAIL", "evidence/phase3/unauthenticated.json", tc302 ? "401 oauth challenge" : `status ${unauth.status}`);
  if (!tc302) await finish(1);

  const metadata = JSON.parse((await httpCall("/.well-known/oauth-protected-resource")).raw);
  const tc303 = metadata.resource === `${base}/mcp`
    && metadata.authorization_servers?.[0] === base
    && metadata.scopes_supported?.includes("mcp:read");
  await writeFile(path.join(evidenceDir, "protected-resource.json"), JSON.stringify(metadata, null, 2));
  record("TC-303", tc303 ? "PASS" : "FAIL", "evidence/phase3/protected-resource.json", tc303 ? "metadata matches MCP resource" : "metadata mismatch");
  if (!tc303) await finish(1);

  const discovery = JSON.parse((await httpCall("/.well-known/oauth-authorization-server")).raw);
  const tc304 = discovery.issuer === base
    && discovery.authorization_endpoint === `${base}/authorize`
    && discovery.token_endpoint === `${base}/token`
    && discovery.code_challenge_methods_supported?.includes("S256")
    && discovery.client_id_metadata_document_supported === true
    && discovery.authorization_response_iss_parameter_supported === true;
  const cimd = await httpCall(`/authorize?${new URLSearchParams({
    response_type: "code",
    client_id: "https://chatgpt.com/oauth/client.json",
    redirect_uri: "https://chatgpt.com/connector_platform_oauth_redirect",
    code_challenge: pkcePair().challenge,
    code_challenge_method: "S256",
    resource: `${base}/mcp`,
    scope: "mcp:read",
  })}`);
  const cimdOk = cimd.status === 200 && cimd.raw.includes("<form");
  await writeFile(path.join(evidenceDir, "authorization-server.json"), JSON.stringify({
    discovery,
    chatgptClientRecognized: cimdOk,
  }, null, 2));
  record("TC-304", tc304 && cimdOk ? "PASS" : "FAIL", "evidence/phase3/authorization-server.json", tc304 && cimdOk ? "discovery valid; ChatGPT CIMD accepted" : "discovery invalid");
  if (!(tc304 && cimdOk)) await finish(1);

  const registered = JSON.parse((await httpCall("/register", {
    method: "POST",
    body: JSON.stringify({
      client_name: "phase3-test",
      redirect_uris: ["http://127.0.0.1:9/callback"],
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    }),
  })).raw);
  const pkce = pkcePair();
  const state = randomBytes(8).toString("hex");
  const consented = await httpCall("/authorize", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      username: process.env.OAUTH_LOGIN_USER || "owner",
      password: process.env.OAUTH_LOGIN_PASSWORD,
      response_type: "code",
      client_id: registered.client_id,
      redirect_uri: "http://127.0.0.1:9/callback",
      code_challenge: pkce.challenge,
      code_challenge_method: "S256",
      resource: `${base}/mcp`,
      scope: "mcp:read",
      state,
    }).toString(),
  });
  const location = new URL(consented.headers.location || "http://invalid.local/");
  const code = location.searchParams.get("code");
  const tokenResponse = code ? await httpCall("/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: "http://127.0.0.1:9/callback",
      client_id: registered.client_id,
      code_verifier: pkce.verifier,
      resource: `${base}/mcp`,
    }).toString(),
  }) : { status: 0, raw: "" };
  const tokenJson = tokenResponse.raw ? JSON.parse(tokenResponse.raw) : {};
  const accessToken = tokenJson.access_token;
  const tc305 = consented.status === 302
    && location.searchParams.get("iss") === base
    && location.searchParams.get("state") === state
    && tokenResponse.status === 200
    && tokenJson.token_type === "Bearer"
    && typeof accessToken === "string";
  await writeFile(path.join(evidenceDir, "pkce-flow.json"), JSON.stringify({
    authorizeStatus: consented.status,
    iss: location.searchParams.get("iss"),
    stateMatches: location.searchParams.get("state") === state,
    tokenStatus: tokenResponse.status,
    tokenType: tokenJson.token_type || null,
    expiresIn: tokenJson.expires_in || null,
    scope: tokenJson.scope || null,
    accessTokenIssued: Boolean(accessToken),
  }, null, 2));
  record("TC-305", tc305 ? "PASS" : "FAIL", "evidence/phase3/pkce-flow.json", tc305 ? "authorization code and PKCE succeeded" : "pkce flow failed");
  if (!tc305) await finish(1);

  const missingPkce = await httpCall(`/authorize?${new URLSearchParams({
    response_type: "code",
    client_id: registered.client_id,
    redirect_uri: "http://127.0.0.1:9/callback",
    resource: `${base}/mcp`,
  })}`);
  const badLocation = new URL(missingPkce.headers.location || "http://invalid.local/");
  const wrongVerifier = await httpCall("/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: "http://127.0.0.1:9/callback",
      client_id: registered.client_id,
      code_verifier: "wrong-verifier-value",
      resource: `${base}/mcp`,
    }).toString(),
  });
  const tc306 = missingPkce.status === 302
    && badLocation.searchParams.get("error") === "invalid_request"
    && badLocation.searchParams.get("iss") === base
    && wrongVerifier.status === 400
    && wrongVerifier.raw.includes("invalid_grant");
  await writeFile(path.join(evidenceDir, "pkce-rejected.json"), JSON.stringify({
    missingChallengeStatus: missingPkce.status,
    missingChallengeError: badLocation.searchParams.get("error"),
    wrongVerifierStatus: wrongVerifier.status,
  }, null, 2));
  record("TC-306", tc306 ? "PASS" : "FAIL", "evidence/phase3/pkce-rejected.json", tc306 ? "missing challenge and wrong verifier rejected" : "pkce rejection failed");
  if (!tc306) await finish(1);

  async function expectRejected(token, file, id, note) {
    const response = await httpCall("/mcp", {
      method: "POST",
      headers: mcpHeaders(token),
      body: JSON.stringify(rpcBody("tools/list", {}, 2)),
    });
    const ok = response.status === 401 && !response.raw.includes("jsonrpc") && !response.raw.includes(key) && !(token && response.raw.includes(token));
    await writeFile(path.join(evidenceDir, file), JSON.stringify({ status: response.status, body: response.raw, contentType: response.headers["content-type"] || null }, null, 2));
    record(id, ok ? "PASS" : "FAIL", `evidence/phase3/${file}`, ok ? note : `status ${response.status}`);
    return ok;
  }

  const tampered = `${accessToken.slice(0, -1)}${accessToken.endsWith("a") ? "b" : "a"}`;
  if (!await expectRejected(tampered, "bad-signature.json", "TC-307", "tampered token rejected")) await finish(1);

  const now = Math.floor(Date.now() / 1000);
  const expired = signJwt({ iss: base, aud: `${base}/mcp`, sub: "owner", scope: "mcp:read", iat: now - 7200, exp: now - 3600 });
  if (!await expectRejected(expired, "expired.json", "TC-308", "expired token rejected")) await finish(1);

  const wrongIss = signJwt({ iss: "https://evil.example", aud: `${base}/mcp`, sub: "owner", scope: "mcp:read", iat: now, exp: now + 600 });
  if (!await expectRejected(wrongIss, "wrong-issuer.json", "TC-309", "wrong issuer rejected")) await finish(1);

  const wrongAud = signJwt({ iss: base, aud: "https://evil.example/mcp", sub: "owner", scope: "mcp:read", iat: now, exp: now + 600 });
  if (!await expectRejected(wrongAud, "wrong-audience.json", "TC-310", "wrong audience rejected")) await finish(1);

  const wrongScope = signJwt({ iss: base, aud: `${base}/mcp`, sub: "owner", scope: "other", iat: now, exp: now + 600 });
  if (!await expectRejected(wrongScope, "wrong-scope.json", "TC-311", "missing scope rejected")) await finish(1);

  const listed = await proxyMcp(rpcBody("tools/list", {}, 2), accessToken);
  const tools = listed.messages[0]?.result?.tools;
  const tc312 = listed.status === 200 && Array.isArray(tools) && tools.length > 0 && !listed.raw.includes(key);
  await writeFile(path.join(evidenceDir, "valid-token.json"), JSON.stringify({
    status: listed.status,
    contentType: listed.headers["content-type"] || null,
    toolCount: tools?.length ?? 0,
  }, null, 2));
  record("TC-312", tc312 ? "PASS" : "FAIL", "evidence/phase3/valid-token.json", tc312 ? `${tools.length} tools through validated token` : "validated request did not reach MCP");
  if (!tc312) await finish(1);

  const asserted = await proxyMcp(rpcBody("tools/list", {}, 7), accessToken);
  const assertHeader = asserted.headers["x-proxy-auth-assert"] || "";
  const tc313 = assertHeader.includes(`inbound-sha=${hashBearer(accessToken)}`)
    && assertHeader.includes("inbound-replaced=1")
    && assertHeader.includes("upstream-timeless=1")
    && !asserted.raw.includes(accessToken)
    && !asserted.raw.includes(key);
  await writeFile(path.join(evidenceDir, "substitution.json"), JSON.stringify({
    header: assertHeader.split(";").map((part) => part.trim().startsWith("inbound-sha=") ? "inbound-sha=present" : part.trim()),
    inboundShaMatches: assertHeader.includes(`inbound-sha=${hashBearer(accessToken)}`),
    replaced: assertHeader.includes("inbound-replaced=1"),
    upstreamTimeless: assertHeader.includes("upstream-timeless=1"),
  }, null, 2));
  record("TC-313", tc313 ? "PASS" : "FAIL", "evidence/phase3/substitution.json", tc313 ? "oauth token terminated at the proxy" : "substitution check failed");
  if (!tc313) await finish(1);

  const init = await proxyMcp(rpcBody("initialize", {
    protocolVersion: "2025-03-26",
    capabilities: {},
    clientInfo: { name: "phase3", version: "0.1.0" },
  }, 1), accessToken);
  const tc315 = init.status === 200 && init.messages[0]?.result?.serverInfo?.name === "Timeless";
  await writeFile(path.join(evidenceDir, "initialize.json"), JSON.stringify({
    status: init.status,
    server: init.messages[0]?.result?.serverInfo ?? null,
    protocol: init.messages[0]?.result?.protocolVersion ?? null,
  }, null, 2));
  record("TC-314", !captured.some((raw) => raw.includes(key)) && !serverLog.includes(key) ? "PASS" : "FAIL", "evidence/phase3/secret-scan.json", "Timeless credential absent from responses and local logs");
  record("TC-315", tc315 ? "PASS" : "FAIL", "evidence/phase3/initialize.json", tc315 ? "production initialize matched Timeless" : "initialize failed");
  if (captured.some((raw) => raw.includes(key)) || serverLog.includes(key) || !tc315) await finish(1);

  const baseline = JSON.parse(await readFile(path.resolve("evidence/phase1/tools-list.json"), "utf8"));
  const same = JSON.stringify(normalizeTools(tools)) === JSON.stringify(normalizeTools(baseline.result.tools));
  const baseNames = new Set(baseline.result.tools.map((tool) => tool.name));
  const proxyNames = new Set(tools.map((tool) => tool.name));
  const missing = [...baseNames].filter((name) => !proxyNames.has(name));
  const extra = [...proxyNames].filter((name) => !baseNames.has(name));
  await writeFile(path.join(evidenceDir, "tools-list-diff.json"), JSON.stringify({ same, missing, extra, count: tools.length }, null, 2));
  record("TC-316", same ? "PASS" : "FAIL", "evidence/phase3/tools-list-diff.json", same ? "equivalent to Phase 1 baseline" : "catalogue differs");
  record("TC-317", missing.length === 0 && extra.length === 0 ? "PASS" : "FAIL", "evidence/phase3/tools-list-diff.json", `missing ${missing.length}, extra ${extra.length}`);
  if (!same || missing.length || extra.length) await finish(1);

  const runtime = JSON.parse(await readFile(path.resolve("evidence/phase1/runtime.json"), "utf8"));
  const meetingArgs = { limit: 1, status: "completed" };
  const directMeetings = await directTool("list_meetings", meetingArgs, 3);
  const proxyMeetings = await proxyMcp(rpcBody("tools/call", { name: "list_meetings", arguments: meetingArgs }, 3), accessToken);
  const directMeetingText = toolText(directMeetings.messages[0]);
  const proxyMeetingText = toolText(proxyMeetings.messages[0]);
  const meetingsOk = directMeetingText && directMeetingText === proxyMeetingText && !proxyMeetings.messages[0]?.result?.isError;
  await writeFile(path.join(evidenceDir, "meetings.json"), JSON.stringify({ sameBody: directMeetingText === proxyMeetingText, proxyError: Boolean(proxyMeetings.messages[0]?.result?.isError) }, null, 2));
  record("TC-318", meetingsOk ? "PASS" : "FAIL", "evidence/phase3/meetings.json", meetingsOk ? "remote discovery matched direct Timeless" : "discovery diverged");
  if (!meetingsOk) await finish(1);

  const transcriptArgs = { meeting_id: runtime.meetingId };
  const directTranscript = await directTool("get_meeting_transcript", transcriptArgs, 4);
  const proxyTranscript = await proxyMcp(rpcBody("tools/call", { name: "get_meeting_transcript", arguments: transcriptArgs }, 4), accessToken);
  const directTranscriptJson = JSON.parse(toolText(directTranscript.messages[0]));
  const proxyTranscriptJson = JSON.parse(toolText(proxyTranscript.messages[0]));
  const transcriptOk = directTranscriptJson.meeting_id === proxyTranscriptJson.meeting_id
    && directTranscriptJson.segments.length === proxyTranscriptJson.segments.length;
  await writeFile(path.join(evidenceDir, "transcript.json"), JSON.stringify({
    sameMeeting: directTranscriptJson.meeting_id === proxyTranscriptJson.meeting_id,
    directSegments: directTranscriptJson.segments.length,
    proxySegments: proxyTranscriptJson.segments.length,
  }, null, 2));
  record("TC-319", transcriptOk ? "PASS" : "FAIL", "evidence/phase3/transcript.json", transcriptOk ? "remote transcript matched" : "transcript diverged");
  if (!transcriptOk) await finish(1);

  const badArgs = { meeting_id: "mtg_does_not_exist" };
  const directBad = await directTool("get_meeting_transcript", badArgs, 6);
  const proxyBad = await proxyMcp(rpcBody("tools/call", { name: "get_meeting_transcript", arguments: badArgs }, 6), accessToken);
  const directBadText = toolText(directBad.messages[0]).split(key).join("[REDACTED]");
  const proxyBadText = toolText(proxyBad.messages[0]).split(key).join("[REDACTED]");
  const errorOk = Boolean(directBad.messages[0]?.result?.isError) && Boolean(proxyBad.messages[0]?.result?.isError) && directBadText === proxyBadText && !proxyBad.raw.includes(key) && !proxyBad.raw.includes(accessToken);
  await writeFile(path.join(evidenceDir, "upstream-error.json"), JSON.stringify({
    directIsError: Boolean(directBad.messages[0]?.result?.isError),
    proxyIsError: Boolean(proxyBad.messages[0]?.result?.isError),
    sameText: directBadText === proxyBadText,
  }, null, 2));
  record("TC-320", errorOk ? "PASS" : "FAIL", "evidence/phase3/upstream-error.json", errorOk ? "upstream error preserved" : "error diverged");
  if (!errorOk) await finish(1);

  record("TC-321", "FAIL", "evidence/phase3/chatgpt.json", "ChatGPT product connection is not completed in this run");
  await writeFile(path.join(evidenceDir, "chatgpt.json"), JSON.stringify({
    result: "FAIL",
    reason: "Connecting ChatGPT requires an interactive product login that has not been completed.",
  }, null, 2));
  await finish(1);
} catch (error) {
  console.error(`PHASE3 ERROR ${error.message}`);
  await finish(1);
} finally {
  await stopLocal();
}

async function finish(code) {
  await stopLocal();
  const leaks = [];
  for (const file of ["connectivity.json", "unauthenticated.json", "protected-resource.json", "authorization-server.json", "pkce-flow.json", "pkce-rejected.json", "bad-signature.json", "expired.json", "wrong-issuer.json", "wrong-audience.json", "wrong-scope.json", "valid-token.json", "substitution.json", "initialize.json", "tools-list-diff.json", "meetings.json", "transcript.json", "upstream-error.json", "chatgpt.json", "server.log"]) {
    try {
      const text = await readFile(path.join(evidenceDir, file), "utf8");
      if (text.includes(key) || text.includes("eyJ")) leaks.push(file);
    } catch {
      // Evidence file is written only after its test runs.
    }
  }
  if (serverLog.includes(key)) leaks.push("server-log-memory");
  await writeFile(path.join(evidenceDir, "server.log"), serverLog.split(key).join("[REDACTED]"));
  await writeFile(path.join(evidenceDir, "secret-scan.json"), JSON.stringify({ leaks }, null, 2));
  await writeFile(path.join(evidenceDir, "results.json"), JSON.stringify({ cases }, null, 2));
  const failed = cases.filter((item) => item.result !== "PASS");
  console.log(failed.length ? `PHASE3 STOP ${failed.map((item) => item.id).join(",")}` : "PHASE3 PASS");
  process.exit(code);
}
