import { spawn } from "node:child_process";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { mcpRequest, rpcBody, TIMELESS_MCP_URL } from "./mcp-client.mjs";

const evidenceDir = path.resolve("evidence/phase2");
const proxyUrl = process.env.PROXY_URL || "http://127.0.0.1:3010/mcp";
const key = process.env.TIMELESS_API_KEY;
if (!key) {
  console.error("TIMELESS_API_KEY is not set. Source .env before running.");
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
  return stable(
    [...tools]
      .map((tool) => ({
        name: tool.name,
        description: tool.description ?? null,
        inputSchema: tool.inputSchema ?? null,
        annotations: tool.annotations ?? null,
      }))
      .sort((left, right) => left.name.localeCompare(right.name)),
  );
}

function toolText(message) {
  return message?.result?.content?.find((item) => item.type === "text")?.text ?? "";
}

function parseTool(message) {
  const text = toolText(message);
  try {
    return { isError: Boolean(message?.result?.isError), json: text ? JSON.parse(text) : null, text };
  } catch {
    return { isError: Boolean(message?.result?.isError), json: null, text };
  }
}

function shapeOf(value) {
  if (Array.isArray(value)) return { type: "array", length: value.length, itemKeys: value[0] && typeof value[0] === "object" ? Object.keys(value[0]).sort() : [] };
  if (value && typeof value === "object") {
    const fields = {};
    for (const [name, field] of Object.entries(value)) {
      if (Array.isArray(field)) fields[name] = { type: "array", length: field.length };
      else if (field && typeof field === "object") fields[name] = { type: "object", keys: Object.keys(field).sort() };
      else fields[name] = { type: typeof field };
    }
    return { type: "object", keys: Object.keys(value).sort(), fields };
  }
  return { type: typeof value };
}

async function startServer(extra = {}, { stripKey = false } = {}) {
  await stopServer();
  serverLog = "";
  const env = { ...process.env, PORT: "3010", HOST: "127.0.0.1", ...extra };
  if (stripKey) delete env.TIMELESS_API_KEY;
  server = spawn(process.execPath, ["src/server.mjs"], { env, stdio: ["ignore", "pipe", "pipe"] });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("proxy did not start")), 5000);
    const onChunk = (chunk) => {
      serverLog += chunk.toString("utf8");
      if (serverLog.includes("listening")) {
        clearTimeout(timer);
        resolve();
      }
    };
    server.stdout.on("data", onChunk);
    server.stderr.on("data", onChunk);
    server.on("exit", (code) => {
      if (!serverLog.includes("listening")) {
        clearTimeout(timer);
        reject(new Error(`proxy exited ${code}`));
      }
    });
  });
}

async function stopServer() {
  if (!server || server.killed) {
    server = null;
    return;
  }
  const child = server;
  server = null;
  child.kill("SIGTERM");
  await new Promise((resolve) => child.once("exit", resolve));
}

async function proxyCall(body, { token } = {}) {
  const response = await mcpRequest({ url: proxyUrl, token, body });
  captured.push(response.raw);
  return response;
}

async function directCall(body) {
  return mcpRequest({ url: TIMELESS_MCP_URL, token: key, body });
}

await mkdir(evidenceDir, { recursive: true });

try {
  await startServer({ AUTH_ASSERT: "1" });
  const startupLeaks = serverLog.includes(key);
  record(
    "TC-201",
    serverLog.includes("listening") && !startupLeaks ? "PASS" : "FAIL",
    "evidence/phase2/startup.log",
    startupLeaks ? "secret printed at startup" : "listening on 127.0.0.1:3010",
  );
  if (startupLeaks || !serverLog.includes("listening")) await finish(1);

  const initBody = rpcBody("initialize", {
    protocolVersion: "2025-03-26",
    capabilities: {},
    clientInfo: { name: "timeless-proxy-phase2", version: "0.1.0" },
  }, 1);
  const directInit = await directCall(initBody);
  const proxyInit = await proxyCall(initBody);
  const initMatch = proxyInit.status === 200
    && proxyInit.messages[0]?.result?.protocolVersion === directInit.messages[0]?.result?.protocolVersion
    && proxyInit.messages[0]?.result?.serverInfo?.name === directInit.messages[0]?.result?.serverInfo?.name;
  await writeFile(path.join(evidenceDir, "initialize.json"), JSON.stringify({
    proxyStatus: proxyInit.status,
    directStatus: directInit.status,
    proxyProtocol: proxyInit.messages[0]?.result?.protocolVersion ?? null,
    proxyServer: proxyInit.messages[0]?.result?.serverInfo ?? null,
    contentType: proxyInit.headers["content-type"] ?? null,
  }, null, 2));
  record("TC-202", initMatch ? "PASS" : "FAIL", "evidence/phase2/initialize.json", initMatch ? "initialize matched native server identity" : "initialize diverged");
  if (!initMatch) await finish(1);

  await proxyCall(rpcBody("notifications/initialized", undefined, null));

  const listBody = rpcBody("tools/list", {}, 2);
  const directList = await directCall(listBody);
  const proxyList = await proxyCall(listBody);
  const directTools = normalizeTools(directList.messages[0]?.result?.tools ?? []);
  const proxyTools = normalizeTools(proxyList.messages[0]?.result?.tools ?? []);
  const sameCatalogue = JSON.stringify(directTools) === JSON.stringify(proxyTools);
  const directNames = new Set(directTools.map((tool) => tool.name));
  const proxyNames = new Set(proxyTools.map((tool) => tool.name));
  const missing = [...directNames].filter((name) => !proxyNames.has(name));
  const extra = [...proxyNames].filter((name) => !directNames.has(name));
  await writeFile(path.join(evidenceDir, "tools-list-diff.json"), JSON.stringify({
    sameCatalogue,
    directCount: directTools.length,
    proxyCount: proxyTools.length,
    missing,
    extra,
  }, null, 2));
  record("TC-203", sameCatalogue ? "PASS" : "FAIL", "evidence/phase2/tools-list-diff.json", sameCatalogue ? `${proxyTools.length} tools equivalent` : "catalogue differs");
  record("TC-204", missing.length === 0 && extra.length === 0 ? "PASS" : "FAIL", "evidence/phase2/tools-list-diff.json", `missing ${missing.length}, extra ${extra.length}`);
  record("TC-205", sameCatalogue ? "PASS" : "FAIL", "evidence/phase2/tools-list-diff.json", sameCatalogue ? "descriptions and schemas unchanged" : "definition mismatch");
  if (!sameCatalogue || missing.length || extra.length) await finish(1);

  const runtime = JSON.parse(await readFile(path.resolve("evidence/phase1/runtime.json"), "utf8"));
  const meetingArgs = { limit: 1, status: "completed" };
  const directMeetings = parseTool((await directCall(rpcBody("tools/call", { name: "list_meetings", arguments: meetingArgs }, 3))).messages[0]);
  const proxyMeetings = parseTool((await proxyCall(rpcBody("tools/call", { name: "list_meetings", arguments: meetingArgs }, 3))).messages[0]);
  const meetingsMatch = !directMeetings.isError && !proxyMeetings.isError
    && JSON.stringify(shapeOf(directMeetings.json)) === JSON.stringify(shapeOf(proxyMeetings.json))
    && directMeetings.json?.data?.[0]?.id === proxyMeetings.json?.data?.[0]?.id;
  await writeFile(path.join(evidenceDir, "meetings.json"), JSON.stringify({
    directError: directMeetings.isError,
    proxyError: proxyMeetings.isError,
    sameShape: JSON.stringify(shapeOf(directMeetings.json)) === JSON.stringify(shapeOf(proxyMeetings.json)),
    sameFirstId: directMeetings.json?.data?.[0]?.id === proxyMeetings.json?.data?.[0]?.id,
  }, null, 2));
  record("TC-206", meetingsMatch ? "PASS" : "FAIL", "evidence/phase2/meetings.json", meetingsMatch ? "discovery equivalent" : "discovery diverged");
  if (!meetingsMatch) await finish(1);

  const transcriptArgs = { meeting_id: runtime.meetingId };
  const directTranscript = parseTool((await directCall(rpcBody("tools/call", { name: "get_meeting_transcript", arguments: transcriptArgs }, 4))).messages[0]);
  const proxyTranscript = parseTool((await proxyCall(rpcBody("tools/call", { name: "get_meeting_transcript", arguments: transcriptArgs }, 4))).messages[0]);
  const transcriptMatch = !directTranscript.isError && !proxyTranscript.isError
    && directTranscript.json?.meeting_id === proxyTranscript.json?.meeting_id
    && directTranscript.json?.segments?.length === proxyTranscript.json?.segments?.length
    && JSON.stringify(shapeOf(directTranscript.json)) === JSON.stringify(shapeOf(proxyTranscript.json));
  await writeFile(path.join(evidenceDir, "transcript.json"), JSON.stringify({
    directError: directTranscript.isError,
    proxyError: proxyTranscript.isError,
    sameMeeting: directTranscript.json?.meeting_id === proxyTranscript.json?.meeting_id,
    directSegments: directTranscript.json?.segments?.length ?? null,
    proxySegments: proxyTranscript.json?.segments?.length ?? null,
    sameShape: JSON.stringify(shapeOf(directTranscript.json)) === JSON.stringify(shapeOf(proxyTranscript.json)),
  }, null, 2));
  record("TC-207", transcriptMatch ? "PASS" : "FAIL", "evidence/phase2/transcript.json", transcriptMatch ? "transcript equivalent" : "transcript diverged");
  if (!transcriptMatch) await finish(1);

  const directAuto = parseTool((await directCall(rpcBody("tools/call", { name: "get_notetaker_automation", arguments: {} }, 5))).messages[0]);
  const proxyAuto = parseTool((await proxyCall(rpcBody("tools/call", { name: "get_notetaker_automation", arguments: {} }, 5))).messages[0]);
  const autoMatch = !directAuto.isError && !proxyAuto.isError && directAuto.text === proxyAuto.text;
  await writeFile(path.join(evidenceDir, "automation.json"), JSON.stringify({
    directError: directAuto.isError,
    proxyError: proxyAuto.isError,
    sameBody: directAuto.text === proxyAuto.text,
    shape: shapeOf(proxyAuto.json),
  }, null, 2));
  record("TC-208", autoMatch ? "PASS" : "FAIL", "evidence/phase2/automation.json", autoMatch ? "automation payload equivalent" : "automation diverged");
  if (!autoMatch) await finish(1);

  const sessionOk = proxyInit.headers["content-type"]?.includes("text/event-stream")
    && proxyInit.messages[0]?.result?.protocolVersion === "2025-03-26"
    && proxyList.status === 200
    && proxyMeetings.json
    && proxyTranscript.json;
  await writeFile(path.join(evidenceDir, "transport.json"), JSON.stringify({
    contentType: proxyInit.headers["content-type"] ?? null,
    protocolVersion: proxyInit.messages[0]?.result?.protocolVersion ?? null,
    sessionHeader: proxyInit.headers["mcp-session-id"] ?? null,
    successiveCalls: sessionOk,
  }, null, 2));
  record("TC-209", sessionOk ? "PASS" : "FAIL", "evidence/phase2/transport.json", "SSE and successive calls preserved");
  if (!sessionOk) await finish(1);

  const badArgs = { meeting_id: "mtg_does_not_exist" };
  const directBad = await directCall(rpcBody("tools/call", { name: "get_meeting_transcript", arguments: badArgs }, 6));
  const proxyBad = await proxyCall(rpcBody("tools/call", { name: "get_meeting_transcript", arguments: badArgs }, 6));
  const directBadText = toolText(directBad.messages[0]).split(key).join("[REDACTED]");
  const proxyBadText = toolText(proxyBad.messages[0]).split(key).join("[REDACTED]");
  const errorMatch = directBad.status === proxyBad.status
    && Boolean(directBad.messages[0]?.result?.isError) === Boolean(proxyBad.messages[0]?.result?.isError)
    && directBadText === proxyBadText
    && !proxyBadText.includes(key);
  await writeFile(path.join(evidenceDir, "error.json"), JSON.stringify({
    directStatus: directBad.status,
    proxyStatus: proxyBad.status,
    directIsError: Boolean(directBad.messages[0]?.result?.isError),
    proxyIsError: Boolean(proxyBad.messages[0]?.result?.isError),
    sameText: directBadText === proxyBadText,
    textLength: proxyBadText.length,
  }, null, 2));
  record("TC-210", errorMatch ? "PASS" : "FAIL", "evidence/phase2/error.json", errorMatch ? "upstream error preserved" : "error diverged");
  if (!errorMatch) await finish(1);

  const asserted = await proxyCall(initBody, { token: "client-dummy-token" });
  const assertHeader = asserted.headers["x-proxy-auth-assert"] || "";
  const assertOk = assertHeader.includes("inbound-replaced=1") && assertHeader.includes("upstream-timeless=1") && !assertHeader.includes(key) && !assertHeader.includes("client-dummy-token");
  await writeFile(path.join(evidenceDir, "auth-assert.json"), JSON.stringify({ header: assertHeader, ok: assertOk }, null, 2));
  record("TC-211", assertOk ? "PASS" : "FAIL", "evidence/phase2/auth-assert.json", assertHeader || "missing assert header");
  if (!assertOk) await finish(1);

  const responseLeak = captured.some((raw) => raw.includes(key));
  record("TC-212", responseLeak ? "FAIL" : "PASS", "evidence/phase2/secret-scan.json", responseLeak ? "credential in a client response" : "credential absent from responses");
  if (responseLeak) await finish(1);

  const logLeak = serverLog.includes(key);
  record("TC-213", logLeak ? "FAIL" : "PASS", "evidence/phase2/secret-scan.json", logLeak ? "credential in server log" : "credential absent from logs");
  if (logLeak) await finish(1);

  await stopServer();
  await startServer({}, { stripKey: true });
  const closed = await proxyCall(initBody);
  const closedOk = closed.status === 503 && closed.raw.includes("timeless_credential_missing") && !closed.raw.includes("invalid_token") && !closed.raw.includes(key);
  await writeFile(path.join(evidenceDir, "fail-closed.json"), JSON.stringify({ status: closed.status, body: closed.raw }, null, 2));
  record("TC-214", closedOk ? "PASS" : "FAIL", "evidence/phase2/fail-closed.json", closedOk ? "503 without upstream call" : `status ${closed.status}`);
  if (!closedOk) await finish(1);

  const runtimeFiles = [];
  for (const file of await readdir(path.resolve("src"))) {
    if (file.endsWith(".mjs")) runtimeFiles.push(await readFile(path.resolve("src", file), "utf8"));
  }
  const catalogue = JSON.parse(await readFile(path.resolve("evidence/phase1/tools-list.json"), "utf8"));
  const names = catalogue.result.tools.map((tool) => tool.name);
  const defined = names.filter((name) => runtimeFiles.some((source) => source.includes(name)));
  await writeFile(path.join(evidenceDir, "source-audit.json"), JSON.stringify({ files: ["src/*.mjs"], definedToolNames: defined }, null, 2));
  record("TC-215", defined.length === 0 ? "PASS" : "FAIL", "evidence/phase2/source-audit.json", defined.length ? defined.join(",") : "runtime source has no Timeless catalogue");
  if (defined.length) await finish(1);

  await stopServer();
  await startServer({ AUTH_ASSERT: "1" });
  const restarted = await proxyCall(listBody);
  const restartedTools = normalizeTools(restarted.messages[0]?.result?.tools ?? []);
  const baseline = normalizeTools(catalogue.result.tools);
  const restartOk = JSON.stringify(restartedTools) === JSON.stringify(baseline);
  await writeFile(path.join(evidenceDir, "restart.json"), JSON.stringify({ equivalent: restartOk, count: restartedTools.length }, null, 2));
  record("TC-216", restartOk ? "PASS" : "FAIL", "evidence/phase2/restart.json", restartOk ? "catalogue stable across restart" : "catalogue changed");
  if (!restartOk) await finish(1);

  await finish(0);
} catch (error) {
  console.error(`PHASE2 ERROR ${error.message}`);
  await finish(1);
} finally {
  await stopServer();
}

async function finish(code) {
  await stopServer();
  const leaks = [];
  const files = await readdir(evidenceDir).catch(() => []);
  for (const file of files) {
    const text = await readFile(path.join(evidenceDir, file), "utf8");
    if (text.includes(key)) leaks.push(file);
  }
  if (serverLog.includes(key)) leaks.push("server.log");
  await writeFile(path.join(evidenceDir, "server.log"), serverLog.split(key).join("[REDACTED]"));
  await writeFile(path.join(evidenceDir, "secret-scan.json"), JSON.stringify({
    responseLeak: captured.some((raw) => raw.includes(key)),
    logLeak: serverLog.includes(key),
    evidenceLeaks: leaks,
  }, null, 2));
  await writeFile(path.join(evidenceDir, "results.json"), JSON.stringify({ cases }, null, 2));
  const failed = cases.filter((item) => item.result === "FAIL");
  console.log(failed.length ? `PHASE2 FAIL ${failed.map((item) => item.id).join(",")}` : cases.length === 16 ? "PHASE2 PASS" : `PHASE2 INCOMPLETE ${cases.length}`);
  process.exit(code);
}
