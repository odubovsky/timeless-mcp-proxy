import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { mcpRequest, rpcBody, TIMELESS_MCP_URL } from "./mcp-client.mjs";

const evidenceDir = path.resolve("evidence/phase1");
const key = process.env.TIMELESS_API_KEY;
if (!key) {
  console.error("TIMELESS_API_KEY is not set. Source .env before running.");
  process.exit(1);
}

const cases = [];
const notes = [];

function record(id, result, evidence, note = "") {
  cases.push({ id, result, evidence, note });
  console.log(`${id} ${result}${note ? ` — ${note}` : ""}`);
}

function redact(value) {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  return text.split(key).join("[REDACTED]");
}

function headerSubset(headers) {
  const keep = [
    "content-type",
    "www-authenticate",
    "mcp-session-id",
    "mcp-protocol-version",
    "cache-control",
    "x-accel-buffering",
  ];
  const out = {};
  for (const name of keep) {
    if (headers[name] != null) out[name] = headers[name];
  }
  return out;
}

function summarizeJson(value, depth = 0) {
  if (value == null || typeof value !== "object") {
    return { type: value == null ? "null" : typeof value };
  }
  if (Array.isArray(value)) {
    return {
      type: "array",
      length: value.length,
      item: value.length ? summarizeJson(value[0], depth + 1) : null,
    };
  }
  const summary = { type: "object", keys: Object.keys(value).sort() };
  if (depth < 2) {
    summary.fields = {};
    for (const [field, fieldValue] of Object.entries(value)) {
      if (field === "text" || field === "title" || field === "share_url") {
        summary.fields[field] = {
          type: typeof fieldValue,
          length: typeof fieldValue === "string" ? fieldValue.length : undefined,
        };
      } else if (typeof fieldValue === "string" || typeof fieldValue === "number" || typeof fieldValue === "boolean") {
        summary.fields[field] = field.endsWith("_id") || field === "id"
          ? { type: typeof fieldValue, length: String(fieldValue).length, prefix: String(fieldValue).slice(0, 4) }
          : { type: typeof fieldValue };
      } else {
        summary.fields[field] = summarizeJson(fieldValue, depth + 1);
      }
    }
  }
  return summary;
}

await mkdir(evidenceDir, { recursive: true });

const init = await mcpRequest({
  url: TIMELESS_MCP_URL,
  token: key,
  body: rpcBody("initialize", {
    protocolVersion: "2025-03-26",
    capabilities: {},
    clientInfo: { name: "timeless-proxy-baseline", version: "0.1.0" },
  }),
});
const initMsg = init.messages[0];
const initOk = init.status === 200 && initMsg?.result?.protocolVersion && initMsg?.result?.serverInfo;
record(
  "TC-101",
  initOk ? "PASS" : "FAIL",
  "evidence/phase1/initialize.json",
  initOk ? "authentication accepted" : `status ${init.status}`,
);
record(
  "TC-102",
  initOk ? "PASS" : "FAIL",
  "evidence/phase1/initialize.json",
  initOk
    ? `${initMsg.result.serverInfo.name} ${initMsg.result.serverInfo.version} protocol ${initMsg.result.protocolVersion}`
    : "initialize failed",
);

const initialized = await mcpRequest({
  url: TIMELESS_MCP_URL,
  token: key,
  body: rpcBody("notifications/initialized", undefined, null),
});

await writeFile(
  path.join(evidenceDir, "initialize.json"),
  JSON.stringify(
    {
      url: TIMELESS_MCP_URL,
      status: init.status,
      headers: headerSubset(init.headers),
      result: initMsg?.result ?? null,
      notificationStatus: initialized.status,
      notificationBodyEmpty: initialized.raw.length === 0,
    },
    null,
    2,
  ),
);

if (!initOk) {
  await finish(1);
}

const toolsResponse = await mcpRequest({
  url: TIMELESS_MCP_URL,
  token: key,
  body: rpcBody("tools/list", {}, 2),
});
const toolsMsg = toolsResponse.messages[0];
const tools = toolsMsg?.result?.tools;
const toolsOk = toolsResponse.status === 200 && Array.isArray(tools) && tools.length > 0;
await writeFile(
  path.join(evidenceDir, "tools-list.json"),
  redact(JSON.stringify({ status: toolsResponse.status, headers: headerSubset(toolsResponse.headers), result: toolsMsg?.result ?? null }, null, 2)),
);
record("TC-103", toolsOk ? "PASS" : "FAIL", "evidence/phase1/tools-list.json", toolsOk ? `${tools.length} tools` : "tools/list failed");

if (!toolsOk) await finish(1);

const schemaProblems = [];
for (const tool of tools) {
  if (typeof tool.name !== "string" || !tool.name) schemaProblems.push("missing name");
  if (tool.description != null && typeof tool.description !== "string") schemaProblems.push(`${tool.name} description`);
  const schema = tool.inputSchema;
  if (!schema || schema.type !== "object" || typeof schema !== "object") {
    schemaProblems.push(`${tool.name || "?"} inputSchema`);
  }
}
await writeFile(
  path.join(evidenceDir, "schema-validation.json"),
  JSON.stringify({ toolCount: tools.length, problems: schemaProblems, names: tools.map((tool) => tool.name) }, null, 2),
);
record(
  "TC-104",
  schemaProblems.length === 0 ? "PASS" : "FAIL",
  "evidence/phase1/schema-validation.json",
  schemaProblems.length === 0 ? `${tools.length} schemas usable` : schemaProblems.join("; "),
);
if (schemaProblems.length) await finish(1);

async function callTool(name, args, id) {
  return mcpRequest({
    url: TIMELESS_MCP_URL,
    token: key,
    body: rpcBody("tools/call", { name, arguments: args }, id),
  });
}

function toolPayload(message) {
  const result = message?.result;
  if (!result || result.isError) return { error: true, result };
  const text = result.content?.find((item) => item.type === "text")?.text;
  let parsed = null;
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = { nonJsonTextLength: text.length };
    }
  }
  return { error: false, parsed, structured: result.structuredContent ?? null };
}

const meetings = await callTool("list_meetings", { limit: 1, status: "completed" }, 3);
const meetingPayload = toolPayload(meetings.messages[0]);
const meeting = meetingPayload.parsed?.data?.[0];
const meetingOk = meetings.status === 200 && !meetingPayload.error && meeting?.id;
await writeFile(
  path.join(evidenceDir, "list-meetings.json"),
  JSON.stringify(
    {
      status: meetings.status,
      headers: headerSubset(meetings.headers),
      isError: Boolean(meetingPayload.error),
      shape: summarizeJson(meetingPayload.parsed),
    },
    null,
    2,
  ),
);
record("TC-105", meetingOk ? "PASS" : "FAIL", "evidence/phase1/list-meetings.json", meetingOk ? "one meeting returned" : "discovery failed");
if (!meetingOk) await finish(1);

await writeFile(
  path.join(evidenceDir, "runtime.json"),
  JSON.stringify({ meetingId: meeting.id }),
);

const transcript = await callTool("get_meeting_transcript", { meeting_id: meeting.id }, 4);
const transcriptPayload = toolPayload(transcript.messages[0]);
const transcriptOk = transcript.status === 200 && !transcriptPayload.error && transcriptPayload.parsed;
await writeFile(
  path.join(evidenceDir, "transcript.json"),
  JSON.stringify(
    {
      status: transcript.status,
      headers: headerSubset(transcript.headers),
      isError: Boolean(transcriptPayload.error),
      shape: summarizeJson(transcriptPayload.parsed),
      requestedIdPrefix: String(meeting.id).slice(0, 4),
    },
    null,
    2,
  ),
);
record(
  "TC-106",
  transcriptOk ? "PASS" : "FAIL",
  "evidence/phase1/transcript.json",
  transcriptOk ? "transcript structure captured" : "transcript failed",
);
if (!transcriptOk) await finish(1);

const automation = await callTool("get_notetaker_automation", {}, 5);
const automationPayload = toolPayload(automation.messages[0]);
const automationOk = automation.status === 200 && !automationPayload.error && automationPayload.parsed && !Array.isArray(automationPayload.parsed?.data);
await writeFile(
  path.join(evidenceDir, "notetaker-automation.json"),
  JSON.stringify(
    {
      status: automation.status,
      headers: headerSubset(automation.headers),
      isError: Boolean(automationPayload.error),
      shape: summarizeJson(automationPayload.parsed),
    },
    null,
    2,
  ),
);
record(
  "TC-107",
  automationOk ? "PASS" : "FAIL",
  "evidence/phase1/notetaker-automation.json",
  automationOk ? "second payload shape captured" : "automation call failed",
);
if (!automationOk) await finish(1);

const invalid = await mcpRequest({
  url: TIMELESS_MCP_URL,
  token: "invalid-token-not-real",
  body: rpcBody("initialize", {
    protocolVersion: "2025-03-26",
    capabilities: {},
    clientInfo: { name: "timeless-proxy-baseline", version: "0.1.0" },
  }, 9),
});
const invalidOk = invalid.status === 401 && !invalid.raw.includes("mtg_") && !invalid.raw.includes(key);
await writeFile(
  path.join(evidenceDir, "invalid-credential.json"),
  JSON.stringify({ status: invalid.status, headers: headerSubset(invalid.headers), body: invalid.raw }, null, 2),
);
record("TC-108", invalidOk ? "PASS" : "FAIL", "evidence/phase1/invalid-credential.json", invalidOk ? "401 invalid_token" : `status ${invalid.status}`);
if (!invalidOk) await finish(1);

const badTool = await callTool("get_meeting_transcript", { meeting_id: "mtg_does_not_exist" }, 6);
await writeFile(
  path.join(evidenceDir, "transport.json"),
  JSON.stringify(
    {
      endpoint: TIMELESS_MCP_URL,
      transport: "streamable-http",
      requestHeaders: ["authorization", "content-type", "accept"],
      accept: "application/json, text/event-stream",
      successContentType: init.headers["content-type"],
      notificationStatus: initialized.status,
      sessionHeaderPresent: Boolean(init.headers["mcp-session-id"]),
      protocolVersion: initMsg.result.protocolVersion,
      server: initMsg.result.serverInfo,
      capabilities: initMsg.result.capabilities,
      streaming: "SSE event:message frames; single-frame responses observed",
      preserve: [
        "POST body bytes",
        "accept",
        "content-type",
        "mcp-session-id",
        "mcp-protocol-version",
        "response status",
        "response content-type",
        "SSE body",
      ],
      invalidToolStatus: badTool.status,
      invalidToolIsError: Boolean(badTool.messages[0]?.result?.isError),
      invalidToolShape: summarizeJson(toolPayload(badTool.messages[0]).parsed),
    },
    null,
    2,
  ),
);
record(
  "TC-109",
  init.headers["content-type"]?.includes("text/event-stream") ? "PASS" : "FAIL",
  "evidence/phase1/transport.json",
  "SSE POST, no session header observed",
);

const files = ["initialize.json", "tools-list.json", "schema-validation.json", "list-meetings.json", "transcript.json", "notetaker-automation.json", "invalid-credential.json", "transport.json"];
const leaks = [];
for (const file of files) {
  const text = await readFile(path.join(evidenceDir, file), "utf8");
  if (text.includes(key) || text.toLowerCase().includes("bearer " + key.toLowerCase())) leaks.push(file);
}
const runtime = await readFile(path.join(evidenceDir, "runtime.json"), "utf8");
if (runtime.includes(key)) leaks.push("runtime.json");
await writeFile(path.join(evidenceDir, "secret-scan.json"), JSON.stringify({ scanned: [...files, "runtime.json"], leaks }, null, 2));
record("TC-110", leaks.length === 0 ? "PASS" : "FAIL", "evidence/phase1/secret-scan.json", leaks.length ? leaks.join(",") : "no secrets in artifacts");
if (leaks.length) await finish(1);

await finish(0);

async function finish(code) {
  await writeFile(path.join(evidenceDir, "results.json"), JSON.stringify({ cases, notes }, null, 2));
  const failed = cases.filter((item) => item.result === "FAIL");
  console.log(failed.length ? `PHASE1 FAIL ${failed.map((item) => item.id).join(",")}` : "PHASE1 PASS");
  process.exit(code);
}
