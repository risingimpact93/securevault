#!/usr/bin/env node
// Stdio bridge for the Keyhaven MCP server. Node 18+, no dependencies.
// Reads one JSON-RPC message per line from stdin and POSTs it to the local server.

import { createInterface } from "node:readline";

const url = process.env.KEYHAVEN_MCP_URL || "http://127.0.0.1:47821/mcp";
const token = process.env.KEYHAVEN_MCP_TOKEN || "";

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });

for await (const line of lines) {
  const trimmed = line.trim();
  if (!trimmed) continue;

  let message;
  try {
    message = JSON.parse(trimmed);
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    process.stderr.write(`keyhaven mcp bridge: invalid json: ${detail}\n`);
    continue;
  }

  const isNotification =
    message &&
    typeof message === "object" &&
    !Array.isArray(message) &&
    (message.id === undefined || message.id === null);

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: `Bearer ${token}`,
      },
      body: trimmed,
    });

    if (response.status === 202 || isNotification) {
      if (!response.ok && response.status !== 202) {
        const text = await response.text();
        process.stderr.write(`keyhaven mcp bridge: HTTP ${response.status} ${text}\n`);
      }
      continue;
    }

    const text = await response.text();
    if (!response.ok) {
      process.stderr.write(`keyhaven mcp bridge: HTTP ${response.status} ${text}\n`);
      const id = message && typeof message === "object" && !Array.isArray(message) ? message.id ?? null : null;
      if (id !== null && id !== undefined) {
        process.stdout.write(
          `${JSON.stringify({
            jsonrpc: "2.0",
            id,
            error: { code: -32000, message: `HTTP ${response.status}` },
          })}\n`,
        );
      }
      continue;
    }
    if (text.trim()) {
      process.stdout.write(`${text.trim()}\n`);
    }
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    process.stderr.write(`keyhaven mcp bridge: ${detail}\n`);
    const id = message && typeof message === "object" && !Array.isArray(message) ? message.id ?? null : null;
    if (!isNotification && id !== null && id !== undefined) {
      process.stdout.write(
        `${JSON.stringify({
          jsonrpc: "2.0",
          id,
          error: { code: -32000, message: detail },
        })}\n`,
      );
    }
  }
}
