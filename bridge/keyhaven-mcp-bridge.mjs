#!/usr/bin/env node
// Compatibility launcher. Configs that still point at keyhaven-mcp-bridge.mjs
// keep working. Prefer bridge/securevault-mcp-bridge.mjs.
// KEYHAVEN_MCP_URL and KEYHAVEN_MCP_TOKEN are still accepted.
import "./securevault-mcp-bridge.mjs";
