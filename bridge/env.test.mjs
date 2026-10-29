import { describe, expect, it } from "vitest";
import { envValue } from "./env.mjs";

describe("bridge envValue", () => {
  it("reads the new SECUREVAULT_ name", () => {
    expect(envValue("MCP_TOKEN", { SECUREVAULT_MCP_TOKEN: "new" })).toBe("new");
  });
  it("falls back to the legacy KEYHAVEN_ name", () => {
    expect(envValue("MCP_URL", { KEYHAVEN_MCP_URL: "old" })).toBe("old");
  });
  it("prefers the new name when both are set", () => {
    expect(envValue("MCP_TOKEN", { SECUREVAULT_MCP_TOKEN: "new", KEYHAVEN_MCP_TOKEN: "old" })).toBe("new");
  });
  it("treats a blank new value as unset", () => {
    expect(envValue("MCP_TOKEN", { SECUREVAULT_MCP_TOKEN: "  ", KEYHAVEN_MCP_TOKEN: "old" })).toBe("old");
  });
  it("returns empty when neither is set", () => {
    expect(envValue("MCP_TOKEN", {})).toBe("");
  });
});
