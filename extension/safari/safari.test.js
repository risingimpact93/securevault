import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { safariManifest } from "../../scripts/safari-manifest.mjs";
import { nativeRequest } from "../chrome/lib/logic.js";

const read = (p) => readFileSync(new URL(p, import.meta.url), "utf8");
const chrome = JSON.parse(read("../chrome/manifest.json"));
const relay = read("Extension/AutofillRelay.swift");
const rust = read("../../crates/securevault-core/src/autofill_ipc.rs");

describe("safari manifest", () => {
  const m = safariManifest(chrome);
  it("drops the Chrome key and keeps the same minimal permissions", () => {
    expect(m.key).toBeUndefined();
    expect(m.permissions).toEqual(chrome.permissions);
    expect(m.host_permissions).toBeUndefined();
    expect(m.content_scripts).toBeUndefined();
    expect(m.version).toBe("0.6.1");
    expect(m.background.type).toBe("module");
    expect(m.browser_specific_settings.safari.strict_min_version).toBe("16.4");
  });
  it("does not mutate the Chrome manifest", () => {
    expect(chrome.key).toBeTruthy();
  });
});

describe("swift relay stays in sync", () => {
  it("uses the Safari caller origin the app allows", () => {
    const origin = rust.match(/SAFARI_CALLER_ORIGIN: &str = "([^"]+)"/)[1];
    expect(relay).toContain(`callerOrigin = "${origin}"`);
  });
  it("forwards exactly the keys the extension may send", () => {
    const keys = JSON.parse(relay.match(/allowedKeys = (\[[^\]]+\])/)[1]);
    const all = nativeRequest("x", { page_url: 1, top_url: 1, item_id: 1, user_confirmed: 1, token: 1, caller_origin: 1 });
    expect(keys.sort()).toEqual(Object.keys(all).sort());
  });
  it("checks peer UID, token mode and never logs", () => {
    expect(relay).toContain("getpeereid");
    expect(relay).toContain("0o077");
    expect(relay).toContain("O_NOFOLLOW");
    expect(relay).not.toMatch(/\b(print|NSLog|os_log|Logger)\b/);
    expect(relay).not.toMatch(/AF_INET|127\.0\.0\.1|localhost/);
  });
  it("sandbox exception is limited to the autofill folder", () => {
    const ent = read("Extension/Extension.entitlements");
    expect(ent).toContain("com.apple.security.app-sandbox");
    expect(ent).not.toContain("network.client");
    expect(ent).not.toContain("network.server");
    expect([...ent.matchAll(/<string>([^<]+)<\/string>/g)].map((x) => x[1])).toEqual([
      "/Library/Application Support/com.securevault.app/autofill/",
    ]);
  });
  it("matches the Xcode template shape Safari lists", async () => {
    const { safariManifest } = await import("../../scripts/safari-manifest.mjs");
    const fs = await import("node:fs");
    const chrome = JSON.parse(fs.readFileSync(new URL("../chrome/manifest.json", import.meta.url)));
    const m = safariManifest(chrome);
    expect(m.background).toEqual({ service_worker: "background.js", type: "module" });
    for (const f of Object.values(m.icons)) expect(fs.existsSync(new URL("../chrome/" + f, import.meta.url))).toBe(true);
    expect(m.icons["512"]).toBeTruthy();
    const plist = read("Extension/Info.plist");
    for (const k of ["SFSafariWebExtensionConverterVersion", "NSHumanReadableDescription", "CFBundleDisplayName", "LSMinimumSystemVersion"]) expect(plist).toContain(k);
    expect(read("project.yml")).toContain("CODE_SIGN_INJECT_BASE_ENTITLEMENTS: NO");
  });
});
