import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import vm from "node:vm";
import { framesToQuery, isFillableUrl, isTrustedSender, nativeRequest, pickExact, statusMessage } from "../lib/logic.js";

const dir = new URL("..", import.meta.url);
const manifest = JSON.parse(readFileSync(new URL("manifest.json", dir), "utf8"));

function loadFields() {
  const ctx = {};
  ctx.globalThis = ctx;
  vm.runInNewContext(readFileSync(new URL("lib/fields.js", dir), "utf8"), ctx);
  return ctx.SVFields;
}

describe("manifest", () => {
  it("pins the ID with a public key only", () => {
    const der = Buffer.from(manifest.key, "base64");
    const hex = createHash("sha256").update(der).digest("hex").slice(0, 32);
    const id = [...hex].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
    expect(id).toBe("lldiolamhehhhjchiinofbnbeabnclcm");
    expect(der.length).toBeLessThan(600); // SPKI public key; private keys are far larger
    expect(JSON.stringify(manifest)).not.toMatch(/PRIVATE/);
  });
  it("asks for minimal permissions and no host access", () => {
    expect(manifest.manifest_version).toBe(3);
    expect(manifest.permissions.sort()).toEqual(["activeTab", "nativeMessaging", "scripting"]);
    expect(manifest.host_permissions).toBeUndefined();
    expect(manifest.content_scripts).toBeUndefined();
    expect(manifest.version).toBe("0.6.1");
  });
});

describe("frames", () => {
  const r = (frameId, url, hasLogin = true) => ({ frameId, result: { url, hasLogin } });
  it("only https frames with login fields, subframes carry top_url", () => {
    const q = framesToQuery(
      [r(0, "https://github.com/login"), r(3, "https://evil.example/x"), r(4, "http://github.com/"), r(5, "https://a.b/", false)],
      "https://github.com/login",
    );
    expect(q).toEqual([
      { frameId: 0, page_url: "https://github.com/login" },
      { frameId: 3, page_url: "https://evil.example/x", top_url: "https://github.com/login" },
    ]);
  });
  it("rejects non-https", () => {
    for (const u of ["http://github.com", "javascript:alert(1)", "data:text/html,x", "file:///etc", "nope"]) {
      expect(isFillableUrl(u)).toBe(false);
    }
  });
});

describe("policy helpers", () => {
  it("shortcut fills only a single exact match", () => {
    expect(pickExact([{ id: "1", level: "same_site" }])).toBeNull();
    expect(pickExact([{ id: "1", level: "exact" }, { id: "2", level: "exact" }])).toBeNull();
    expect(pickExact([{ id: "1", level: "exact" }, { id: "2", level: "same_site" }]).id).toBe("1");
  });
  it("trusts only its own popup", () => {
    const pop = "chrome-extension://me/popup.html";
    expect(isTrustedSender({ id: "me", url: pop }, "me", pop)).toBe(true);
    expect(isTrustedSender({ id: "me", url: pop, tab: { id: 1 } }, "me", pop)).toBe(false);
    expect(isTrustedSender({ id: "other", url: pop }, "me", pop)).toBe(false);
    expect(isTrustedSender({ id: "me", url: "https://evil/" }, "me", pop)).toBe(false);
  });
  it("never forwards token or caller_origin", () => {
    expect(nativeRequest("status", { token: "x", caller_origin: "y", page_url: "https://a/" })).toEqual({
      op: "status",
      page_url: "https://a/",
    });
  });
  it("has messages for every host status", () => {
    for (const s of ["locked", "unauthorized", "unavailable", "denied"]) expect(statusMessage(s)).toBeTruthy();
    expect(statusMessage("weird")).toBe(statusMessage("unavailable"));
  });
});

describe("field detection", () => {
  const F = loadFields();
  const d = (o) => ({ type: "text", autocomplete: "", name: "", id: "", visible: true, disabled: false, readOnly: false, form: 0, ...o });
  it("finds username + password", () => {
    expect(F.classify([d({ name: "q", form: -1 }), d({ name: "email" }), d({ type: "password" })])).toEqual({ username: 1, password: 2 });
  });
  it("skips hidden password fields", () => {
    expect(F.classify([d({ type: "password", visible: false })])).toBeNull();
  });
  it("prefers current-password over new-password", () => {
    expect(F.classify([d({ type: "password", autocomplete: "new-password" }), d({ type: "password", autocomplete: "current-password" })]).password).toBe(1);
  });
  it("does not take a username from another form", () => {
    expect(F.classify([d({ name: "user", form: 1 }), d({ type: "password", form: 0 })])).toEqual({ username: -1, password: 1 });
  });
});
