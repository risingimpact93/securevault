// Injected into page frames (isolated world). Classic script: defines
// globalThis.SVFields. No network, no storage, no logging.
(() => {
  const USER_HINT = /user|login|email|e-mail|account|id$|^id|아이디|이메일/i;

  /**
   * Pure: pick username/password field indexes from plain descriptors.
   * desc: { type, autocomplete, name, id, visible, form } (form = form index or -1)
   * Returns { password: i, username: i|-1 } or null.
   */
  function classify(descs) {
    const ok = (d) => d.visible && !d.disabled && !d.readOnly;
    const pwIdx = descs.findIndex(
      (d) => ok(d) && d.type === "password" && !/new-password/i.test(d.autocomplete || ""),
    );
    const pw = pwIdx >= 0 ? pwIdx : descs.findIndex((d) => ok(d) && d.type === "password");
    if (pw < 0) return null;
    const textish = (d) => ["text", "email", "tel", ""].includes(d.type);
    let user = -1;
    for (let i = pw - 1; i >= 0; i--) {
      const d = descs[i];
      if (!ok(d) || !textish(d) || d.form !== descs[pw].form) continue;
      if (/username|email/i.test(d.autocomplete || "") || USER_HINT.test(`${d.name} ${d.id}`)) {
        user = i;
        break;
      }
      if (user < 0) user = i;
    }
    return { password: pw, username: user };
  }

  function inputs() {
    return Array.from(document.querySelectorAll("input"));
  }

  function describe(el) {
    const r = el.getBoundingClientRect();
    const cs = getComputedStyle(el);
    return {
      type: (el.getAttribute("type") || "").toLowerCase(),
      autocomplete: el.getAttribute("autocomplete") || "",
      name: el.name || "",
      id: el.id || "",
      visible: r.width > 0 && r.height > 0 && cs.visibility !== "hidden" && cs.display !== "none",
      disabled: el.disabled,
      readOnly: el.readOnly,
      form: el.form ? Array.from(document.forms).indexOf(el.form) : -1,
    };
  }

  function scan() {
    const found = classify(inputs().map(describe));
    return { url: location.href, hasLogin: !!found };
  }

  function setValue(el, value) {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    el.focus();
    setter.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  /** Fill only if this frame is still on the origin the app approved. */
  function fill(expectedUrl, username, password) {
    let expected;
    try {
      expected = new URL(expectedUrl);
    } catch {
      return { ok: false, reason: "bad-url" };
    }
    if (location.protocol !== "https:" || location.origin !== expected.origin) {
      return { ok: false, reason: "origin-changed" };
    }
    const els = inputs();
    const found = classify(els.map(describe));
    if (!found) return { ok: false, reason: "no-fields" };
    if (found.username >= 0 && username) setValue(els[found.username], username);
    setValue(els[found.password], password);
    return { ok: true };
  }

  globalThis.SVFields = { classify, scan, fill };
})();
