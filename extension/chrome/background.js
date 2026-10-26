import { HOST_NAME, framesToQuery, isTrustedSender, nativeRequest, pickExact } from "./lib/logic.js";

async function native(op, fields) {
  try {
    const resp = await chrome.runtime.sendNativeMessage(HOST_NAME, nativeRequest(op, fields));
    return resp && typeof resp.status === "string" ? resp : { status: "unavailable" };
  } catch {
    return { status: "unavailable" };
  }
}

async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function scanFrames(tabId) {
  const inject = async (allFrames) => {
    await chrome.scripting.executeScript({ target: { tabId, allFrames }, files: ["lib/fields.js"] });
    return chrome.scripting.executeScript({ target: { tabId, allFrames }, func: () => globalThis.SVFields.scan() });
  };
  try {
    return await inject(true);
  } catch {
    // activeTab does not cover cross-origin subframes; fall back to the top frame.
    return inject(false);
  }
}

async function candidates() {
  const tab = await activeTab();
  if (!tab?.id) return { status: "restricted" };
  const status = await native("status");
  if (status.status !== "unlocked") return status;
  let results;
  try {
    results = await scanFrames(tab.id);
  } catch {
    return { status: "restricted" };
  }
  const frames = framesToQuery(results, tab.url);
  if (frames.length === 0) return { status: "no_fields" };
  const groups = [];
  for (const f of frames) {
    const resp = await native("candidates", { page_url: f.page_url, top_url: f.top_url });
    if (resp.status === "locked" || resp.status === "unauthorized" || resp.status === "unavailable") return resp;
    if (resp.status === "candidates" && resp.items.length) groups.push({ ...f, items: resp.items });
  }
  return { status: "candidates", tabId: tab.id, groups };
}

async function fill(tabId, frame, itemId, userConfirmed) {
  const resp = await native("reveal", {
    item_id: itemId,
    page_url: frame.page_url,
    top_url: frame.top_url,
    user_confirmed: userConfirmed,
  });
  if (resp.status !== "credential") return resp;
  const { username, password } = resp.credential;
  const [res] = await chrome.scripting.executeScript({
    target: { tabId, frameIds: [frame.frameId] },
    func: (url, u, p) => globalThis.SVFields?.fill(url, u, p) ?? { ok: false, reason: "no-fields" },
    args: [frame.page_url, username, password],
  });
  return res?.result?.ok ? { status: "filled" } : { status: "denied" };
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!isTrustedSender(sender, chrome.runtime.id, chrome.runtime.getURL("popup.html"))) return false;
  (async () => {
    if (msg?.type === "candidates") return candidates();
    if (msg?.type === "fill" && msg.frame && typeof msg.itemId === "string") {
      return fill(msg.tabId, msg.frame, msg.itemId, true); // popup click = user confirmation
    }
    return { status: "denied" };
  })()
    .then(sendResponse)
    .catch(() => sendResponse({ status: "unavailable" }));
  return true;
});

chrome.commands.onCommand.addListener(async (command) => {
  if (command !== "fill-exact") return;
  const res = await candidates();
  if (res.status !== "candidates") return;
  const top = res.groups.find((g) => g.frameId === 0);
  const item = pickExact(top?.items);
  // Shortcut never confirms: subdomain matches stay click-only.
  if (item) await fill(res.tabId, top, item.id, false);
});
