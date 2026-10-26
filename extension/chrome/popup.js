import { statusMessage } from "./lib/logic.js";

const msg = document.getElementById("msg");
const list = document.getElementById("list");

function show(text) {
  msg.textContent = text;
  msg.hidden = !text;
}

function row(tabId, group, item) {
  const li = document.createElement("li");
  const btn = document.createElement("button");
  const title = document.createElement("span");
  title.textContent = item.title || item.host;
  const sub = document.createElement("span");
  sub.className = "sub";
  sub.textContent = `${item.username || ""} · ${item.host}`;
  btn.append(title, sub);
  if (item.level !== "exact") {
    const tag = document.createElement("span");
    tag.className = "tag";
    tag.textContent = "하위 도메인 항목 · 클릭해야 채웁니다";
    btn.append(tag);
  }
  btn.addEventListener("click", async () => {
    const res = await chrome.runtime.sendMessage({
      type: "fill",
      tabId,
      itemId: item.id,
      frame: { frameId: group.frameId, page_url: group.page_url, top_url: group.top_url },
    });
    if (res?.status === "filled") window.close();
    else show(statusMessage(res?.status));
  });
  li.append(btn);
  return li;
}

(async () => {
  const res = await chrome.runtime.sendMessage({ type: "candidates" });
  if (res?.status !== "candidates") return show(statusMessage(res?.status));
  const total = res.groups.reduce((n, g) => n + g.items.length, 0);
  if (!total) return show(statusMessage("none"));
  show("");
  for (const g of res.groups) for (const it of g.items) list.append(row(res.tabId, g, it));
})();
