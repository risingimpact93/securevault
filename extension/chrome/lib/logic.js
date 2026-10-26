// Pure helpers shared by the service worker and popup (unit tested).

export const HOST_NAME = "com.securevault.nmh";

export const MESSAGES = {
  unavailable: "SecureVault 앱이 실행 중이 아니거나 '브라우저 확장 연결'이 꺼져 있습니다.",
  unauthorized: "앱이 이 확장을 거부했습니다. 앱 설정에서 Chrome 호스트를 다시 설치해 주세요.",
  locked: "SecureVault가 잠겨 있습니다. 앱에서 잠금을 해제해 주세요.",
  denied: "이 페이지에는 채울 수 없습니다.",
  needs_confirmation: "목록에서 직접 선택해 주세요.",
  none: "이 사이트에 맞는 로그인 항목이 없습니다.",
  no_fields: "이 페이지에서 로그인 입력란을 찾지 못했습니다.",
  restricted: "이 페이지에서는 확장을 사용할 수 없습니다.",
};

export function statusMessage(status) {
  return MESSAGES[status] || MESSAGES.unavailable;
}

/** https pages only; everything else is never sent to the app. */
export function isFillableUrl(url) {
  try {
    return new URL(url).protocol === "https:";
  } catch {
    return false;
  }
}

/**
 * From executeScript results ([{frameId, result:{url, hasLogin}}]) build the
 * list of frames to ask the app about. Subframes carry the top URL so the
 * app can refuse cross-site iframes.
 */
export function framesToQuery(results, tabUrl) {
  const top = results.find((r) => r.frameId === 0)?.result?.url || tabUrl;
  return results
    .filter((r) => r?.result?.hasLogin && isFillableUrl(r.result.url))
    .map((r) => ({
      frameId: r.frameId,
      page_url: r.result.url,
      ...(r.frameId === 0 ? {} : { top_url: top }),
    }));
}

/** Keyboard shortcut: fill only when there is exactly one exact match. */
export function pickExact(items) {
  const exact = (items || []).filter((c) => c.level === "exact");
  return exact.length === 1 ? exact[0] : null;
}

/** Only the extension's own popup may drive the service worker. */
export function isTrustedSender(sender, runtimeId, popupUrl) {
  return !!sender && sender.id === runtimeId && !sender.tab && typeof sender.url === "string" && sender.url.startsWith(popupUrl);
}

/** Only these keys ever go to the native host. */
export function nativeRequest(op, fields = {}) {
  const out = { op };
  for (const k of ["page_url", "top_url", "item_id", "user_confirmed"]) {
    if (fields[k] !== undefined) out[k] = fields[k];
  }
  return out;
}
