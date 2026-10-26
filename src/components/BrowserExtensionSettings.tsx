import { useEffect, useState } from "react";
import { autofillGetStatus, autofillInstallHost, autofillSetEnabled, type AutofillStatus } from "../api";
import type { Toast } from "../types";

export default function BrowserExtensionSettings({ onToast }: { onToast: (toast: Omit<Toast, "id">) => void }) {
  const [status, setStatus] = useState<AutofillStatus | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    autofillGetStatus()
      .then(setStatus)
      .catch(() => setStatus(null));
  }, []);

  if (!status || !status.supported) return null;

  const run = (p: Promise<AutofillStatus>, ok: string) => {
    setBusy(true);
    p.then((s) => {
      setStatus(s);
      onToast({ kind: "ok", message: ok });
    })
      .catch((e) => onToast({ kind: "err", message: String(e) }))
      .finally(() => setBusy(false));
  };

  return (
    <div className="card">
      <h3>브라우저 확장 연결</h3>
      <p className="lede">
        켜 두면 SecureVault Chrome 확장이 이 앱에 로그인 정보를 물어볼 수 있습니다. 같은 사이트(HTTPS)일 때만 후보를 보여 주고,
        잠겨 있으면 아무것도 알려 주지 않습니다. 연결은 이 Mac 안에서만 이루어지며(네트워크 포트 없음), 기본값은 꺼짐입니다.
      </p>
      <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <input
          type="checkbox"
          checked={status.enabled}
          disabled={busy}
          onChange={(e) =>
            run(autofillSetEnabled(e.target.checked), e.target.checked ? "브라우저 확장 연결을 켰습니다" : "브라우저 확장 연결을 껐습니다")
          }
        />
        브라우저 확장 연결
      </label>
      <p className="lede" style={{ marginTop: 8 }}>
        상태: {status.listening ? "연결 대기 중" : "꺼짐"} · Chrome 호스트: {status.hostInstalled ? "설치됨" : "설치 안 됨"}
        <br />
        확장 ID: <code>{status.extensionId}</code>
      </p>
      <div className="row" style={{ marginTop: 10 }}>
        <button
          type="button"
          className="btn btn-ghost"
          disabled={busy}
          onClick={() => run(autofillInstallHost(), "Chrome 네이티브 호스트를 설치했습니다")}
        >
          {status.hostInstalled ? "Chrome 호스트 다시 설치" : "Chrome 호스트 설치"}
        </button>
      </div>
    </div>
  );
}
