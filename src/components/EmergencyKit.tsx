import type { ReactNode } from "react";
import { useEffect, useState } from "react";
import QRCode from "qrcode";
import {
  copyToClipboard,
  isTauri,
  mapError,
  printEmergencyKit,
  saveEmergencyKitPdf,
  saveSecretKeyQr,
} from "../api";
import type { EmergencyKit as Kit } from "../types";

function koreanError(err: unknown, fallback: string): string {
  const raw = (err instanceof Error ? err.message : String(err)).trim();
  if (!raw) return fallback;
  const mapped = mapError(raw);
  if (mapped !== raw) return mapped;
  if (/[가-힣]/.test(mapped)) return mapped;
  return fallback;
}

function EkIcon({ children }: { children: ReactNode }) {
  return (
    <svg
      className="ek-icon"
      viewBox="0 0 24 24"
      aria-hidden="true"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      {children}
    </svg>
  );
}

function PdfIcon() {
  return (
    <EkIcon>
      <path d="M7 3.5h7.2L19 8.2V20a1.5 1.5 0 0 1-1.5 1.5h-10A1.5 1.5 0 0 1 6 20V5A1.5 1.5 0 0 1 7.5 3.5H7z" />
      <path d="M14 3.5V8.5h5" />
      <path d="M8.5 13h7M8.5 16.5h4.5" />
    </EkIcon>
  );
}

function PrintIcon() {
  return (
    <EkIcon>
      <path d="M7 9V4.5h10V9" />
      <path d="M6.5 17.5H5a1.5 1.5 0 0 1-1.5-1.5v-4A1.5 1.5 0 0 1 5 10.5h14a1.5 1.5 0 0 1 1.5 1.5v4a1.5 1.5 0 0 1-1.5 1.5h-1.5" />
      <rect x="7" y="14" width="10" height="6.5" rx="1.2" />
    </EkIcon>
  );
}

function CopyIcon() {
  return (
    <EkIcon>
      <rect x="9" y="9" width="10" height="10" rx="1.6" />
      <path d="M7 15H6.2A1.7 1.7 0 0 1 4.5 13.3V6.2A1.7 1.7 0 0 1 6.2 4.5h7.1A1.7 1.7 0 0 1 15 6.2V7" />
    </EkIcon>
  );
}

function QrIcon() {
  return (
    <EkIcon>
      <rect x="4" y="4" width="6.5" height="6.5" rx="1" />
      <rect x="13.5" y="4" width="6.5" height="6.5" rx="1" />
      <rect x="4" y="13.5" width="6.5" height="6.5" rx="1" />
      <path d="M13.5 13.5h3v3h-3zM18 13.5h2v6.5h-6.5v-2H18" />
    </EkIcon>
  );
}

export default function EmergencyKit({
  kit,
  onDone,
  viewOnly,
}: {
  kit: Kit;
  onDone: () => void;
  viewOnly?: boolean;
}) {
  const [qr, setQr] = useState("");
  const [kept, setKept] = useState(false);
  const [error, setError] = useState("");
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setError("");
    setStatus("");
    void QRCode.toDataURL(kit.secretKey, { margin: 1, width: 360, errorCorrectionLevel: "M" }).then(
      (url) => {
        if (!cancelled) setQr(url);
      },
      (err: unknown) => {
        if (!cancelled) setError(koreanError(err, "QR 이미지를 만들지 못했습니다."));
      },
    );
    return () => {
      cancelled = true;
    };
  }, [kit.secretKey]);

  const canFinish = viewOnly || kept;
  const desktop = isTauri();

  async function copyKey() {
    setError("");
    setStatus("");
    try {
      await copyToClipboard(kit.secretKey, 0);
      setStatus("Secret Key를 복사했습니다.");
    } catch (err) {
      setError(koreanError(err, "Secret Key를 클립보드에 복사하지 못했습니다."));
    }
  }

  async function saveQr() {
    setError("");
    setStatus("");
    setBusy(true);
    try {
      const path = await saveSecretKeyQr(kit.secretKey);
      if (!path) return;
      setStatus(desktop ? `QR 이미지를 저장했습니다: ${path}` : "QR 이미지를 내려받았습니다.");
    } catch (err) {
      setError(koreanError(err, "QR 이미지를 저장하지 못했습니다."));
    } finally {
      setBusy(false);
    }
  }

  async function savePdf() {
    setError("");
    setStatus("");
    setBusy(true);
    try {
      const path = await saveEmergencyKitPdf(kit);
      if (!path) return;
      setStatus(desktop ? `PDF를 저장했습니다: ${path}` : "PDF를 내려받았습니다.");
    } catch (err) {
      setError(koreanError(err, "PDF를 저장하지 못했습니다."));
    } finally {
      setBusy(false);
    }
  }

  async function printKit() {
    setError("");
    setStatus("");
    setBusy(true);
    try {
      await printEmergencyKit(kit);
      setStatus(desktop ? "Preview에서 인쇄할 PDF를 열었습니다." : "인쇄 미리보기를 열었습니다.");
    } catch (err) {
      setError(koreanError(err, "인쇄하지 못했습니다."));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop emergency-backdrop" role="presentation">
      <div
        className="modal emergency-kit"
        role="dialog"
        aria-modal="true"
        aria-labelledby="emergency-kit-title"
      >
        <div className="emergency-main">
          <h2 id="emergency-kit-title">비상 키트</h2>
          <p className="lede">
            Secret Key는 금고 파일에 저장되지 않습니다. 종이로 인쇄해 안전한 곳에 보관하세요. 기기와 비밀번호를
            함께 잃으면 이 키 없이는 금고를 열 수 없습니다.
          </p>
          {kit.storeError ? (
            <p className="notice emergency-store-error">
              이 기기에 Secret Key를 저장하지 못했습니다. 잠금 해제할 때마다 입력하세요.
            </p>
          ) : null}
          <div className="emergency-columns">
            <div className="emergency-qr-col">
              <div className="emergency-qr">
                {qr ? <img src={qr} alt="Secret Key QR" /> : <p>QR 만드는 중…</p>}
              </div>
            </div>
            <div className="emergency-details">
              <div className="emergency-meta">
                <div>
                  <span>금고</span>
                  <strong>{kit.vaultName}</strong>
                </div>
                <div>
                  <span>날짜</span>
                  <strong>{kit.date}</strong>
                </div>
              </div>
              <label className="field">
                <span>Secret Key</span>
                <textarea className="secret-key-display" readOnly value={kit.secretKey} rows={2} />
              </label>
              <label className="field emergency-password-blank">
                <span>마스터 비밀번호</span>
                <div className="handwrite-box">손으로 적으세요</div>
              </label>
            </div>
          </div>
          {error ? (
            <p className="error emergency-feedback" role="alert">
              {error}
            </p>
          ) : null}
          {status ? <p className="notice emergency-feedback">{status}</p> : null}
        </div>
        <div className="emergency-footer no-print">
          <div className="emergency-footer-left">
            <button className="btn emergency-btn" type="button" disabled={busy} onClick={() => void savePdf()}>
              <PdfIcon />
              PDF로 저장
            </button>
            <button className="btn emergency-btn" type="button" disabled={busy} onClick={() => void printKit()}>
              <PrintIcon />
              인쇄
            </button>
            <button className="btn emergency-btn" type="button" disabled={busy} onClick={() => void copyKey()}>
              <CopyIcon />
              Secret Key 복사
            </button>
            <button className="btn emergency-btn" type="button" disabled={busy} onClick={() => void saveQr()}>
              <QrIcon />
              QR 이미지 저장
            </button>
          </div>
          <div className="emergency-footer-right">
            {viewOnly ? null : (
              <label className="check-row emergency-kept">
                <input
                  type="checkbox"
                  checked={kept}
                  onChange={(e) => setKept(e.target.checked)}
                />
                <span>안전한 곳에 보관했어요</span>
              </label>
            )}
            <button
              className={`btn emergency-btn emergency-done${canFinish ? " btn-primary" : ""}`}
              type="button"
              disabled={!canFinish}
              onClick={onDone}
            >
              {viewOnly ? "닫기" : "완료"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
