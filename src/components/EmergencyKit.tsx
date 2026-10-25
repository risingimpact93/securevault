import { useEffect, useState } from "react";
import QRCode from "qrcode";
import type { EmergencyKit as Kit } from "../types";

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

  useEffect(() => {
    let cancelled = false;
    void QRCode.toDataURL(kit.secretKey, { margin: 1, width: 280, errorCorrectionLevel: "M" }).then(
      (url) => {
        if (!cancelled) setQr(url);
      },
    );
    return () => {
      cancelled = true;
    };
  }, [kit.secretKey]);

  function printKit() {
    window.print();
  }

  const canFinish = viewOnly || kept;

  return (
    <div className="modal-backdrop emergency-backdrop" role="presentation">
      <div
        className="modal emergency-kit"
        role="dialog"
        aria-modal="true"
        aria-labelledby="emergency-kit-title"
      >
        <h2 id="emergency-kit-title">비상 키트</h2>
        <p className="lede">
          Secret Key는 금고 파일에 저장되지 않습니다. 종이로 인쇄해 안전한 곳에 보관하세요. 기기와 비밀번호를
          함께 잃으면 이 키 없이는 금고를 열 수 없습니다.
        </p>
        {kit.storeError ? (
          <p className="notice">
            이 기기에 Secret Key를 저장하지 못했습니다. 잠금 해제할 때마다 입력하세요.
          </p>
        ) : null}
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
          <textarea className="secret-key-display" readOnly value={kit.secretKey} rows={3} />
        </label>
        <div className="emergency-qr">{qr ? <img src={qr} alt="Secret Key QR" /> : <p>QR 만드는 중…</p>}</div>
        <label className="field emergency-password-blank">
          <span>마스터 비밀번호</span>
          <div className="handwrite-box">손으로 적으세요</div>
        </label>
        <div className="actions emergency-actions no-print">
          <button className="btn" type="button" onClick={printKit}>
            인쇄
          </button>
          <button className="btn" type="button" onClick={printKit}>
            PDF로 저장
          </button>
        </div>
        {viewOnly ? null : (
          <label className="check-row no-print">
            <input type="checkbox" checked={kept} onChange={(e) => setKept(e.target.checked)} />
            <span>보관했어요</span>
          </label>
        )}
        <button className="btn btn-primary no-print" type="button" disabled={!canFinish} onClick={onDone}>
          {viewOnly ? "닫기" : "완료"}
        </button>
      </div>
    </div>
  );
}
