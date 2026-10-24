import { useEffect, useState } from "react";
import type { ApprovalRequest } from "../types";

const FIELD_LABEL: Record<string, string> = {
  password: "비밀번호",
  notes: "메모",
  number: "카드 번호",
  cvv: "CVV",
  cardholder: "카드 소유자",
  expiry: "유효기간",
  username: "사용자 이름",
  url: "주소",
};

export const DEMO_APPROVAL: ApprovalRequest = {
  requestId: "demo",
  tokenName: "Claude Desktop",
  itemTitle: "네이버",
  field: "password",
  timeoutSecs: 60,
};

export default function ApprovalModal({
  request,
  onApprove,
  onDeny,
}: {
  request: ApprovalRequest;
  onApprove: () => void;
  onDeny: () => void;
}) {
  const [left, setLeft] = useState(request.timeoutSecs);

  useEffect(() => {
    setLeft(request.timeoutSecs);
  }, [request.requestId, request.timeoutSecs]);

  useEffect(() => {
    if (left <= 0) {
      onDeny();
      return;
    }
    const timer = window.setTimeout(() => setLeft((value) => value - 1), 1000);
    return () => window.clearTimeout(timer);
  }, [left, onDeny]);

  const fieldLabel = FIELD_LABEL[request.field];
  const field = fieldLabel && fieldLabel !== request.field ? `${fieldLabel} (${request.field})` : request.field;

  return (
    <div className="modal-backdrop" role="presentation">
      <div className="modal approval-modal" role="dialog" aria-modal="true" aria-labelledby="approval-title">
        <h2 id="approval-title">비밀 값 접근 요청</h2>
        <p className="lede">MCP 클라이언트가 비밀 필드를 읽으려 합니다. 이번 요청만 허용됩니다.</p>
        <div className="kv">
          <div className="k">토큰</div>
          <div className="v">{request.tokenName}</div>
        </div>
        <div className="kv">
          <div className="k">항목</div>
          <div className="v">{request.itemTitle}</div>
        </div>
        <div className="kv">
          <div className="k">필드</div>
          <div className="v">{field}</div>
        </div>
        <p className="countdown">남은 시간 {left}초</p>
        <div className="actions">
          <button className="btn btn-primary" type="button" onClick={onApprove}>
            승인
          </button>
          <button className="btn btn-danger" type="button" onClick={onDeny}>
            거절
          </button>
        </div>
      </div>
    </div>
  );
}
