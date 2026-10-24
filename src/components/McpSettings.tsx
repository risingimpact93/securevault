import { FormEvent, useEffect, useState } from "react";
import {
  copyToClipboard,
  getMcpAccessLog,
  getMcpSettings,
  isTauri,
  issueMcpToken,
  revokeMcpToken,
  setMcpSettings,
} from "../api";
import type { AccessLogEntry, McpSettings as McpSettingsData, Toast } from "../types";

function when(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString("ko-KR");
}

export default function McpSettings({
  onToast,
}: {
  onToast: (toast: Omit<Toast, "id">) => void;
}) {
  const [settings, setSettings] = useState<McpSettingsData | null>(null);
  const [enabled, setEnabled] = useState(false);
  const [port, setPort] = useState(47821);
  const [logs, setLogs] = useState<AccessLogEntry[]>([]);
  const [tokenName, setTokenName] = useState("");
  const [freshToken, setFreshToken] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function reload() {
    const [next, nextLogs] = await Promise.all([getMcpSettings(), getMcpAccessLog()]);
    setSettings(next);
    setEnabled(next.enabled);
    setPort(next.port);
    setLogs([...nextLogs].reverse());
  }

  useEffect(() => {
    void reload().catch((err: unknown) => {
      onToast({ kind: "err", message: err instanceof Error ? err.message : String(err) });
    });
  }, []);

  async function apply(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      await setMcpSettings(enabled, port);
      await reload();
      onToast({ kind: "ok", message: enabled ? "MCP 서버를 적용했습니다." : "MCP 서버를 껐습니다." });
    } catch (err) {
      onToast({ kind: "err", message: err instanceof Error ? err.message : String(err) });
    } finally {
      setBusy(false);
    }
  }

  async function issue(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const issued = await issueMcpToken(tokenName);
      setFreshToken(issued.token);
      setTokenName("");
      await reload();
      onToast({ kind: "ok", message: "토큰을 발급했습니다. 이 화면에서만 확인할 수 있습니다." });
    } catch (err) {
      onToast({ kind: "err", message: err instanceof Error ? err.message : String(err) });
    } finally {
      setBusy(false);
    }
  }

  async function revoke(id: string) {
    setBusy(true);
    try {
      await revokeMcpToken(id);
      await reload();
      onToast({ kind: "ok", message: "토큰을 폐기했습니다." });
    } catch (err) {
      onToast({ kind: "err", message: err instanceof Error ? err.message : String(err) });
    } finally {
      setBusy(false);
    }
  }

  async function copyToken() {
    if (!freshToken) return;
    try {
      await copyToClipboard(freshToken, 0);
      onToast({ kind: "ok", message: "토큰을 복사했습니다." });
    } catch (err) {
      onToast({ kind: "err", message: err instanceof Error ? err.message : String(err) });
    }
  }

  return (
    <>
      <form className="card" onSubmit={(e) => void apply(e)}>
        <h3>MCP 연결</h3>
        <p className="lede">
          {isTauri()
            ? "서버는 127.0.0.1에만 열립니다. 기본 포트는 47821입니다. 금고가 잠겨 있으면 도구 호출이 거부됩니다."
            : "MCP는 이 웹 서버의 /mcp 경로에서 Bearer 토큰으로 동작합니다. 금고가 잠겨 있으면 도구 호출이 거부됩니다."}
        </p>
        <label className="row" style={{ marginBottom: 14 }}>
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          MCP 서버 사용
        </label>
        {isTauri() ? (
          <label className="field">
            <span>포트</span>
            <input
              type="number"
              min={1}
              max={65535}
              value={port}
              onChange={(e) => setPort(Number(e.target.value) || 0)}
            />
          </label>
        ) : null}
        <button className="btn btn-primary" type="submit" disabled={busy}>
          적용
        </button>
      </form>

      <form className="card" onSubmit={(e) => void issue(e)}>
        <h3>접근 토큰</h3>
        <p className="lede">토큰은 발급 직후 한 번만 표시됩니다. 서버에는 SHA-256 해시만 저장됩니다.</p>
        <label className="field">
          <span>이름</span>
          <input
            value={tokenName}
            onChange={(e) => setTokenName(e.target.value)}
            placeholder="예: Claude Desktop"
          />
        </label>
        <button className="btn" type="submit" disabled={busy}>
          토큰 발급
        </button>
        {freshToken ? (
          <div className="token-once">
            <div className="lbl">새 토큰 (다시 표시되지 않습니다)</div>
            <div>{freshToken}</div>
            <div className="actions" style={{ marginTop: 8 }}>
              <button className="btn btn-small" type="button" onClick={() => void copyToken()}>
                복사
              </button>
              <button className="btn btn-ghost btn-small" type="button" onClick={() => setFreshToken(null)}>
                닫기
              </button>
            </div>
          </div>
        ) : null}
        <div className="log-wrap" style={{ marginTop: 12 }}>
          <table className="log-table">
            <thead>
              <tr>
                <th>이름</th>
                <th>만든 시각</th>
                <th>마지막 사용</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {(settings?.tokens ?? []).length === 0 ? (
                <tr>
                  <td colSpan={4}>발급된 토큰이 없습니다.</td>
                </tr>
              ) : (
                settings?.tokens.map((token) => (
                  <tr key={token.id}>
                    <td>{token.name}</td>
                    <td>{when(token.createdAt)}</td>
                    <td>{when(token.lastUsedAt)}</td>
                    <td>
                      <button
                        className="btn btn-danger btn-small"
                        type="button"
                        disabled={busy}
                        onClick={() => void revoke(token.id)}
                      >
                        폐기
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </form>

      <div className="card">
        <div className="detail-head">
          <h3>접근 기록</h3>
          <button className="btn btn-ghost btn-small" type="button" onClick={() => void reload()}>
            새로고침
          </button>
        </div>
        <div className="log-wrap">
          <table className="log-table">
            <thead>
              <tr>
                <th>시각</th>
                <th>토큰</th>
                <th>도구</th>
                <th>항목</th>
                <th>결과</th>
                <th>이유</th>
              </tr>
            </thead>
            <tbody>
              {logs.length === 0 ? (
                <tr>
                  <td colSpan={6}>기록이 없습니다.</td>
                </tr>
              ) : (
                logs.map((entry, index) => (
                  <tr key={`${entry.timestamp}-${index}`}>
                    <td>{when(entry.timestamp)}</td>
                    <td>{entry.tokenName}</td>
                    <td>{entry.tool}</td>
                    <td>{entry.itemId || "—"}</td>
                    <td>{entry.allowed ? "허용" : "거부"}</td>
                    <td>{entry.reason}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
