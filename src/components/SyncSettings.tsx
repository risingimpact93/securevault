import { FormEvent, useEffect, useState } from "react";
import {
  isTauri,
  mapError,
  mergeSyncPassword,
  pickVaultFile,
  resolveSyncConflict,
  setVaultLocation,
  syncConflicts,
  syncStatus,
} from "../api";
import type { ConflictAction, ConflictView, SyncStatus, Toast, VaultLocationMode } from "../types";

function labelFor(deleted: boolean, title: string, username: string): string {
  if (deleted) return title ? `삭제됨 · ${title}` : "삭제됨";
  return username ? `${title || "제목 없음"} · ${username}` : title || "제목 없음";
}

export default function SyncSettings({
  status,
  onStatus,
  onReload,
  onToast,
  onRequireUnlock,
}: {
  status: SyncStatus | null;
  onStatus: (status: SyncStatus) => void;
  onReload: () => Promise<void>;
  onToast: (toast: Omit<Toast, "id">) => void;
  onRequireUnlock: () => void;
}) {
  const [path, setPath] = useState(status?.vaultPath ?? "");
  const [conflicts, setConflicts] = useState<ConflictView[]>([]);
  const [passwords, setPasswords] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (status?.vaultPath) setPath(status.vaultPath);
  }, [status?.vaultPath]);

  useEffect(() => {
    let cancelled = false;
    void syncConflicts()
      .then((next) => {
        if (!cancelled) setConflicts(next);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [status?.generation, status?.conflictCount]);

  function leaveIfLocked(next: SyncStatus | null, message?: string) {
    if (message === "vault file needs a different password" || message === "vault is locked") {
      onRequireUnlock();
      return true;
    }
    if (next?.locked || next?.state === "waiting_icloud") {
      if (next.state === "waiting_icloud") {
        onToast({ kind: "info", message: mapError(next.message) });
      }
      onRequireUnlock();
      return true;
    }
    return false;
  }

  async function browse(mode: VaultLocationMode) {
    try {
      const picked = await pickVaultFile(mode);
      if (picked) setPath(picked);
    } catch (err) {
      onToast({ kind: "err", message: mapError(err instanceof Error ? err.message : String(err)) });
    }
  }

  async function apply(mode: VaultLocationMode) {
    const chosen = path.trim();
    if (!chosen) {
      onToast({ kind: "err", message: "금고 파일 경로를 입력하세요." });
      return;
    }
    setBusy(true);
    try {
      const next = await setVaultLocation(chosen, mode);
      onStatus(next);
      if (leaveIfLocked(next)) return;
      await onReload();
      onToast({
        kind: "ok",
        message: mode === "move" ? "금고 파일을 옮겼습니다." : "금고 파일을 열었습니다.",
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      leaveIfLocked(null, message);
      onToast({ kind: "err", message: mapError(message) });
    } finally {
      setBusy(false);
    }
  }

  async function resolve(itemId: string, conflictId: string, action: ConflictAction) {
    setBusy(true);
    try {
      await resolveSyncConflict(itemId, conflictId, action);
      await onReload();
      const next = await syncStatus();
      onStatus(next);
      setConflicts(await syncConflicts());
      onToast({
        kind: "ok",
        message: action === "keep" ? "현재 항목을 유지했습니다." : "충돌 버전을 복원했습니다.",
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      leaveIfLocked(null, message);
      onToast({ kind: "err", message: mapError(message) });
    } finally {
      setBusy(false);
    }
  }

  async function mergeFile(event: FormEvent, file: string) {
    event.preventDefault();
    const password = passwords[file] ?? "";
    if (!password) {
      onToast({ kind: "err", message: "그 파일의 마스터 비밀번호를 입력하세요." });
      return;
    }
    setBusy(true);
    try {
      await mergeSyncPassword(file, password);
      setPasswords((current) => ({ ...current, [file]: "" }));
      await onReload();
      const next = await syncStatus();
      onStatus(next);
      setConflicts(await syncConflicts());
      onToast({ kind: "ok", message: "파일을 금고에 합쳤습니다." });
    } catch (err) {
      setPasswords((current) => ({ ...current, [file]: "" }));
      const message = err instanceof Error ? err.message : String(err);
      leaveIfLocked(null, message);
      onToast({ kind: "err", message: mapError(message) });
    } finally {
      setBusy(false);
    }
  }

  const pending = status?.pendingFiles ?? [];

  return (
    <div className="card">
      <h3>기기 간 동기화</h3>
      <p className="lede">
        암호화된 금고 파일만 선택한 경로에 둡니다. iCloud Drive 예:{" "}
        <span className="path-note">~/Library/Mobile Documents/com~apple~CloudDocs/Keyhaven/vault.khv</span>
        . 잠금 상태, 키, 토큰, 세션, 패스키와 Touch ID 자료는 이 기기에 남습니다.
      </p>
      <label className="field">
        <span>금고 파일 경로</span>
        <input
          value={path}
          onChange={(event) => setPath(event.target.value)}
          placeholder="절대 경로 또는 ~/로 시작하는 경로"
          autoComplete="off"
          spellCheck={false}
        />
      </label>
      {!isTauri() ? (
        <p className="lede">웹에서는 서버가 읽을 수 있는 절대 경로를 직접 입력합니다.</p>
      ) : null}
      <div className="actions">
        {isTauri() ? (
          <button className="btn btn-ghost" type="button" disabled={busy} onClick={() => void browse("move")}>
            위치 찾기
          </button>
        ) : null}
        <button className="btn btn-primary" type="button" disabled={busy} onClick={() => void apply("move")}>
          이 경로로 옮기기
        </button>
        {isTauri() ? (
          <button className="btn btn-ghost" type="button" disabled={busy} onClick={() => void browse("open")}>
            파일 찾기
          </button>
        ) : null}
        <button className="btn" type="button" disabled={busy} onClick={() => void apply("open")}>
          이 경로 열기
        </button>
      </div>
      {status && status.state !== "ok" ? <p className="error">{mapError(status.message)}</p> : null}

      {pending.length > 0 ? (
        <div>
          <h3>다른 비밀번호</h3>
          <p className="lede">이 파일은 현재 마스터 비밀번호로 열리지 않아 자동으로 합치지 않았습니다.</p>
          {pending.map((file) => (
            <form key={file} onSubmit={(event) => void mergeFile(event, file)}>
              <p className="path-note">{file}</p>
              <label className="field">
                <span>그 파일의 마스터 비밀번호</span>
                <input
                  type="password"
                  value={passwords[file] ?? ""}
                  onChange={(event) => setPasswords((current) => ({ ...current, [file]: event.target.value }))}
                  autoComplete="off"
                />
              </label>
              <button className="btn" type="submit" disabled={busy}>
                이 비밀번호로 합치기
              </button>
            </form>
          ))}
        </div>
      ) : null}

      {conflicts.length > 0 ? (
        <div>
          <h3>충돌 {conflicts.length}건</h3>
          <p className="lede">
            같은 항목을 서로 다른 기기에서 고치면 더 최근 시각이 남고, 진 쪽은 여기에 보관됩니다. 시각이 같으면 기기
            id가 큰 쪽이 이깁니다.
          </p>
          {conflicts.map((conflict) => (
            <div className="conflict-row" key={`${conflict.itemId}:${conflict.conflictId}`}>
              <p>
                현재: {labelFor(conflict.currentDeleted, conflict.currentTitle, conflict.currentUsername)}
              </p>
              <p>
                보관: {labelFor(conflict.conflictDeleted, conflict.conflictTitle, conflict.conflictUsername)}
                {conflict.conflictUpdatedBy ? ` · ${conflict.conflictUpdatedBy}` : ""}
              </p>
              <div className="actions">
                <button
                  className="btn btn-small"
                  type="button"
                  disabled={busy}
                  onClick={() => void resolve(conflict.itemId, conflict.conflictId, "keep")}
                >
                  현재 항목 유지
                </button>
                <button
                  className="btn btn-small"
                  type="button"
                  disabled={busy}
                  onClick={() => void resolve(conflict.itemId, conflict.conflictId, "restore")}
                >
                  보관 버전으로 되돌리기
                </button>
              </div>
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}
