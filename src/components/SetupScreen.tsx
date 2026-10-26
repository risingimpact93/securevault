import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import {
  clientPlatform,
  discoverVaults,
  iosPluginStatus,
  isTauri,
  mapError,
  openExistingVault,
  pickVaultFile,
} from "../api";
import type { DiscoveredVault } from "../types";
import BuildStamp from "./BuildStamp";
import Logo from "./Logo";

const ICLOUD_POLL_MS = 1500;
const ICLOUD_TIMEOUT_MS = 90_000;

function scorePassword(pw: string): { score: number; label: string } {
  let score = 0;
  if (pw.length >= 8) score += 1;
  if (pw.length >= 12) score += 1;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score += 1;
  if (/\d/.test(pw)) score += 1;
  if (/[^A-Za-z0-9]/.test(pw)) score += 1;
  const labels = ["매우 약함", "약함", "보통", "강함", "매우 강함", "매우 강함"];
  return { score, label: pw ? labels[score] : "비밀번호를 입력하세요" };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    window.setTimeout(resolve, ms);
  });
}

export default function SetupScreen({
  onCreate,
  onOpened,
}: {
  onCreate: (password: string) => Promise<void>;
  onOpened: () => void;
}) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [creating, setCreating] = useState(false);
  const [waiting, setWaiting] = useState(false);
  const [existingPath, setExistingPath] = useState("");
  const [discovered, setDiscovered] = useState<DiscoveredVault[]>([]);
  const [confirmCreate, setConfirmCreate] = useState(false);
  const strength = useMemo(() => scorePassword(password), [password]);
  const cancelRef = useRef(false);
  const discoverRef = useRef<Promise<DiscoveredVault[]>>(Promise.resolve([]));
  const desktop = isTauri();

  useEffect(() => {
    // iOS: check that the Swift document-picker plugin is wired; show failures.
    let cancelled = false;
    if (!isTauri()) return;
    void clientPlatform().then(async (platform) => {
      if (platform !== "ios") return;
      try {
        await iosPluginStatus();
      } catch (err) {
        if (!cancelled) {
          setError(`파일 접근 플러그인 오류: ${err instanceof Error ? err.message : String(err)}`);
        }
      }
    });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    return () => {
      cancelRef.current = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    const pending = discoverVaults().catch(() => [] as DiscoveredVault[]);
    discoverRef.current = pending;
    void pending.then((list) => {
      if (!cancelled) setDiscovered(list);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  async function beginOpen(startPath: string) {
    const chosen = startPath.trim();
    if (!chosen) {
      setError("금고 파일 경로를 입력하세요.");
      return;
    }
    setError("");
    setBusy(true);
    setWaiting(false);
    const started = Date.now();
    let current = chosen;
    try {
      for (;;) {
        if (cancelRef.current) return;
        const status = await openExistingVault(current);
        if (cancelRef.current) return;
        if (status.path) current = status.path;
        if (status.state === "ready") {
          onOpened();
          return;
        }
        if (status.state !== "waiting_icloud") {
          setError(mapError(status.message || "금고를 열 수 없습니다."));
          return;
        }
        if (Date.now() - started >= ICLOUD_TIMEOUT_MS) {
          setError(
            "iCloud에서 금고 파일을 시간 안에 받지 못했습니다. 연결을 확인한 뒤 다시 시도하세요.",
          );
          return;
        }
        setWaiting(true);
        await sleep(ICLOUD_POLL_MS);
      }
    } catch (err) {
      if (!cancelRef.current) {
        setError(mapError(err instanceof Error ? err.message : String(err)));
      }
    } finally {
      if (!cancelRef.current) {
        setWaiting(false);
        setBusy(false);
      }
    }
  }

  async function browse() {
    setError("");
    try {
      const picked = await pickVaultFile("open");
      if (picked) await beginOpen(picked);
    } catch (err) {
      setError(mapError(err instanceof Error ? err.message : String(err)));
    }
  }

  function validateNewPassword(): boolean {
    if (password.length < 8) {
      setError("마스터 비밀번호는 8자 이상이어야 합니다.");
      return false;
    }
    if (password !== confirm) {
      setError("비밀번호가 일치하지 않습니다.");
      return false;
    }
    return true;
  }

  async function createNow() {
    setConfirmCreate(false);
    setBusy(true);
    setCreating(true);
    try {
      await onCreate(password);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setCreating(false);
      setBusy(false);
    }
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    if (!validateNewPassword()) return;
    const list = await discoverRef.current;
    setDiscovered(list);
    if (list.length > 0) {
      setConfirmCreate(true);
      return;
    }
    await createNow();
  }

  const width = `${(strength.score / 5) * 100}%`;
  const color =
    strength.score <= 1 ? "var(--danger)" : strength.score <= 3 ? "var(--gold)" : "var(--ok)";

  return (
    <div className="auth-wrap">
      <div className="auth-card">
        <div className="brand-row">
          <Logo />
          <div>
            <h1 className="brand-name">SecureVault</h1>
            <p className="brand-tag">열쇠가 머무는 안식처</p>
          </div>
        </div>
        <p className="lede">
          첫 금고를 만들거나 기존 금고 파일을 엽니다. 마스터 비밀번호는 서버에 보내지지 않으며,
          잊으면 항목을 복구할 수 없습니다.
        </p>
        {discovered.length > 0 ? (
          <div className="discover-list">
            <p className="lede">이 기기에서 찾은 금고</p>
            {discovered.map((vault) => (
              <button
                key={vault.path}
                className="discover-item"
                type="button"
                disabled={busy}
                onClick={() => void beginOpen(vault.path)}
              >
                <strong>{vault.name}</strong>
                <span className="path-note">{vault.path}</span>
                {vault.placeholder ? <span>iCloud에만 있음</span> : null}
              </button>
            ))}
          </div>
        ) : null}
        {desktop ? (
          <button
            className="btn"
            type="button"
            disabled={busy}
            style={{ width: "100%" }}
            onClick={() => void browse()}
          >
            기존 금고 열기
          </button>
        ) : (
          <>
            <label className="field">
              <span>기존 금고 경로</span>
              <input
                value={existingPath}
                onChange={(event) => setExistingPath(event.target.value)}
                placeholder="절대 경로 또는 ~/로 시작하는 경로"
                autoComplete="off"
                spellCheck={false}
                disabled={busy}
              />
            </label>
            <p className="lede">웹에서는 이 서버가 읽을 수 있는 경로를 입력합니다.</p>
            <button
              className="btn"
              type="button"
              disabled={busy}
              style={{ width: "100%" }}
              onClick={() => void beginOpen(existingPath)}
            >
              기존 금고 열기
            </button>
          </>
        )}
        {waiting ? <p className="lede">iCloud에서 금고 파일을 내려받는 중입니다…</p> : null}
        <div className="or-divider">또는 새 금고</div>
        <form onSubmit={handleSubmit}>
          <label className="field">
            <span>마스터 비밀번호</span>
            <input
              type="password"
              autoFocus
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={busy}
            />
          </label>
          <div className="strength">
            <div className="strength-bar">
              <i style={{ width, background: color }} />
            </div>
            <span>{strength.label}</span>
          </div>
          <label className="field">
            <span>비밀번호 확인</span>
            <input
              type="password"
              autoComplete="new-password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              disabled={busy}
            />
          </label>
          <p className="error">{error}</p>
          <button className="btn btn-primary" type="submit" disabled={busy} style={{ width: "100%" }}>
            {creating ? "금고 생성 중…" : "금고 만들기"}
          </button>
        </form>
        <BuildStamp />
      </div>
      {confirmCreate ? (
        <div className="modal-backdrop" role="presentation">
          <div className="modal" role="dialog" aria-modal="true" aria-labelledby="create-vault-title">
            <h2 id="create-vault-title">별도 금고를 만들까요?</h2>
            <p className="lede">
              이미 금고 파일을 찾았습니다. 새로 만들면 그 금고와 다른 비밀번호와 salt를 쓰는 별도의
              금고가 됩니다. 기존 항목은 옮겨지지 않습니다.
            </p>
            <div className="actions">
              <button className="btn btn-ghost" type="button" onClick={() => setConfirmCreate(false)}>
                취소
              </button>
              <button className="btn btn-primary" type="button" onClick={() => void createNow()}>
                새 금고 만들기
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
