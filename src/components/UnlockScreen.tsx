import { FormEvent, useEffect, useState } from "react";
import { biometricStatus } from "../api";
import type { BiometricStatus } from "../types";
import Logo from "./Logo";

export default function UnlockScreen({
  onUnlock,
  onBiometric,
}: {
  onUnlock: (password: string) => Promise<void>;
  onBiometric: () => Promise<void>;
}) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [bio, setBio] = useState<BiometricStatus | null>(null);

  useEffect(() => {
    let cancelled = false;
    void biometricStatus()
      .then((next) => {
        if (!cancelled) setBio(next);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, []);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      await onUnlock(password);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function handleBiometric() {
    setError("");
    setBusy(true);
    try {
      await onBiometric();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  const bioLabel =
    bio?.platform === "macos" ? "Touch ID로 열기" : bio?.platform === "web" ? "패스키로 열기" : "생체 인증으로 열기";
  const passwordHint = bio?.passwordRequired
    ? bio.reason === "interval"
      ? "설정한 기간이 지나 마스터 비밀번호가 필요합니다."
      : "다시 시작한 뒤에는 마스터 비밀번호가 필요합니다."
    : null;

  return (
    <div className="auth-wrap">
      <form className="auth-card" onSubmit={handleSubmit}>
        <div className="brand-row">
          <Logo />
          <div>
            <h1 className="brand-name">Keyhaven</h1>
            <p className="brand-tag">금고가 잠겨 있습니다</p>
          </div>
        </div>
        <p className="lede">마스터 비밀번호를 입력해 금고를 여세요.</p>
        {passwordHint ? <p className="lede">{passwordHint}</p> : null}
        <label className="field">
          <span>마스터 비밀번호</span>
          <input
            type="password"
            autoFocus
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        <p className="error">{error}</p>
        <button className="btn btn-primary" type="submit" disabled={busy} style={{ width: "100%" }}>
          {busy ? "확인 중…" : "잠금 해제"}
        </button>
        {bio?.canUnlock ? (
          <button className="btn" type="button" disabled={busy} style={{ width: "100%" }} onClick={() => void handleBiometric()}>
            {bioLabel}
          </button>
        ) : null}
      </form>
    </div>
  );
}
