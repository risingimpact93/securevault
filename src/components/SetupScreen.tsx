import { FormEvent, useMemo, useState } from "react";
import Logo from "./Logo";

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

export default function SetupScreen({
  onCreate,
}: {
  onCreate: (password: string) => Promise<void>;
}) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const strength = useMemo(() => scorePassword(password), [password]);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    if (password.length < 8) {
      setError("마스터 비밀번호는 8자 이상이어야 합니다.");
      return;
    }
    if (password !== confirm) {
      setError("비밀번호가 일치하지 않습니다.");
      return;
    }
    setBusy(true);
    try {
      await onCreate(password);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  const width = `${(strength.score / 5) * 100}%`;
  const color =
    strength.score <= 1 ? "var(--danger)" : strength.score <= 3 ? "var(--gold)" : "var(--ok)";

  return (
    <div className="auth-wrap">
      <form className="auth-card" onSubmit={handleSubmit}>
        <div className="brand-row">
          <Logo />
          <div>
            <h1 className="brand-name">Keyhaven</h1>
            <p className="brand-tag">열쇠가 머무는 안식처</p>
          </div>
        </div>
        <p className="lede">
          첫 금고를 만듭니다. 마스터 비밀번호는 서버에 보내지지 않으며, 잊으면 항목을 복구할 수
          없습니다.
        </p>
        <label className="field">
          <span>마스터 비밀번호</span>
          <input
            type="password"
            autoFocus
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
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
          />
        </label>
        <p className="error">{error}</p>
        <button className="btn btn-primary" type="submit" disabled={busy} style={{ width: "100%" }}>
          {busy ? "금고 생성 중…" : "금고 만들기"}
        </button>
      </form>
    </div>
  );
}
