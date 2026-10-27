import { FormEvent, useEffect, useRef, useState } from "react";
import { biometricStatus, clientPlatform, iosFaceIdStatus, iosFaceIdUnlock, mapError } from "../api";
import { faceIdReasonMessage } from "../faceId";
import type { BiometricStatus, FaceIdStatus, IosDemo } from "../types";
import BuildStamp from "./BuildStamp";
import Logo from "./Logo";

export default function UnlockScreen({
  onUnlock,
  onBiometric,
  onOpened,
  iosUi,
  demo,
}: {
  onUnlock: (password: string) => Promise<void>;
  onBiometric: () => Promise<void>;
  onOpened?: () => Promise<void>;
  iosUi?: boolean;
  demo?: IosDemo | null;
}) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [bio, setBio] = useState<BiometricStatus | null>(null);
  const [face, setFace] = useState<FaceIdStatus | null>(null);
  const [isIos, setIsIos] = useState(!!iosUi);
  const autoTried = useRef(false);

  const demoFaceId =
    demo?.view === "unlock" || demo?.view === "faceid" || demo?.view === "face-id-lock";

  useEffect(() => {
    let cancelled = false;
    void clientPlatform().then((platform) => {
      if (!cancelled) setIsIos(platform === "ios" || !!iosUi);
    });
    return () => {
      cancelled = true;
    };
  }, [iosUi]);

  useEffect(() => {
    let cancelled = false;
    if (isIos) {
      void iosFaceIdStatus()
        .then((next) => {
          if (!cancelled) setFace(next);
        })
        .catch(() => undefined);
    } else {
      void biometricStatus()
        .then((next) => {
          if (!cancelled) setBio(next);
        })
        .catch(() => undefined);
    }
    return () => {
      cancelled = true;
    };
  }, [isIos]);

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

  async function handleFaceId() {
    setError("");
    setBusy(true);
    try {
      await iosFaceIdUnlock();
      if (onOpened) await onOpened();
      else await onBiometric();
    } catch (err) {
      const raw = err instanceof Error ? err.message : String(err);
      setError(faceIdReasonMessage(raw) ?? mapError(raw));
      if (raw === "invalidated" || raw === "notFound" || raw === "itemMissing") {
        void iosFaceIdStatus()
          .then(setFace)
          .catch(() => undefined);
      }
    } finally {
      setBusy(false);
    }
  }

  const showFaceButton = isIos && (face?.canUnlock || demoFaceId);
  const faceHint = faceIdReasonMessage(face?.reason) ?? (face?.disabledToggle ? faceIdReasonMessage("invalidated") : null);

  useEffect(() => {
    if (!isIos || autoTried.current || busy || demoFaceId) return;
    if (!face?.canUnlock) return;
    autoTried.current = true;
    void handleFaceId();
    // Face ID auto-prompt once when the lock screen appears.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isIos, face?.canUnlock, demoFaceId]);

  const bioLabel =
    bio?.platform === "macos" ? "Touch ID로 열기" : bio?.platform === "web" ? "패스키로 열기" : "생체 인증으로 열기";
  const passwordHint = bio?.passwordRequired
    ? bio.reason === "interval"
      ? "설정한 기간이 지나 마스터 비밀번호가 필요합니다."
      : "다시 시작한 뒤에는 마스터 비밀번호가 필요합니다."
    : null;

  return (
    <div className={`auth-wrap${isIos ? " ios-unlock" : ""}`}>
      <form className="auth-card" onSubmit={handleSubmit}>
        <div className="brand-row">
          <Logo />
          <div>
            <h1 className="brand-name">SecureVault</h1>
            <p className="brand-tag">금고가 잠겨 있습니다</p>
          </div>
        </div>
        <p className="lede">마스터 비밀번호를 입력해 금고를 여세요.</p>
        {bio?.touchIdReregister ? (
          <p className="notice">
            Touch ID 키체인 항목을 새 앱 이름으로 옮기지 못했습니다. 마스터 비밀번호로 연 뒤 설정에서 Touch ID를 다시
            등록해 주세요.
          </p>
        ) : null}
        {passwordHint ? <p className="lede">{passwordHint}</p> : null}
        {faceHint ? <p className="notice">{faceHint}</p> : null}
        <label className="field">
          <span>마스터 비밀번호</span>
          <input
            type="password"
            autoFocus={!showFaceButton}
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        <p className="error">{error}</p>
        <button className="btn btn-primary" type="submit" disabled={busy} style={{ width: "100%" }}>
          {busy ? "확인 중…" : "잠금 해제"}
        </button>
        {showFaceButton ? (
          <button
            className="btn ios-faceid-btn"
            type="button"
            disabled={busy}
            style={{ width: "100%" }}
            onClick={() => void handleFaceId()}
          >
            Face ID로 잠금 해제
          </button>
        ) : null}
        {!isIos && bio?.canUnlock ? (
          <button className="btn" type="button" disabled={busy} style={{ width: "100%" }} onClick={() => void handleBiometric()}>
            {bioLabel}
          </button>
        ) : null}
        <BuildStamp />
      </form>
    </div>
  );
}
