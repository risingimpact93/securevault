import { FormEvent, useRef, useState } from "react";
import jsQR from "jsqr";
import { importSecretKey, mapError } from "../api";
import BuildStamp from "./BuildStamp";
import Logo from "./Logo";

async function decodeQrFile(file: File): Promise<string> {
  const bitmap = await createImageBitmap(file);
  const canvas = document.createElement("canvas");
  canvas.width = bitmap.width;
  canvas.height = bitmap.height;
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("QR 이미지를 읽지 못했습니다.");
  ctx.drawImage(bitmap, 0, 0);
  const image = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const result = jsQR(image.data, image.width, image.height);
  if (!result?.data) throw new Error("QR 코드에서 Secret Key를 읽지 못했습니다.");
  return result.data;
}

export default function SecretKeyScreen({
  onReady,
}: {
  onReady: (secretKey: string, stored: boolean) => void;
}) {
  const [value, setValue] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  async function submitKey(secretKey: string) {
    setBusy(true);
    setError("");
    try {
      const status = await importSecretKey(secretKey);
      onReady(secretKey, status.stored);
    } catch (err) {
      setError(mapError(err instanceof Error ? err.message : String(err)));
    } finally {
      setBusy(false);
    }
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!value.trim()) {
      setError("Secret Key를 입력하세요.");
      return;
    }
    await submitKey(value);
  }

  async function handleQr(file: File | null) {
    if (!file) return;
    setError("");
    setBusy(true);
    try {
      const decoded = await decodeQrFile(file);
      setValue(decoded);
      await submitKey(decoded);
    } catch (err) {
      setError(mapError(err instanceof Error ? err.message : String(err)));
      setBusy(false);
    }
  }

  return (
    <div className="auth-wrap">
      <form className="auth-card" onSubmit={handleSubmit}>
        <div className="brand-row">
          <Logo />
          <div>
            <h1 className="brand-name">SecureVault</h1>
            <p className="brand-tag">Secret Key 입력</p>
          </div>
        </div>
        <p className="lede">
          이 금고는 Secret Key로 잠겨 있습니다. 비상 키트에 적힌 키를 입력하거나 QR 이미지를 가져오세요.
        </p>
        <label className="field">
          <span>Secret Key</span>
          <textarea
            autoFocus
            autoComplete="off"
            spellCheck={false}
            rows={3}
            className="secret-key-display"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="SV1-XXXXXX-XXXXXX-…"
          />
        </label>
        <input
          ref={fileRef}
          className="hidden-file"
          type="file"
          accept="image/*"
          onChange={(e) => {
            const file = e.target.files?.[0] ?? null;
            e.target.value = "";
            void handleQr(file);
          }}
        />
        <p className="error">{error}</p>
        <button className="btn btn-primary" type="submit" disabled={busy} style={{ width: "100%" }}>
          {busy ? "확인 중…" : "Secret Key 확인"}
        </button>
        <button
          className="btn"
          type="button"
          disabled={busy}
          style={{ width: "100%" }}
          onClick={() => fileRef.current?.click()}
        >
          QR 이미지 가져오기
        </button>
        <BuildStamp />
      </form>
    </div>
  );
}
