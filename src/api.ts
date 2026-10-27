import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import type {
  AccessLogEntry,
  ApprovalRequest,
  BiometricStatus,
  FaceIdStatus,
  GenerateOpts,
  ImportMode,
  IssuedMcpToken,
  ItemDraft,
  McpSettings,
  ConflictAction,
  ConflictView,
  SettingsPatch,
  SyncStatus,
  AppBuild,
  DiscoveredVault,
  EmergencyKit,
  OpenVaultStatus,
  SecretKeyStatus,
  DeviceManagerStatus,
  VaultItem,
  VaultLocationMode,
  VaultSettings,
} from "./types";

export function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export type ClientPlatform = "web" | "macos" | "ios" | "unsupported";

export function looksLikeIos(): boolean {
  return typeof navigator !== "undefined" && /iPhone|iPad|iPod/.test(navigator.userAgent);
}

let cachedPlatform: ClientPlatform | null = null;

export async function clientPlatform(): Promise<ClientPlatform> {
  if (!isTauri()) return "web";
  if (cachedPlatform) return cachedPlatform;
  try {
    const value = await invoke<ClientPlatform>("client_platform");
    if (value === "web" || value === "macos" || value === "ios" || value === "unsupported") {
      cachedPlatform = value;
      return value;
    }
  } catch {
    /* fall through */
  }
  return looksLikeIos() ? "ios" : "unsupported";
}

/** iOS: resolves when the Swift vault-access plugin answers. */
export async function iosPluginStatus(): Promise<string> {
  return invoke<string>("ios_plugin_status");
}

export async function scanSecretKeyQr(): Promise<string> {
  const scanner = await import("@tauri-apps/plugin-barcode-scanner");
  let permission = await scanner.checkPermissions();
  if (permission !== "granted") {
    permission = await scanner.requestPermissions();
  }
  if (permission !== "granted") {
    throw new Error("카메라 권한이 없습니다. QR 이미지를 가져오세요.");
  }
  const scanned = await scanner.scan({
    formats: [scanner.Format.QRCode],
    cameraDirection: "back",
  });
  if (!scanned.content.trim()) {
    throw new Error("QR 코드에서 Secret Key를 읽지 못했습니다.");
  }
  return scanned.content;
}

let csrfToken: string | null = null;
let pendingImportFile: File | null = null;

export function mapError(message: string): string {
  const table: Record<string, string> = {
    "wrong password": "마스터 비밀번호가 올바르지 않습니다.",
    "vault is locked": "금고가 잠겨 있습니다.",
    "vault already exists": "금고가 이미 있습니다.",
    "vault not found": "금고를 찾을 수 없습니다.",
    "ciphertext or header was tampered with": "금고 파일이 손상되었거나 변조되었습니다.",
    "not a vault": "이 파일은 금고 파일이 아닙니다.",
    corrupt: "금고 파일이 잘렸거나 손상되었습니다.",
    "unsupported version": "이 앱이 지원하지 않는 금고 버전입니다.",
    "invalid item type": "알 수 없는 항목 종류입니다.",
    "item not found": "항목을 찾을 수 없습니다.",
    "mode must be merge or replace": "가져오기 방식이 올바르지 않습니다.",
    "too many attempts": "시도가 너무 많습니다. 잠시 후 다시 시도하세요.",
    "csrf rejected": "요청이 거부되었습니다. 페이지를 새로고침하세요.",
    "invalid auto-lock choice": "자동 잠금 시간이 올바르지 않습니다.",
    "invalid password interval": "비밀번호 확인 주기가 올바르지 않습니다.",
    "master password required": "마스터 비밀번호로 다시 열어야 합니다.",
    "biometrics unavailable": "생체 인증을 사용할 수 없습니다.",
    "biometrics invalidated": "생체 정보가 바뀌어 생체 인증을 쓸 수 없습니다. 마스터 비밀번호로 여세요.",
    "passkey session only": "패스키만으로는 잠긴 금고를 열 수 없습니다. 마스터 비밀번호를 사용하세요.",
    cancelled: "생체 인증이 취소되었습니다.",
    unsupported: "이 환경에서는 Face ID를 사용할 수 없습니다.",
    notFound: "Face ID 정보가 바뀌었거나 없어 Face ID 잠금 해제를 껐습니다. 마스터 비밀번호를 입력하세요.",
    invalidated: "Face ID 정보가 바뀌었거나 없어 Face ID 잠금 해제를 껐습니다. 마스터 비밀번호를 입력하세요.",
    itemMissing: "Face ID 정보가 바뀌었거나 없어 Face ID 잠금 해제를 껐습니다. 마스터 비밀번호를 입력하세요.",
    rebooted: "기기를 다시 시작해 마스터 비밀번호가 필요합니다.",
    expired: "보안을 위해 7일마다 마스터 비밀번호가 필요합니다.",
    firstSetup: "처음 설정할 때는 마스터 비밀번호가 필요합니다.",
    notEnabled: "Face ID 잠금 해제가 꺼져 있습니다.",
    failed: "Face ID에 실패했습니다. 마스터 비밀번호를 입력하세요.",
    "passkeys require http://localhost": "패스키는 http://localhost 주소로 열어야 합니다.",
    "vault file needs a different password": "이 금고 파일의 비밀번호가 현재 비밀번호와 다릅니다.",
    "waiting for iCloud download": "iCloud에서 금고 파일을 내려받는 중입니다. 잠시 후 다시 시도하세요.",
    "path must be absolute": "경로는 절대 경로여야 합니다.",
    "mode must be move or open": "이동 또는 열기만 할 수 있습니다.",
    "secret key required": "Secret Key가 필요합니다.",
    "Secret Key가 이 금고와 맞지 않습니다": "Secret Key가 이 금고와 맞지 않습니다.",
    "Secret Key 형식이 올바르지 않습니다": "Secret Key 형식이 올바르지 않습니다.",
    "Secret Key 접두사가 올바르지 않습니다": "Secret Key 접두사가 올바르지 않습니다.",
    "Secret Key 체크섬이 올바르지 않습니다": "Secret Key 체크섬이 올바르지 않습니다.",
    "secret key store unavailable": "Secret Key를 이 기기에 저장하지 못했습니다. 잠금 해제할 때마다 입력하세요.",
    "관리 기기가 없습니다": "관리 기기가 없습니다.",
    "등록되지 않은 기기입니다": "등록되지 않은 기기입니다.",
    "기기 ID가 없습니다": "기기 ID가 없습니다.",
    "failed to encode QR code": "QR 이미지를 만들지 못했습니다.",
    "failed to encode PNG": "QR 이미지를 만들지 못했습니다.",
  };
  return table[message] ?? message;
}

function rememberCsrf(data: unknown): void {
  if (data && typeof data === "object" && "csrfToken" in data) {
    const value = (data as { csrfToken?: unknown }).csrfToken;
    if (typeof value === "string" && value) {
      csrfToken = value;
    }
  }
}

async function http<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  const mutating = method !== "GET" && method !== "HEAD";
  if (mutating && csrfToken) {
    headers.set("X-CSRF-Token", csrfToken);
  }
  if (init.body && typeof init.body === "string" && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const res = await fetch(path, {
    ...init,
    method,
    headers,
    credentials: "include",
  });
  const headerCsrf = res.headers.get("X-CSRF-Token");
  if (headerCsrf) csrfToken = headerCsrf;
  const contentType = res.headers.get("content-type") ?? "";
  if (!res.ok) {
    let message = res.statusText;
    if (contentType.includes("application/json")) {
      try {
        const data: unknown = await res.json();
        if (data && typeof data === "object" && "error" in data) {
          const error = (data as { error?: unknown }).error;
          if (typeof error === "string" && error) message = error;
        }
      } catch {
        /* keep statusText */
      }
    }
    throw new Error(message);
  }
  if (res.status === 204) {
    return undefined as T;
  }
  if (contentType.includes("application/json")) {
    const data: unknown = await res.json();
    rememberCsrf(data);
    return data as T;
  }
  return undefined as T;
}

export async function getSession(): Promise<{
  unlocked: boolean;
  csrfToken?: string;
  autoLockMinutes?: number;
}> {
  if (isTauri()) {
    return { unlocked: await invoke<boolean>("is_unlocked") };
  }
  const data = await http<{
    unlocked: boolean;
    csrfToken?: string;
    autoLockMinutes?: number;
  }>("/api/session");
  rememberCsrf(data);
  return data;
}

export async function getVaultSettings(): Promise<VaultSettings> {
  if (isTauri()) return invoke<VaultSettings>("get_vault_settings");
  return http<VaultSettings>("/api/settings");
}

export async function updateVaultSettings(patch: SettingsPatch): Promise<VaultSettings> {
  if (isTauri()) return invoke<VaultSettings>("update_vault_settings", { patch });
  return http<VaultSettings>("/api/settings", {
    method: "POST",
    body: JSON.stringify(patch),
  });
}

export async function touchActivity(): Promise<void> {
  if (isTauri()) return;
  await http("/api/activity", { method: "POST" });
}

/** Idle expiry. On the web this keeps an unwrapped vault key so a passkey can resume. */
export async function idleLock(): Promise<void> {
  if (isTauri()) {
    await invoke("lock");
    return;
  }
  try {
    await http("/api/idle-lock", { method: "POST" });
  } catch (err) {
    if (!(err instanceof Error) || err.message !== "vault is locked") throw err;
  }
  csrfToken = null;
}

export async function biometricStatus(): Promise<BiometricStatus> {
  if (isTauri()) return invoke<BiometricStatus>("biometric_status");
  return http<BiometricStatus>("/api/biometrics/status");
}

function bytesToB64url(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = "";
  for (const byte of view) bin += String.fromCharCode(byte);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64urlToBytes(value: string): Uint8Array {
  const pad = value.length % 4 === 0 ? "" : "=".repeat(4 - (value.length % 4));
  const b64 = value.replace(/-/g, "+").replace(/_/g, "/") + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

function copyBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function prepPublicKey(options: Record<string, unknown>, kind: "create"): CredentialCreationOptions;
function prepPublicKey(options: Record<string, unknown>, kind: "get"): CredentialRequestOptions;
function prepPublicKey(options: Record<string, unknown>, kind: "create" | "get"): CredentialCreationOptions | CredentialRequestOptions {
  const root = (options.publicKey ?? options) as Record<string, unknown>;
  if (typeof root.challenge === "string") root.challenge = copyBuffer(b64urlToBytes(root.challenge));
  const user = root.user as { id?: unknown } | undefined;
  if (user && typeof user.id === "string") user.id = copyBuffer(b64urlToBytes(user.id));
  for (const listName of ["excludeCredentials", "allowCredentials"]) {
    const list = root[listName];
    if (!Array.isArray(list)) continue;
    for (const entry of list) {
      if (entry && typeof entry === "object" && typeof (entry as { id?: unknown }).id === "string") {
        (entry as { id: ArrayBuffer }).id = copyBuffer(b64urlToBytes((entry as { id: string }).id));
      }
    }
  }
  const extensions = root.extensions as { prf?: { eval?: { first?: unknown } } } | undefined;
  const first = extensions?.prf?.eval?.first;
  if (typeof first === "string" && extensions?.prf?.eval) {
    extensions.prf.eval.first = copyBuffer(b64urlToBytes(first));
  }
  const wrapped = { publicKey: root };
  return kind === "create"
    ? (wrapped as unknown as CredentialCreationOptions)
    : (wrapped as unknown as CredentialRequestOptions);
}

function credentialToJson(cred: PublicKeyCredential): Record<string, unknown> {
  const response = cred.response;
  const clientDataJSON = bytesToB64url(response.clientDataJSON);
  if (response instanceof AuthenticatorAttestationResponse) {
    return {
      id: cred.id,
      rawId: bytesToB64url(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON,
        attestationObject: bytesToB64url(response.attestationObject),
        transports: typeof response.getTransports === "function" ? response.getTransports() : undefined,
      },
    };
  }
  const assertion = response as AuthenticatorAssertionResponse;
  return {
    id: cred.id,
    rawId: bytesToB64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON,
      authenticatorData: bytesToB64url(assertion.authenticatorData),
      signature: bytesToB64url(assertion.signature),
      userHandle: assertion.userHandle ? bytesToB64url(assertion.userHandle) : undefined,
    },
  };
}

function prfFromCredential(cred: PublicKeyCredential): string | undefined {
  const ext = cred.getClientExtensionResults() as {
    prf?: { results?: { first?: ArrayBuffer } };
  };
  const first = ext.prf?.results?.first;
  return first ? bytesToB64url(first) : undefined;
}

export async function biometricEnable(): Promise<BiometricStatus> {
  if (isTauri()) return invoke<BiometricStatus>("biometric_enable");
  if (!window.PublicKeyCredential) throw new Error("biometrics unavailable");
  const start = await http<{ options: Record<string, unknown> }>("/api/webauthn/register/start", {
    method: "POST",
  });
  const created = (await navigator.credentials.create(
    prepPublicKey(start.options, "create"),
  )) as PublicKeyCredential | null;
  if (!created) throw new Error("cancelled");
  return http<BiometricStatus>("/api/webauthn/register/finish", {
    method: "POST",
    body: JSON.stringify({
      credential: credentialToJson(created),
      prfFirst: prfFromCredential(created),
    }),
  });
}

export async function biometricDisable(): Promise<BiometricStatus> {
  if (isTauri()) return invoke<BiometricStatus>("biometric_disable");
  return http<BiometricStatus>("/api/webauthn/credential", { method: "DELETE" });
}

export async function iosFaceIdStatus(): Promise<FaceIdStatus> {
  if (!isTauri()) {
    return {
      supported: false,
      available: false,
      enrolled: false,
      biometryType: "none",
      enabled: false,
      canUnlock: false,
      itemPresent: false,
      reason: "notEnabled",
    };
  }
  return invoke<FaceIdStatus>("ios_face_id_status");
}

export async function iosFaceIdEnable(password: string): Promise<FaceIdStatus> {
  return invoke<FaceIdStatus>("ios_face_id_enable", { password });
}

export async function iosFaceIdDisable(): Promise<FaceIdStatus> {
  return invoke<FaceIdStatus>("ios_face_id_disable");
}

export async function iosFaceIdUnlock(): Promise<void> {
  await invoke("ios_face_id_unlock");
}

export async function verifyMasterPassword(password: string): Promise<void> {
  await invoke("verify_master_password", { password });
}

export async function biometricUnlock(): Promise<void> {
  if (isTauri()) {
    await invoke("biometric_unlock");
    return;
  }
  if (!window.PublicKeyCredential) throw new Error("biometrics unavailable");
  const start = await http<{ options: Record<string, unknown> }>("/api/webauthn/authenticate/start", {
    method: "POST",
  });
  const assertion = (await navigator.credentials.get(prepPublicKey(start.options, "get"))) as PublicKeyCredential | null;
  if (!assertion) throw new Error("cancelled");
  await http("/api/webauthn/authenticate/finish", {
    method: "POST",
    body: JSON.stringify({
      credential: credentialToJson(assertion),
      prfFirst: prfFromCredential(assertion),
    }),
  });
}

export async function getPendingApprovals(): Promise<ApprovalRequest[]> {
  if (isTauri()) return [];
  const data = await http<{ pending?: ApprovalRequest[] }>("/api/approvals");
  return data.pending ?? [];
}

export async function vaultExists(): Promise<boolean> {
  if (isTauri()) return invoke<boolean>("vault_exists");
  return http<boolean>("/api/vault-exists");
}

export async function discoverVaults(): Promise<DiscoveredVault[]> {
  if (isTauri()) return invoke<DiscoveredVault[]>("discover_vaults");
  return http<DiscoveredVault[]>("/api/vaults/discover");
}

export async function openExistingVault(path: string): Promise<OpenVaultStatus> {
  if (isTauri()) return invoke<OpenVaultStatus>("open_existing_vault", { path });
  return http<OpenVaultStatus>("/api/vaults/open", {
    method: "POST",
    body: JSON.stringify({ path }),
  });
}

export async function createVault(password: string): Promise<void> {
  if (isTauri()) {
    await invoke("create_vault", { password });
    return;
  }
  await http("/api/create-vault", {
    method: "POST",
    body: JSON.stringify({ password }),
  });
}

export async function unlock(password: string, secretKey?: string): Promise<void> {
  if (isTauri()) {
    await invoke("unlock", { password, secretKey: secretKey || null });
    return;
  }
  await http("/api/unlock", {
    method: "POST",
    body: JSON.stringify({ password, secretKey: secretKey || undefined }),
  });
}

export async function secretKeyStatus(): Promise<SecretKeyStatus> {
  if (isTauri()) return invoke<SecretKeyStatus>("secret_key_status");
  return http<SecretKeyStatus>("/api/secret-key/status");
}

export async function importSecretKey(secretKey: string): Promise<SecretKeyStatus> {
  if (isTauri()) return invoke<SecretKeyStatus>("import_secret_key", { secretKey });
  return http<SecretKeyStatus>("/api/secret-key/import", {
    method: "POST",
    body: JSON.stringify({ secretKey }),
  });
}

export async function enableSecretKey(password: string): Promise<EmergencyKit> {
  if (isTauri()) return invoke<EmergencyKit>("enable_secret_key", { password });
  return http<EmergencyKit>("/api/secret-key/enable", {
    method: "POST",
    body: JSON.stringify({ password }),
  });
}

export async function disableSecretKey(password: string, secretKey: string): Promise<void> {
  if (isTauri()) {
    await invoke("disable_secret_key", { password, secretKey });
    return;
  }
  await http("/api/secret-key/disable", {
    method: "POST",
    body: JSON.stringify({ password, secretKey }),
  });
}

export async function revealSecretKey(password: string): Promise<EmergencyKit> {
  if (isTauri()) return invoke<EmergencyKit>("reveal_secret_key", { password });
  return http<EmergencyKit>("/api/secret-key/reveal", {
    method: "POST",
    body: JSON.stringify({ password }),
  });
}

export async function rotateSecretKey(password: string, secretKey: string): Promise<EmergencyKit> {
  if (isTauri()) return invoke<EmergencyKit>("rotate_secret_key", { password, secretKey });
  return http<EmergencyKit>("/api/secret-key/rotate", {
    method: "POST",
    body: JSON.stringify({ password, secretKey }),
  });
}

export async function deviceManagerStatus(): Promise<DeviceManagerStatus> {
  if (isTauri()) return invoke<DeviceManagerStatus>("device_manager_status");
  return http<DeviceManagerStatus>("/api/device");
}

export async function designateManager(password: string, secretKey: string): Promise<DeviceManagerStatus> {
  if (isTauri()) return invoke<DeviceManagerStatus>("designate_manager", { password, secretKey });
  return http<DeviceManagerStatus>("/api/secret-key/designate", {
    method: "POST",
    body: JSON.stringify({ password, secretKey }),
  });
}

export async function takeoverManager(password: string, secretKey: string): Promise<DeviceManagerStatus> {
  if (isTauri()) return invoke<DeviceManagerStatus>("takeover_manager", { password, secretKey });
  return http<DeviceManagerStatus>("/api/secret-key/takeover", {
    method: "POST",
    body: JSON.stringify({ password, secretKey }),
  });
}

export async function handoverManager(deviceId: string): Promise<DeviceManagerStatus> {
  if (isTauri()) return invoke<DeviceManagerStatus>("handover_manager", { deviceId });
  return http<DeviceManagerStatus>("/api/secret-key/handover", {
    method: "POST",
    body: JSON.stringify({ deviceId }),
  });
}

export async function lock(): Promise<void> {
  if (isTauri()) {
    await invoke("lock");
    return;
  }
  await http("/api/lock", { method: "POST" });
  csrfToken = null;
}

export async function isUnlocked(): Promise<boolean> {
  if (isTauri()) return invoke<boolean>("is_unlocked");
  return http<boolean>("/api/is-unlocked");
}

export async function listItems(): Promise<VaultItem[]> {
  if (isTauri()) return invoke<VaultItem[]>("list_items");
  return http<VaultItem[]>("/api/items");
}

export async function addItem(item: ItemDraft): Promise<VaultItem> {
  if (isTauri()) return invoke<VaultItem>("add_item", { item });
  return http<VaultItem>("/api/items", {
    method: "POST",
    body: JSON.stringify(item),
  });
}

export async function updateItem(item: VaultItem): Promise<VaultItem> {
  if (isTauri()) return invoke<VaultItem>("update_item", { item });
  return http<VaultItem>("/api/items", {
    method: "PUT",
    body: JSON.stringify(item),
  });
}

export async function deleteItem(id: string): Promise<void> {
  if (isTauri()) {
    await invoke("delete_item", { id });
    return;
  }
  await http(`/api/items/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export async function moveItem(id: string, beforeId: string | null): Promise<VaultItem> {
  if (isTauri()) return invoke<VaultItem>("move_item", { id, beforeId });
  return http<VaultItem>(`/api/items/${encodeURIComponent(id)}/move`, {
    method: "POST",
    body: JSON.stringify({ beforeId }),
  });
}

export async function appBuild(): Promise<AppBuild> {
  if (isTauri()) return invoke<AppBuild>("app_build");
  return http<AppBuild>("/api/about");
}

export async function changeMasterPassword(
  currentPassword: string,
  newPassword: string,
): Promise<void> {
  if (isTauri()) {
    await invoke("change_master_password", { currentPassword, newPassword });
    return;
  }
  await http("/api/change-master-password", {
    method: "POST",
    body: JSON.stringify({ currentPassword, newPassword }),
  });
}

export async function generatePassword(opts: GenerateOpts): Promise<string> {
  if (isTauri()) {
    return invoke<string>("generate_password", {
      length: opts.length,
      upper: opts.upper,
      lower: opts.lower,
      digits: opts.digits,
      symbols: opts.symbols,
    });
  }
  return http<string>("/api/generate-password", {
    method: "POST",
    body: JSON.stringify(opts),
  });
}

export async function exportVault(path: string, exportPassword: string): Promise<void> {
  if (isTauri()) {
    await invoke("export_vault", { path, exportPassword });
    return;
  }
  const res = await fetch("/api/export-vault", {
    method: "POST",
    credentials: "include",
    headers: {
      Accept: "application/octet-stream",
      "Content-Type": "application/json",
      ...(csrfToken ? { "X-CSRF-Token": csrfToken } : {}),
    },
    body: JSON.stringify({ exportPassword }),
  });
  if (!res.ok) {
    let message = res.statusText;
    try {
      const data: unknown = await res.json();
      if (data && typeof data === "object" && "error" in data) {
        const error = (data as { error?: unknown }).error;
        if (typeof error === "string" && error) message = error;
      }
    } catch {
      /* keep statusText */
    }
    throw new Error(message);
  }
  const blob = await res.blob();
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = path.split(/[/\\]/).pop() || "vault.khv";
  a.click();
  URL.revokeObjectURL(a.href);
}

export async function importVault(
  path: string,
  exportPassword: string,
  mode: ImportMode,
): Promise<void> {
  if (isTauri()) {
    await invoke("import_vault", { path, exportPassword, mode });
    return;
  }
  if (!pendingImportFile) {
    throw new Error("가져올 파일을 선택하세요.");
  }
  const buffer = new Uint8Array(await pendingImportFile.arrayBuffer());
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < buffer.length; i += chunk) {
    binary += String.fromCharCode(...buffer.subarray(i, i + chunk));
  }
  const fileBase64 = btoa(binary);
  void path;
  await http("/api/import-vault", {
    method: "POST",
    body: JSON.stringify({ exportPassword, mode, fileBase64 }),
  });
  pendingImportFile = null;
}

async function webCopy(text: string, clearAfterSecs: number): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    return;
  }
  if (clearAfterSecs > 0) {
    window.setTimeout(() => {
      void navigator.clipboard.readText().then((current) => {
        if (current === text) {
          void navigator.clipboard.writeText("");
        }
      });
    }, clearAfterSecs * 1000);
  }
}

export async function copyToClipboard(text: string, clearAfterSecs: number): Promise<void> {
  if (isTauri()) {
    await invoke("copy_to_clipboard", { text, clearAfterSecs });
    return;
  }
  await webCopy(text, clearAfterSecs);
}

function downloadBlob(bytes: Uint8Array, filename: string, mime: string): void {
  const blob = new Blob([bytes], { type: mime });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

async function httpBytes(path: string, init: RequestInit = {}): Promise<Uint8Array> {
  const method = (init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);
  const mutating = method !== "GET" && method !== "HEAD";
  if (mutating && csrfToken) {
    headers.set("X-CSRF-Token", csrfToken);
  }
  if (init.body && typeof init.body === "string" && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const res = await fetch(path, {
    ...init,
    method,
    headers,
    credentials: "include",
  });
  const headerCsrf = res.headers.get("X-CSRF-Token");
  if (headerCsrf) csrfToken = headerCsrf;
  if (!res.ok) {
    let message = res.statusText;
    const contentType = res.headers.get("content-type") ?? "";
    if (contentType.includes("application/json")) {
      try {
        const data: unknown = await res.json();
        if (data && typeof data === "object" && "error" in data) {
          const error = (data as { error?: unknown }).error;
          if (typeof error === "string" && error) message = error;
        }
      } catch {
        /* keep statusText */
      }
    }
    throw new Error(message);
  }
  return new Uint8Array(await res.arrayBuffer());
}

/** Native save dialog. `null` means the user cancelled. */
export async function saveEmergencyKitPdf(kit: EmergencyKit): Promise<string | null> {
  if (isTauri()) {
    return invoke<string | null>("save_emergency_kit_pdf", {
      secretKey: kit.secretKey,
      vaultName: kit.vaultName,
      date: kit.date,
    });
  }
  const bytes = await httpBytes("/api/secret-key/emergency-kit.pdf", {
    method: "POST",
    body: JSON.stringify({
      secretKey: kit.secretKey,
      vaultName: kit.vaultName,
      date: kit.date,
    }),
  });
  downloadBlob(bytes, "SecureVault Emergency Kit.pdf", "application/pdf");
  return "SecureVault Emergency Kit.pdf";
}

/** Save a PDF under app data (or the temp dir) and open it in Preview. */
export async function printEmergencyKit(kit: EmergencyKit): Promise<void> {
  if (isTauri()) {
    await invoke("print_emergency_kit", {
      secretKey: kit.secretKey,
      vaultName: kit.vaultName,
      date: kit.date,
    });
    return;
  }
  const bytes = await httpBytes("/api/secret-key/emergency-kit.pdf", {
    method: "POST",
    body: JSON.stringify({
      secretKey: kit.secretKey,
      vaultName: kit.vaultName,
      date: kit.date,
    }),
  });
  const blob = new Blob([bytes], { type: "application/pdf" });
  const url = URL.createObjectURL(blob);
  const opened = window.open(url, "_blank");
  if (!opened) {
    URL.revokeObjectURL(url);
    throw new Error("인쇄 미리보기를 열지 못했습니다.");
  }
}

/** Native save dialog. `null` means the user cancelled. */
export async function saveSecretKeyQr(secretKey: string): Promise<string | null> {
  if (isTauri()) {
    return invoke<string | null>("save_secret_key_qr", { secretKey });
  }
  const bytes = await httpBytes("/api/secret-key/qr.png", {
    method: "POST",
    body: JSON.stringify({ secretKey }),
  });
  downloadBlob(bytes, "SecureVault Secret Key QR.png", "image/png");
  return "SecureVault Secret Key QR.png";
}

export async function revealSavedFile(path: string): Promise<void> {
  if (isTauri()) {
    await invoke("reveal_saved_file", { path });
    return;
  }
  throw new Error("이 환경에서는 파일 위치를 열 수 없습니다.");
}

export async function openSavedFilePreview(path: string): Promise<void> {
  if (isTauri()) {
    await invoke("open_saved_file_preview", { path });
    return;
  }
  throw new Error("이 환경에서는 Preview를 열 수 없습니다.");
}

export async function syncStatus(): Promise<SyncStatus> {
  if (isTauri()) return invoke<SyncStatus>("sync_status");
  return http<SyncStatus>("/api/sync/status");
}

export async function syncConflicts(): Promise<ConflictView[]> {
  if (isTauri()) return invoke<ConflictView[]>("sync_conflicts");
  return http<ConflictView[]>("/api/sync/conflicts");
}

export async function resolveSyncConflict(
  itemId: string,
  conflictId: string,
  action: ConflictAction,
): Promise<void> {
  if (isTauri()) {
    await invoke("resolve_sync_conflict", { itemId, conflictId, action });
    return;
  }
  await http("/api/sync/conflicts/resolve", {
    method: "POST",
    body: JSON.stringify({ itemId, conflictId, action }),
  });
}

export async function setVaultLocation(path: string, mode: VaultLocationMode): Promise<SyncStatus> {
  if (isTauri()) return invoke<SyncStatus>("set_vault_location", { path, mode });
  return http<SyncStatus>("/api/sync/location", {
    method: "POST",
    body: JSON.stringify({ path, mode }),
  });
}

export async function mergeSyncPassword(path: string, password: string): Promise<void> {
  if (isTauri()) {
    await invoke("merge_sync_password", { path, password });
    return;
  }
  await http("/api/sync/merge-password", {
    method: "POST",
    body: JSON.stringify({ path, password }),
  });
}

export async function pickVaultFile(mode: VaultLocationMode): Promise<string | null> {
  if (!isTauri()) return null;
  if (mode !== "move" && (await clientPlatform()) === "ios") {
    // No fallback to the dialog plugin: on iOS it is not the vault picker and
    // a silent fallback hid real failures. Errors go to the screen.
    try {
      return await invoke<string | null>("pick_ios_vault");
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new Error(message || "문서 선택기를 열지 못했습니다.");
    }
  }
  if (mode === "move") {
    const selected = await save({
      title: "금고 파일 위치",
      defaultPath: "vault.khv",
      filters: [{ name: "SecureVault", extensions: ["khv"] }],
    });
    return selected;
  }
  const selected = await open({
    title: "기존 금고 열기",
    multiple: false,
    filters: [
      { name: "SecureVault", extensions: ["khv"] },
      { name: "iCloud placeholder", extensions: ["icloud"] },
    ],
  });
  const picked = Array.isArray(selected) ? (selected[0] ?? null) : selected;
  if (!picked) return null;
  if ((await clientPlatform()) === "ios") {
    return invoke<string>("adopt_ios_vault_path", { path: picked });
  }
  return picked;
}

export async function pickSavePath(): Promise<string | null> {
  if (!isTauri()) return "vault.khv";
  const selected = await save({
    title: "금고 내보내기",
    defaultPath: "vault.khv",
    filters: [{ name: "SecureVault", extensions: ["khv"] }],
  });
  return selected;
}

export async function pickOpenPath(): Promise<string | null> {
  if (isTauri()) {
    const selected = await open({
      title: "금고 가져오기",
      multiple: false,
      filters: [{ name: "SecureVault", extensions: ["khv"] }],
    });
    if (Array.isArray(selected)) return selected[0] ?? null;
    return selected;
  }
  return new Promise((resolve) => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".khv,application/octet-stream";
    input.onchange = () => {
      pendingImportFile = input.files?.[0] ?? null;
      resolve(pendingImportFile ? pendingImportFile.name : null);
    };
    input.oncancel = () => resolve(null);
    input.click();
  });
}

export async function getMcpSettings(): Promise<McpSettings> {
  if (isTauri()) return invoke<McpSettings>("mcp_get_settings");
  return http<McpSettings>("/api/mcp/settings");
}

export async function setMcpSettings(enabled: boolean, port: number): Promise<void> {
  if (isTauri()) {
    await invoke("mcp_set_settings", { enabled, port });
    return;
  }
  if (port < 1 || port > 65535) {
    throw new Error("포트는 1에서 65535 사이여야 합니다.");
  }
  await http("/api/mcp/settings", {
    method: "POST",
    body: JSON.stringify({ enabled, port }),
  });
}

export async function issueMcpToken(name: string): Promise<IssuedMcpToken> {
  if (isTauri()) return invoke<IssuedMcpToken>("mcp_issue_token", { name });
  return http<IssuedMcpToken>("/api/mcp/tokens", {
    method: "POST",
    body: JSON.stringify({ name }),
  });
}

export async function revokeMcpToken(id: string): Promise<void> {
  if (isTauri()) {
    await invoke("mcp_revoke_token", { id });
    return;
  }
  await http(`/api/mcp/tokens/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export async function getMcpAccessLog(): Promise<AccessLogEntry[]> {
  if (isTauri()) return invoke<AccessLogEntry[]>("mcp_access_log");
  return http<AccessLogEntry[]>("/api/mcp/access-log");
}

export async function respondMcpApproval(requestId: string, approved: boolean): Promise<void> {
  if (isTauri()) {
    if (requestId === "demo") return;
    await invoke("respond_mcp_approval", { requestId, approved });
    return;
  }
  if (requestId === "demo") return;
  await http(`/api/approvals/${encodeURIComponent(requestId)}`, {
    method: "POST",
    body: JSON.stringify({ approved }),
  });
}

/** iOS: open a login item's address in Safari via the vault-access plugin. */
export async function openExternalUrl(url: string): Promise<void> {
  if (isTauri()) {
    await invoke("open_external_url", { url });
    return;
  }
  const full = /^https?:\/\//i.test(url.trim()) ? url.trim() : `https://${url.trim()}`;
  window.open(full, "_blank", "noopener,noreferrer");
}

export interface DemoView {
  view?: string | null;
  theme?: string | null;
}

/** CI screenshots: the dummy-vault launch may ask for a specific iOS screen. */
export async function demoView(): Promise<DemoView | null> {
  if (!isTauri()) return null;
  try {
    return (await invoke<DemoView | null>("demo_view")) ?? null;
  } catch {
    return null;
  }
}

/** Site icon for an entry URL as a data URL, fetched by the native side from
 *  that site's own HTTPS origin (cached 7 days in the app data dir). The web
 *  build never fetches icons. */
export async function siteIcon(url: string, force = false): Promise<string | null> {
  if (!isTauri()) return null;
  return invoke<string | null>("site_icon", { url, force });
}

export async function clearSiteIcons(): Promise<void> {
  if (!isTauri()) return;
  await invoke("clear_site_icons");
}

export type AutofillStatus = {
  supported: boolean;
  enabled: boolean;
  listening: boolean;
  hostInstalled: boolean;
  extensionId: string;
  manifestPath: string | null;
};

/** Browser extension bridge (desktop app only; the web build has none). */
export async function autofillGetStatus(): Promise<AutofillStatus | null> {
  if (!isTauri()) return null;
  return invoke<AutofillStatus>("autofill_get_status");
}

export async function autofillSetEnabled(enabled: boolean): Promise<AutofillStatus> {
  return invoke<AutofillStatus>("autofill_set_enabled", { enabled });
}

export async function autofillInstallHost(): Promise<AutofillStatus> {
  return invoke<AutofillStatus>("autofill_install_host");
}
