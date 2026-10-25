export type ItemType = "login" | "note" | "card";
export type FilterId = "all" | "login" | "note" | "card" | "favorites";
export type ImportMode = "merge" | "replace";

export interface VaultItem {
  id: string;
  itemType: ItemType;
  title: string;
  favorite: boolean;
  createdAt: string;
  updatedAt: string;
  username?: string;
  password?: string;
  url?: string;
  notes?: string;
  cardholder?: string;
  number?: string;
  expiry?: string;
  cvv?: string;
  tags?: string[];
  order?: string;
  orderUpdatedAt?: string;
  orderUpdatedBy?: string;
  orderVersions?: Record<string, number>;
}

export interface AppBuild {
  version: string;
  commit: string;
}

export interface McpTokenInfo {
  id: string;
  name: string;
  createdAt: string;
  lastUsedAt?: string | null;
}

export interface McpSettings {
  enabled: boolean;
  port: number;
  tokens: McpTokenInfo[];
}

export interface IssuedMcpToken {
  token: string;
  info: McpTokenInfo;
}

export interface AccessLogEntry {
  timestamp: string;
  tokenName: string;
  tool: string;
  itemId?: string | null;
  allowed: boolean;
  reason: string;
}

export interface ApprovalRequest {
  requestId: string;
  tokenName: string;
  itemTitle: string;
  field: string;
  timeoutSecs: number;
}

export type ItemDraft = Omit<VaultItem, "id" | "createdAt" | "updatedAt">;

export interface GenerateOpts {
  length: number;
  upper: boolean;
  lower: boolean;
  digits: boolean;
  symbols: boolean;
}

export interface Toast {
  id: number;
  message: string;
  kind: "ok" | "err" | "info";
}

export interface VaultSettings {
  autoLockMinutes: number;
  lockOnScreenLock: boolean;
  biometricsEnabled: boolean;
  passwordIntervalDays: number;
  screenLockSupported: boolean;
}

export const DEFAULT_VAULT_SETTINGS: VaultSettings = {
  autoLockMinutes: 1,
  lockOnScreenLock: false,
  biometricsEnabled: false,
  passwordIntervalDays: 14,
  screenLockSupported: false,
};

export interface BiometricStatus {
  available: boolean;
  configured: boolean;
  prf: boolean;
  canUnlock: boolean;
  passwordRequired: boolean;
  reason?: "restart" | "interval";
  platform: "web" | "macos" | "ios" | "unsupported";
  touchIdReregister?: boolean;
}

export interface SettingsPatch {
  autoLockMinutes?: number;
  lockOnScreenLock?: boolean;
  passwordIntervalDays?: number;
}

export interface SecretKeyStatus {
  enabled: boolean;
  stored: boolean;
  required: boolean;
}

export interface DeviceRecord {
  id: string;
  name: string;
  lastSeen: string;
}

export interface DeviceManagerStatus {
  deviceId: string;
  deviceName: string;
  managerDeviceId?: string | null;
  managerDeviceName?: string | null;
  canChangeSecretKey: boolean;
  managerMissing: boolean;
  isManager: boolean;
  notice?: string | null;
  devices: DeviceRecord[];
}

export interface EmergencyKit {
  secretKey: string;
  vaultName: string;
  date: string;
  stored: boolean;
  storeError?: string;
}

export interface DiscoveredVault {
  path: string;
  name: string;
  placeholder: boolean;
}

export interface OpenVaultStatus {
  state: "ready" | "waiting_icloud" | string;
  path: string;
  message: string;
  placeholder: boolean;
}

export type SyncState = "ok" | "waiting_icloud" | "password_required" | "error";

export interface SyncStatus {
  state: SyncState | string;
  vaultPath: string;
  deviceId: string;
  revision: number;
  generation: number;
  conflictCount: number;
  pendingFiles: string[];
  message: string;
  locked: boolean;
}

export interface ConflictView {
  itemId: string;
  conflictId: string;
  currentDeleted: boolean;
  currentTitle: string;
  currentUpdatedAt: string;
  currentItemType: string;
  currentUsername: string;
  conflictDeleted: boolean;
  conflictTitle: string;
  conflictUpdatedAt: string;
  conflictItemType: string;
  conflictUsername: string;
  conflictUpdatedBy: string;
}

export type VaultLocationMode = "move" | "open";
export type ConflictAction = "keep" | "restore";
