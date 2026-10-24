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
  platform: "web" | "macos" | "unsupported";
}

export interface SettingsPatch {
  autoLockMinutes?: number;
  lockOnScreenLock?: boolean;
  passwordIntervalDays?: number;
}
