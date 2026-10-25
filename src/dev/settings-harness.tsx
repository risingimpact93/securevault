import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { SettingsPanel } from "../components/MainScreen";
import { DEFAULT_VAULT_SETTINGS, type DeviceManagerStatus, type SyncStatus, type Toast } from "../types";
import "../index.css";

const MANAGER_ID = "3f2c1a90-7b6e-4d11-9c08-a1b2c3d4e5f6";
const HOME_ID = "18b04d77-2c91-4a55-90e1-112233445566";
const TRAVEL_ID = "91aa02bc-44d1-4e77-8f30-bbccddeeff00";

const MANAGER: DeviceManagerStatus = {
  deviceId: MANAGER_ID,
  deviceName: "작업실 Mac",
  managerDeviceId: MANAGER_ID,
  managerDeviceName: "작업실 Mac",
  canChangeSecretKey: true,
  managerMissing: false,
  isManager: true,
  notice: null,
  devices: [
    { id: MANAGER_ID, name: "작업실 Mac", lastSeen: "2026-10-25T09:12:00Z" },
    { id: HOME_ID, name: "집 Mac", lastSeen: "2026-10-24T18:04:00Z" },
  ],
};

const NON_MANAGER: DeviceManagerStatus = {
  deviceId: TRAVEL_ID,
  deviceName: "여행용 iPad",
  managerDeviceId: MANAGER_ID,
  managerDeviceName: "작업실 Mac",
  canChangeSecretKey: false,
  managerMissing: false,
  isManager: false,
  notice: "관리 기기(작업실 Mac)에서만 변경할 수 있어요",
  devices: [
    { id: MANAGER_ID, name: "작업실 Mac", lastSeen: "2026-10-25T09:12:00Z" },
    { id: TRAVEL_ID, name: "여행용 iPad", lastSeen: "2026-10-25T08:40:00Z" },
  ],
};

function installTauriMock(device: DeviceManagerStatus): void {
  const internals = {
    invoke: async (cmd: string) => {
      switch (cmd) {
        case "device_manager_status":
          return device;
        case "secret_key_status":
          return { enabled: true, stored: true, required: true };
        case "biometric_status":
          return {
            available: true,
            configured: false,
            prf: false,
            canUnlock: false,
            passwordRequired: true,
            platform: "macos",
          };
        case "sync_conflicts":
          return [];
        case "sync_status":
          return syncStatusFor(device);
        case "mcp_get_settings":
          return { enabled: false, port: 47821, tokens: [] };
        case "mcp_access_log":
          return [];
        case "app_build":
          return { version: "0.3.2", commit: "dev" };
        case "copy_to_clipboard":
          return null;
        default:
          throw new Error(`mocked tauri command failed: ${cmd}`);
      }
    },
    transformCallback: () => 0,
    unregisterCallback: () => undefined,
  };
  Object.defineProperty(window, "__TAURI_INTERNALS__", {
    value: internals,
    configurable: true,
  });
}

function syncStatusFor(device: DeviceManagerStatus): SyncStatus {
  return {
    state: "ok",
    vaultPath: "/Users/dummy/Library/Mobile Documents/com~apple~CloudDocs/SecureVault/vault.khv",
    deviceId: device.deviceId,
    revision: 7,
    generation: 2,
    conflictCount: 0,
    pendingFiles: [],
    message: "",
    locked: false,
  };
}

const view = new URLSearchParams(window.location.search).get("view");
const device = view === "nonmanager" ? NON_MANAGER : MANAGER;
installTauriMock(device);

const root = document.getElementById("root");
if (!root) {
  throw new Error("missing root");
}

function onToast(toast: Omit<Toast, "id">): void {
  console.error(`toast ${toast.kind}: ${toast.message}`);
}

createRoot(root).render(
  <StrictMode>
    <div className="settings-shot">
      <SettingsPanel
        settings={DEFAULT_VAULT_SETTINGS}
        syncStatus={syncStatusFor(device)}
        onSettingsChange={() => undefined}
        onSyncStatus={() => undefined}
        onRequireUnlock={() => undefined}
        onToast={onToast}
        onReload={() => Promise.resolve()}
        onKit={() => undefined}
      />
    </div>
  </StrictMode>,
);
