import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import EmergencyKit from "../components/EmergencyKit";
import type { EmergencyKit as Kit } from "../types";
import "../index.css";

const DUMMY_KIT: Kit = {
  secretKey: "SV1-AAAAAA-BBBBBB-CCCCCC-DDDDDD-EEEEEE-FFFFFF-AA2345",
  vaultName: "우리집 금고",
  date: "2026-10-25",
  stored: true,
};

function installTauriMock(): void {
  const internals = {
    invoke: async (cmd: string) => {
      if (
        cmd === "save_emergency_kit_pdf" ||
        cmd === "save_secret_key_qr" ||
        cmd === "print_emergency_kit" ||
        cmd === "copy_to_clipboard"
      ) {
        return null;
      }
      throw new Error("mocked tauri command failed");
    },
    transformCallback: () => 0,
    unregisterCallback: () => undefined,
  };
  Object.defineProperty(window, "__TAURI_INTERNALS__", {
    value: internals,
    configurable: true,
  });
}

installTauriMock();

const root = document.getElementById("root");
if (!root) {
  throw new Error("missing root");
}

createRoot(root).render(
  <StrictMode>
    <EmergencyKit kit={DUMMY_KIT} viewOnly={false} onDone={() => undefined} />
  </StrictMode>,
);
