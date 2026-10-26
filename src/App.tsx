import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  biometricUnlock,
  clientPlatform,
  createVault,
  demoView,
  getPendingApprovals,
  getSession,
  getVaultSettings,
  isTauri,
  listItems,
  idleLock,
  lock,
  looksLikeIos,
  mapError,
  respondMcpApproval,
  secretKeyStatus,
  syncStatus as fetchSyncStatus,
  touchActivity,
  unlock,
  vaultExists,
} from "./api";
import ApprovalModal, { DEMO_APPROVAL } from "./components/ApprovalModal";
import MainScreen from "./components/MainScreen";
import IosMain, { type IosDemo } from "./components/ios/IosMain";
import SecretKeyScreen from "./components/SecretKeyScreen";
import SetupScreen from "./components/SetupScreen";
import UnlockScreen from "./components/UnlockScreen";
import type { ApprovalRequest, SyncStatus, Toast, VaultItem, VaultSettings } from "./types";
import { DEFAULT_VAULT_SETTINGS } from "./types";

type Screen = "loading" | "setup" | "secret-key" | "unlock" | "main";
type Theme = "dark" | "light";

const THEME_KEY = "securevault.theme";
const LEGACY_THEME_KEY = "keyhaven.theme";

export default function App() {
  const [screen, setScreen] = useState<Screen>("loading");
  const [items, setItems] = useState<VaultItem[]>([]);
  const [theme, setTheme] = useState<Theme>(() => {
    const saved = localStorage.getItem(THEME_KEY) ?? localStorage.getItem(LEGACY_THEME_KEY);
    return saved === "light" ? "light" : "dark";
  });
  const [settings, setSettings] = useState<VaultSettings>(DEFAULT_VAULT_SETTINGS);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [approval, setApproval] = useState<ApprovalRequest | null>(null);
  const [syncStatus, setSyncStatus] = useState<SyncStatus | null>(null);
  const [demoDismissed, setDemoDismissed] = useState(false);
  const [pendingSecretKey, setPendingSecretKey] = useState("");
  // iPhone app (or the web UI opened on an iPhone) gets the native-style shell.
  // The Mac app reports "macos" and always keeps MainScreen.
  const [iosUi, setIosUi] = useState(looksLikeIos);
  const [demo, setDemo] = useState<IosDemo | null>(null);
  const toastSeq = useRef(1);
  const seenGeneration = useRef<number | null>(null);
  const idleTimer = useRef<number | null>(null);
  const lastActivityPing = useRef(0);
  const demoApproval = useMemo(() => {
    if (typeof window === "undefined") return false;
    return new URLSearchParams(window.location.search).get("demoApproval") === "1";
  }, []);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem(THEME_KEY, theme);
  }, [theme]);

  useEffect(() => {
    let cancelled = false;
    void clientPlatform().then((platform) => {
      if (cancelled) return;
      setIosUi(platform === "ios" || (platform === "web" && looksLikeIos()));
    });
    void demoView().then((d) => {
      if (cancelled || !d) return;
      if (d.theme === "light" || d.theme === "dark") setTheme(d.theme);
      setDemo({ view: d.view ?? null });
    });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    document.documentElement.classList.toggle("ios-ui", iosUi);
  }, [iosUi]);

  const pushToast = useCallback((toast: Omit<Toast, "id">) => {
    const id = toastSeq.current;
    toastSeq.current += 1;
    setToasts((list) => [...list, { ...toast, id }]);
    window.setTimeout(() => {
      setToasts((list) => list.filter((t) => t.id !== id));
    }, 3200);
  }, []);

  const reloadItems = useCallback(async () => {
    try {
      const next = await listItems();
      setItems(next);
    } catch (err) {
      if (err instanceof Error && err.message === "vault is locked") {
        setItems([]);
        setScreen("unlock");
      }
      throw err;
    }
  }, []);

  const enterMain = useCallback(async () => {
    const nextSettings = await getVaultSettings();
    setSettings(nextSettings);
    const next = await listItems();
    setItems(next);
    setScreen("main");
  }, []);

  const showUnlock = useCallback(() => {
    setApproval((current) => {
      if (current && current.requestId !== "demo") {
        void respondMcpApproval(current.requestId, false).catch(() => undefined);
      }
      return null;
    });
    setItems([]);
    void secretKeyStatus()
      .then((sk) => setScreen(sk.required ? "secret-key" : "unlock"))
      .catch(() => setScreen("unlock"));
  }, []);

  const handleLock = useCallback(async () => {
    setApproval((current) => {
      if (current && current.requestId !== "demo") {
        void respondMcpApproval(current.requestId, false).catch(() => undefined);
      }
      return null;
    });
    try {
      await lock();
    } finally {
      setItems([]);
      setScreen("unlock");
    }
  }, []);

  const handleIdle = useCallback(async () => {
    setApproval((current) => {
      if (current && current.requestId !== "demo") {
        void respondMcpApproval(current.requestId, false).catch(() => undefined);
      }
      return null;
    });
    try {
      await idleLock();
    } catch {
      /* the server may already have dropped the session */
    } finally {
      setItems([]);
      setScreen("unlock");
    }
  }, []);

  const applyApproval = useCallback((payload: ApprovalRequest) => {
    setApproval((current) => {
      if (current && current.requestId !== "demo" && current.requestId !== payload.requestId) {
        void respondMcpApproval(current.requestId, false).catch(() => undefined);
      }
      return payload;
    });
  }, []);

  useEffect(() => {
    if (isTauri()) {
      let unlisten: (() => void) | undefined;
      let cancelled = false;
      void import("@tauri-apps/api/event").then(({ listen }) =>
        listen<ApprovalRequest>("mcp-approval-request", (event) => {
          applyApproval(event.payload);
        }),
      ).then((fn) => {
        if (cancelled) fn();
        else unlisten = fn;
      });
      return () => {
        cancelled = true;
        unlisten?.();
      };
    }
    if (screen !== "main") return;
    const es = new EventSource("/api/events");
    es.onmessage = (event) => {
      try {
        applyApproval(JSON.parse(event.data) as ApprovalRequest);
      } catch {
        /* ignore malformed events */
      }
    };
    const poll = window.setInterval(() => {
      void getPendingApprovals()
        .then((pending) => {
          if (pending[0]) applyApproval(pending[0]);
        })
        .catch((err: unknown) => {
          if (err instanceof Error && err.message === "vault is locked") {
            showUnlock();
          }
        });
    }, 2000);
    return () => {
      es.close();
      window.clearInterval(poll);
    };
  }, [applyApproval, screen]);

  useEffect(() => {
    if (screen !== "main") {
      seenGeneration.current = null;
      return;
    }
    let cancelled = false;
    const tick = async () => {
      try {
        const status = await fetchSyncStatus();
        if (cancelled) return;
        if (status.locked) {
          showUnlock();
          return;
        }
        setSyncStatus(status);
        if (seenGeneration.current === null) {
          seenGeneration.current = status.generation;
          return;
        }
        if (status.generation !== seenGeneration.current) {
          seenGeneration.current = status.generation;
          try {
            await reloadItems();
          } catch {
            return;
          }
          const nextSettings = await getVaultSettings().catch(() => null);
          if (!cancelled && nextSettings) setSettings(nextSettings);
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (message === "vault is locked" || message === "csrf rejected") {
          showUnlock();
        }
      }
    };
    void tick();
    const id = window.setInterval(() => {
      void tick();
    }, 3000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [screen, reloadItems, showUnlock]);

  const decideApproval = useCallback((approved: boolean) => {
    setApproval((current) => {
      if (current && current.requestId !== "demo") {
        void respondMcpApproval(current.requestId, approved).catch(() => undefined);
      }
      return null;
    });
    setDemoDismissed(true);
  }, []);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const exists = await vaultExists();
        const session = await getSession();
        if (cancelled) return;
        if (session.unlocked) {
          const nextSettings = await getVaultSettings();
          if (cancelled) return;
          setSettings(nextSettings);
          const next = await listItems();
          if (cancelled) return;
          setItems(next);
          setScreen("main");
          return;
        }
        if (!exists) {
          setScreen("setup");
          return;
        }
        const sk = await secretKeyStatus().catch(() => null);
        setScreen(sk?.required ? "secret-key" : "unlock");
      } catch {
        if (!cancelled) {
          const exists = await vaultExists().catch(() => false);
          if (!exists) {
            setScreen("setup");
            return;
          }
          const sk = await secretKeyStatus().catch(() => null);
          setScreen(sk?.required ? "secret-key" : "unlock");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!isTauri()) return;
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    void import("@tauri-apps/api/event").then(({ listen }) =>
      listen("vault-locked", () => {
        void handleLock();
      }),
    ).then((fn) => {
      if (cancelled) fn();
      else unlisten = fn;
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [handleLock]);

  useEffect(() => {
    if (screen !== "main") {
      if (idleTimer.current) window.clearTimeout(idleTimer.current);
      return;
    }
    const minutes = settings.autoLockMinutes > 0 ? settings.autoLockMinutes : 1;
    const bump = () => {
      if (idleTimer.current) window.clearTimeout(idleTimer.current);
      idleTimer.current = window.setTimeout(() => {
        void handleIdle();
      }, minutes * 60 * 1000);
      if (!isTauri()) {
        const now = Date.now();
        if (now - lastActivityPing.current > 10_000) {
          lastActivityPing.current = now;
          void touchActivity().catch((err: unknown) => {
            if (err instanceof Error && err.message === "vault is locked") {
              showUnlock();
            }
          });
        }
      }
    };
    bump();
    const events: Array<keyof WindowEventMap> = ["mousemove", "keydown", "mousedown", "touchstart"];
    events.forEach((name) => window.addEventListener(name, bump, { passive: true }));
    const onReturn = () => {
      if (document.visibilityState === "hidden") return;
      void getSession()
        .then((session) => {
          if (!session.unlocked) showUnlock();
        })
        .catch(() => undefined);
    };
    document.addEventListener("visibilitychange", onReturn);
    window.addEventListener("focus", onReturn);
    return () => {
      if (idleTimer.current) window.clearTimeout(idleTimer.current);
      events.forEach((name) => window.removeEventListener(name, bump));
      document.removeEventListener("visibilitychange", onReturn);
      window.removeEventListener("focus", onReturn);
    };
  }, [screen, settings.autoLockMinutes, handleIdle]);

  async function handleCreate(password: string) {
    try {
      await createVault(password);
      await enterMain();
    } catch (e) {
      throw new Error(mapError(e instanceof Error ? e.message : String(e)));
    }
  }

  async function handleUnlock(password: string) {
    try {
      await unlock(password, pendingSecretKey || undefined);
      setPendingSecretKey("");
      await enterMain();
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      if (message === "secret key required") {
        setScreen("secret-key");
      }
      throw new Error(mapError(message));
    }
  }

  async function handleBiometric() {
    try {
      await biometricUnlock();
      await enterMain();
    } catch (e) {
      throw new Error(mapError(e instanceof Error ? e.message : String(e)));
    }
  }

  return (
    <>
      {screen === "loading" ? <div className="auth-wrap">불러오는 중…</div> : null}
      {screen === "setup" ? (
        <SetupScreen
          onCreate={handleCreate}
          onOpened={() => {
            void secretKeyStatus()
              .then((sk) => setScreen(sk.required ? "secret-key" : "unlock"))
              .catch(() => setScreen("unlock"));
          }}
        />
      ) : null}
      {screen === "secret-key" ? (
        <SecretKeyScreen
          onReady={(secretKey) => {
            setPendingSecretKey(secretKey);
            setScreen("unlock");
          }}
        />
      ) : null}
      {screen === "unlock" ? <UnlockScreen onUnlock={handleUnlock} onBiometric={handleBiometric} /> : null}
      {screen === "main" && iosUi ? (
        <IosMain
          items={items}
          theme={theme}
          settings={settings}
          demo={demo}
          onReload={reloadItems}
          onLock={handleLock}
          onToggleTheme={() => setTheme((t) => (t === "dark" ? "light" : "dark"))}
          onSettingsChange={setSettings}
          onToast={pushToast}
          syncStatus={syncStatus}
          onSyncStatus={setSyncStatus}
          onRequireUnlock={showUnlock}
        />
      ) : null}
      {screen === "main" && !iosUi ? (
        <MainScreen
          items={items}
          theme={theme}
          settings={settings}
          onReload={reloadItems}
          onLock={handleLock}
          onToggleTheme={() => setTheme((t) => (t === "dark" ? "light" : "dark"))}
          onSettingsChange={setSettings}
          onToast={pushToast}
          syncStatus={syncStatus}
          onSyncStatus={setSyncStatus}
          onRequireUnlock={showUnlock}
        />
      ) : null}
      {approval || (demoApproval && !demoDismissed) ? (
        <ApprovalModal
          request={approval ?? DEMO_APPROVAL}
          onApprove={() => decideApproval(true)}
          onDeny={() => decideApproval(false)}
        />
      ) : null}
      <div className="toasts">
        {toasts.map((t) => (
          <div key={t.id} className={`toast ${t.kind}`}>
            {t.message}
          </div>
        ))}
      </div>
    </>
  );
}
