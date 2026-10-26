import { FormEvent, ReactNode, TouchEvent, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import {
  addItem,
  appBuild,
  copyToClipboard,
  deleteItem,
  generatePassword,
  mapError,
  openExternalUrl,
  updateItem,
} from "../../api";
import type {
  EmergencyKit as EmergencyKitData,
  GenerateOpts,
  ItemDraft,
  ItemType,
  SyncStatus,
  Toast,
  VaultItem,
  VaultSettings,
} from "../../types";
import EmergencyKit from "../EmergencyKit";
import { SettingsPanel } from "../MainScreen";

/* iOS-only shell (iPhone app, or the web UI opened on an iPhone).
   The Mac/desktop layout lives in MainScreen and is not touched by this file. */

type Tab = "items" | "generator" | "settings";
type Route = { kind: "list" } | { kind: "detail"; id: string } | { kind: "edit"; id: string | null };
type TypeFilter = "all" | ItemType;

export interface IosDemo {
  view?: string | null;
}

interface Props {
  items: VaultItem[];
  theme: "dark" | "light";
  settings: VaultSettings;
  syncStatus: SyncStatus | null;
  demo: IosDemo | null;
  onReload: () => Promise<void>;
  onLock: () => Promise<void>;
  onToggleTheme: () => void;
  onSettingsChange: (settings: VaultSettings) => void;
  onSyncStatus: (status: SyncStatus) => void;
  onRequireUnlock: () => void;
  onToast: (toast: Omit<Toast, "id">) => void;
}

const TYPE_FILTERS: { id: TypeFilter; label: string }[] = [
  { id: "all", label: "전체" },
  { id: "login", label: "로그인" },
  { id: "card", label: "카드" },
  { id: "note", label: "메모" },
];

function typeLabel(t: ItemType): string {
  if (t === "login") return "로그인";
  if (t === "note") return "보안 메모";
  return "카드";
}

function subtitle(item: VaultItem): string {
  if (item.itemType === "login") return item.username || item.url || "로그인";
  if (item.itemType === "card") {
    const n = (item.number ?? "").replace(/\s+/g, "");
    return n.length >= 4 ? `•••• ${n.slice(-4)}` : item.cardholder || "카드";
  }
  return item.notes?.split("\n")[0] || "보안 메모";
}

function compareItems(a: VaultItem, b: VaultItem): number {
  const order = (a.order ?? "").localeCompare(b.order ?? "");
  if (order !== 0) return order;
  return a.id.localeCompare(b.id);
}

function emptyDraft(type: ItemType): ItemDraft {
  return {
    itemType: type,
    title: "",
    favorite: false,
    username: "",
    password: "",
    url: "",
    notes: "",
    cardholder: "",
    number: "",
    expiry: "",
    cvv: "",
    tags: [],
  };
}

function itemToDraft(item: VaultItem): ItemDraft {
  return {
    itemType: item.itemType,
    title: item.title,
    favorite: item.favorite,
    username: item.username ?? "",
    password: item.password ?? "",
    url: item.url ?? "",
    notes: item.notes ?? "",
    cardholder: item.cardholder ?? "",
    number: item.number ?? "",
    expiry: item.expiry ?? "",
    cvv: item.cvv ?? "",
    tags: item.tags ?? [],
  };
}

function errText(err: unknown): string {
  return mapError(err instanceof Error ? err.message : String(err));
}

/* ---------- icons ---------- */

function Icon({ children, size = 22 }: { children: ReactNode; size?: number }) {
  return (
    <svg className="ios-icon" width={size} height={size} viewBox="0 0 24 24" aria-hidden="true">
      {children}
    </svg>
  );
}
const stroke = { fill: "none", stroke: "currentColor", strokeWidth: 2, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };
const IconChevronLeft = () => (
  <Icon size={24}>
    <path d="M15 4l-8 8 8 8" {...stroke} strokeWidth={2.6} />
  </Icon>
);
const IconChevronRight = () => (
  <Icon size={14}>
    <path d="M9 4l8 8-8 8" {...stroke} strokeWidth={2.6} />
  </Icon>
);
const IconPlus = () => (
  <Icon size={26}>
    <path d="M12 4v16M4 12h16" {...stroke} strokeWidth={2.4} />
  </Icon>
);
const IconSearch = () => (
  <Icon size={18}>
    <circle cx="11" cy="11" r="7" {...stroke} />
    <path d="M20 20l-3.6-3.6" {...stroke} />
  </Icon>
);
const IconEye = ({ off }: { off?: boolean }) => (
  <Icon>
    <path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z" {...stroke} />
    <circle cx="12" cy="12" r="3" {...stroke} />
    {off ? <path d="M4 4l16 16" {...stroke} /> : null}
  </Icon>
);
const IconOpen = () => (
  <Icon>
    <path d="M14 4h6v6M20 4l-9 9" {...stroke} />
    <path d="M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5" {...stroke} />
  </Icon>
);
const IconStar = ({ filled }: { filled?: boolean }) => (
  <Icon>
    <path
      d="M12 3.5l2.6 5.3 5.9.9-4.3 4.1 1 5.8L12 16.9l-5.2 2.7 1-5.8-4.3-4.1 5.9-.9z"
      fill={filled ? "currentColor" : "none"}
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinejoin="round"
    />
  </Icon>
);
const IconKey = () => (
  <Icon size={26}>
    <circle cx="8" cy="15" r="4" {...stroke} />
    <path d="M11 12l9-9M17 6l3 3M15 8l2 2" {...stroke} />
  </Icon>
);
const IconDice = () => (
  <Icon size={26}>
    <rect x="4" y="4" width="16" height="16" rx="4" {...stroke} />
    <circle cx="9" cy="9" r="1.3" fill="currentColor" />
    <circle cx="15" cy="15" r="1.3" fill="currentColor" />
    <circle cx="15" cy="9" r="1.3" fill="currentColor" />
    <circle cx="9" cy="15" r="1.3" fill="currentColor" />
  </Icon>
);
const IconGear = () => (
  <Icon size={26}>
    <circle cx="12" cy="12" r="3.2" {...stroke} />
    <path
      d="M12 2.8v2.4M12 18.8v2.4M2.8 12h2.4M18.8 12h2.4M5.5 5.5l1.7 1.7M16.8 16.8l1.7 1.7M5.5 18.5l1.7-1.7M16.8 7.2l1.7-1.7"
      {...stroke}
    />
  </Icon>
);
const IconCopy = () => (
  <Icon size={20}>
    <rect x="8" y="8" width="12" height="12" rx="2.5" {...stroke} />
    <path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2" {...stroke} />
  </Icon>
);

/* ---------- small building blocks ---------- */

function Avatar({ item, size = 40 }: { item: Pick<VaultItem, "title" | "itemType">; size?: number }) {
  const title = item.title.trim();
  let hash = 0;
  for (const ch of title) hash = (hash * 31 + ch.codePointAt(0)!) % 360;
  const letter = title.replace(/^예시\s*/, "").charAt(0) || title.charAt(0) || "?";
  return (
    <span
      className="ios-avatar"
      style={{ width: size, height: size, fontSize: size * 0.45, background: `hsl(${hash} 42% 42%)` }}
      aria-hidden="true"
    >
      {item.itemType === "card" ? "▭" : item.itemType === "note" ? "✎" : letter.toUpperCase()}
    </span>
  );
}

function NavBar({
  left,
  title,
  right,
  showTitle = true,
}: {
  left?: ReactNode;
  title?: string;
  right?: ReactNode;
  showTitle?: boolean;
}) {
  return (
    <header className="ios-navbar">
      <div className="ios-navbar-row">
        <div className="ios-nav-left">{left}</div>
        <div className={`ios-nav-title${showTitle ? " shown" : ""}`}>{title}</div>
        <div className="ios-nav-right">{right}</div>
      </div>
    </header>
  );
}

function Group({ header, footer, children }: { header?: string; footer?: ReactNode; children: ReactNode }) {
  return (
    <section className="ios-group">
      {header ? <h3 className="ios-group-header">{header}</h3> : null}
      <div className="ios-group-card">{children}</div>
      {footer ? <div className="ios-group-footer">{footer}</div> : null}
    </section>
  );
}

function Switch({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      className={`ios-switch${checked ? " on" : ""}`}
      onClick={() => onChange(!checked)}
    >
      <span className="knob" />
    </button>
  );
}

function Segmented<T extends string>({
  value,
  options,
  onChange,
}: {
  value: T;
  options: { id: T; label: string }[];
  onChange: (v: T) => void;
}) {
  return (
    <div className="ios-segmented" role="tablist">
      {options.map((o) => (
        <button
          key={o.id}
          type="button"
          role="tab"
          aria-selected={value === o.id}
          className={value === o.id ? "active" : ""}
          onClick={() => onChange(o.id)}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

/* ---------- list row with swipe actions ---------- */

const SWIPE_WIDTH = 152;

function SwipeRow({
  item,
  open,
  onOpenChange,
  onSelect,
  onCopyPassword,
  onFavorite,
}: {
  item: VaultItem;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSelect: () => void;
  onCopyPassword: () => void;
  onFavorite: () => void;
}) {
  const start = useRef<{ x: number; y: number; base: number } | null>(null);
  const axis = useRef<"x" | "y" | null>(null);
  const moved = useRef(false);
  const [dx, setDx] = useState<number | null>(null);
  const offset = dx ?? (open ? -SWIPE_WIDTH : 0);

  function onTouchStart(e: TouchEvent) {
    const t = e.touches[0];
    start.current = { x: t.clientX, y: t.clientY, base: open ? -SWIPE_WIDTH : 0 };
    axis.current = null;
    moved.current = false;
  }
  function onTouchMove(e: TouchEvent) {
    if (!start.current) return;
    const t = e.touches[0];
    const mx = t.clientX - start.current.x;
    const my = t.clientY - start.current.y;
    if (!axis.current) {
      if (Math.abs(mx) < 8 && Math.abs(my) < 8) return;
      axis.current = Math.abs(mx) > Math.abs(my) ? "x" : "y";
    }
    if (axis.current !== "x") return;
    moved.current = true;
    setDx(Math.max(-SWIPE_WIDTH - 24, Math.min(0, start.current.base + mx)));
  }
  function onTouchEnd() {
    if (axis.current === "x" && dx !== null) onOpenChange(dx < -SWIPE_WIDTH / 2.5);
    setDx(null);
    start.current = null;
  }

  return (
    <div className="ios-swipe">
      <div className="ios-swipe-actions" aria-hidden={!open}>
        {item.itemType === "login" && item.password ? (
          <button type="button" className="swipe-copy" onClick={onCopyPassword} tabIndex={open ? 0 : -1}>
            <IconCopy />
            <span>비밀번호</span>
          </button>
        ) : null}
        <button type="button" className="swipe-fav" onClick={onFavorite} tabIndex={open ? 0 : -1}>
          <IconStar filled={!item.favorite} />
          <span>{item.favorite ? "해제" : "즐겨찾기"}</span>
        </button>
      </div>
      <button
        type="button"
        className="ios-row ios-row-item"
        style={{
          transform: `translateX(${offset}px)`,
          transition: dx === null ? "transform 0.25s ease" : "none",
        }}
        onTouchStart={onTouchStart}
        onTouchMove={onTouchMove}
        onTouchEnd={onTouchEnd}
        onTouchCancel={onTouchEnd}
        onClick={() => {
          if (moved.current) {
            moved.current = false;
            return;
          }
          if (open) onOpenChange(false);
          else onSelect();
        }}
      >
        <Avatar item={item} />
        <span className="ios-row-text">
          <span className="ios-row-title">
            {item.title}
            {item.favorite ? (
              <span className="ios-fav-dot" aria-label="즐겨찾기">
                <IconStar filled />
              </span>
            ) : null}
          </span>
          <span className="ios-row-sub">{subtitle(item)}</span>
        </span>
        <span className="ios-chevron">
          <IconChevronRight />
        </span>
      </button>
    </div>
  );
}

/* ---------- main ---------- */

export default function IosMain(props: Props) {
  const { items, syncStatus, demo, onReload, onToast } = props;
  const [tab, setTab] = useState<Tab>("items");
  const [route, setRoute] = useState<Route>({ kind: "list" });
  const [query, setQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState<TypeFilter>("all");
  const [swipeOpen, setSwipeOpen] = useState<string | null>(null);
  const [kit, setKit] = useState<EmergencyKitData | null>(null);
  const [kitViewOnly, setKitViewOnly] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const scrollRef = useRef<HTMLElement | null>(null);
  const savedListScroll = useRef(0);
  const demoApplied = useRef(false);

  useEffect(() => {
    document.documentElement.classList.add("ios-main");
    return () => document.documentElement.classList.remove("ios-main");
  }, []);

  const sorted = useMemo(() => [...items].sort(compareItems), [items]);
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return sorted.filter((item) => {
      if (typeFilter !== "all" && item.itemType !== typeFilter) return false;
      if (!q) return true;
      return [item.title, item.username, item.url, item.notes, item.cardholder, ...(item.tags ?? [])]
        .filter(Boolean)
        .join(" ")
        .toLowerCase()
        .includes(q);
    });
  }, [sorted, query, typeFilter]);
  const favorites = filtered.filter((i) => i.favorite);
  const others = filtered.filter((i) => !i.favorite);

  // CI screenshots open a specific screen on the dummy vault.
  useEffect(() => {
    if (demoApplied.current || !demo?.view || sorted.length === 0) return;
    demoApplied.current = true;
    const first = sorted.find((i) => i.favorite) ?? sorted[0];
    switch (demo.view) {
      case "detail":
        setRoute({ kind: "detail", id: first.id });
        break;
      case "edit":
        setRoute({ kind: "edit", id: first.id });
        break;
      case "new":
        setRoute({ kind: "edit", id: null });
        break;
      case "settings":
        setTab("settings");
        break;
      case "generator":
        setTab("generator");
        break;
      case "swipe":
        setSwipeOpen((sorted.find((i) => !i.favorite) ?? first).id);
        break;
      case "scrolled":
        window.setTimeout(() => {
          const el = scrollRef.current;
          if (el) el.scrollTo({ top: el.scrollHeight, behavior: "auto" });
        }, 400);
        break;
      default:
        break;
    }
  }, [demo, sorted]);

  // Each screen starts at the top; the list keeps its position when you come back.
  const pageKey = `${tab}:${route.kind}:${route.kind === "list" ? "" : route.id ?? "new"}`;
  useLayoutEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    el.scrollTop = tab === "items" && route.kind === "list" ? savedListScroll.current : 0;
    setScrolled(el.scrollTop > 8);
  }, [pageKey]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (route.kind !== "list" && !items.some((i) => i.id === (route as { id: string | null }).id) && !(route.kind === "edit" && route.id === null)) {
      setRoute({ kind: "list" });
    }
  }, [items, route]);

  async function copy(text: string, label: string) {
    try {
      await copyToClipboard(text, 30);
      onToast({ kind: "ok", message: `${label} 복사됨` });
    } catch (e) {
      onToast({ kind: "err", message: errText(e) });
    }
  }

  async function toggleFavorite(item: VaultItem) {
    try {
      await updateItem({ ...item, favorite: !item.favorite });
      await onReload();
      onToast({ kind: "ok", message: item.favorite ? "즐겨찾기 해제됨" : "즐겨찾기에 추가됨" });
    } catch (e) {
      onToast({ kind: "err", message: errText(e) });
    }
  }

  function openItem(id: string) {
    if (scrollRef.current) savedListScroll.current = scrollRef.current.scrollTop;
    setSwipeOpen(null);
    setRoute({ kind: "detail", id });
  }

  const current = route.kind === "list" ? null : items.find((i) => i.id === route.id) ?? null;
  const inEdit = tab === "items" && route.kind === "edit";

  let page: ReactNode;
  if (tab === "generator") {
    page = <GeneratorPage scrolled={scrolled} onCopy={(pw) => void copy(pw, "비밀번호")} />;
  } else if (tab === "settings") {
    page = (
      <SettingsPage
        {...props}
        scrolled={scrolled}
        onKit={(next, viewOnly) => {
          setKitViewOnly(viewOnly);
          setKit(next);
        }}
      />
    );
  } else if (route.kind === "edit") {
    page = (
      <EditPage
        key={route.id ?? "new"}
        item={route.id ? current : null}
        onCancel={() => setRoute(route.id ? { kind: "detail", id: route.id } : { kind: "list" })}
        onSaved={(id) => setRoute({ kind: "detail", id })}
        onDeleted={() => setRoute({ kind: "list" })}
        onReload={onReload}
        onToast={onToast}
      />
    );
  } else if (route.kind === "detail" && current) {
    page = (
      <DetailPage
        key={current.id}
        item={current}
        scrolled={scrolled}
        onBack={() => setRoute({ kind: "list" })}
        onEdit={() => setRoute({ kind: "edit", id: current.id })}
        onFavorite={() => void toggleFavorite(current)}
        onCopy={(text, label) => void copy(text, label)}
        onToast={onToast}
      />
    );
  } else {
    page = (
      <>
        <NavBar
          title="항목"
          showTitle={scrolled}
          right={
            <button type="button" className="ios-nav-icon" aria-label="새 항목" onClick={() => setRoute({ kind: "edit", id: null })}>
              <IconPlus />
            </button>
          }
        />
        <h1 className="ios-large-title">항목</h1>
        <div className="ios-search">
          <IconSearch />
          <input
            type="search"
            inputMode="search"
            enterKeyHint="search"
            placeholder="검색"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            autoCorrect="off"
            autoCapitalize="none"
            spellCheck={false}
          />
          {query ? (
            <button type="button" className="ios-search-clear" aria-label="지우기" onClick={() => setQuery("")}>
              ✕
            </button>
          ) : null}
        </div>
        <div className="ios-filter">
          <Segmented value={typeFilter} options={TYPE_FILTERS} onChange={setTypeFilter} />
        </div>
        {syncStatus && syncBanner(syncStatus) ? (
          <button type="button" className="ios-banner" onClick={() => setTab("settings")}>
            {syncBanner(syncStatus)}
          </button>
        ) : null}
        {filtered.length === 0 ? (
          <p className="ios-empty">{items.length === 0 ? "아직 항목이 없습니다. 오른쪽 위 +로 추가하세요." : "검색 결과가 없습니다."}</p>
        ) : null}
        {favorites.length > 0 ? (
          <Group header="즐겨찾기">
            {favorites.map((item) => (
              <SwipeRow
                key={item.id}
                item={item}
                open={swipeOpen === item.id}
                onOpenChange={(o) => setSwipeOpen(o ? item.id : null)}
                onSelect={() => openItem(item.id)}
                onCopyPassword={() => {
                  setSwipeOpen(null);
                  void copy(item.password ?? "", "비밀번호");
                }}
                onFavorite={() => {
                  setSwipeOpen(null);
                  void toggleFavorite(item);
                }}
              />
            ))}
          </Group>
        ) : null}
        {others.length > 0 ? (
          <Group header={favorites.length > 0 ? "모든 항목" : undefined}>
            {others.map((item) => (
              <SwipeRow
                key={item.id}
                item={item}
                open={swipeOpen === item.id}
                onOpenChange={(o) => setSwipeOpen(o ? item.id : null)}
                onSelect={() => openItem(item.id)}
                onCopyPassword={() => {
                  setSwipeOpen(null);
                  void copy(item.password ?? "", "비밀번호");
                }}
                onFavorite={() => {
                  setSwipeOpen(null);
                  void toggleFavorite(item);
                }}
              />
            ))}
          </Group>
        ) : null}
        {filtered.length > 0 ? <p className="ios-count">항목 {filtered.length}개 · 왼쪽으로 밀면 빠른 동작</p> : null}
      </>
    );
  }

  return (
    <div className={`ios-root${inEdit ? " no-tabbar" : ""}`}>
      <main
        className="ios-page"
        ref={scrollRef}
        onScroll={(e) => {
          const top = e.currentTarget.scrollTop;
          const next = top > 8;
          if (next !== scrolled) setScrolled(next);
        }}
      >
        {page}
      </main>
      {inEdit ? null : (
        <nav className="ios-tabbar" aria-label="탭">
          <TabButton active={tab === "items"} label="항목" onClick={() => {
            if (tab === "items") setRoute({ kind: "list" });
            setTab("items");
          }}>
            <IconKey />
          </TabButton>
          <TabButton active={tab === "generator"} label="생성기" onClick={() => setTab("generator")}>
            <IconDice />
          </TabButton>
          <TabButton active={tab === "settings"} label="설정" onClick={() => setTab("settings")}>
            <IconGear />
          </TabButton>
        </nav>
      )}
      {kit ? <EmergencyKit kit={kit} viewOnly={kitViewOnly} onDone={() => setKit(null)} /> : null}
    </div>
  );
}

function TabButton({ active, label, onClick, children }: { active: boolean; label: string; onClick: () => void; children: ReactNode }) {
  return (
    <button type="button" className={`ios-tab${active ? " active" : ""}`} aria-current={active ? "page" : undefined} onClick={onClick}>
      {children}
      <span>{label}</span>
    </button>
  );
}

function syncBanner(status: SyncStatus): string | null {
  if (status.state === "waiting_icloud") return "iCloud에서 금고 파일을 내려받는 중입니다. 설정을 여세요.";
  if (status.state === "password_required") return "다른 비밀번호가 필요한 금고 파일이 있습니다. 설정에서 합치세요.";
  if (status.state === "error") return "동기화 중 오류가 있습니다. 설정을 여세요.";
  if (status.conflictCount > 0) return `동기화 충돌 ${status.conflictCount}건이 있습니다. 설정에서 고르세요.`;
  return null;
}

/* ---------- detail ---------- */

function FieldRow({
  label,
  value,
  display,
  mono,
  multiline,
  onCopy,
  accessory,
}: {
  label: string;
  value?: string;
  display?: string;
  mono?: boolean;
  multiline?: boolean;
  onCopy?: () => void;
  accessory?: ReactNode;
}) {
  if (!value) return null;
  return (
    <div
      className="ios-row ios-field"
      role="button"
      tabIndex={0}
      onClick={onCopy}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") onCopy?.();
      }}
    >
      <span className="ios-field-text">
        <span className="ios-field-label">{label}</span>
        <span className={`ios-field-value${mono ? " mono" : ""}${multiline ? " multiline" : ""}`}>{display ?? value}</span>
      </span>
      {accessory ? (
        <span className="ios-field-accessory" onClick={(e) => e.stopPropagation()}>
          {accessory}
        </span>
      ) : null}
    </div>
  );
}

function DetailPage({
  item,
  scrolled,
  onBack,
  onEdit,
  onFavorite,
  onCopy,
  onToast,
}: {
  item: VaultItem;
  scrolled: boolean;
  onBack: () => void;
  onEdit: () => void;
  onFavorite: () => void;
  onCopy: (text: string, label: string) => void;
  onToast: (toast: Omit<Toast, "id">) => void;
}) {
  const [shown, setShown] = useState<Record<string, boolean>>({});
  const mask = (key: string, value?: string) => (shown[key] ? value : "••••••••••");
  const eye = (key: string, label: string) => (
    <button
      type="button"
      className="ios-accessory-btn"
      aria-label={shown[key] ? `${label} 숨기기` : `${label} 보기`}
      onClick={() => setShown((s) => ({ ...s, [key]: !s[key] }))}
    >
      <IconEye off={shown[key]} />
    </button>
  );

  return (
    <>
      <NavBar
        left={
          <button type="button" className="ios-nav-back" onClick={onBack}>
            <IconChevronLeft />
            <span>뒤로</span>
          </button>
        }
        title={item.title}
        showTitle={scrolled}
        right={
          <>
            <button
              type="button"
              className={`ios-nav-icon star${item.favorite ? " on" : ""}`}
              aria-label={item.favorite ? "즐겨찾기 해제" : "즐겨찾기"}
              onClick={onFavorite}
            >
              <IconStar filled={item.favorite} />
            </button>
            <button type="button" className="ios-nav-text" onClick={onEdit}>
              편집
            </button>
          </>
        }
      />
      <div className="ios-detail-head">
        <Avatar item={item} size={64} />
        <h1>{item.title}</h1>
        <p>{typeLabel(item.itemType)}</p>
      </div>

      {item.itemType === "login" ? (
        <Group>
          <FieldRow label="사용자 이름" value={item.username} onCopy={() => onCopy(item.username ?? "", "사용자 이름")} />
          <FieldRow
            label="비밀번호"
            value={item.password}
            display={mask("pw", item.password)}
            mono
            onCopy={() => onCopy(item.password ?? "", "비밀번호")}
            accessory={eye("pw", "비밀번호")}
          />
          <FieldRow
            label="웹사이트"
            value={item.url}
            onCopy={() => onCopy(item.url ?? "", "주소")}
            accessory={
              <button
                type="button"
                className="ios-accessory-btn"
                aria-label="웹사이트 열기"
                onClick={() =>
                  void openExternalUrl(item.url ?? "").catch((e) => onToast({ kind: "err", message: errText(e) }))
                }
              >
                <IconOpen />
              </button>
            }
          />
        </Group>
      ) : null}

      {item.itemType === "card" ? (
        <Group>
          <FieldRow label="카드 소유자" value={item.cardholder} onCopy={() => onCopy(item.cardholder ?? "", "카드 소유자")} />
          <FieldRow
            label="카드 번호"
            value={item.number}
            display={mask("num", item.number)}
            mono
            onCopy={() => onCopy(item.number ?? "", "카드 번호")}
            accessory={eye("num", "카드 번호")}
          />
          <FieldRow label="유효기간" value={item.expiry} onCopy={() => onCopy(item.expiry ?? "", "유효기간")} />
          <FieldRow
            label="CVV"
            value={item.cvv}
            display={mask("cvv", item.cvv)}
            mono
            onCopy={() => onCopy(item.cvv ?? "", "CVV")}
            accessory={eye("cvv", "CVV")}
          />
        </Group>
      ) : null}

      {item.notes ? (
        <Group header="메모">
          <FieldRow label="" value={item.notes} multiline onCopy={() => onCopy(item.notes ?? "", "메모")} />
        </Group>
      ) : null}

      {item.tags && item.tags.length > 0 ? (
        <Group header="태그">
          <div className="ios-tags">
            {item.tags.map((tag) => (
              <span key={tag} className="ios-tag">
                {tag}
              </span>
            ))}
          </div>
        </Group>
      ) : null}

      <p className="ios-meta">
        값을 누르면 복사됩니다 (30초 뒤 클립보드에서 지움)
        <br />
        수정 {new Date(item.updatedAt).toLocaleString("ko-KR")}
      </p>
    </>
  );
}

/* ---------- edit ---------- */

function InputRow({
  label,
  value,
  onChange,
  placeholder,
  type = "text",
  mono,
  trailing,
  inputMode,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  type?: string;
  mono?: boolean;
  trailing?: ReactNode;
  inputMode?: "text" | "email" | "url" | "numeric";
}) {
  return (
    <label className="ios-row ios-input-row">
      <span className="ios-input-label">{label}</span>
      <input
        className={mono ? "mono" : undefined}
        type={type}
        value={value}
        placeholder={placeholder ?? label}
        inputMode={inputMode}
        autoCapitalize="none"
        autoCorrect="off"
        spellCheck={false}
        onChange={(e) => onChange(e.target.value)}
      />
      {trailing}
    </label>
  );
}

const DEFAULT_GEN: GenerateOpts = { length: 20, upper: true, lower: true, digits: true, symbols: true };

function EditPage({
  item,
  onCancel,
  onSaved,
  onDeleted,
  onReload,
  onToast,
}: {
  item: VaultItem | null;
  onCancel: () => void;
  onSaved: (id: string) => void;
  onDeleted: () => void;
  onReload: () => Promise<void>;
  onToast: (toast: Omit<Toast, "id">) => void;
}) {
  const [draft, setDraft] = useState<ItemDraft>(item ? itemToDraft(item) : emptyDraft("login"));
  const [tagText, setTagText] = useState((item?.tags ?? []).join(", "));
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [busy, setBusy] = useState(false);
  const isNew = !item;

  function set<K extends keyof ItemDraft>(key: K, value: ItemDraft[K]) {
    setDraft((d) => ({ ...d, [key]: value }));
  }

  async function save(e?: FormEvent) {
    e?.preventDefault();
    if (!draft.title.trim()) {
      onToast({ kind: "err", message: "제목을 입력하세요." });
      return;
    }
    setBusy(true);
    try {
      if (isNew) {
        const created = await addItem(draft);
        await onReload();
        onSaved(created.id);
      } else if (item) {
        await updateItem({ ...item, ...draft });
        await onReload();
        onSaved(item.id);
      }
      onToast({ kind: "ok", message: "저장됨" });
    } catch (err) {
      onToast({ kind: "err", message: errText(err) });
      await onReload().catch(() => undefined);
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    if (!item) return;
    setBusy(true);
    try {
      await deleteItem(item.id);
      setConfirmDelete(false);
      await onReload();
      onDeleted();
      onToast({ kind: "ok", message: "항목을 삭제했습니다." });
    } catch (err) {
      onToast({ kind: "err", message: errText(err) });
    } finally {
      setBusy(false);
    }
  }

  async function fillPassword() {
    try {
      set("password", await generatePassword(DEFAULT_GEN));
    } catch (err) {
      onToast({ kind: "err", message: errText(err) });
    }
  }

  return (
    <form onSubmit={save} className="ios-edit">
      <NavBar
        left={
          <button type="button" className="ios-nav-text" onClick={onCancel}>
            취소
          </button>
        }
        title={isNew ? "새 항목" : "항목 편집"}
        right={
          <button type="submit" className="ios-nav-text bold" disabled={busy}>
            {isNew ? "추가" : "완료"}
          </button>
        }
      />
      <div className="ios-edit-spacer" />
      {isNew ? (
        <div className="ios-filter">
          <Segmented<ItemType>
            value={draft.itemType}
            options={[
              { id: "login", label: "로그인" },
              { id: "card", label: "카드" },
              { id: "note", label: "보안 메모" },
            ]}
            onChange={(v) => set("itemType", v)}
          />
        </div>
      ) : null}
      <Group>
        <InputRow label="제목" value={draft.title} onChange={(v) => set("title", v)} placeholder="필수" />
        <div className="ios-row ios-input-row">
          <span className="ios-input-label grow">즐겨찾기</span>
          <Switch checked={draft.favorite} label="즐겨찾기" onChange={(v) => set("favorite", v)} />
        </div>
      </Group>

      {draft.itemType === "login" ? (
        <Group header="로그인">
          <InputRow label="사용자 이름" value={draft.username ?? ""} onChange={(v) => set("username", v)} inputMode="email" />
          <InputRow
            label="비밀번호"
            value={draft.password ?? ""}
            onChange={(v) => set("password", v)}
            mono
            trailing={
              <button type="button" className="ios-inline-btn" onClick={() => void fillPassword()}>
                생성
              </button>
            }
          />
          <InputRow label="웹사이트" value={draft.url ?? ""} onChange={(v) => set("url", v)} inputMode="url" placeholder="example.com" />
        </Group>
      ) : null}

      {draft.itemType === "card" ? (
        <Group header="카드">
          <InputRow label="소유자" value={draft.cardholder ?? ""} onChange={(v) => set("cardholder", v)} />
          <InputRow label="카드 번호" value={draft.number ?? ""} onChange={(v) => set("number", v)} inputMode="numeric" mono />
          <InputRow label="유효기간" value={draft.expiry ?? ""} onChange={(v) => set("expiry", v)} placeholder="MM/YY" />
          <InputRow label="CVV" value={draft.cvv ?? ""} onChange={(v) => set("cvv", v)} inputMode="numeric" mono />
        </Group>
      ) : null}

      <Group header="태그" footer="쉼표로 구분합니다.">
        <InputRow
          label="태그"
          value={tagText}
          onChange={(text) => {
            setTagText(text);
            set(
              "tags",
              text
                .split(",")
                .map((p) => p.trim())
                .filter(Boolean),
            );
          }}
          placeholder="예: 업무, 금융"
        />
      </Group>

      <Group header="메모">
        <label className="ios-row ios-textarea-row">
          <textarea value={draft.notes ?? ""} onChange={(e) => set("notes", e.target.value)} placeholder="메모" rows={4} />
        </label>
      </Group>

      {!isNew ? (
        <Group>
          <button type="button" className="ios-row ios-destructive" onClick={() => setConfirmDelete(true)}>
            항목 삭제
          </button>
        </Group>
      ) : null}

      {confirmDelete ? (
        <div className="ios-sheet-backdrop" onClick={() => setConfirmDelete(false)}>
          <div className="ios-sheet" role="dialog" aria-modal="true" onClick={(e) => e.stopPropagation()}>
            <div className="ios-sheet-group">
              <p className="ios-sheet-msg">“{item?.title}” 항목을 삭제할까요? 되돌릴 수 없습니다.</p>
              <button type="button" className="ios-sheet-btn danger" disabled={busy} onClick={() => void remove()}>
                항목 삭제
              </button>
            </div>
            <div className="ios-sheet-group">
              <button type="button" className="ios-sheet-btn bold" onClick={() => setConfirmDelete(false)}>
                취소
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </form>
  );
}

/* ---------- generator ---------- */

function GeneratorPage({ scrolled, onCopy }: { scrolled: boolean; onCopy: (pw: string) => void }) {
  const [opts, setOpts] = useState<GenerateOpts>(DEFAULT_GEN);
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setError("");
    void generatePassword(opts)
      .then((pw) => {
        if (!cancelled) setPassword(pw);
      })
      .catch((e) => {
        if (!cancelled) setError(errText(e));
      });
    return () => {
      cancelled = true;
    };
  }, [opts, nonce]);

  const toggles: { key: "upper" | "lower" | "digits" | "symbols"; label: string }[] = [
    { key: "upper", label: "대문자 (A-Z)" },
    { key: "lower", label: "소문자 (a-z)" },
    { key: "digits", label: "숫자 (0-9)" },
    { key: "symbols", label: "기호 (!@#)" },
  ];

  return (
    <>
      <NavBar title="생성기" showTitle={scrolled} />
      <h1 className="ios-large-title">생성기</h1>
      <Group>
        <div className="ios-gen-preview mono" aria-live="polite">
          {password || "…"}
        </div>
        <div className="ios-gen-actions">
          <button type="button" className="ios-gen-btn" onClick={() => setNonce((n) => n + 1)}>
            다시 만들기
          </button>
          <button type="button" className="ios-gen-btn primary" disabled={!password} onClick={() => onCopy(password)}>
            복사
          </button>
        </div>
      </Group>
      {error ? <p className="ios-error">{error}</p> : null}
      <Group header="옵션">
        <div className="ios-row ios-slider-row">
          <span className="ios-input-label">길이</span>
          <input
            type="range"
            min={8}
            max={64}
            value={opts.length}
            aria-label="길이"
            onChange={(e) => setOpts({ ...opts, length: Number(e.target.value) })}
          />
          <span className="ios-slider-value">{opts.length}</span>
        </div>
        {toggles.map((t) => (
          <div className="ios-row ios-input-row" key={t.key}>
            <span className="ios-input-label grow">{t.label}</span>
            <Switch checked={opts[t.key]} label={t.label} onChange={(v) => setOpts({ ...opts, [t.key]: v })} />
          </div>
        ))}
      </Group>
    </>
  );
}

/* ---------- settings ---------- */

function SettingsPage({
  theme,
  settings,
  syncStatus,
  scrolled,
  onLock,
  onToggleTheme,
  onSettingsChange,
  onSyncStatus,
  onRequireUnlock,
  onToast,
  onReload,
  onKit,
}: Props & { scrolled: boolean; onKit: (kit: EmergencyKitData, viewOnly: boolean) => void }) {
  const [version, setVersion] = useState("");
  useEffect(() => {
    let cancelled = false;
    void appBuild()
      .then((b) => {
        if (!cancelled) setVersion(`${b.version} (${b.commit})`);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <>
      <NavBar title="설정" showTitle={scrolled} />
      <h1 className="ios-large-title">설정</h1>
      <Group header="화면">
        <div className="ios-row ios-input-row">
          <span className="ios-input-label grow">테마</span>
          <Segmented<"dark" | "light">
            value={theme}
            options={[
              { id: "light", label: "밝게" },
              { id: "dark", label: "어둡게" },
            ]}
            onChange={(v) => {
              if (v !== theme) onToggleTheme();
            }}
          />
        </div>
      </Group>
      <Group footer={`자동 잠금: ${settings.autoLockMinutes}분 동안 조작이 없으면 잠급니다. 아래에서 바꿀 수 있습니다.`}>
        <button type="button" className="ios-row ios-action-row" onClick={() => void onLock()}>
          지금 잠그기
        </button>
      </Group>
      <div className="ios-settings-panel">
        <SettingsPanel
          settings={settings}
          syncStatus={syncStatus}
          onSettingsChange={onSettingsChange}
          onSyncStatus={onSyncStatus}
          onRequireUnlock={onRequireUnlock}
          onToast={onToast}
          onReload={onReload}
          onKit={onKit}
        />
      </div>
      <Group header="정보">
        <div className="ios-row ios-input-row">
          <span className="ios-input-label grow">버전</span>
          <span className="ios-value-muted">{version || "…"}</span>
        </div>
      </Group>
    </>
  );
}
