import { DragEvent, FormEvent, useEffect, useMemo, useRef, useState } from "react";
import {
  addItem,
  biometricDisable,
  biometricEnable,
  biometricStatus,
  changeMasterPassword,
  copyToClipboard,
  deleteItem,
  disableSecretKey,
  enableSecretKey,
  exportVault,
  generatePassword,
  getVaultSettings,
  importVault,
  mapError,
  moveItem,
  pickOpenPath,
  pickSavePath,
  revealSecretKey,
  secretKeyStatus,
  updateItem,
  updateVaultSettings,
} from "../api";
import type {
  BiometricStatus,
  FilterId,
  GenerateOpts,
  ImportMode,
  ItemDraft,
  ItemType,
  EmergencyKit as EmergencyKitData,
  SettingsPatch,
  SyncStatus,
  Toast,
  VaultItem,
  VaultSettings,
} from "../types";
import BuildStamp from "./BuildStamp";
import EmergencyKit from "./EmergencyKit";
import Logo from "./Logo";
import McpSettings from "./McpSettings";
import SyncSettings from "./SyncSettings";

const FILTERS: { id: FilterId; label: string }[] = [
  { id: "all", label: "전체" },
  { id: "login", label: "로그인" },
  { id: "note", label: "메모" },
  { id: "card", label: "카드" },
  { id: "favorites", label: "즐겨찾기" },
];

function typeLabel(t: ItemType): string {
  if (t === "login") return "로그인";
  if (t === "note") return "보안 메모";
  return "카드";
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

function compareItems(a: VaultItem, b: VaultItem): number {
  const order = (a.order ?? "").localeCompare(b.order ?? "");
  if (order !== 0) return order;
  return a.id.localeCompare(b.id);
}

function subtitle(item: VaultItem): string {
  if (item.itemType === "login") return item.username || item.url || "로그인";
  if (item.itemType === "card") return item.cardholder || item.number || "카드";
  return item.notes?.split("\n")[0] || "메모";
}

function syncBanner(status: SyncStatus): string | null {
  if (status.state === "waiting_icloud") return "iCloud에서 금고 파일을 내려받는 중입니다. 설정을 여세요.";
  if (status.state === "password_required") return "다른 비밀번호가 필요한 금고 파일이 있습니다. 설정에서 합치세요.";
  if (status.state === "error") return "동기화 중 오류가 있습니다. 설정을 여세요.";
  if (status.conflictCount > 0) return `동기화 충돌 ${status.conflictCount}건이 있습니다. 설정에서 고르세요.`;
  return null;
}

export default function MainScreen({
  items,
  theme,
  settings,
  syncStatus,
  onReload,
  onLock,
  onToggleTheme,
  onSettingsChange,
  onSyncStatus,
  onRequireUnlock,
  onToast,
}: {
  items: VaultItem[];
  theme: "dark" | "light";
  settings: VaultSettings;
  syncStatus: SyncStatus | null;
  onReload: () => Promise<void>;
  onLock: () => Promise<void>;
  onToggleTheme: () => void;
  onSettingsChange: (settings: VaultSettings) => void;
  onSyncStatus: (status: SyncStatus) => void;
  onRequireUnlock: () => void;
  onToast: (toast: Omit<Toast, "id">) => void;
}) {
  const [filter, setFilter] = useState<FilterId>("all");
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(items[0]?.id ?? null);
  const [editing, setEditing] = useState<"new" | "edit" | "settings" | null>(null);
  const [draft, setDraft] = useState<ItemDraft>(emptyDraft("login"));
  const [showSecrets, setShowSecrets] = useState<Record<string, boolean>>({});
  const [confirmId, setConfirmId] = useState<string | null>(null);
  const [genOpen, setGenOpen] = useState(false);
  const [genForField, setGenForField] = useState(false);
  const [dragId, setDragId] = useState<string | null>(null);
  const [overId, setOverId] = useState<string | "end" | null>(null);
  const [kit, setKit] = useState<EmergencyKitData | null>(null);
  const [kitViewOnly, setKitViewOnly] = useState(false);
  const moving = useRef(false);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return items.filter((item) => {
      if (filter === "favorites" && !item.favorite) return false;
      if (filter === "login" || filter === "note" || filter === "card") {
        if (item.itemType !== filter) return false;
      }
      if (!q) return true;
      const blob = [
        item.title,
        item.username,
        item.url,
        item.notes,
        item.cardholder,
        item.number,
        ...(item.tags ?? []),
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return blob.includes(q);
    }).sort(compareItems);
  }, [items, filter, query]);

  useEffect(() => {
    if (selectedId && !filtered.some((i) => i.id === selectedId)) {
      setSelectedId(filtered[0]?.id ?? null);
    }
  }, [filtered, selectedId]);

  const selected = items.find((i) => i.id === selectedId) ?? null;

  async function handleCopy(text: string, label: string) {
    try {
      await copyToClipboard(text, 30);
      onToast({
        kind: "ok",
        message: `${label}을(를) 복사했습니다. 30초 후 클립보드에서 지웁니다.`,
      });
    } catch (e) {
      onToast({ kind: "err", message: e instanceof Error ? e.message : String(e) });
    }
  }

  function startNew() {
    setDraft(emptyDraft("login"));
    setEditing("new");
  }

  function startEdit(item: VaultItem) {
    setDraft(itemToDraft(item));
    setEditing("edit");
  }

  async function saveDraft(e: FormEvent) {
    e.preventDefault();
    if (!draft.title.trim()) {
      onToast({ kind: "err", message: "제목을 입력하세요." });
      return;
    }
    try {
      if (editing === "new") {
        const created = await addItem(draft);
        await onReload();
        setSelectedId(created.id);
      } else if (editing === "edit" && selected) {
        await updateItem({ ...selected, ...draft });
        await onReload();
      }
      setEditing(null);
      onToast({ kind: "ok", message: "저장했습니다." });
    } catch (err) {
      onToast({ kind: "err", message: mapError(err instanceof Error ? err.message : String(err)) });
      await onReload().catch(() => undefined);
    }
  }

  async function confirmDelete() {
    if (!confirmId) return;
    try {
      await deleteItem(confirmId);
      setConfirmId(null);
      setEditing(null);
      await onReload();
      onToast({ kind: "ok", message: "항목을 삭제했습니다." });
    } catch (err) {
      onToast({ kind: "err", message: err instanceof Error ? err.message : String(err) });
    }
  }

  async function placeItem(id: string, beforeId: string | null) {
    if (moving.current) return;
    if (beforeId === id) return;
    moving.current = true;
    try {
      await moveItem(id, beforeId);
      await onReload();
    } catch (err) {
      onToast({ kind: "err", message: err instanceof Error ? err.message : String(err) });
    } finally {
      moving.current = false;
      setDragId(null);
      setOverId(null);
    }
  }

  function moveUp(index: number) {
    if (index <= 0) return;
    void placeItem(filtered[index].id, filtered[index - 1].id);
  }

  function moveDown(index: number) {
    if (index >= filtered.length - 1) return;
    const afterNext = filtered[index + 2];
    void placeItem(filtered[index].id, afterNext ? afterNext.id : null);
  }

  function onDragStart(id: string, event: DragEvent<HTMLButtonElement>) {
    event.dataTransfer.setData("text/plain", id);
    event.dataTransfer.effectAllowed = "move";
    setDragId(id);
  }

  function onDragOverRow(id: string, event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    event.dataTransfer.dropEffect = "move";
    setOverId(id);
  }

  function onDropRow(beforeId: string | null, event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    const id = event.dataTransfer.getData("text/plain") || dragId;
    setDragId(null);
    setOverId(null);
    if (!id) return;
    void placeItem(id, beforeId);
  }

  async function toggleFavorite(item: VaultItem) {
    try {
      await updateItem({ ...item, favorite: !item.favorite });
      await onReload();
    } catch (err) {
      onToast({ kind: "err", message: err instanceof Error ? err.message : String(err) });
    }
  }

  function secretValue(value: string | undefined, key: string): string {
    if (!value) return "—";
    return showSecrets[key] ? value : "••••••••";
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand-mini">
          <Logo />
          <span>SecureVault</span>
        </div>
        <div className="search">
          <svg className="glyph" viewBox="0 0 24 24" aria-hidden="true">
            <circle cx="11" cy="11" r="7" fill="none" stroke="currentColor" strokeWidth="2" />
            <path d="M20 20l-3.5-3.5" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
          </svg>
          <input
            placeholder="제목, 사용자, 주소, 메모 검색"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
        <div className="top-actions">
          <button className="btn btn-ghost btn-small" onClick={startNew}>
            항목 추가
          </button>
          <button className="btn btn-ghost btn-small" onClick={() => setGenOpen(true)}>
            생성기
          </button>
          <button className="btn btn-ghost btn-small" onClick={onToggleTheme}>
            {theme === "dark" ? "밝은 테마" : "어두운 테마"}
          </button>
          <button className="btn btn-ghost btn-small" onClick={() => setEditing("settings")}>
            설정
          </button>
          <button className="btn btn-small" onClick={() => void onLock()}>
            잠금
          </button>
        </div>
      </header>

      {syncStatus && syncBanner(syncStatus) ? (
        <button className="sync-banner" type="button" onClick={() => setEditing("settings")}>
          {syncBanner(syncStatus)}
        </button>
      ) : null}

      <div className={`workspace${selectedId && !editing ? " has-selection" : ""}${editing ? " editing" : ""}`}>
        <nav className="sidebar">
          {FILTERS.map((f) => (
            <button
              key={f.id}
              className={`nav-btn ${filter === f.id ? "active" : ""}`}
              onClick={() => setFilter(f.id)}
            >
              <span className="label">{f.label}</span>
            </button>
          ))}
          <div className="spacer" />
          <button className="btn btn-primary" onClick={startNew}>
            + 새 항목
          </button>
        </nav>

        <section className="item-list">
          {filtered.length === 0 ? (
            <div className="empty">
              <p>표시할 항목이 없습니다.</p>
            </div>
          ) : (
            filtered.map((item, index) => (
              <div
                key={item.id}
                className={`item-row ${item.id === selectedId ? "active" : ""} ${dragId === item.id ? "dragging" : ""} ${overId === item.id ? "drag-over" : ""}`}
                onDragOver={(event) => onDragOverRow(item.id, event)}
                onDrop={(event) => onDropRow(item.id, event)}
              >
                <button
                  type="button"
                  className="drag-handle"
                  draggable
                  aria-label="순서 바꾸기"
                  onDragStart={(event) => onDragStart(item.id, event)}
                  onDragEnd={() => {
                    setDragId(null);
                    setOverId(null);
                  }}
                >
                  ⋮⋮
                </button>
                <button
                  type="button"
                  className="item-main"
                  onClick={() => {
                    setSelectedId(item.id);
                    if (editing === "edit" || editing === "settings") setEditing(null);
                  }}
                >
                  <div className="title">
                    <span>{item.title}</span>
                    {item.favorite ? <span className="star">★</span> : null}
                  </div>
                  <div className="meta">
                    {typeLabel(item.itemType)} · {subtitle(item)}
                    {item.tags && item.tags.length > 0 ? ` · ${item.tags.join(", ")}` : ""}
                  </div>
                </button>
                <div className="reorder-actions">
                  <button
                    type="button"
                    className="reorder-btn"
                    aria-label="위로"
                    disabled={index === 0}
                    onClick={() => moveUp(index)}
                  >
                    ↑
                  </button>
                  <button
                    type="button"
                    className="reorder-btn"
                    aria-label="아래로"
                    disabled={index === filtered.length - 1}
                    onClick={() => moveDown(index)}
                  >
                    ↓
                  </button>
                </div>
              </div>
            ))
          )}
          {dragId ? (
            <div
              className={`drop-end${overId === "end" ? " active" : ""}`}
              onDragOver={(event) => {
                event.preventDefault();
                event.dataTransfer.dropEffect = "move";
                setOverId("end");
              }}
              onDrop={(event) => onDropRow(null, event)}
            >
              맨 아래로
            </div>
          ) : null}
        </section>

        <section className="detail">
          <button
            type="button"
            className="btn btn-ghost btn-small back-to-list"
            onClick={() => {
              setSelectedId(null);
              setEditing(null);
            }}
          >
            목록
          </button>
          {editing === "settings" ? (
            <SettingsPanel
              settings={settings}
              syncStatus={syncStatus}
              onSettingsChange={onSettingsChange}
              onSyncStatus={onSyncStatus}
              onRequireUnlock={onRequireUnlock}
              onToast={onToast}
              onReload={onReload}
              onKit={(next, viewOnly) => {
                setKitViewOnly(viewOnly);
                setKit(next);
              }}
            />
          ) : editing === "new" || editing === "edit" ? (
            <ItemEditor
              key={editing === "new" ? "new" : selected?.id ?? "edit"}
              draft={draft}
              isNew={editing === "new"}
              onChange={setDraft}
              onSubmit={saveDraft}
              onCancel={() => setEditing(null)}
              onOpenGenerator={() => {
                setGenForField(true);
                setGenOpen(true);
              }}
            />
          ) : selected ? (
            <ItemDetail
              item={selected}
              secretValue={secretValue}
              onCopy={handleCopy}
              onToggleSecret={(key) =>
                setShowSecrets((s) => ({ ...s, [key]: !s[key] }))
              }
              onEdit={() => startEdit(selected)}
              onDelete={() => setConfirmId(selected.id)}
              onFavorite={() => void toggleFavorite(selected)}
            />
          ) : (
            <div className="empty">
              <p>왼쪽에서 항목을 고르거나 새 항목을 추가하세요.</p>
            </div>
          )}
        </section>
      </div>

      {genOpen ? (
        <GeneratorDialog
          onClose={() => {
            setGenOpen(false);
            setGenForField(false);
          }}
          onUse={(pw) => {
            if (genForField) {
              setDraft((d) => ({ ...d, password: pw }));
            }
            setGenOpen(false);
            setGenForField(false);
          }}
          onCopy={(pw) => void handleCopy(pw, "비밀번호")}
        />
      ) : null}

      {confirmId ? (
        <div className="modal-backdrop" onClick={() => setConfirmId(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h2>항목 삭제</h2>
            <p className="lede">이 항목을 삭제할까요? 이 작업은 되돌릴 수 없습니다.</p>
            <div className="actions">
              <button className="btn btn-danger" onClick={() => void confirmDelete()}>
                삭제
              </button>
              <button className="btn btn-ghost" onClick={() => setConfirmId(null)}>
                취소
              </button>
            </div>
          </div>
        </div>
      ) : null}
      {kit ? (
        <EmergencyKit kit={kit} viewOnly={kitViewOnly} onDone={() => setKit(null)} />
      ) : null}
      <footer className="app-footer">
        <BuildStamp />
      </footer>
    </div>
  );
}

function ItemDetail({
  item,
  secretValue,
  onCopy,
  onToggleSecret,
  onEdit,
  onDelete,
  onFavorite,
}: {
  item: VaultItem;
  secretValue: (value: string | undefined, key: string) => string;
  onCopy: (text: string, label: string) => void;
  onToggleSecret: (key: string) => void;
  onEdit: () => void;
  onDelete: () => void;
  onFavorite: () => void;
}) {
  return (
    <div>
      <div className="badge">{typeLabel(item.itemType)}</div>
      <div className="detail-head">
        <div>
          <h2>{item.title}</h2>
          <p className="lede" style={{ marginBottom: 0 }}>
            {item.favorite ? "즐겨찾기 등록됨 · " : ""}
            수정 {new Date(item.updatedAt).toLocaleString("ko-KR")}
          </p>
          {item.tags && item.tags.length > 0 ? (
            <div className="tag-row">
              {item.tags.map((tag) => (
                <span className="tag" key={tag}>
                  {tag}
                </span>
              ))}
            </div>
          ) : null}
        </div>
        <div className="actions">
          <button className="btn btn-ghost btn-small" onClick={onFavorite}>
            {item.favorite ? "즐겨찾기 해제" : "즐겨찾기"}
          </button>
          <button className="btn btn-small" onClick={onEdit}>
            편집
          </button>
          <button className="btn btn-danger btn-small" onClick={onDelete}>
            삭제
          </button>
        </div>
      </div>

      {item.itemType === "login" ? (
        <>
          <SecretRow
            label="사용자 이름"
            value={item.username}
            copyLabel="사용자 이름"
            onCopy={onCopy}
          />
          <SecretRow
            label="비밀번호"
            value={secretValue(item.password, `${item.id}-pw`)}
            raw={item.password}
            copyLabel="비밀번호"
            onCopy={onCopy}
            onToggle={() => onToggleSecret(`${item.id}-pw`)}
          />
          <SecretRow label="주소" value={item.url} copyLabel="주소" onCopy={onCopy} />
        </>
      ) : null}

      {item.itemType === "card" ? (
        <>
          <SecretRow
            label="카드 소유자"
            value={item.cardholder}
            copyLabel="카드 소유자"
            onCopy={onCopy}
          />
          <SecretRow
            label="카드 번호"
            value={secretValue(item.number, `${item.id}-num`)}
            raw={item.number}
            copyLabel="카드 번호"
            onCopy={onCopy}
            onToggle={() => onToggleSecret(`${item.id}-num`)}
          />
          <SecretRow label="유효기간" value={item.expiry} copyLabel="유효기간" onCopy={onCopy} />
          <SecretRow
            label="CVV"
            value={secretValue(item.cvv, `${item.id}-cvv`)}
            raw={item.cvv}
            copyLabel="CVV"
            onCopy={onCopy}
            onToggle={() => onToggleSecret(`${item.id}-cvv`)}
          />
        </>
      ) : null}

      {item.notes ? (
        <div style={{ marginTop: 18 }}>
          <div className="lbl">메모</div>
          <p className="notes">{item.notes}</p>
        </div>
      ) : null}
    </div>
  );
}

function SecretRow({
  label,
  value,
  raw,
  copyLabel,
  onCopy,
  onToggle,
}: {
  label: string;
  value?: string;
  raw?: string;
  copyLabel: string;
  onCopy: (text: string, label: string) => void;
  onToggle?: () => void;
}) {
  const shown = value || "—";
  const copyText = raw ?? value;
  return (
    <div className="kv">
      <div className="k">{label}</div>
      <div className={`v ${onToggle && raw && shown.includes("•") ? "secret" : ""}`}>{shown}</div>
      <div className="actions">
        {onToggle && raw ? (
          <button className="btn btn-ghost btn-small" onClick={onToggle}>
            {shown.includes("•") ? "표시" : "숨기기"}
          </button>
        ) : null}
        {copyText ? (
          <button className="btn btn-ghost btn-small" onClick={() => onCopy(copyText, copyLabel)}>
            복사
          </button>
        ) : null}
      </div>
    </div>
  );
}

function ItemEditor({
  draft,
  isNew,
  onChange,
  onSubmit,
  onCancel,
  onOpenGenerator,
}: {
  draft: ItemDraft;
  isNew: boolean;
  onChange: (draft: ItemDraft) => void;
  onSubmit: (e: FormEvent) => void;
  onCancel: () => void;
  onOpenGenerator: () => void;
}) {
  const [tagText, setTagText] = useState((draft.tags ?? []).join(", "));

  function set<K extends keyof ItemDraft>(key: K, value: ItemDraft[K]) {
    onChange({ ...draft, [key]: value });
  }

  return (
    <form onSubmit={onSubmit}>
      <h2>{isNew ? "새 항목" : "항목 편집"}</h2>
      <label className="field" style={{ marginTop: 16 }}>
        <span>종류</span>
        <select
          value={draft.itemType}
          onChange={(e) => set("itemType", e.target.value as ItemType)}
        >
          <option value="login">로그인</option>
          <option value="note">보안 메모</option>
          <option value="card">카드</option>
        </select>
      </label>
      <label className="field">
        <span>제목</span>
        <input value={draft.title} onChange={(e) => set("title", e.target.value)} />
      </label>
      <label className="row" style={{ marginBottom: 14 }}>
        <input
          type="checkbox"
          checked={draft.favorite}
          onChange={(e) => set("favorite", e.target.checked)}
        />
        즐겨찾기
      </label>

      {draft.itemType === "login" ? (
        <>
          <label className="field">
            <span>사용자 이름</span>
            <input value={draft.username ?? ""} onChange={(e) => set("username", e.target.value)} />
          </label>
          <label className="field">
            <span>비밀번호</span>
            <div className="row">
              <input
                style={{ flex: 1 }}
                value={draft.password ?? ""}
                onChange={(e) => set("password", e.target.value)}
              />
              <button type="button" className="btn btn-ghost" onClick={onOpenGenerator}>
                생성
              </button>
            </div>
          </label>
          <label className="field">
            <span>주소</span>
            <input value={draft.url ?? ""} onChange={(e) => set("url", e.target.value)} />
          </label>
        </>
      ) : null}

      {draft.itemType === "card" ? (
        <>
          <label className="field">
            <span>카드 소유자</span>
            <input
              value={draft.cardholder ?? ""}
              onChange={(e) => set("cardholder", e.target.value)}
            />
          </label>
          <label className="field">
            <span>카드 번호</span>
            <input value={draft.number ?? ""} onChange={(e) => set("number", e.target.value)} />
          </label>
          <div className="row">
            <label className="field" style={{ flex: 1 }}>
              <span>유효기간</span>
              <input value={draft.expiry ?? ""} onChange={(e) => set("expiry", e.target.value)} />
            </label>
            <label className="field" style={{ flex: 1 }}>
              <span>CVV</span>
              <input value={draft.cvv ?? ""} onChange={(e) => set("cvv", e.target.value)} />
            </label>
          </div>
        </>
      ) : null}

      <label className="field">
        <span>태그</span>
        <input
          value={tagText}
          placeholder="쉼표로 구분"
          onChange={(e) => {
            const text = e.target.value;
            setTagText(text);
            set(
              "tags",
              text
                .split(",")
                .map((part) => part.trim())
                .filter(Boolean),
            );
          }}
        />
      </label>
      <label className="field">
        <span>메모</span>
        <textarea value={draft.notes ?? ""} onChange={(e) => set("notes", e.target.value)} />
      </label>
      <div className="actions">
        <button className="btn btn-primary" type="submit">
          저장
        </button>
        <button className="btn btn-ghost" type="button" onClick={onCancel}>
          취소
        </button>
      </div>
    </form>
  );
}

function GeneratorDialog({
  onClose,
  onUse,
  onCopy,
}: {
  onClose: () => void;
  onUse: (pw: string) => void;
  onCopy: (pw: string) => void;
}) {
  const [opts, setOpts] = useState<GenerateOpts>({
    length: 20,
    upper: true,
    lower: true,
    digits: true,
    symbols: true,
  });
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  async function regen() {
    setError("");
    try {
      setPassword(await generatePassword(opts));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const next = await generatePassword(opts);
        if (!cancelled) setPassword(next);
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [opts]);

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h2>비밀번호 생성기</h2>
        <p className="lede">길이와 문자 종류를 고른 뒤 복사하거나 항목에 넣으세요.</p>
        <label className="field">
          <span>길이 {opts.length}</span>
          <input
            className="range"
            type="range"
            min={8}
            max={64}
            value={opts.length}
            onChange={(e) => setOpts({ ...opts, length: Number(e.target.value) })}
          />
        </label>
        <div className="check-grid">
          <label>
            <input
              type="checkbox"
              checked={opts.upper}
              onChange={(e) => setOpts({ ...opts, upper: e.target.checked })}
            />
            대문자
          </label>
          <label>
            <input
              type="checkbox"
              checked={opts.lower}
              onChange={(e) => setOpts({ ...opts, lower: e.target.checked })}
            />
            소문자
          </label>
          <label>
            <input
              type="checkbox"
              checked={opts.digits}
              onChange={(e) => setOpts({ ...opts, digits: e.target.checked })}
            />
            숫자
          </label>
          <label>
            <input
              type="checkbox"
              checked={opts.symbols}
              onChange={(e) => setOpts({ ...opts, symbols: e.target.checked })}
            />
            기호
          </label>
        </div>
        <div className="gen-preview">{password}</div>
        <p className="error">{error}</p>
        <div className="actions">
          <button className="btn" type="button" onClick={() => void regen()}>
            다시 만들기
          </button>
          <button className="btn btn-ghost" type="button" onClick={() => onCopy(password)}>
            복사
          </button>
          <button className="btn btn-primary" type="button" onClick={() => onUse(password)}>
            사용
          </button>
          <button className="btn btn-ghost" type="button" onClick={onClose}>
            닫기
          </button>
        </div>
      </div>
    </div>
  );
}

const AUTO_LOCK_CHOICES: { value: number; label: string }[] = [
  { value: 1, label: "1분" },
  { value: 2, label: "2분" },
  { value: 5, label: "5분" },
  { value: 10, label: "10분" },
  { value: 30, label: "30분" },
  { value: 60, label: "1시간" },
];

function SettingsPanel({
  settings,
  syncStatus,
  onSettingsChange,
  onSyncStatus,
  onRequireUnlock,
  onToast,
  onReload,
  onKit,
}: {
  settings: VaultSettings;
  syncStatus: SyncStatus | null;
  onSettingsChange: (settings: VaultSettings) => void;
  onSyncStatus: (status: SyncStatus) => void;
  onRequireUnlock: () => void;
  onToast: (toast: Omit<Toast, "id">) => void;
  onReload: () => Promise<void>;
  onKit: (kit: EmergencyKitData, viewOnly: boolean) => void;
}) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [exportPw, setExportPw] = useState("");
  const [importPw, setImportPw] = useState("");
  const [mode, setMode] = useState<ImportMode>("merge");
  const [intervalDays, setIntervalDays] = useState(String(settings.passwordIntervalDays));
  const [bio, setBio] = useState<BiometricStatus | null>(null);
  const [bioBusy, setBioBusy] = useState(false);
  const [skEnabled, setSkEnabled] = useState(false);
  const [skBusy, setSkBusy] = useState(false);
  const [skPassword, setSkPassword] = useState("");
  const [skValue, setSkValue] = useState("");

  useEffect(() => {
    setIntervalDays(String(settings.passwordIntervalDays));
  }, [settings.passwordIntervalDays]);

  useEffect(() => {
    let cancelled = false;
    void biometricStatus()
      .then((nextStatus) => {
        if (!cancelled) setBio(nextStatus);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [settings.biometricsEnabled]);

  useEffect(() => {
    let cancelled = false;
    void secretKeyStatus()
      .then((status) => {
        if (!cancelled) setSkEnabled(status.enabled);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, []);

  async function savePatch(patch: SettingsPatch) {
    try {
      const nextSettings = await updateVaultSettings(patch);
      onSettingsChange(nextSettings);
    } catch (err) {
      onToast({ kind: "err", message: mapError(err instanceof Error ? err.message : String(err)) });
      const fresh = await getVaultSettings().catch(() => null);
      if (fresh) onSettingsChange(fresh);
    }
  }

  async function toggleBiometrics(enabled: boolean) {
    setBioBusy(true);
    try {
      const status = enabled ? await biometricEnable() : await biometricDisable();
      setBio(status);
      const fresh = await getVaultSettings();
      onSettingsChange(fresh);
      onToast({
        kind: "ok",
        message: enabled ? "생체 인증을 켰습니다." : "생체 인증을 껐습니다.",
      });
    } catch (err) {
      onToast({ kind: "err", message: mapError(err instanceof Error ? err.message : String(err)) });
    } finally {
      setBioBusy(false);
    }
  }

  async function handleEnableSk(e: FormEvent) {
    e.preventDefault();
    setSkBusy(true);
    try {
      const nextKit = await enableSecretKey(skPassword);
      setSkPassword("");
      setSkEnabled(true);
      onKit(nextKit, false);
      onToast({ kind: "ok", message: "Secret Key를 켰습니다. 비상 키트를 보관하세요." });
    } catch (err) {
      onToast({ kind: "err", message: mapError(err instanceof Error ? err.message : String(err)) });
    } finally {
      setSkBusy(false);
    }
  }

  async function handleRevealSk(e: FormEvent) {
    e.preventDefault();
    setSkBusy(true);
    try {
      const nextKit = await revealSecretKey(skPassword);
      setSkPassword("");
      onKit(nextKit, true);
    } catch (err) {
      onToast({ kind: "err", message: mapError(err instanceof Error ? err.message : String(err)) });
    } finally {
      setSkBusy(false);
    }
  }

  async function handleDisableSk(e: FormEvent) {
    e.preventDefault();
    setSkBusy(true);
    try {
      await disableSecretKey(skPassword, skValue);
      setSkPassword("");
      setSkValue("");
      setSkEnabled(false);
      onToast({ kind: "ok", message: "Secret Key를 껐습니다." });
    } catch (err) {
      onToast({ kind: "err", message: mapError(err instanceof Error ? err.message : String(err)) });
    } finally {
      setSkBusy(false);
    }
  }

  async function handleChangePassword(e: FormEvent) {
    e.preventDefault();
    if (next.length < 8) {
      onToast({ kind: "err", message: "새 비밀번호는 8자 이상이어야 합니다." });
      return;
    }
    if (next !== confirm) {
      onToast({ kind: "err", message: "새 비밀번호가 일치하지 않습니다." });
      return;
    }
    try {
      await changeMasterPassword(current, next);
      setCurrent("");
      setNext("");
      setConfirm("");
      onToast({ kind: "ok", message: "마스터 비밀번호를 바꿨습니다." });
    } catch (err) {
      onToast({ kind: "err", message: mapError(err instanceof Error ? err.message : String(err)) });
    }
  }

  async function handleExport(e: FormEvent) {
    e.preventDefault();
    if (!exportPw) {
      onToast({ kind: "err", message: "내보내기 비밀번호를 입력하세요." });
      return;
    }
    try {
      const path = await pickSavePath();
      if (!path) return;
      await exportVault(path, exportPw);
      onToast({ kind: "ok", message: "금고를 내보냈습니다." });
    } catch (err) {
      onToast({ kind: "err", message: err instanceof Error ? err.message : String(err) });
    }
  }

  async function handleImport(e: FormEvent) {
    e.preventDefault();
    if (!importPw) {
      onToast({ kind: "err", message: "가져오기 비밀번호를 입력하세요." });
      return;
    }
    try {
      const path = await pickOpenPath();
      if (!path) return;
      await importVault(path, importPw, mode);
      const fresh = await getVaultSettings();
      onSettingsChange(fresh);
      await onReload();
      onToast({ kind: "ok", message: "금고를 가져왔습니다." });
    } catch (err) {
      onToast({ kind: "err", message: err instanceof Error ? err.message : String(err) });
    }
  }

  return (
    <div className="settings-grid">
      <div>
        <h2>설정</h2>
        <p className="lede">동기화, 자동 잠금, 마스터 비밀번호, MCP 연결, 내보내기/가져오기를 관리합니다.</p>
      </div>
      <SyncSettings
        status={syncStatus}
        onStatus={onSyncStatus}
        onReload={onReload}
        onToast={onToast}
        onRequireUnlock={onRequireUnlock}
      />
      <div className="card">
        <h3>자동 잠금</h3>
        <p className="lede">마우스, 키보드, 터치가 없으면 금고를 잠급니다. 이 값은 암호화된 금고에 저장됩니다.</p>
        <label className="field">
          <span>대기 시간</span>
          <select
            value={settings.autoLockMinutes}
            onChange={(e) => void savePatch({ autoLockMinutes: Number(e.target.value) })}
          >
            {AUTO_LOCK_CHOICES.map((choice) => (
              <option key={choice.value} value={choice.value}>
                {choice.label}
              </option>
            ))}
          </select>
        </label>
        <label className="check-row">
          <input
            type="checkbox"
            checked={settings.lockOnScreenLock}
            onChange={(e) => void savePatch({ lockOnScreenLock: e.target.checked })}
          />
          <span>화면 잠금이나 절전으로 들어가면 즉시 잠금 (macOS 앱에서 동작)</span>
        </label>
        <label className="field">
          <span>마스터 비밀번호를 다시 요구하는 주기(일)</span>
          <input
            type="number"
            min={1}
            max={365}
            value={intervalDays}
            onChange={(e) => setIntervalDays(e.target.value)}
            onBlur={() => {
              const days = Number(intervalDays);
              if (days >= 1 && days <= 365 && days !== settings.passwordIntervalDays) {
                void savePatch({ passwordIntervalDays: days });
              } else {
                setIntervalDays(String(settings.passwordIntervalDays));
              }
            }}
          />
        </label>
      </div>
      <div className="card">
        <h3>생체 인증</h3>
        <p className="lede">
          마스터 비밀번호는 항상 사용할 수 있습니다. 앱이나 서버를 다시 시작한 직후, 그리고 위에서 정한 주기마다
          마스터 비밀번호가 필요합니다.
        </p>
        <label className="check-row">
          <input
            type="checkbox"
            checked={settings.biometricsEnabled}
            disabled={bioBusy || !bio || (bio.platform === "unsupported" && !settings.biometricsEnabled)}
            onChange={(e) => void toggleBiometrics(e.target.checked)}
          />
          <span>
            {bio?.platform === "web"
              ? "패스키로 잠금 해제"
              : bio?.platform === "unsupported"
                ? "생체 인증 (이 환경에서는 사용할 수 없음)"
                : "Touch ID로 잠금 해제"}
          </span>
        </label>
        {bio?.platform === "web" && settings.biometricsEnabled && !bio.prf ? (
          <p className="lede">
            이 패스키는 PRF로 금고 키를 감싸지 못했습니다. 서버 메모리에 키가 남아 있을 때만 세션을 다시 열 수 있고,
            완전히 잠근 뒤에는 마스터 비밀번호가 필요합니다.
          </p>
        ) : null}
        {bio?.touchIdReregister ? (
          <p className="notice">
            Touch ID 키체인 항목을 새 앱 이름으로 옮기지 못했습니다. 아래에서 Touch ID를 다시 등록해 주세요.
          </p>
        ) : null}
        {bio?.platform === "unsupported" ? (
          <p className="lede">이 환경에서는 생체 인증을 사용할 수 없습니다. Linux에서는 꺼진 상태로 둡니다.</p>
        ) : null}
      </div>
      <div className="card">
        <h3>Secret Key</h3>
        <p className="lede">
          1Password처럼 마스터 비밀번호와 함께 쓰는 두 번째 비밀입니다. 금고 파일이나 동기화 폴더에는 저장되지
          않습니다.
        </p>
        {skEnabled ? (
          <>
            <form onSubmit={handleRevealSk}>
              <label className="field">
                <span>마스터 비밀번호</span>
                <input
                  type="password"
                  value={skPassword}
                  onChange={(e) => setSkPassword(e.target.value)}
                  autoComplete="current-password"
                />
              </label>
              <button className="btn" type="submit" disabled={skBusy}>
                Secret Key / QR 보기
              </button>
            </form>
            <form onSubmit={handleDisableSk}>
              <label className="field">
                <span>마스터 비밀번호</span>
                <input
                  type="password"
                  value={skPassword}
                  onChange={(e) => setSkPassword(e.target.value)}
                  autoComplete="current-password"
                />
              </label>
              <label className="field">
                <span>Secret Key</span>
                <textarea
                  className="secret-key-display"
                  rows={3}
                  value={skValue}
                  onChange={(e) => setSkValue(e.target.value)}
                  autoComplete="off"
                  spellCheck={false}
                />
              </label>
              <button className="btn btn-danger" type="submit" disabled={skBusy}>
                Secret Key 끄기
              </button>
            </form>
          </>
        ) : (
          <form onSubmit={handleEnableSk}>
            <label className="field">
              <span>마스터 비밀번호 다시 확인</span>
              <input
                type="password"
                value={skPassword}
                onChange={(e) => setSkPassword(e.target.value)}
                autoComplete="current-password"
              />
            </label>
            <button className="btn btn-primary" type="submit" disabled={skBusy}>
              Secret Key 켜기
            </button>
          </form>
        )}
      </div>
      <form className="card" onSubmit={handleChangePassword}>
        <h3>마스터 비밀번호 변경</h3>
        <label className="field">
          <span>현재 비밀번호</span>
          <input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} />
        </label>
        <label className="field">
          <span>새 비밀번호</span>
          <input type="password" value={next} onChange={(e) => setNext(e.target.value)} />
        </label>
        <label className="field">
          <span>새 비밀번호 확인</span>
          <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
        </label>
        <button className="btn btn-primary" type="submit">
          변경
        </button>
      </form>
      <form className="card" onSubmit={handleExport}>
        <h3>내보내기</h3>
        <p className="lede">암호화된 .khv 파일로 금고를 저장합니다.</p>
        <label className="field">
          <span>내보내기 비밀번호</span>
          <input type="password" value={exportPw} onChange={(e) => setExportPw(e.target.value)} />
        </label>
        <button className="btn" type="submit">
          파일로 내보내기
        </button>
      </form>
      <form className="card" onSubmit={handleImport}>
        <h3>가져오기</h3>
        <p className="lede">다른 SecureVault 금고를 병합하거나 현재 금고를 교체합니다.</p>
        <label className="field">
          <span>가져오기 비밀번호</span>
          <input type="password" value={importPw} onChange={(e) => setImportPw(e.target.value)} />
        </label>
        <label className="field">
          <span>방식</span>
          <select value={mode} onChange={(e) => setMode(e.target.value as ImportMode)}>
            <option value="merge">병합</option>
            <option value="replace">교체</option>
          </select>
        </label>
        <button className="btn" type="submit">
          파일에서 가져오기
        </button>
      </form>
      <McpSettings onToast={onToast} />
      <BuildStamp />
    </div>
  );
}
