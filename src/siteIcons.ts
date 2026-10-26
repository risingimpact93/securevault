import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import { clearSiteIcons, siteIcon } from "./api";

/* Live site icons for entries (iOS UI). Icons come from each entry's own
   site at runtime via the native `site_icon` command; nothing is bundled
   except the demo-mode dummies the native side returns for *.example.invalid.
   Lookups are lazy (only rows on screen) and at most MAX_ACTIVE at a time. */

const PREF_KEY = "securevault.siteIcons";
const MAX_ACTIVE = 3;

let enabled = localStorage.getItem(PREF_KEY) !== "off";
let generation = 0;
const listeners = new Set<() => void>();
const memo = new Map<string, string | null>(); // key: generation + url
const inflight = new Map<string, Promise<string | null>>();
const queue: Array<() => void> = [];
let active = 0;

function emit() {
  for (const l of listeners) l();
}
function subscribe(l: () => void) {
  listeners.add(l);
  return () => listeners.delete(l);
}

export function useSiteIconsEnabled(): boolean {
  return useSyncExternalStore(subscribe, () => enabled);
}

export function setSiteIconsEnabled(on: boolean) {
  enabled = on;
  localStorage.setItem(PREF_KEY, on ? "on" : "off");
  emit();
}

/** Drop the on-disk cache and refetch whatever is visible. */
export async function clearSiteIconCache(): Promise<void> {
  await clearSiteIcons();
  refreshSiteIcons(false);
}

/** Refetch visible icons; `force` bypasses the 7-day disk cache. */
let forceNext = false;
export function refreshSiteIcons(force = true) {
  memo.clear();
  inflight.clear();
  forceNext = force;
  if (force) setTimeout(() => (forceNext = false), 15000);
  generation += 1;
  emit();
}

function pump() {
  while (active < MAX_ACTIVE && queue.length) {
    active += 1;
    queue.shift()!();
  }
}

function load(url: string): Promise<string | null> {
  const key = `${generation}\n${url}`;
  if (memo.has(key)) return Promise.resolve(memo.get(key)!);
  const existing = inflight.get(key);
  if (existing) return existing;
  const force = forceNext;
  const p = new Promise<string | null>((resolve) => {
    queue.push(() => {
      siteIcon(url, force)
        .catch(() => null)
        .then((icon) => {
          memo.set(key, icon);
          resolve(icon);
        })
        .finally(() => {
          active -= 1;
          inflight.delete(key);
          pump();
        });
    });
    pump();
  });
  inflight.set(key, p);
  return p;
}

/** Icon data URL for `url` once the element is on screen, else null. */
export function useSiteIcon(url: string | undefined) {
  const on = useSiteIconsEnabled();
  const gen = useSyncExternalStore(subscribe, () => generation);
  const ref = useRef<HTMLSpanElement | null>(null);
  const [visible, setVisible] = useState(false);
  const [icon, setIcon] = useState<string | null>(null);
  const target = on && url?.trim() ? url.trim() : "";

  useEffect(() => {
    const el = ref.current;
    if (!el || !target) return;
    if (typeof IntersectionObserver === "undefined") {
      setVisible(true);
      return;
    }
    const io = new IntersectionObserver((entries) => {
      if (entries.some((e) => e.isIntersecting)) {
        setVisible(true);
        io.disconnect();
      }
    }, { rootMargin: "120px" });
    io.observe(el);
    return () => io.disconnect();
  }, [target]);

  const shownFor = useRef("");
  useEffect(() => {
    // A new URL clears the old site's icon; a refresh keeps it until the
    // result arrives (and the native side returns the old icon on failure).
    if (shownFor.current !== target) {
      shownFor.current = target;
      setIcon(null);
    }
    if (!target || !visible) return;
    let live = true;
    void load(target).then((i) => {
      if (live) setIcon(i);
    });
    return () => {
      live = false;
    };
  }, [target, visible, gen]);

  return { ref, icon: target ? icon : null };
}
