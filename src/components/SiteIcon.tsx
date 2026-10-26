import { useState } from "react";
import { useSiteIcon } from "../siteIcons";
import type { VaultItem } from "../types";

/* Mac (desktop) site icon: the live icon for a login's URL, or an initial
   avatar while loading, offline with no cache, or when there is no URL. */
export default function SiteIcon({ item, size }: { item: Pick<VaultItem, "title" | "itemType" | "url">; size: number }) {
  const { ref, icon } = useSiteIcon(item.url);
  const [broken, setBroken] = useState<string | null>(null);
  const title = item.title.trim();
  let hash = 0;
  for (const ch of title) hash = (hash * 31 + ch.codePointAt(0)!) % 360;
  const letter = (title.replace(/^예시\s*/, "").charAt(0) || title.charAt(0) || "?").toUpperCase();
  const show = icon && broken !== icon;
  return (
    <span
      ref={ref}
      className={`site-icon${show ? " has-icon" : ""}`}
      style={{ width: size, height: size, fontSize: size * 0.48, background: show ? undefined : `hsl(${hash} 42% 42%)` }}
      aria-hidden="true"
    >
      {show ? <img src={icon} alt="" draggable={false} onError={() => setBroken(icon)} /> : letter}
    </span>
  );
}
