// Derive the Safari manifest from the Chrome one so both stay in sync.
// Safari ignores Chrome's `key` (its extension ID comes from the appex bundle).
export function safariManifest(chrome) {
  const m = structuredClone(chrome);
  delete m.key;
  delete m.minimum_chrome_version;
  // Same shape as Xcode's Safari Extension App template (MV3 module service worker).
  m.background = { service_worker: "background.js", type: "module" };
  // Safari's Settings > Extensions list uses the larger icon sizes.
  m.icons = { ...m.icons, "96": "icons/icon-96.png", "256": "icons/icon-256.png", "512": "icons/icon-512.png" };
  m.browser_specific_settings = { safari: { strict_min_version: "16.4" } };
  return m;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const fs = await import("node:fs");
  const [src, dst] = process.argv.slice(2);
  fs.writeFileSync(dst, JSON.stringify(safariManifest(JSON.parse(fs.readFileSync(src, "utf8"))), null, 2) + "\n");
}
