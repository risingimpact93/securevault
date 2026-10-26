// Derive the Safari manifest from the Chrome one so both stay in sync.
// Safari ignores Chrome's `key` (its extension ID comes from the appex bundle).
export function safariManifest(chrome) {
  const m = structuredClone(chrome);
  delete m.key;
  delete m.minimum_chrome_version;
  m.background = { service_worker: "background.js", scripts: ["background.js"], type: "module", preferred_environment: ["service_worker"] };
  m.browser_specific_settings = { safari: { strict_min_version: "16.4" } };
  return m;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const fs = await import("node:fs");
  const [src, dst] = process.argv.slice(2);
  fs.writeFileSync(dst, JSON.stringify(safariManifest(JSON.parse(fs.readFileSync(src, "utf8"))), null, 2) + "\n");
}
