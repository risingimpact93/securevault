// Reads SECUREVAULT_<suffix>, falling back to the legacy KEYHAVEN_<suffix>.
export function envValue(suffix, env = process.env) {
  const primary = env[`SECUREVAULT_${suffix}`];
  if (primary && primary.trim()) return primary.trim();
  const legacy = env[`KEYHAVEN_${suffix}`];
  if (legacy && legacy.trim()) return legacy.trim();
  return "";
}
