// Shared between popup.js and background.js — the one place that knows
// how to reach the Hookline API and how to interpret a verdict. Both
// callers import this as an ES module (manifest.json sets
// background.type = "module"; popup.html loads popup.js the same way).

export const DEFAULT_API_BASE = "http://127.0.0.1:8000";

export async function getApiBase() {
  const { apiBase } = await chrome.storage.sync.get("apiBase");
  return apiBase || DEFAULT_API_BASE;
}

export function originPatternFor(apiBase) {
  try {
    const url = new URL(apiBase);
    return `${url.protocol}//${url.hostname}${url.port ? ":" + url.port : ""}/*`;
  } catch {
    return null;
  }
}

// Throws with a human-readable .message on any failure — network error,
// non-2xx response, or a response that isn't the JSON shape /check
// returns — so callers can show it directly rather than a stack trace.
export async function checkContent(type, content) {
  const apiBase = await getApiBase();
  let res;
  try {
    res = await fetch(`${apiBase}/check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type, content }),
    });
  } catch (err) {
    throw new Error(
      `Couldn't reach the Hookline API at ${apiBase}. Is it running? ` +
      `(uvicorn app.main:app --reload) — you can change the address in the extension's options.`
    );
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail ? JSON.stringify(body.detail) : `Request failed (HTTP ${res.status})`);
  }

  return res.json();
}

export function verdictWord(v) {
  return { safe: "Safe", suspicious: "Suspicious", malicious: "Malicious" }[v] || v;
}

// Badge/notification color per verdict — same three-way split the demo
// UI's verdict card uses, just as solid colors instead of CSS custom
// properties (badge backgrounds don't get to use a stylesheet).
export function verdictColor(v) {
  return { safe: "#3f7a5c", suspicious: "#9c6a1f", malicious: "#a3403a" }[v] || "#4b5563";
}

// A page a phishing check can never meaningfully apply to — internal
// browser UI, the extension's own pages, etc. Checking these would just
// send garbage to the scorer and confuse the user with a meaningless result.
export function isCheckableUrl(url) {
  if (!url) return false;
  return /^https?:\/\//i.test(url);
}
