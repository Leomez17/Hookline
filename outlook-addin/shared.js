// Shared between taskpane.js and (eventually) any other add-in surface —
// the one place that knows how to reach the Hookline API and how to read
// or write the saved API base URL. Mirrors extension/shared.js, but swaps
// chrome.storage.sync for Office.context.roamingSettings, which is the
// Outlook add-in equivalent: it follows the signed-in user across devices
// rather than being scoped to one browser profile.

export const DEFAULT_API_BASE = "http://127.0.0.1:8000";
const ROAMING_KEY = "hooklineApiBase";

export function getApiBase() {
  const value = Office.context.roamingSettings.get(ROAMING_KEY);
  return value || DEFAULT_API_BASE;
}

export function setApiBase(value) {
  return new Promise((resolve, reject) => {
    Office.context.roamingSettings.set(ROAMING_KEY, value);
    Office.context.roamingSettings.saveAsync((result) => {
      if (result.status === Office.AsyncResultStatus.Succeeded) {
        resolve();
      } else {
        reject(new Error(result.error?.message || "Couldn't save the setting."));
      }
    });
  });
}

// Throws with a human-readable .message on any failure — network error,
// non-2xx response, or a response that isn't the JSON shape /check
// returns — so callers can show it directly rather than a stack trace.
export async function checkContent(type, content) {
  const apiBase = getApiBase();
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
      `(python -m uvicorn app.main:app --reload) — you can change the address in the add-in's settings.`
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
