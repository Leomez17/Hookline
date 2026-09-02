import { DEFAULT_API_BASE, originPatternFor } from "./shared.js";

const input = document.getElementById("api-base");
const statusEl = document.getElementById("status");

async function load() {
  const { apiBase } = await chrome.storage.sync.get("apiBase");
  input.value = apiBase || DEFAULT_API_BASE;
}

function showStatus(message, ok) {
  statusEl.textContent = message;
  statusEl.className = "status " + (ok ? "ok" : "err");
}

document.getElementById("save-btn").addEventListener("click", async () => {
  const value = input.value.trim().replace(/\/$/, "");
  if (!value) {
    showStatus("Enter an API base URL.", false);
    return;
  }

  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    showStatus("That doesn't look like a valid URL (include http:// or https://).", false);
    return;
  }
  if (!/^https?:$/.test(parsed.protocol)) {
    showStatus("Only http:// and https:// are supported.", false);
    return;
  }

  const pattern = originPatternFor(value);
  const alreadyDefault = value === "http://127.0.0.1:8000" || value === "http://localhost:8000";

  if (!alreadyDefault && pattern) {
    const granted = await chrome.permissions.request({ origins: [pattern] });
    if (!granted) {
      showStatus("Permission to reach that address was declined, so the setting wasn't saved.", false);
      return;
    }
  }

  await chrome.storage.sync.set({ apiBase: value });
  showStatus("Saved.", true);
});

load();
