import { checkContent, verdictWord, getApiBase, setApiBase } from "./shared.js";

const messageFromEl = document.getElementById("message-from");
const messageSubjectEl = document.getElementById("message-subject");
const checkBtn = document.getElementById("check-btn");
const resultEl = document.getElementById("result");
const errorEl = document.getElementById("error");
const limitationNoteEl = document.getElementById("limitation-note");

const settingsToggle = document.getElementById("settings-toggle");
const settingsPanel = document.getElementById("settings-panel");
const apiBaseInput = document.getElementById("api-base");
const settingsStatus = document.getElementById("settings-status");

settingsToggle.addEventListener("click", () => {
  const showing = settingsPanel.style.display === "block";
  if (!showing) apiBaseInput.value = getApiBase();
  settingsPanel.style.display = showing ? "none" : "block";
  settingsStatus.textContent = "";
});

document.getElementById("cancel-settings").addEventListener("click", () => {
  settingsPanel.style.display = "none";
});

document.getElementById("save-settings").addEventListener("click", async () => {
  const value = apiBaseInput.value.trim().replace(/\/$/, "");
  if (!value) {
    settingsStatus.textContent = "Enter an API base URL.";
    settingsStatus.className = "err";
    return;
  }
  try {
    const parsed = new URL(value);
    if (!/^https?:$/.test(parsed.protocol)) throw new Error();
  } catch {
    settingsStatus.textContent = "That doesn't look like a valid URL (include http:// or https://).";
    settingsStatus.className = "err";
    return;
  }
  try {
    await setApiBase(value);
    settingsStatus.textContent = "Saved.";
    settingsStatus.className = "ok";
  } catch (err) {
    settingsStatus.textContent = err.message;
    settingsStatus.className = "err";
  }
});

function renderResult(result, { limitedHeaders = false } = {}) {
  const card = document.getElementById("verdict-card");
  card.className = "verdict-card " + result.verdict;
  document.getElementById("score").textContent = result.score;
  document.getElementById("verdict-label").textContent = verdictWord(result.verdict);
  document.getElementById("notes").textContent = result.notes || "";

  const mitreRow = document.getElementById("mitre-row");
  mitreRow.innerHTML = "";
  result.mitre_techniques.forEach((t) => {
    const pill = document.createElement("span");
    pill.className = "mitre-pill";
    pill.textContent = t;
    mitreRow.appendChild(pill);
  });

  const list = document.getElementById("evidence-list");
  list.innerHTML = "";
  if (result.evidence.length === 0) {
    const div = document.createElement("div");
    div.className = "evidence-item";
    div.innerHTML = "<span class='evidence-detail'>No signals triggered.</span>";
    list.appendChild(div);
  } else {
    result.evidence.forEach((ev) => {
      const div = document.createElement("div");
      div.className = "evidence-item";
      const detail = document.createElement("span");
      detail.className = "evidence-detail";
      detail.textContent = ev.detail;
      const signal = document.createElement("span");
      signal.className = "evidence-signal";
      signal.textContent = ev.signal;
      detail.appendChild(signal);
      const points = document.createElement("span");
      points.className = "evidence-points";
      points.textContent = ev.points > 0 ? "+" + ev.points : String(ev.points);
      div.appendChild(detail);
      div.appendChild(points);
      list.appendChild(div);
    });
  }

  limitationNoteEl.style.display = limitedHeaders ? "block" : "none";
  limitationNoteEl.textContent = limitedHeaders
    ? "This Outlook client didn't provide full message headers, so Reply-To mismatch and SPF/DKIM/DMARC " +
      "alignment couldn't be checked — only sender, subject, body text, and any links were scored."
    : "";

  resultEl.style.display = "block";
  errorEl.style.display = "none";
}

function getBodyText(item) {
  return new Promise((resolve, reject) => {
    item.body.getAsync(Office.CoercionType.Text, (result) => {
      if (result.status === Office.AsyncResultStatus.Succeeded) {
        resolve(result.value || "");
      } else {
        reject(new Error(result.error?.message || "Couldn't read the message body."));
      }
    });
  });
}

function getAllInternetHeaders(item) {
  return new Promise((resolve, reject) => {
    if (typeof item.getAllInternetHeadersAsync !== "function") {
      resolve(null);
      return;
    }
    item.getAllInternetHeadersAsync((result) => {
      if (result.status === Office.AsyncResultStatus.Succeeded) {
        resolve(result.value || null);
      } else {
        // Some hosts advertise the method but still refuse it (e.g. an item
        // in an unsupported folder) — degrade to the fallback rather than fail.
        resolve(null);
      }
    });
  });
}

// A raw source the same email-signal parser the browser extension and demo
// UI use can read: real internet headers when the host gives them to us
// (From/Reply-To/Authentication-Results, exactly what app/signals/email_signals.py
// looks for), or a minimal reconstructed From/Subject block when it can't —
// clearly flagged in the UI rather than silently skipping checks.
async function buildRawEmail(item) {
  const headers = await getAllInternetHeaders(item);
  const body = await getBodyText(item);

  if (headers) {
    return { raw: `${headers}\n\n${body}`, limitedHeaders: false };
  }

  const fromAddr = item.from ? `"${item.from.displayName || ""}" <${item.from.emailAddress || ""}>` : "";
  const subject = item.subject || "";
  return { raw: `From: ${fromAddr}\nSubject: ${subject}\n\n${body}`, limitedHeaders: true };
}

async function runCheck(item) {
  checkBtn.disabled = true;
  checkBtn.textContent = "Checking…";
  errorEl.style.display = "none";
  try {
    const { raw, limitedHeaders } = await buildRawEmail(item);
    const result = await checkContent("email", raw);
    renderResult(result, { limitedHeaders });
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.style.display = "block";
    resultEl.style.display = "none";
  } finally {
    checkBtn.disabled = false;
    checkBtn.textContent = "Check this email";
  }
}

Office.onReady(() => {
  const item = Office.context.mailbox.item;
  if (!item) {
    messageFromEl.textContent = "No message is open.";
    checkBtn.disabled = true;
    return;
  }

  const fromName = item.from?.displayName || "";
  const fromAddr = item.from?.emailAddress || "";
  messageFromEl.textContent = fromName ? `${fromName} <${fromAddr}>` : fromAddr || "(unknown sender)";
  messageSubjectEl.textContent = item.subject || "(no subject)";

  checkBtn.addEventListener("click", () => runCheck(item));
});
