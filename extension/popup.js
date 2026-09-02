import { checkContent, verdictWord, isCheckableUrl } from "./shared.js";

const currentUrlEl = document.getElementById("current-url");
const checkBtn = document.getElementById("check-btn");
const uncheckableEl = document.getElementById("uncheckable");
const resultEl = document.getElementById("result");
const errorEl = document.getElementById("error");
const staleNoteEl = document.getElementById("stale-note");
document.getElementById("options-link").addEventListener("click", (e) => {
  e.preventDefault();
  chrome.runtime.openOptionsPage();
});

// How long a context-menu-triggered result (stored by background.js) is
// still shown as "already checked" before the popup asks you to re-check
// instead — long enough to be useful, short enough not to show something
// stale as if it were current.
const RESULT_FRESHNESS_MS = 10 * 60 * 1000;

let currentTab = null;

function renderResult(result, { stale = false } = {}) {
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

  staleNoteEl.style.display = stale ? "block" : "none";
  staleNoteEl.textContent = stale ? "From an earlier check via the right-click menu — click below to re-check." : "";
  resultEl.style.display = "block";
  errorEl.style.display = "none";
}

async function runCheck(url) {
  checkBtn.disabled = true;
  checkBtn.textContent = "Checking…";
  errorEl.style.display = "none";
  try {
    const result = await checkContent("url", url);
    renderResult(result);
    if (currentTab) {
      await chrome.storage.local.set({
        [`lastResult:${currentTab.id}`]: { url, result, checkedAt: Date.now() },
      });
    }
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.style.display = "block";
    resultEl.style.display = "none";
  } finally {
    checkBtn.disabled = false;
    checkBtn.textContent = "Check this page";
  }
}

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentTab = tab;
  const url = tab?.url || "";
  currentUrlEl.textContent = url || "(no URL)";

  if (!isCheckableUrl(url)) {
    checkBtn.style.display = "none";
    uncheckableEl.style.display = "block";
    return;
  }

  checkBtn.addEventListener("click", () => runCheck(url));

  // If the right-click "Check this link/page" menu already produced a
  // recent result for this tab, show it immediately instead of making
  // the user click Check again for something already known.
  const key = `lastResult:${tab.id}`;
  const stored = await chrome.storage.local.get(key);
  const last = stored[key];
  if (last && last.url === url && Date.now() - last.checkedAt < RESULT_FRESHNESS_MS) {
    renderResult(last.result, { stale: false });
  }
}

init();
