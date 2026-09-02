// Service worker (Manifest V3 — no persistent background page, so this
// re-registers its context menus on every install/update rather than
// relying on state surviving between wakeups).
import { checkContent, verdictColor, verdictWord, isCheckableUrl } from "./shared.js";

const MENU_PAGE = "hookline-check-page";
const MENU_LINK = "hookline-check-link";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: MENU_PAGE,
    title: "Check this page with Hookline",
    contexts: ["page"],
  });
  chrome.contextMenus.create({
    id: MENU_LINK,
    title: "Check this link with Hookline",
    contexts: ["link"],
  });
});

async function runCheck(targetUrl, tabId) {
  if (!isCheckableUrl(targetUrl)) {
    chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon128.png",
      title: "Hookline",
      message: "That doesn't look like a checkable http(s) link.",
    });
    return;
  }

  try {
    const result = await checkContent("url", targetUrl);

    // Popup reads this when it's next opened for the same tab, so a
    // context-menu check and the toolbar popup stay in sync without
    // either one needing to poll the other.
    await chrome.storage.local.set({
      [`lastResult:${tabId}`]: { url: targetUrl, result, checkedAt: Date.now() },
    });

    if (tabId !== undefined) {
      chrome.action.setBadgeText({ text: String(result.score), tabId });
      chrome.action.setBadgeBackgroundColor({ color: verdictColor(result.verdict), tabId });
    }

    const topEvidence = result.evidence.find((e) => e.points > 0);
    chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon128.png",
      title: `Hookline: ${verdictWord(result.verdict)} (${result.score}/100)`,
      message: topEvidence ? topEvidence.detail : "No signals triggered.",
    });
  } catch (err) {
    chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon128.png",
      title: "Hookline check failed",
      message: err.message,
    });
  }
}

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === MENU_PAGE) {
    runCheck(info.pageUrl || tab?.url, tab?.id);
  } else if (info.menuItemId === MENU_LINK) {
    runCheck(info.linkUrl, tab?.id);
  }
});

// Badges are per-tab and don't clear themselves on navigation — clear
// ours so a stale score from the previous page doesn't linger.
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") {
    chrome.action.setBadgeText({ text: "", tabId });
  }
});
