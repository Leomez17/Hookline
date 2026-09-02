# Hookline browser extension

A Manifest V3 Chrome/Edge extension that lets you check the current page or
a right-clicked link against your own Hookline API, without switching to
the demo UI and pasting anything in. It's a thin client — every score,
verdict, and piece of evidence still comes straight from your running
Hookline server; the extension just gets it in front of you faster.

## Install (Load unpacked)

1. Make sure your Hookline API is running somewhere reachable (locally,
   by default):
   ```bash
   uvicorn app.main:app --reload
   ```
2. Open `chrome://extensions` (Edge: `edge://extensions`).
3. Turn on **Developer mode** (top right).
4. Click **Load unpacked** and select this `extension/` folder.
5. Pin it to the toolbar if you want one-click access (puzzle-piece icon →
   pin next to Hookline).

There's no build step — it's plain JS/HTML/CSS, loaded straight from disk.

## Using it

- **Toolbar popup** — click the icon to check the page you're currently
  on. Shows the same score, verdict, MITRE tags, and evidence list as the
  demo UI.
- **Right-click menu** — right-click any page or any link and choose
  *"Check this page/link with Hookline"*. Runs in the background, shows a
  desktop notification with the top evidence item, and badges the toolbar
  icon with the score. Open the popup afterward and it'll show that same
  result instead of asking you to check again (for 10 minutes — after
  that it's treated as stale and you'll be asked to re-check).
- **Settings** (gear/"settings" link in the popup, or right-click the
  icon → *Options*) — change the API base URL if your Hookline instance
  isn't at the default `http://127.0.0.1:8000` (a different port, or a
  server reachable over your network). Pointing it at a non-default
  address will ask Chrome to grant the extension permission to reach that
  address — that's Chrome's own permission prompt, not Hookline's.

## What it can and can't check

Only `http://` and `https://` pages/links are checkable — anything else
(a `chrome://` page, a `file://` link, a `javascript:` bookmarklet) is
skipped, with the popup explaining why rather than silently failing.

This talks to a *local or self-hosted* Hookline instance you control —
it's not a hosted service, and no URL you check leaves your own machine
(or wherever you've pointed the API base) except to reach the threat-intel
and enrichment sources Hookline itself is configured to call, exactly as
documented in the main README.

## Why no CORS errors

Chrome extensions with a granted `host_permissions` entry for an origin
bypass the browser's CORS enforcement for requests to that origin, so the
extension's own fetches work regardless. The server (`app/main.py`) also
now sends permissive CORS headers, mainly so you can poke `/check` from a
plain browser console or a script on a different port without the same
extension-permission dance — see the comment above
`app.add_middleware(CORSMiddleware, ...)` there for the reasoning and the
one thing to change (`allow_origins`) before ever running an instance
somewhere other than your own machine.

## Files

```
extension/
  manifest.json     Manifest V3 config — permissions, icons, entry points
  background.js      Service worker — context menus, badge, notifications
  popup.html/js       Toolbar popup UI
  options.html/js      Settings page (API base URL)
  shared.js            Common helpers: checkContent(), URL validation, verdict colors
  icons/                16/32/48/128px icons
```

## Known limitation

No automated test suite here the way `pytest` covers the Python backend —
there isn't an equivalent harness for a Manifest V3 extension in this
project. It's been smoke-tested end-to-end against a real running Hookline
server (service worker starts cleanly, options page saves and reloads
correctly, and a check against a live sample URL returns a correctly
scored, correctly tagged result through the extension's own code), but the
toolbar-click and right-click-menu flows are worth clicking through
yourself once after installing, just to see it in your own browser.
