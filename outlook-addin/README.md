# Hookline — Outlook Add-in

A task pane add-in that scores the email you're currently reading for phishing signals, using the same Hookline API and rules/threat-intel/enrichment/ML pipeline as the demo web UI and the browser extension.

## Why this one needs an extra step

The Chrome extension loads straight off your disk ("Load unpacked"). Outlook doesn't work that way — every add-in is fetched over a URL, and Outlook requires that URL to be HTTPS, even on your own machine during development. `office-addin-dev-certs` (a small tool from Microsoft) generates a certificate for `https://localhost:3000` and trusts it on your machine the first time you run this add-in, so there's no security warning.

## Setup

1. Make sure Node.js is installed (`node --version` in a terminal — if that fails, install it from nodejs.org, then reopen your terminal).
2. In this folder (`outlook-addin/`), install dependencies:
   ```
   npm install
   ```
3. Start the HTTPS server:
   ```
   npm start
   ```
   The first run installs a local dev certificate and may ask for permission — approve it. Leave this running in its own terminal window the whole time you're using the add-in (same idea as the API server).
4. Also make sure the Hookline API itself is running in another terminal, same as always:
   ```
   python -m uvicorn app.main:app --reload
   ```

## Sideload it into Outlook on the web

1. Go to outlook.office.com (or outlook.live.com) and sign in.
2. Open any email, then find "Get Add-ins" on the ribbon (or the "..." more-actions menu) → "My add-ins" in the left sidebar.
3. Near the bottom, "+ Add a custom add-in" → "Add from file...".
4. Select `manifest.xml` from this folder.
5. Accept the install prompt.

*(Exact menu wording shifts occasionally as Microsoft updates the UI — if this exact path isn't there, search Settings for "add-ins" and it'll be nearby.)*

## Using it

1. Open any email.
2. On the ribbon (or the "..." more-actions menu if the ribbon is condensed), find "Check with Hookline" and click it — this opens the task pane.
3. Click "Check this email".
4. Same verdict card / evidence trail / MITRE tags as everywhere else in Hookline.

If your Outlook client doesn't expose full message headers (some do, some don't — this add-in checks and tells you), Reply-To mismatch and SPF/DKIM/DMARC checks are skipped for that message, but sender, subject, body text, and any links are still scored normally. That limitation is called out directly in the task pane when it applies, rather than silently skipping checks.

## Known limitations

- No automated test suite for this add-in specifically — same situation as the browser extension (there's no practical way to script-test an Outlook host UI the way pytest tests the API). It's been validated by serving it locally and confirming the manifest, HTTPS server, and task pane all load and render correctly; the actual click-through inside Outlook still needs a manual check the first time.
- Sideload steps above are for Outlook on the web. Classic desktop Outlook uses a different (shared-folder or registry) sideloading method — ask if you want those instructions too.
