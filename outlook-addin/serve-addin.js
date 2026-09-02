// Serves this folder over HTTPS on https://localhost:3000.
//
// Outlook add-ins are stricter than a Chrome extension's "Load unpacked"
// flow: every URL in manifest.xml (the task pane, its icons) has to be
// HTTPS, even for local development. office-addin-dev-certs is Microsoft's
// own tool for this — it generates a self-signed certificate for
// localhost and installs it into your system's trust store the first time
// it runs, so Outlook (and your browser) accept it without a warning.
// The Chrome extension never needed this because "Load unpacked" reads
// files straight off disk; Outlook always fetches the add-in over a URL.
const https = require("https");
const http = require("http");
const fs = require("fs");
const path = require("path");
const devCerts = require("office-addin-dev-certs");

const PORT = 3000;
const ROOT = __dirname;

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".xml": "application/xml; charset=utf-8",
  ".png": "image/png",
  ".ico": "image/x-icon",
};

function requestHandler(req, res) {
  let reqPath = decodeURIComponent(req.url.split("?")[0]);
  if (reqPath === "/") reqPath = "/taskpane.html";

  const filePath = path.join(ROOT, reqPath);
  // Refuse to serve anything outside this folder.
  if (!filePath.startsWith(ROOT)) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end(`Not found: ${reqPath}`);
      return;
    }
    const ext = path.extname(filePath);
    res.writeHead(200, {
      "Content-Type": MIME_TYPES[ext] || "application/octet-stream",
      "Access-Control-Allow-Origin": "*",
    });
    res.end(data);
  });
}

async function main() {
  const httpsOptions = await devCerts.getHttpsServerOptions();
  https.createServer(httpsOptions, requestHandler).listen(PORT, () => {
    console.log(`Hookline Outlook add-in served at https://localhost:${PORT}`);
    console.log(`Manifest to sideload: https://localhost:${PORT}/manifest.xml`);
    console.log("Leave this running while you use the add-in in Outlook. Ctrl+C to stop.");
  });
}

main().catch((err) => {
  console.error("Couldn't start the HTTPS server:", err.message);
  process.exit(1);
});
