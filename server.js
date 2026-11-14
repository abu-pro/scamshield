/*
 * ScamShield — zero-dependency Node server.
 * Serves the static site and the analysis API.
 * Run: node server.js   (PORT env optional, default 3000)
 */
const http = require("http");
const fs = require("fs");
const path = require("path");
const { analyze } = require("./shield");

const PORT = process.env.PORT || 3000;
const PUBLIC = path.join(__dirname, "public");

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
};

function sendJson(res, code, obj) {
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(obj));
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");

  if (url.pathname === "/api/analyze" && req.method === "POST") {
    let body = "";
    req.on("data", (c) => {
      body += c;
      if (body.length > 200000) req.destroy();
    });
    req.on("end", () => {
      try {
        const { text } = JSON.parse(body || "{}");
        if (!text || typeof text !== "string") return sendJson(res, 400, { error: "Provide a message in 'text'." });
        return sendJson(res, 200, analyze(text.slice(0, 20000)));
      } catch (e) {
        return sendJson(res, 400, { error: "Invalid JSON body" });
      }
    });
    return;
  }

  if (url.pathname === "/shield.js") {
    res.writeHead(200, { "Content-Type": MIME[".js"] });
    return res.end(fs.readFileSync(path.join(__dirname, "shield.js")));
  }

  let filePath = url.pathname === "/" ? "/index.html" : url.pathname;
  filePath = path.normalize(path.join(PUBLIC, filePath));
  if (!filePath.startsWith(PUBLIC)) {
    res.writeHead(403);
    return res.end("Forbidden");
  }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { "Content-Type": "text/plain" });
      return res.end("Not found");
    }
    res.writeHead(200, { "Content-Type": MIME[path.extname(filePath)] || "application/octet-stream" });
    res.end(data);
  });
});

server.listen(PORT, () => {
  console.log(`ScamShield running on http://localhost:${PORT}`);
});
