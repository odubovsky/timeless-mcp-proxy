import http from "node:http";
import { handle } from "./app.mjs";

const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || "127.0.0.1";

const server = http.createServer((req, res) => {
  handle(req, res).catch((error) => {
    console.error("proxy_error");
    if (!res.headersSent) {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "proxy_error" }));
    }
  });
});

server.listen(port, host, () => {
  console.error(`listening ${host}:${port}`);
});
