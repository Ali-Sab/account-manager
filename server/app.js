"use strict";

const path = require("path");
require("dotenv").config({ path: path.join(__dirname, "..", ".env") });

const express      = require("express");
const cookieParser = require("cookie-parser");

const app = express();
app.set("trust proxy", 1);

const SERVE_STATIC = process.env.NODE_ENV !== "development";

app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN"); // allow authorize page in same origin
  next();
});

if (SERVE_STATIC) {
  app.use("/", express.static(path.join(__dirname, "..", "dist")));
}

// OAuth / discovery routes at root
app.use("/", require("./routes/oauth"));
app.use("/", require("./routes/jwks"));

// API routes
app.use("/api", require("./routes/setup"));
app.use("/api", require("./routes/auth"));
app.use("/api", require("./routes/webauthn"));

// SPA fallback — exclude API, OAuth, and well-known paths
if (SERVE_STATIC) {
  app.get(/^(?!\/(api|authorize|token|oauth|\.well-known)\b).*$/, (req, res) => {
    res.sendFile(path.join(__dirname, "..", "dist", "index.html"));
  });
}

module.exports = { app };
