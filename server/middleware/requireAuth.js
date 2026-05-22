"use strict";

const { verifyAccess } = require("../lib/crypto");

function requireAuth(req, res, next) {
  const auth  = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: "No token" });
  const payload = verifyAccess(token);
  if (!payload) return res.status(401).json({ error: "Invalid or expired token" });
  req.user = payload.sub;
  next();
}

module.exports = requireAuth;
