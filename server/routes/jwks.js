"use strict";

const express = require("express");
const router  = express.Router();
const { jwks } = require("../lib/keys");

router.get("/.well-known/jwks.json", (req, res) => {
  res.setHeader("Cache-Control", "public, max-age=3600");
  res.json(jwks);
});

module.exports = router;
