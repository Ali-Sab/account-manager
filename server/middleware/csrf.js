"use strict";

const { doubleCsrf } = require("csrf-csrf");

const IS_PROD    = process.env.NODE_ENV === "production";
const CSRF_SECRET = process.env.CSRF_SECRET;

if (!CSRF_SECRET && IS_PROD) {
  throw new Error("CSRF_SECRET must be set in production");
}

const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  getSecret:              () => CSRF_SECRET || "dev-csrf-secret",
  getSessionIdentifier:   () => "default",
  cookieName:             IS_PROD ? "__Host-csrf" : "csrf",
  cookieOptions:          { sameSite: "strict", secure: IS_PROD, httpOnly: false, path: "/" },
  ignoredMethods:         ["GET", "HEAD", "OPTIONS"],
  skipCsrfProtection:     () => process.env.NODE_ENV === "test",
});

module.exports = { generateCsrfToken, doubleCsrfProtection };
