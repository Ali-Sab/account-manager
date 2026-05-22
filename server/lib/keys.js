"use strict";

const fs     = require("fs");
const crypto = require("crypto");
const path   = require("path");

const DATA_DIR  = process.env.DATA_DIR  || path.resolve(__dirname, "..", "..", "data");
const PRIV_PATH = process.env.PRIVATE_KEY_PATH || path.join(DATA_DIR, "keys", "private.pem");
const PUB_PATH  = process.env.PUBLIC_KEY_PATH  || path.join(DATA_DIR, "keys", "public.pem");

if (!fs.existsSync(PRIV_PATH) || !fs.existsSync(PUB_PATH)) {
  throw new Error(`RSA keys not found. Run: npm run setup\n  Expected: ${PRIV_PATH}, ${PUB_PATH}`);
}

const privateKey = fs.readFileSync(PRIV_PATH, "utf8");
const publicKey  = fs.readFileSync(PUB_PATH,  "utf8");

// Build JWKS from the public key
const keyObj    = crypto.createPublicKey(publicKey);
const { n, e }  = keyObj.export({ format: "jwk" });
const jwks = {
  keys: [{
    kty: "RSA",
    use: "sig",
    alg: "RS256",
    kid: "account-manager-1",
    n,
    e,
  }],
};

module.exports = { privateKey, publicKey, jwks };
