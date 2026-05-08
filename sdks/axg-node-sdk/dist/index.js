"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var index_exports = {};
__export(index_exports, {
  AxgClient: () => AxgClient,
  AxgVerificationError: () => AxgVerificationError,
  hashPayload: () => hashPayload,
  verifyPassport: () => verifyPassport
});
module.exports = __toCommonJS(index_exports);
var jose = __toESM(require("jose"));
var import_json_stable_stringify = __toESM(require("json-stable-stringify"));
var import_crypto = require("crypto");
var AxgVerificationError = class extends Error {
  constructor(message, code) {
    super(message);
    this.code = code;
    this.name = "AxgVerificationError";
  }
  code;
};
function hashPayload(payload) {
  const serialized = (0, import_json_stable_stringify.default)(payload);
  if (serialized === void 0) {
    throw new Error("Failed to serialize payload: result was undefined");
  }
  return (0, import_crypto.createHash)("sha256").update(serialized).digest("hex");
}
async function verifyPassport(token, payload, options, jwksUrl) {
  let key;
  if (options.publicKey) {
    key = await jose.importSPKI(options.publicKey, "RS256");
  } else {
    if (!jwksUrl) {
      throw new Error("Either publicKey or jwksUrl must be provided.");
    }
    const jwks = jose.createRemoteJWKSet(new URL(jwksUrl));
    key = jwks;
  }
  try {
    const { payload: claims } = await jose.jwtVerify(token, key, {
      issuer: "axg-engine",
      audience: options.appId,
      algorithms: ["RS256"]
    });
    const passport = claims;
    if (passport.decision !== "ALLOW") {
      throw new AxgVerificationError(
        `Action not allowed by AXG decision: ${passport.decision}`,
        "DECISION_NOT_ALLOWED"
      );
    }
    if (options.tenantId && passport.tenant_id !== options.tenantId) {
      throw new AxgVerificationError(
        `Tenant ID mismatch: expected ${options.tenantId}, got ${passport.tenant_id}`,
        "TENANT_ID_MISMATCH"
      );
    }
    if (options.allowedActionTypes && !options.allowedActionTypes.includes(passport.action_type)) {
      throw new AxgVerificationError(
        `Action type mismatch: ${passport.action_type}`,
        "ACTION_TYPE_MISMATCH"
      );
    }
    if (!passport.payload_hash) {
      throw new AxgVerificationError("Missing payload_hash claim in passport.", "MISSING_PAYLOAD_HASH");
    }
    if (claims.payload_hash !== hashPayload(payload)) {
      throw new AxgVerificationError("Payload hash mismatch. Possible tampering detected.", "PAYLOAD_TAMPERED");
    }
    return passport;
  } catch (err) {
    if (err instanceof AxgVerificationError) throw err;
    throw new AxgVerificationError(
      `Passport verification failed: ${err.message}`,
      err.code || "VERIFICATION_FAILED"
    );
  }
}
var AxgClient = class {
  jwksUrl;
  constructor(baseUrl) {
    this.jwksUrl = new URL(".well-known/jwks.json", baseUrl).toString();
  }
  async verifyPassport(token, payload, options) {
    return verifyPassport(token, payload, options, this.jwksUrl);
  }
};
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  AxgClient,
  AxgVerificationError,
  hashPayload,
  verifyPassport
});
