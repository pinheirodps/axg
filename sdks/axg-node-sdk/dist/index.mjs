// src/index.ts
import * as jose from "jose";
import stringify from "json-stable-stringify";
import { createHash } from "crypto";
var AxgVerificationError = class extends Error {
  constructor(message, code) {
    super(message);
    this.code = code;
    this.name = "AxgVerificationError";
  }
  code;
};
function hashPayload(payload) {
  const serialized = stringify(payload);
  if (serialized === void 0) {
    throw new Error("Failed to serialize payload: result was undefined");
  }
  return createHash("sha256").update(serialized).digest("hex");
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
export {
  AxgClient,
  AxgVerificationError,
  hashPayload,
  verifyPassport
};
