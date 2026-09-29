import * as jose from 'jose';
import stringify from 'json-stable-stringify';
import { createHash } from 'crypto';

export interface AxgPassportClaims extends jose.JWTPayload {
  iss: 'axg-engine';
  sub: string; // execution_id
  aud: string; // app_id
  decision: 'ALLOW' | 'SUGGEST' | 'CONFIRM' | 'BLOCK';
  action_type: string;
  payload_hash: string;
  // Passport v2
  ver?: number;
  tenant_id?: string;
  azp?: string; // client that requested the decision
  policy?: string; // plugin@version
}

/** Single-use enforcement for Passports (v2 carries a jti). */
export interface ReplayCache {
  checkAndStore(jti: string, expiresAt: number): boolean | Promise<boolean>;
}

/** Process-local replay protection. Use a shared store (e.g. Redis SET NX) across replicas. */
export class InMemoryReplayCache implements ReplayCache {
  private seen = new Map<string, number>();

  checkAndStore(jti: string, expiresAt: number): boolean {
    const now = Math.floor(Date.now() / 1000);
    for (const [key, exp] of this.seen) if (exp <= now) this.seen.delete(key);
    if (this.seen.has(jti)) return false;
    this.seen.set(jti, expiresAt);
    return true;
  }
}

export interface VerificationOptions {
  appId: string;
  tenantId?: string;
  allowedActionTypes?: string[];
  publicKey?: string; // Optional local public key (PEM) to skip JWKS fetch
  replayCache?: ReplayCache; // Reject a Passport presented more than once (needs Passport v2)
}

export class AxgVerificationError extends Error {
  constructor(message: string, public code: string) {
    super(message);
    this.name = 'AxgVerificationError';
  }
}

function serialize(payload: Record<string, any>): string {
  const serialized = stringify(payload);
  if (serialized === undefined) {
    throw new Error('Failed to serialize payload: result was undefined');
  }
  return serialized;
}

/**
 * Canonical SHA-256 hash used by Passport v2 (sorted keys, UTF-8, ECMAScript numbers).
 * Byte-identical to AXG core and the Python SDK (tests/fixtures/canonical_vectors.json).
 */
export function hashPayload(payload: Record<string, any>): string {
  return createHash('sha256').update(serialize(payload)).digest('hex');
}

/** Passport v1 hash: Python's json.dumps escaped every non-ASCII UTF-16 unit as \uXXXX. */
export function legacyHashPayload(payload: Record<string, any>): string {
  const escaped = serialize(payload).replace(
    /[\u0080-￿]/g,
    (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'),
  );
  return createHash('sha256').update(escaped).digest('hex');
}

/**
 * Top-level utility for quick Passport verification.
 */
export async function verifyPassport(
  token: string,
  payload: Record<string, any>,
  options: VerificationOptions,
  jwksUrl?: string
): Promise<AxgPassportClaims> {
  let key: any;

  if (options.publicKey) {
    key = await jose.importSPKI(options.publicKey, 'RS256');
  } else {
    if (!jwksUrl) {
      throw new Error('Either publicKey or jwksUrl must be provided.');
    }
    const jwks = jose.createRemoteJWKSet(new URL(jwksUrl));
    key = jwks;
  }

  try {
    const { payload: claims } = await jose.jwtVerify(token, key, {
      issuer: 'axg-engine',
      audience: options.appId,
      algorithms: ['RS256'],
    });

    const passport = claims as AxgPassportClaims;

    // 1. Decision Check
    if (passport.decision !== 'ALLOW') {
      throw new AxgVerificationError(
        `Action not allowed by AXG decision: ${passport.decision}`,
        'DECISION_NOT_ALLOWED'
      );
    }

    // 2. Tenant Check (if provided)
    if (options.tenantId && passport.tenant_id !== options.tenantId) {
       throw new AxgVerificationError(
          `Tenant ID mismatch: expected ${options.tenantId}, got ${passport.tenant_id}`,
          'TENANT_ID_MISMATCH'
       );
    }

    // 3. Action Type Check (Optional but recommended)
    if (options.allowedActionTypes && !options.allowedActionTypes.includes(passport.action_type)) {
      throw new AxgVerificationError(
        `Action type mismatch: ${passport.action_type}`,
        'ACTION_TYPE_MISMATCH'
      );
    }

    // 4. Payload Integrity check
    if (!passport.payload_hash) {
      throw new AxgVerificationError('Missing payload_hash claim in passport.', 'MISSING_PAYLOAD_HASH');
    }

    const expectedHash = passport.ver === 2 ? hashPayload(payload) : legacyHashPayload(payload);
    if (claims.payload_hash !== expectedHash) {
      throw new AxgVerificationError('Payload hash mismatch. Possible tampering detected.', 'PAYLOAD_TAMPERED');
    }

    // 5. Replay protection (single use within the validity window)
    if (options.replayCache) {
      if (!passport.jti) {
        throw new AxgVerificationError('Passport has no jti; replay protection needs Passport v2.', 'MISSING_JTI');
      }
      if (!(await options.replayCache.checkAndStore(passport.jti, Number(passport.exp)))) {
        throw new AxgVerificationError('Passport was already used.', 'PASSPORT_REPLAYED');
      }
    }

    return passport;
  } catch (err: any) {
    if (err instanceof AxgVerificationError) throw err;
    
    throw new AxgVerificationError(
      `Passport verification failed: ${err.message}`,
      err.code || 'VERIFICATION_FAILED'
    );
  }
}

export class AxgClient {
  private jwksUrl: string;

  constructor(baseUrl: string) {
    this.jwksUrl = new URL('.well-known/jwks.json', baseUrl).toString();
  }

  async verifyPassport(
    token: string,
    payload: Record<string, any>,
    options: VerificationOptions
  ): Promise<AxgPassportClaims> {
    return verifyPassport(token, payload, options, this.jwksUrl);
  }
}
