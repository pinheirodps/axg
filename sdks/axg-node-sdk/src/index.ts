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
}

export interface VerificationOptions {
  appId: string;
  tenantId?: string;
  allowedActionTypes?: string[];
  publicKey?: string; // Optional local public key (PEM) to skip JWKS fetch
}

export class AxgVerificationError extends Error {
  constructor(message: string, public code: string) {
    super(message);
    this.name = 'AxgVerificationError';
  }
}

/**
 * Deterministic SHA-256 hash of a payload.
 * Matches AXG (Python) implementation.
 */
export function hashPayload(payload: Record<string, any>): string {
  const serialized = stringify(payload);
  if (serialized === undefined) {
    throw new Error('Failed to serialize payload: result was undefined');
  }
  return createHash('sha256').update(serialized).digest('hex');
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

    if (claims.payload_hash !== hashPayload(payload)) {
      throw new AxgVerificationError('Payload hash mismatch. Possible tampering detected.', 'PAYLOAD_TAMPERED');
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
