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
  axgBaseUrl: string;
  allowedActionTypes?: string[];
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
  return createHash('sha256').update(serialized).digest('hex');
}

export class AxgClient {
  private jwks: ReturnType<typeof jose.createRemoteJWKSet>;

  constructor(private baseUrl: string) {
    const url = new URL('.well-known/jwks.json', baseUrl).toString();
    this.jwks = jose.createRemoteJWKSet(new URL(url));
  }

  /**
   * Verifies an AXG Decision Token (Passport).
   * 
   * Checks:
   * 1. Cryptographic signature (RS256 via JWKS)
   * 2. Token expiration (exp)
   * 3. Issuer (iss)
   * 4. Audience (aud)
   * 5. Payload integrity (payload_hash)
   */
  async verifyPassport(
    token: string,
    payload: Record<string, any>,
    options: VerificationOptions
  ): Promise<AxgPassportClaims> {
    try {
      const { payload: claims } = await jose.jwtVerify(token, this.jwks, {
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

      // 2. Action Type Check (Optional but recommended)
      if (options.allowedActionTypes && !options.allowedActionTypes.includes(passport.action_type)) {
        throw new AxgVerificationError(
          `Action type mismatch: ${passport.action_type}`,
          'ACTION_TYPE_MISMATCH'
        );
      }

      // 3. Payload Integrity Check (Anti-tampering)
      const currentHash = hashPayload(payload);
      if (passport.payload_hash !== currentHash) {
        throw new AxgVerificationError(
          'Payload hash mismatch. Possible tampering detected.',
          'PAYLOAD_TAMPERED'
        );
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
}
