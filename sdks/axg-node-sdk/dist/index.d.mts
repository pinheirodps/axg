import * as jose from 'jose';

interface AxgPassportClaims extends jose.JWTPayload {
    iss: 'axg-engine';
    sub: string;
    aud: string;
    decision: 'ALLOW' | 'SUGGEST' | 'CONFIRM' | 'BLOCK';
    action_type: string;
    payload_hash: string;
}
interface VerificationOptions {
    appId: string;
    tenantId?: string;
    allowedActionTypes?: string[];
    publicKey?: string;
}
declare class AxgVerificationError extends Error {
    code: string;
    constructor(message: string, code: string);
}
/**
 * Deterministic SHA-256 hash of a payload.
 * Matches AXG (Python) implementation.
 */
declare function hashPayload(payload: Record<string, any>): string;
/**
 * Top-level utility for quick Passport verification.
 */
declare function verifyPassport(token: string, payload: Record<string, any>, options: VerificationOptions, jwksUrl?: string): Promise<AxgPassportClaims>;
declare class AxgClient {
    private jwksUrl;
    constructor(baseUrl: string);
    verifyPassport(token: string, payload: Record<string, any>, options: VerificationOptions): Promise<AxgPassportClaims>;
}

export { AxgClient, type AxgPassportClaims, AxgVerificationError, type VerificationOptions, hashPayload, verifyPassport };
