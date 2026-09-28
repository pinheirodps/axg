import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { createHash } from 'crypto';
import * as jose from 'jose';
import stringify from 'json-stable-stringify';
import {
  AxgClient,
  AxgVerificationError,
  InMemoryReplayCache,
  hashPayload,
  legacyHashPayload,
  verifyPassport,
} from './index';

// Shared with AXG core and the Python SDK: any divergence breaks all three test suites
const VECTORS: { name: string; input: string; canonical: string; sha256: string }[] = JSON.parse(
  readFileSync(resolve(__dirname, '../../../tests/fixtures/canonical_vectors.json'), 'utf8'),
);
const PAYLOAD = { category: 'Alimentação', amount: 1500, merchant: 'Padaria São João' };

let privateKey: jose.KeyLike;
let publicKey: string;

beforeAll(async () => {
  const pair = await jose.generateKeyPair('RS256', { extractable: true });
  privateKey = pair.privateKey;
  publicKey = await jose.exportSPKI(pair.publicKey);
});

async function passport(claims: Record<string, unknown>): Promise<string> {
  return new jose.SignJWT({ decision: 'ALLOW', action_type: 'create_expense', tenant_id: 'tenant_a', ...claims })
    .setProtectedHeader({ alg: 'RS256' })
    .setIssuer('axg-engine')
    .setAudience('finnorte')
    .setSubject('exec_1')
    .setIssuedAt()
    .setNotBefore('0s')
    .setExpirationTime('5m')
    .sign(privateKey);
}

async function expectCode(promise: Promise<unknown>, code: string) {
  await expect(promise).rejects.toMatchObject({ name: 'AxgVerificationError', code });
}

describe('canonical hashing (shared vectors)', () => {
  it.each(VECTORS.map((v) => [v.name, v] as const))('%s', (_name, vector) => {
    const value = JSON.parse(vector.input);
    expect(stringify(value)).toBe(vector.canonical);
    expect(hashPayload(value)).toBe(vector.sha256);
  });

  it('legacy hash escapes non-ASCII like Python json.dumps', () => {
    const escaped = '{"amount":1500,"category":"Alimenta\\u00e7\\u00e3o","merchant":"Padaria S\\u00e3o Jo\\u00e3o"}';
    expect(legacyHashPayload(PAYLOAD)).toBe(createHash('sha256').update(escaped).digest('hex'));
    expect(legacyHashPayload({ a: 1 })).toBe(hashPayload({ a: 1 }));
  });

  it('rejects values that cannot be serialized', () => {
    expect(() => hashPayload(undefined as unknown as Record<string, any>)).toThrow('Failed to serialize payload');
  });
});

describe('Passport v2 verification', () => {
  it('verifies accented payloads with the canonical hash', async () => {
    const token = await passport({ ver: 2, jti: 'j1', payload_hash: hashPayload(PAYLOAD) });
    const claims = await verifyPassport(token, PAYLOAD, { appId: 'finnorte', tenantId: 'tenant_a', publicKey });
    expect(claims.ver).toBe(2);
  });

  it('still verifies v1 passports with the legacy hash', async () => {
    const token = await passport({ payload_hash: legacyHashPayload(PAYLOAD) });
    await expect(verifyPassport(token, PAYLOAD, { appId: 'finnorte', publicKey })).resolves.toBeTruthy();
  });

  it('rejects a tampered payload', async () => {
    const token = await passport({ ver: 2, jti: 'j2', payload_hash: hashPayload(PAYLOAD) });
    await expectCode(verifyPassport(token, { ...PAYLOAD, amount: 15000 }, { appId: 'finnorte', publicKey }), 'PAYLOAD_TAMPERED');
  });

  it('rejects a replayed passport', async () => {
    const replayCache = new InMemoryReplayCache();
    const token = await passport({ ver: 2, jti: 'j3', payload_hash: hashPayload(PAYLOAD) });
    await verifyPassport(token, PAYLOAD, { appId: 'finnorte', publicKey, replayCache });
    await expectCode(verifyPassport(token, PAYLOAD, { appId: 'finnorte', publicKey, replayCache }), 'PASSPORT_REPLAYED');
  });

  it('requires a jti when replay protection is on', async () => {
    const token = await passport({ payload_hash: legacyHashPayload(PAYLOAD) });
    await expectCode(
      verifyPassport(token, PAYLOAD, { appId: 'finnorte', publicKey, replayCache: new InMemoryReplayCache() }),
      'MISSING_JTI',
    );
  });

  it('rejects a foreign tenant', async () => {
    const token = await passport({ ver: 2, jti: 'j4', payload_hash: hashPayload(PAYLOAD) });
    await expectCode(verifyPassport(token, PAYLOAD, { appId: 'finnorte', tenantId: 'tenant_b', publicKey }), 'TENANT_ID_MISMATCH');
  });

  it('client forwards the replay cache', async () => {
    const client = new AxgClient('https://axg.example.com/');
    const replayCache = new InMemoryReplayCache();
    const token = await passport({ ver: 2, jti: 'j5', payload_hash: hashPayload(PAYLOAD) });
    await client.verifyPassport(token, PAYLOAD, { appId: 'finnorte', publicKey, replayCache });
    await expect(client.verifyPassport(token, PAYLOAD, { appId: 'finnorte', publicKey, replayCache })).rejects.toBeInstanceOf(
      AxgVerificationError,
    );
  });
});

describe('InMemoryReplayCache', () => {
  it('forgets expired entries', () => {
    const cache = new InMemoryReplayCache();
    const now = Math.floor(Date.now() / 1000);
    expect(cache.checkAndStore('old', now - 1)).toBe(true);
    expect(cache.checkAndStore('old', now + 60)).toBe(true);
    expect(cache.checkAndStore('old', now + 60)).toBe(false);
  });
});
