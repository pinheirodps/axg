import { describe, it, expect, vi, beforeEach } from 'vitest';
import { hashPayload, AxgClient, AxgVerificationError } from './index';
import * as jose from 'jose';

// Correctly mock the jose module for ESM
vi.mock('jose', async (importOriginal) => {
  const mod = await importOriginal<any>();
  return {
    ...mod,
    jwtVerify: vi.fn(),
    createRemoteJWKSet: vi.fn(() => () => ({})), // Returns a dummy getter
  };
});

describe('AXG Node.js SDK', () => {
  describe('hashPayload', () => {
    it('should produce a deterministic hash regardless of key order', () => {
      const p1 = { amount: 100, merchant: 'Uber' };
      const p2 = { merchant: 'Uber', amount: 100 };
      
      expect(hashPayload(p1)).toBe(hashPayload(p2));
      // Standard SHA-256 for {"amount":100,"merchant":"Uber"} (Python-compatible)
      expect(hashPayload(p1)).toBe('3e66ff52a65f3c436352e70d6cf0b4a6391f921706147bd1b06c13eae608795c');
    });
  });

  describe('AxgClient', () => {
    const baseUrl = 'https://axg.example.com';
    const appId = 'test-app';
    
    beforeEach(() => {
      vi.clearAllMocks();
    });

    it('should verify a valid passport successfully', async () => {
      const executionId = 'exec-123';
      const actionType = 'create_expense';
      const payload = { amount: 100 };
      const payloadHash = hashPayload(payload);
      
      const mockClaims = {
        iss: 'axg-engine',
        aud: appId,
        sub: executionId,
        decision: 'ALLOW',
        action_type: actionType,
        payload_hash: payloadHash,
      };

      (jose.jwtVerify as any).mockResolvedValue({
        payload: mockClaims,
        protectedHeader: { alg: 'RS256' },
      });

      const client = new AxgClient(baseUrl);
      const result = await client.verifyPassport('dummy-token', payload, {
        appId,
        axgBaseUrl: baseUrl,
      });

      expect(result.sub).toBe(executionId);
      expect(result.decision).toBe('ALLOW');
      expect(jose.jwtVerify).toHaveBeenCalled();
    });

    it('should throw error if decision is not ALLOW', async () => {
      (jose.jwtVerify as any).mockResolvedValue({
        payload: {
          iss: 'axg-engine',
          aud: appId,
          decision: 'CONFIRM',
        },
      });

      const client = new AxgClient(baseUrl);
      await expect(client.verifyPassport('token', {}, { appId, axgBaseUrl: baseUrl }))
        .rejects.toThrow(AxgVerificationError);
    });

    it('should throw error if payload hash mismatch (tampering)', async () => {
      const originalPayload = { amount: 100 };
      const tamperedPayload = { amount: 1000 };
      
      (jose.jwtVerify as any).mockResolvedValue({
        payload: {
          iss: 'axg-engine',
          aud: appId,
          decision: 'ALLOW',
          payload_hash: hashPayload(originalPayload),
        },
      });

      const client = new AxgClient(baseUrl);
      await expect(client.verifyPassport('token', tamperedPayload, { appId, axgBaseUrl: baseUrl }))
        .rejects.toThrow('Payload hash mismatch');
    });

    it('should throw error if action type mismatch', async () => {
      (jose.jwtVerify as any).mockResolvedValue({
        payload: {
          iss: 'axg-engine',
          aud: appId,
          decision: 'ALLOW',
          action_type: 'wrong_action',
          payload_hash: hashPayload({}),
        },
      });

      const client = new AxgClient(baseUrl);
      await expect(client.verifyPassport('token', {}, { 
        appId, 
        axgBaseUrl: baseUrl,
        allowedActionTypes: ['correct_action']
      }))
        .rejects.toThrow('Action type mismatch');
    });

    it('should wrap generic errors into AxgVerificationError', async () => {
      (jose.jwtVerify as any).mockRejectedValue(new Error('JWT Expired'));

      const client = new AxgClient(baseUrl);
      await expect(client.verifyPassport('token', {}, { appId, axgBaseUrl: baseUrl }))
        .rejects.toThrow(AxgVerificationError);
    });
  });
});
