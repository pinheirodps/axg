import { describe, expect, it } from 'vitest';
import { APPROVAL_META_KEY, AxgApprovalError, AxgClient, submitApproval } from './index';

const APPROVED = { execution_id: 'e1', outcome: 'approved', passport: 'jwt', passport_id: 't1', actionable_payload: { a: 1 } };
const SUBMISSION = { ticket: 'tk', actionablePayload: { a: 1 }, approver: { id: 'user-1', role: 'end_user' } };

function fakeFetch(status: number, body: unknown, seen: Request[] = []): typeof fetch {
  return (async (input: any, init?: any) => {
    seen.push(new Request(input, init));
    if (body instanceof Error) throw body;
    return new Response(typeof body === 'string' ? body : JSON.stringify(body), { status });
  }) as typeof fetch;
}

describe('submitApproval', () => {
  it('sends the ticket, the payload and the approver', async () => {
    const seen: Request[] = [];
    const result = await submitApproval('https://axg.test', 'key', SUBMISSION, fakeFetch(200, APPROVED, seen));
    expect(result.passport).toBe('jwt');
    expect(seen[0].url).toBe('https://axg.test/v1/approvals');
    expect(seen[0].headers.get('authorization')).toBe('Bearer key');
    expect(await seen[0].json()).toEqual({
      ticket: 'tk', actionable_payload: { a: 1 }, approver: { id: 'user-1', role: 'end_user' }, outcome: 'approve',
    });
  });

  it('raises AXG refusals with their status and reason', async () => {
    const refusal = submitApproval('https://axg.test/', 'key', SUBMISSION,
      fakeFetch(403, { detail: "This action must be approved by the role 'tenant_admin'" }));
    await expect(refusal).rejects.toMatchObject({ statusCode: 403, message: expect.stringContaining('tenant_admin') });
    await expect(submitApproval('https://axg.test', 'key', SUBMISSION, fakeFetch(409, 'plain text')))
      .rejects.toMatchObject({ statusCode: 409, message: expect.stringContaining('plain text') });
  });

  it('reports an outage as 503 and validates the outcome', async () => {
    await expect(submitApproval('https://axg.test', 'key', SUBMISSION, fakeFetch(0, new TypeError('fetch failed'))))
      .rejects.toBeInstanceOf(AxgApprovalError);
    await expect(submitApproval('https://axg.test', 'key', { ...SUBMISSION, outcome: 'maybe' as any }))
      .rejects.toBeInstanceOf(TypeError);
  });

  it('works through AxgClient, which needs an API key', async () => {
    const denied = { ...APPROVED, outcome: 'denied', passport: null, passport_id: null, actionable_payload: {} };
    const client = new AxgClient('https://axg.test/', 'key');
    expect((await client.submitApproval({ ...SUBMISSION, outcome: 'deny' }, fakeFetch(200, denied))).outcome).toBe('denied');
    await expect(new AxgClient('https://axg.test/').submitApproval(SUBMISSION)).rejects.toBeInstanceOf(TypeError);
  });

  it('shares the approval meta key with the integrations', () => {
    expect(APPROVAL_META_KEY).toBe('io.axg/approval');
  });
});
