import { describe, it, expect } from 'vitest';
import { handleAuditLog } from '../tools/audit-log.js';
import { CredError } from '@credninja/sdk';

describe('cred_audit_log tool', () => {
  it('returns the caller\'s recent audit events when called with no filters', async () => {
    const entries = [
      { id: 'evt_1', action: 'delegate', service: 'github', userId: 'default', timestamp: new Date().toISOString() },
      { id: 'evt_2', action: 'use', service: 'github', userId: 'default', timestamp: new Date().toISOString() },
    ];

    let receivedParams: unknown;
    const result = await handleAuditLog(
      { user_id: 'default' },
      {
        cred: {
          getAuditLog: async (params: unknown) => {
            receivedParams = params;
            return entries;
          },
        } as any,
        appClientId: 'external-runtime',
      },
    );

    expect(result.isError).toBeUndefined();
    expect(receivedParams).toMatchObject({ userId: 'default', appClientId: 'external-runtime' });
    const payload = JSON.parse(String(result.content[0]?.text));
    expect(payload.entries).toEqual(entries);
  });

  it('passes through a service filter and returns only matching events', async () => {
    const entries = [
      { id: 'evt_1', action: 'delegate', service: 'google', userId: 'default', timestamp: new Date().toISOString() },
    ];

    let receivedParams: unknown;
    const result = await handleAuditLog(
      { user_id: 'default', service: 'google' },
      {
        cred: {
          getAuditLog: async (params: unknown) => {
            receivedParams = params;
            return entries;
          },
        } as any,
        appClientId: 'external-runtime',
      },
    );

    expect(result.isError).toBeUndefined();
    expect(receivedParams).toMatchObject({ userId: 'default', service: 'google' });
    const payload = JSON.parse(String(result.content[0]?.text));
    expect(payload.entries).toEqual(entries);
  });

  it('passes through a limit filter', async () => {
    let receivedParams: unknown;
    const result = await handleAuditLog(
      { user_id: 'default', limit: 5 },
      {
        cred: {
          getAuditLog: async (params: unknown) => {
            receivedParams = params;
            return [];
          },
        } as any,
        appClientId: 'external-runtime',
      },
    );

    expect(result.isError).toBeUndefined();
    expect(receivedParams).toMatchObject({ userId: 'default', limit: 5 });
  });

  it('returns an empty list, not an error, for an empty audit trail', async () => {
    const result = await handleAuditLog(
      { user_id: 'default' },
      {
        cred: {
          getAuditLog: async () => [],
        } as any,
        appClientId: 'external-runtime',
      },
    );

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(String(result.content[0]?.text));
    expect(payload.entries).toEqual([]);
  });

  it('surfaces a thrown CredError as a structured error, matching U3\'s pattern', async () => {
    const result = await handleAuditLog(
      { user_id: 'default' },
      {
        cred: {
          getAuditLog: async () => {
            throw new CredError('audit query not supported by this vault backend', 'not_supported', 501);
          },
        } as any,
        appClientId: 'external-runtime',
      },
    );

    expect(result.isError).toBe(true);
    const payload = JSON.parse(String(result.content[0]?.text));
    expect(payload).toMatchObject({ error: 'not_supported', statusCode: 501 });
  });
});
