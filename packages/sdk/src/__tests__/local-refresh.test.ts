/**
 * Local mode refreshes an expired credential through the real native OAuth
 * adapter and a real encrypted vault. Only the provider's token endpoint is
 * stubbed, so the request form and the stored result are what a provider
 * would actually see and what the vault actually keeps.
 */
import { afterAll, afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Cred } from '../index';
import { CredVault } from '@credninja/vault';

const PASSPHRASE = 'test-passphrase-local-refresh';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const dirs: string[] = [];

afterAll(() => {
  for (const made of dirs) rmSync(made, { recursive: true, force: true });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

async function expiredGoogle(scopes: string[]) {
  const where = mkdtempSync(join(tmpdir(), 'cred-local-refresh-'));
  dirs.push(where);
  const options = { passphrase: PASSPHRASE, path: join(where, 'vault.sqlite'), storage: 'sqlite' as const };
  const vault = new CredVault(options);
  await vault.init();
  await vault.store({
    provider: 'google',
    userId: 'alice',
    accessToken: 'synthetic-expired-access',
    refreshToken: 'synthetic-stored-refresh',
    scopes,
    expiresAt: new Date(Date.now() - 60_000),
  });
  const cred = new Cred({
    mode: 'local',
    vault: options,
    providers: { google: { clientId: 'cid-local', clientSecret: 'csecret-local' } },
  });
  return { cred, vault };
}

function tokenEndpoint(reply: Record<string, unknown>, status = 200) {
  const forms: URLSearchParams[] = [];
  const fetchStub = vi.fn(async (url: string | URL, init?: RequestInit) => {
    if (String(url) !== TOKEN_URL) throw new Error(`unexpected fetch ${String(url)}`);
    forms.push(new URLSearchParams(String(init?.body ?? '')));
    return new Response(JSON.stringify(reply), { status, headers: { 'content-type': 'application/json' } });
  });
  vi.stubGlobal('fetch', fetchStub);
  return { forms, fetchStub };
}

const SCOPES = ['https://www.googleapis.com/auth/calendar.readonly', 'https://www.googleapis.com/auth/gmail.readonly'];

describe('local mode refresh of an expired credential', () => {
  it('sends the stored refresh token and returns and stores the refreshed access token', async () => {
    const { cred, vault } = await expiredGoogle(SCOPES);
    const { forms } = tokenEndpoint({ access_token: 'synthetic-refreshed-access', expires_in: 3600 });

    const result = await cred.delegate({ service: 'google', userId: 'alice', appClientId: 'local' });

    expect(forms).toHaveLength(1);
    expect(forms[0].get('grant_type')).toBe('refresh_token');
    expect(forms[0].get('refresh_token')).toBe('synthetic-stored-refresh');
    expect(forms[0].get('client_id')).toBe('cid-local');
    expect(result.accessToken).toBe('synthetic-refreshed-access');
    const stored = await vault.getStored({ provider: 'google', userId: 'alice' });
    expect(stored?.accessToken).toBe('synthetic-refreshed-access');
    // No refresh_token in the reply: the stored one is kept, not erased.
    expect(stored?.refreshToken).toBe('synthetic-stored-refresh');
    // No scope in the reply: the authority is unchanged (RFC 6749 section 5.1).
    expect(stored?.scopes).toEqual(SCOPES);
    expect(stored!.expiresAt!.getTime()).toBeGreaterThan(Date.now());
  });

  it('stores the scope a refresh states, and a rotated refresh token', async () => {
    const { cred, vault } = await expiredGoogle(SCOPES);
    tokenEndpoint({
      access_token: 'synthetic-narrowed-access',
      refresh_token: 'synthetic-rotated-refresh',
      expires_in: 3600,
      scope: SCOPES[0],
    });

    await cred.delegate({ service: 'google', userId: 'alice', appClientId: 'local', scopes: [SCOPES[0]] });

    const stored = await vault.getStored({ provider: 'google', userId: 'alice' });
    expect(stored?.scopes).toEqual([SCOPES[0]]);
    expect(stored?.refreshToken).toBe('synthetic-rotated-refresh');
  });

  it('refuses when the provider rejects the refresh, and leaves the row as it was', async () => {
    const { cred, vault } = await expiredGoogle(SCOPES);
    tokenEndpoint({ error: 'invalid_grant' }, 400);

    await expect(cred.delegate({ service: 'google', userId: 'alice', appClientId: 'local' })).rejects.toThrow();

    const stored = await vault.getStored({ provider: 'google', userId: 'alice' });
    expect(stored?.accessToken).toBe('synthetic-expired-access');
    expect(stored?.refreshToken).toBe('synthetic-stored-refresh');
  });
});
