import { describe, expect, it } from 'vitest';

const runLiveSmoke = process.env.RUN_WEB_BOT_AUTH_LIVE_SMOKE === '1';
const liveBaseUrl = process.env.WEB_BOT_AUTH_LIVE_BASE_URL;

const maybeDescribe = runLiveSmoke && liveBaseUrl ? describe : describe.skip;

maybeDescribe('Web Bot Auth live smoke', () => {
  it('fetches a live signed directory document', async () => {
    const url = `${liveBaseUrl!.replace(/\/$/, '')}/.well-known/http-message-signatures-directory`;
    const response = await fetch(url, {
      headers: {
        Accept: 'application/http-message-signatures-directory+json, application/json',
      },
    });

    expect(response.ok).toBe(true);
    expect(response.headers.get('content-type')).toContain('application/http-message-signatures-directory+json');
    expect(response.headers.get('signature-input')).toContain('http-message-signatures-directory');
    expect(response.headers.get('signature')).toMatch(/^sig1=:/);

    const body = await response.json() as { keys?: Array<{ kid?: string }> };
    expect(Array.isArray(body.keys)).toBe(true);
    expect(body.keys!.length).toBeGreaterThan(0);
    expect(body.keys![0]?.kid).toBeTruthy();
  });
});
