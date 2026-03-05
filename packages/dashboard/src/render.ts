import type { VaultEntry } from '@credninja/vault';
import type { ProviderConfig } from './config';

const STYLES = `
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    background: #0a0a0a;
    color: #e0e0e0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    line-height: 1.6;
    padding: 2rem;
    max-width: 960px;
    margin: 0 auto;
  }
  h1 {
    color: #00ff88;
    font-size: 1.8rem;
    margin-bottom: 0.5rem;
  }
  .subtitle {
    color: #888;
    margin-bottom: 2rem;
    font-size: 0.9rem;
  }
  .flash {
    padding: 0.75rem 1rem;
    border-radius: 6px;
    margin-bottom: 1.5rem;
    font-size: 0.9rem;
  }
  .flash-success {
    background: rgba(0, 255, 136, 0.1);
    border: 1px solid #00ff88;
    color: #00ff88;
  }
  .flash-error {
    background: rgba(255, 68, 68, 0.1);
    border: 1px solid #ff4444;
    color: #ff4444;
  }
  .section { margin-bottom: 2.5rem; }
  .section-title {
    color: #00ff88;
    font-size: 1.1rem;
    margin-bottom: 1rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-weight: 600;
  }
  .card {
    background: #1a1a2e;
    border-radius: 8px;
    padding: 1.25rem;
    margin-bottom: 1rem;
  }
  .card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin-bottom: 0.75rem;
  }
  .provider-name {
    font-size: 1.1rem;
    font-weight: 600;
    color: #fff;
  }
  .badge {
    display: inline-block;
    padding: 0.2rem 0.6rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
  }
  .badge-connected {
    background: rgba(0, 255, 136, 0.15);
    color: #00ff88;
  }
  .badge-expired {
    background: rgba(255, 170, 0, 0.15);
    color: #ffaa00;
  }
  .meta {
    display: flex;
    flex-wrap: wrap;
    gap: 1.5rem;
    font-size: 0.85rem;
    color: #999;
    margin-bottom: 0.75rem;
  }
  .meta code {
    font-family: 'SF Mono', 'Fira Code', monospace;
    color: #ccc;
    font-size: 0.8rem;
  }
  .actions {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin-top: 0.75rem;
  }
  .btn {
    display: inline-block;
    padding: 0.4rem 0.9rem;
    border-radius: 5px;
    text-decoration: none;
    font-size: 0.85rem;
    font-weight: 500;
    cursor: pointer;
    border: none;
    transition: opacity 0.15s;
  }
  .btn:hover { opacity: 0.85; }
  .btn-primary {
    background: #00ff88;
    color: #0a0a0a;
  }
  .btn-secondary {
    background: #2a2a4a;
    color: #e0e0e0;
  }
  .btn-danger {
    background: rgba(255, 68, 68, 0.2);
    color: #ff6666;
    border: 1px solid rgba(255, 68, 68, 0.3);
  }
  .connect-grid {
    display: flex;
    flex-wrap: wrap;
    gap: 0.75rem;
  }
  .connect-btn {
    background: #1a1a2e;
    color: #e0e0e0;
    padding: 0.6rem 1.2rem;
    border-radius: 6px;
    text-decoration: none;
    font-size: 0.9rem;
    border: 1px solid #2a2a4a;
    transition: border-color 0.15s, background 0.15s;
  }
  .connect-btn:hover {
    border-color: #00ff88;
    background: #1a1a3e;
  }
  pre.json-output {
    background: #111;
    border: 1px solid #2a2a4a;
    border-radius: 6px;
    padding: 1rem;
    overflow-x: auto;
    font-family: 'SF Mono', 'Fira Code', monospace;
    font-size: 0.8rem;
    color: #ccc;
    max-height: 400px;
    overflow-y: auto;
    white-space: pre-wrap;
    word-break: break-word;
  }
  .empty-state {
    color: #666;
    font-style: italic;
    padding: 1rem 0;
  }
  @media (max-width: 600px) {
    body { padding: 1rem; }
    .card-header { flex-direction: column; align-items: flex-start; }
    .meta { flex-direction: column; gap: 0.5rem; }
  }
`;

function layout(title: string, body: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title} - Cred Dashboard</title>
  <style>${STYLES}</style>
</head>
<body>
  <h1>Cred Dashboard</h1>
  <p class="subtitle">Local credential control panel</p>
  ${body}
</body>
</html>`;
}

function flashHtml(flash?: { type: string; message: string }): string {
  if (!flash) return '';
  return `<div class="flash flash-${flash.type}">${escapeHtml(flash.message)}</div>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatExpiry(entry: VaultEntry): { text: string; isExpired: boolean } {
  if (!entry.expiresAt) return { text: 'No expiry', isExpired: false };
  const now = new Date();
  const isExpired = entry.expiresAt <= now;
  const timeStr = entry.expiresAt.toLocaleString();
  return { text: timeStr, isExpired };
}

export function renderDashboard(
  providers: ProviderConfig[],
  credentials: VaultEntry[],
  flash?: { type: string; message: string }
): string {
  const connectedSlugs = new Set(credentials.map(c => c.provider));
  const unconnected = providers.filter(p => !connectedSlugs.has(p.slug));

  let credentialsHtml = '';
  if (credentials.length === 0) {
    credentialsHtml = '<p class="empty-state">No credentials stored yet. Connect a provider below.</p>';
  } else {
    credentialsHtml = credentials.map(entry => {
      const provider = providers.find(p => p.slug === entry.provider);
      const displayName = provider?.name || entry.provider;
      const expiry = formatExpiry(entry);
      const badgeClass = expiry.isExpired ? 'badge-expired' : 'badge-connected';
      const badgeText = expiry.isExpired ? 'Expired' : 'Connected';
      const scopesText = entry.scopes?.join(', ') || 'none';

      return `
        <div class="card">
          <div class="card-header">
            <span class="provider-name">${escapeHtml(displayName)}</span>
            <span class="badge ${badgeClass}">${badgeText}</span>
          </div>
          <div class="meta">
            <span>Scopes: <code>${escapeHtml(scopesText)}</code></span>
            <span>Expires: <code>${escapeHtml(expiry.text)}</code></span>
            <span>Updated: <code>${entry.updatedAt.toLocaleString()}</code></span>
          </div>
          <div class="actions">
            <a href="/refresh/${escapeHtml(entry.provider)}" class="btn btn-secondary">Refresh</a>
            <a href="/test/${escapeHtml(entry.provider)}" class="btn btn-secondary">Test</a>
            <a href="/revoke/${escapeHtml(entry.provider)}" class="btn btn-danger" onclick="return confirm('Revoke and delete this credential?')">Revoke</a>
          </div>
        </div>`;
    }).join('');
  }

  let connectHtml = '';
  if (unconnected.length > 0) {
    connectHtml = `
      <div class="section">
        <h2 class="section-title">Connect</h2>
        <div class="connect-grid">
          ${unconnected.map(p => `<a href="/connect/${p.slug}" class="connect-btn">+ ${escapeHtml(p.name)}</a>`).join('')}
        </div>
      </div>`;
  }

  // Always show reconnect option for connected providers
  let reconnectHtml = '';
  const connected = providers.filter(p => connectedSlugs.has(p.slug));
  if (connected.length > 0) {
    reconnectHtml = `
      <div class="section">
        <h2 class="section-title">Reconnect</h2>
        <div class="connect-grid">
          ${connected.map(p => `<a href="/connect/${p.slug}" class="connect-btn">${escapeHtml(p.name)}</a>`).join('')}
        </div>
      </div>`;
  }

  const body = `
    ${flashHtml(flash)}
    <div class="section">
      <h2 class="section-title">Credentials</h2>
      ${credentialsHtml}
    </div>
    ${connectHtml}
    ${reconnectHtml}
  `;

  return layout('Dashboard', body);
}

export function renderTestResult(
  providerName: string,
  result: unknown,
  error?: string
): string {
  let body = '';
  if (error) {
    body = `
      <div class="flash flash-error">${escapeHtml(error)}</div>
      <a href="/" class="btn btn-secondary">Back to Dashboard</a>
    `;
  } else {
    body = `
      <div class="section">
        <h2 class="section-title">${escapeHtml(providerName)} - Test Result</h2>
        <pre class="json-output">${escapeHtml(JSON.stringify(result, null, 2))}</pre>
      </div>
      <a href="/" class="btn btn-secondary">Back to Dashboard</a>
    `;
  }
  return layout(`Test ${providerName}`, body);
}
