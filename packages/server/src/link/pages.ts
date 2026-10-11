/**
 * Cred Link server: hosted pages (spec 1, 2).
 *
 * Server-rendered HTML, no client framework. Every dynamic value is escaped;
 * page configuration travels in a non-executable JSON data block, and the
 * one executable script is a static string run under a per-response nonce.
 *
 * Headers on every page: a strict Content-Security-Policy (default-src
 * 'none', nonce'd script and style, form-action limited to this service plus
 * the exact origins a form submission may be redirected to), Cache-Control
 * no-store, Referrer-Policy no-referrer, X-Content-Type-Options nosniff and
 * Cred-Request-Id. Only the embedded picker may be framed, and only by the
 * transaction's registered origin; every other page sends
 * `frame-ancestors 'none'`. No Cross-Origin-Opener-Policy is sent: the
 * popup must keep its opener.
 *
 * Message delivery (never targetOrigin '*'):
 *   popup     pages post to window.opener with the registered origin
 *   embedded  the picker iframe posts to window.parent with the registered
 *             origin and relays messages from the top-level window it opened;
 *             that window posts to window.opener (the iframe) with this
 *             service's own origin
 */

import crypto from 'node:crypto';
import type { Request, Response } from 'express';
import {
  LINK_FORM_FIELDS,
  LINK_PATHS,
  linkResultMessage,
} from '@credninja/protocol';
import type {
  LinkExitStep,
  LinkProviderSlug,
  LinkResult,
  LinkTheme,
  LinkWidgetMode,
  ScopeCatalogEntry,
} from '@credninja/protocol';
import { escapeHtml, jsonForScriptBlock, requestId } from './util.js';
import { FLAG_HINTS } from './scopes.js';

/** Where a page runs, which decides where its messages go. */
export type LinkPageContext = 'iframe' | 'top';

export interface LinkPageSecurity {
  /** The single origin allowed to frame this page, or null for 'none'. */
  frameAncestor: string | null;
  /** Origins (besides 'self') a form on this page may end up at; null when the page has no form. */
  formActions: string[] | null;
  /** connect-src 'self' instead of 'none': only the popup-mode picker (redirect-only handoff fetch). */
  connectSelf?: boolean;
}

/** Client-side configuration of the page script. */
export interface LinkPageScriptConfig {
  context: LinkPageContext;
  /** The transaction's widget mode. */
  mode: LinkWidgetMode;
  /** targetOrigin for every message this page sends itself; also the only origin an ack is accepted from. */
  target: string;
  /** iframe only: the registered origin used when relaying to window.parent. */
  parent_origin?: string;
  /** This service's origin: messages relayed by the iframe must come from it. */
  self_origin: string;
  step?: LinkExitStep;
  provider?: LinkProviderSlug;
  result?: ReturnType<typeof linkResultMessage>;
  /**
   * Result pages of popup and embedded flows (top-level window): the
   * registered redirect_uri with the result and cred_link_via=popup, used
   * when the opener is gone or no ack arrives in ack_timeout_ms.
   */
  fallback_url?: string;
  /** The provider remembered as redirect-only on a real opener loss. */
  memory_provider?: LinkProviderSlug;
  ack_timeout_ms: number;
  /** localStorage key and entry lifetime of the redirect-only memory. */
  storage_key: string;
  redirect_only_ttl_ms: number;
  /** Popup-mode picker: hand remembered providers off to redirect mode. */
  handoff?: boolean;
  /** Confirm page of a reconnect: scopes held today and labels, for the live diff. */
  reconnect?: { today: string[]; labels: Record<string, string> };
}

const PROVIDER_NAMES: Record<LinkProviderSlug, string> = {
  google: 'Google',
  github: 'GitHub',
  slack: 'Slack',
  notion: 'Notion',
  salesforce: 'Salesforce',
  linear: 'Linear',
  hubspot: 'HubSpot',
};

export function providerDisplayName(provider: LinkProviderSlug): string {
  return PROVIDER_NAMES[provider];
}

/**
 * The page script. Static text: it reads its configuration from the JSON
 * data block and posts only to the configured targetOrigin.
 *
 * Popup fallback (spec 9 Q12): a result page of a popup or embedded flow
 * posts the result to its opener and waits for cred.link.ack (from the
 * target origin and from window.opener only). On ack it closes; on timeout
 * it falls back to redirect delivery (location.replace to fallback_url).
 * With no opener at all it falls back at once and remembers the provider
 * as redirect-only in this origin's localStorage (never on a timeout). The
 * popup-mode picker hands a remembered provider off to redirect mode: it
 * records the choice with fetch, posts a step with handoff 'redirect' and
 * waits to be closed; any failure submits the form normally.
 */
/** Picker form field the page script fills: '1' (had an opener), '0', or 'handoff'. */
export const LINK_PICKER_OPENER_FIELD = 'opener';
/** Confirm form field carrying what the reconnect diff was computed against. */
export const LINK_RECONNECT_BASIS_FIELD = 'reconnect_basis';

export const LINK_PAGE_SCRIPT = `(function () {
  var el = document.getElementById('cred-link-config');
  if (!el) return;
  var c;
  try { c = JSON.parse(el.textContent || '{}'); } catch (e) { return; }
  function target() { return c.context === 'iframe' ? window.parent : window.opener; }
  function send(msg) {
    var t = target();
    if (!t || t === window) return false;
    try { t.postMessage(msg, c.target); return true; } catch (e) { return false; }
  }
  function step(name, provider, handoff) {
    var m = { type: 'cred.link.step', v: 1, step: name };
    if (provider) m.provider = provider;
    if (handoff) m.handoff = handoff;
    return send(m);
  }
  function readMemory() {
    try {
      var raw = window.localStorage.getItem(c.storage_key);
      var m = raw ? JSON.parse(raw) : {};
      return m && typeof m === 'object' && !Array.isArray(m) ? m : {};
    } catch (e) { return null; }
  }
  function remember(provider) {
    if (!provider || !c.storage_key) return;
    try {
      var m = readMemory() || {};
      m[provider] = Date.now();
      window.localStorage.setItem(c.storage_key, JSON.stringify(m));
    } catch (e) {}
  }
  function isRedirectOnly(provider) {
    var m = readMemory();
    if (!m) return false;
    var at = m[provider];
    if (typeof at !== 'number' || !isFinite(at)) return false;
    var age = Date.now() - at;
    return age >= 0 && age < c.redirect_only_ttl_ms;
  }
  function showDone() {
    var note = document.getElementById('cred-link-done');
    if (note) note.hidden = false;
  }
  if (c.step) step(c.step, c.provider);
  if (c.context === 'iframe') {
    var resultSource = null;
    window.addEventListener('message', function (ev) {
      var d = ev.data;
      if (!d || typeof d !== 'object' || d.v !== 1) return;
      if (ev.source === window.parent) {
        if (ev.origin === c.parent_origin && d.type === 'cred.link.ack' && resultSource) {
          try { resultSource.postMessage({ type: 'cred.link.ack', v: 1 }, c.self_origin); } catch (e) {}
        }
        return;
      }
      if (ev.origin !== c.self_origin) return;
      if (d.type !== 'cred.link.result' && d.type !== 'cred.link.step') return;
      if (d.type === 'cred.link.result') resultSource = ev.source;
      try { window.parent.postMessage(d, c.parent_origin); } catch (e) {}
    });
    var last = -1;
    var size = function () {
      var h = Math.ceil(document.documentElement.scrollHeight);
      if (h !== last) { last = h; send({ type: 'cred.link.resize', v: 1, height: h }); }
    };
    size();
    if (window.ResizeObserver) { new window.ResizeObserver(size).observe(document.documentElement); }
  }
  var forms = document.querySelectorAll('form[data-cred-provider]');
  for (var i = 0; i < forms.length; i++) {
    forms[i].addEventListener('submit', function (ev) {
      var form = ev.currentTarget;
      var p = form.getAttribute('data-cred-provider');
      if (!p) return;
      var openerField = form.querySelector('input[name="opener"]');
      if (openerField) openerField.value = window.opener ? '1' : '0';
      if (c.handoff && window.opener && typeof window.fetch === 'function' && isRedirectOnly(p)) {
        ev.preventDefault();
        var submitNormally = function () {
          var a = document.createElement('input');
          a.type = 'hidden'; a.name = 'action'; a.value = 'continue';
          form.appendChild(a);
          step('provider', p);
          form.submit();
        };
        var body;
        try {
          body = new URLSearchParams(new FormData(form));
          body.set('action', 'continue');
          body.set('opener', 'handoff');
        } catch (e) { submitNormally(); return; }
        window.fetch(form.action, { method: 'POST', body: body, credentials: 'include', redirect: 'manual' }).then(function (r) {
          if (r.type === 'opaqueredirect' || (r.status >= 300 && r.status < 400)) { step('provider', p, 'redirect'); }
          else { submitNormally(); }
        }, submitNormally);
        return;
      }
      step('provider', p);
    });
  }
  if (c.reconnect) {
    var confirmForm = document.getElementById('cred-link-confirm');
    var fill = function (id, list) {
      var ul = document.getElementById(id);
      if (!ul) return;
      while (ul.firstChild) ul.removeChild(ul.firstChild);
      if (list.length === 0) {
        var none = document.createElement('li');
        none.className = 'muted';
        none.textContent = 'Nothing';
        ul.appendChild(none);
        return;
      }
      for (var k = 0; k < list.length; k++) {
        var li = document.createElement('li');
        li.setAttribute('data-scope', list[k]);
        li.textContent = c.reconnect.labels[list[k]] || list[k];
        ul.appendChild(li);
      }
    };
    var update = function () {
      var selected = {};
      var inputs = confirmForm ? confirmForm.querySelectorAll('input[name="scope"]') : [];
      for (var k = 0; k < inputs.length; k++) {
        if (inputs[k].type === 'hidden' || inputs[k].checked) selected[inputs[k].value] = true;
      }
      var today = {};
      var kept = [], added = [], removed = [];
      for (var t = 0; t < c.reconnect.today.length; t++) {
        var s = c.reconnect.today[t];
        today[s] = true;
        if (selected[s]) kept.push(s); else removed.push(s);
      }
      var keys = Object.keys(selected).sort();
      for (var a = 0; a < keys.length; a++) if (!today[keys[a]]) added.push(keys[a]);
      fill('cred-reconnect-kept', kept);
      fill('cred-reconnect-added', added);
      fill('cred-reconnect-removed', removed);
    };
    if (confirmForm) confirmForm.addEventListener('change', update);
    update();
  }
  if (c.result) {
    if (c.context === 'iframe' || !c.fallback_url) {
      var delivered = send(c.result);
      if (delivered && c.context !== 'iframe') { setTimeout(function () { window.close(); }, 100); }
      showDone();
      return;
    }
    if (!window.opener) {
      remember(c.memory_provider);
      window.location.replace(c.fallback_url);
      return;
    }
    var settled = false;
    var timer = null;
    window.addEventListener('message', function (ev) {
      if (settled) return;
      if (ev.origin !== c.target || ev.source !== window.opener) return;
      var d = ev.data;
      if (!d || typeof d !== 'object' || d.type !== 'cred.link.ack' || d.v !== 1) return;
      settled = true;
      if (timer !== null) clearTimeout(timer);
      showDone();
      window.close();
    });
    send(c.result);
    timer = setTimeout(function () {
      if (settled) return;
      settled = true;
      window.location.replace(c.fallback_url);
    }, c.ack_timeout_ms);
  }
})();`;

function themeCss(theme: LinkTheme, nonce: string): string {
  const accent = theme.accent ?? '#4f46e5';
  const radius = theme.radius ?? 8;
  const font = theme.font ? `'${theme.font}', ` : '';
  const scheme = theme.colorScheme ?? 'auto';
  const light = `--bg:#ffffff;--fg:#111827;--muted:#6b7280;--card:#f9fafb;--border:#e5e7eb;`;
  const dark = `--bg:#0b0b0f;--fg:#f3f4f6;--muted:#9ca3af;--card:#16161d;--border:#2a2a33;`;
  const vars = scheme === 'dark'
    ? `:root{${dark}}`
    : scheme === 'light'
      ? `:root{${light}}`
      : `:root{${light}} @media (prefers-color-scheme: dark){:root{${dark}}}`;
  return `<style nonce="${nonce}">
${vars}
:root{--accent:${accent};--radius:${radius}px;color-scheme:${scheme === 'auto' ? 'light dark' : scheme};}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 ${font}-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif}
main{max-width:460px;margin:0 auto;padding:24px 20px}
h1{font-size:19px;margin:0 0 4px}
p{margin:6px 0}
.muted{color:var(--muted);font-size:13px}
.logo{max-height:40px;max-width:160px;display:block;margin-bottom:12px}
.card{border:1px solid var(--border);background:var(--card);border-radius:var(--radius);padding:14px;margin:14px 0}
.card h2{font-size:16px;margin:0 0 8px}
label.scope{display:flex;gap:10px;align-items:flex-start;padding:6px 0}
label.scope input{margin-top:3px;accent-color:var(--accent)}
.hint{display:inline-block;font-size:11px;color:var(--muted);border:1px solid var(--border);border-radius:999px;padding:0 6px;margin-left:4px}
.risk-high{color:#b91c1c}
button{font:inherit;border-radius:var(--radius);padding:9px 14px;border:1px solid var(--border);background:transparent;color:var(--fg);cursor:pointer}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}
code{font-size:12px}
.reconnect{border-color:var(--accent)}
.reconnect h2{font-size:16px}
.reconnect h3{font-size:14px;margin:10px 0 4px}
.reconnect ul{margin:0;padding-left:20px}
</style>`;
}

function headerHtml(theme: LinkTheme): string {
  const logo = theme.logoUrl ? `<img class="logo" src="${escapeHtml(theme.logoUrl)}" alt="">` : '';
  return logo;
}

function cspHeader(nonce: string, security: LinkPageSecurity): string {
  const formAction = security.formActions === null
    ? `'none'`
    : ["'self'", ...security.formActions].join(' ');
  const frame = security.frameAncestor ?? `'none'`;
  return [
    "default-src 'none'",
    `script-src 'nonce-${nonce}'`,
    `style-src 'nonce-${nonce}'`,
    'img-src https: data:',
    `form-action ${formAction}`,
    "base-uri 'none'",
    `frame-ancestors ${frame}`,
    security.connectSelf === true ? "connect-src 'self'" : "connect-src 'none'",
  ].join('; ');
}

/** Headers shared by every Link page and redirect. */
export function setNoStoreHeaders(res: Response): void {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Content-Type-Options', 'nosniff');
}

function sendPage(
  req: Request,
  res: Response,
  input: {
    status?: number;
    title: string;
    theme: LinkTheme;
    body: (nonce: string) => string;
    security: LinkPageSecurity;
    script?: LinkPageScriptConfig;
  },
): void {
  const nonce = crypto.randomBytes(16).toString('base64');
  requestId(req, res);
  setNoStoreHeaders(res);
  res.setHeader('Content-Security-Policy', cspHeader(nonce, input.security));
  if (input.security.frameAncestor === null) res.setHeader('X-Frame-Options', 'DENY');
  const config = input.script
    ? `<script type="application/json" id="cred-link-config">${jsonForScriptBlock(input.script)}</script>
<script nonce="${nonce}">${LINK_PAGE_SCRIPT}</script>`
    : '';
  res.status(input.status ?? 200).type('html').send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>${escapeHtml(input.title)}</title>
${themeCss(input.theme, nonce)}
</head>
<body>
<main>
${input.body(nonce)}
</main>
${config}
</body>
</html>`);
}

/** Local error page: generic text and a request id only (spec 2 fail-closed split). */
export function sendLocalErrorPage(req: Request, res: Response, status = 400): void {
  const id = requestId(req, res);
  sendPage(req, res, {
    status,
    title: 'Link unavailable',
    theme: {},
    security: { frameAncestor: null, formActions: null },
    body: () => `<h1>This link can't be used</h1>
<p>It may have expired or already been used. Go back to the app and try connecting again.</p>
<p class="muted">Request ID: <code>${escapeHtml(id)}</code></p>`,
  });
}

export interface PickerProviderView {
  provider: LinkProviderSlug;
  entries: Array<{ entry: ScopeCatalogEntry; checked: boolean; locked: boolean }>;
}

export interface PickerPageInput {
  envelope: string;
  mode: LinkWidgetMode;
  context: LinkPageContext;
  theme: LinkTheme;
  providers: PickerProviderView[];
  security: LinkPageSecurity;
  script: LinkPageScriptConfig;
  /** Shown when an update or reauth names the existing account. */
  intentNote?: string;
}

function scopeRow(provider: LinkProviderSlug, item: PickerProviderView['entries'][number]): string {
  const { entry, checked, locked } = item;
  const hints = entry.flags
    .map((f) => FLAG_HINTS[f])
    .filter((h): h is string => typeof h === 'string')
    .map((h) => `<span class="hint">${escapeHtml(h)}</span>`)
    .join('');
  const enforced = entry.enforced_by === 'cred' ? '<span class="hint">Enforced by Cred</span>' : '';
  const name = escapeHtml(LINK_FORM_FIELDS.scope);
  const value = escapeHtml(entry.scope);
  const input = locked
    ? `<input type="checkbox" checked disabled><input type="hidden" name="${name}" value="${value}">`
    : `<input type="checkbox" name="${name}" value="${value}"${checked ? ' checked' : ''}>`;
  const riskClass = entry.risk === 'high' ? ' class="risk-high"' : '';
  return `<label class="scope">${input}<span><span${riskClass}>${escapeHtml(entry.label)}</span>${locked ? '<span class="hint">Required</span>' : ''}${hints}${enforced}<br><code class="muted">${escapeHtml(provider)}: ${value}</code></span></label>`;
}

/** The provider picker with permission toggles. */
export function sendPickerPage(req: Request, res: Response, input: PickerPageInput): void {
  const appName = input.theme.appName ?? 'This app';
  const e = escapeHtml(input.envelope);
  const fieldE = escapeHtml(LINK_FORM_FIELDS.envelope);
  const fieldAction = escapeHtml(LINK_FORM_FIELDS.action);
  const fieldProvider = escapeHtml(LINK_FORM_FIELDS.provider);
  const embeddedIframe = input.mode === 'embedded' && input.context === 'iframe';
  const providerTarget = embeddedIframe ? ' target="_blank" rel="opener"' : '';
  const cancelAction = embeddedIframe ? `${LINK_PATHS.picker}?frame=iframe` : LINK_PATHS.picker;
  sendPage(req, res, {
    title: 'Connect an account',
    theme: input.theme,
    security: input.security,
    script: input.script,
    body: () => `${headerHtml(input.theme)}<h1>Connect an account</h1>
<p class="muted">${escapeHtml(appName)} is asking to connect one of your accounts. Choose what it may do.</p>
${input.intentNote ? `<p class="muted">${escapeHtml(input.intentNote)}</p>` : ''}
${input.providers.map((p) => `<form class="card" method="post" action="${escapeHtml(LINK_PATHS.picker)}" data-cred-provider="${escapeHtml(p.provider)}"${providerTarget}>
<h2>${escapeHtml(providerDisplayName(p.provider))}</h2>
<input type="hidden" name="${fieldE}" value="${e}">
<input type="hidden" name="${fieldProvider}" value="${escapeHtml(p.provider)}">
<input type="hidden" name="${LINK_PICKER_OPENER_FIELD}" value="0">
${p.entries.length === 0 ? '<p class="muted">No permissions requested.</p>' : p.entries.map((item) => scopeRow(p.provider, item)).join('\n')}
<div class="actions"><button class="primary" type="submit" name="${fieldAction}" value="continue">Continue with ${escapeHtml(providerDisplayName(p.provider))}</button></div>
</form>`).join('\n')}
<form method="post" action="${escapeHtml(cancelAction)}">
<input type="hidden" name="${fieldE}" value="${e}">
<div class="actions"><button type="submit" name="${fieldAction}" value="cancel">Cancel</button></div>
</form>`,
  });
}

/** A scope with the label shown to the user. */
export interface LabeledScope {
  scope: string;
  label: string;
}

/**
 * The reconnect diff (a connect that lands on an account this client and
 * subject already have connected): what the app can do today, and what it
 * keeps, gains and loses on confirm with the initial toggles.
 */
export interface ReconnectView {
  today: LabeledScope[];
  kept: LabeledScope[];
  added: LabeledScope[];
  removed: LabeledScope[];
}

export interface ConfirmPageInput {
  envelope: string;
  provider: LinkProviderSlug;
  theme: LinkTheme;
  accountLabel?: string;
  entries: Array<{ entry: ScopeCatalogEntry; checked: boolean; locked: boolean }>;
  reconnect?: ReconnectView;
  /** What the reconnect diff was computed against ('<grant id>:<version>' or 'none'), echoed by the form. */
  reconnectBasis: string;
  /** Shown above the form when the page is re-rendered because the account changed. */
  notice?: string;
  security: LinkPageSecurity;
  script: LinkPageScriptConfig;
}

function scopeList(id: string | null, items: LabeledScope[]): string {
  const attr = id ? ` id="${escapeHtml(id)}"` : '';
  const body = items.length === 0
    ? '<li class="muted">Nothing</li>'
    : items.map((i) => `<li data-scope="${escapeHtml(i.scope)}">${escapeHtml(i.label)}</li>`).join('');
  return `<ul${attr}>${body}</ul>`;
}

function reconnectBlock(view: ReconnectView, appName: string, providerName: string): string {
  return `<section class="card reconnect" id="cred-link-reconnect" role="note">
<h2>This ${escapeHtml(providerName)} account is already connected</h2>
<p><strong>Confirming replaces the access ${escapeHtml(appName)} has today.</strong> Anything left unchecked or not listed below will be removed.</p>
<h3>Today ${escapeHtml(appName)} can</h3>
${scopeList('cred-reconnect-today', view.today)}
<h3>After you confirm</h3>
<p class="muted">Keeps</p>
${scopeList('cred-reconnect-kept', view.kept)}
<p class="muted">Adds</p>
${scopeList('cred-reconnect-added', view.added)}
<p class="muted">Removes</p>
${scopeList('cred-reconnect-removed', view.removed)}
</section>`;
}

/** The scope confirmation screen: what the provider granted, narrowable. */
export function sendConfirmPage(req: Request, res: Response, input: ConfirmPageInput): void {
  const appName = input.theme.appName ?? 'This app';
  const name = providerDisplayName(input.provider);
  const fieldAction = escapeHtml(LINK_FORM_FIELDS.action);
  sendPage(req, res, {
    title: 'Confirm permissions',
    theme: input.theme,
    security: input.security,
    script: input.script,
    body: () => `${headerHtml(input.theme)}<h1>Confirm permissions</h1>
<p class="muted">${escapeHtml(name)} granted the permissions below${input.accountLabel ? ` for <strong>${escapeHtml(input.accountLabel)}</strong>` : ''}. ${escapeHtml(appName)} gets only what you leave checked.</p>
${input.notice ? `<p class="card" role="alert">${escapeHtml(input.notice)}</p>` : ''}
${input.reconnect ? reconnectBlock(input.reconnect, appName, name) : ''}
<form class="card" id="cred-link-confirm" method="post" action="${escapeHtml(LINK_PATHS.confirm)}">
<input type="hidden" name="${escapeHtml(LINK_FORM_FIELDS.envelope)}" value="${escapeHtml(input.envelope)}">
<input type="hidden" name="${LINK_RECONNECT_BASIS_FIELD}" value="${escapeHtml(input.reconnectBasis)}">
${input.entries.length === 0 ? '<p class="muted">No permissions were granted.</p>' : input.entries.map((item) => scopeRow(input.provider, item)).join('\n')}
<div class="actions">
<button class="primary" type="submit" name="${fieldAction}" value="confirm">Confirm</button>
<button type="submit" name="${fieldAction}" value="back">Back</button>
<button type="submit" name="${fieldAction}" value="cancel">Cancel</button>
</div>
</form>`,
  });
}

/**
 * Final page in popup and embedded modes: posts the result and closes.
 * It has no form and no control. In the embedded iframe (the picker's own
 * cancel) it is framable by the registered origin, like the picker it
 * replaces; everywhere else it sends frame-ancestors 'none'.
 */
export function sendResultPage(
  req: Request,
  res: Response,
  input: { result: LinkResult; theme: LinkTheme; script: Omit<LinkPageScriptConfig, 'result'>; frameAncestor?: string | null },
): void {
  const text = input.result.outcome === 'success'
    ? 'Your account is connected.'
    : input.result.outcome === 'exit'
      ? 'Connection cancelled.'
      : "The connection didn't complete.";
  sendPage(req, res, {
    title: 'Cred Link',
    theme: input.theme,
    security: { frameAncestor: input.frameAncestor ?? null, formActions: null },
    script: { ...input.script, result: linkResultMessage(input.result) },
    body: () => `<h1>${escapeHtml(text)}</h1>
<p id="cred-link-done" class="muted" hidden>You can close this window.</p>`,
  });
}

/** Security for the embedded picker iframe: framable by the registered origin only. */
export function embeddedPickerSecurity(origin: string, formActions: string[]): LinkPageSecurity {
  return { frameAncestor: origin, formActions };
}
