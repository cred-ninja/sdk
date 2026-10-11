# @credninja/link

Cred Link: a drop-in account-connection widget. Your user picks a provider, completes that provider's OAuth flow on Cred-hosted pages, confirms granular permissions, and your app receives a `connection_id`. Raw provider credentials never reach your frontend, your backend or your agents.

Vanilla JS, no runtime dependencies beyond `@credninja/protocol`. For React, see [`@credninja/link-react`](../link-react).

## Install

```bash
npm install @credninja/link
```

## How it works

1. **Your backend** pushes the request to Cred (`POST /link/v1/par`) with client authentication. It names the user (`subject`, from your own session), the providers and scopes, your registered `redirect_uri` and `origin`, and a `state` value. Cred returns a single-use `request_uri`, valid for 10 minutes.
2. **The browser** hands that `request_uri` to the widget as `token`. The widget opens the hosted flow and reports the outcome to `onSuccess`, `onError` or `onExit`.
3. **Your backend** activates the connection (`POST /link/v1/connections/:id/activate`) with the one-time `code` and the `subject` from its own current session.

The browser never supplies authoritative scopes or identity. That is why the widget has no `client_id`, `subject`, `redirect_uri` or `state` option (it throws if you pass one), and why `providers` and `scopes` on the widget can only narrow what your backend pushed.

## Activation: the connection is pending until your backend activates it

`onSuccess` does not mean the account is usable. The connection and its grant are written as `pending`. Nothing can use them until your backend calls:

```
POST /link/v1/connections/:id/activate
{ "code": "<one-time code from onSuccess>", "subject": "<the user in your backend's current session>" }
```

Take `subject` from your server-side session, never from the request body, the query string or anything else the browser sends. Cred compares it with the subject your backend pushed; on any mismatch it returns the opaque `401 {"error":"access_denied"}` and revokes the pending connection. This is what stops consent phishing (an attacker starts a flow under their own account and sends the hosted page to a victim) and connection injection (a browser hands your backend someone else's `connection_id`). A connection that is never activated is revoked at the provider when the transaction expires.

Also compare the echoed `state` with the value you pushed for this session before activating.

## End-to-end example (popup mode)

Backend (pseudocode, any framework). Credentials come from the environment.

```ts
// 1. Mint a widget token for the signed-in user.
app.post('/api/cred/link-token', requireLogin, async (req, res) => {
  const state = randomUrlSafeString(32);
  req.session.credLinkState = state;

  const r = await fetch('https://link.cred.ninja/link/v1/par', {
    method: 'POST',
    headers: {
      // client_secret_basic shown; private_key_jwt is also supported
      authorization: 'Basic ' + base64(`${process.env.CRED_LINK_CLIENT_ID}:${process.env.CRED_LINK_CLIENT_SECRET}`),
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      intent: 'connect',
      subject: req.session.userId,          // from YOUR session
      subject_type: 'user',
      providers: ['google', 'slack'],
      scopes: { google: ['calendar.readonly', 'gmail.send'], slack: ['chat:write'] },
      required_scopes: { google: ['calendar.readonly'] },
      redirect_uri: 'https://app.example.com/cred/return', // exact match with your registration
      origin: 'https://app.example.com',                   // exact match with your registration
      state,
    }),
  });
  const { request_uri } = await r.json();   // 201 { request_uri: 'urn:cred:link:...', expires_in: 600 }
  res.json({ token: request_uri });
});

// 3. Activate what the browser reports.
app.post('/api/cred/connections', requireLogin, async (req, res) => {
  const { connection_id, code, state } = req.body;
  if (state !== req.session.credLinkState) return res.status(400).end();

  const r = await fetch(
    `https://link.cred.ninja/link/v1/connections/${encodeURIComponent(connection_id)}/activate`,
    {
      method: 'POST',
      headers: { authorization: credLinkClientAuth(), 'content-type': 'application/json' },
      body: JSON.stringify({ code, subject: req.session.userId }), // subject from YOUR session, never req.body
    },
  );
  if (!r.ok) return res.status(400).json({ error: 'activation_failed' }); // opaque 401 on any mismatch
  const connection = await r.json(); // status 'active'
  await db.connections.insert({ userId: req.session.userId, connectionId: connection.connection_id });
  res.json({ ok: true });
});
```

Browser:

```js
import { Cred } from '@credninja/link';

// Fetch the token before the click: open() must run inside the click itself
// or the browser blocks the popup.
const { token } = await (await fetch('/api/cred/link-token', { method: 'POST' })).json();

const link = Cred.link({
  token,
  theme: { accent: '#4f46e5', colorScheme: 'auto' },
  onSuccess: async ({ connection_id, code, state, provider, scopes }) => {
    await fetch('/api/cred/connections', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ connection_id, code, state }),
    });
  },
  onError: ({ error, request_id }) => showError(error, request_id),
  onExit: ({ step, provider }) => track('cred_link_exit', { step, provider }),
});

document.querySelector('#connect').addEventListener('click', () => link.open());
```

## Theme

`theme` styles the hosted pages: `accent` (`#rgb` or `#rrggbb`), `radius` (0 to 24), `font` (one family name) and `colorScheme` (`light`, `dark`, `auto`). Invalid values are dropped.

**`theme.appName` and `theme.logoUrl` are ignored.** They are accepted so `LinkTheme` objects type-check, but they never leave the browser. The app name and logo on the consent pages identify who is asking for access, so they come only from your client registration on the Cred server; otherwise any page holding a token could relabel the request. Set them when you register the client.

## Modes

### `popup` (default)

Opens the hosted flow in a centered popup and listens for the result. If the user closes the popup without finishing, `onExit` fires with the last step the hosted pages reported (`picker`, `provider` or `confirm`).

- Call `open()` directly inside a user gesture. If the browser still blocks the popup, `open()` throws `CredLinkError` with code `popup_blocked` and leaves nothing running; the user can click again. The widget does not silently fall back to redirect mode, because that would navigate your page away without your return page being ready.
- Your page must keep its opener relationship with the popup: do not serve it with `Cross-Origin-Opener-Policy: same-origin`. `same-origin-allow-popups` or no COOP header both work.

### Popup fallback

Popup mode needs the popup to keep its link to your page (`window.opener`) for the whole flow. Some providers' consent pages cut that link (a strict `Cross-Origin-Opener-Policy`). When that happens, Link falls back to redirect delivery on its own; popup stays the default.

What happens:

1. The hosted result page posts the result to your page as usual, and the widget acknowledges it at once. If the link to your page is gone, or no acknowledgement arrives within 2 seconds, the popup navigates itself to your registered `redirect_uri` with the result, `cred_link_via=popup` and `cred_link_flow`, a flow id that is the SHA-256 of the widget's token.
2. On that page, `Cred.handleRedirect()` offers the result, over a `BroadcastChannel` on your origin, to the widget for that flow if it is still waiting on another page. Only a widget whose own token hashes to that flow id claims it. That widget validates the result, sends a receipt, and gets it through its normal `onSuccess`, `onError` or `onExit`. Once the receipt arrives, the return page calls your `onRelayed` callback instead of its result callbacks and asks the browser to close the window. If nobody claims within 700 ms, or no receipt arrives within about 1 s of the delivery (a short extra grace lets a receipt already queued behind a busy page still count), `handleRedirect()` delivers the result to its own callbacks, exactly as in redirect mode, and the window stays open. A return URL with the marker but no valid flow id is always handled on the return page.
3. The browser remembers that this provider cut the popup off. Next time, when the user picks that provider, the popup closes and your page continues in redirect mode: the top window navigates to Link, and the result comes back to your `redirect_uri` page.

What you need to do:

- **The page at your registered `redirect_uri` must call `Cred.handleRedirect()`**, the same requirement as redirect mode. Without it the fallback delivers nothing.
- **The relay only works when the `redirect_uri` page and the page hosting the widget are on the same origin.** Otherwise the return page handles the result itself, and the widget page eventually reports an exit.
- **Show something when the result went elsewhere.** Pass `onRelayed` to `handleRedirect()`. It runs when the result was handed to the waiting page; then this page's `onSuccess`, `onError` and `onExit` do not run. The browser may refuse `window.close()` (a window the user opened, or a popup whose browsing context was swapped), so use `onRelayed` to show "Connected. You can close this window."
- **Trigger activation from the callbacks, not from `handleRedirect()`'s return value.** The return value is the parsed result either way, but in the fallback case another page may be the one that delivers it and activates. Activating from both would make one attempt fail.
- **What the relay does and does not protect.** The relay is bound to the flow: a crafted return URL (from any site) cannot reach a waiting widget unless it carries that widget's flow id, which is derived from a token that never leaves the user's browser, and two tabs running different flows cannot take each other's results. But the relay channel trusts every script on your page's origin. Such a script can see the flow id in an offer and claim the result, so it can read a relayed result, or answer with its own receipt and keep the result from being delivered (the return window then closes and the waiting widget reports an exit only when the transaction expires). Same-origin script can already do worse, so this sits inside the same trust boundary. Backend activation remains the real check: `POST /link/v1/connections/:id/activate` with `{code, subject}`, the subject taken from your session, after checking the echoed `state`.
- **After a handoff the top window navigates away**, just like redirect mode. Persist any in-progress state (form input, the page to come back to) the same way you would for redirect mode.

Trade-off: if the popup reads as closed within 3 seconds of the user choosing a provider, the widget treats it as a lost link, not a cancel. It stays waiting for a relayed result and does not call `onExit` until the transaction can no longer complete (10 minutes). So if the user really closes the popup in that window, `onExit` is delayed. Call `close()` to end the attempt sooner; calling `open()` again also ends it (with `onExit`) and starts a new popup. A popup closed at any other time reports `onExit` right away, as before.

In the relay case `handleRedirect()` still returns the parsed result and cleans the URL synchronously, but its callbacks (or `onRelayed`) run asynchronously, after the relay decision. Pass `relay: false` to always handle the result on the return page. If `BroadcastChannel` or Web Crypto is missing, the result is handled on the return page. The return page never calls `window.close()` after handling a result itself.

Residual double delivery: if the page that opened the popup has its main thread blocked for seconds, the popup can give up waiting for the acknowledgement and fall back to the redirect while the original result message is still queued for that page. Both pages can then deliver the same result. The code is single use, so one of the two activation calls fails with the opaque `401`; treat that as "already connected" if the connection shows up as active.

### `redirect`

`open()` navigates the top window to the hosted flow. At the end, Cred redirects to your registered `redirect_uri` with the result in the query string. On that page:

```js
import { Cred } from '@credninja/link';

Cred.handleRedirect({
  onSuccess: ({ connection_id, code, state }) => activateOnBackend({ connection_id, code, state }),
  onError: ({ error, request_id }) => showError(error, request_id),
  onExit: ({ step }) => track('cred_link_exit', { step }),
});
```

`handleRedirect()` parses the result with the contracts helper (only the Link parameters are handed to it, so an unrelated malformed parameter such as `x=%E0%A4` cannot break parsing), removes the Link parameters (`cred_link`, `cred_link_via`, `connection_id`, `code`, `grant_id`, `provider`, `scope`, `state`, `error`, `request_id`, `step`) from the address bar with `history.replaceState`, keeps your other parameters and the fragment, then calls the matching callback once. It returns the result, or `null` if the page was not reached from Link. If the Link parameters themselves are malformed, nothing is delivered and the URL is left untouched, so a result is never cleaned away without being delivered.

This assumes your registered `redirect_uri` has no query parameter of its own named like a Link result parameter; Cred's client registration rejects such redirect URIs, because a repeated parameter makes the result unparseable.

If the widget runs inside a frame that may not navigate the top window (a cross-origin or sandboxed iframe without `allow-top-navigation-by-user-activation`), `open()` throws `CredLinkError` with code `navigation_blocked` and the handle stays usable: call `open()` again from a user gesture, or use popup mode. Call it early, before analytics or anything that reads the URL, and serve the return page with `Referrer-Policy: no-referrer` (or `same-origin`) so the code never leaks in a Referer header. Since the parameters are removed, a reload does not deliver the result twice.

Your return page can also read the result server-side: `parseRedirectResult(url)` (or `parseLinkRedirectResult` from `@credninja/protocol`) has no side effects.

### `embedded`

Renders the provider picker in an iframe inside `container`:

```js
Cred.link({ token, mode: 'embedded', container: document.querySelector('#cred'), onSuccess, onError, onExit }).open();
```

Only the picker runs in the iframe. When the user picks a provider, the picker opens a new top-level window for the provider's consent and the scope confirmation (providers refuse to be framed, and a framed consent toggle would be a clickjacking target). The result travels back through the iframe to your page. The iframe resizes itself to its content.

- The iframe sandbox is `allow-scripts allow-forms allow-same-origin allow-popups allow-popups-to-escape-sandbox`, exported as `LINK_IFRAME_SANDBOX`. It never gets top navigation.
- Your page's CSP must allow the Link origin in `frame-src`, and the Link service only lets your registered origins frame the picker.
- The iframe is removed when a result arrives, on `close()` and on `destroy()`.

## API

```ts
import { Cred, link, handleRedirect, parseRedirectResult, buildAuthorizeUrl, CredLinkError } from '@credninja/link';

Cred.link(options: CredLinkOptions): CredLink   // same as link(options)

interface CredLinkOptions {
  token: string;                                  // request_uri from POST /link/v1/par
  mode?: 'popup' | 'redirect' | 'embedded';       // default 'popup'
  container?: HTMLElement | null;                 // embedded only
  baseUrl?: string;                               // default https://link.cred.ninja, or your self-hosted server
  providers?: LinkProviderSlug[];                 // narrowing only
  scopes?: Partial<Record<LinkProviderSlug, string[]>>; // narrowing only
  theme?: { accent?; radius?; font?; colorScheme?: 'light' | 'dark' | 'auto'; appName?; logoUrl? }; // appName, logoUrl ignored
  onSuccess?(r: { connection_id; code; grant_id; provider; scopes: string[]; state? }): void;
  onError?(e: { error: LinkErrorCode; request_id: string; state? }): void;
  onExit?(m: { step: 'picker' | 'provider' | 'confirm'; provider?; state? }): void;
}

interface CredLink {
  open(): void;    // start; a second call while running does not start a second flow
  close(): void;   // end the running flow; calls onExit if no result had arrived
  destroy(): void; // tear down silently; the handle can no longer be opened
}

Cred.handleRedirect(options?: { onSuccess?; onError?; onExit?; onRelayed?(): void; url?: string; relay?: boolean }): LinkResult | null
parseRedirectResult(input: string | { search: string }): LinkResult | null
buildAuthorizeUrl(options: Pick<CredLinkOptions, 'token' | 'mode' | 'baseUrl' | 'providers' | 'scopes' | 'theme'>): string
```

Guarantees:

- Each `open()` delivers at most one of `onSuccess`, `onError`, `onExit`. All listeners and timers are removed when the flow ends, on `close()` and on `destroy()`.
- A message is accepted only when its origin is exactly the origin of `baseUrl`, it comes from the widget's own popup or iframe window, and `parseLinkMessage` accepts it. Everything else is ignored silently.
- `state` is your PAR `state`, echoed by the Link service. It is present on every result the Link service delivers. When the widget itself detects the exit (popup closed, or `close()`), the Link service was not involved and `state` is absent.
- After the Link service delivers a result, the token is spent and `open()` throws `token_spent`; ask your backend for a new token. After an exit the widget detected itself, `open()` may be called again with the same token.
- Importing the package touches no browser API, so it is safe during server-side rendering. `Cred.link()` only validates options; browser APIs are used inside `open()`, `close()`, `destroy()` and `handleRedirect()`.

`CredLinkError.code` values, thrown synchronously for programming or environment problems: `invalid_options`, `invalid_token`, `popup_blocked`, `navigation_blocked`, `no_window`, `token_spent`, `destroyed`. Flow outcomes from the Link service never throw; they arrive in `onError` with one of `access_denied`, `invalid_scope`, `required_scope_declined`, `provider_error`, `temporarily_unavailable`, `server_error`.

## License

Apache-2.0
