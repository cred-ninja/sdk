# @credninja/link-react

React bindings for Cred Link, the drop-in account-connection widget: `<CredConnect>` and `useCredLink()`. Built on [`@credninja/link`](../link); read its README for the flow, the modes and the security model.

## Install

```bash
npm install @credninja/link-react
```

`react` 18 or later is a peer dependency.

## End-to-end example

Backend (pseudocode). The two calls are the same for every Link integration:

```ts
// Mint a widget token for the signed-in user.
app.post('/api/cred/link-token', requireLogin, async (req, res) => {
  const state = randomUrlSafeString(32);
  req.session.credLinkState = state;
  const r = await fetch('https://link.cred.ninja/link/v1/par', {
    method: 'POST',
    headers: { authorization: credLinkClientAuth(), 'content-type': 'application/json' },
    body: JSON.stringify({
      intent: 'connect',
      subject: req.session.userId,                  // from YOUR session
      subject_type: 'user',
      providers: ['google'],
      scopes: { google: ['calendar.readonly'] },
      redirect_uri: 'https://app.example.com/cred/return',
      origin: 'https://app.example.com',
      state,
    }),
  });
  const { request_uri } = await r.json();           // 201 { request_uri, expires_in: 600 }
  res.json({ token: request_uri });
});

// Activate the pending connection the browser reports.
app.post('/api/cred/connections', requireLogin, async (req, res) => {
  const { connection_id, code, state } = req.body;
  if (state !== req.session.credLinkState) return res.status(400).end();
  const r = await fetch(
    `https://link.cred.ninja/link/v1/connections/${encodeURIComponent(connection_id)}/activate`,
    {
      method: 'POST',
      headers: { authorization: credLinkClientAuth(), 'content-type': 'application/json' },
      body: JSON.stringify({ code, subject: req.session.userId }), // never a subject from the browser
    },
  );
  if (!r.ok) return res.status(400).json({ error: 'activation_failed' });
  res.json({ ok: true });
});
```

`credLinkClientAuth()` stands for your client authentication (`client_secret_basic` with credentials from the environment, or a `private_key_jwt` assertion).

Frontend:

```tsx
import { CredConnect } from '@credninja/link-react';

export function ConnectGoogle({ token }: { token: string | null }) {
  return (
    <CredConnect
      token={token}
      theme={{ accent: '#4f46e5' }}
      onSuccess={({ connection_id, code, state }) =>
        fetch('/api/cred/connections', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ connection_id, code, state }),
        })
      }
      onError={({ error, request_id }) => report(error, request_id)}
      onExit={({ step }) => track('cred_link_exit', { step })}
    >
      <button>Connect an account</button>
    </CredConnect>
  );
}
```

Fetch the token before the user clicks (for example when the settings page loads): the popup has to open inside the click itself.

**The connection is pending after `onSuccess`.** Nothing can use it until your backend calls `POST /link/v1/connections/:id/activate` with `{code, subject}`, where `subject` is the user in your backend's own current session. Never accept the subject from the browser; Cred rejects a mismatch with an opaque `401` and revokes the pending connection.

## `<CredConnect>`

Props are the `Cred.link()` options (`token`, `mode`, `container`, `baseUrl`, `providers`, `scopes`, `theme`, `onSuccess`, `onError`, `onExit`) plus `children`:

- A single element child becomes the trigger. Its own `onClick` runs first; call `event.preventDefault()` there to cancel opening.
- Text or no children render a plain `<button>` that is disabled until the widget is ready.
- `token` may be `null` or `undefined` while it loads.
- `container` (embedded mode) may be a ref.
- `theme` only sets `accent`, `radius`, `font` and `colorScheme`. `theme.appName` and `theme.logoUrl` are accepted for type compatibility but ignored: the app name and logo on the consent pages come only from your client registration on the Cred server, so no page can relabel who is asking for consent.
- Option errors and a blocked popup are logged with `console.error`. Use `useCredLink` to show them in your UI.

## `useCredLink(options)`

```ts
const { open, ready, error } = useCredLink({ token, onSuccess, onError, onExit });
```

- `open()`: call from a click handler. Never throws; a no-op until `ready`.
- `ready`: a valid token is loaded in the browser. Always `false` during server-side rendering.
- `error`: a `CredLinkError` for invalid options (`invalid_token`, `invalid_options`) or a failed `open()` (`popup_blocked`, `navigation_blocked`, `token_spent`). Flow outcomes from the Link service go to `onError`.

Embedded mode, rendered as soon as the token is ready:

```tsx
function EmbeddedPicker({ token }: { token: string }) {
  const container = useRef<HTMLDivElement>(null);
  const { open, ready } = useCredLink({ token, mode: 'embedded', container, onSuccess });
  useEffect(() => {
    if (ready) open();
  }, [ready, open]);
  return <div ref={container} />;
}
```

Redirect mode: on the page your `redirect_uri` points to, call `handleRedirect` (re-exported from `@credninja/link`) once on mount.

## Behavior

- The widget is created after mount and re-created only when `token`, `mode`, `baseUrl`, `container`, `providers`, `scopes` or `theme` change by value. Inline arrays and objects are fine.
- Callbacks always use the latest props; changing them never restarts a running flow.
- Unmounting destroys the widget: the popup or iframe is closed, listeners and timers are removed, and no callback fires afterwards.
- Strict mode is safe: the double effect creates and destroys an idle widget, and one click opens exactly one flow.
- The modules carry `'use client'` and touch no browser API at import or during server rendering.

## License

Apache-2.0
