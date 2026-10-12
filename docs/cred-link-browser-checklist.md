# Cred Link: real-browser checklist

Cred Link's popup mode, its fallback to redirect delivery and the relay between pages are tested against simulated browsers only. Every provider interaction in the test suite is simulated too. This checklist is the manual pass that has to happen before Link is switched on for real users. It answers two questions per provider: does the consent page cut the popup's link to the page that opened it, and does the fallback deliver the result when it does.

Background: [design, section 1 "Popup fallback"](./design/cred-link.md) and the "Popup fallback" section of the [`@credninja/link` README](../packages/link/README.md).

## Setup

1. Run `@credninja/server` with `LINK_ENABLED=true` on an HTTPS origin. The Link cookies use the `__Host-` prefix and are refused on plain HTTP, so use a tunnel or a local certificate. Call this origin LINK.
2. Register a Link client with a `redirect_uri` and `origin` on a second HTTPS origin, the test app. Call it APP. LINK and APP must be different sites, as they will be in production.
3. Create a real OAuth app at each provider with the callback `LINK/link/v1/callback/<provider>` and configure it on the server.
4. On APP, serve two pages from the same origin:
   - a widget page that calls `Cred.link({ token, mode, onSuccess, onError, onExit })` and logs every callback with a timestamp;
   - the page at `redirect_uri`, which calls `Cred.handleRedirect({ onSuccess, onError, onExit, onRelayed })` and logs the same.
   Both `onSuccess` handlers post `{ connection_id, code }` to a backend route that calls `POST /link/v1/connections/:id/activate` with the session's subject.
5. Keep the browser's developer tools open on the popup window (network tab, "preserve log").

Browsers: Chrome, Firefox, Safari and Edge on desktop; Safari on iOS; Chrome on Android. Providers: Google, GitHub, Slack, Notion, Salesforce, Linear, HubSpot.

## What to record

One row per provider and browser.

| Field | How to read it |
|---|---|
| COOP header | `Cross-Origin-Opener-Policy` on the provider's consent pages (network tab). `same-origin` cuts the opener; `same-origin-allow-popups` and no header do not |
| Opener after the hop | On the Link confirmation page in the popup, run `window.opener` in the console: an object, or `null` |
| Delivery path | `postMessage` (popup closes itself), or fallback (popup navigates to APP's `redirect_uri` with `cred_link_via=popup`) |
| Callbacks | Which page ran `onSuccess`, how many times in total, and whether `onRelayed` ran |
| Return window | Closed by itself, or stayed open showing the `onRelayed` message |
| Activation | Number of activate calls and their status codes |
| Remembered | Value of `localStorage["cred.link.redirect_only"]` on LINK after the flow |

## Checks per provider and browser

Run 1 to 4 for every provider. A provider that keeps the opener still needs 3 and 4 with the opener cut by hand: on the Link confirmation page in the popup, run `window.opener = null` in the console before confirming.

1. **Popup, opener intact.** Start in popup mode, connect, confirm. Expect: the widget page's `onSuccess` once, the popup closes, one activate call answering 200, nothing remembered on LINK.
2. **Does this provider cut the opener?** Read the COOP header and `window.opener` as above. This is the answer the open question in the spec is waiting for. Check both a first consent and a repeat consent, and a signed-out start, since providers serve different pages for each.
3. **Fallback delivery.** With the opener gone, confirm. Expect: about 2 seconds later the popup navigates to APP's `redirect_uri` with the result, `cred_link_via=popup` and `cred_link_flow`; the widget page's `onSuccess` runs once; the return page runs `onRelayed` and none of its result callbacks; exactly one activate call answers 200. Note whether the window closed.
4. **Remembered provider.** Start again and pick the same provider. Expect: the popup closes and the widget page itself navigates to Link, then to the provider, and the result arrives on the `redirect_uri` page through its own `onSuccess`. Clear LINK's site data and confirm popup mode is back.

Run these once per browser, with any one provider:

5. **Memory is not written wrongly.** After a clean popup flow (check 1), nothing is remembered. Open the authorize URL directly in a tab (no opener at all), finish the flow, and confirm nothing is remembered either.
6. **Return page on another origin.** Point `redirect_uri` at a third origin and repeat check 3. Expect: no relay, the return page delivers the result itself, and the widget page reports `onExit` only when the transaction expires (10 minutes) or when `close()` is called.
7. **Early close.** Choose a provider and close the popup within 3 seconds. Expect: no `onExit` yet (the widget treats this as a possible lost opener). Call `close()` and expect `onExit` at once. Repeat, closing after more than 3 seconds, and expect `onExit` at once.
8. **Busy opener.** Before confirming, pause the widget page in the debugger for 5 seconds, or move its tab to the background with CPU throttling on. Expect either one delivery, or the documented double delivery: both pages run `onSuccess` and the second activate call answers 401. Record which.
9. **Back, refresh and double submit** on the picker, the provider page and the confirmation page. Expect the current step to render again each time, one code exchange, and one result.
10. **Popup blocked.** Call `open()` outside a click handler. Record what the widget reports.
11. **Embedded mode.** Run checks 1 and 3 with `mode: 'embedded'`. The picker is in the iframe, and the provider hop opens a top-level window whose opener is the iframe.
12. **Redirect mode.** Run one full flow with `mode: 'redirect'` as the baseline.

Mobile only:

13. **iOS Safari and Chrome on Android.** Popups open as tabs. Run checks 1, 3 and 4 and record whether `window.close()` works on the return tab.
14. **In-app browsers** (open the widget page from a link inside a mail or chat app). Record whether a popup opens at all and what the widget reports when it does not.

## Provider-specific things to look at

- **Google.** Untick a scope on Google's consent screen. The Link confirmation page must show what Google actually granted, and a required scope that was unticked must end in `required_scope_declined`.
- **GitHub.** A repeat authorization returns without showing a consent page. Confirm the flow still completes and note that the hop takes well under 3 seconds (it interacts with check 7).
- **Slack.** Phase 1 connects as a bot install. Confirm the workspace picker and the account label.
- **Notion.** Notion has no scopes and shows its own page picker. Confirm the confirmation page says so.
- **Salesforce.** Start at `login.salesforce.com` and at a custom domain. The connection must be pinned to the instance host the token response names.
- **Linear, HubSpot.** Confirm the account or workspace picker and the account label.

## Pass criteria

- Every provider and browser delivers exactly one usable result in checks 1 and 3, and activation succeeds exactly once.
- No flow ends with a connected account and no callback on either page.
- Check 4 moves a provider that cut the opener to redirect mode without the user doing anything.
- Nothing is remembered after a flow whose opener was intact.

## What to do with the results

- A provider that always cuts the opener in the major browsers should start in redirect mode by default, so users never wait for the 2 second timeout. That is a small follow-up change; record the provider here first.
- A browser where `window.close()` is refused after the relay needs a visible `onRelayed` message in the app's return page. Note it in the widget README.
- Any double delivery outside check 8, and any flow that delivers nothing, is a bug: file it with the row from the table above.
