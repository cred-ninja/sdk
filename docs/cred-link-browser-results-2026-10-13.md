# Cred Link real-browser pass: desktop Chrome, 2026-10-13

Partial pass of [the checklist](./cred-link-browser-checklist.md), run by an agent on Kieran's Mac in his desktop Chrome. Built from `main` at `09f9488`. **This pass does not satisfy the pass criteria.** No provider completed a consent, so no check produced a connection, and no activation ran. What it does give is the error path (provider denial) through every delivery route that could be driven, and the once-per-browser checks that need no successful result.

## Setup used

- LINK: `@credninja/server` (`LINK_ENABLED=true`, SQLite) on `127.0.0.1:3456` behind a Cloudflare quick tunnel (`*.trycloudflare.com`).
- APP: a small test app (widget page and `/return` page, `@credninja/link` bundled with esbuild, PAR and activate from its backend) behind a second quick tunnel. THIRD: the same `/return` page on a third tunnel, for check 6.
- `trycloudflare.com` is on the Public Suffix List (private section), so the three tunnel hosts are three different sites, as the checklist requires.
- Chrome on macOS (Kieran's profile, signed in to GitHub).
- GitHub OAuth app "Cred Link browser test (temp)" created for this pass. Its client secret could not be generated (see below), so the server ran with the real client id and a placeholder secret. Every GitHub hop was real; every flow was ended with GitHub's **Cancel**, which returns `error=access_denied` to the callback and needs no secret.

## Providers

| Provider | Covered | Why not |
|---|---|---|
| GitHub | Partly (denial path only) | Generating a client secret needs GitHub sudo mode (GitHub Mobile or authenticator 2FA from Kieran). The app exists, without a secret |
| Google | No | Cloud Console asked Kieran to re-enter his password ("Verify it's you") |
| Slack | No | Not signed in to Slack in this Chrome profile |
| Notion | No | Not signed in |
| Salesforce | No | Not signed in; no org known |
| Linear | No | Not signed in |
| HubSpot | No | Session expired, sign-in required |

## Tooling limits in this pass

- The Chrome automation extension cannot see or drive popup windows (they are not in its tab group), and AppleScript JavaScript in Chrome is off. So nothing could be clicked or inspected **inside the Link popup**. Popup-mode flows could be opened and closed, not completed.
- Clicks did not reach the cross-origin embedded picker iframe, so embedded mode could only be rendered.
- The flows that were completed ran in a top-level tab: redirect mode, and the authorize URL opened directly in a tab (no opener).

## Results

| Check | Mode / setup | Result |
|---|---|---|
| 1 Popup, opener intact | popup | Not run: popup cannot be driven, no provider can succeed |
| 2 COOP on GitHub | header read with a same-origin `fetch` on the consent page (signed in, first consent) and `curl` (signed out) | **No `Cross-Origin-Opener-Policy`** on `github.com/login/oauth/authorize` (signed in, first consent), its 302, or `github.com/login` (signed out). Repeat consent not reachable (needs a completed consent). `window.opener` inside a real popup not read (tooling) |
| 3 Fallback delivery | popup | Not run in a popup. Equivalent no-opener path covered by check 5 below |
| 4 Remembered provider | popup | Not run |
| 5 Memory not written wrongly | authorize URL opened directly in a tab, `mode=popup`, GitHub, Cancel | Result page had no opener and fell back at once to APP `/return` with `cred_link_via=popup` and `cred_link_flow`. No widget claimed it; the return page ran `onError(access_denied)` once, 0.9 s after load. `localStorage["cred.link.redirect_only"]` on LINK: **absent**. Pass for this path. The "after a clean popup flow" half not run |
| 6 Return page on another origin | same, `redirect_uri` on THIRD | Fallback went to THIRD `/return`, which delivered `onError(access_denied)` itself, 1.7 s after load. Widget-side `onExit` timing not observable (no widget in this run) |
| 7 Early close | popup | Popup closed at the picker (about 65 s after open, no provider chosen): `onExit({step:'picker'})` at once. `close()` 1 s after open: `onExit({step:'picker'})` at once and the popup window closed. The under-3-seconds-after-choosing-a-provider case was not reachable |
| 8 Busy opener | popup | Not run |
| 9 Back, refresh | redirect mode | Refresh on the picker re-rendered the picker. Back from GitHub's consent page went to the Link authorize URL, which sent the browser straight back to GitHub's consent page (current step rendered again). Refresh on the return page after delivery: `handleRedirect()` returned `null`, nothing delivered twice. Confirmation page not reachable |
| 10 Popup blocked | `open()` from script with no user gesture | `open()` threw `CredLinkError` `popup_blocked` synchronously. Pass |
| 11 Embedded | embedded | Picker rendered in the iframe. Clicks could not reach it (tooling), so the provider window was never opened |
| 12 Redirect mode | redirect, GitHub, Cancel | Picker, GitHub consent, Cancel, back to APP `/return`: `onError(access_denied)` once, Link parameters removed from the URL. `redirect_only` absent afterwards. Pass for the denial path |

"What to record" fields for the GitHub rows that ran:

| Field | Check 12 (redirect) | Check 5 (direct tab) | Check 6 (third origin) |
|---|---|---|---|
| COOP header | none | none | none |
| Opener after the hop | n/a (top window) | `null` (no opener from the start) | `null` |
| Delivery path | redirect | fallback (immediate, no opener) | fallback (immediate) |
| Callbacks | return page `onError` x1 | return page `onError` x1, no `onRelayed` | THIRD return page `onError` x1, no `onRelayed` |
| Return window | n/a | stayed open (expected: it handled the result itself) | stayed open |
| Activation | none (error result) | none | none |
| Remembered | absent | absent | absent |

Defects found: none. Two observations, not filed:

- The picker shows non-required scopes unticked. Continuing without ticking anything sent GitHub an authorize request with no `scope` (GitHub shows "Public data only"). What the confirmation screen and the grant do with an empty provider grant was not reachable in this pass.
- The GitHub hop carries no PKCE challenge, as expected for GitHub OAuth apps.

## Hand-off: what Kieran still needs to run

Prerequisites:

1. Provider apps. GitHub: open the temp app below, click "Generate a new client secret", approve the 2FA prompt. Google: create an OAuth client (Web) after the password re-check. Slack, Notion, Salesforce, Linear, HubSpot: sign in and create apps (none exist). Callback for each: `LINK/link/v1/callback/<provider>`. Quick tunnel hosts change on every start, so use a stable LINK host (for example a named Cloudflare tunnel on a temporary subdomain) before registering callbacks everywhere.
2. Keep DevTools open on the popup (network tab, preserve log). The agent could not do this part; it has to be a person or a tool that can drive popup windows.

Desktop Chrome, still open:

- [ ] Checks 1 to 4 for all seven providers, including first consent, repeat consent and signed-out start for check 2
- [ ] Check 5 first half: clean popup flow leaves nothing remembered
- [ ] Check 6 widget side: `onExit` only at 10 min or on `close()`
- [ ] Check 7: close within 3 s of choosing a provider (expect no `onExit` until `close()`)
- [ ] Check 8 busy opener
- [ ] Check 9 on the confirmation page, and double submit on picker and confirmation
- [ ] Check 11 embedded: checks 1 and 3
- [ ] Check 12 with a successful result and one activation
- [ ] Provider-specific items (Google untick, GitHub fast repeat hop, Slack workspace, Notion page picker, Salesforce custom domain, Linear and HubSpot labels)

Firefox, Safari, Edge (desktop): every check, 1 to 12, every provider.

iOS Safari, Chrome on Android: checks 1, 3, 4 and 13 (does `window.close()` work on the return tab).

In-app browsers: check 14.

Temporary OAuth apps created for this pass (delete when done):

- GitHub OAuth app "Cred Link browser test (temp)", owner `kierandotai`, github.com/settings/applications/3930076. No client secret was generated. No user has authorized it.
