/**
 * Express/Connect middleware for @credninja/oauth
 *
 * Optional import: import { credOAuth } from '@credninja/oauth/express'
 *
 * Creates /auth/:provider and /auth/:provider/callback routes automatically.
 */

import type { IncomingMessage, ServerResponse } from 'http';
import { OAuthClient } from '../client.js';
import type { ServiceAdapter, TokenResponse } from '../types.js';

export interface ProviderConfig {
  clientId: string;
  clientSecret: string;
  scopes: string[];
  adapter: ServiceAdapter;
}

export interface CredOAuthOptions {
  redirectUri: string | ((provider: string) => string);
  onSuccess: (
    req: IncomingMessage,
    res: ServerResponse,
    ctx: { provider: string; tokens: TokenResponse }
  ) => void;
  onError?: (
    req: IncomingMessage,
    res: ServerResponse,
    error: Error
  ) => void;
  /** Session key to store CSRF state (default: 'oauthState') */
  stateSessionKey?: string;
  /** Session key to store PKCE verifier (default: 'pkceVerifier') */
  pkceSessionKey?: string;
}

type AnyRequest = IncomingMessage & {
  session?: Record<string, unknown>;
  params?: Record<string, string>;
  query?: Record<string, string>;
  url?: string;
};

type AnyResponse = ServerResponse & {
  redirect?: (url: string) => void;
};

/**
 * Create an Express-compatible middleware for OAuth flows.
 *
 * @example
 * ```ts
 * import express from 'express';
 * import { credOAuth } from '@credninja/oauth/express';
 * import { GoogleAdapter, GitHubAdapter } from '@credninja/oauth';
 *
 * const app = express();
 *
 * app.use('/auth', credOAuth({
 *   google: { adapter: new GoogleAdapter(), clientId: '...', clientSecret: '...', scopes: ['calendar'] },
 * }, {
 *   redirectUri: 'http://localhost:3000/auth/callback',
 *   onSuccess: (req, res, { provider, tokens }) => {
 *     req.session.tokens = tokens;
 *     res.redirect('/dashboard');
 *   },
 * }));
 * ```
 */
export function credOAuth(
  providers: Record<string, ProviderConfig>,
  options: CredOAuthOptions
) {
  const stateKey = options.stateSessionKey ?? 'oauthState';
  const pkceKey = options.pkceSessionKey ?? 'pkceVerifier';

  const getRedirectUri = (provider: string): string =>
    typeof options.redirectUri === 'function'
      ? options.redirectUri(provider)
      : options.redirectUri;

  return async function oauthMiddleware(
    req: AnyRequest,
    res: AnyResponse,
    next: (err?: unknown) => void
  ) {
    const url = req.url ?? '';

    // Match /auth/:provider (initiate flow)
    const initMatch = url.match(/^\/([^/?]+)\/?(\?.*)?$/);
    // Match /auth/:provider/callback
    const callbackMatch = url.match(/^\/([^/?]+)\/callback(\?.*)?$/);

    const handleError = (error: Error) => {
      if (options.onError) {
        options.onError(req, res, error);
      } else {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end(`OAuth error: ${error.message}`);
      }
    };

    try {
      if (callbackMatch) {
        const provider = callbackMatch[1];
        const config = providers[provider];
        if (!config) {
          return next();
        }

        const qs = new URL(`http://x${url}`).searchParams;
        const code = qs.get('code');
        const returnedState = qs.get('state');
        const error = qs.get('error');

        if (error) {
          return handleError(new Error(`OAuth error from provider: ${error}`));
        }

        if (!code) {
          return handleError(new Error('Missing authorization code in callback'));
        }

        // Validate CSRF state
        const session = req.session ?? {};
        const savedState = session[`${stateKey}:${provider}`] as string | undefined;
        if (!savedState || savedState !== returnedState) {
          return handleError(new Error('State mismatch — possible CSRF attack'));
        }

        const codeVerifier = session[`${pkceKey}:${provider}`] as string | undefined;

        const client = new OAuthClient({
          adapter: config.adapter,
          clientId: config.clientId,
          clientSecret: config.clientSecret,
          redirectUri: getRedirectUri(provider),
        });

        const tokens = await client.exchangeCode({ code, codeVerifier });
        options.onSuccess(req, res, { provider, tokens });

      } else if (initMatch) {
        const provider = initMatch[1];
        const config = providers[provider];
        if (!config) {
          return next();
        }

        const client = new OAuthClient({
          adapter: config.adapter,
          clientId: config.clientId,
          clientSecret: config.clientSecret,
          redirectUri: getRedirectUri(provider),
        });

        const { url: authUrl, state, codeVerifier } = await client.getAuthorizationUrl({
          scopes: config.scopes,
        });

        // Store state and PKCE verifier in session
        if (req.session) {
          req.session[`${stateKey}:${provider}`] = state;
          if (codeVerifier) {
            req.session[`${pkceKey}:${provider}`] = codeVerifier;
          }
        }

        if (res.redirect) {
          res.redirect(authUrl);
        } else {
          res.writeHead(302, { Location: authUrl });
          res.end();
        }
      } else {
        next();
      }
    } catch (err) {
      handleError(err instanceof Error ? err : new Error(String(err)));
    }
  };
}
