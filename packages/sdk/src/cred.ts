/**
 * Cred SDK — Main client class
 *
 * Uses fetch (Node 18+ built-in). Zero runtime dependencies.
 */

import {
  CredConfig,
  DelegateParams,
  DelegationResult,
  Connection,
  GetConsentUrlParams,
  RevokeParams,
} from './types';
import { CredError, ConsentRequiredError } from './errors';

const DEFAULT_BASE_URL = 'https://api.cred.ninja';

export class Cred {
  private readonly agentToken: string;
  private readonly baseUrl: string;

  constructor(config: CredConfig) {
    if (!config.agentToken) {
      throw new CredError('agentToken is required', 'invalid_config', 0);
    }
    this.agentToken = config.agentToken;
    this.baseUrl = (config.baseUrl ?? DEFAULT_BASE_URL).replace(/\/$/, '');
  }

  // ── Core methods ────────────────────────────────────────────────────────────

  /**
   * Get a delegated access token for a service on behalf of a user.
   *
   * `appClientId` is required and should be baked into the agent's deployment
   * config — agents always know which app they belong to. User-facing consent
   * flows that don't have app context belong in the portal, not the SDK.
   *
   * Throws ConsentRequiredError (with `consentUrl`) if the user hasn't
   * connected the service yet.
   */
  async delegate(params: DelegateParams): Promise<DelegationResult> {
    const body: Record<string, unknown> = {
      service: params.service,
      user_id: params.userId,
      appClientId: params.appClientId,
    };
    if (params.scopes && params.scopes.length > 0) {
      body.scopes = params.scopes;
    }
    if (params.agentDid) {
      body.agent_did = params.agentDid;
    }

    const data = await this.post<{
      access_token: string;
      token_type: string;
      expires_in?: number;
      service: string;
      scopes: string[];
      delegation_id: string;
      receipt?: string;
    }>('/api/v1/delegate', body);

    return {
      accessToken: data.access_token,
      tokenType: data.token_type,
      expiresIn: data.expires_in,
      service: data.service,
      scopes: data.scopes,
      delegationId: data.delegation_id,
      receipt: data.receipt,
    };
  }

  /**
   * List all services a user has actively connected.
   */
  async getUserConnections(userId: string, appClientId?: string): Promise<Connection[]> {
    const params = new URLSearchParams({ user_id: userId });
    if (appClientId) params.set('app_client_id', appClientId);

    const data = await this.get<{ connections: Connection[] }>(
      `/api/v1/connections?${params.toString()}`,
    );
    return data.connections;
  }

  /**
   * Build a consent URL to redirect a user to connect a service.
   * Pure URL construction — no HTTP call.
   */
  getConsentUrl(params: GetConsentUrlParams): string {
    const url = new URL(`${this.baseUrl}/api/connect/${params.service}/authorize`);
    url.searchParams.set('app_client_id', params.appClientId);
    url.searchParams.set('scopes', params.scopes.join(','));
    url.searchParams.set('redirect_uri', params.redirectUri);
    // state is generated server-side when user hits the authorize endpoint
    return url.toString();
  }

  /**
   * Revoke a user's connection to a service.
   */
  async revoke(params: RevokeParams): Promise<void> {
    const query = new URLSearchParams({ user_id: params.userId });
    if (params.appClientId) query.set('app_client_id', params.appClientId);

    await this.delete(`/api/v1/connections/${params.service}?${query.toString()}`);
  }

  // ── Private HTTP helpers ────────────────────────────────────────────────────

  private headers(): Record<string, string> {
    return {
      'Authorization': `Bearer ${this.agentToken}`,
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    };
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: this.headers(),
      body: JSON.stringify(body),
    });
    return this.handleResponse<T>(res);
  }

  private async get<T>(path: string): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: 'GET',
      headers: this.headers(),
    });
    return this.handleResponse<T>(res);
  }

  private async delete(path: string): Promise<void> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: 'DELETE',
      headers: this.headers(),
    });
    if (res.status === 204) return;
    await this.handleResponse(res);
  }

  private async handleResponse<T>(res: Response): Promise<T> {
    if (res.ok) {
      return res.json() as Promise<T>;
    }

    let body: Record<string, unknown> = {};
    try {
      const parsed: unknown = await res.json();
      if (parsed !== null && typeof parsed === 'object') {
        body = parsed as Record<string, unknown>;
      }
    } catch {
      // ignore parse errors
    }

    const message = typeof body.message === 'string'
      ? body.message
      : typeof body.error === 'string'
        ? body.error
        : `Request failed with status ${res.status}`;

    // 403 consent_required → ConsentRequiredError
    if (res.status === 403 && body.error === 'consent_required') {
      const consentUrl = typeof body.consent_url === 'string' ? body.consent_url : '';
      throw new ConsentRequiredError(message, consentUrl);
    }

    throw new CredError(message, String(body.error ?? 'unknown'), res.status);
  }
}
