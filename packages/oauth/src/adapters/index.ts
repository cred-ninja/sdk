/**
 * Adapter barrel export + factory
 */

export { BaseServiceAdapter } from './base.js';
export type { ServiceAdapter } from './base.js';
export { GoogleAdapter } from './google.js';
export { GitHubAdapter } from './github.js';
export { SlackAdapter } from './slack.js';
export { NotionAdapter } from './notion.js';
export {
  SalesforceAdapter,
  SALESFORCE_PRODUCTION,
  SALESFORCE_SANDBOX,
} from './salesforce.js';
export type { SalesforceTokenResponse } from './salesforce.js';
export { LinearAdapter } from './linear.js';
export { HubSpotAdapter } from './hubspot.js';

import { GoogleAdapter } from './google.js';
import { GitHubAdapter } from './github.js';
import { SlackAdapter } from './slack.js';
import { NotionAdapter } from './notion.js';
import { SalesforceAdapter, SALESFORCE_PRODUCTION, SALESFORCE_SANDBOX } from './salesforce.js';
import { LinearAdapter } from './linear.js';
import { HubSpotAdapter } from './hubspot.js';
import type { ServiceAdapter } from './base.js';

/** Built-in adapter slugs */
export type BuiltinAdapterSlug =
  | 'google'
  | 'github'
  | 'slack'
  | 'notion'
  | 'salesforce'
  | 'salesforce-sandbox'
  | 'linear'
  | 'hubspot';

/**
 * Create a built-in adapter by slug.
 * Throws if the slug is not recognised.
 */
export function createAdapter(slug: BuiltinAdapterSlug): ServiceAdapter {
  switch (slug) {
    case 'google':
      return new GoogleAdapter('google');
    case 'github':
      return new GitHubAdapter();
    case 'slack':
      return new SlackAdapter();
    case 'notion':
      return new NotionAdapter();
    case 'salesforce':
      return new SalesforceAdapter(SALESFORCE_PRODUCTION);
    case 'salesforce-sandbox':
      return new SalesforceAdapter(SALESFORCE_SANDBOX);
    case 'linear':
      return new LinearAdapter();
    case 'hubspot':
      return new HubSpotAdapter();
    default: {
      const _exhaustive: never = slug;
      throw new Error(`Unknown adapter slug: ${String(_exhaustive)}`);
    }
  }
}
