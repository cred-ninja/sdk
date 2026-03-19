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

// New adapters — DEBT-008
export { StripeAdapter } from './stripe.js';
export { DiscordAdapter } from './discord.js';
export { TwilioAdapter } from './twilio.js';
export { JiraAdapter } from './jira.js';
export { ZoomAdapter } from './zoom.js';
export { AsanaAdapter } from './asana.js';
export { PagerDutyAdapter } from './pagerduty.js';
export { AwsAdapter } from './aws.js';
export { OpenAIAdapter } from './openai.js';
export { SendGridAdapter } from './sendgrid.js';

import { GoogleAdapter } from './google.js';
import { GitHubAdapter } from './github.js';
import { SlackAdapter } from './slack.js';
import { NotionAdapter } from './notion.js';
import { SalesforceAdapter, SALESFORCE_PRODUCTION, SALESFORCE_SANDBOX } from './salesforce.js';
import { LinearAdapter } from './linear.js';
import { HubSpotAdapter } from './hubspot.js';
import { StripeAdapter } from './stripe.js';
import { DiscordAdapter } from './discord.js';
import { TwilioAdapter } from './twilio.js';
import { JiraAdapter } from './jira.js';
import { ZoomAdapter } from './zoom.js';
import { AsanaAdapter } from './asana.js';
import { PagerDutyAdapter } from './pagerduty.js';
import { AwsAdapter } from './aws.js';
import { OpenAIAdapter } from './openai.js';
import { SendGridAdapter } from './sendgrid.js';
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
  | 'hubspot'
  | 'stripe'
  | 'discord'
  | 'twilio'
  | 'jira'
  | 'zoom'
  | 'asana'
  | 'pagerduty'
  | 'aws'
  | 'openai'
  | 'sendgrid';

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
    case 'stripe':
      return new StripeAdapter();
    case 'discord':
      return new DiscordAdapter();
    case 'twilio':
      return new TwilioAdapter();
    case 'jira':
      return new JiraAdapter();
    case 'zoom':
      return new ZoomAdapter();
    case 'asana':
      return new AsanaAdapter();
    case 'pagerduty':
      return new PagerDutyAdapter();
    case 'aws':
      return new AwsAdapter();
    case 'openai':
      return new OpenAIAdapter();
    case 'sendgrid':
      return new SendGridAdapter();
    default: {
      const _exhaustive: never = slug;
      throw new Error(`Unknown adapter slug: ${String(_exhaustive)}`);
    }
  }
}
