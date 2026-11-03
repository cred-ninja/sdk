import { describe, expect, it } from 'vitest';
import {
  SLACK_MAPPED_METHODS,
  canonicalBrokerUrl,
  contentTypeMismatch,
  evaluateOperation,
  hasOperationTable,
  methodOverrideChannel,
} from '../operations.js';
import { isBrokerOnlyScope, withDerivedScopes, withStoredDerivedScopes, withoutRedundantDerivedScopes } from '@credninja/protocol';

const outcome = (service: string, method: string, url: string, scopes: string[], body?: unknown) =>
  evaluateOperation({ service, method, url, body }, scopes).outcome;

describe('evaluateOperation', () => {
  it('has a table for every brokered service', () => {
    for (const service of ['google', 'github', 'slack', 'notion', 'salesforce', 'linear', 'hubspot']) {
      expect(hasOperationTable(service)).toBe(true);
    }
    expect(hasOperationTable('other')).toBe(false);
    expect(outcome('other', 'GET', 'https://example.com/x', ['a'])).toBe('not_mapped');
    expect(outcome('constructor', 'GET', 'https://example.com/x', ['a'])).toBe('not_mapped');
    expect(outcome('__proto__', 'GET', 'https://example.com/x', ['a'])).toBe('not_mapped');
  });

  it('reads a Slack method name as data, never as a key of the table object', () => {
    for (const name of ['constructor', '__proto__', 'hasOwnProperty', 'toString']) {
      expect(outcome('slack', 'POST', `https://slack.com/api/${name}`, ['chat:write'])).toBe('not_mapped');
    }
  });

  it('matches Google scopes in any stored spelling, and no other', () => {
    const url = 'https://gmail.googleapis.com/gmail/v1/users/me/messages';
    expect(outcome('google', 'GET', url, ['gmail.readonly'])).toBe('allowed');
    expect(outcome('google', 'GET', url, ['https://www.googleapis.com/auth/gmail.readonly'])).toBe('allowed');
    expect(outcome('google', 'GET', url, ['https://mail.google.com/'])).toBe('allowed');
    expect(outcome('google', 'GET', url, ['gmail.readonly.extra'])).toBe('not_mapped');
    expect(outcome('google', 'GET', url, ['calendar.readonly'])).toBe('insufficient');
  });

  it('only the full mail scope deletes a message', () => {
    const url = 'https://gmail.googleapis.com/gmail/v1/users/me/messages/1';
    expect(outcome('google', 'DELETE', url, ['gmail.modify'])).toBe('insufficient');
    expect(outcome('google', 'DELETE', url, ['https://mail.google.com/'])).toBe('allowed');
    expect(outcome('google', 'POST', `${url}/trash`, ['gmail.modify'])).toBe('allowed');
    expect(outcome('google', 'POST', `${url}/trash`, ['gmail.readonly'])).toBe('insufficient');
  });

  it('applies a table only on its own host', () => {
    expect(outcome('google', 'GET', 'https://sheets.googleapis.com/gmail/v1/users/me/messages', ['gmail.readonly'])).toBe('not_mapped');
    expect(outcome('github', 'GET', 'https://uploads.github.com/repos/o/r', ['repo'])).toBe('not_mapped');
    expect(outcome('salesforce', 'GET', 'https://evil.example.com/services/data/v60.0/limits', ['api'])).toBe('not_mapped');
  });

  it('classifies every GraphQL operation, whatever operationName picks', () => {
    const url = 'https://api.linear.app/graphql';
    expect(outcome('linear', 'POST', url, ['read'], { query: 'query A { viewer { id } } query B { viewer { id } }', operationName: 'A' })).toBe('allowed');
    expect(outcome('linear', 'POST', url, ['read'], { query: 'query A { viewer { id } } mutation B { issueDelete(id:"x") { success } }', operationName: 'A' })).toBe('insufficient');
    expect(outcome('linear', 'POST', url, ['read'], { query: 'fragment F on Query { viewer { id } } query A { ...F }' })).toBe('allowed');
    expect(outcome('linear', 'POST', url, ['read'], { query: 'x'.repeat(5) })).toBe('not_mapped');
    expect(outcome('linear', 'POST', url, ['read'], { query: `{ ${'a '.repeat(20_000)} }` })).toBe('not_mapped');
  });

  it('a narrow Linear scope allows only its own mutations, by field name and not alias', () => {
    const url = 'https://api.linear.app/graphql';
    expect(outcome('linear', 'POST', url, ['comments:create'], { query: 'mutation { commentCreate(input:{}) { success } }' })).toBe('allowed');
    expect(outcome('linear', 'POST', url, ['comments:create'], { query: 'mutation { commentCreate: issueDelete(id:"x") { success } }' })).toBe('insufficient');
    expect(outcome('linear', 'POST', url, ['comments:create'], { query: 'mutation {  __typename }' })).toBe('insufficient');
    expect(outcome('linear', 'POST', url, ['admin'], { query: 'mutation { issueDelete(id:"x") { success } }' })).toBe('insufficient');
  });

  describe('GitHub GraphQL', () => {
    const url = 'https://api.github.com/graphql';
    const query = { query: '{ repository(owner: "o", name: "r") { issues(first: 1) { totalCount } } }' };
    const mutation = (fields: string) => ({ query: `mutation { ${fields} }` });
    const create = 'createIssue(input: {}) { clientMutationId }';

    it('a query needs the repository scope itself, not an identity scope or github.read', () => {
      for (const scope of ['repo', 'public_repo']) expect(outcome('github', 'POST', url, [scope], query), scope).toBe('allowed');
      for (const scope of ['github.read', 'read:user', 'user', 'read:org', 'gist']) expect(outcome('github', 'POST', url, [scope], query), scope).toBe('insufficient');
      expect(outcome('github', 'POST', url, ['read:user'], { query: '{ viewer { login } }' })).toBe('insufficient');
    });

    it('a listed mutation needs its write scope', () => {
      for (const field of [create, 'closeIssue(input: {}) { clientMutationId }', 'addComment(input: {}) { clientMutationId }']) {
        expect(outcome('github', 'POST', url, ['repo'], mutation(field)), field).toBe('allowed');
        expect(outcome('github', 'POST', url, ['public_repo'], mutation(field)), field).toBe('allowed');
        expect(outcome('github', 'POST', url, ['github.read'], mutation(field)), field).toBe('insufficient');
        expect(outcome('github', 'POST', url, ['read:user'], mutation(field)), field).toBe('insufficient');
      }
    });

    it('any other mutation is not mapped, whatever the grant', () => {
      for (const field of ['deleteRepository(input: {}) { clientMutationId }', 'addStar(input: {}) { clientMutationId }', 'constructor', '__proto__']) {
        expect(outcome('github', 'POST', url, ['repo', 'admin:org', 'delete_repo'], mutation(field)), field).toBe('not_mapped');
      }
    });

    it('a listed mutation cannot carry an unlisted one, by alias, fragment or a second operation', () => {
      const grant = ['repo'];
      expect(outcome('github', 'POST', url, grant, mutation(`${create} deleteRepository(input: {}) { clientMutationId }`))).toBe('not_mapped');
      expect(outcome('github', 'POST', url, grant, mutation('createIssue: deleteRepository(input: {}) { clientMutationId }'))).toBe('not_mapped');
      expect(outcome('github', 'POST', url, grant, { query: 'mutation { ...F } fragment F on Mutation { createIssue(input: {}) { clientMutationId } }' })).toBe('not_mapped');
      expect(outcome('github', 'POST', url, grant, { query: `mutation A { ${create} } mutation B { deleteRepository(input: {}) { clientMutationId } }`, operationName: 'A' })).toBe('not_mapped');
      expect(outcome('github', 'POST', url, grant, mutation(`renamed: ${create} again: ${create}`))).toBe('allowed');
    });
  });

  it('an empty scope list covers nothing', () => {
    expect(outcome('notion', 'POST', 'https://api.notion.com/v1/pages', [], {})).toBe('insufficient');
    expect(outcome('github', 'GET', 'https://api.github.com/repos/o/r', [])).toBe('insufficient');
  });

  it('every Slack method the table maps has a dot, so the audit list can name it', () => {
    expect(SLACK_MAPPED_METHODS.length).toBeGreaterThan(10);
    expect(SLACK_MAPPED_METHODS.every((name) => name.includes('.'))).toBe(true);
  });
});

describe('derived read scopes', () => {
  const derived = (service: string, scopes: string[]) => withDerivedScopes(service, scopes).filter((scope) => !scopes.includes(scope));

  it('derive from the wider scope, on that provider only, one way', () => {
    expect(derived('github', ['repo'])).toEqual(['github.read']);
    expect(derived('github', ['public_repo'])).toEqual(['github.read']);
    expect(derived('github', ['read:user'])).toEqual([]);
    expect(derived('github', ['github.read'])).toEqual([]);
    expect(derived('salesforce', ['api'])).toEqual(['salesforce.read']);
    expect(derived('salesforce', ['refresh_token'])).toEqual([]);
    expect(derived('slack', ['channels:read'])).toEqual([]);
    expect(derived('google', ['repo'])).toEqual([]);
    expect(derived('constructor', ['repo'])).toEqual([]);
  });

  it('only a stored Notion connection with no scopes covers both names, and a read-only list cannot widen', () => {
    expect(withStoredDerivedScopes('notion', [])).toEqual(['notion.read', 'content']);
    expect(withDerivedScopes('notion', [])).toEqual([]);
    expect(withDerivedScopes('notion', ['content'])).toEqual(['content', 'notion.read']);
    expect(withDerivedScopes('notion', ['notion.read'])).toEqual(['notion.read']);
    expect(withStoredDerivedScopes('notion', ['notion.read'])).toEqual(['notion.read']);
  });

  it('drops a derived scope only when its source stays', () => {
    expect(withoutRedundantDerivedScopes('github', ['repo', 'github.read'])).toEqual(['repo']);
    expect(withoutRedundantDerivedScopes('github', ['github.read'])).toEqual(['github.read']);
    expect(withoutRedundantDerivedScopes('notion', ['content', 'notion.read'])).toEqual(['content']);
    expect(withoutRedundantDerivedScopes('notion', ['notion.read'])).toEqual(['notion.read']);
  });

  it('knows which scopes hold only at the broker', () => {
    expect(isBrokerOnlyScope('github', 'github.read')).toBe(true);
    expect(isBrokerOnlyScope('slack', 'github.read')).toBe(false);
    expect(isBrokerOnlyScope('github', 'repo')).toBe(false);
    expect(isBrokerOnlyScope('notion', 'content')).toBe(false);
  });
});

describe('canonicalBrokerUrl', () => {
  it('normalizes what parsing normalizes, and drops any fragment', () => {
    expect(canonicalBrokerUrl('https://API.GitHub.com/a/../repos?x=1#f')).toBe('https://api.github.com/repos?x=1');
    expect(canonicalBrokerUrl('https://api.github.com:443/repos')).toBe('https://api.github.com/repos');
    expect(canonicalBrokerUrl('https://api.github.com/%2e%2e/repos')).toBe('https://api.github.com/repos');
  });

  it('refuses what could read differently upstream', () => {
    for (const url of [
      'http://api.github.com/x', 'https://u:p@api.github.com/x', 'https://api.github.com:8443/x',
      'https://api.github.com./x', 'https://api.github.com/a%2Fb', 'https://api.github.com/a%5Cb',
      'https://api.github.com/a%252fb', 'https://api.github.com//a', 'https://api.github.com/a%00b', 'not a url',
    ]) {
      expect(canonicalBrokerUrl(url), url).toBeNull();
    }
  });
});

describe('override channels', () => {
  const url = 'https://api.github.com/repos/o/r';

  it('finds them in the query, headers and body', () => {
    for (const key of ['_method', '$httpMethod', '_HttpMethod', 'x-http-method-override', 'x.http.method', 'method']) {
      expect(methodOverrideChannel({ url: `${url}?${encodeURIComponent(key)}=DELETE` }), key).toBe('query');
    }
    for (const key of ['X-HTTP-Method-Override', ' x-http-method ', 'X-Method-Override', 'X-Original-URL']) {
      expect(methodOverrideChannel({ url, headers: { [key]: 'DELETE' } }), key).toBe('header');
    }
    for (const key of ['_method', '$httpMethod', '_HttpMethod', 'X-HTTP-Method-Override', 'methodOverride']) {
      expect(methodOverrideChannel({ url, body: { [key]: 'DELETE' } }), key).toBe('body');
    }
  });

  it('leaves ordinary data alone', () => {
    expect(methodOverrideChannel({ url, headers: { 'X-GitHub-Api-Version': '2022-11-28' }, body: { method: 'x', paymentMethod: 'y' } })).toBeNull();
    expect(methodOverrideChannel({ url, body: ['_method'] })).toBeNull();
  });
});

describe('contentTypeMismatch', () => {
  it('accepts JSON only', () => {
    expect(contentTypeMismatch(undefined)).toBe(false);
    expect(contentTypeMismatch({ Accept: 'text/plain' })).toBe(false);
    expect(contentTypeMismatch({ 'Content-Type': 'application/json' })).toBe(false);
    expect(contentTypeMismatch({ ' content-type ': 'application/json; charset=utf-8' })).toBe(false);
    for (const value of ['application/graphql', 'multipart/mixed', 'application/json, text/plain', 'application/jsonp']) {
      expect(contentTypeMismatch({ 'Content-Type': value }), value).toBe(true);
    }
  });
});
