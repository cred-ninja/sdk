import { describe, expect, it } from 'vitest';
import {
  SLACK_MAPPED_METHODS,
  canonicalBrokerUrl,
  contentTypeMismatch,
  evaluateOperation,
  listOperationRows,
  hasOperationTable,
  methodOverrideChannel,
} from '../operations.js';
import { isBrokerOnlyScope, withDerivedScopes, withStoredDerivedScopes, withoutRedundantDerivedScopes } from '@credninja/protocol';

const outcome = (service: string, method: string, url: string, scopes: string[], body?: unknown) =>
  evaluateOperation({ service, method, url, body }, scopes).outcome;

describe('Google scopes that name less than a URL shows', () => {
  const gmail = 'https://gmail.googleapis.com/gmail/v1/users/me/messages/1';
  it('gmail.metadata reads only metadata', () => {
    expect(outcome('google', 'GET', `${gmail}?format=metadata`, ['gmail.metadata'])).toBe('allowed');
    expect(outcome('google', 'GET', `${gmail}?format=full`, ['gmail.metadata'])).toBe('insufficient');
    expect(outcome('google', 'GET', gmail, ['gmail.metadata'])).toBe('insufficient');
    expect(outcome('google', 'GET', gmail, ['gmail.readonly'])).toBe('allowed');
  });
  it('drive.metadata never downloads or exports', () => {
    const file = 'https://www.googleapis.com/drive/v3/files/1';
    expect(outcome('google', 'GET', file, ['drive.metadata.readonly'])).toBe('allowed');
    expect(outcome('google', 'GET', `${file}?alt=media`, ['drive.metadata.readonly'])).toBe('insufficient');
    expect(outcome('google', 'GET', `${file}/export`, ['drive.metadata'])).toBe('insufficient');
    expect(outcome('google', 'GET', `${file}?alt=media`, ['drive.readonly'])).toBe('allowed');
  });
  it.each(['$alt', '%24alt'])('Drive metadata refuses content through %s', (key) => {
    const url = `https://www.googleapis.com/drive/v3/files/1?${key}=media`;
    for (const scope of ['drive.metadata', 'drive.metadata.readonly']) {
      expect(outcome('google', 'GET', url, [scope])).toBe('insufficient');
    }
    expect(outcome('google', 'GET', url, ['drive.readonly'])).toBe('allowed');
  });
  it.each([
    'alt=json&alt=media', '$alt=json&alt=media', 'alt=media&%24alt=json',
    'ALT=media', 'Alt=media', 'format=metadata&format=full',
    'format=metadata&%24format=full', '$format=metadata', 'Format=metadata',
  ])('Google refuses ambiguous representation parameters for every scope: %s', (query) => {
    for (const scope of ['drive.metadata.readonly', 'drive', 'gmail.metadata', 'gmail.readonly']) {
      expect(outcome('google', 'GET', `${gmail}?${query}`, [scope])).toBe('not_mapped');
      expect(outcome('google', 'GET', `https://www.googleapis.com/drive/v3/files/1?${query}`, [scope])).toBe('not_mapped');
    }
  });
  it('ordinary broad-scope representations remain valid', () => {
    expect(outcome('google', 'GET', `${gmail}?format=full`, ['gmail.readonly'])).toBe('allowed');
    expect(outcome('google', 'GET', `${gmail}?format=raw`, ['gmail.modify'])).toBe('allowed');
    expect(outcome('google', 'GET', 'https://www.googleapis.com/drive/v3/files/1?alt=media', ['drive'])).toBe('allowed');
  });
  it.each(['messages', 'threads'])('gmail.metadata cannot search %s by content', (collection) => {
    const list = `https://gmail.googleapis.com/gmail/v1/users/me/${collection}`;
    for (const query of ['q=secret', '%71=secret', 'q=']) {
      expect(outcome('google', 'GET', `${list}?${query}`, ['gmail.metadata'])).toBe('insufficient');
      expect(outcome('google', 'GET', `${list}?${query}`, ['gmail.readonly'])).toBe('allowed');
    }
    expect(outcome('google', 'GET', list, ['gmail.metadata'])).toBe('allowed');
  });
  describe.each(['https://gmail.googleapis.com', 'https://www.googleapis.com'])('drafts-list search in the Gmail API on %s', (origin) => {
    const drafts = `${origin}/gmail/v1/users/me/drafts`;
    it.each(['q=secret', '%71=secret', 'q='])('gmail.metadata refuses %s', (query) => {
      expect(outcome('google', 'GET', `${drafts}?${query}`, ['gmail.metadata'])).toBe('insufficient');
    });
    it.each(['', '/synthetic-draft?format=metadata', '/synthetic-draft?format=minimal'])('gmail.metadata cannot read drafts even with a reduced representation: %s', (suffix) => {
      expect(outcome('google', 'GET', `${drafts}${suffix}`, ['gmail.metadata'])).toBe('insufficient');
    });
    it.each(['gmail.readonly', 'gmail.compose', 'gmail.modify', 'https://mail.google.com/'])('%s retains draft read access', (scope) => {
      for (const suffix of ['', '/synthetic-draft?format=metadata', '/synthetic-draft?format=minimal']) {
        expect(outcome('google', 'GET', `${drafts}${suffix}`, [scope])).toBe('allowed');
      }
    });
    it.each(['q=secret', '%71=secret', 'q='])('gmail.readonly still allows %s', (query) => {
      expect(outcome('google', 'GET', `${drafts}?${query}`, ['gmail.readonly'])).toBe('allowed');
    });
  });
  it('identity scopes read the user\'s own People profile and no other contact', () => {
    const people = 'https://people.googleapis.com/v1/people';
    for (const scope of ['userinfo.email', 'userinfo.profile']) {
      expect(outcome('google', 'GET', `${people}/me?personFields=names`, [scope])).toBe('allowed');
      expect(outcome('google', 'GET', `${people}/c123?personFields=names`, [scope])).toBe('insufficient');
      expect(outcome('google', 'GET', `${people}/me/connections`, [scope])).toBe('insufficient');
    }
    expect(outcome('google', 'GET', `${people}/c123?personFields=names`, ['contacts.readonly'])).toBe('allowed');
    expect(outcome('google', 'GET', `${people}/me/connections`, ['contacts.readonly'])).toBe('allowed');
  });
  it.each(['q=x&q=y', '$q=x', 'Q=x'])('Google refuses ambiguous search parameters: %s', (query) => {
    expect(outcome('google', 'GET', `${gmail}?${query}`, ['gmail.readonly'])).toBe('not_mapped');
  });
  it('calendar partition and free/busy scopes do not read or change events', () => {
    const events = 'https://www.googleapis.com/calendar/v3/calendars/c/events';
    for (const scope of ['calendar.events.freebusy', 'calendar.app.created', 'calendar.events.owned']) {
      expect(outcome('google', 'GET', events, [scope]), scope).not.toBe('allowed');
      expect(outcome('google', 'DELETE', `${events}/1`, [scope]), scope).not.toBe('allowed');
    }
  });
});

describe('listOperationRows', () => {
  it('lists every provider, and every row classifies as listed under a scope it names', () => {
    const rows = listOperationRows();
    expect(new Set(rows.map((row) => row.service))).toEqual(new Set(['google', 'github', 'slack', 'notion', 'salesforce', 'linear', 'hubspot']));
    for (const row of rows) {
      if (row.origin === null || row.needs === 'any' || row.pattern.includes('*:')) continue;
      const path = row.pattern.replace(/\/\*\*$/, '/a/b').replace(/\*/g, 'x');
      const body = row.graphql === 'query' ? { query: '{ viewer { id } }' }
        : row.graphql ? { query: `mutation { ${row.graphql.mutation}(input: {}) { clientMutationId } }` } : {};
      const verdict = evaluateOperation({ service: row.service, method: row.methods[0]!, url: `${row.origin}${path}`, body }, [row.needs[0]!]);
      expect(verdict.outcome, `${row.service} ${row.methods[0]} ${row.pattern}`).toBe('allowed');
    }
  });
});

describe('evaluateOperation', () => {
  describe('GitHub user and org routes follow the scopes GitHub documents', () => {
    const api = 'https://api.github.com';
    it('a profile scope adds no SSH, GPG or signing key, and starts no migration', () => {
      for (const path of ['/user/keys', '/user/gpg_keys', '/user/ssh_signing_keys', '/user/migrations']) {
        expect(outcome('github', 'POST', `${api}${path}`, ['user', 'repo']), path).not.toBe('allowed');
      }
      expect(outcome('github', 'POST', `${api}/user/keys`, ['write:public_key'])).toBe('allowed');
      expect(outcome('github', 'POST', `${api}/user/keys`, ['admin:public_key'])).toBe('allowed');
      expect(outcome('github', 'DELETE', `${api}/user/keys/1`, ['write:public_key'])).not.toBe('allowed');
      expect(outcome('github', 'DELETE', `${api}/user/keys/1`, ['admin:public_key'])).toBe('allowed');
      expect(outcome('github', 'POST', `${api}/user/gpg_keys`, ['write:gpg_key'])).toBe('allowed');
      expect(outcome('github', 'POST', `${api}/user/ssh_signing_keys`, ['write:ssh_signing_key'])).toBe('allowed');
      expect(outcome('github', 'PATCH', `${api}/user`, ['user'])).toBe('allowed');
    });

    it('read:user does not list private repositories or read mail addresses', () => {
      expect(outcome('github', 'GET', `${api}/user/repos`, ['read:user'])).not.toBe('allowed');
      expect(outcome('github', 'GET', `${api}/user/emails`, ['read:user'])).not.toBe('allowed');
      expect(outcome('github', 'GET', `${api}/user/repos`, ['repo'])).toBe('allowed');
      expect(outcome('github', 'GET', `${api}/user/emails`, ['user:email'])).toBe('allowed');
      expect(outcome('github', 'GET', `${api}/user/followers`, ['read:user'])).toBe('allowed');
      expect(outcome('github', 'GET', `${api}/user/codespaces/secrets`, ['user', 'repo'])).toBe('not_mapped');
    });

    it('an org read scope does not reach secrets, webhooks or secret scanning', () => {
      for (const path of ['/secret-scanning/alerts', '/actions/secrets', '/hooks', '/actions/runners/registration-token']) {
        expect(outcome('github', 'GET', `${api}/orgs/o${path}`, ['read:org', 'repo', 'admin:org']), path).toBe('not_mapped');
      }
      expect(outcome('github', 'GET', `${api}/orgs/o`, ['read:org'])).toBe('allowed');
      expect(outcome('github', 'GET', `${api}/orgs/o/members`, ['read:org'])).toBe('allowed');
      expect(outcome('github', 'GET', `${api}/orgs/o/repos`, ['read:org'])).not.toBe('allowed');
      expect(outcome('github', 'GET', `${api}/orgs/o/repos`, ['repo'])).toBe('allowed');
    });

    it('write:org manages membership only: not runners, secrets or the org itself', () => {
      expect(outcome('github', 'PUT', `${api}/orgs/o/memberships/u`, ['write:org'])).toBe('allowed');
      expect(outcome('github', 'POST', `${api}/orgs/o/invitations`, ['write:org'])).toBe('allowed');
      expect(outcome('github', 'POST', `${api}/orgs/o/actions/runners/registration-token`, ['write:org'])).not.toBe('allowed');
      expect(outcome('github', 'PUT', `${api}/orgs/o/actions/secrets/S`, ['write:org'])).not.toBe('allowed');
      expect(outcome('github', 'DELETE', `${api}/orgs/o`, ['admin:org', 'write:org'])).not.toBe('allowed');
      expect(outcome('github', 'POST', `${api}/orgs/o/repos`, ['repo'])).toBe('allowed');
      expect(outcome('github', 'POST', `${api}/orgs/o/repos`, ['write:org'])).not.toBe('allowed');
    });

    it('a team is managed by admin:org, and write:org only moves people', () => {
      expect(outcome('github', 'PUT', `${api}/orgs/o/teams/t/memberships/u`, ['write:org'])).toBe('allowed');
      expect(outcome('github', 'POST', `${api}/orgs/o/teams`, ['write:org'])).not.toBe('allowed');
      expect(outcome('github', 'DELETE', `${api}/orgs/o/teams/t`, ['write:org'])).not.toBe('allowed');
      expect(outcome('github', 'PUT', `${api}/orgs/o/teams/t/repos/o/r`, ['write:org'])).not.toBe('allowed');
      expect(outcome('github', 'DELETE', `${api}/orgs/o/teams/t`, ['admin:org'])).toBe('allowed');
      expect(outcome('github', 'GET', `${api}/orgs/o/teams/t/members`, ['read:org'])).toBe('allowed');
      expect(outcome('github', 'GET', `${api}/orgs/o/teams/t/repos`, ['read:org'])).not.toBe('allowed');
      expect(outcome('github', 'GET', `${api}/orgs/o/teams/t/repos`, ['repo'])).toBe('allowed');
      expect(outcome('github', 'GET', `${api}/orgs/o/teams/t/discussions`, ['read:org'])).toBe('not_mapped');
    });

    it('a repository write scope does not add keys, collaborators, webhooks, transfers or secrets', () => {
      for (const tail of ['keys', 'collaborators/u', 'hooks', 'transfer', 'actions/secrets/S']) {
        const method = tail.includes('/') ? 'PUT' : 'POST';
        expect(outcome('github', method, `${api}/repos/o/r/${tail}`, ['repo']), tail).toBe('not_mapped');
      }
      expect(outcome('github', 'POST', `${api}/repos/o/r/issues`, ['repo'])).toBe('allowed');
      expect(outcome('github', 'PUT', `${api}/repos/o/r/contents/a.txt`, ['public_repo'])).toBe('allowed');
    });

    it('a repository scope does not read org membership', () => {
      expect(outcome('github', 'GET', `${api}/orgs/o/members`, ['repo'])).not.toBe('allowed');
    });

    it('reads gists only under the gist scope', () => {
      expect(outcome('github', 'GET', `${api}/gists`, ['repo'])).not.toBe('allowed');
      expect(outcome('github', 'GET', `${api}/gists/1`, ['public_repo'])).not.toBe('allowed');
      expect(outcome('github', 'GET', `${api}/gists/1`, ['gist'])).toBe('allowed');
    });
  });

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
