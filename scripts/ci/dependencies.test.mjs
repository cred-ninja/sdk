import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const root = new URL('../../', import.meta.url);
const manifest = JSON.parse(readFileSync(new URL('package.json', root), 'utf8'));
const lock = JSON.parse(readFileSync(new URL('package-lock.json', root), 'utf8'));

test('combined Python constraints include the dnspython security patch where Python supports it', () => {
  const constraints = readFileSync(new URL('scripts/python-test-constraints.txt', root), 'utf8');
  assert.match(constraints, /^dnspython==2\.9\.2 ; python_full_version >= '3\.11'$/m);
});

test('the Hono security override is reflected in every locked copy', () => {
  const expected = manifest.overrides.hono;
  assert.match(expected, /^\d+\.\d+\.\d+$/);
  const copies = Object.entries(lock.packages).filter(([path]) => /(?:^|\/)node_modules\/hono$/.test(path));
  assert.ok(copies.length > 0, 'Hono must be present in the dependency lock');
  for (const [path, pkg] of copies) assert.equal(pkg.version, expected, `${path} must match the security override`);
});

test('GraphQL runtime consumers and generated servers declare its supported Node range', () => {
  const graphql = lock.packages['node_modules/graphql'];
  assert.equal(graphql.engines.node, '^22.0.0 || ^24.0.0 || >=26.0.0');
  for (const path of ['', 'packages/guard', 'packages/server', 'packages/mcp']) {
    const file = path ? `${path}/package.json` : 'package.json';
    const pkg = JSON.parse(readFileSync(new URL(file, root), 'utf8'));
    assert.equal(pkg.engines.node, graphql.engines.node, `${file} must match GraphQL support`);
    assert.equal(lock.packages[path].engines.node, pkg.engines.node, `${file} must match the lock`);
  }
  const template = JSON.parse(readFileSync(new URL('packages/create-cred-app/template/package.json', root), 'utf8'));
  assert.equal(template.engines?.node, graphql.engines.node, 'generated servers must declare the server runtime contract');
});
