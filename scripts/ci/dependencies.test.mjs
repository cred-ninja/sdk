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
