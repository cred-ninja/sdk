import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { npmPackEntries, npmPackFilename } from '../npm-pack.mjs';

const first = { name: 'example-one', filename: 'example-one-1.0.0.tgz', files: [{ path: 'dist/index.js' }] };
const second = { name: '@example/two', filename: 'example-two-1.0.0.tgz', files: [{ path: 'dist/index.js' }] };

test('generated projects approve only the reviewed native build version they need', () => {
  const read = (path) => JSON.parse(readFileSync(new URL(`../../${path}`, import.meta.url), 'utf8'));
  const root = read('package.json');
  const template = read('packages/create-cred-app/template/package.json');
  const native = read('package-lock.json').packages['node_modules/better-sqlite3'];
  assert.ok(native, 'SQLite is a required server dependency');
  if (native.hasInstallScript) {
    assert.equal(template.allowScripts?.[`better-sqlite3@${native.version}`], true);
  }
  for (const [pkg, allowed] of Object.entries(template.allowScripts ?? {})) {
    assert.equal(allowed, true);
    assert.equal(root.allowScripts[pkg], true, `${pkg} must already have repository approval`);
  }
});

for (const [format, inventory] of [
  ['npm 11 array', [first, second]],
  ['npm 12 keyed object', { 'example-one': first, '@example/two': second }],
]) {
  test(`retains every package in ${format}`, () => {
    assert.deepEqual(npmPackEntries(inventory), [first, second]);
  });
}

for (const value of [null, false, 42, 'not an inventory', [], {}, [null], [[]], { example: null }, { example: 'invalid' }]) {
  test(`refuses malformed or empty pack inventory ${JSON.stringify(value)}`, () => {
    assert.throws(() => npmPackEntries(value), /Invalid or empty npm pack inventory/);
  });
}

test('single-workspace filename is identical for both actual npm output shapes', () => {
  assert.equal(npmPackFilename([first]), first.filename);
  assert.equal(npmPackFilename({ 'example-one': first }), first.filename);
});

test('single-workspace packing refuses multiple tarballs', () => {
  assert.throws(() => npmPackFilename([first, second]), /one valid tarball filename/);
  assert.throws(() => npmPackFilename({ 'example-one': first, '@example/two': second }), /one valid tarball filename/);
});

for (const filename of [undefined, null, 42, '', '../escape.tgz', 'dir/nested.tgz', 'dir\\nested.tgz', '/absolute.tgz', 'not-a-tarball.json', 'line\nbreak.tgz']) {
  test(`refuses invalid tarball filename ${JSON.stringify(filename)}`, () => {
    assert.throws(() => npmPackFilename([{ ...first, filename }]), /one valid tarball filename/);
  });
}
