#!/usr/bin/env node

const fs = require('node:fs');
const path = require('node:path');

const packageTypes = [
  ['dist/cjs', 'commonjs'],
  ['dist/esm', 'module'],
];

for (const [relativeDir, type] of packageTypes) {
  const dir = path.resolve(process.cwd(), relativeDir);
  if (!fs.existsSync(dir)) {
    console.error(`Missing build output directory: ${relativeDir}`);
    process.exitCode = 1;
    continue;
  }

  fs.writeFileSync(
    path.join(dir, 'package.json'),
    `${JSON.stringify({ type }, null, 2)}\n`,
  );
}
