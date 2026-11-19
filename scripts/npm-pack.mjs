/** npm 11 emits an array; npm 12 emits a package-name-keyed object. */
export function npmPackEntries(output) {
  const entries = Array.isArray(output)
    ? output
    : output !== null && typeof output === 'object'
      ? Object.values(output)
      : [];
  if (!entries.length || entries.some((entry) => entry === null || typeof entry !== 'object' || Array.isArray(entry))) {
    throw new Error('Invalid or empty npm pack inventory');
  }
  return entries;
}

/** A single-workspace pack must identify exactly one local tarball. */
export function npmPackFilename(output) {
  const entries = npmPackEntries(output);
  const filename = entries.length === 1 ? entries[0].filename : undefined;
  if (typeof filename !== 'string' || !/^[^/\\\u0000-\u001f]+\.tgz$/u.test(filename)) {
    throw new Error('npm pack did not return one valid tarball filename');
  }
  return filename;
}
