// The Google URL families sit in front of the operation tables. A scope the tables
// accept but the families do not name can never make the call, however the tables read.
import { describe, expect, it } from 'vitest';
import { listOperationRows } from '@credninja/guard';
import { isAllowedGoogleScopeEndpoint } from '../google-scopes.js';

describe('Google URL families and operation tables', () => {
  it('every scope a Google row names passes the URL family check for that row', () => {
    const unreachable: string[] = [];
    for (const row of listOperationRows()) {
      if (row.service !== 'google' || row.needs === 'any') continue;
      const url = `${row.origin}${row.pattern.replace(/\/\*\*$/, '/a/b').replace(/\*/g, 'x')}`;
      for (const scope of row.needs) {
        if (!isAllowedGoogleScopeEndpoint(url, [scope])) unreachable.push(`${scope} -> ${row.methods[0]} ${url}`);
      }
    }
    expect(unreachable).toEqual([]);
  });
});
