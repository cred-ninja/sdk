// A mock third-party resource server that speaks plain OAuth bearer, not
// WIMSE. It stands in for the Google Calendar API, so Cred's existing
// provider tables (scopes, operation classifier, URL allowlist) apply
// unchanged: a read (GET events, scope calendar.readonly) and a write (POST
// events, scope calendar.events).
//
// Cred only ever calls https://www.googleapis.com. In this process only,
// globalThis.fetch is wrapped so those calls go to this local server over
// plain HTTP; every other URL passes through. No Cred code is changed. The
// headers recorded here are the ones Cred actually sent.
import http from 'node:http';

export async function startMockProvider() {
  const received = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      received.push({ method: req.method, path: req.url, headers: { ...req.headers }, body });
      const auth = req.headers.authorization ?? '';
      if (!auth.startsWith('Bearer ')) {
        res.writeHead(401, { 'content-type': 'application/json' }).end('{"error":"unauthorized"}');
        return;
      }
      if (req.method === 'GET' && req.url.startsWith('/calendar/v3/calendars/primary/events')) {
        res.writeHead(200, { 'content-type': 'application/json' })
          .end(JSON.stringify({ kind: 'calendar#events', items: [{ id: 'evt1', summary: 'IETF 127 hackathon' }] }));
        return;
      }
      if (req.method === 'POST' && req.url.startsWith('/calendar/v3/calendars/primary/events')) {
        res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ id: 'evt2', status: 'confirmed' }));
        return;
      }
      res.writeHead(404, { 'content-type': 'application/json' }).end('{"error":"not_found"}');
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const realFetch = globalThis.fetch;
  globalThis.fetch = (input, init) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    if (url.startsWith('https://www.googleapis.com/')) {
      return realFetch(`http://127.0.0.1:${port}${url.slice('https://www.googleapis.com'.length)}`, init);
    }
    return realFetch(input, init);
  };
  return {
    port,
    received,
    async close() {
      globalThis.fetch = realFetch;
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}
