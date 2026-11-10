// Separate-process SQLite tests load current source, never stale dist output.
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const ts = require('typescript');
require.extensions['.ts'] = (module, filename) => {
  const source = readFileSync(filename, 'utf8').replace(/(['"])\.\/budget-operation\.js\1/g, "'./budget-operation.ts'");
  const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020, esModuleInterop: true } });
  module._compile(compiled.outputText, filename);
};
const { DurableBudgetStore, prepareBudgetOperation, executeBudgetedOperation } = require(join(__dirname, '..', '..', 'durable-budget-admission.ts'));
const Database = require('better-sqlite3');
let store;
let config;
let lock;
process.on('message', async message => {
  try {
    if (message.type === 'configure') {
      config = message;
      if (config.mode === 'lock') {
        lock = new Database(config.path);
        lock.exec('BEGIN IMMEDIATE');
      } else {
        store = new DurableBudgetStore({ path: config.path, ...config.identity, busyTimeoutMs: 5000 });
      }
      process.send({ type: 'ready', pid: process.pid });
      return;
    }
    if (message.type !== 'go') return;
    if (config.mode === 'lock') {
      lock.exec('ROLLBACK'); lock.close(); process.send({ type: 'done', pid: process.pid, sends: 0, denials: 0 }); process.disconnect(); return;
    }
    const operation = prepareBudgetOperation({ method: 'POST', target: 'https://provider.example/items?q=a', body: Buffer.from('payload'), headers: { 'Content-Type': 'text/plain' } });
    if (config.mode === 'crash-claimed' || config.mode === 'crash-reserved') {
      store.reserve(config.auth, 'crash-request', operation);
      if (config.mode === 'crash-claimed') store.claim(config.auth, 'crash-request', operation, `worker-${process.pid}`);
      process.send({ type: 'crash-ready', pid: process.pid });
      // Parent sends SIGKILL: no graceful close or finalization.
      return;
    }
    if (config.registration) {
      store.registerConnection(config.registration.connection);
      store.registerGrant(config.registration.grant);
      for (const token of config.registration.tokens) store.registerToken(token);
    }
    let sends = 0;
    let denials = 0;
    for (let i = 0; i < config.count; i++) {
      const key = config.sharedKey ?? `worker-${config.index}-request-${i}`;
      try {
        await executeBudgetedOperation(store, config.auth, key, operation, `worker-${process.pid}`, async () => {
          sends++;
          await new Promise(resolve => setTimeout(resolve, 2));
          return { reference: `result-${config.index}-${i}` };
        });
      } catch (error) {
        if (error.code !== 'budget_exceeded') throw error;
        denials++;
      }
    }
    store.close();
    process.send({ type: 'done', pid: process.pid, sends, denials });
    process.disconnect();
  } catch (error) {
    process.send({ type: 'failure', code: error.code ?? error.name });
    store?.close();
    process.exitCode = 1;
    process.disconnect();
  }
});
