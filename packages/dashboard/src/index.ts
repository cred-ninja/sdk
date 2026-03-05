import path from 'path';
import fs from 'fs';
import express from 'express';
import { createVault } from '@credninja/vault';
import { getVaultPassphrase } from './config';
import { createAuthRouter } from './auth';
import { createDashboardRouter } from './dashboard';

const PORT = 3456;
const VAULT_PATH = path.resolve(__dirname, '..', 'data', 'vault.json');

async function main() {
  // Ensure data directory exists
  const dataDir = path.dirname(VAULT_PATH);
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }

  // Initialize vault
  const vault = await createVault({
    passphrase: getVaultPassphrase(),
    storage: 'file',
    path: VAULT_PATH,
  });

  // Create Express app
  const app = express();

  // Mount routes
  app.use(createAuthRouter(vault));
  app.use(createDashboardRouter(vault));

  // Start server
  app.listen(PORT, () => {
    console.log(`\n  Cred Dashboard running at http://localhost:${PORT}\n`);
  });
}

main().catch((err) => {
  console.error('Failed to start:', err);
  process.exit(1);
});
