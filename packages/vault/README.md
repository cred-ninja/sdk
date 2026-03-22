# @credninja/vault

**Local-first encrypted token vault for OAuth credentials.**

AES-256-GCM encryption. PBKDF2-SHA256 key derivation (100,000 iterations). Zero cloud dependency. Works offline. Store OAuth tokens securely in a SQLite database or an encrypted JSON file.

No AWS. No KMS. No managed service required. Just a passphrase and a local file.

---

## Installation

```bash
npm install @credninja/vault
# SQLite backend (recommended for production):
npm install better-sqlite3
```

---

## Quick Start

```typescript
import { createVault } from '@credninja/vault';

const vault = await createVault({
  passphrase: process.env.VAULT_PASSPHRASE!,  // Never stored, only used to derive key
  storage: 'sqlite',                           // or 'file'
  path: './cred-vault.db',                    // path to vault file
});

// Store tokens after OAuth flow
await vault.store({
  provider: 'google',
  userId: 'user-123',
  accessToken: tokens.access_token,
  refreshToken: tokens.refresh_token,
  expiresAt: new Date(Date.now() + tokens.expires_in * 1000),
  scopes: ['calendar.readonly', 'gmail.readonly'],
});

// Retrieve (decrypts automatically)
const creds = await vault.get({ provider: 'google', userId: 'user-123' });
console.log(creds?.accessToken); // ya29.A0AfH6...

// List all connections for a user
const connections = await vault.list({ userId: 'user-123' });

// Delete
await vault.delete({ provider: 'google', userId: 'user-123' });
```

---

## Storage Backends

### SQLite (Recommended)

Best for: production apps, multiple users, concurrent access.

```typescript
const vault = await createVault({
  passphrase: process.env.VAULT_PASSPHRASE!,
  storage: 'sqlite',
  path: './vault.db',
});
```

Requires `better-sqlite3` as a runtime dependency. Auto-creates the table on first use.

### Encrypted JSON File

Best for: CLI tools, single-user scripts, zero-dep environments.

```typescript
const vault = await createVault({
  passphrase: process.env.VAULT_PASSPHRASE!,
  storage: 'file',
  path: './vault.json',
});
```

No additional dependencies. Atomic writes (temp file + rename) prevent corruption. The JSON file stores ciphertext: each token value is individually AES-256-GCM encrypted.

---

## Auto-Refresh

If you provide an OAuth adapter (compatible with `@credninja/oauth`), the vault will automatically refresh expired tokens when you call `get()`:

```typescript
import { createVault } from '@credninja/vault';
import { OAuthClient, GoogleAdapter } from '@credninja/oauth';

const vault = await createVault({ passphrase: '...', storage: 'sqlite', path: './vault.db' });

const adapter = new GoogleAdapter();

const creds = await vault.get({
  provider: 'google',
  userId: 'user-123',
  adapter,                                  // Enables auto-refresh
  clientId: process.env.GOOGLE_CLIENT_ID!,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
});
// If the token was expired, it's now refreshed and the new token is already persisted.
// creds.accessToken is guaranteed to be fresh (or null if refresh failed).
```

---

## Security Model

### Encryption

Every access token and refresh token is individually encrypted using **AES-256-GCM** before being written to disk. The encryption is authenticated: any tampering with the ciphertext will cause decryption to throw, never silently corrupt.

### Key Derivation

Your passphrase is **never stored**. Instead, it's used to derive a 256-bit AES key via **PBKDF2-SHA256** with 100,000 iterations:

```
key = PBKDF2-SHA256(passphrase, salt, iterations=100000, keyLength=32)
```

The **salt** is random (32 bytes) and stored in a `.salt` file alongside your vault. The salt is not secret. Only your passphrase needs to be kept private.

### IV (Initialization Vector)

Each encryption operation uses a **fresh random 16-byte IV** (`crypto.randomBytes(16)`). This ensures that encrypting the same token twice produces different ciphertext, preventing pattern analysis.

### What's on Disk

- Ciphertext (hex-encoded)
- IV (hex-encoded, 16 bytes)
- GCM auth tag (hex-encoded, 16 bytes)
- Salt (hex-encoded, 32 bytes, stored in `.salt` file)

**What's never on disk:** passphrase, derived key, plaintext tokens.

### Threat Model

✅ Protects against: stolen vault file, compromised storage backend, unauthorized file access  
✅ Guarantees: wrong passphrase throws (GCM auth tag verification), never returns garbage  
⚠️ Does not protect against: compromise of the machine while the vault is open (key is in memory), keyloggers capturing the passphrase  

---

## API Reference

### `createVault(options)` → `Promise<CredVault>`

Factory function that creates and initializes a vault in one call.

| Option | Type | Description |
|--------|------|-------------|
| `passphrase` | `string` | Encryption passphrase. Never stored. |
| `storage` | `'sqlite' \| 'file'` | Backend type |
| `path` | `string` | Path to vault file (`.db` or `.json`) |

### `vault.store(input)`

Store (or update) credentials for a provider + userId.

### `vault.get(input)` → `VaultEntry | null`

Retrieve credentials. Returns `null` if not found. Auto-refreshes if expired + adapter provided.

### `vault.delete(input)`

Remove credentials. Idempotent.

### `vault.list({ userId })` → `VaultEntry[]`

List all provider connections for a userId.

---

## Custom Storage Backends

Implement the `StorageBackend` interface to add Redis, PostgreSQL, or any other store:

```typescript
import type { StorageBackend } from '@credninja/vault';

class RedisBackend implements StorageBackend {
  async init() { /* connect */ }
  async store(row) { /* HSET */ }
  async get(provider, userId) { /* HGET */ }
  async delete(provider, userId) { /* HDEL */ }
  async list(userId) { /* HSCAN */ }
}
```

---

## Pairing With Cred Server

`@credninja/vault` is great for single-machine and CLI use. When you need a separate broker process, browser-based provider connection flows, or centralized policy enforcement, pair it with the self-hosted [`@credninja/server`](../server).

---

## License

MIT
