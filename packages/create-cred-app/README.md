# create-cred-app

Scaffold a self-hosted [Cred](https://cred.ninja) server in seconds.

## Usage

```bash
npx create-cred-app my-cred-server
cd my-cred-server
npm start
```

Open [http://localhost:3456/connect](http://localhost:3456/connect) to manage OAuth providers.

## What You Get

- **Express server** powered by `@credninja/server`
- **SQLite vault** — zero config, no external database needed
- **Admin UI** at `/connect` for managing OAuth provider connections
- **Auto-generated credentials** — vault passphrase, admin token, agent token
- **Pre-configured** for Google, GitHub, and Slack

## How It Works

1. `create-cred-app` scaffolds a project with `@credninja/server` as a dependency
2. Generates a `.env` with a random vault passphrase and tokens
3. Run `npm start` to launch the server with the built-in CLI
4. Use the admin UI to connect OAuth providers
5. Give your AI agent the agent token and server URL — it uses `POST /api/v1/delegate` through `@credninja/sdk` to get access tokens

## Documentation

- [cred.ninja](https://cred.ninja) — Project home
- [cred.ninja/docs](https://cred.ninja/docs) — Full docs
- [TOFU proof of possession](https://github.com/cred-ninja/sdk/blob/main/docs/tofu-proof-of-possession.md) — Self-hosted agent identity flow
- [@credninja/server](https://github.com/cred-ninja/sdk/tree/main/packages/server) — Server package
- [@credninja/sdk](https://github.com/cred-ninja/sdk/tree/main/packages/sdk) — TypeScript SDK for agents

## License

MIT
