# @credninja/protocol

Shared Cred wire-protocol constants for Cred clients and servers.

```typescript
import {
  CRED_PROTOCOL_VERSION,
  CRED_PROTOCOL_VERSION_HEADER,
  isCredProtocolVersionSupported,
} from '@credninja/protocol';
```

## Cred Link contracts

`src/link.ts` (re-exported from the package root) holds the Cred Link Phase 1
contracts shared by the server, policy and widget packages: identifiers and
enums, error codes and bodies, the record types (`Connection`, `ClientGrant`,
`LinkTransaction`, `LinkClient`), request and response shapes for every
`/link/v1` route, widget `postMessage` and redirect results, the `LinkStore`,
`LinkSecretStore`, `PermissionPort` and `LinkHooks` interfaces, the scope
catalog, and pure helpers (envelope encode/decode, scope-set math, query and
message parsing). It has no dependencies and runs in browsers and Node.

```typescript
import { decodeLinkEnvelope, isScopeSubset, LINK_PATHS } from '@credninja/protocol';
```
