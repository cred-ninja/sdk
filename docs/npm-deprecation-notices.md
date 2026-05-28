# npm deprecation notices

Use this exact notice for npm registry deprecation metadata:

> DEPRECATED: use cred-ninja/daemon. Current package continues to work; security fixes only until daemon v0; migration guidance is not yet available.

The package descriptions in this repository have been updated with the same notice so the next published package metadata also surfaces the deprecation consistently. To update the npm registry deprecation banner for already-published versions, run:

```sh
npm deprecate '@credninja/vault@*' 'DEPRECATED: use cred-ninja/daemon. Current package continues to work; security fixes only until daemon v0; migration guidance is not yet available.'
npm deprecate '@credninja/server@*' 'DEPRECATED: use cred-ninja/daemon. Current package continues to work; security fixes only until daemon v0; migration guidance is not yet available.'
npm deprecate '@credninja/sdk@*' 'DEPRECATED: use cred-ninja/daemon. Current package continues to work; security fixes only until daemon v0; migration guidance is not yet available.'
npm deprecate '@credninja/oauth@*' 'DEPRECATED: use cred-ninja/daemon. Current package continues to work; security fixes only until daemon v0; migration guidance is not yet available.'
npm deprecate '@credninja/mcp@*' 'DEPRECATED: use cred-ninja/daemon. Current package continues to work; security fixes only until daemon v0; migration guidance is not yet available.'
npm deprecate '@credninja/ai@*' 'DEPRECATED: use cred-ninja/daemon. Current package continues to work; security fixes only until daemon v0; migration guidance is not yet available.'
npm deprecate '@credninja/guard@*' 'DEPRECATED: use cred-ninja/daemon. Current package continues to work; security fixes only until daemon v0; migration guidance is not yet available.'
npm deprecate 'create-cred-app@*' 'DEPRECATED: use cred-ninja/daemon. Current package continues to work; security fixes only until daemon v0; migration guidance is not yet available.'
```

`@credninja/tofu` has package metadata in this repository but was not present on the public npm registry when checked. Its package description has the same notice. If it is published or exists in a private registry, use:

```sh
npm deprecate '@credninja/tofu@*' 'DEPRECATED: use cred-ninja/daemon. Current package continues to work; security fixes only until daemon v0; migration guidance is not yet available.'
```
