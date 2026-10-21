# draft-asor-wimse-agent-delegation-chain-02 interop vectors

The 35 `.json` files here are copied verbatim from
[attenu-io/attenu-guard](https://github.com/attenu-io/attenu-guard) at tag
`v0.20.0` (commit `89e97cd617236e1bec7739371a71e2cb0e01b649`), path
`tests/vectors-02/`, licensed Apache-2.0. They are byte-identical to the copy
in `cred-ninja/protocol` under `conformance/asor-delegation-chain/vectors-02/`.
Do not edit them; refresh by copying a newer tag and updating this pin.

`../../asor-02-vectors.test.ts` scores every file with
`verifyAgentDelegationChain()`, using each file's `verifier` block
(`accepted_algs`, `audience`) and its HS256 `signer` block as the key.
