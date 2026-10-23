# Offline eMudhra certificate fixtures

The twelve `*.we-have-a-problem.com.pem` chains were downloaded from
https://emudhra.we-have-a-problem.com/chains.zip on 2026-10-22. The publisher
captured them on 2026-10-20. They cover six compromised TLS intermediate keys,
each through the emSign and AAA cross-signed paths. `roots.pem` contains the
three associated public root certificates from that site's `roots.json`.
These roots are deliberately distrusted; they are only loaded by the regression
test to prove that the verifier independently rejects the compromised keys.
Never install them in an operating-system or application trust store.

Downloaded archive SHA-256:
`8a2edc81b6c51e3ad27d45ca1e441ec84c961e2dee0fc547f2a02c0f74315f95`.
Downloaded roots JSON SHA-256:
`119f32cd81a6b5a4e3c4c2df5fe07daa90dc43cafa123a62f0394f1895d92380`.

`control-root.pem` and `control-leaf.pem` are an independently generated test CA
and localhost server certificate. Their private keys were discarded. They provide
a successful verification control and a hostname-mismatch control.

Verification uses 2026-10-23 00:00:00 UTC, inside the certificates' validity
periods, so a later expiration does not masquerade as successful remediation.
No test connects to the public test hosts or uses production credentials.
