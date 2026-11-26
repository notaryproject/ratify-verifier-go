# ratify-verifier-go

Verifier implementations for [Ratify](https://github.com/notaryproject/ratify).
Each verifier is an independent Go module:

| Module | Plugin type | Description |
|---|---|---|
| [`notation`](./notation) | `notation` | Verifies [Notation](https://notaryproject.dev) signatures. |
| [`cosign`](./cosign) | `cosign` | Verifies [Sigstore Cosign](https://www.sigstore.dev) signatures. |

## Usage

### As a library

Construct a verifier directly and pass it to a
[`ratify.Executor`](https://pkg.go.dev/github.com/notaryproject/ratify-go):

```go
v, err := notation.NewVerifier(&notation.VerifierOptions{...})
```

### As a Ratify plugin

Each module provides a `Factory` that implements the
[`plugin`](https://pkg.go.dev/github.com/notaryproject/ratify-go/plugin)
contract of `ratify-go` and owns the schema of the verifier `parameters`, plus
a `register` package that registers the factory to `plugin.Default`:

```go
import (
	_ "github.com/notaryproject/ratify-verifier-go/cosign/register"
	_ "github.com/notaryproject/ratify-verifier-go/notation/register"
)
```

#### Notation parameters

| Parameter | Description |
|---|---|
| `certificates` | Trust stores. Each entry has an optional `type` (`ca`, `tsa` or `signingAuthority`) and one or more key providers keyed by type, e.g. `inline` or `files`. Required. |
| `scopes` | Repository scopes of the trust policy. Defaults to `*`. |
| `trustedIdentities` | Trusted identities. Defaults to `*`. |
| `pluginDirectory` | Directory with Notation verification plugins (`<dir>/<name>/notation-<name>`), e.g. for AWS Signer. |
| `pluginConfig` | Key-value pairs passed to verification plugins, e.g. `aws-region`. |

#### Cosign parameters

| Parameter | Description |
|---|---|
| `trustPolicies` | List of trust policies. Each has `scopes` (defaults to the executor scopes), keyless identity options (`certificateIdentity`, `certificateIdentityRegex`, `certificateOIDCIssuer`, `certificateOIDCIssuerRegex`), `keys` (one key provider keyed by type), `ignoreTLog`, `ignoreCTLog` and `ignoreObserverTimestamps`. Required. |
