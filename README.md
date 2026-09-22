# ratify-verifier-go

A collection of [ratify-go](https://github.com/notaryproject/ratify-go)
`Verifier` implementations. Each verifier is a self-contained Go module that
implements the `ratify.Verifier` interface and can be imported independently.

## Verifiers

| Verifier | Module | Description |
| --- | --- | --- |
| [notation](./notation) | `github.com/notaryproject/ratify-verifier-go/notation` | Verifies [Notation](https://notaryproject.dev/) signatures. |
| [cosign](./cosign) | `github.com/notaryproject/ratify-verifier-go/cosign` | Verifies [Cosign](https://docs.sigstore.dev/cosign/overview/) (Sigstore) signatures, key-based and keyless. |
| [licensechecker](./licensechecker) | `github.com/notaryproject/ratify-verifier-go/licensechecker` | Validates that packages in an SPDX SBOM use only allowed licenses. |
| [sbom](./sbom) | `github.com/notaryproject/ratify-verifier-go/sbom` | Validates an SPDX JSON SBOM against disallowed licenses and packages. |
| [schemavalidator](./schemavalidator) | `github.com/notaryproject/ratify-verifier-go/schemavalidator` | Validates artifact blobs against configured JSON schemas by media type. |
| [vulnerabilityreport](./vulnerabilityreport) | `github.com/notaryproject/ratify-verifier-go/vulnerabilityreport` | Validates a SARIF vulnerability report against severity, CVE, and freshness policies. |

The `licensechecker`, `sbom`, `schemavalidator`, and `vulnerabilityreport`
verifiers are ports of the corresponding built-in verifier plugins from
[Ratify v1](https://github.com/ratify-project/ratify).

## Usage

Each module is versioned and released independently. Add the verifier you need
as a dependency, for example:

```sh
go get github.com/notaryproject/ratify-verifier-go/sbom
```

Then construct the verifier with its `NewVerifier` constructor and register it
with the ratify-go executor. See the per-verifier `README.md` for the available
`VerifierOptions`.

## Development

Run the unit tests for every module:

```sh
make test
```
