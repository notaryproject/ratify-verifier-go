# License Checker Verifier

The license checker verifier inspects an [SPDX](https://spdx.dev/) SBOM (in
tag-value format) attached to a subject image and validates that every package
declares a license from a configured allow list.

## Configuration

`VerifierOptions` fields:

| Field | Required | Description |
| --- | --- | --- |
| `Name` | yes | Instance name of the verifier. |
| `AllowedLicenses` | no | List of permitted licenses. A package whose concluded license is not present fails verification. If empty, all package licenses are treated as disallowed. |
| `ArtifactTypes` | no | Artifact types the verifier is verifiable against. If empty, the verifier is verifiable against any artifact. |

## Behavior

For each blob (layer) referenced by the artifact manifest, the verifier parses
the SPDX tag-value document, collects the concluded license of every package,
and fails if any package license is not in `AllowedLicenses`. The failing
packages are reported in the verification result `Detail` under the
`disallowedLicenses` key.
