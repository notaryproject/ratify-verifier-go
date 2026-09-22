# SBOM Verifier

The SBOM verifier validates an [SPDX](https://spdx.dev/) JSON SBOM attached to a
subject image against a deny list of licenses and packages.

## Configuration

`VerifierOptions` fields:

| Field | Required | Description |
| --- | --- | --- |
| `Name` | yes | Instance name of the verifier. |
| `DisallowedLicenses` | no | Licenses that are not permitted. A package whose license contains any of these (whole-word match) fails verification. |
| `DisallowedPackages` | no | Packages that are not permitted, matched by name, or by name and version. |
| `ArtifactTypes` | no | Artifact types the verifier is verifiable against. Defaults to `application/spdx+json`. |

## Behavior

The verifier parses the SPDX JSON blob and, if any deny list is configured,
checks every package for license and package violations. Violations are reported
in the verification result `Detail` under the `licenseViolations` and
`packageViolations` keys, along with the SBOM `creationInfo`. If no deny list is
configured, the SBOM is considered valid as long as it parses.
