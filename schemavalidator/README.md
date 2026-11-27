# Schema Validator Verifier

The schema validator verifier validates the blobs of an artifact against
configured [JSON Schemas](https://json-schema.org/), keyed by blob media type.

## Configuration

`VerifierOptions` fields:

| Field | Required | Description |
| --- | --- | --- |
| `Name` | yes | Instance name of the verifier. |
| `Schemas` | yes | Map of blob media type to a schema reference loader source (e.g. a `file://` or `https://` URL). |
| `ArtifactTypes` | no | Artifact types the verifier is verifiable against. If empty, the verifier is verifiable against any artifact. |

## Behavior

For every blob (layer) referenced by the artifact manifest, the verifier looks
up the schema configured for the blob's media type and validates the blob
against it. Verification fails if a blob's media type has no configured schema
or if the blob does not conform to its schema.
