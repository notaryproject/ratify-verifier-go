/*
Copyright The Ratify Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package schemavalidator

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/notaryproject/ratify-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const verifierTypeSchemaValidator = "schemavalidator"

// VerifierOptions contains the options for creating a new schema validator
// verifier.
type VerifierOptions struct {
	// Name is the instance name of the verifier to be created. Required.
	Name string

	// Schemas maps a blob media type to the JSON schema that blobs of that
	// media type are validated against. The schema value is a reference loader
	// source, e.g. a `file://` or `https://` URL. Required.
	Schemas map[string]string

	// ArtifactTypes is the list of artifact types that this verifier can
	// verify. Optional. If empty, the verifier is verifiable against any
	// artifact type.
	ArtifactTypes []string
}

// Verifier is a ratify.Verifier implementation that validates the blobs of an
// artifact against configured JSON schemas keyed by media type.
type Verifier struct {
	name          string
	schemas       map[string]string
	artifactTypes []string
}

// NewVerifier creates a new schema validator verifier.
func NewVerifier(opts *VerifierOptions) (*Verifier, error) {
	if opts == nil {
		return nil, fmt.Errorf("verifier options are required")
	}
	if opts.Name == "" {
		return nil, fmt.Errorf("verifier name is required")
	}
	if len(opts.Schemas) == 0 {
		return nil, fmt.Errorf("at least one schema is required")
	}

	return &Verifier{
		name:          opts.Name,
		schemas:       opts.Schemas,
		artifactTypes: opts.ArtifactTypes,
	}, nil
}

// Name returns the name of the verifier.
func (v *Verifier) Name() string {
	return v.name
}

// Type returns the type of the verifier which is always `schemavalidator`.
func (v *Verifier) Type() string {
	return verifierTypeSchemaValidator
}

// Verifiable returns true if the artifact type is configured for this verifier.
// If no artifact types are configured, it returns true for any artifact.
func (v *Verifier) Verifiable(artifact ocispec.Descriptor) bool {
	if len(v.artifactTypes) == 0 {
		return true
	}
	for _, t := range v.artifactTypes {
		if t == artifact.ArtifactType {
			return true
		}
	}
	return false
}

// Verify validates every blob of the artifact against the configured schema for
// its media type.
func (v *Verifier) Verify(ctx context.Context, opts *ratify.VerifyOptions) (*ratify.VerificationResult, error) {
	result := &ratify.VerificationResult{
		Verifier: v,
	}

	manifestBytes, err := opts.Store.FetchManifest(ctx, opts.Repository, opts.ArtifactDescriptor)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch manifest for artifact: %w", err)
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal manifest: %w", err)
	}

	if len(manifest.Layers) == 0 {
		result.Err = fmt.Errorf("no blobs found for referrer %s@%s", opts.Repository, opts.ArtifactDescriptor.Digest.String())
		result.Description = "Schema validation failed"
		return result, nil
	}

	for _, blobDesc := range manifest.Layers {
		refBlob, err := opts.Store.FetchBlob(ctx, opts.Repository, blobDesc)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch blob for subject %s digest %s: %w", opts.Repository, blobDesc.Digest, err)
		}

		if err := v.processMediaType(blobDesc.MediaType, refBlob); err != nil {
			result.Err = fmt.Errorf("schema validation failed for digest %s, media type %s: %w", blobDesc.Digest, blobDesc.MediaType, err)
			result.Description = "Schema validation failed"
			return result, nil
		}
	}

	result.Description = "Schema validation succeeded for configured media types"
	return result, nil
}

func (v *Verifier) processMediaType(mediaType string, refBlob []byte) error {
	schema, ok := v.schemas[mediaType]
	if !ok || len(schema) == 0 {
		return fmt.Errorf("media type not configured for plugin: %s", mediaType)
	}
	return validate(schema, refBlob)
}
