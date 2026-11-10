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

package licensechecker

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/notaryproject/ratify-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const verifierTypeLicenseChecker = "licensechecker"

// PackageLicense holds the license concluded for a single SPDX package.
type PackageLicense struct {
	// PackageName is the name of the package.
	PackageName string

	// PackageLicense is the concluded license of the package.
	PackageLicense string
}

// VerifierOptions contains the options for creating a new license checker
// verifier.
type VerifierOptions struct {
	// Name is the instance name of the verifier to be created. Required.
	Name string

	// AllowedLicenses is the list of licenses that are permitted. A package
	// whose concluded license is not in this list causes the verification to
	// fail. Optional. If empty, every package license is treated as
	// disallowed.
	AllowedLicenses []string

	// ArtifactTypes is the list of artifact types that this verifier can
	// verify. Optional. If empty, the verifier is verifiable against any
	// artifact type.
	ArtifactTypes []string
}

// Verifier is a ratify.Verifier implementation that checks the licenses of the
// packages described by an SPDX SBOM against a list of allowed licenses.
type Verifier struct {
	name            string
	allowedLicenses map[string]struct{}
	artifactTypes   []string
}

// NewVerifier creates a new license checker verifier.
func NewVerifier(opts *VerifierOptions) (*Verifier, error) {
	if opts == nil {
		return nil, fmt.Errorf("verifier options are required")
	}
	if opts.Name == "" {
		return nil, fmt.Errorf("verifier name is required")
	}

	return &Verifier{
		name:            opts.Name,
		allowedLicenses: loadAllowedLicenses(opts.AllowedLicenses),
		artifactTypes:   opts.ArtifactTypes,
	}, nil
}

// Name returns the name of the verifier.
func (v *Verifier) Name() string {
	return v.name
}

// Type returns the type of the verifier which is always `licensechecker`.
func (v *Verifier) Type() string {
	return verifierTypeLicenseChecker
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

// Verify verifies that every package described by the SPDX SBOM has a license
// that is in the list of allowed licenses.
func (v *Verifier) Verify(ctx context.Context, opts *ratify.VerifyOptions) (*ratify.VerificationResult, error) {
	result := &ratify.VerificationResult{
		Verifier: v,
	}

	blobs, err := fetchBlobDescriptors(ctx, opts.Store, opts.Repository, opts.ArtifactDescriptor)
	if err != nil {
		return nil, err
	}

	if len(blobs) == 0 {
		result.Err = fmt.Errorf("no blobs found for referrer %s@%s", opts.Repository, opts.ArtifactDescriptor.Digest.String())
		result.Description = "License check failed"
		return result, nil
	}

	for _, blobDesc := range blobs {
		refBlob, err := opts.Store.FetchBlob(ctx, opts.Repository, blobDesc)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch blob for subject %s digest %s: %w", opts.Repository, blobDesc.Digest, err)
		}

		spdxDoc, err := blobToSPDX(refBlob)
		if err != nil {
			return nil, fmt.Errorf("failed to parse SPDX document: %w", err)
		}

		packageLicenses := getPackageLicenses(spdxDoc)
		disallowedLicenses := filterPackageLicenses(packageLicenses, v.allowedLicenses)

		if len(disallowedLicenses) > 0 {
			result.Err = fmt.Errorf("license check failed: %d package(s) have disallowed licenses", len(disallowedLicenses))
			result.Description = "License check failed: found packages with disallowed licenses"
			result.Detail = map[string]any{
				"disallowedLicenses": disallowedLicenses,
			}
			return result, nil
		}
	}

	result.Description = "License check succeeded: all packages have allowed licenses"
	return result, nil
}

// fetchBlobDescriptors fetches the manifest of the artifact and returns the
// blob (layer) descriptors it references.
func fetchBlobDescriptors(ctx context.Context, store ratify.Store, repo string, artifactDesc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	manifestBytes, err := store.FetchManifest(ctx, repo, artifactDesc)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch manifest for artifact: %w", err)
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal manifest: %w", err)
	}

	return manifest.Layers, nil
}
