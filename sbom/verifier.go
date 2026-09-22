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

package sbom

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/notaryproject/ratify-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	jsonLoader "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

const (
	verifierTypeSBOM = "sbom"

	// SPDXJSONMediaType is the artifact type of an SPDX JSON SBOM.
	SPDXJSONMediaType = "application/spdx+json"

	creationInfo     = "creationInfo"
	licenseViolation = "licenseViolations"
	packageViolation = "packageViolations"
)

// PackageInfo identifies a package by name and optional version.
type PackageInfo struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// PackageLicense holds the name, version, and concluded license of a package.
type PackageLicense struct {
	Name    string
	Version string
	License string
}

// VerifierOptions contains the options for creating a new SBOM verifier.
type VerifierOptions struct {
	// Name is the instance name of the verifier to be created. Required.
	Name string

	// DisallowedLicenses is the list of licenses that are not permitted. A
	// package whose license contains any of these fails verification.
	// Optional.
	DisallowedLicenses []string

	// DisallowedPackages is the list of packages that are not permitted. A
	// package matching an entry (by name, or by name and version) fails
	// verification. Optional.
	DisallowedPackages []PackageInfo

	// ArtifactTypes is the list of artifact types that this verifier can
	// verify. Optional. If empty, it defaults to the SPDX JSON media type.
	ArtifactTypes []string
}

// Verifier is a ratify.Verifier implementation that validates an SPDX JSON SBOM
// against disallowed licenses and packages.
type Verifier struct {
	name               string
	disallowedLicenses []string
	disallowedPackages []PackageInfo
	artifactTypes      []string
}

// NewVerifier creates a new SBOM verifier.
func NewVerifier(opts *VerifierOptions) (*Verifier, error) {
	if opts == nil {
		return nil, fmt.Errorf("verifier options are required")
	}
	if opts.Name == "" {
		return nil, fmt.Errorf("verifier name is required")
	}

	artifactTypes := opts.ArtifactTypes
	if len(artifactTypes) == 0 {
		artifactTypes = []string{SPDXJSONMediaType}
	}

	return &Verifier{
		name:               opts.Name,
		disallowedLicenses: opts.DisallowedLicenses,
		disallowedPackages: opts.DisallowedPackages,
		artifactTypes:      artifactTypes,
	}, nil
}

// Name returns the name of the verifier.
func (v *Verifier) Name() string {
	return v.name
}

// Type returns the type of the verifier which is always `sbom`.
func (v *Verifier) Type() string {
	return verifierTypeSBOM
}

// Verifiable returns true if the artifact type is one this verifier handles.
func (v *Verifier) Verifiable(artifact ocispec.Descriptor) bool {
	for _, t := range v.artifactTypes {
		if t == artifact.ArtifactType {
			return true
		}
	}
	return false
}

// Verify validates the SPDX JSON SBOM referenced by the artifact.
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
		result.Description = "SBOM validation failed"
		return result, nil
	}

	artifactType := opts.ArtifactDescriptor.ArtifactType
	for _, blobDesc := range manifest.Layers {
		refBlob, err := opts.Store.FetchBlob(ctx, opts.Repository, blobDesc)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch blob for subject %s digest %s: %w", opts.Repository, blobDesc.Digest, err)
		}

		switch artifactType {
		case SPDXJSONMediaType:
			return v.processSPDXJSONMediaType(refBlob), nil
		default:
			result.Err = fmt.Errorf("unsupported artifactType: %s", artifactType)
			result.Description = "Failed to process SBOM blobs"
			return result, nil
		}
	}

	result.Description = "SBOM verification success. No license or package violation found"
	return result, nil
}

// processSPDXJSONMediaType parses the SPDX JSON blob and detects violations.
func (v *Verifier) processSPDXJSONMediaType(refBlob []byte) *ratify.VerificationResult {
	result := &ratify.VerificationResult{
		Verifier: v,
	}

	spdxDoc, err := jsonLoader.Read(bytes.NewReader(refBlob))
	if err != nil || spdxDoc == nil {
		result.Err = fmt.Errorf("failed to parse SPDX JSON document: %w", err)
		result.Description = "SBOM validation failed"
		return result
	}

	if len(v.disallowedLicenses) == 0 && len(v.disallowedPackages) == 0 {
		result.Description = "SBOM verification success. No license or package violation found"
		result.Detail = map[string]any{creationInfo: spdxDoc.CreationInfo}
		return result
	}

	packageViolations, licenseViolations := getViolations(spdxDoc, v.disallowedLicenses, v.disallowedPackages)

	detail := map[string]any{creationInfo: spdxDoc.CreationInfo}
	if len(licenseViolations) > 0 {
		detail[licenseViolation] = licenseViolations
	}
	if len(packageViolations) > 0 {
		detail[packageViolation] = packageViolations
	}

	if len(licenseViolations) > 0 || len(packageViolations) > 0 {
		result.Err = fmt.Errorf("license or package violation found")
		result.Description = "SBOM validation failed: license or package violation found"
		result.Detail = detail
		return result
	}

	result.Description = "SBOM verification success. No license or package violation found"
	result.Detail = detail
	return result
}

// getViolations returns the package and license violations based on the deny
// lists.
func getViolations(spdxDoc *v2_3.Document, disallowedLicenses []string, disallowedPackages []PackageInfo) (packageViolations []PackageLicense, licenseViolations []PackageLicense) {
	packageLicenses := getPackageLicenses(spdx.Document(*spdxDoc))
	packageMap, packageNameMap := loadDisallowedPackagesMap(disallowedPackages)
	return filterDisallowedPackages(packageLicenses, disallowedLicenses, packageMap, packageNameMap)
}

// loadDisallowedPackagesMap converts the disallowed packages into lookup maps:
// one keyed by name+version, one keyed by name only (for entries without a
// version).
func loadDisallowedPackagesMap(packages []PackageInfo) (map[PackageInfo]struct{}, map[string]struct{}) {
	packagesInfo := map[PackageInfo]struct{}{}
	packagesName := map[string]struct{}{}

	for _, item := range packages {
		if len(item.Version) == 0 {
			packagesName[item.Name] = struct{}{}
		}
		packagesInfo[item] = struct{}{}
	}
	return packagesInfo, packagesName
}

// filterDisallowedPackages iterates through the package licenses and returns the
// license and package violations.
func filterDisallowedPackages(packageLicenses []PackageLicense, disallowedLicense []string, disallowedPackage map[PackageInfo]struct{}, disallowedPackageName map[string]struct{}) (violationPackage []PackageLicense, violationLicense []PackageLicense) {
	for _, packageInfo := range packageLicenses {
		for _, disallowed := range disallowedLicense {
			if containsLicense(strings.ToLower(packageInfo.License), strings.ToLower(disallowed)) {
				violationLicense = append(violationLicense, packageInfo)
			}
		}

		current := PackageInfo{
			Name:    packageInfo.Name,
			Version: packageInfo.Version,
		}

		if _, ok := disallowedPackageName[current.Name]; ok {
			violationPackage = append(violationPackage, packageInfo)
			continue
		}

		if _, ok := disallowedPackage[current]; ok {
			violationPackage = append(violationPackage, packageInfo)
		}
	}
	return violationPackage, violationLicense
}
