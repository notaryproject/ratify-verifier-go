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
	"errors"
	"testing"

	"github.com/notaryproject/ratify-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	testVerifierName = "licensechecker-1"
	testRepo         = "test-registry/test-repo"
	testDigest       = "sha256:cd0abf4135161b8aeb079b64b8215e433088d21463204771d070aadc52678aa0"

	spdxMITPackage = `SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: test
DocumentNamespace: https://example.com/test
Creator: Tool: test
Created: 2023-01-01T00:00:00Z

PackageName: mypackage
SPDXID: SPDXRef-Package-mypackage
PackageDownloadLocation: NOASSERTION
PackageLicenseConcluded: MIT
PackageLicenseDeclared: MIT
PackageCopyrightText: NOASSERTION
`

	spdxGPLPackage = `SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: test
DocumentNamespace: https://example.com/test
Creator: Tool: test
Created: 2023-01-01T00:00:00Z

PackageName: gplpackage
SPDXID: SPDXRef-Package-gplpackage
PackageDownloadLocation: NOASSERTION
PackageLicenseConcluded: GPL-3.0-only
PackageLicenseDeclared: GPL-3.0-only
PackageCopyrightText: NOASSERTION
`
)

// mockStore is a mock implementation of ratify.Store.
type mockStore struct {
	manifest    *ocispec.Manifest
	manifestErr error
	blob        []byte
	blobErr     error
}

func (m *mockStore) Resolve(_ context.Context, _ string) (ocispec.Descriptor, error) {
	return ocispec.Descriptor{}, nil
}

func (m *mockStore) ListReferrers(_ context.Context, _ string, _ []string, _ func(referrers []ocispec.Descriptor) error) error {
	return nil
}

func (m *mockStore) FetchBlob(_ context.Context, _ string, _ ocispec.Descriptor) ([]byte, error) {
	if m.blobErr != nil {
		return nil, m.blobErr
	}
	return m.blob, nil
}

func (m *mockStore) FetchManifest(_ context.Context, _ string, _ ocispec.Descriptor) ([]byte, error) {
	if m.manifestErr != nil {
		return nil, m.manifestErr
	}
	return json.Marshal(m.manifest)
}

func newManifest() *ocispec.Manifest {
	return &ocispec.Manifest{
		Layers: []ocispec.Descriptor{
			{
				MediaType: "application/spdx",
				Digest:    testDigest,
			},
		},
	}
}

func TestNewVerifier(t *testing.T) {
	tests := []struct {
		name    string
		opts    *VerifierOptions
		wantErr bool
	}{
		{name: "nil options", opts: nil, wantErr: true},
		{name: "empty name", opts: &VerifierOptions{}, wantErr: true},
		{name: "valid", opts: &VerifierOptions{Name: testVerifierName, AllowedLicenses: []string{"MIT"}}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := NewVerifier(tt.opts)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewVerifier() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && v.Name() != testVerifierName {
				t.Fatalf("Name() = %s, want %s", v.Name(), testVerifierName)
			}
		})
	}
}

func TestType(t *testing.T) {
	v, _ := NewVerifier(&VerifierOptions{Name: testVerifierName})
	if v.Type() != verifierTypeLicenseChecker {
		t.Fatalf("Type() = %s, want %s", v.Type(), verifierTypeLicenseChecker)
	}
}

func TestVerifiable(t *testing.T) {
	tests := []struct {
		name          string
		artifactTypes []string
		artifact      ocispec.Descriptor
		want          bool
	}{
		{name: "no configured types accepts all", artifactTypes: nil, artifact: ocispec.Descriptor{ArtifactType: "anything"}, want: true},
		{name: "matching type", artifactTypes: []string{"application/spdx+json"}, artifact: ocispec.Descriptor{ArtifactType: "application/spdx+json"}, want: true},
		{name: "non-matching type", artifactTypes: []string{"application/spdx+json"}, artifact: ocispec.Descriptor{ArtifactType: "other"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := NewVerifier(&VerifierOptions{Name: testVerifierName, ArtifactTypes: tt.artifactTypes})
			if got := v.Verifiable(tt.artifact); got != tt.want {
				t.Fatalf("Verifiable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	tests := []struct {
		name        string
		allowed     []string
		store       *mockStore
		wantErr     bool
		wantFailure bool
	}{
		{
			name:    "all licenses allowed",
			allowed: []string{"MIT"},
			store:   &mockStore{manifest: newManifest(), blob: []byte(spdxMITPackage)},
		},
		{
			name:        "disallowed license",
			allowed:     []string{"MIT"},
			store:       &mockStore{manifest: newManifest(), blob: []byte(spdxGPLPackage)},
			wantFailure: true,
		},
		{
			name:        "no blobs",
			allowed:     []string{"MIT"},
			store:       &mockStore{manifest: &ocispec.Manifest{}},
			wantFailure: true,
		},
		{
			name:    "manifest fetch error",
			allowed: []string{"MIT"},
			store:   &mockStore{manifestErr: errors.New("boom")},
			wantErr: true,
		},
		{
			name:    "blob fetch error",
			allowed: []string{"MIT"},
			store:   &mockStore{manifest: newManifest(), blobErr: errors.New("boom")},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := NewVerifier(&VerifierOptions{Name: testVerifierName, AllowedLicenses: tt.allowed})
			result, err := v.Verify(context.Background(), &ratify.VerifyOptions{
				Store:              tt.store,
				Repository:         testRepo,
				ArtifactDescriptor: ocispec.Descriptor{Digest: testDigest},
			})
			if (err != nil) != tt.wantErr {
				t.Fatalf("Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if tt.wantFailure && result.Err == nil {
				t.Fatalf("Verify() expected failure but result.Err is nil")
			}
			if !tt.wantFailure && result.Err != nil {
				t.Fatalf("Verify() unexpected failure: %v", result.Err)
			}
		})
	}
}
