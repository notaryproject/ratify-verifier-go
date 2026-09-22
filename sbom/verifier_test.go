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
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/notaryproject/ratify-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	testVerifierName = "sbom-1"
	testRepo         = "test-registry/test-repo"
	testDigest       = "sha256:cd0abf4135161b8aeb079b64b8215e433088d21463204771d070aadc52678aa0"
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

func manifestWithLayer() *ocispec.Manifest {
	return &ocispec.Manifest{
		Layers: []ocispec.Descriptor{
			{MediaType: SPDXJSONMediaType, Digest: testDigest},
		},
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	return b
}

func TestNewVerifier(t *testing.T) {
	tests := []struct {
		name    string
		opts    *VerifierOptions
		wantErr bool
	}{
		{name: "nil options", opts: nil, wantErr: true},
		{name: "empty name", opts: &VerifierOptions{}, wantErr: true},
		{name: "valid", opts: &VerifierOptions{Name: testVerifierName}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewVerifier(tt.opts)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewVerifier() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTypeAndName(t *testing.T) {
	v, _ := NewVerifier(&VerifierOptions{Name: testVerifierName})
	if v.Name() != testVerifierName {
		t.Fatalf("Name() = %s", v.Name())
	}
	if v.Type() != verifierTypeSBOM {
		t.Fatalf("Type() = %s", v.Type())
	}
}

func TestVerifiable(t *testing.T) {
	v, _ := NewVerifier(&VerifierOptions{Name: testVerifierName})
	if !v.Verifiable(ocispec.Descriptor{ArtifactType: SPDXJSONMediaType}) {
		t.Fatal("expected verifiable true for SPDX JSON")
	}
	if v.Verifiable(ocispec.Descriptor{ArtifactType: "application/other"}) {
		t.Fatal("expected verifiable false for other type")
	}
}

func TestContainsLicense(t *testing.T) {
	if !containsLicense("gpl-2.0-only", "gpl-2.0-only") {
		t.Fatal("expected whole word match")
	}
	if !containsLicense("mit or (gpl-2.0-only)", "gpl-2.0-only") {
		t.Fatal("expected match within bracketed expression")
	}
	if containsLicense("gpl-2.0-only-plus", "gpl-2.0-only") {
		t.Fatal("expected no partial word match")
	}
}

func TestVerify(t *testing.T) {
	spdxBlob := mustRead(t, "testdata/syftbom.spdx.json")

	tests := []struct {
		name         string
		opts         *VerifierOptions
		store        *mockStore
		artifactType string
		wantErr      bool
		wantFailure  bool
	}{
		{
			name:         "no deny lists passes",
			opts:         &VerifierOptions{Name: testVerifierName},
			store:        &mockStore{manifest: manifestWithLayer(), blob: spdxBlob},
			artifactType: SPDXJSONMediaType,
		},
		{
			name:         "disallowed license",
			opts:         &VerifierOptions{Name: testVerifierName, DisallowedLicenses: []string{"GPL-2.0-only"}},
			store:        &mockStore{manifest: manifestWithLayer(), blob: spdxBlob},
			artifactType: SPDXJSONMediaType,
			wantFailure:  true,
		},
		{
			name:         "disallowed package by name",
			opts:         &VerifierOptions{Name: testVerifierName, DisallowedPackages: []PackageInfo{{Name: "busybox"}}},
			store:        &mockStore{manifest: manifestWithLayer(), blob: spdxBlob},
			artifactType: SPDXJSONMediaType,
			wantFailure:  true,
		},
		{
			name:         "allowed license and package",
			opts:         &VerifierOptions{Name: testVerifierName, DisallowedLicenses: []string{"AGPL-3.0"}, DisallowedPackages: []PackageInfo{{Name: "does-not-exist"}}},
			store:        &mockStore{manifest: manifestWithLayer(), blob: spdxBlob},
			artifactType: SPDXJSONMediaType,
		},
		{
			name:         "unsupported artifact type",
			opts:         &VerifierOptions{Name: testVerifierName, ArtifactTypes: []string{"application/other"}},
			store:        &mockStore{manifest: manifestWithLayer(), blob: spdxBlob},
			artifactType: "application/other",
			wantFailure:  true,
		},
		{
			name:         "no blobs",
			opts:         &VerifierOptions{Name: testVerifierName},
			store:        &mockStore{manifest: &ocispec.Manifest{}},
			artifactType: SPDXJSONMediaType,
			wantFailure:  true,
		},
		{
			name:         "manifest error",
			opts:         &VerifierOptions{Name: testVerifierName},
			store:        &mockStore{manifestErr: errors.New("boom")},
			artifactType: SPDXJSONMediaType,
			wantErr:      true,
		},
		{
			name:         "blob error",
			opts:         &VerifierOptions{Name: testVerifierName},
			store:        &mockStore{manifest: manifestWithLayer(), blobErr: errors.New("boom")},
			artifactType: SPDXJSONMediaType,
			wantErr:      true,
		},
		{
			name:         "invalid spdx json",
			opts:         &VerifierOptions{Name: testVerifierName, DisallowedLicenses: []string{"GPL-2.0-only"}},
			store:        &mockStore{manifest: manifestWithLayer(), blob: []byte("not json")},
			artifactType: SPDXJSONMediaType,
			wantFailure:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := NewVerifier(tt.opts)
			if err != nil {
				t.Fatalf("NewVerifier() error = %v", err)
			}
			result, err := v.Verify(context.Background(), &ratify.VerifyOptions{
				Store:              tt.store,
				Repository:         testRepo,
				ArtifactDescriptor: ocispec.Descriptor{ArtifactType: tt.artifactType, Digest: testDigest},
			})
			if (err != nil) != tt.wantErr {
				t.Fatalf("Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if tt.wantFailure && result.Err == nil {
				t.Fatal("expected verification failure")
			}
			if !tt.wantFailure && result.Err != nil {
				t.Fatalf("unexpected verification failure: %v", result.Err)
			}
		})
	}
}
